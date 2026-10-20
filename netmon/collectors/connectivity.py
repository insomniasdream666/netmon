"""Connectivity collector: ping, DNS, traceroute and gateway probes.

Every probe type runs concurrently within one collection:

* all ``monitoring.targets.ping`` entries are pinged in parallel;
* all ``monitoring.targets.dns`` entries are resolved in parallel through
  ``dns.asyncresolver`` (5 second lifetime); when dnspython is unavailable the
  collector falls back to ``dig`` and then to the system resolver;
* only the first ``monitoring.targets.traceroute`` entry is traced, because
  traceroute is slow compared with the other probes;
* the default gateway is pinged once.

Recoverable problems (unreachable targets, missing binaries) are reported in
the payload and in ``result.errors`` while ``result.ok`` stays true whenever
any probe data was gathered.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import shutil
import socket
import time
from datetime import UTC, datetime
from typing import Any

from netmon.collectors.base import BaseCollector, CollectionResult
from netmon.config.settings import NetMonConfig
from netmon.integrations.kali_tools import KaliTools

try:
    from dns.asyncresolver import Resolver as AsyncResolver
    from dns.exception import DNSException
except ImportError:  # pragma: no cover - dnspython is a declared dependency
    AsyncResolver = None  # type: ignore[assignment,misc]
    DNSException = Exception  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

MEASUREMENT = "connectivity"
DNS_LIFETIME_S = 5.0
TRACEROUTE_TIMEOUT_S = 20.0


def _is_ip_literal(value: str) -> bool:
    """True when text parses as an IPv4 or IPv6 address literal."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _summarise_ping(ping: dict[str, Any]) -> dict[str, Any]:
    """Aggregate ping results into the contract's ``internet`` block."""
    successful = [info for info in ping.values() if info.get("success")]
    latencies = [
        float(info["latency_ms"]) for info in successful if info.get("latency_ms") is not None
    ]
    losses = [float(info.get("packet_loss") or 0.0) for info in ping.values()]
    return {
        "reachable": bool(successful),
        "targets_ok": len(successful),
        "targets_total": len(ping),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
        "avg_packet_loss": round(sum(losses) / len(losses), 2) if losses else None,
    }


def _summarise_dns(dns: dict[str, Any]) -> dict[str, Any]:
    """Aggregate resolution results into the contract's ``dns_health`` block."""
    total = len(dns)
    failures = sum(1 for info in dns.values() if not info.get("success"))
    latencies = [
        float(info["latency_ms"]) for info in dns.values() if info.get("latency_ms") is not None
    ]
    return {
        "healthy": total > 0 and failures == 0,
        "failures": failures,
        "total": total,
        "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
        "failure_rate": round(failures / total * 100, 2) if total else 0.0,
    }


class ConnectivityCollector(BaseCollector):
    """Probes internet reachability, DNS resolution, traceroute and gateway."""

    name = "connectivity"
    #: Traceroute dominates the runtime, so the budget is larger than usual.
    timeout = 45.0

    def __init__(self, config: NetMonConfig, tools: KaliTools | None = None) -> None:
        """Store configuration and the tool wrapper used for the probes."""
        super().__init__(interval=config.monitoring.interval_for(self.name))
        self.config = config
        self.tools = tools or KaliTools()

    async def collect(self) -> CollectionResult:
        """Run every connectivity probe and build the summary blocks."""
        result = self.result()
        now = datetime.now(UTC)
        targets = self.config.monitoring.targets
        traceroute_target = targets.traceroute[0] if targets.traceroute else None

        route = await self.tools.default_route()
        gateway = route.get("gateway")

        gathered = await asyncio.gather(
            self._collect_pings(list(targets.ping)),
            self._collect_dns(list(targets.dns)),
            self._collect_traceroute(traceroute_target),
            self._probe_gateway(gateway),
            return_exceptions=True,
        )
        ping_data, ping_errors = self._unpack(gathered[0], "ping", result)
        dns_data, dns_errors = self._unpack(gathered[1], "dns", result)
        traceroute_data, traceroute_errors = self._unpack(gathered[2], "traceroute", result)
        gateway_data, gateway_errors = self._unpack(gathered[3], "gateway", result)
        for message in (*ping_errors, *dns_errors, *traceroute_errors, *gateway_errors):
            result.add_error(message)

        internet = _summarise_ping(ping_data)
        dns_health = _summarise_dns(dns_data)
        result.data.update(
            {
                "ping": ping_data,
                "dns": dns_data,
                "traceroute": traceroute_data,
                "gateway": gateway_data,
                "internet": internet,
                "dns_health": dns_health,
            }
        )

        if not ping_data and not dns_data and not traceroute_data and not gateway_data:
            result.ok = False
            if not result.errors:
                result.add_error("no connectivity targets configured or all probes were skipped")
            return result

        self._emit_metrics(result, now, ping_data, dns_data, gateway_data, internet)
        return result

    # -- probes --------------------------------------------------------------

    async def _collect_pings(self, targets: list[str]) -> tuple[dict[str, Any], list[str]]:
        """Ping every configured target concurrently."""
        if not targets:
            return {}, []
        gathered = await asyncio.gather(
            *(self.tools.ping(target) for target in targets), return_exceptions=True
        )
        entries: dict[str, Any] = {}
        errors: list[str] = []
        for target, outcome in zip(targets, gathered, strict=True):
            if isinstance(outcome, BaseException):
                message = f"{type(outcome).__name__}: {outcome}"
                entries[target] = {
                    "target": target,
                    "latency_ms": None,
                    "packet_loss": 100.0,
                    "success": False,
                    "transmitted": 0,
                    "received": 0,
                    "jitter_ms": None,
                }
                errors.append(f"ping {target}: {message}")
                continue
            entries[target] = {
                "target": target,
                "latency_ms": outcome.latency_ms,
                "packet_loss": outcome.packet_loss,
                "success": outcome.success,
                "transmitted": outcome.transmitted,
                "received": outcome.received,
                "jitter_ms": outcome.jitter_ms,
            }
            if outcome.error and outcome.transmitted == 0:
                errors.append(f"ping {target}: {outcome.error}")
        return entries, errors

    async def _collect_dns(self, targets: list[str]) -> tuple[dict[str, Any], list[str]]:
        """Resolve every configured name concurrently."""
        if not targets:
            return {}, []
        gathered = await asyncio.gather(
            *(self._resolve(name) for name in targets), return_exceptions=True
        )
        entries: dict[str, Any] = {}
        errors: list[str] = []
        for target, outcome in zip(targets, gathered, strict=True):
            if isinstance(outcome, BaseException):
                message = f"{type(outcome).__name__}: {outcome}"
                entries[target] = {
                    "name": target,
                    "latency_ms": None,
                    "success": False,
                    "addresses": [],
                    "error": message,
                }
                errors.append(f"dns {target}: {message}")
                continue
            entries[target] = outcome
            if not outcome["success"]:
                errors.append(f"dns {target}: {outcome['error']}")
        return entries, errors

    async def _resolve(self, name: str) -> dict[str, Any]:
        """Resolve one name, preferring dnspython with a 5 second lifetime."""
        started = time.perf_counter()
        if AsyncResolver is not None:
            try:
                resolver = AsyncResolver()
                resolver.lifetime = DNS_LIFETIME_S
                resolver.timeout = DNS_LIFETIME_S
                answer = await resolver.resolve(name, "A")
                return self._dns_entry(name, [str(record) for record in answer], started)
            except (DNSException, OSError, ValueError) as exc:
                latency = (time.perf_counter() - started) * 1000
                return {
                    "name": name,
                    "latency_ms": round(latency, 2),
                    "success": False,
                    "addresses": [],
                    "error": f"{type(exc).__name__}: {str(exc).strip()}",
                }
        return await self._resolve_fallback(name, started)

    async def _resolve_fallback(self, name: str, started: float) -> dict[str, Any]:
        """Resolve through ``dig``, then the system resolver, without dnspython."""
        error: str | None = None
        if shutil.which("dig"):
            command = await self.tools.run(
                ["dig", "+short", "+time=2", "+tries=1", name], timeout=6.0
            )
            addresses = [
                line.strip() for line in command.stdout.splitlines() if _is_ip_literal(line.strip())
            ]
            if addresses:
                return self._dns_entry(name, addresses, started)
            error = command.error or "dig returned no addresses"
        else:
            error = "dnspython and dig are both unavailable"
        try:
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(name, None, type=socket.SOCK_STREAM)
        except OSError as exc:
            error = f"{error}; system resolver: {exc}"
            infos = []
        addresses = sorted({str(info[4][0]) for info in infos})
        if addresses:
            return self._dns_entry(name, addresses, started)
        latency = (time.perf_counter() - started) * 1000
        return {
            "name": name,
            "latency_ms": round(latency, 2),
            "success": False,
            "addresses": [],
            "error": error or "no addresses returned",
        }

    @staticmethod
    def _dns_entry(name: str, addresses: list[str], started: float) -> dict[str, Any]:
        """Successful DNS result entry with the measured latency."""
        latency = (time.perf_counter() - started) * 1000
        return {
            "name": name,
            "latency_ms": round(latency, 2),
            "success": True,
            "addresses": addresses,
            "error": None,
        }

    async def _collect_traceroute(self, target: str | None) -> tuple[dict[str, Any], list[str]]:
        """Trace the first configured traceroute target (tracing is slow)."""
        if not target:
            return {}, []
        entry = await self.tools.traceroute(target, timeout=TRACEROUTE_TIMEOUT_S)
        errors = [f"traceroute {target}: {entry['error']}"] if entry.get("error") else []
        return {target: entry}, errors

    async def _probe_gateway(self, gateway: str | None) -> tuple[dict[str, Any], list[str]]:
        """Ping the default gateway twice to confirm the local link works."""
        if not gateway:
            return {}, []
        summary = await self.tools.ping(gateway, count=2, timeout=4.0)
        return (
            {
                "gateway": gateway,
                "reachable": summary.success,
                "latency_ms": summary.latency_ms,
                "packet_loss": summary.packet_loss,
            },
            [],
        )

    # -- result helpers ------------------------------------------------------

    @staticmethod
    def _unpack(
        outcome: Any, label: str, result: CollectionResult
    ) -> tuple[dict[str, Any], list[str]]:
        """Normalise one ``gather(..., return_exceptions=True)`` outcome."""
        if isinstance(outcome, BaseException):
            logger.debug("connectivity %s section failed: %s", label, outcome)
            result.add_error(f"{label}: {type(outcome).__name__}: {outcome}")
            return {}, []
        data, errors = outcome
        return data, errors

    @staticmethod
    def _emit_metrics(
        result: CollectionResult,
        now: datetime,
        ping_data: dict[str, Any],
        dns_data: dict[str, Any],
        gateway_data: dict[str, Any],
        internet: dict[str, Any],
    ) -> None:
        """Append ``connectivity`` points for every probed target."""
        for target, info in ping_data.items():
            fields: dict[str, Any] = {
                "packet_loss": info["packet_loss"],
                "success": 1 if info["success"] else 0,
            }
            if info["latency_ms"] is not None:
                fields["latency_ms"] = info["latency_ms"]
            result.metrics.append(
                {
                    "measurement": MEASUREMENT,
                    "tags": {"target": target, "type": "ping"},
                    "fields": fields,
                    "time": now,
                }
            )
        for name, info in dns_data.items():
            fields = {"success": 1 if info["success"] else 0}
            if info["latency_ms"] is not None:
                fields["latency_ms"] = info["latency_ms"]
            result.metrics.append(
                {
                    "measurement": MEASUREMENT,
                    "tags": {"target": name, "type": "dns"},
                    "fields": fields,
                    "time": now,
                }
            )
        if gateway_data:
            fields = {
                "packet_loss": gateway_data["packet_loss"],
                "success": 1 if gateway_data["reachable"] else 0,
            }
            if gateway_data["latency_ms"] is not None:
                fields["latency_ms"] = gateway_data["latency_ms"]
            result.metrics.append(
                {
                    "measurement": MEASUREMENT,
                    "tags": {"target": str(gateway_data["gateway"]), "type": "gateway"},
                    "fields": fields,
                    "time": now,
                }
            )
        if internet["targets_total"]:
            fields = {
                "packet_loss": internet["avg_packet_loss"],
                "success": 1 if internet["reachable"] else 0,
            }
            if internet["avg_latency_ms"] is not None:
                fields["latency_ms"] = internet["avg_latency_ms"]
            result.metrics.append(
                {
                    "measurement": MEASUREMENT,
                    "tags": {"target": "internet", "type": "internet"},
                    "fields": fields,
                    "time": now,
                }
            )


__all__ = ["ConnectivityCollector"]
