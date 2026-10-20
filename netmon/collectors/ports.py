"""Port scan collector: nmap over a bounded list of configured targets.

Targets come from ``monitoring.port_scan.targets`` when set, otherwise from
``monitoring.targets.ports``, and at most ``max_targets`` are scanned per
cycle. :meth:`KaliTools.nmap_scan` performs the scan (TCP connect by default,
so no root privileges are required) and parses the XML output.

When ``nmap`` is missing the collector fails cleanly with a descriptive error
and emits no metrics. Per-host scan duration is the overall scan time,
because nmap only reports the total duration in its XML output.
"""

from __future__ import annotations

import logging
import shutil
from datetime import UTC, datetime
from typing import Any

from netmon.collectors.base import BaseCollector, CollectionResult
from netmon.config.settings import NetMonConfig
from netmon.integrations.kali_tools import KaliTools

logger = logging.getLogger(__name__)

MEASUREMENT = "port_scan"
SCAN_TIMEOUT_S = 240.0


class PortsCollector(BaseCollector):
    """Scans configured targets with nmap and reports open ports."""

    name = "ports"
    timeout = 300.0

    def __init__(self, config: NetMonConfig, tools: KaliTools | None = None) -> None:
        """Store configuration and the tool wrapper used for nmap."""
        super().__init__(interval=config.monitoring.interval_for(self.name))
        self.config = config
        self.tools = tools or KaliTools()

    async def collect(self) -> CollectionResult:
        """Scan the configured targets and map open ports into the payload."""
        result = self.result()
        now = datetime.now(UTC)
        settings = self.config.monitoring.port_scan
        empty: dict[str, Any] = {"targets": {}, "scanned": 0, "total_open": 0}

        if not settings.enabled:
            result.data.update({**empty, "note": "port scanning disabled in configuration"})
            return result

        targets = (
            list(settings.targets)
            if settings.targets
            else list(self.config.monitoring.targets.ports)
        )
        targets = targets[: settings.max_targets]
        if not targets:
            result.ok = False
            result.add_error("no port scan targets configured")
            result.data.update(empty)
            return result
        if shutil.which("nmap") is None:
            result.ok = False
            result.add_error("nmap is not installed; install nmap to enable port scanning")
            result.data.update(empty)
            return result

        scan = await self.tools.nmap_scan(
            targets,
            ports=settings.ports,
            protocol=settings.protocol,
            service_detection=settings.service_detection,
            arguments=settings.arguments,
            timeout=SCAN_TIMEOUT_S,
        )
        duration_ms = float(scan.get("duration_ms") or 0.0)
        scan_error = scan.get("error")
        error_text = str(scan_error) if scan_error else None
        hosts = [host for host in scan.get("hosts") or [] if isinstance(host, dict)]
        payload = self._map_hosts(targets, hosts, duration_ms, error_text)
        total_open = sum(len(host["open_ports"]) for host in payload.values())
        result.data.update(
            {"targets": payload, "scanned": len(payload), "total_open": total_open}
        )

        if not hosts:
            result.ok = False
            result.add_error(
                f"nmap scan failed: {error_text}"
                if error_text
                else "nmap returned no host results (targets may be unreachable)"
            )
            return result
        if error_text:
            result.add_error(f"nmap: {error_text}")

        for key, host in payload.items():
            counts: dict[str, int] = {}
            for port in host["open_ports"]:
                protocol = str(port.get("protocol") or "tcp")
                counts[protocol] = counts.get(protocol, 0) + 1
            if not counts:
                counts = {settings.protocol if settings.protocol != "both" else "tcp": 0}
            for protocol, count in counts.items():
                result.metrics.append(
                    {
                        "measurement": MEASUREMENT,
                        "tags": {"target": key, "protocol": protocol},
                        "fields": {
                            "open_ports": count,
                            "scan_duration_ms": host["scan_duration_ms"],
                        },
                        "time": now,
                    }
                )
        return result

    @staticmethod
    def _map_hosts(
        requested: list[str],
        hosts: list[dict[str, Any]],
        duration_ms: float,
        scan_error: str | None,
    ) -> dict[str, dict[str, Any]]:
        """Map parsed nmap hosts into the contract's ``targets`` mapping."""
        payload: dict[str, dict[str, Any]] = {}
        for host in hosts:
            address = str(host.get("target") or "").strip()
            if not address:
                continue
            payload[address] = {
                "target": address,
                "hostname": host.get("hostname"),
                "state": host.get("state") or "unknown",
                "scan_duration_ms": round(duration_ms, 2),
                "error": None,
                "open_ports": [dict(port) for port in host.get("open_ports") or []],
            }
        # Keep requested targets that nmap did not report (down or filtered)
        # visible in the payload, flagged with the scan error when there is one.
        for target in requested:
            if target in payload:
                continue
            if any(entry.get("hostname") == target for entry in payload.values()):
                continue
            payload[target] = {
                "target": target,
                "hostname": None,
                "state": "unknown",
                "scan_duration_ms": round(duration_ms, 2),
                "error": scan_error,
                "open_ports": [],
            }
        return payload


__all__ = ["PortsCollector"]
