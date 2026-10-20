"""Certificate collector: TLS expiry monitoring for configured endpoints.

Each ``monitoring.targets.certificates`` entry (``host:port``) is probed with
``openssl s_client`` through :class:`~netmon.integrations.kali_tools.KaliTools`;
at most four probes run concurrently. The parsed validity window drives
``days_remaining`` and the ``expiring_soon`` / ``expired`` lists, which use the
configured certificate warning threshold.

A probe that cannot fetch a certificate contributes an ``error`` entry and a
note in ``result.errors``; the collector only fails entirely when no
certificate could be inspected.

Some builds of :class:`KaliTools` forward an ``input_text`` keyword to
``KaliTools.run`` that the wrapper does not accept; in that case the same
openssl probes are performed directly through :func:`run_command`.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
from datetime import UTC, datetime
from typing import Any

from netmon.collectors.base import BaseCollector, CollectionResult
from netmon.config.settings import NetMonConfig
from netmon.integrations.kali_tools import KaliTools, days_until, parse_certificate
from netmon.utils.async_cmd import run_command

logger = logging.getLogger(__name__)

MEASUREMENT = "certificates"
MAX_CONCURRENCY = 4
DEFAULT_PORT = 443
OPENSSL_TIMEOUT_S = 12.0
PROTOCOL_RE = re.compile(r"Protocol\s*:\s*(\S+)")


def _parse_target(spec: str) -> tuple[str | None, int | None, str | None]:
    """Split ``host:port`` text into host and port, or explain the problem."""
    text = str(spec).strip()
    if not text:
        return None, None, "empty certificate target"
    host, port = text, DEFAULT_PORT
    if ":" in text:
        host, _, raw_port = text.rpartition(":")
        host = host.strip("[]")
        try:
            port = int(raw_port)
        except ValueError:
            return None, None, f"invalid port: {raw_port!r}"
    if not host:
        return None, None, "missing host"
    if not 1 <= port <= 65535:
        return None, None, f"port out of range: {port}"
    return host, port, None


def _error_entry(target: str, host: str | None, port: int | None, error: str) -> dict[str, Any]:
    """Contract-shaped certificate entry for a failed probe."""
    return {
        "target": target,
        "host": host,
        "port": port,
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "expired": False,
        "self_signed": False,
        "protocol": None,
        "error": error,
    }


def _as_iso(value: Any) -> str | None:
    """ISO-8601 text for a datetime, passing other values through."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


class CertificatesCollector(BaseCollector):
    """Watches TLS certificate expiry for the configured endpoints."""

    name = "certificates"
    timeout = 60.0

    def __init__(self, config: NetMonConfig, tools: KaliTools | None = None) -> None:
        """Store configuration and the probe concurrency limit."""
        super().__init__(interval=config.monitoring.interval_for(self.name))
        self.config = config
        self.tools = tools or KaliTools()
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

    async def collect(self) -> CollectionResult:
        """Probe every configured endpoint and evaluate its certificate."""
        result = self.result()
        now = datetime.now(UTC)
        targets = list(self.config.monitoring.targets.certificates)
        if not targets:
            result.ok = False
            result.add_error("no certificate targets configured")
            result.data.update({"certificates": {}, "expiring_soon": [], "expired": []})
            return result

        warning_days = self.config.health.thresholds.cert_expiry_warning_days
        gathered = await asyncio.gather(*(self._check(spec) for spec in targets))
        certificates: dict[str, dict[str, Any]] = {}
        expiring_soon: list[str] = []
        expired: list[str] = []
        for entry in gathered:
            key = str(entry["target"])
            certificates[key] = entry
            if entry["error"]:
                result.add_error(f"certificate {key}: {entry['error']}")
                continue
            days = entry["days_remaining"]
            if entry["expired"]:
                expired.append(key)
            elif days is not None and days <= warning_days:
                expiring_soon.append(key)
            if days is not None:
                result.metrics.append(
                    {
                        "measurement": MEASUREMENT,
                        "tags": {"target": key},
                        "fields": {
                            "days_remaining": int(days),
                            "expired": 1 if entry["expired"] else 0,
                        },
                        "time": now,
                    }
                )

        result.data.update(
            {"certificates": certificates, "expiring_soon": expiring_soon, "expired": expired}
        )
        if not any(not entry["error"] for entry in certificates.values()):
            result.ok = False
        return result

    # -- probing -------------------------------------------------------------

    async def _check(self, spec: str) -> dict[str, Any]:
        """Probe one target, converting any failure into an error entry."""
        async with self._semaphore:
            try:
                return await self._probe(spec)
            except Exception as exc:
                logger.debug("certificate probe for %s crashed: %s", spec, exc)
                return _error_entry(spec, None, None, f"{type(exc).__name__}: {exc}")

    async def _probe(self, spec: str) -> dict[str, Any]:
        """Fetch and evaluate the certificate for one ``host:port`` target."""
        host, port, parse_error = _parse_target(spec)
        if parse_error is not None or host is None or port is None:
            return _error_entry(spec, host, port, parse_error or "invalid target")
        parsed = await self._fetch(host, port)
        if parsed.get("error"):
            return _error_entry(spec, host, port, str(parsed["error"]))
        not_after = parsed.get("not_after")
        days = days_until(not_after if isinstance(not_after, datetime) else None)
        expired = days is not None and days < 0
        return {
            "target": spec,
            "host": host,
            "port": port,
            "subject": parsed.get("subject"),
            "issuer": parsed.get("issuer"),
            "not_before": _as_iso(parsed.get("not_before")),
            "not_after": _as_iso(not_after),
            "days_remaining": days,
            "expired": expired,
            "self_signed": bool(parsed.get("self_signed")),
            "protocol": parsed.get("protocol"),
            "error": None,
        }

    async def _fetch(self, host: str, port: int) -> dict[str, Any]:
        """Certificate details through KaliTools, with a defensive fallback."""
        try:
            return await self.tools.certificate(host, port)
        except TypeError as exc:
            if "input_text" not in str(exc):
                raise
            logger.debug("KaliTools.certificate unusable for %s: %s", host, exc)
            return await self._openssl_probe(host, port)

    @staticmethod
    async def _openssl_probe(host: str, port: int) -> dict[str, Any]:
        """Mirror of ``KaliTools.certificate`` using ``run_command`` directly."""
        if shutil.which("openssl") is None:
            return {"error": "openssl not installed"}
        s_client = await run_command(
            [
                "openssl",
                "s_client",
                "-connect",
                f"{host}:{port}",
                "-servername",
                host,
                "-showcerts",
            ],
            timeout=OPENSSL_TIMEOUT_S,
            input_text="",
        )
        if not s_client.stdout:
            return {"error": s_client.error or "openssl s_client produced no output"}
        details = await run_command(
            ["openssl", "x509", "-noout", "-dates", "-subject", "-issuer"],
            timeout=6.0,
            input_text=s_client.stdout,
        )
        parsed = parse_certificate(details.stdout)
        if not parsed.get("not_after"):
            return {"error": details.error or "could not parse certificate dates"}
        match = PROTOCOL_RE.search(s_client.stdout)
        parsed.update(
            {
                "host": host,
                "port": port,
                "protocol": match.group(1) if match else None,
                "self_signed": bool(
                    parsed.get("subject") and parsed.get("subject") == parsed.get("issuer")
                ),
            }
        )
        return parsed


__all__ = ["CertificatesCollector"]
