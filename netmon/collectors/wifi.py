"""Wi-Fi collector: link state, signal quality, clients and rfkill status.

``iw dev <iface> link`` (through :class:`~netmon.integrations.kali_tools.KaliTools`)
supplies the association details and ``station dump`` adds the connected
clients. ``rfkill list`` marks radios blocked in software or hardware. Hosts
without a wireless interface report ``has_wifi: false`` instead of an error.

Fields that ``iw`` does not expose (noise floor, security suite, 802.11
standard) are reported as ``None`` rather than guessed.
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import UTC, datetime
from typing import Any

from netmon.collectors.base import BaseCollector, CollectionResult
from netmon.config.settings import NetMonConfig
from netmon.integrations.kali_tools import KaliTools, WifiLink, signal_to_quality

logger = logging.getLogger(__name__)

MEASUREMENT = "wifi"
NO_WIFI_NOTE = "no wireless interface detected"
RFKILL_BLOCK_RE = re.compile(r"^\d+:\s+(?P<kind>.+)$")


def _parse_rfkill(stdout: str) -> bool | None:
    """True when a wireless radio is blocked, None when none is listed."""
    blocked: bool | None = None
    wireless_block = False
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if RFKILL_BLOCK_RE.match(line):
            wireless_block = "wireless" in line.lower()
            if wireless_block and blocked is None:
                blocked = False
            continue
        if not wireless_block:
            continue
        lowered = line.lower()
        if ("soft blocked:" in lowered or "hard blocked:" in lowered) and lowered.endswith("yes"):
            blocked = True
    return blocked


class WifiCollector(BaseCollector):
    """Collects wireless link state, quality and rfkill blocking."""

    name = "wifi"
    timeout = 30.0

    def __init__(self, config: NetMonConfig, tools: KaliTools | None = None) -> None:
        """Store configuration and the tool wrapper used for ``iw``."""
        super().__init__(interval=config.monitoring.interval_for(self.name))
        self.config = config
        self.tools = tools or KaliTools()

    async def collect(self) -> CollectionResult:
        """Collect link details for every wireless interface."""
        result = self.result()
        now = datetime.now(UTC)
        names = await self.tools.wireless_interfaces()
        if not names:
            result.data.update({"has_wifi": False, "interfaces": {}, "note": NO_WIFI_NOTE})
            return result

        rfkill_blocked = await self._rfkill_blocked()
        gathered = await asyncio.gather(
            *(self.tools.iw_link(name, station_dump=True) for name in names),
            return_exceptions=True,
        )
        interfaces: dict[str, dict[str, Any]] = {}
        for name, outcome in zip(names, gathered, strict=True):
            if isinstance(outcome, BaseException):
                message = f"{type(outcome).__name__}: {outcome}"
                logger.debug("iw link for %s failed: %s", name, outcome)
                interfaces[name] = self._link_payload(
                    WifiLink(interface=name, error=message), rfkill_blocked
                )
                result.add_error(f"wifi {name}: {message}")
                continue
            interfaces[name] = self._link_payload(outcome, rfkill_blocked)
            if outcome.error:
                result.add_error(f"wifi {name}: {outcome.error}")

        result.data.update({"has_wifi": True, "interfaces": interfaces, "note": None})
        for name, info in interfaces.items():
            fields: dict[str, Any] = {"connected": 1 if info["connected"] else 0}
            for key in ("signal_dbm", "noise_dbm", "quality_percent", "bitrate_mbps", "channel"):
                if info[key] is not None:
                    fields[key] = info[key]
            result.metrics.append(
                {
                    "measurement": MEASUREMENT,
                    "tags": {"interface": name, "ssid": str(info["ssid"] or "")},
                    "fields": fields,
                    "time": now,
                }
            )
        return result

    # -- helpers -------------------------------------------------------------

    async def _rfkill_blocked(self) -> bool | None:
        """Whether rfkill reports a blocked wireless radio (None when unknown)."""
        command = await self.tools.run(["rfkill", "list"], timeout=5.0)
        if not command.ok:
            logger.debug("rfkill list unavailable: %s", command.error)
            return None
        return _parse_rfkill(command.stdout)

    @staticmethod
    def _link_payload(link: WifiLink, rfkill_blocked: bool | None) -> dict[str, Any]:
        """Contract-shaped payload for one wireless interface."""
        quality = signal_to_quality(link.signal_dbm) if link.signal_dbm is not None else None
        return {
            "name": link.interface,
            "connected": link.connected,
            "ssid": link.ssid,
            "bssid": link.bssid,
            "signal_dbm": link.signal_dbm,
            "noise_dbm": None,
            "quality_percent": quality,
            "bitrate_mbps": link.bitrate_mbps,
            "channel": link.channel,
            "frequency_mhz": link.frequency_mhz,
            "band": link.band,
            "tx_power_dbm": link.tx_power_dbm,
            "security": None,
            "standard": None,
            "link_quality": round(quality / 100.0, 4) if quality is not None else None,
            "clients": [dict(client) for client in link.clients],
            "rfkill_blocked": rfkill_blocked,
            "error": link.error,
        }


__all__ = ["WifiCollector"]
