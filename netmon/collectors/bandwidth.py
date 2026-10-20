"""Bandwidth collector: per-interface throughput from counter deltas.

``psutil.net_io_counters(pernic=True)`` is sampled once per collection and the
rates are computed against the previous sample kept on the collector instance
(protected by an :class:`asyncio.Lock`). Interface statistics supply the
negotiated link speed used by ``utilization_percent``; when the speed is
unknown the utilization is reported as ``None`` instead of a fabricated value.

The first collection after start-up always reports zero rates plus a note,
because a single counter snapshot contains no rate information.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psutil

from netmon.collectors.base import BaseCollector, CollectionResult
from netmon.config.settings import NetMonConfig
from netmon.integrations.kali_tools import KaliTools

logger = logging.getLogger(__name__)

MEASUREMENT = "bandwidth"
BITS_PER_MEGABIT = 1_000_000.0
MIN_ELAPSED_S = 1e-6
#: Linux ``IFF_LOOPBACK`` flag; not exported by psutil/socket on every build.
IFF_LOOPBACK_FLAG = 0x8
FIRST_SAMPLE_NOTE = "first sample; rates are zero until the next collection"


@dataclass(slots=True)
class _Counters:
    """Raw interface counters captured at one sampling instant."""

    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int


def _has_flag(stats: Any, flag_name: str, flag_bit: int) -> bool:
    """True when an interface flag is set.

    psutil below 7 reports ``flags`` as a bit mask; psutil 7 changed the
    attribute to a comma-separated string of names, so both are supported.
    """
    raw = getattr(stats, "flags", None)
    if isinstance(raw, str):
        return flag_name in raw.split(",")
    if raw is None:
        return False
    try:
        return bool(int(raw) & flag_bit)
    except (TypeError, ValueError):
        return False


def _is_loopback(name: str, stats: Any) -> bool:
    """True when the interface is the loopback device."""
    if name == "lo":
        return True
    return _has_flag(stats, "loopback", IFF_LOOPBACK_FLAG)


def _link_speed(stats: Any) -> int | None:
    """Negotiated link speed in Mbps, or None when the NIC does not report it."""
    speed = int(getattr(stats, "speed", 0) or 0)
    return speed if speed > 0 else None


class BandwidthCollector(BaseCollector):
    """Derives per-interface throughput and link utilization from psutil."""

    name = "bandwidth"
    timeout = 20.0

    def __init__(self, config: NetMonConfig, tools: KaliTools | None = None) -> None:
        """Store configuration and the previous counter sample."""
        super().__init__(interval=config.monitoring.interval_for(self.name))
        self.config = config
        self.tools = tools or KaliTools()
        self._lock = asyncio.Lock()
        self._previous: dict[str, _Counters] = {}
        self._previous_at: float | None = None

    async def collect(self) -> CollectionResult:
        """Sample counters and compute rates against the previous sample."""
        result = self.result()
        now = datetime.now(UTC)

        async with self._lock:
            sampled_at = time.monotonic()
            counters = self._read_counters(result)
            stats = self._read_stats(result)
            elapsed = (
                None
                if self._previous_at is None
                else max(sampled_at - self._previous_at, MIN_ELAPSED_S)
            )
            first_sample = elapsed is None
            previous = self._previous
            self._previous = {
                name: _Counters(
                    rx_bytes=int(getattr(io, "bytes_recv", 0) or 0),
                    tx_bytes=int(getattr(io, "bytes_sent", 0) or 0),
                    rx_packets=int(getattr(io, "packets_recv", 0) or 0),
                    tx_packets=int(getattr(io, "packets_sent", 0) or 0),
                )
                for name, io in counters.items()
            }
            self._previous_at = sampled_at

            interfaces: dict[str, dict[str, Any]] = {}
            total_rx = 0.0
            total_tx = 0.0
            for name in sorted(counters):
                if self.config.monitoring.ignores_interface(name):
                    continue
                if _is_loopback(name, stats.get(name)):
                    continue

                io = counters[name]
                rx_bytes = int(getattr(io, "bytes_recv", 0) or 0)
                tx_bytes = int(getattr(io, "bytes_sent", 0) or 0)
                rx_packets = int(getattr(io, "packets_recv", 0) or 0)
                tx_packets = int(getattr(io, "packets_sent", 0) or 0)

                if elapsed is not None and name in previous:
                    previous_sample = previous[name]
                    rx_rate = max(0.0, (rx_bytes - previous_sample.rx_bytes) / elapsed)
                    tx_rate = max(0.0, (tx_bytes - previous_sample.tx_bytes) / elapsed)
                    rx_packet_rate = max(0.0, (rx_packets - previous_sample.rx_packets) / elapsed)
                    tx_packet_rate = max(0.0, (tx_packets - previous_sample.tx_packets) / elapsed)
                else:
                    rx_rate = tx_rate = rx_packet_rate = tx_packet_rate = 0.0

                speed_mbps = _link_speed(stats.get(name))
                rx_mbps = round(rx_rate * 8 / BITS_PER_MEGABIT, 3)
                tx_mbps = round(tx_rate * 8 / BITS_PER_MEGABIT, 3)
                utilization = (
                    round(max(rx_mbps, tx_mbps) / speed_mbps * 100, 2)
                    if speed_mbps is not None
                    else None
                )

                interfaces[name] = {
                    "name": name,
                    "rx_bytes_per_sec": round(rx_rate, 2),
                    "tx_bytes_per_sec": round(tx_rate, 2),
                    "rx_packets_per_sec": round(rx_packet_rate, 2),
                    "tx_packets_per_sec": round(tx_packet_rate, 2),
                    "rx_mbps": rx_mbps,
                    "tx_mbps": tx_mbps,
                    "utilization_percent": utilization,
                    "link_speed_mbps": speed_mbps,
                }
                total_rx += rx_rate
                total_tx += tx_rate

        result.data.update(
            {
                "interfaces": interfaces,
                "totals": {
                    "rx_bytes_per_sec": round(total_rx, 2),
                    "tx_bytes_per_sec": round(total_tx, 2),
                },
                "sample_interval_s": round(elapsed, 3) if elapsed is not None else 0.0,
            }
        )
        if first_sample:
            result.data["note"] = FIRST_SAMPLE_NOTE
        if not interfaces:
            result.ok = False
            result.add_error("no interfaces available for bandwidth measurement")
            return result

        for name, info in interfaces.items():
            fields: dict[str, Any] = {
                "rx_bytes_per_sec": info["rx_bytes_per_sec"],
                "tx_bytes_per_sec": info["tx_bytes_per_sec"],
                "rx_packets_per_sec": info["rx_packets_per_sec"],
                "tx_packets_per_sec": info["tx_packets_per_sec"],
            }
            if info["utilization_percent"] is not None:
                fields["utilization_percent"] = info["utilization_percent"]
            result.metrics.append(
                {
                    "measurement": MEASUREMENT,
                    "tags": {"interface": name},
                    "fields": fields,
                    "time": now,
                }
            )
        return result

    # -- source helpers ------------------------------------------------------

    @staticmethod
    def _read_counters(result: CollectionResult) -> dict[str, Any]:
        """``psutil.net_io_counters(pernic=True)``, isolating failures."""
        try:
            return dict(psutil.net_io_counters(pernic=True))
        except Exception as exc:
            logger.debug("net_io_counters failed: %s", exc)
            result.add_error(f"psutil net_io_counters failed: {exc}")
            return {}

    @staticmethod
    def _read_stats(result: CollectionResult) -> dict[str, Any]:
        """``psutil.net_if_stats()``, isolating failures."""
        try:
            return dict(psutil.net_if_stats())
        except Exception as exc:
            logger.debug("net_if_stats failed: %s", exc)
            result.add_error(f"psutil net_if_stats failed: {exc}")
            return {}


__all__ = ["BandwidthCollector"]
