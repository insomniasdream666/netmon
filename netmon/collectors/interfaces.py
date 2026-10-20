"""Interface inventory collector: link state, addresses, routes and counters.

Data sources:

* ``psutil.net_if_addrs`` / ``net_if_stats`` / ``net_io_counters`` for the
  authoritative kernel view of every NIC.
* ``ip -j addr show`` through :class:`~netmon.integrations.kali_tools.KaliTools`
  for addresses and link flags, including the carrier state used by the rule
  engine when diagnosing a down interface.
* ``ip route`` / ``/proc/net/route`` for the default route and
  ``resolvectl`` / ``/etc/resolv.conf`` for the configured DNS servers.

Interfaces matching ``monitoring.ignored_interfaces`` are omitted from both
the payload and the emitted metrics.
"""

from __future__ import annotations

import logging
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

from netmon.collectors.base import BaseCollector, CollectionResult
from netmon.config.settings import NetMonConfig
from netmon.integrations.kali_tools import KaliTools

logger = logging.getLogger(__name__)

MEASUREMENT = "interface_metrics"
SYS_CLASS_NET = Path("/sys/class/net")
#: Linux ``IFF_LOOPBACK`` flag; not exported by psutil/socket on every build.
IFF_LOOPBACK_FLAG = 0x8
#: Duplex values used by ``psutil.net_if_stats`` (NIC_DUPLEX_HALF/FULL).
DUPLEX_NAMES: dict[int, str] = {1: "half", 2: "full"}
OPERSTATE_UP = {"UP", "DORMANT"}
OPERSTATE_DOWN = {"DOWN", "LOWERLAYERDOWN", "NOTPRESENT"}


def _dedupe(values: list[str]) -> list[str]:
    """Order-preserving duplicate removal."""
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


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


def _duplex_name(stats: Any) -> str | None:
    """Duplex mode name, tolerating psutil int and enum representations."""
    raw = getattr(stats, "duplex", None)
    if raw is None:
        return None
    try:
        return DUPLEX_NAMES.get(int(raw))
    except (TypeError, ValueError):
        return None


def _read_carrier(interface: str) -> bool | None:
    """Carrier state from ``/sys/class/net/<iface>/carrier``.

    The kernel only exposes the file while the interface is administratively
    up, so an unreadable file means "unknown", never "no carrier".
    """
    try:
        raw = (SYS_CLASS_NET / interface / "carrier").read_text(encoding="ascii").strip()
    except OSError:
        return None
    return raw == "1"


def _carrier_state(interface: str, entry: dict[str, Any]) -> bool | None:
    """Carrier flag for one interface, preferring explicit ``ip`` data."""
    raw = entry.get("carrier")
    if isinstance(raw, bool):
        return raw
    if raw is not None:
        try:
            return bool(int(raw))
        except (TypeError, ValueError):
            logger.debug("unparsable carrier value for %s: %r", interface, raw)
    sysfs = _read_carrier(interface)
    if sysfs is not None:
        return sysfs
    operstate = str(entry.get("operstate") or "").upper()
    if operstate in OPERSTATE_UP:
        return True
    if operstate in OPERSTATE_DOWN:
        return False
    return None


def _addresses_from_ip(entry: dict[str, Any]) -> tuple[list[str], list[str]]:
    """IPv4 and IPv6 address lists from one ``ip -j addr show`` entry."""
    ipv4: list[str] = []
    ipv6: list[str] = []
    for info in entry.get("addr_info") or []:
        local = info.get("local")
        if not local:
            continue
        family = info.get("family")
        if family == "inet":
            ipv4.append(str(local))
        elif family == "inet6":
            ipv6.append(str(local))
    return _dedupe(ipv4), _dedupe(ipv6)


def _addresses_from_psutil(addrs: list[Any]) -> tuple[list[str], list[str], str | None]:
    """IPv4, IPv6 and MAC addresses for one interface, via psutil."""
    ipv4: list[str] = []
    ipv6: list[str] = []
    mac: str | None = None
    for addr in addrs:
        family = getattr(addr, "family", None)
        value = str(getattr(addr, "address", "") or "")
        if family == socket.AF_INET:
            ipv4.append(value)
        elif family == socket.AF_INET6:
            ipv6.append(value.split("%", 1)[0])
        elif family == psutil.AF_LINK:
            mac = value
    return _dedupe(ipv4), _dedupe(ipv6), mac or None


def _mac_from_ip(entry: dict[str, Any]) -> str | None:
    """Link-layer address from an ``ip -j`` entry, when it looks like a MAC."""
    value = str(entry.get("address") or "")
    if value.count(":") == 5 and len(value) == 17:
        return value
    return None


def _is_wireless(interface: str) -> bool:
    """True when sysfs or the interface name marks the NIC as wireless."""
    base = SYS_CLASS_NET / interface
    try:
        if (base / "wireless").exists() or (base / "phy80211").exists():
            return True
    except OSError:
        logger.debug("could not inspect sysfs for %s", interface)
    return interface.startswith("wl")


def _counter_value(io: Any, attribute: str) -> int | None:
    """One psutil counter as int, or None when the counters are unavailable."""
    if io is None:
        return None
    value = getattr(io, attribute, None)
    return int(value) if value is not None else None


class InterfacesCollector(BaseCollector):
    """Collects per-interface inventory, addresses and traffic counters."""

    name = "interfaces"
    timeout = 20.0

    def __init__(self, config: NetMonConfig, tools: KaliTools | None = None) -> None:
        """Store configuration and the tool wrapper used for ``ip`` calls."""
        super().__init__(interval=config.monitoring.interval_for(self.name))
        self.config = config
        self.tools = tools or KaliTools()

    async def collect(self) -> CollectionResult:
        """Collect interface inventory, addresses, routes and DNS servers."""
        result = self.result()
        now = datetime.now(UTC)
        hostname = self._hostname()

        stats = self._safe_stats(result)
        counters = self._safe_counters(result)
        psutil_addrs = self._safe_addrs(result)
        ip_entries = await self._ip_entries(result)
        route = await self.tools.default_route()
        dns_servers = await self.tools.dns_servers()

        default_interface = route.get("interface")
        gateway = route.get("gateway")
        interfaces: dict[str, dict[str, Any]] = {}
        for name in sorted(set(stats) | set(counters) | set(psutil_addrs) | set(ip_entries)):
            if self.config.monitoring.ignores_interface(name):
                continue
            interfaces[name] = self._build_interface(
                name,
                ip_entry=ip_entries.get(name, {}),
                stats=stats.get(name),
                counters=counters.get(name),
                psutil_addrs=psutil_addrs.get(name, []),
                is_default=default_interface == name,
                gateway=gateway,
                dns_servers=dns_servers,
            )

        result.data.update(
            {
                "hostname": hostname,
                "interfaces": interfaces,
                "default_route": {
                    "gateway": gateway,
                    "interface": default_interface,
                    "metric": route.get("metric"),
                },
                "interfaces_count": len(interfaces),
                "up_count": sum(1 for info in interfaces.values() if info["is_up"]),
            }
        )
        if not interfaces:
            result.ok = False
            result.add_error("no network interfaces could be collected")
            return result

        for name, info in interfaces.items():
            result.metrics.append(
                {
                    "measurement": MEASUREMENT,
                    "tags": {"interface": name, "hostname": hostname},
                    "fields": {
                        "rx_bytes": info["rx_bytes"],
                        "tx_bytes": info["tx_bytes"],
                        "rx_packets": info["rx_packets"],
                        "tx_packets": info["tx_packets"],
                        "rx_errors": info["rx_errors"],
                        "tx_errors": info["tx_errors"],
                        "rx_dropped": info["rx_dropped"],
                        "tx_dropped": info["tx_dropped"],
                        "mtu": info["mtu"],
                        "is_up": 1 if info["is_up"] else 0,
                    },
                    "time": now,
                }
            )
        return result

    # -- source helpers ------------------------------------------------------

    @staticmethod
    def _hostname() -> str:
        """Local hostname, or ``unknown`` when the system call fails."""
        try:
            return socket.gethostname()
        except OSError:
            return "unknown"

    @staticmethod
    def _safe_stats(result: CollectionResult) -> dict[str, Any]:
        """``psutil.net_if_stats()``, isolating psutil failures."""
        try:
            return dict(psutil.net_if_stats())
        except Exception as exc:
            logger.debug("net_if_stats failed: %s", exc)
            result.add_error(f"psutil net_if_stats failed: {exc}")
            return {}

    @staticmethod
    def _safe_counters(result: CollectionResult) -> dict[str, Any]:
        """``psutil.net_io_counters(pernic=True)``, isolating failures."""
        try:
            return dict(psutil.net_io_counters(pernic=True))
        except Exception as exc:
            logger.debug("net_io_counters failed: %s", exc)
            result.add_error(f"psutil net_io_counters failed: {exc}")
            return {}

    @staticmethod
    def _safe_addrs(result: CollectionResult) -> dict[str, list[Any]]:
        """``psutil.net_if_addrs()``, isolating psutil failures."""
        try:
            return {name: list(addrs) for name, addrs in psutil.net_if_addrs().items()}
        except Exception as exc:
            logger.debug("net_if_addrs failed: %s", exc)
            result.add_error(f"psutil net_if_addrs failed: {exc}")
            return {}

    async def _ip_entries(self, result: CollectionResult) -> dict[str, dict[str, Any]]:
        """``ip -j addr show`` entries keyed by interface name."""
        entries: dict[str, dict[str, Any]] = {}
        for entry in await self.tools.ip_addr_json():
            name = str(entry.get("ifname") or "")
            if name:
                entries[name] = entry
        if not entries:
            logger.debug("ip -j addr show returned no entries; using psutil addresses")
            result.add_error("ip address data unavailable; psutil addresses used instead")
        return entries

    # -- payload building ----------------------------------------------------

    def _build_interface(
        self,
        name: str,
        *,
        ip_entry: dict[str, Any],
        stats: Any,
        counters: Any,
        psutil_addrs: list[Any],
        is_default: bool,
        gateway: str | None,
        dns_servers: list[str],
    ) -> dict[str, Any]:
        """Contract-shaped inventory entry for one interface."""
        ipv4, ipv6 = _addresses_from_ip(ip_entry)
        psutil_ipv4, psutil_ipv6, psutil_mac = _addresses_from_psutil(psutil_addrs)
        operstate = str(ip_entry.get("operstate") or "").upper()

        is_up = bool(getattr(stats, "isup", False)) if stats is not None else operstate == "UP"
        is_loopback = name == "lo" or _has_flag(stats, "loopback", IFF_LOOPBACK_FLAG)
        speed = int(getattr(stats, "speed", 0) or 0)
        mtu = int(getattr(stats, "mtu", 0) or 0) or int(ip_entry.get("mtu") or 0)

        info: dict[str, Any] = {
            "name": name,
            "is_up": is_up,
            "is_loopback": is_loopback,
            "is_wireless": _is_wireless(name),
            "ipv4": ipv4 or psutil_ipv4,
            "ipv6": ipv6 or psutil_ipv6,
            "mac": psutil_mac or _mac_from_ip(ip_entry),
            "mtu": mtu or None,
            "speed_mbps": speed if speed > 0 else None,
            "duplex": _duplex_name(stats),
            "rx_bytes": _counter_value(counters, "bytes_recv"),
            "tx_bytes": _counter_value(counters, "bytes_sent"),
            "rx_packets": _counter_value(counters, "packets_recv"),
            "tx_packets": _counter_value(counters, "packets_sent"),
            "rx_errors": _counter_value(counters, "errin"),
            "tx_errors": _counter_value(counters, "errout"),
            "rx_dropped": _counter_value(counters, "dropin"),
            "tx_dropped": _counter_value(counters, "dropout"),
            "gateway": gateway if is_default else None,
            "dns_servers": list(dns_servers) if is_default else [],
        }
        # The rule engine treats any present ``carrier`` key as authoritative,
        # so the key is omitted when the state cannot be determined.
        carrier = _carrier_state(name, ip_entry)
        if carrier is not None:
            info["carrier"] = carrier
        return info


__all__ = ["InterfacesCollector"]
