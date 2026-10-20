"""Wrappers around Kali Linux network tooling.

NetMon deliberately shells out to the tools Kali already ships (``ip``, ``iw``,
``ss``, ``ping``, ``traceroute``, ``nmap``, ``openssl``, ``resolvectl``,
``journalctl``, ``systemctl``) instead of re-implementing kernel interfaces in
Python. This module provides three things:

* async command wrappers returning :class:`~netmon.utils.async_cmd.CommandResult`
* pure parsers for the text/XML formats those tools emit
* capability detection so callers can degrade gracefully on minimal systems
"""

from __future__ import annotations

import contextlib
import logging
import re
import shutil
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from netmon.utils.async_cmd import CommandResult, run_command
from netmon.utils.validation import validate_interface_name

logger = logging.getLogger(__name__)

PING_RE = re.compile(
    r"(?P<transmitted>\d+) packets transmitted, (?P<received>\d+) (?:packets )?received"
    r".*?(?P<loss>\d+(?:\.\d+)?)% packet loss",
    re.DOTALL,
)
RTT_RE = re.compile(
    r"rtt min/avg/max/(?:mdev|stddev) = (?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)/(?P<mdev>[\d.]+)"
)
SS_PROCESS_RE = re.compile(r'users:\(\("(?P<name>[^"]+)",pid=(?P<pid>\d+)')
IW_SIGNAL_RE = re.compile(r"signal:\s*(?P<signal>-?\d+)\s*dBm")
IW_FREQ_RE = re.compile(r"freq:\s*(?P<freq>\d+)")
IW_BITRATE_RE = re.compile(r"tx bitrate:\s*(?P<bitrate>[\d.]+)\s*(?P<unit>MBit/s|GBit/s|Mbit/s)")
IW_STATION_RE = re.compile(
    r"Station (?P<mac>[0-9a-f:]{17}).*?signal:\s*(?P<signal>-?\d+)\s*dBm.*?inactive time:\s*(?P<inactive>\d+)\s*ms",
    re.DOTALL,
)
IWCONFIG_RE = re.compile(
    r"(?P<iface>\S+)\s+IEEE (?P<standard>\S+)\s+ESSID:\"(?P<ssid>[^\"]*)\""
    r"(?P<rest>.*)",
    re.DOTALL,
)
CERT_DATE_RE = re.compile(r"notBefore=(?P<before>.+?)\nnotAfter=(?P<after>.+?)\n")
CERT_SUBJECT_RE = re.compile(r"subject=(?P<subject>.+?)\n")
CERT_ISSUER_RE = re.compile(r"issuer=(?P<issuer>.+?)\n")
TRACEROUTE_HOP_RE = re.compile(r"^\s*(?P<hop>\d+)\s+(?P<body>.*)$")
IP_RE = re.compile(r"(?P<addr>\d{1,3}(?:\.\d{1,3}){3})\s*$")


@dataclass(slots=True)
class ToolStatus:
    """Availability of an external tool."""

    name: str
    path: str | None

    @property
    def available(self) -> bool:
        """True when the tool was found on PATH."""
        return self.path is not None


@dataclass(slots=True)
class PingSummary:
    """Parsed ``ping`` output."""

    target: str
    transmitted: int = 0
    received: int = 0
    packet_loss: float = 100.0
    latency_ms: float | None = None
    rtt_min_ms: float | None = None
    rtt_max_ms: float | None = None
    jitter_ms: float | None = None
    success: bool = False
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Collector payload shape for one ping target."""
        return {
            "target": self.target,
            "transmitted": self.transmitted,
            "received": self.received,
            "packet_loss": self.packet_loss,
            "latency_ms": self.latency_ms,
            "rtt_min_ms": self.rtt_min_ms,
            "rtt_max_ms": self.rtt_max_ms,
            "jitter_ms": self.jitter_ms,
            "success": self.success,
            "error": self.error,
        }


@dataclass(slots=True)
class SocketEntry:
    """One row of ``ss`` output."""

    protocol: str
    state: str
    local_address: str
    local_port: int
    remote_address: str | None = None
    remote_port: int | None = None
    process: str | None = None
    pid: int | None = None
    family: str = "inet"

    def as_dict(self) -> dict[str, Any]:
        """Serialise for the connections collector."""
        return {
            "protocol": self.protocol,
            "state": self.state,
            "local_address": self.local_address,
            "local_port": self.local_port,
            "remote_address": self.remote_address,
            "remote_port": self.remote_port,
            "process": self.process,
            "pid": self.pid,
            "family": self.family,
        }


@dataclass(slots=True)
class WifiLink:
    """Parsed ``iw dev <iface> link`` output."""

    interface: str
    connected: bool = False
    ssid: str | None = None
    bssid: str | None = None
    signal_dbm: int | None = None
    frequency_mhz: int | None = None
    channel: int | None = None
    bitrate_mbps: float | None = None
    tx_power_dbm: float | None = None
    clients: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    @property
    def band(self) -> str | None:
        """Frequency band derived from the centre frequency."""
        if self.frequency_mhz is None:
            return None
        if self.frequency_mhz < 2500:
            return "2.4GHz"
        if self.frequency_mhz < 5900:
            return "5GHz"
        return "6GHz"

    def as_dict(self) -> dict[str, Any]:
        """Collector payload shape for one wireless interface."""
        return {
            "name": self.interface,
            "connected": self.connected,
            "ssid": self.ssid,
            "bssid": self.bssid,
            "signal_dbm": self.signal_dbm,
            "frequency_mhz": self.frequency_mhz,
            "channel": self.channel,
            "band": self.band,
            "bitrate_mbps": self.bitrate_mbps,
            "tx_power_dbm": self.tx_power_dbm,
            "clients": self.clients,
            "error": self.error,
        }


def frequency_to_channel(frequency_mhz: int) -> int | None:
    """Convert a centre frequency in MHz to its Wi-Fi channel number."""
    if frequency_mhz == 2484:
        return 14
    if 2412 <= frequency_mhz <= 2472:
        return (frequency_mhz - 2407) // 5
    if 5000 <= frequency_mhz <= 5895:
        return (frequency_mhz - 5000) // 5
    if 5955 <= frequency_mhz <= 7115:
        return (frequency_mhz - 5950) // 5
    return None


def signal_to_quality(signal_dbm: int) -> float:
    """Map an RSSI value in dBm to a 0-100 quality percentage."""
    clamped = max(-100, min(-30, int(signal_dbm)))
    return round((clamped + 100) * (100 / 70), 1)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def parse_ping_output(target: str, stdout: str, stderr: str = "") -> PingSummary:
    """Parse Linux ``ping`` output into a :class:`PingSummary`."""
    summary = PingSummary(target=target)
    if not stdout.strip():
        summary.error = stderr.strip().splitlines()[0] if stderr.strip() else "no output"
        return summary

    if match := PING_RE.search(stdout):
        summary.transmitted = int(match.group("transmitted"))
        summary.received = int(match.group("received"))
        summary.packet_loss = float(match.group("loss"))
    if match := RTT_RE.search(stdout):
        summary.latency_ms = float(match.group("avg"))
        summary.rtt_min_ms = float(match.group("min"))
        summary.rtt_max_ms = float(match.group("max"))
        summary.jitter_ms = float(match.group("mdev"))
    summary.success = summary.received > 0
    if not summary.success and summary.error is None:
        summary.error = stderr.strip().splitlines()[0] if stderr.strip() else None
    return summary


def _port_or_zero(text: str) -> int:
    """Parse a port that may be a wildcard (``*``) into 0."""
    try:
        return int(text)
    except ValueError:
        return 0


def _split_host_port(text: str) -> tuple[str, int]:
    """Split ``addr:port`` output, which may be ``[::1]:443`` or ``*:22``."""
    candidate = text.strip()
    if candidate.startswith("["):
        host, sep, port_text = candidate.rpartition("]:")
        if not sep:
            return candidate.strip("[]") or "*", 0
        return host.lstrip("[") or "*", _port_or_zero(port_text)
    host, sep, port_text = candidate.rpartition(":")
    if not sep:
        return candidate or "*", 0
    return host or "*", _port_or_zero(port_text)


def parse_ss_output(stdout: str, *, family: str = "inet") -> list[SocketEntry]:
    """Parse ``ss -tunap`` output into socket entries."""
    entries: list[SocketEntry] = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] in {"Netid", "State"}:
            continue
        protocol, state = parts[0], parts[1]
        if not protocol.startswith(("tcp", "udp")):
            continue
        local_index = 4
        peer_index = 5
        if len(parts) <= peer_index:
            continue
        local_address, local_port = _split_host_port(parts[local_index])
        remote_address: str | None = None
        remote_port: int | None = None
        peer_token = parts[peer_index]
        if "*" not in peer_token or ":" in peer_token:
            remote_address, remote_port = _split_host_port(peer_token)
            if remote_address in {"*", "0.0.0.0", "::"}:
                remote_address = None
        process: str | None = None
        pid: int | None = None
        if match := SS_PROCESS_RE.search(line):
            process = match.group("name")
            pid = int(match.group("pid"))
        entries.append(
            SocketEntry(
                protocol=protocol.rstrip("*"),
                state=state,
                local_address=local_address,
                local_port=local_port,
                remote_address=remote_address,
                remote_port=remote_port,
                process=process,
                pid=pid,
                family=family,
            )
        )
    return entries


def parse_iw_link(interface: str, stdout: str, stderr: str = "") -> WifiLink:
    """Parse ``iw dev <iface> link`` output."""
    link = WifiLink(interface=interface)
    text = stdout.strip()
    if not text or text.lower().startswith("not connected"):
        link.connected = False
        link.error = None if not stderr.strip() else stderr.strip().splitlines()[0]
        return link

    link.connected = True
    if match := re.search(r"Connected to (?P<bssid>[0-9a-f:]{17})", text):
        link.bssid = match.group("bssid")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("SSID:"):
            link.ssid = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("freq:") and (match := IW_FREQ_RE.search(stripped)):
            link.frequency_mhz = int(match.group("freq"))
            link.channel = frequency_to_channel(link.frequency_mhz)
        elif stripped.startswith("signal:") and (match := IW_SIGNAL_RE.search(stripped)):
            link.signal_dbm = int(match.group("signal"))
        elif stripped.startswith("tx bitrate:") and (match := IW_BITRATE_RE.search(stripped)):
            value = float(match.group("bitrate"))
            link.bitrate_mbps = value * 1000 if match.group("unit").lower().startswith("g") else value
        elif stripped.startswith("txpower:"):
            raw = stripped.split(":", 1)[1].strip().split()[0]
            with contextlib.suppress(ValueError):
                link.tx_power_dbm = float(raw)
    return link


def parse_iw_station_dump(stdout: str) -> list[dict[str, Any]]:
    """Parse ``iw dev <iface> station dump`` output into client entries."""
    clients: list[dict[str, Any]] = []
    for block in stdout.split("Station ")[1:]:
        mac = block.split()[0] if block.split() else ""
        signal: int | None = None
        inactive: int | None = None
        if match := re.search(r"signal:\s*(-?\d+) dBm", block):
            signal = int(match.group(1))
        if match := re.search(r"inactive time:\s*(\d+) ms", block):
            inactive = int(match.group(1))
        if mac:
            clients.append({"mac": mac, "signal_dbm": signal, "inactive_ms": inactive})
    return clients


def parse_iwconfig(stdout: str) -> dict[str, Any]:
    """Parse legacy ``iwconfig`` output for a single interface."""
    result: dict[str, Any] = {
        "ssid": None,
        "signal_dbm": None,
        "quality_percent": None,
        "bitrate_mbps": None,
        "standard": None,
    }
    if match := re.search(r'ESSID:"(?P<ssid>[^"]*)"', stdout):
        result["ssid"] = match.group("ssid")
    if match := re.search(r"Signal level[=:]\s*(-?\d+)\s*dBm", stdout):
        result["signal_dbm"] = int(match.group(1))
        result["quality_percent"] = signal_to_quality(int(match.group(1)))
    elif match := re.search(r"Signal level[=:]\s*(?P<quality>\d+)/100", stdout):
        quality = int(match.group("quality"))
        result["quality_percent"] = float(quality)
        result["signal_dbm"] = int(quality * 0.7 - 100)
    if match := re.search(r"Bit Rate[=:]\s*(?P<rate>[\d.]+)\s*(?P<unit>\S+)", stdout):
        value = float(match.group("rate"))
        unit = match.group("unit").lower()
        result["bitrate_mbps"] = value * 1000 if unit.startswith("g") else value
    if match := re.search(r"IEEE (?P<standard>\S+)", stdout):
        result["standard"] = match.group("standard")
    return result


def parse_certificate(stdout: str) -> dict[str, Any]:
    """Parse ``openssl x509 -noout -dates -subject -issuer`` output."""
    parsed: dict[str, Any] = {
        "subject": None,
        "issuer": None,
        "not_before": None,
        "not_after": None,
    }
    if match := CERT_SUBJECT_RE.search(stdout):
        parsed["subject"] = " ".join(match.group("subject").split())
    if match := CERT_ISSUER_RE.search(stdout):
        parsed["issuer"] = " ".join(match.group("issuer").split())
    if match := CERT_DATE_RE.search(stdout):
        for key, raw in (("not_before", match.group("before")), ("not_after", match.group("after"))):
            try:
                parsed[key] = datetime.strptime(raw.strip(), "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=UTC
                )
            except ValueError:
                parsed[key] = None
    return parsed


def days_until(moment: datetime | None) -> int | None:
    """Whole days from now until ``moment`` (negative when in the past)."""
    if moment is None:
        return None
    reference = moment if moment.tzinfo else moment.replace(tzinfo=UTC)
    return int((reference - datetime.now(UTC)).total_seconds() // 86400)


def parse_traceroute(stdout: str) -> list[dict[str, Any]]:
    """Parse ``traceroute``/``tracepath`` output into hop records."""
    hops: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        if not (match := TRACEROUTE_HOP_RE.match(line)):
            continue
        body = match.group("body").strip()
        if not body:
            continue
        addresses = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{6,})", body)
        rtts = [float(value) for value in re.findall(r"([\d.]+)\s*ms", body)]
        hostname = None
        if host_match := re.search(r"([A-Za-z0-9._-]+\.[A-Za-z]{2,})", body):
            hostname = host_match.group(1)
        hops.append(
            {
                "hop": int(match.group("hop")),
                "address": addresses[-1] if addresses else None,
                "host": hostname,
                "rtt_ms": min(rtts) if rtts else None,
            }
        )
    return hops


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    """Parse ``nmap -oX -`` output into NetMon's port-scan payload."""
    hosts: list[dict[str, Any]] = []
    if not xml_text.strip():
        return {"hosts": hosts, "total_open": 0}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.debug("nmap XML parse failed: %s", exc)
        return {"hosts": hosts, "total_open": 0, "error": f"XML parse error: {exc}"}

    total_open = 0
    for host in root.findall("host"):
        address = ""
        for addr in host.findall("address"):
            if addr.get("addrtype") in {"ipv4", "ipv6"} and not address:
                address = addr.get("addr", "")
        state_element = host.find("status")
        state = state_element.get("state", "unknown") if state_element is not None else "unknown"
        hostname = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            first = hostnames.find("hostname")
            if first is not None:
                hostname = first.get("name")

        open_ports: list[dict[str, Any]] = []
        for port in host.findall("ports/port"):
            port_state = port.find("state")
            if port_state is None or port_state.get("state") != "open":
                continue
            service = port.find("service")
            open_ports.append(
                {
                    "port": int(port.get("portid", 0)),
                    "protocol": port.get("protocol", "tcp"),
                    "service": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                }
            )
        total_open += len(open_ports)
        hosts.append(
            {
                "target": address,
                "hostname": hostname,
                "state": state,
                "open_ports": sorted(open_ports, key=lambda item: item["port"]),
            }
        )
    return {"hosts": hosts, "total_open": total_open}


def parse_proc_net_route(content: str) -> dict[str, Any]:
    """Parse ``/proc/net/route`` for the default gateway and its interface."""
    result: dict[str, Any] = {"gateway": None, "interface": None, "metric": None}
    best_metric: int | None = None
    for line in content.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        interface, destination, gateway_hex, _, _, metric = (
            fields[0],
            fields[1],
            fields[2],
            fields[3],
            fields[4],
            fields[6],
        )
        if destination != "00000000":
            continue
        try:
            gateway = ".".join(str(int(gateway_hex[i : i + 2], 16)) for i in (6, 4, 2, 0))
            metric_value = int(metric)
        except ValueError:
            continue
        if best_metric is None or metric_value < best_metric:
            best_metric = metric_value
            result = {"gateway": gateway, "interface": interface, "metric": metric_value}
    return result


def parse_resolvectl_status(stdout: str) -> dict[str, Any]:
    """Parse ``resolvectl status`` for DNS servers and per-link details."""
    servers: list[str] = []
    links: dict[str, dict[str, Any]] = {}
    current_link: str | None = None
    for line in stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Link ") and "(" in stripped:
            current_link = stripped.split("(", 1)[1].rstrip(")")
            links[current_link] = {"dns": [], "domains": []}
        elif stripped.startswith("Current DNS Server:"):
            value = stripped.split(":", 1)[1].strip()
            if value and value not in servers:
                servers.append(value)
        elif stripped.startswith("DNS Servers:"):
            for value in stripped.split(":", 1)[1].split():
                if value not in servers and re.match(r"^[0-9a-fA-F:.]+$", value):
                    servers.append(value)
        elif stripped.startswith("DNS Domain:") and current_link:
            links[current_link]["domains"] = stripped.split(":", 1)[1].split()
    return {"servers": servers, "links": links}


# ---------------------------------------------------------------------------
# Command wrappers
# ---------------------------------------------------------------------------


class KaliTools:
    """Async wrappers around the network tools shipped with Kali Linux.

    Every method tolerates a missing binary and returns either a failure
    result or an empty structure, so collectors never crash on stripped-down
    systems.
    """

    def __init__(self, *, default_timeout: float = 15.0) -> None:
        self.default_timeout = default_timeout
        self._which_cache: dict[str, str | None] = {}

    # -- capabilities --------------------------------------------------------

    def tool_status(self) -> dict[str, ToolStatus]:
        """Availability of every tool NetMon may call."""
        names = (
            "ip",
            "iw",
            "iwconfig",
            "ss",
            "ping",
            "ping6",
            "traceroute",
            "tracepath",
            "nmap",
            "openssl",
            "dig",
            "resolvectl",
            "journalctl",
            "systemctl",
            "nmcli",
            "ethtool",
            "arp",
        )
        return {name: ToolStatus(name=name, path=shutil.which(name)) for name in names}

    def available_tools(self) -> list[str]:
        """Names of the tools present on this host."""
        return [name for name, status in self.tool_status().items() if status.available]

    def clear_cache(self) -> None:
        """Forget cached lookups."""
        self._which_cache.clear()

    # -- generic helpers -----------------------------------------------------

    async def run(
        self,
        args: Sequence[str],
        *,
        timeout: float | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        """Run an arbitrary command with NetMon's standard timeout."""
        return await run_command(args, timeout=timeout or self.default_timeout, input_text=input_text)

    async def ip_addr_json(self, *, interface: str | None = None) -> list[dict[str, Any]]:
        """`ip -j addr show [iface]` parsed into JSON objects."""
        args = ["ip", "-j", "addr", "show"]
        if interface:
            args.append(validate_interface_name(interface))
        result = await self.run(args, timeout=8.0)
        if not result.ok:
            return []
        try:
            import json

            payload = json.loads(result.stdout or "[]")
            return payload if isinstance(payload, list) else []
        except ValueError:
            return []

    async def ip_route_json(self) -> list[dict[str, Any]]:
        """`ip -j route show` parsed into JSON objects."""
        result = await self.run(["ip", "-j", "route", "show"], timeout=8.0)
        if not result.ok:
            return []
        try:
            import json

            payload = json.loads(result.stdout or "[]")
            return payload if isinstance(payload, list) else []
        except ValueError:
            return []

    async def default_route(self) -> dict[str, Any]:
        """Current default route, from ``ip`` with a ``/proc`` fallback."""
        for route in await self.ip_route_json():
            if route.get("dst") == "default":
                return {
                    "gateway": route.get("gateway"),
                    "interface": route.get("dev"),
                    "metric": route.get("metric"),
                }
        try:
            with open("/proc/net/route", encoding="utf-8") as handle:
                return parse_proc_net_route(handle.read())
        except OSError:
            return {"gateway": None, "interface": None, "metric": None}

    async def dns_servers(self) -> list[str]:
        """Configured DNS servers, preferring ``resolvectl``."""
        if shutil.which("resolvectl"):
            result = await self.run(["resolvectl", "status"], timeout=6.0)
            if result.ok and (servers := parse_resolvectl_status(result.stdout)["servers"]):
                return list(servers)
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as handle:
                return [
                    line.split()[1]
                    for line in handle
                    if line.startswith("nameserver") and len(line.split()) > 1
                ]
        except OSError:
            return []

    async def resolvectl_status(self) -> str:
        """Raw ``resolvectl status`` output (empty when unavailable)."""
        result = await self.run(["resolvectl", "status"], timeout=8.0)
        return result.stdout if result.ok else ""

    # -- connectivity --------------------------------------------------------

    async def ping(
        self,
        target: str,
        *,
        count: int = 3,
        timeout: float = 6.0,
        interval: float = 0.3,
    ) -> PingSummary:
        """Ping a target and return the parsed summary."""
        binary = "ping6" if ":" in target else "ping"
        result = await self.run(
            [binary, "-c", str(count), "-i", str(interval), "-W", str(max(1, int(timeout - 1))), target],
            timeout=timeout + 2,
        )
        summary = parse_ping_output(target, result.stdout, result.stderr)
        if result.error and not summary.error:
            summary.error = result.error
        return summary

    async def traceroute(self, target: str, *, max_hops: int = 20, timeout: float = 25.0) -> dict[str, Any]:
        """Run traceroute and return hops plus timing metadata."""
        binary = "traceroute"
        args: list[str]
        if shutil.which("traceroute"):
            args = [binary, "-n", "-m", str(max_hops), "-w", "2", target]
        elif shutil.which("tracepath"):
            args = ["tracepath", "-m", str(max_hops), target]
        else:
            return {"target": target, "hops": [], "success": False, "error": "traceroute not installed"}

        result = await self.run(args, timeout=timeout)
        hops = parse_traceroute(result.stdout)
        return {
            "target": target,
            "hops": hops,
            "success": bool(hops),
            "duration_ms": round(result.duration_ms, 2),
            "error": None if hops else (result.error or "no hops parsed"),
        }

    async def nmap_scan(
        self,
        targets: Iterable[str],
        *,
        ports: str = "1-1024",
        protocol: str = "tcp",
        service_detection: bool = True,
        arguments: str = "",
        timeout: float = 240.0,
    ) -> dict[str, Any]:
        """Run nmap with XML output and parse the result.

        Requires the ``nmap`` binary. SYN scans (``-sS``) need root; NetMon
        defaults to a TCP connect scan so it also works unprivileged.
        """
        if not shutil.which("nmap"):
            return {"hosts": [], "total_open": 0, "error": "nmap not installed"}

        target_list = [str(target) for target in targets]
        if not target_list:
            return {"hosts": [], "total_open": 0, "error": "no targets configured"}

        args = ["nmap", "-oX", "-"]
        if protocol == "udp":
            args.append("-sU")
        elif protocol == "both":
            args.extend(["-sS", "-sU"])
        else:
            args.append("-sT")
        if ports:
            args.extend(["-p", ports])
        if service_detection:
            args.append("-sV")
        if arguments:
            args.extend(arguments.split())
        args.extend(target_list)

        result = await self.run(args, timeout=timeout)
        if result.timed_out:
            return {
                "hosts": [],
                "total_open": 0,
                "error": f"nmap timed out after {timeout:.0f}s",
                "duration_ms": round(result.duration_ms, 2),
            }
        parsed = parse_nmap_xml(result.stdout)
        parsed["duration_ms"] = round(result.duration_ms, 2)
        if result.error and not parsed.get("hosts"):
            parsed["error"] = result.error
        if result.stderr.strip():
            parsed["stderr"] = result.stderr.strip()[:2000]
        return parsed

    # -- sockets -------------------------------------------------------------

    async def ss_connections(self) -> list[SocketEntry]:
        """Active TCP/UDP sockets via ``ss -tunap``, with a psutil fallback."""
        if shutil.which("ss"):
            result = await self.run(["ss", "-tunap"], timeout=10.0)
            if result.ok:
                return parse_ss_output(result.stdout)
        return self._psutil_connections()

    @staticmethod
    def _psutil_connections() -> list[SocketEntry]:
        entries: list[SocketEntry] = []
        try:
            import psutil
        except ImportError:  # pragma: no cover - psutil is a hard dependency
            return entries
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            try:
                connections = psutil.net_connections(kind="tcp")
            except Exception:
                return entries
        except Exception:
            return entries

        for connection in connections:
            local_address = connection.laddr
            remote_address = connection.raddr
            process_name = None
            if connection.pid:
                try:
                    process_name = psutil.Process(connection.pid).name()
                except Exception:
                    process_name = None
            entries.append(
                SocketEntry(
                    protocol="tcp" if connection.type.name == "SOCK_STREAM" else "udp",
                    state=connection.status,
                    local_address=local_address.ip if local_address else "*",
                    local_port=local_address.port if local_address else 0,
                    remote_address=remote_address.ip if remote_address else None,
                    remote_port=remote_address.port if remote_address else None,
                    process=process_name,
                    pid=connection.pid,
                )
            )
        return entries

    # -- wifi ----------------------------------------------------------------

    async def iw_link(self, interface: str, *, station_dump: bool = True) -> WifiLink:
        """Wireless link details for one interface, via ``iw`` then ``iwconfig``."""
        name = validate_interface_name(interface)
        if shutil.which("iw"):
            result = await self.run(["iw", "dev", name, "link"], timeout=8.0)
            link = parse_iw_link(name, result.stdout, result.stderr)
            if station_dump and link.connected:
                stations = await self.run(["iw", "dev", name, "station", "dump"], timeout=10.0)
                if stations.ok:
                    link.clients = parse_iw_station_dump(stations.stdout)
            if link.connected or result.ok:
                return link
        if shutil.which("iwconfig"):
            result = await self.run(["iwconfig", name], timeout=6.0)
            parsed = parse_iwconfig(result.stdout)
            link = WifiLink(
                interface=name,
                connected=bool(parsed.get("ssid")),
                ssid=parsed.get("ssid"),
                signal_dbm=parsed.get("signal_dbm"),
                bitrate_mbps=parsed.get("bitrate_mbps"),
                error=None if parsed.get("ssid") else (result.error or "no wireless data"),
            )
            return link
        return WifiLink(interface=name, error="neither iw nor iwconfig is installed")

    async def wireless_interfaces(self) -> list[str]:
        """Names of the host's wireless interfaces."""
        if shutil.which("iw"):
            result = await self.run(["iw", "dev"], timeout=6.0)
            if result.ok:
                names = re.findall(r"Interface\s+(\S+)", result.stdout)
                if names:
                    return names
        try:
            import psutil

            return [name for name in psutil.net_if_stats() if name.startswith("wl")]
        except Exception:
            return []

    # -- certificates --------------------------------------------------------

    async def certificate(self, host: str, port: int = 443, *, timeout: float = 12.0) -> dict[str, Any]:
        """Fetch and parse a TLS certificate's validity window."""
        if not shutil.which("openssl"):
            return {"error": "openssl not installed"}
        s_client = await self.run(
            [
                "openssl",
                "s_client",
                "-connect",
                f"{host}:{port}",
                "-servername",
                host,
                "-showcerts",
            ],
            timeout=timeout,
            input_text="",
        )
        if not s_client.stdout:
            return {"error": s_client.error or "openssl s_client produced no output"}

        details = await self.run(
            ["openssl", "x509", "-noout", "-dates", "-subject", "-issuer"],
            timeout=6.0,
            input_text=s_client.stdout,
        )
        parsed = parse_certificate(details.stdout)
        if not parsed.get("not_after"):
            return {"error": details.error or "could not parse certificate dates"}

        protocol = None
        if match := re.search(r"Protocol\s*:\s*(\S+)", s_client.stdout):
            protocol = match.group(1)
        parsed.update(
            {
                "host": host,
                "port": port,
                "protocol": protocol,
                "self_signed": bool(parsed.get("subject") and parsed.get("subject") == parsed.get("issuer")),
            }
        )
        return parsed

    # -- services and logs ---------------------------------------------------

    async def journalctl(
        self,
        units: Iterable[str] = (),
        *,
        since: str = "30 min ago",
        lines: int = 200,
        priority: str | None = None,
    ) -> str:
        """Fetch recent journal entries for the given units."""
        if not shutil.which("journalctl"):
            return ""
        args = ["journalctl", "--no-pager", "--since", since, "-n", str(lines), "-o", "short-iso"]
        for unit in units:
            args.extend(["-u", unit])
        if priority:
            args.extend(["-p", priority])
        result = await self.run(args, timeout=15.0)
        return result.stdout if result.ok else (result.stderr or "")

    async def systemctl_status(self, unit: str) -> dict[str, Any]:
        """``systemctl is-active`` / ``is-enabled`` for one unit."""
        if not shutil.which("systemctl"):
            return {"unit": unit, "active": None, "enabled": None, "error": "systemctl not installed"}
        active = await self.run(["systemctl", "is-active", unit], timeout=8.0)
        enabled = await self.run(["systemctl", "is-enabled", unit], timeout=8.0)
        return {
            "unit": unit,
            "active": active.first_line(),
            "enabled": enabled.first_line(),
            "error": None,
        }

    async def nmcli_device_status(self) -> str:
        """Raw ``nmcli device status`` output."""
        if not shutil.which("nmcli"):
            return ""
        result = await self.run(["nmcli", "device", "status"], timeout=8.0)
        return result.stdout if result.ok else ""

    async def ethtool_stats(self, interface: str) -> str:
        """Raw ``ethtool -S`` output for one interface."""
        name = validate_interface_name(interface)
        if not shutil.which("ethtool"):
            return ""
        result = await self.run(["ethtool", "-S", name], timeout=8.0)
        return result.stdout if result.ok else ""


__all__ = [
    "KaliTools",
    "PingSummary",
    "SocketEntry",
    "ToolStatus",
    "WifiLink",
    "days_until",
    "frequency_to_channel",
    "parse_certificate",
    "parse_iw_link",
    "parse_iw_station_dump",
    "parse_iwconfig",
    "parse_nmap_xml",
    "parse_ping_output",
    "parse_proc_net_route",
    "parse_resolvectl_status",
    "parse_ss_output",
    "parse_traceroute",
    "signal_to_quality",
]
