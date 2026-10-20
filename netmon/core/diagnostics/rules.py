"""Rule-based fast path for common network faults.

The rule engine is the deterministic first line of diagnosis: it runs in
microseconds, works with no LLM available, and covers the faults NetMon sees
most often (gateway down, DNS failure, weak Wi-Fi, firewall drops, expiring
certificates). Each rule returns a :class:`RuleMatch` - a neutral verdict that
:class:`~netmon.core.diagnostics.engine.DiagnosticEngine` turns into a domain
:class:`~netmon.core.diagnostics.engine.Diagnosis`.

Rules are ordered by specificity; the first match for an issue wins.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from netmon.core.health import HealthIssue

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class RuleMatch:
    """A deterministic diagnosis produced by a rule."""

    rule_name: str
    diagnosis: str
    confidence: float
    fixes: list[dict[str, str]] = field(default_factory=list)
    risks: str = ""
    verify: str = ""
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the diagnostic history and API."""
        return {
            "rule_name": self.rule_name,
            "diagnosis": self.diagnosis,
            "confidence": self.confidence,
            "fixes": list(self.fixes),
            "risks": self.risks,
            "verify": self.verify,
            "explanation": self.explanation,
        }


def _fix(command: str, explanation: str, *, needs_root: bool = False) -> dict[str, str]:
    return {"command": command, "explanation": explanation, "requires_root": str(needs_root).lower()}


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

GATEWAY_PATTERNS = ("gateway_unreachable",)
DNS_PATTERNS = ("dns_failure", "dns_latency_high")
FIREWALL_HINTS = re.compile(r"(iptables|nftables|nft |ufw|firewalld|DROP|REJECT)", re.IGNORECASE)


def _gateway_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    gateway = str(issue.details.get("gateway") or "the default gateway")
    interface = _interface_from_context(context, gateway)
    return RuleMatch(
        rule_name="gateway-unreachable",
        diagnosis=(
            f"The default gateway {gateway} does not answer ARP/ICMP, so all off-link traffic "
            "fails at the first hop."
        ),
        confidence=85.0,
        fixes=[
            _fix("ip route show", "Inspect the routing table and confirm the default route is present."),
            _fix(f"arp -n {gateway}", "Check whether the gateway MAC address resolves; silence means L2 is down."),
            _fix(
                f"ping -c 3 {gateway}",
                "Confirm reachability of the gateway itself, bypassing name resolution.",
            ),
            _fix(
                f"nmcli device status && ip link show {interface}" if interface else "nmcli device status",
                "Verify the uplink interface is up and carried by NetworkManager.",
            ),
            _fix(
                "sudo systemctl restart NetworkManager",
                "Re-request a DHCP lease if the link is up but the gateway stays silent.",
                needs_root=True,
            ),
        ],
        risks=(
            "Restarting NetworkManager briefly drops all connectivity, including any remote session "
            "you are using."
        ),
        verify=f"ping -c 3 {gateway} && ip route show default",
        explanation="Gateway reachability is the first check; if it fails nothing beyond the local subnet works.",
    )


def _internet_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    target = str(issue.details.get("target") or "the internet target")
    gateway_ok = _gateway_reachable(context)
    if gateway_ok:
        diagnosis = (
            f"The gateway is reachable but {target} is not, so the fault is upstream of the local "
            "network (ISP, VPN tunnel or egress firewall)."
        )
        fixes = [
            _fix("mtr --report --report-cycles 10 1.1.1.1", "Locate the hop where packets are lost."),
            _fix("ip rule show && ip route show table all", "Check policy routing or a VPN default route hijack."),
            _fix("sudo iptables -L OUTPUT -n -v", "Confirm the egress firewall is not dropping traffic.", needs_root=True),
        ]
        confidence = 70.0
    else:
        diagnosis = (
            f"{target} is unreachable and so is the gateway, so the failure is local to this host "
            "or its access point."
        )
        fixes = [
            _fix("ip -brief addr show", "Confirm the host still holds an IP address."),
            _fix("ip route show default", "Confirm a default route still exists."),
            _fix("resolvectl status", "Rule out DNS as the reason the target name did not resolve."),
        ]
        confidence = 75.0
    return RuleMatch(
        rule_name="internet-unreachable",
        diagnosis=diagnosis,
        confidence=confidence,
        fixes=fixes,
        risks="No state is changed by these commands; they are read-only diagnostics.",
        verify="ping -c 3 1.1.1.1 && curl -sI https://1.1.1.1 | head -1",
        explanation="Comparing gateway and internet reachability separates local faults from upstream ones.",
    )


def _dns_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    servers = _dns_servers(context)
    failed = issue.details.get("failed") or []
    failed_text = ", ".join(str(name) for name in failed) if failed else "configured names"
    server_text = ", ".join(servers) if servers else "the configured resolvers"
    return RuleMatch(
        rule_name="dns-resolution-failure",
        diagnosis=(
            f"Name resolution fails for {failed_text} while using {server_text}, so the resolver "
            "path (stub resolver, DNS server reachability or search domains) is broken."
        ),
        confidence=80.0,
        fixes=[
            _fix("resolvectl status", "Show which per-link DNS servers systemd-resolved is actually using."),
            _fix("cat /etc/resolv.conf", "Check for a stale or loopback nameserver entry."),
            _fix("dig +short +time=2 google.com @1.1.1.1", "Test an external resolver directly, bypassing the stub."),
            _fix(
                "dig +short +time=2 google.com @127.0.0.53",
                "Test the local stub resolver to see whether the problem is local.",
            ),
            _fix(
                "sudo resolvectl flush-caches",
                "Discard poisoned or stale negative cache entries.",
                needs_root=True,
            ),
        ],
        risks=(
            "Flushing the resolver cache is harmless but momentarily slows the next lookups. "
            "Editing /etc/resolv.conf directly will be overwritten if systemd-resolved manages it."
        ),
        verify="dig +short google.com @1.1.1.1 && resolvectl query google.com",
        explanation="DNS failures usually come from an unreachable resolver or a misconfigured stub.",
    )


def _latency_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    target = str(issue.details.get("target") or "the target")
    latency = issue.value
    latency_text = f"{latency:.0f} ms" if isinstance(latency, (int, float)) else "above threshold"
    return RuleMatch(
        rule_name="high-latency",
        diagnosis=(
            f"Round-trip time to {target} is {latency_text}, which points to congestion, a saturated "
            "uplink or a distant route rather than a hard failure."
        ),
        confidence=65.0,
        fixes=[
            _fix(f"mtr --report --report-cycles 20 {target}", "Show per-hop latency and loss to find the slow hop."),
            _fix("ss -tunap state established | head -30", "Look for a local process saturating the link."),
            _fix("ip -s link show", "Check for interface errors or drops that inflate latency."),
            _fix("cat /proc/sys/net/ipv4/tcp_congestion_control", "Confirm which congestion control algorithm is active."),
        ],
        risks="Read-only diagnostics; nothing is modified.",
        verify=f"ping -c 10 {target}",
        explanation="Latency without loss is usually congestion or buffering, not a broken path.",
    )


def _loss_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    target = str(issue.details.get("target") or "the target")
    loss = issue.details.get("packet_loss")
    loss_text = f"{float(loss):.1f}%" if isinstance(loss, (int, float)) else "elevated"
    return RuleMatch(
        rule_name="packet-loss",
        diagnosis=(
            f"Packet loss to {target} is {loss_text}, indicating a congested or error-prone link "
            "(Wi-Fi interference, duplex mismatch or an overloaded uplink)."
        ),
        confidence=70.0,
        fixes=[
            _fix(f"mtr --report --report-cycles 20 {target}", "Identify the hop where loss first appears."),
            _fix("ethtool -S $(ip route get 1.1.1.1 | grep -oP 'dev \\K\\S+')", "Read NIC error counters for the egress interface."),
            _fix("ip -s link show", "Compare error and drop counters across interfaces."),
            _fix("iw dev $(iw dev | awk '/Interface/{print $2; exit}') link", "For wireless links, check signal and retry rates."),
        ],
        risks="Read-only diagnostics; the fix may require a cable, channel or bandwidth change.",
        verify=f"ping -c 20 {target}",
        explanation="Loss localises the fault differently from latency: it usually means a physical or wireless problem.",
    )


def _wifi_weak_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    interface = str(issue.details.get("interface") or "the wireless interface")
    ssid = issue.details.get("ssid")
    signal = issue.value
    signal_text = f"{int(signal)} dBm" if isinstance(signal, (int, float)) else "weak"
    return RuleMatch(
        rule_name="wifi-weak-signal",
        diagnosis=(
            f"{interface} is associated with {ssid or 'its access point'} but the signal is {signal_text}, "
            "so frames are being retried or dropped (interference, distance or channel congestion)."
        ),
        confidence=82.0,
        fixes=[
            _fix(f"iw dev {interface} link", "Confirm current SSID, band, channel and bitrate."),
            _fix("nmcli -f IN-USE,SSID,SIGNAL,CHAN,SECURITY device wifi list", "Compare nearby APs and pick a cleaner channel."),
            _fix(f"iw dev {interface} station dump", "Inspect retry and signal history for this link."),
            _fix(
                f"nmcli connection up id {ssid}" if ssid else f"nmcli device connect {interface}",
                "Re-associate to force the driver onto a better AP or band.",
            ),
        ],
        risks=(
            "Re-associating drops the link for a few seconds. If the AP is on a fixed channel, moving "
            "bands requires an AP-side change."
        ),
        verify=f"iw dev {interface} link | grep -E 'signal|bitrate'",
        explanation="Weak RSSI is the most common cause of Wi-Fi slowness and loss on laptops.",
    )


def _wifi_down_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    interface = str(issue.details.get("interface") or "the wireless interface")
    blocked = _rfkill_blocked(context)
    diagnosis = (
        f"{interface} is not associated with any access point"
        + (" and the radio appears to be blocked by rfkill." if blocked else ".")
    )
    fixes = [
        _fix("rfkill list", "Check for a hardware or software rfkill block."),
        _fix("nmcli device status", "Confirm NetworkManager state for the radio."),
        _fix(f"iw dev {interface} link", "Confirm the interface is not silently associated."),
    ]
    if blocked:
        fixes.insert(
            1,
            _fix("sudo rfkill unblock wifi", "Remove the software rfkill block on the Wi-Fi radio.", needs_root=True),
        )
    fixes.append(
        _fix(
            "nmcli device wifi connect <SSID> password <KEY>",
            "Rejoin the network once the radio is unblocked.",
        )
    )
    return RuleMatch(
        rule_name="wifi-disconnected",
        diagnosis=diagnosis,
        confidence=78.0 if blocked else 68.0,
        fixes=fixes,
        risks="Unblocking the radio re-enables transmission; make sure that is intended on this host.",
        verify=f"iw dev {interface} link && nmcli -f GENERAL.STATE device show {interface}",
        explanation="Radio blocks and saved-profile mismatches explain most Wi-Fi disconnections.",
    )


def _interface_down_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    interface = str(issue.details.get("interface") or "the interface")
    carrier = _carrier_state(context, interface)
    diagnosis = (
        f"{interface} is administratively or physically down"
        + (
            " with no carrier detected, which points at the cable, switch port or driver."
            if carrier is False
            else "."
        )
    )
    fixes = [
        _fix(f"ip link show {interface}", "Show administrative state, MTU and carrier flags."),
        _fix(f"ethtool {interface} | head -20", "Confirm the NIC sees a link partner and negotiated speed."),
        _fix("journalctl -u NetworkManager --since='10 min ago' --no-pager", "Look for driver or DHCP failures."),
        _fix(f"sudo ip link set {interface} up", "Bring the interface up administratively.", needs_root=True),
        _fix(
            f"sudo nmcli device connect {interface}",
            "Ask NetworkManager to re-run DHCP on the interface.",
            needs_root=True,
        ),
    ]
    return RuleMatch(
        rule_name="interface-down",
        diagnosis=diagnosis,
        confidence=75.0,
        fixes=fixes,
        risks=(
            "Bringing an interface down or re-running DHCP can interrupt an active remote session "
            "if this is your only uplink."
        ),
        verify=f"ip -brief link show {interface} && ip -brief addr show {interface}",
        explanation="A down interface with no carrier is almost always physical; with carrier it is configuration.",
    )


def _interface_errors_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    interface = str(issue.details.get("interface") or "the interface")
    errors = issue.value
    return RuleMatch(
        rule_name="interface-errors",
        diagnosis=(
            f"{interface} is up but reporting "
            f"{int(errors) if isinstance(errors, (int, float)) else 'elevated'} errors/drops, which typically means a "
            "bad cable, a duplex mismatch or a congested queue."
        ),
        confidence=72.0,
        fixes=[
            _fix(f"ip -s link show {interface}", "Read RX/TX error and drop counters per interface."),
            _fix(f"ethtool -S {interface}", "Read driver-level statistics to identify the error class."),
            _fix(f"ethtool {interface} | grep -E 'Speed|Duplex'", "Check for a speed/duplex downgrade."),
            _fix("journalctl -k --since='1 hour ago' --no-pager | tail -50", "Look for link flap messages in the kernel log."),
        ],
        risks="Read-only diagnostics; replacing a cable or renegotiating speed is required to fix the cause.",
        verify=f"ip -s link show {interface}",
        explanation="Error counters distinguish physical faults from software drops.",
    )


def _bandwidth_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    interface = str(issue.details.get("interface") or "the interface")
    utilization = issue.value
    return RuleMatch(
        rule_name="bandwidth-saturated",
        diagnosis=(
            f"{interface} is at {float(utilization):.0f}% of its link capacity"
            if isinstance(utilization, (int, float))
            else f"{interface} is near link saturation"
        )
        + ", so latency and loss will rise for every other flow sharing that link.",
        confidence=76.0,
        fixes=[
            _fix("ss -tunap | sort -k3 -n | tail -20", "List the sockets involved, largest queues first."),
            _fix(
                "sudo nethogs 2>/dev/null || ss -tunap | head -30",
                "Attribute the traffic to a process (nethogs when installed).",
                needs_root=True,
            ),
            _fix(
                "cat /proc/net/dev",
                "Confirm per-interface byte counters and spot which direction is saturating.",
            ),
            _fix(
                f"cat /sys/class/net/{interface}/statistics/tx_bytes",
                "Sample the interface counter twice to measure the current rate.",
            ),
        ],
        risks="Identifying a bandwidth hog may require stopping a backup, update or sync job.",
        verify=f"cat /sys/class/net/{interface}/statistics/tx_bytes",
        explanation="Saturation is a capacity problem; the fix is to find the consumer or raise the ceiling.",
    )


def _cert_expiring_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    target = str(issue.details.get("target") or issue.details.get("host") or "the endpoint")
    days = issue.value
    host = issue.details.get("host") or target.split(":")[0]
    days_text = f"{int(days)} days" if isinstance(days, (int, float)) else "soon"
    return RuleMatch(
        rule_name="certificate-expiring",
        diagnosis=(
            f"The TLS certificate presented by {target} expires in {days_text}, which will break "
            "HTTPS clients and monitoring checks once it lapses."
        ),
        confidence=90.0,
        fixes=[
            _fix(
                f"openssl s_client -connect {target} -servername {host} </dev/null 2>/dev/null | openssl x509 -noout -dates -issuer",
                "Confirm the exact expiry date and issuing CA.",
            ),
            _fix(
                f"sudo certbot renew --cert-name {host}",
                "Renew the certificate with certbot when it is the ACME client in use.",
                needs_root=True,
            ),
            _fix("sudo systemctl list-timers | grep -i certbot", "Verify the renewal timer is actually scheduled.", needs_root=True),
        ],
        risks=(
            "Renewal can be rate-limited by the CA and may reload the service that terminates TLS, "
            "briefly interrupting it."
        ),
        verify=f"echo | openssl s_client -connect {target} -servername {host} 2>/dev/null | openssl x509 -noout -enddate",
        explanation="Certificate expiry is predictable, so the fix is planned renewal rather than debugging.",
    )


def _cert_expired_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    target = str(issue.details.get("target") or "the endpoint")
    host = issue.details.get("host") or target.split(":")[0]
    return RuleMatch(
        rule_name="certificate-expired",
        diagnosis=(
            f"The TLS certificate for {target} has already expired, so every client validating the "
            "chain will refuse the connection."
        ),
        confidence=92.0,
        fixes=[
            _fix(
                f"openssl s_client -connect {target} -servername {host} </dev/null 2>/dev/null | openssl x509 -noout -dates",
                "Confirm the expiry window that clients are rejecting.",
            ),
            _fix("sudo certbot renew --force-renewal", "Force an immediate renewal.", needs_root=True),
            _fix(
                "sudo systemctl restart nginx",
                "Reload the TLS terminator so it picks up the renewed certificate.",
                needs_root=True,
            ),
        ],
        risks="Forcing a renewal consumes CA rate limit quota; restarting the web server drops in-flight requests.",
        verify=f"echo | openssl s_client -connect {target} -servername {host} 2>/dev/null | openssl x509 -noout -enddate",
        explanation="An expired certificate needs immediate renewal plus a service reload.",
    )


def _firewall_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    evidence_blob = " ".join(str(item) for item in issue.evidence) + " " + str(issue.details)
    if not FIREWALL_HINTS.search(evidence_blob) and not _firewall_active(context):
        return None
    return RuleMatch(
        rule_name="firewall-blocking",
        diagnosis=(
            "A host or network firewall rule is dropping traffic for this flow, so the packets never "
            "reach their destination or the replies are discarded."
        ),
        confidence=72.0,
        fixes=[
            _fix("sudo nft list ruleset | head -50", "Inspect the nftables ruleset for drop/reject rules.", needs_root=True),
            _fix("sudo iptables -S | head -50", "Inspect the iptables ruleset if iptables-nft is in use.", needs_root=True),
            _fix("sudo ufw status verbose", "Check the ufw profile and default policy.", needs_root=True),
            _fix(
                "sudo journalctl -k --since='30 min ago' --no-pager | grep -i -E 'DROP|REJECT|nft|iptables' | tail -30",
                "Read kernel log entries showing what is being dropped.",
                needs_root=True,
            ),
        ],
        risks=(
            "Do not flush rules blindly: on a remote host that locks you out. Always inspect before "
            "changing the default policy."
        ),
        verify="sudo nft list ruleset 2>/dev/null | head -20; sudo iptables -S 2>/dev/null | head -20",
        explanation="Silent drops with a reachable gateway are the classic firewall signature.",
    )


def _connection_overload_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    total = issue.value
    return RuleMatch(
        rule_name="connection-overload",
        diagnosis=(
            f"The host holds {int(total) if isinstance(total, (int, float)) else 'a large number of'} "
            "connections, which usually means a runaway client, a port scan or a missing TIMEWAIT cleanup."
        ),
        confidence=68.0,
        fixes=[
            _fix("ss -tunap state established | wc -l", "Count established sockets."),
            _fix("ss -tunap | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head", "Rank peers by connection count."),
            _fix("ss -tunap | grep -c TIME-WAIT", "Check for TIME_WAIT accumulation."),
            _fix("cat /proc/sys/net/ipv4/tcp_tw_reuse", "Check whether socket reuse is enabled."),
        ],
        risks="Killing the wrong process can drop production traffic; identify the owner first.",
        verify="ss -tunap | head -20",
        explanation="Connection count spikes are either abuse or a leak; the ranking shows which.",
    )


def _port_closed_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    target = str(issue.details.get("target") or "the host")
    port = issue.details.get("port")
    return RuleMatch(
        rule_name="port-closed",
        diagnosis=(
            f"TCP port {port} on {target} is not accepting connections, so the service is stopped, "
            "bound to another address, or filtered."
        ),
        confidence=74.0,
        fixes=[
            _fix(f"ss -tlnp | grep ': {port}'" if port else "ss -tlnp", "Check whether anything is listening locally."),
            _fix("sudo systemctl status <service>", "Confirm the service unit state.", needs_root=True),
            _fix(
                f"sudo nmap -Pn -p {port} {target}" if port else f"sudo nmap -Pn {target}",
                "Re-scan the exact port from this host to rule out a stale result.",
                needs_root=True,
            ),
            _fix("sudo ufw status verbose", "Check for a local firewall rule blocking the port.", needs_root=True),
        ],
        risks="Read-only diagnostics; starting a service may expose it to the network.",
        verify=f"nc -vz {target} {port}" if port else f"nmap -p- {target}",
        explanation="A closed port is either a stopped service or a filter; the listener check splits the two.",
    )


def _vpn_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    interfaces = _interface_names(context)
    tunnels = [name for name in interfaces if re.match(r"^(tun|tap|wg|ppp|ipsec)\d*", name)]
    if not tunnels:
        return None
    return RuleMatch(
        rule_name="vpn-tunnel",
        diagnosis=(
            f"A tunnel interface ({', '.join(tunnels)}) is present but traffic is failing, which suggests "
            "the VPN session dropped while its routes remained installed."
        ),
        confidence=66.0,
        fixes=[
            _fix("ip -brief addr show", "Confirm the tunnel interface state and address."),
            _fix("ip route show table all | head -30", "Check whether VPN routes are still installed."),
            _fix("sudo wg show", "For WireGuard, inspect the handshake and transfer counters.", needs_root=True),
            _fix("sudo systemctl restart wg-quick@<iface>", "Restart the tunnel to re-establish the session.", needs_root=True),
        ],
        risks="Restarting the tunnel drops all traffic routed through it and may change your public IP.",
        verify="ip -brief addr show && ping -c 3 1.1.1.1",
        explanation="Stale tunnel routes are a classic cause of 'internet works, some sites do not'.",
    )


def _dhcp_rule(issue: HealthIssue, context: Mapping[str, Any]) -> RuleMatch | None:
    interfaces = _interface_names(context)
    if not interfaces:
        return None
    return RuleMatch(
        rule_name="dhcp-no-lease",
        diagnosis=(
            "An interface is up but has no usable address, which usually means the DHCP lease expired "
            "or the server is unreachable."
        ),
        confidence=70.0,
        fixes=[
            _fix("ip -brief addr show", "Confirm which interfaces lack addresses."),
            _fix("nmcli -f GENERAL.STATE,IP4.ADDRESS device show", "Show NetworkManager's view of addressing."),
            _fix("journalctl -u NetworkManager --since='30 min ago' --no-pager | grep -i dhcp | tail -20", "Look for DHCP timeouts or NAKs."),
            _fix("sudo nmcli device reapply <iface>", "Re-run DHCP without bouncing the interface.", needs_root=True),
        ],
        risks="Reapplying DHCP briefly interrupts connectivity on that interface.",
        verify="ip -brief addr show && ip route show default",
        explanation="No address on an up interface points at DHCP rather than the physical layer.",
    )


@dataclass(slots=True)
class Rule:
    """A named predicate over a health issue."""

    name: str
    issue_types: tuple[str, ...]
    handler: Callable[[HealthIssue, Mapping[str, Any]], RuleMatch | None]
    description: str = ""


def _default_rules() -> list[Rule]:
    """Rule set in evaluation order; names match the verdicts they produce."""
    return [
        Rule("gateway-unreachable", GATEWAY_PATTERNS, _gateway_rule, "Default gateway is unreachable"),
        Rule("certificate-expired", ("cert_expired",), _cert_expired_rule, "Certificate has expired"),
        Rule("certificate-expiring", ("cert_expiring",), _cert_expiring_rule, "Certificate expires soon"),
        Rule("wifi-weak-signal", ("wifi_weak_signal",), _wifi_weak_rule, "Weak Wi-Fi signal"),
        Rule("wifi-disconnected", ("wifi_disconnected",), _wifi_down_rule, "Wi-Fi not associated"),
        Rule("interface-down", ("interface_down",), _interface_down_rule, "Interface is down"),
        Rule("interface-errors", ("interface_errors",), _interface_errors_rule, "Interface error counters rising"),
        Rule(
            "firewall-blocking",
            ("internet_unreachable", "gateway_unreachable", "port_closed"),
            _firewall_rule,
            "Firewall dropping traffic",
        ),
        Rule("vpn-tunnel", ("internet_unreachable", "dns_failure"), _vpn_rule, "VPN tunnel stale"),
        Rule("dhcp-no-lease", ("interface_down", "internet_unreachable"), _dhcp_rule, "No DHCP lease"),
        Rule("dns-resolution-failure", DNS_PATTERNS, _dns_rule, "DNS resolution failing or slow"),
        Rule("internet-unreachable", ("internet_unreachable",), _internet_rule, "Internet unreachable"),
        Rule("high-latency", ("latency_high",), _latency_rule, "Latency above threshold"),
        Rule("packet-loss", ("packet_loss_high",), _loss_rule, "Packet loss above threshold"),
        Rule("bandwidth-saturated", ("bandwidth_saturated",), _bandwidth_rule, "Link saturated"),
        Rule("connection-overload", ("connection_overload",), _connection_overload_rule, "Too many connections"),
        Rule("port-closed", ("port_closed",), _port_closed_rule, "Port not accepting connections"),
    ]


class RuleEngine:
    """Evaluates the ordered rule set against health issues.

    Args:
        rules: Optional rule override (used by tests).
        min_confidence: Matches below this confidence are discarded so the AI
            path gets a chance to do better.
    """

    def __init__(self, rules: list[Rule] | None = None, *, min_confidence: float = 40.0) -> None:
        self.rules = rules if rules is not None else _default_rules()
        self.min_confidence = min_confidence
        self._coverage: dict[str, int] = {}

    def match(self, issue: HealthIssue, context: Mapping[str, Any] | None = None) -> RuleMatch | None:
        """Return the first matching rule verdict, or None."""
        ctx: Mapping[str, Any] = context or {}
        for rule in self.rules:
            if issue.issue_type not in rule.issue_types:
                continue
            try:
                verdict = rule.handler(issue, ctx)
            except Exception as exc:
                logger.warning("rule %s raised: %s", rule.name, exc)
                continue
            if verdict is None:
                continue
            if verdict.confidence < self.min_confidence:
                continue
            self._coverage[verdict.rule_name] = self._coverage.get(verdict.rule_name, 0) + 1
            return verdict
        return None

    def coverage(self) -> dict[str, int]:
        """How often each rule has matched, for diagnostics of the engine itself."""
        return dict(self._coverage)

    def describe(self) -> list[dict[str, str]]:
        """List the configured rules (used by the docs and the settings screen)."""
        return [
            {"name": rule.name, "types": ", ".join(rule.issue_types), "description": rule.description}
            for rule in self.rules
        ]


# ---------------------------------------------------------------------------
# Context helpers - tolerant of missing keys
# ---------------------------------------------------------------------------


def _interface_map(context: Mapping[str, Any]) -> dict[str, Any]:
    """Interfaces dict from either a snapshot or a wrapped payload."""
    interfaces = context.get("interfaces") or {}
    if isinstance(interfaces, Mapping) and isinstance(interfaces.get("interfaces"), Mapping):
        interfaces = interfaces["interfaces"]
    return dict(interfaces) if isinstance(interfaces, Mapping) else {}


def _interface_names(context: Mapping[str, Any]) -> list[str]:
    return list(_interface_map(context))


def _interface_from_context(context: Mapping[str, Any], gateway: str) -> str | None:
    route = context.get("default_route") or {}
    if isinstance(route, Mapping) and route.get("interface"):
        return str(route["interface"])
    for name, info in _interface_map(context).items():
        if isinstance(info, Mapping) and info.get("gateway") == gateway:
            return str(name)
    return None


def _gateway_reachable(context: Mapping[str, Any]) -> bool:
    connectivity = context.get("connectivity") or {}
    if not isinstance(connectivity, Mapping):
        return False
    gateway = connectivity.get("gateway") or {}
    if isinstance(gateway, Mapping) and gateway.get("reachable"):
        return True
    internet = connectivity.get("internet") or {}
    return bool(internet.get("reachable")) if isinstance(internet, Mapping) else False


def _dns_servers(context: Mapping[str, Any]) -> list[str]:
    servers: list[str] = []
    for info in _interface_map(context).values():
        if isinstance(info, Mapping):
            servers.extend(str(item) for item in (info.get("dns_servers") or []))
    return sorted(set(servers))


def _carrier_state(context: Mapping[str, Any], interface: str) -> bool | None:
    entry = _interface_map(context).get(interface)
    if not isinstance(entry, Mapping):
        return None
    if "carrier" in entry:
        return bool(entry["carrier"])
    return None


def _rfkill_blocked(context: Mapping[str, Any]) -> bool:
    wifi = context.get("wifi") or {}
    if isinstance(wifi, Mapping):
        wifi_interfaces = wifi.get("interfaces") or {}
        if isinstance(wifi_interfaces, Mapping):
            for info in wifi_interfaces.values():
                if isinstance(info, Mapping) and info.get("rfkill_blocked"):
                    return True
    logs = str(context.get("logs") or "")
    return bool(re.search(r"rfkill|hard blocked|soft blocked", logs, re.IGNORECASE))


def _firewall_active(context: Mapping[str, Any]) -> bool:
    logs = str(context.get("logs") or "")
    return bool(FIREWALL_HINTS.search(logs))


__all__ = ["Rule", "RuleEngine", "RuleMatch"]
