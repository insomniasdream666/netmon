"""Unit tests for the Kali tool parsers.

These parsers sit between raw command output and the collector payloads, so
they are exercised against realistic sample output — including the IPv6
wildcard forms of ``ss`` that previously crashed the connection collector.
"""

from __future__ import annotations

from netmon.integrations.kali_tools import (
    _split_host_port,
    days_until,
    frequency_to_channel,
    parse_certificate,
    parse_iw_link,
    parse_iw_station_dump,
    parse_iwconfig,
    parse_nmap_xml,
    parse_ping_output,
    parse_proc_net_route,
    parse_resolvectl_status,
    parse_ss_output,
    parse_traceroute,
    signal_to_quality,
)

# ---------------------------------------------------------------------------
# ping
# ---------------------------------------------------------------------------

PING_OK = """PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=115 time=12.3 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=115 time=12.4 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=115 time=12.5 ms

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 12.300/12.400/12.500/0.081 ms
"""

PING_FAIL = """PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.

--- 10.0.0.1 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3060ms
"""


def test_parse_ping_output_success() -> None:
    summary = parse_ping_output("8.8.8.8", PING_OK)
    assert summary.success is True
    assert summary.transmitted == 3 and summary.received == 3
    assert summary.packet_loss == 0.0
    assert summary.latency_ms == 12.4
    assert summary.jitter_ms == 0.081


def test_parse_ping_output_total_loss() -> None:
    summary = parse_ping_output("10.0.0.1", PING_FAIL)
    assert summary.success is False
    assert summary.packet_loss == 100.0
    assert summary.latency_ms is None


def test_parse_ping_output_no_output_uses_stderr() -> None:
    summary = parse_ping_output("10.0.0.1", "", "ping: connect: Network is unreachable")
    assert summary.success is False
    assert summary.error == "ping: connect: Network is unreachable"


# ---------------------------------------------------------------------------
# ss
# ---------------------------------------------------------------------------

SS_OUTPUT = """Netid State  Recv-Q Send-Q Local Address:Port   Peer Address:Port Process
tcp   LISTEN 0      4096           [::]:22           [::]:*     users:(("sshd",pid=812,fd=3))
tcp   LISTEN 0      511           0.0.0.0:80         0.0.0.0:*  users:(("nginx",pid=900,fd=6))
udp   UNCONN 0      0             0.0.0.0:68         0.0.0.0:*
tcp   ESTAB  0      0       192.168.1.20:51000  142.250.185.78:443 users:(("firefox",pid=2210,fd=60))
tcp   ESTAB  0      0      [2001:db8::1]:51000  [2606:4700::1]:443
"""


def test_split_host_port_handles_ipv6_and_wildcards() -> None:
    assert _split_host_port("[::1]:443") == ("::1", 443)
    assert _split_host_port("[::]:*") == ("::", 0)
    assert _split_host_port("*:22") == ("*", 22)
    assert _split_host_port("0.0.0.0:68") == ("0.0.0.0", 68)
    assert _split_host_port("sshd") == ("sshd", 0)


def test_parse_ss_output_including_ipv6_listeners() -> None:
    entries = parse_ss_output(SS_OUTPUT)
    assert len(entries) == 5

    listener = entries[0]
    assert listener.protocol == "tcp" and listener.state == "LISTEN"
    assert (listener.local_address, listener.local_port) == ("::", 22)
    assert listener.remote_address is None, "wildcard peers mean no remote"
    assert listener.process == "sshd" and listener.pid == 812

    established = entries[3]
    assert established.remote_address == "142.250.185.78"
    assert established.remote_port == 443

    ipv6_peer = entries[4]
    assert ipv6_peer.local_address == "2001:db8::1"
    assert ipv6_peer.remote_address == "2606:4700::1"
    assert ipv6_peer.remote_port == 443


# ---------------------------------------------------------------------------
# iw / iwconfig
# ---------------------------------------------------------------------------

IW_LINK = """Connected to aa:bb:cc:dd:ee:ff (on wlan0)
        SSID: HomeNet
        freq: 5180
        signal: -58 dBm
        tx bitrate: 130.0 MBit/s
        txpower: 20.00 dBm
"""


def test_parse_iw_link_connected() -> None:
    link = parse_iw_link("wlan0", IW_LINK)
    assert link.connected is True
    assert link.ssid == "HomeNet"
    assert link.bssid == "aa:bb:cc:dd:ee:ff"
    assert link.signal_dbm == -58
    assert link.frequency_mhz == 5180 and link.channel == 36
    assert link.band == "5GHz"
    assert link.bitrate_mbps == 130.0
    assert link.tx_power_dbm == 20.0


def test_parse_iw_link_disconnected() -> None:
    link = parse_iw_link("wlan0", "Not connected.")
    assert link.connected is False
    assert link.ssid is None
    assert link.error is None


def test_parse_iw_station_dump() -> None:
    dump = """Station 11:22:33:44:55:66 (on wlan0)
        inactive time:  120 ms
        signal:         -62 dBm
        tx bitrate:     86.7 MBit/s
"""
    clients = parse_iw_station_dump(dump)
    assert clients == [{"mac": "11:22:33:44:55:66", "signal_dbm": -62, "inactive_ms": 120}]


def test_parse_iwconfig() -> None:
    output = """wlan0     IEEE 802.11ac  ESSID:"HomeNet"  Nickname:"<WIFI@REALTEK>"
          Mode:Managed  Frequency:5.18 GHz  Access Point: AA:BB:CC:DD:EE:FF
          Bit Rate=130 Mb/s   Tx-Power=20 dBm
          Signal level=-58 dBm
"""
    parsed = parse_iwconfig(output)
    assert parsed["ssid"] == "HomeNet"
    assert parsed["signal_dbm"] == -58
    assert parsed["quality_percent"] == signal_to_quality(-58)
    assert parsed["bitrate_mbps"] == 130.0
    assert parsed["standard"] == "802.11ac"


# ---------------------------------------------------------------------------
# certificates
# ---------------------------------------------------------------------------

CERT_OUTPUT = """subject=CN = github.com
issuer=C = US, O = DigiCert Inc, CN = DigiCert TLS RSA SHA256 2020 CA1
notBefore=Jan  1 00:00:00 2026 GMT
notAfter=Dec 31 23:59:59 2026 GMT
"""


def test_parse_certificate() -> None:
    parsed = parse_certificate(CERT_OUTPUT)
    assert parsed["subject"] == "CN = github.com"
    assert parsed["issuer"].startswith("C = US")
    assert parsed["not_before"] is not None and parsed["not_after"] is not None
    assert parsed["not_before"].year == 2026
    assert days_until(parsed["not_after"]) > 0


def test_days_until_past_and_none() -> None:
    from datetime import UTC, datetime, timedelta

    assert days_until(None) is None
    # Whole days, floored: a partial positive day does not count, and any
    # moment in the past rounds down so an expired certificate is negative.
    assert days_until(datetime.now(UTC) + timedelta(days=10)) == 9
    assert days_until(datetime.now(UTC) - timedelta(days=3, hours=1)) == -4


# ---------------------------------------------------------------------------
# traceroute / nmap
# ---------------------------------------------------------------------------


def test_parse_traceroute() -> None:
    output = """traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.100 ms  1.201 ms  1.300 ms
 2  * * *
 3  142.250.185.78 (142.250.185.78)  12.4 ms  12.9 ms  13.1 ms
"""
    hops = parse_traceroute(output)
    assert len(hops) == 3
    assert hops[0]["hop"] == 1 and hops[0]["address"] == "192.168.1.1"
    assert hops[1]["address"] is None, "all-star hop has no address"
    assert hops[2]["rtt_ms"] == 12.4, "the minimum RTT is reported"


NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
  <status state="up" reason="syn-ack"/>
  <address addr="192.168.1.10" addrtype="ipv4"/>
  <hostnames><hostname name="router.local" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
    <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
    <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
  </ports>
</host>
</nmaprun>
"""


def test_parse_nmap_xml() -> None:
    parsed = parse_nmap_xml(NMAP_XML)
    assert parsed["total_open"] == 2
    assert len(parsed["hosts"]) == 1

    host = parsed["hosts"][0]
    assert host["target"] == "192.168.1.10"
    assert host["hostname"] == "router.local"
    assert host["state"] == "up"
    assert [entry["port"] for entry in host["open_ports"]] == [22, 443]
    assert host["open_ports"][0]["service"] == "ssh"
    assert host["open_ports"][0]["product"] == "OpenSSH"


def test_parse_nmap_xml_malformed_input() -> None:
    parsed = parse_nmap_xml("<nmaprun>")
    assert parsed["hosts"] == []
    assert "error" in parsed


# ---------------------------------------------------------------------------
# /proc/net/route and resolvectl
# ---------------------------------------------------------------------------


def test_parse_proc_net_route_picks_best_metric() -> None:
    content = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth0\t0002A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
"""
    route = parse_proc_net_route(content)
    assert route == {"gateway": "192.168.2.1", "interface": "eth0", "metric": 100}


def test_parse_resolvectl_status() -> None:
    output = """Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub
Current DNS Server: 192.168.1.1
       DNS Servers: 192.168.1.1 fe80::1
        DNS Domain: lan

Link 2 (eth0)
    Current Scopes: DNS
         Protocols: -DefaultRoute
Current DNS Server: 1.1.1.1
       DNS Servers: 1.1.1.1 8.8.8.8
        DNS Domain: ~.
"""
    parsed = parse_resolvectl_status(output)
    assert parsed["servers"][0] == "192.168.1.1"
    assert "1.1.1.1" in parsed["servers"] and "8.8.8.8" in parsed["servers"]
    assert "eth0" in parsed["links"]
    assert parsed["links"]["eth0"]["domains"] == ["~."]


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def test_frequency_to_channel() -> None:
    assert frequency_to_channel(2484) == 14
    assert frequency_to_channel(2412) == 1
    assert frequency_to_channel(5180) == 36
    assert frequency_to_channel(5955) == 1
    assert frequency_to_channel(1000) is None


def test_signal_to_quality_bounds() -> None:
    assert signal_to_quality(-30) == 100.0
    assert signal_to_quality(-100) == 0.0
    assert signal_to_quality(-200) == 0.0
    assert signal_to_quality(-65) == 50.0
