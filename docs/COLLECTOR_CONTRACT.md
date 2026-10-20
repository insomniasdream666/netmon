# NetMon Collector Contract

This document is the authoritative interface between the seven collectors and
the rest of NetMon (health checker, TUI, web API, InfluxDB writer). Every
collector subclasses `netmon.collectors.base.BaseCollector` and returns a
`CollectionResult` whose `data` payload matches the schema below.

## Common rules

- `collect()` must never raise for recoverable problems; report them in
  `result.errors` and keep `result.ok` true when partial data was gathered.
- Set `result.ok = False` only when no usable data could be collected.
- Every metric dict has the shape
  `{"measurement": str, "tags": {str: str}, "fields": {str: number}, "time": datetime}`.
- Booleans are written as `1`/`0` in InfluxDB fields.
- Never emit emoji or ANSI colour codes in `data` or `errors`.
- Missing values are `None`, never the string `"N/A"`.
- Timestamps are timezone-aware UTC datetimes.

## Interval / measurement summary

| Collector | Config interval key | InfluxDB measurement |
|---|---|---|
| interfaces | `interfaces` (2s) | `interface_metrics` |
| connectivity | `connectivity` (10s) | `connectivity` |
| bandwidth | `bandwidth` (5s) | `bandwidth` |
| ports | `ports` (300s) | `port_scan` |
| connections | `connections` (15s) | `connections` |
| wifi | `wifi` (30s) | `wifi` |
| certificates | `certificates` (3600s) | `certificates` |

## 1. `interfaces`

Sources: `psutil.net_if_addrs`, `psutil.net_if_stats`, `psutil.net_io_counters`,
`/proc/net/route` (or `ip -j route`), `/etc/resolv.conf`.

```jsonc
{
  "hostname": "kali",
  "interfaces": {
    "eth0": {
      "name": "eth0",
      "is_up": true,
      "is_loopback": false,
      "is_wireless": false,
      "ipv4": ["192.168.1.20"],
      "ipv6": ["fe80::1"],
      "mac": "aa:bb:cc:dd:ee:ff",
      "mtu": 1500,
      "speed_mbps": 1000,
      "duplex": "full",
      "rx_bytes": 1234567, "tx_bytes": 7654321,
      "rx_packets": 10000, "tx_packets": 9000,
      "rx_errors": 0, "tx_errors": 0,
      "rx_dropped": 0, "tx_dropped": 0,
      "gateway": "192.168.1.1",
      "dns_servers": ["1.1.1.1"]
    }
  },
  "default_route": {"gateway": "192.168.1.1", "interface": "eth0", "metric": 100},
  "interfaces_count": 2,
  "up_count": 1
}
```

Metrics: `interface_metrics` tagged `interface`, `hostname` with fields
`rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors, rx_dropped,
tx_dropped, mtu, is_up`.

## 2. `connectivity`

Sources: `ping -c N -W timeout`, `dig`/`dnspython`, `traceroute` (or `tracepath`).

```jsonc
{
  "ping": {
    "8.8.8.8": {"target": "8.8.8.8", "latency_ms": 12.4, "packet_loss": 0.0,
                 "success": true, "transmitted": 3, "received": 3, "jitter_ms": 1.2}
  },
  "dns": {
    "google.com": {"name": "google.com", "latency_ms": 18.2, "success": true,
                    "addresses": ["142.250.185.78"], "error": null}
  },
  "traceroute": {
    "8.8.8.8": {"target": "8.8.8.8", "success": true, "duration_ms": 1500.0,
                 "hops": [{"hop": 1, "address": "192.168.1.1", "host": null, "rtt_ms": 1.1}],
                 "error": null}
  },
  "gateway": {"gateway": "192.168.1.1", "reachable": true, "latency_ms": 1.2, "packet_loss": 0.0},
  "internet": {"reachable": true, "targets_ok": 3, "targets_total": 3,
                "avg_latency_ms": 14.1, "avg_packet_loss": 0.0},
  "dns_health": {"healthy": true, "failures": 0, "total": 3,
                  "avg_latency_ms": 20.5, "failure_rate": 0.0}
}
```

Metrics: `connectivity` tagged `target`, `type` (`ping|dns|gateway|internet`)
with fields `latency_ms, packet_loss, success`.

## 3. `bandwidth`

Source: `psutil.net_io_counters` sampled twice against the previous collection.

```jsonc
{
  "interfaces": {
    "eth0": {"name": "eth0", "rx_bytes_per_sec": 125000.0, "tx_bytes_per_sec": 8000.0,
              "rx_packets_per_sec": 100.0, "tx_packets_per_sec": 50.0,
              "rx_mbps": 1.0, "tx_mbps": 0.064,
              "utilization_percent": 0.1, "link_speed_mbps": 1000}
  },
  "totals": {"rx_bytes_per_sec": 125000.0, "tx_bytes_per_sec": 8000.0},
  "sample_interval_s": 5.0
}
```

`utilization_percent` is `None` when the link speed is unknown.

Metrics: `bandwidth` tagged `interface` with fields
`rx_bytes_per_sec, tx_bytes_per_sec, rx_packets_per_sec, tx_packets_per_sec, utilization_percent`.

## 4. `ports`

Source: `python-nmap` when available, otherwise the `nmap` binary via
`run_command`. Runs at most `monitoring.port_scan.max_targets` targets per cycle.

```jsonc
{
  "targets": {
    "127.0.0.1": {"target": "127.0.0.1", "hostname": "localhost", "state": "up",
                   "scan_duration_ms": 820.0, "error": null,
                   "open_ports": [{"port": 22, "protocol": "tcp", "service": "ssh",
                                    "product": "OpenSSH", "version": "9.6"}]}
  },
  "scanned": 1, "total_open": 1
}
```

Metrics: `port_scan` tagged `target`, `protocol` with fields
`open_ports` (count), `scan_duration_ms`.

## 5. `connections`

Source: `ss -tunap` (fallback: `psutil.net_connections(kind="inet")`).

```jsonc
{
  "summary": {"total": 42, "tcp": 30, "udp": 12, "unix": 0,
               "established": 18, "listen": 6, "time_wait": 4},
  "listening": [{"protocol": "tcp", "local_address": "0.0.0.0", "local_port": 22,
                  "process": "sshd", "pid": 812, "family": "inet"}],
  "established": [{"protocol": "tcp", "local_address": "192.168.1.20",
                    "local_port": 51000, "remote_address": "142.250.185.78",
                    "remote_port": 443, "state": "ESTAB", "process": "firefox",
                    "pid": 2210, "family": "inet"}],
  "top_remote": [{"address": "142.250.185.78", "count": 6}],
  "top_processes": [{"name": "firefox", "pid": 2210, "connections": 12}]
}
```

Metrics: `connections` with fields `total, tcp, udp, established, listen, time_wait`.

## 6. `wifi`

Source: `iw dev <iface> link|station dump|info`, falling back to `iwconfig`.
Always report `has_wifi: false` on hosts without a wireless interface.

```jsonc
{
  "has_wifi": true,
  "interfaces": {
    "wlan0": {"name": "wlan0", "connected": true, "ssid": "HomeNet",
               "bssid": "aa:bb:cc:dd:ee:ff", "signal_dbm": -58, "noise_dbm": -95,
               "quality_percent": 71.0, "bitrate_mbps": 130.0, "channel": 36,
               "frequency_mhz": 5180, "band": "5GHz", "tx_power_dbm": 20.0,
               "security": "WPA2", "standard": "802.11ac", "link_quality": 0.71,
               "clients": [{"mac": "11:22:33:44:55:66", "signal_dbm": -62,
                             "inactive_ms": 120}],
               "error": null}
  },
  "note": null
}
```

Metrics: `wifi` tagged `interface`, `ssid` with fields
`signal_dbm, noise_dbm, quality_percent, bitrate_mbps, channel, connected`.

## 7. `certificates`

Source: `openssl s_client -connect host:port -servername host` piped through
`openssl x509 -noout -dates -subject -issuer`, or `openssl s_client -showcerts`.

```jsonc
{
  "certificates": {
    "github.com:443": {"target": "github.com:443", "host": "github.com", "port": 443,
                        "subject": "CN=github.com", "issuer": "C=US, O=DigiCert",
                        "not_before": "2026-01-01T00:00:00+00:00",
                        "not_after": "2026-12-31T23:59:59+00:00",
                        "days_remaining": 74, "expired": false, "self_signed": false,
                        "protocol": "TLSv1.3", "error": null}
  },
  "expiring_soon": ["github.com:443"],
  "expired": []
}
```

Metrics: `certificates` tagged `target` with fields `days_remaining, expired`.

## Health component mapping

| Component | Collector | Key inputs |
|---|---|---|
| interfaces | interfaces | `is_up`, `rx_errors`, `tx_errors` |
| connectivity | connectivity | `ping.*.latency_ms`, `packet_loss`, `success` |
| dns | connectivity | `dns_health.failure_rate`, `avg_latency_ms` |
| bandwidth | bandwidth | `utilization_percent` |
| wifi | wifi | `signal_dbm`, `connected` |
| certificates | certificates | `days_remaining`, `expired` |
| connections | connections | `summary.total`, `established` |
