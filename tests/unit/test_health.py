"""Unit tests for health evaluation."""

from __future__ import annotations

import pytest

from netmon.config.settings import HealthSettings
from netmon.core.health import HealthChecker, HealthState, SystemSnapshot


@pytest.fixture()
def checker() -> HealthChecker:
    return HealthChecker(HealthSettings())


def test_empty_snapshot_reports_unknown_components(checker: HealthChecker) -> None:
    report = checker.evaluate(SystemSnapshot())
    assert report.score == 0.0
    assert report.state == str(HealthState.UNKNOWN)
    assert all(component.state == str(HealthState.UNKNOWN) for component in report.components)
    assert report.issues == []


def test_healthy_snapshot_scores_full_marks(checker: HealthChecker) -> None:
    snapshot = SystemSnapshot(
        interfaces={
            "hostname": "kali",
            "interfaces": {
                "eth0": {"name": "eth0", "is_up": True, "is_loopback": False, "rx_errors": 0, "tx_errors": 0}
            },
        },
        connectivity={
            "ping": {"8.8.8.8": {"target": "8.8.8.8", "latency_ms": 12.0, "packet_loss": 0.0, "success": True}},
            "gateway": {"gateway": "192.168.1.1", "reachable": True, "latency_ms": 1.0, "packet_loss": 0.0},
            "dns": {"google.com": {"name": "google.com", "latency_ms": 18.0, "success": True}},
            "dns_health": {"healthy": True, "failures": 0, "total": 1, "avg_latency_ms": 18.0, "failure_rate": 0.0},
            "internet": {"reachable": True, "targets_ok": 1, "targets_total": 1, "avg_latency_ms": 12.0, "avg_packet_loss": 0.0},
        },
        bandwidth={"interfaces": {"eth0": {"name": "eth0", "utilization_percent": 3.0}}},
        connections={"summary": {"total": 42, "established": 10, "listen": 5}},
    )
    report = checker.evaluate(snapshot)
    assert report.score == 100.0
    assert report.state == str(HealthState.OK)
    assert report.issues == []
    assert report.component("connectivity").score == 100.0
    assert report.component("dns").score == 100.0


def test_gateway_unreachable_is_critical(checker: HealthChecker) -> None:
    snapshot = SystemSnapshot(
        connectivity={
            "gateway": {"gateway": "192.168.1.1", "reachable": False, "packet_loss": 100.0},
            "ping": {"8.8.8.8": {"target": "8.8.8.8", "latency_ms": None, "packet_loss": 100.0, "success": False}},
        }
    )
    report = checker.evaluate(snapshot)
    assert report.state == str(HealthState.CRITICAL)
    types = {issue.issue_type for issue in report.issues}
    assert "gateway_unreachable" in types
    assert "internet_unreachable" in types

    gateway_issue = next(issue for issue in report.issues if issue.issue_type == "gateway_unreachable")
    assert gateway_issue.severity == "critical"
    assert gateway_issue.suggested_checks, "issues must carry actionable checks"
    assert gateway_issue.key.startswith("gateway_unreachable:connectivity:")


def test_high_latency_and_loss_thresholds(checker: HealthChecker) -> None:
    snapshot = SystemSnapshot(
        connectivity={
            "ping": {
                "1.1.1.1": {"target": "1.1.1.1", "latency_ms": 250.0, "packet_loss": 8.0, "success": True},
            }
        }
    )
    report = checker.evaluate(snapshot)
    connectivity = report.component("connectivity")
    assert connectivity.score < 50
    assert {issue.issue_type for issue in connectivity.issues} == {"packet_loss_high"}
    assert connectivity.issues[0].severity == "critical"


def test_dns_failure_rate_and_warning_levels(checker: HealthChecker) -> None:
    partial = SystemSnapshot(
        connectivity={
            "dns": {"a.com": {"name": "a.com", "success": False}, "b.com": {"name": "b.com", "success": True}},
            "dns_health": {"failure_rate": 50.0, "avg_latency_ms": 20.0, "failures": 1, "total": 2},
        }
    )
    report = checker.evaluate(partial)
    dns = report.component("dns")
    assert dns.state == str(HealthState.CRITICAL)
    assert dns.issues[0].issue_type == "dns_failure"
    assert dns.issues[0].severity == "critical"

    slow = SystemSnapshot(
        connectivity={
            "dns": {"a.com": {"name": "a.com", "success": True}},
            "dns_health": {"failure_rate": 0.0, "avg_latency_ms": 150.0, "failures": 0, "total": 1},
        }
    )
    slow_report = checker.evaluate(slow)
    assert slow_report.component("dns").issues[0].issue_type == "dns_latency_high"
    assert slow_report.component("dns").issues[0].severity == "warning"


def test_wifi_states(checker: HealthChecker) -> None:
    weak = SystemSnapshot(
        wifi={"has_wifi": True, "interfaces": {"wlan0": {"name": "wlan0", "connected": True, "signal_dbm": -85, "ssid": "Home"}}}
    )
    report = checker.evaluate(weak)
    wifi = report.component("wifi")
    assert wifi.issues[0].issue_type == "wifi_weak_signal"
    assert wifi.issues[0].severity == "critical"

    disconnected = SystemSnapshot(
        wifi={"has_wifi": True, "interfaces": {"wlan0": {"name": "wlan0", "connected": False}}}
    )
    assert checker.evaluate(disconnected).component("wifi").issues[0].issue_type == "wifi_disconnected"

    absent = checker.evaluate(SystemSnapshot(wifi={"has_wifi": False, "interfaces": {}}))
    assert absent.component("wifi").state == str(HealthState.UNKNOWN)


def test_interval_types_are_reported_as_health_issues(checker: HealthChecker) -> None:
    snapshot = SystemSnapshot(
        interfaces={
            "interfaces": {
                "eth0": {"name": "eth0", "is_up": True, "is_loopback": False, "rx_errors": 5, "tx_errors": 0},
                "eth1": {"name": "eth1", "is_up": False, "is_loopback": False, "ipv4": []},
            }
        },
        bandwidth={"interfaces": {"eth0": {"name": "eth0", "utilization_percent": 97.0}}},
    )
    report = checker.evaluate(snapshot)
    types = {issue.issue_type for issue in report.issues}
    assert {"interface_errors", "interface_down", "bandwidth_saturated"} <= types
    assert report.component("interfaces").score < 100


def test_certificate_expiry_states(checker: HealthChecker) -> None:
    expiring = SystemSnapshot(
        certificates={
            "certificates": {
                "a.com:443": {"target": "a.com:443", "days_remaining": 5, "expired": False, "host": "a.com"},
            }
        }
    )
    report = checker.evaluate(expiring)
    assert report.component("certificates").issues[0].issue_type == "cert_expiring"

    expired = SystemSnapshot(
        certificates={"certificates": {"a.com:443": {"target": "a.com:443", "days_remaining": -3, "expired": True}}}
    )
    expired_report = checker.evaluate(expired)
    assert expired_report.component("certificates").issues[0].issue_type == "cert_expired"
    assert expired_report.component("certificates").issues[0].severity == "critical"


def test_connection_overload_warning(checker: HealthChecker) -> None:
    snapshot = SystemSnapshot(connections={"summary": {"total": 5000, "established": 4000, "listen": 10}})
    report = checker.evaluate(snapshot)
    assert report.component("connections").issues[0].issue_type == "connection_overload"


def test_loopback_and_unknown_components_do_not_penalise_score(checker: HealthChecker) -> None:
    snapshot = SystemSnapshot(
        interfaces={"interfaces": {"lo": {"name": "lo", "is_up": True, "is_loopback": True}}},
        connectivity={
            "ping": {"8.8.8.8": {"target": "8.8.8.8", "latency_ms": 10.0, "packet_loss": 0.0, "success": True}}
        },
    )
    report = checker.evaluate(snapshot)
    assert report.component("interfaces").state == str(HealthState.UNKNOWN)
    assert report.score == 100.0, "unknown components are excluded from the weighted score"


def test_weighted_score_uses_configured_weights() -> None:
    settings = HealthSettings(weights={"connectivity": 3.0, "interfaces": 1.0})
    checker = HealthChecker(settings)
    snapshot = SystemSnapshot(
        interfaces={"interfaces": {"eth0": {"name": "eth0", "is_up": False}}},
        connectivity={
            "ping": {"8.8.8.8": {"target": "8.8.8.8", "latency_ms": 10.0, "packet_loss": 0.0, "success": True}}
        },
    )
    report = checker.evaluate(snapshot)
    # connectivity scores 100 with weight 3, interfaces scores 0 with weight 1.
    assert report.score == pytest.approx(75.0)


def test_report_is_serialisable(checker: HealthChecker) -> None:
    report = checker.evaluate(
        SystemSnapshot(
            connectivity={"gateway": {"gateway": "10.0.0.1", "reachable": False, "packet_loss": 100.0}}
        )
    )
    payload = report.to_dict()
    assert payload["state"] == "critical"
    assert payload["issues"][0]["key"]
    assert isinstance(payload["components"], list)
    assert payload["checked_at"]
