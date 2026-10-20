"""Unit tests for the rule-based diagnostic fast path."""

from __future__ import annotations

from netmon.core.diagnostics.rules import RuleEngine
from netmon.core.health import HealthIssue


def issue(issue_type: str, **details: object) -> HealthIssue:
    return HealthIssue(
        issue_type=issue_type,
        component="connectivity",
        message=f"{issue_type} detected",
        details=dict(details),
        value=details.get("value") if isinstance(details.get("value"), float) else None,
    )


def test_gateway_down_rule_produces_actionable_fixes() -> None:
    verdict = RuleEngine().match(
        issue("gateway_unreachable", gateway="192.168.1.1"),
        {"default_route": {"interface": "eth0"}},
    )
    assert verdict is not None
    assert verdict.rule_name == "gateway-unreachable"
    assert verdict.confidence >= 70
    commands = " ".join(fix["command"] for fix in verdict.fixes)
    assert "ip route show" in commands
    assert "arp" in commands
    assert verdict.verify
    assert verdict.risks


def test_dns_rule_includes_flush_and_external_probe() -> None:
    verdict = RuleEngine().match(
        issue("dns_failure", failed=["google.com"]),
        {"interfaces": {"interfaces": {"eth0": {"dns_servers": ["127.0.0.53"]}}}},
    )
    assert verdict is not None
    commands = [fix["command"] for fix in verdict.fixes]
    assert any("resolvectl" in command for command in commands)
    assert any("dig" in command and "1.1.1.1" in command for command in commands)


def test_wifi_weak_signal_rule_mentions_interface_and_band() -> None:
    verdict = RuleEngine().match(
        issue("wifi_weak_signal", interface="wlan0", ssid="HomeNet", signal_dbm=-82),
        {},
    )
    assert verdict is not None
    assert "wlan0" in verdict.diagnosis
    assert any("nmcli" in fix["command"] for fix in verdict.fixes)


def test_wifi_disconnected_rule_adds_rfkill_fix_when_blocked() -> None:
    blocked = RuleEngine().match(
        issue("wifi_disconnected", interface="wlan0"),
        {"wifi": {"interfaces": {"wlan0": {"rfkill_blocked": True}}}},
    )
    assert blocked is not None
    assert any("rfkill unblock" in fix["command"] for fix in blocked.fixes)

    plain = RuleEngine().match(issue("wifi_disconnected", interface="wlan0"), {})
    assert plain is not None
    assert not any("rfkill unblock" in fix["command"] for fix in plain.fixes)


def test_firewall_rule_requires_firewall_evidence() -> None:
    engine = RuleEngine()
    assert engine.match(issue("internet_unreachable", target="8.8.8.8"), {}) is not None

    firewall_issue = HealthIssue(
        issue_type="internet_unreachable",
        component="connectivity",
        message="blocked",
        evidence=["kernel: DROP IN=eth0 SRC=10.0.0.5"],
    )
    verdict = engine.match(firewall_issue, {})
    assert verdict is not None
    assert verdict.rule_name == "firewall-blocking"
    assert "nft list ruleset" in " ".join(fix["command"] for fix in verdict.fixes)


def test_certificate_rules_cover_expiring_and_expired() -> None:
    engine = RuleEngine()
    expiring = engine.match(issue("cert_expiring", target="a.com:443", host="a.com", port=443, value=5.0), {})
    assert expiring is not None and expiring.rule_name == "certificate-expiring"
    assert any("certbot" in fix["command"] for fix in expiring.fixes)

    expired = engine.match(issue("cert_expired", target="a.com:443", host="a.com"), {})
    assert expired is not None and expired.rule_name == "certificate-expired"
    assert expired.confidence >= 90


def test_vpn_rule_only_fires_when_a_tunnel_exists() -> None:
    engine = RuleEngine()
    without_tunnel = engine.match(issue("internet_unreachable", target="8.8.8.8"), {"interfaces": {"interfaces": {"eth0": {}}}})
    assert without_tunnel is not None
    assert without_tunnel.rule_name != "vpn-tunnel"

    with_tunnel = engine.match(
        issue("internet_unreachable", target="8.8.8.8"),
        {"interfaces": {"interfaces": {"wg0": {}, "eth0": {}}}},
    )
    assert with_tunnel is not None
    assert with_tunnel.rule_name == "vpn-tunnel"


def test_unknown_issue_type_returns_no_match() -> None:
    assert RuleEngine().match(issue("totally_unknown_issue"), {}) is None


def test_coverage_counters_and_describe() -> None:
    engine = RuleEngine()
    engine.match(issue("gateway_unreachable", gateway="10.0.0.1"), {})
    engine.match(issue("cert_expired", target="a.com:443"), {})
    coverage = engine.coverage()
    assert coverage["gateway-unreachable"] == 1
    described = engine.describe()
    assert any(entry["name"] == "gateway-unreachable" for entry in described)
    assert all(entry["types"] for entry in described)


def test_broken_rule_does_not_break_matching(monkeypatch) -> None:
    from netmon.core.diagnostics import rules as rules_module

    engine = RuleEngine()

    def explode(*args: object, **kwargs: object) -> None:
        raise RuntimeError("boom")

    engine.rules.insert(0, rules_module.Rule("broken", ("dns_failure",), explode))
    verdict = engine.match(issue("dns_failure", failed=["a.com"]), {})
    assert verdict is not None, "matching must continue past a failing rule"
    assert verdict.rule_name == "dns-resolution-failure"


def test_min_confidence_filters_weak_matches() -> None:
    engine = RuleEngine(min_confidence=99.0)
    assert engine.match(issue("gateway_unreachable", gateway="10.0.0.1"), {}) is None
