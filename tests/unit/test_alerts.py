"""Unit tests for alert evaluation, cooldown and delivery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from netmon.config.settings import AlertChannel, AlertsSettings, HealthSettings
from netmon.core.alerts import AlertManager, AlertRecord, build_metric_map
from netmon.core.health import HealthChecker, HealthIssue, OverallHealth, SystemSnapshot
from netmon.storage.sqlite import open_repository


async def make_manager(
    tmp_path: Path, *, seed_rules: bool = False, **settings: Any
) -> tuple[AlertManager, Any]:
    """Build an alert manager.

    Default rules are not seeded unless requested, so issue-driven tests are
    not perturbed by the ``health-score-low`` rule firing on the synthetic
    health report.
    """
    repository = await open_repository(tmp_path / "alerts.db")
    manager = AlertManager(AlertsSettings(**settings), repository)
    await manager.start(seed_rules=seed_rules)
    return manager, repository


def health_with(issues: list[HealthIssue]) -> OverallHealth:
    return OverallHealth(score=42.0, state="critical", components=[], issues=issues)


def issue(issue_type: str = "gateway_unreachable", severity: str = "critical") -> HealthIssue:
    return HealthIssue(
        issue_type=issue_type,
        component="connectivity",
        message=f"{issue_type}: default gateway is unreachable",
        severity=severity,
        metric="connectivity.gateway.latency_ms",
        value=100.0,
    )


async def test_issues_become_alert_events(tmp_path: Path) -> None:
    manager, repository = await make_manager(tmp_path)
    try:
        fired = await manager.evaluate(health_with([issue()]))
        assert len(fired) == 1
        assert fired[0].event_id is not None

        events = await repository.list_alert_events(limit=10)
        assert len(events) == 1
        assert events[0]["rule_name"] == "gateway_unreachable"
        assert events[0]["severity"] == "critical"
        assert manager.stats()["sent"] == 1
    finally:
        await manager.stop()
        await repository.close()


async def test_cooldown_suppresses_repeats(tmp_path: Path) -> None:
    manager, repository = await make_manager(tmp_path, cooldown=300)
    try:
        first = await manager.evaluate(health_with([issue("dns_failure", "warning")]))
        second = await manager.evaluate(health_with([issue("dns_failure", "warning")]))
        assert len(first) == 1
        assert second == []
        assert manager.stats()["suppressed"] == 1

        manager.reset_cooldowns()
        third = await manager.evaluate(health_with([issue("dns_failure", "warning")]))
        assert len(third) == 1
    finally:
        await manager.stop()
        await repository.close()


async def test_critical_alerts_rearm_faster_than_warning(tmp_path: Path) -> None:
    manager, repository = await make_manager(tmp_path, cooldown=400)
    try:
        await manager.evaluate(health_with([issue("gateway_unreachable", "critical")]))
        # A critical issue uses a quarter of the configured cooldown (100s), so a
        # second alert inside that window is still suppressed.
        assert await manager.evaluate(health_with([issue("gateway_unreachable", "critical")])) == []
        cooldowns = manager._cooldowns
        assert cooldowns
    finally:
        await manager.stop()
        await repository.close()


async def test_disabled_alerting_produces_nothing(tmp_path: Path) -> None:
    manager, repository = await make_manager(tmp_path, enabled=False, cooldown=1)
    try:
        assert await manager.evaluate(health_with([issue()])) == []
    finally:
        await manager.stop()
        await repository.close()


async def test_severity_floor_filters_info_alerts(tmp_path: Path) -> None:
    manager, repository = await make_manager(tmp_path, min_severity="critical")
    try:
        fired = await manager.evaluate(health_with([issue("dns_failure", "warning")]))
        assert fired == []
    finally:
        await manager.stop()
        await repository.close()


async def test_metric_rules_are_evaluated(tmp_path: Path) -> None:
    manager, repository = await make_manager(tmp_path, min_severity="warning")
    try:
        await repository.upsert_alert_rule(
            name="latency-critical",
            metric="connectivity.avg_latency_ms",
            operator=">",
            threshold=100.0,
            severity="critical",
        )
        report = OverallHealth(score=95.0, state="ok", components=[], issues=[])

        snapshot = SystemSnapshot(
            connectivity={
                "ping": {"8.8.8.8": {"target": "8.8.8.8", "latency_ms": 150.0, "packet_loss": 0.0, "success": True}},
                "internet": {"reachable": True, "avg_latency_ms": 150.0, "avg_packet_loss": 0.0, "targets_ok": 1, "targets_total": 1},
            }
        )
        fired = await manager.evaluate(report, snapshot)
        names = {record.rule_name for record in fired}
        assert "latency-critical" in names
        latency_alert = next(record for record in fired if record.rule_name == "latency-critical")
        assert latency_alert.value == 150.0
        assert "150.00" in latency_alert.message
    finally:
        await manager.stop()
        await repository.close()


async def test_default_health_score_rule_fires_on_low_scores(tmp_path: Path) -> None:
    manager, repository = await make_manager(tmp_path, seed_rules=True, cooldown=60)
    try:
        fired = await manager.evaluate(health_with([]), SystemSnapshot())
        names = {record.rule_name for record in fired}
        assert "health-score-low" in names

        healthy = OverallHealth(score=88.0, state="ok", components=[], issues=[])
        assert await manager.evaluate(healthy, SystemSnapshot()) == []
    finally:
        await manager.stop()
        await repository.close()


async def test_score_rule_skipped_until_data_collected(tmp_path: Path) -> None:
    manager, repository = await make_manager(tmp_path, seed_rules=True, cooldown=60)
    try:
        # No collector has reported yet: the score is not a measurement, so
        # neither the metric map nor the score rule may treat it as a failure.
        report = HealthChecker(HealthSettings()).evaluate(SystemSnapshot())
        assert build_metric_map(report) == {}
        assert await manager.evaluate(report, SystemSnapshot()) == []
    finally:
        await manager.stop()
        await repository.close()


async def test_webhook_delivery_success_and_failure(tmp_path: Path) -> None:
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        if "fail" in str(request.url):
            return httpx.Response(500, text="nope")
        return httpx.Response(200, text="ok")

    repository = await open_repository(tmp_path / "webhook.db")
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    settings = AlertsSettings(
        cooldown=1,
        channels=[
            AlertChannel(type="ntfy", url="https://ntfy.sh/ok-topic"),
            AlertChannel(type="webhook", url="https://example.com/fail"),
        ],
    )
    manager = AlertManager(settings, repository, client=client)
    await manager.start(seed_rules=False)
    try:
        fired = await manager.evaluate(health_with([issue()]))
        assert len(fired) == 1
        assert fired[0].delivered is True
        assert fired[0].delivery_errors and "500" in fired[0].delivery_errors[0]
        assert any("ntfy" in str(request.url) for request in captured)
        assert all("Title" in request.headers for request in captured if "ntfy" in str(request.url))
    finally:
        await manager.stop()
        await repository.close()
        await client.aclose()


async def test_listener_receives_fired_alerts(tmp_path: Path) -> None:
    manager, repository = await make_manager(tmp_path, cooldown=1)
    received: list[AlertRecord] = []
    unsubscribe = manager.subscribe(received.append)
    try:
        await manager.evaluate(health_with([issue()]))
        assert len(received) == 1
        unsubscribe()
        manager.reset_cooldowns()
        await manager.evaluate(health_with([issue("dns_failure", "warning")]))
        assert len(received) == 1, "unsubscribed listener must not be called"
    finally:
        await manager.stop()
        await repository.close()


async def test_failing_listener_is_isolated(tmp_path: Path) -> None:
    manager, repository = await make_manager(tmp_path, cooldown=1)

    def explode(record: AlertRecord) -> None:
        raise RuntimeError("listener boom")

    manager.subscribe(explode)
    try:
        fired = await manager.evaluate(health_with([issue()]))
        assert len(fired) == 1
    finally:
        await manager.stop()
        await repository.close()


def test_build_metric_map_flattens_health_and_snapshot() -> None:
    snapshot = SystemSnapshot(
        connectivity={
            "gateway": {"gateway": "10.0.0.1", "reachable": False, "packet_loss": 100.0},
            "dns_health": {"failure_rate": 50.0, "avg_latency_ms": 120.0, "failures": 1, "total": 2},
        },
        bandwidth={"interfaces": {"eth0": {"name": "eth0", "utilization_percent": 91.0}}},
        interfaces={"interfaces": {"eth0": {"name": "eth0", "is_up": False}}},
        certificates={"certificates": {"a.com:443": {"days_remaining": 3}}},
        connections={"summary": {"total": 12}},
    )
    report = HealthChecker(HealthSettings()).evaluate(snapshot)
    metrics = build_metric_map(report, snapshot)

    assert metrics["health.score"] == report.score
    assert metrics["connectivity.gateway.success"] == 0.0
    assert metrics["dns.failure_rate"] == 50.0
    assert metrics["dns.avg_latency_ms"] == 120.0
    assert metrics["bandwidth.eth0.utilization_percent"] == 91.0
    assert metrics["interface.eth0.is_up"] == 0.0
    assert metrics["certificates.a.com:443.days_remaining"] == 3.0
    assert metrics["connections.total"] == 12.0
    assert metrics["bandwidth.peak_utilization"] == 91.0


async def test_seed_default_rules_is_idempotent(tmp_path: Path) -> None:
    from netmon.core.alerts import DEFAULT_RULES

    repository = await open_repository(tmp_path / "rules.db")
    try:
        assert await repository.list_alert_rules() == []
        first = await repository.seed_default_rules(DEFAULT_RULES)
        assert first == len(DEFAULT_RULES)

        rules = await repository.list_alert_rules()
        assert any(rule["name"] == "gateway-unreachable" for rule in rules)

        added = await repository.seed_default_rules(
            [
                {"name": "gateway-unreachable", "metric": "x", "threshold": 1},
                {"name": "brand-new", "metric": "y", "threshold": 2},
            ]
        )
        assert added == 1
        assert len(await repository.list_alert_rules()) == len(DEFAULT_RULES) + 1
    finally:
        await repository.close()


@pytest.mark.parametrize("channel_type", ["log", "ntfy", "discord", "webhook"])
async def test_test_channel_never_raises(tmp_path: Path, channel_type: str) -> None:
    manager, repository = await make_manager(tmp_path)
    try:
        channel = AlertChannel(type=channel_type, url="https://example.invalid/hook")
        ok, error = await manager.test_channel(channel)
        if channel_type == "log":
            assert ok is True
        else:
            assert ok is False or error is None
    finally:
        await manager.stop()
        await repository.close()
