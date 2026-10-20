"""Unit tests for the SQLite and InfluxDB storage layers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from netmon.config.settings import InfluxSettings
from netmon.storage.influx import (
    MEASUREMENT_CONNECTIVITY,
    MEASUREMENT_HEALTH,
    MEASUREMENT_INTERFACES,
    InfluxRepository,
    MetricPoint,
)
from netmon.storage.sqlite import SQLiteRepository, open_repository

# ---------------------------------------------------------------------------
# SQLite
# ---------------------------------------------------------------------------


async def test_open_repository_creates_database(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "netmon.db"
    repository = await open_repository(path)
    try:
        assert path.exists()
        assert await repository.ping() is True
    finally:
        await repository.close()


async def test_config_entries_round_trip(tmp_path: Path) -> None:
    repository = await open_repository(tmp_path / "config.db")
    try:
        assert await repository.get_config_map() == {}

        written = await repository.set_config_values({"web.port": 8080, "monitoring.targets.ping": ["1.1.1.1"]})
        assert written == 2
        assert await repository.get_config_value("web.port") == 8080
        config_map = await repository.get_config_map()
        assert config_map["monitoring.targets.ping"] == ["1.1.1.1"]

        await repository.set_config_value("web.port", 9090)
        assert await repository.get_config_value("web.port") == 9090, "upsert must overwrite"

        assert await repository.delete_config_value("web.port") is True
        assert await repository.delete_config_value("web.port") is False
    finally:
        await repository.close()


async def test_diagnostic_history_lifecycle(tmp_path: Path) -> None:
    repository = await open_repository(tmp_path / "history.db")
    try:
        diagnostic_id = await repository.add_diagnostic(
            issue_type="gateway_unreachable",
            issue_details="gateway 10.0.0.1 is unreachable",
            severity="critical",
            diagnosis="gateway down",
            confidence=85.0,
            source="rule",
            fixes=[{"command": "ip route show", "explanation": "check routes"}],
            risks="none",
            verify_command="ping -c 3 10.0.0.1",
        )
        record = await repository.get_diagnostic(diagnostic_id)
        assert record is not None
        assert record["issue_type"] == "gateway_unreachable"
        assert record["fixes"][0]["command"] == "ip route show"
        assert record["execution_success"] is None

        assert await repository.record_fix_execution(
            diagnostic_id, command="ip route show", output="default via 10.0.0.1", success=True
        )
        updated = await repository.get_diagnostic(diagnostic_id)
        assert updated is not None
        assert updated["execution_success"] is True
        assert updated["resolution"] == "resolved"

        similar = await repository.find_similar_diagnostics("gateway_unreachable")
        assert [item["id"] for item in similar] == [diagnostic_id]

        stats = await repository.diagnostic_stats()
        assert stats["total"] == 1
        assert stats["resolved"] == 1
        assert stats["by_type"]["gateway_unreachable"] == 1

        listed = await repository.list_diagnostics(limit=10)
        assert len(listed) == 1
        assert listed[0]["created_at"]
    finally:
        await repository.close()


async def test_find_similar_filters_unresolved_when_requested(tmp_path: Path) -> None:
    repository = await open_repository(tmp_path / "similar.db")
    try:
        untested = await repository.add_diagnostic(issue_type="dns_failure", diagnosis="test dns")
        tested = await repository.add_diagnostic(issue_type="dns_failure", diagnosis="flush cache")
        await repository.record_fix_execution(tested, command="resolvectl flush-caches", output="ok", success=True)

        unresolved = await repository.find_similar_diagnostics("dns_failure", successful_only=False)
        assert {item["id"] for item in unresolved} == {untested, tested}

        resolved = await repository.find_similar_diagnostics("dns_failure", successful_only=True)
        assert [item["id"] for item in resolved] == [tested]
    finally:
        await repository.close()


async def test_prune_diagnostics_respects_retention(tmp_path: Path) -> None:
    repository = await open_repository(tmp_path / "prune.db")
    try:
        old_id = await repository.add_diagnostic(issue_type="dns_failure", diagnosis="old")

        from netmon.config.models import DiagnosticHistory

        async with repository._sessions()() as session:
            row = await session.get(DiagnosticHistory, old_id)
            assert row is not None
            row.created_at = datetime.now(UTC) - timedelta(days=120)
            await session.commit()

        await repository.add_diagnostic(issue_type="dns_failure", diagnosis="fresh")
        removed = await repository.prune_diagnostics(retention_days=90)
        assert removed == 1
        remaining = await repository.list_diagnostics(limit=10)
        assert [item["diagnosis"] for item in remaining] == ["fresh"]
    finally:
        await repository.close()


async def test_alert_rule_crud(tmp_path: Path) -> None:
    repository = await open_repository(tmp_path / "rules.db")
    try:
        rule_id = await repository.upsert_alert_rule(
            name="latency", metric="connectivity.avg_latency_ms", operator=">", threshold=100.0, severity="warning"
        )
        assert rule_id > 0
        rules = await repository.list_alert_rules()
        assert len(rules) == 1 and rules[0]["name"] == "latency"

        again = await repository.upsert_alert_rule(
            name="latency", metric="connectivity.avg_latency_ms", operator=">", threshold=250.0, severity="critical"
        )
        assert again == rule_id, "upsert by name must update in place"
        updated = (await repository.list_alert_rules())[0]
        assert updated["threshold"] == 250.0 and updated["severity"] == "critical"

        assert await repository.set_alert_rule_enabled("latency", False) is True
        assert await repository.list_alert_rules(enabled_only=True) == []
        assert await repository.set_alert_rule_enabled("missing", False) is False

        assert await repository.delete_alert_rule("latency") is True
        assert await repository.delete_alert_rule("latency") is False
    finally:
        await repository.close()


async def test_alert_events_and_acknowledgement(tmp_path: Path) -> None:
    repository = await open_repository(tmp_path / "events.db")
    try:
        event_id = await repository.add_alert_event(
            rule_name="gateway-unreachable",
            severity="critical",
            message="gateway down",
            metric="connectivity.gateway.success",
            value=0.0,
            payload={"interface": "eth0"},
            delivered=True,
        )
        events = await repository.list_alert_events(limit=10)
        assert len(events) == 1
        assert events[0]["acknowledged"] is False

        assert await repository.acknowledge_alert(event_id) is True
        assert (await repository.list_alert_events(unacknowledged_only=True)) == []

        assert await repository.acknowledge_all_alerts() == 0
        assert await repository.acknowledge_alert(999) is False
    finally:
        await repository.close()


async def test_prune_alert_events_keeps_newest(tmp_path: Path) -> None:
    repository = await open_repository(tmp_path / "prune_events.db")
    try:
        from netmon.config.models import AlertEvent

        for index in range(10):
            event_id = await repository.add_alert_event(
                rule_name=f"rule-{index}", severity="warning", message=f"event {index}"
            )
            async with repository._sessions()() as session:
                row = await session.get(AlertEvent, event_id)
                assert row is not None
                row.created_at = datetime.now(UTC) - timedelta(minutes=10 - index)
                await session.commit()

        removed = await repository.prune_alert_events(max_events=4)
        assert removed == 6
        remaining = await repository.list_alert_events(limit=20)
        assert [event["rule_name"] for event in remaining] == ["rule-9", "rule-8", "rule-7", "rule-6"]
    finally:
        await repository.close()


async def test_prune_alert_events_noop_on_zero(tmp_path: Path) -> None:
    repository = await open_repository(tmp_path / "noop.db")
    try:
        assert await repository.prune_alert_events(0) == 0
        assert await repository.prune_diagnostics(0) == 0
    finally:
        await repository.close()


# ---------------------------------------------------------------------------
# InfluxDB (memory fallback path - no server required)
# ---------------------------------------------------------------------------


@pytest.fixture()
def memory_influx() -> InfluxRepository:
    return InfluxRepository(InfluxSettings(token="", enabled=True))


async def test_unconfigured_influx_uses_memory(memory_influx: InfluxRepository) -> None:
    assert memory_influx.configured is False

    point = MetricPoint(
        measurement=MEASUREMENT_CONNECTIVITY,
        fields={"latency_ms": 12.5},
        tags={"target": "8.8.8.8", "type": "ping"},
    )
    assert await memory_influx.write_points([point]) is False, "no token means no remote write"
    assert memory_influx.available is False

    series = await memory_influx.series(
        MEASUREMENT_CONNECTIVITY, "latency_ms", range_token="15m"
    )
    assert len(series) == 1
    assert series[0][1] == 12.5

    rows = await memory_influx.query_range(MEASUREMENT_CONNECTIVITY, range_token="1h")
    assert rows[0]["field"] == "latency_ms"
    assert rows[0]["tags"]["target"] == "8.8.8.8"
    assert rows[0]["source"] == "memory"


async def test_memory_ring_buffer_is_bounded() -> None:
    repository = InfluxRepository(InfluxSettings(token=""), memory_buffer_size=5)
    for index in range(20):
        await repository.write_points(
            [MetricPoint(measurement=MEASUREMENT_HEALTH, fields={"score": float(index)})]
        )
    retained = repository.memory_series(MEASUREMENT_HEALTH)
    assert len(retained) == 5
    assert retained[-1].fields["score"] == 19.0


async def test_write_collection_metrics_maps_collector_output(memory_influx: InfluxRepository) -> None:
    written = await memory_influx.write_collection_metrics(
        [
            {
                "measurement": MEASUREMENT_INTERFACES,
                "tags": {"interface": "eth0"},
                "fields": {"rx_bytes": 100, "tx_bytes": 200, "rx_errors": None},
            },
            {"measurement": "", "fields": {"ignored": 1}},
            {"measurement": MEASUREMENT_HEALTH, "fields": {}},
        ]
    )
    assert written == 2
    points = memory_influx.memory_series(MEASUREMENT_INTERFACES)
    assert points[0].fields == {"rx_bytes": 100, "tx_bytes": 200}, "None fields are dropped"
    assert memory_influx.stats()["memory_points"][MEASUREMENT_INTERFACES] == 1


async def test_query_range_respects_time_window(memory_influx: InfluxRepository) -> None:
    old = MetricPoint(
        measurement=MEASUREMENT_HEALTH,
        fields={"score": 1.0},
        time=datetime.now(UTC) - timedelta(hours=5),
    )
    recent = MetricPoint(measurement=MEASUREMENT_HEALTH, fields={"score": 99.0})
    await memory_influx.write_points([old, recent])

    rows = await memory_influx.query_range(MEASUREMENT_HEALTH, range_token="1h")
    assert [row["value"] for row in rows] == [99.0]

    latest = await memory_influx.latest(MEASUREMENT_HEALTH)
    assert latest is not None and latest["value"] == 99.0


async def test_flux_query_is_escaped(memory_influx: InfluxRepository) -> None:
    query = memory_influx._build_flux(
        'evil") |> drop()',
        "1h",
        "10s",
        ["latency_ms"],
        {"target": 'x" or "1"=="1'},
    )
    assert 'r._measurement == "evil\\") |> drop()"' in query
    assert 'r["target"] == "x\\" or \\"1\\"==\\"1"' in query
    assert "aggregateWindow(every: 10s" in query


async def test_ping_without_token_is_graceful(memory_influx: InfluxRepository) -> None:
    assert await memory_influx.ping() is False
    assert memory_influx.available is False
    await memory_influx.close()


def test_sqlite_repository_url_uses_aiosqlite(tmp_path: Path) -> None:
    repository = SQLiteRepository(tmp_path / "x.db")
    assert repository._url.startswith("sqlite+aiosqlite:///")


async def test_config_values_survive_reopen(tmp_path: Path) -> None:
    path = tmp_path / "persist.db"
    repository = await open_repository(path)
    await repository.set_config_value("web.port", 8181)
    await repository.close()

    reopened = await open_repository(path)
    try:
        assert await reopened.get_config_value("web.port") == 8181
    finally:
        await reopened.close()
