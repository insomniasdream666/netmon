"""End-to-end pipeline tests: collector -> health -> alerts -> storage -> UI state.

These tests drive a real :class:`MonitorManager` with lightweight fake
collectors so the whole orchestrator (scheduler, health checker, alert manager,
SQLite repository, InfluxDB memory mirror, diagnostic engine) runs together
without touching the network.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from netmon.collectors.base import BaseCollector, CollectionResult
from netmon.config.settings import InfluxSettings, NetMonConfig
from netmon.core.alerts import DEFAULT_RULES, AlertManager
from netmon.core.diagnostics.engine import build_engine
from netmon.core.health import HealthChecker
from netmon.core.monitor import MonitorManager
from netmon.storage.influx import InfluxRepository
from netmon.storage.sqlite import SQLiteRepository, open_repository

# ---------------------------------------------------------------------------
# Fake collectors
# ---------------------------------------------------------------------------


class FakeCollector(BaseCollector):
    """Returns canned data; optionally raises to prove error isolation."""

    def __init__(
        self,
        name: str,
        *,
        data: dict[str, Any] | None = None,
        metrics: list[dict[str, Any]] | None = None,
        failure: Exception | None = None,
    ) -> None:
        super().__init__(interval=30)
        self.name = name
        self.payload = data or {}
        self.metrics = metrics or []
        self.failure = failure
        self.collected = 0

    async def collect(self) -> CollectionResult:
        self.collected += 1
        if self.failure is not None:
            raise self.failure
        return CollectionResult(
            collector_name=self.name,
            data=dict(self.payload),
            metrics=[dict(metric) for metric in self.metrics],
        )


DOWN_CONNECTIVITY: dict[str, Any] = {
    "ping": {
        "8.8.8.8": {
            "target": "8.8.8.8",
            "latency_ms": None,
            "packet_loss": 100.0,
            "success": False,
            "transmitted": 3,
            "received": 0,
        }
    },
    "dns": {
        "example.com": {
            "name": "example.com",
            "latency_ms": None,
            "success": False,
            "addresses": [],
            "error": "timed out",
        }
    },
    "gateway": {
        "gateway": "10.0.0.1",
        "reachable": False,
        "latency_ms": None,
        "packet_loss": 100.0,
    },
    "internet": {
        "reachable": False,
        "targets_ok": 0,
        "targets_total": 3,
        "avg_latency_ms": None,
        "avg_packet_loss": 100.0,
    },
    "dns_health": {
        "healthy": False,
        "failures": 3,
        "total": 3,
        "avg_latency_ms": None,
        "failure_rate": 100.0,
    },
}

CONNECTIVITY_METRICS: list[dict[str, Any]] = [
    {
        "measurement": "connectivity",
        "tags": {"target": "8.8.8.8", "type": "ping"},
        "fields": {"latency_ms": None, "packet_loss": 100.0, "success": 0},
    },
    {
        "measurement": "connectivity",
        "tags": {"target": "10.0.0.1", "type": "gateway"},
        "fields": {"latency_ms": None, "packet_loss": 100.0, "success": 0},
    },
]

UP_INTERFACES: dict[str, Any] = {
    "hostname": "testhost",
    "interfaces": {
        "eth0": {
            "name": "eth0",
            "is_up": True,
            "is_loopback": False,
            "ipv4": ["192.168.1.20"],
            "rx_bytes": 1000,
            "tx_bytes": 2000,
            "rx_errors": 0,
            "tx_errors": 0,
        }
    },
    "default_route": {"gateway": "192.168.1.1", "interface": "eth0", "metric": 100},
    "interfaces_count": 1,
    "up_count": 1,
}

INTERFACE_METRICS: list[dict[str, Any]] = [
    {
        "measurement": "interface_metrics",
        "tags": {"interface": "eth0", "hostname": "testhost"},
        "fields": {"rx_bytes": 1000, "tx_bytes": 2000, "is_up": 1},
    }
]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


async def start_monitor(
    tmp_path: Path,
    collectors: list[BaseCollector],
) -> tuple[MonitorManager, SQLiteRepository, InfluxRepository]:
    config = NetMonConfig()
    repository = await open_repository(tmp_path / "e2e.db")
    influx = InfluxRepository(InfluxSettings(token="", enabled=True))

    holder: dict[str, MonitorManager] = {}
    engine = build_engine(
        config,
        repository,
        influx,
        snapshot_provider=lambda: holder["monitor"].get_current_state().snapshot,
    )
    monitor = MonitorManager(
        config,
        collectors,
        HealthChecker(config.health),
        engine,
        AlertManager(config.alerts, repository),
        repository,
        influx,
    )
    holder["monitor"] = monitor
    return monitor, repository, influx


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_full_pipeline_from_collectors_to_alerts(tmp_path: Path) -> None:
    interfaces = FakeCollector("interfaces", data=UP_INTERFACES, metrics=INTERFACE_METRICS)
    connectivity = FakeCollector(
        "connectivity", data=DOWN_CONNECTIVITY, metrics=CONNECTIVITY_METRICS
    )
    monitor, repository, influx = await start_monitor(tmp_path, [interfaces, connectivity])

    notifications: list[Any] = []
    monitor.subscribe(notifications.append)

    try:
        await monitor.start()
        state = monitor.get_current_state()

        # -- collectors produced data ------------------------------------
        assert state.snapshot is not None
        assert state.snapshot.connectivity["gateway"]["reachable"] is False
        assert state.snapshot.interfaces["interfaces"]["eth0"]["is_up"] is True
        assert state.cycles == 1

        # -- health reacted ----------------------------------------------
        assert state.health is not None
        issue_types = {issue["issue_type"] for issue in state.health.to_dict()["issues"]}
        assert "gateway_unreachable" in issue_types
        assert state.health.score < 100.0
        assert state.score == state.health.score

        # -- alerts fired, reached listeners and were persisted ----------
        assert notifications, "state listeners must be notified after a cycle"
        assert state.alerts, "critical issues must produce alert records"
        rule_names = {alert["rule_name"] for alert in state.alerts}
        assert "gateway_unreachable" in rule_names

        events = await repository.list_alert_events(limit=50)
        assert events, "alert events must be persisted in SQLite"
        persisted = {event["rule_name"] for event in events}
        assert "gateway_unreachable" in persisted
        assert any(event["delivered"] for event in events)

        # -- metrics reached the InfluxDB repository (memory mirror) -----
        connectivity_points = influx.memory_series("connectivity")
        assert connectivity_points, "collector metrics must be written to storage"
        assert influx.stats()["memory_points"]["connectivity"] >= 2
        health_points = influx.memory_series("health_score")
        assert health_points, "health scores must be mirrored to storage"

        # -- default alert rules were seeded -----------------------------
        seeded = await repository.list_alert_rules()
        assert len(seeded) == len(DEFAULT_RULES)

        # -- the diagnostic engine diagnoses the live issue --------------
        diagnosis = await monitor.diagnose_issue("gateway_unreachable", use_ai=False)
        assert diagnosis is not None
        assert diagnosis.source == "rule"
        assert diagnosis.rule_name == "gateway-unreachable"
        assert diagnosis.fixes, "the rule must propose at least one fix"
        assert diagnosis.history_id is not None

        # -- and the fix gate refuses to run without confirmation --------
        outcome = await monitor.execute_fix(diagnosis, 0)
        assert outcome.executed is False
        assert outcome.blocked_reason is not None
    finally:
        await monitor.stop()
        await repository.close()


async def test_collector_crash_is_isolated(tmp_path: Path) -> None:
    good = FakeCollector("interfaces", data=UP_INTERFACES, metrics=INTERFACE_METRICS)
    bad = FakeCollector("connectivity", failure=RuntimeError("iw exploded"))
    monitor, repository, _ = await start_monitor(tmp_path, [good, bad])

    try:
        await monitor.start()
        state = monitor.get_current_state()

        assert state.snapshot is not None
        assert state.snapshot.interfaces.get("interfaces"), "good collectors still deliver"
        assert "connectivity" in state.snapshot.errors
        assert any("iw exploded" in error for error in state.snapshot.errors["connectivity"])
        assert state.health is not None, "health is still evaluated with partial data"
        assert bad.failure_count >= 1
    finally:
        await monitor.stop()
        await repository.close()


async def test_manual_refresh_runs_selected_collectors(tmp_path: Path) -> None:
    # Fake names keep the background scheduler tasks disabled, so the only
    # runs are the initial cycle and the explicit refresh under test.
    interfaces = FakeCollector("fake-interfaces", data=UP_INTERFACES, metrics=INTERFACE_METRICS)
    connectivity = FakeCollector(
        "fake-connectivity", data=DOWN_CONNECTIVITY, metrics=CONNECTIVITY_METRICS
    )
    monitor, repository, _ = await start_monitor(tmp_path, [interfaces, connectivity])

    try:
        await monitor.start()
        assert connectivity.collected == 1, "the initial cycle runs every collector once"
        assert interfaces.collected == 1

        outcome = await monitor.refresh(collectors=["fake-connectivity"])
        assert outcome == {"fake-connectivity": True}
        assert connectivity.collected == 2
        assert interfaces.collected == 1, "unselected collectors must not run"
    finally:
        await monitor.stop()
        await repository.close()


async def test_config_changed_applies_new_intervals(tmp_path: Path) -> None:
    interfaces = FakeCollector("interfaces", data=UP_INTERFACES)
    monitor, repository, _ = await start_monitor(tmp_path, [interfaces])

    try:
        await monitor.start()

        config = monitor.config.model_copy(deep=True)
        config.monitoring.intervals.interfaces = 7
        await monitor.config_changed(config)

        assert monitor.scheduler.get("interfaces") is not None
        assert monitor.scheduler.get("interfaces").interval == 7  # type: ignore[union-attr]
        assert interfaces.interval == 7
    finally:
        await monitor.stop()
        await repository.close()
