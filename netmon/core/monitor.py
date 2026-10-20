"""The monitoring orchestrator that wires every subsystem together.

:class:`MonitorManager` owns the lifecycle of the whole application:

* collectors run on their own schedules and publish :class:`CollectionResult`
* results are merged into a :class:`~netmon.core.health.SystemSnapshot`
* metrics are written to InfluxDB (SQLite keeps state and history)
* the health checker scores the snapshot and the alert manager fires alerts
* listeners (TUI, web sockets, SSE) are notified with the new state

It is deliberately UI-agnostic: the Textual app, the FastAPI app and headless
mode all drive the same manager instance.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from netmon.collectors.base import BaseCollector, CollectionResult
from netmon.config.settings import NetMonConfig
from netmon.core.alerts import AlertManager, AlertRecord
from netmon.core.diagnostics.engine import Diagnosis, DiagnosticEngine, FixExecutionResult
from netmon.core.health import (
    HealthChecker,
    HealthIssue,
    OverallHealth,
    SystemSnapshot,
)
from netmon.core.scheduler import Scheduler
from netmon.storage.influx import InfluxRepository
from netmon.storage.sqlite import SQLiteRepository

logger = logging.getLogger(__name__)

StateListener = Callable[["SystemState"], Awaitable[None] | None]

RECENT_ISSUE_HISTORY = 50


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(UTC)


@dataclass(slots=True)
class SystemState:
    """Everything the interfaces need to render the current system status."""

    health: OverallHealth | None = None
    snapshot: SystemSnapshot | None = None
    collectors: list[dict[str, Any]] = field(default_factory=list)
    scheduler: dict[str, Any] = field(default_factory=dict)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    alert_stats: dict[str, Any] = field(default_factory=dict)
    influx: dict[str, Any] = field(default_factory=dict)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    started_at: datetime = field(default_factory=utcnow)
    last_cycle_at: datetime | None = None
    last_cycle_ms: float = 0.0
    cycles: int = 0
    errors: list[str] = field(default_factory=list)
    issues: list[dict[str, Any]] = field(default_factory=list)
    hostname: str = ""
    version: str = ""

    @property
    def score(self) -> float:
        """Overall health score, 0 when nothing has been collected yet."""
        return self.health.score if self.health else 0.0

    @property
    def state(self) -> str:
        """Overall health state name."""
        return self.health.state if self.health else "unknown"

    @property
    def uptime_seconds(self) -> float:
        """Seconds since the monitor started."""
        return (utcnow() - self.started_at).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the REST API and the web socket payload."""
        return {
            "score": round(self.score, 2),
            "state": self.state,
            "hostname": self.hostname,
            "version": self.version,
            "uptime_seconds": round(self.uptime_seconds, 1),
            "started_at": self.started_at.isoformat(),
            "last_cycle_at": self.last_cycle_at.isoformat() if self.last_cycle_at else None,
            "last_cycle_ms": round(self.last_cycle_ms, 2),
            "cycles": self.cycles,
            "health": self.health.to_dict() if self.health else None,
            "snapshot": _snapshot_to_dict(self.snapshot),
            "collectors": self.collectors,
            "scheduler": self.scheduler,
            "alerts": self.alerts,
            "alert_stats": self.alert_stats,
            "influx": self.influx,
            "diagnostics": self.diagnostics,
            "issues": self.issues,
            "errors": self.errors,
        }


def _snapshot_to_dict(snapshot: SystemSnapshot | None) -> dict[str, Any] | None:
    if snapshot is None:
        return None
    return {
        "interfaces": snapshot.interfaces,
        "connectivity": snapshot.connectivity,
        "bandwidth": snapshot.bandwidth,
        "ports": snapshot.ports,
        "connections": snapshot.connections,
        "wifi": snapshot.wifi,
        "certificates": snapshot.certificates,
        "errors": snapshot.collector_errors(),
        "collected_at": snapshot.collected_at.isoformat(),
    }


class MonitorManager:
    """Owns collectors, health evaluation, alerting and persistence.

    Args:
        config: Effective configuration.
        collectors: Collector instances to schedule.
        health_checker: Health evaluator.
        diagnostic_engine: Rule + AI diagnosis coordinator.
        alert_manager: Threshold/issue alerting and delivery.
        sqlite: Repository for config, history and alert events.
        influx: Time-series repository (optional; memory fallback otherwise).
        scheduler: Scheduler instance (a default one is created when omitted).
    """

    def __init__(
        self,
        config: NetMonConfig,
        collectors: Sequence[BaseCollector],
        health_checker: HealthChecker,
        diagnostic_engine: DiagnosticEngine,
        alert_manager: AlertManager,
        sqlite: SQLiteRepository,
        influx: InfluxRepository | None = None,
        *,
        scheduler: Scheduler | None = None,
    ) -> None:
        self.config = config
        self.collectors: dict[str, BaseCollector] = {collector.name: collector for collector in collectors}
        self.health_checker = health_checker
        self.diagnostic_engine = diagnostic_engine
        self.alert_manager = alert_manager
        self.sqlite = sqlite
        self.influx = influx
        self.scheduler = scheduler or Scheduler()

        self._snapshot = SystemSnapshot()
        self._health: OverallHealth | None = None
        self._results: dict[str, CollectionResult] = {}
        self._recent_alerts: deque[AlertRecord] = deque(maxlen=100)
        self._issue_history: deque[dict[str, Any]] = deque(maxlen=RECENT_ISSUE_HISTORY)
        self._listeners: list[StateListener] = []
        self._started_at = utcnow()
        self._last_cycle_at: datetime | None = None
        self._last_cycle_ms = 0.0
        self._cycles = 0
        self._errors: deque[str] = deque(maxlen=50)
        self._cycle_lock = asyncio.Lock()
        self._running = False
        self._tasks: list[asyncio.Task[Any]] = []

    # -- lifecycle -----------------------------------------------------------

    @property
    def running(self) -> bool:
        """True while the monitor loop is active."""
        return self._running

    async def start(self) -> None:
        """Set up collectors, start scheduling and run an initial cycle."""
        if self._running:
            return
        self._started_at = utcnow()

        for collector in self.collectors.values():
            try:
                await collector.setup()
            except Exception as exc:
                logger.warning("collector %s setup failed: %s", collector.name, exc)
                self._record_error(f"collector {collector.name} setup failed: {exc}")

        await self.alert_manager.start()
        self.alert_manager.subscribe(self._on_alert)

        for name, collector in self.collectors.items():
            interval = self.config.monitoring.interval_for(name)
            collector.interval = interval
            self.scheduler.add(
                name,
                self._make_task(collector),
                interval,
                enabled=name in self.config.monitoring.enabled_collectors,
            )
        self.scheduler.add("alerts-prune", self._prune_alerts, 900.0, jitter=0.05)

        if self.influx is not None:
            self._tasks.append(asyncio.create_task(self._probe_influx(), name="netmon:influx-probe"))
            if self.influx.configured:
                self._tasks.append(
                    asyncio.create_task(
                        self._apply_influx_retention(), name="netmon:influx-retention"
                    )
                )

        await self.scheduler.start()
        self._running = True
        await self.run_collection_cycle()
        logger.info("monitor started with %d collector(s)", len(self.collectors))

    async def stop(self) -> None:
        """Stop scheduling, tear down collectors and close clients."""
        if not self._running and not self.scheduler.running:
            return
        self._running = False
        await self.scheduler.stop()
        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        for collector in self.collectors.values():
            try:
                await collector.teardown()
            except Exception as exc:
                logger.debug("collector %s teardown failed: %s", collector.name, exc)

        await self.alert_manager.stop()
        logger.info("monitor stopped")

    def _make_task(self, collector: BaseCollector) -> Callable[[], Awaitable[CollectionResult]]:
        async def _run() -> CollectionResult:
            result = await collector.run()
            await self._handle_result(result)
            return result

        return _run

    # -- collection cycle ----------------------------------------------------

    async def run_collection_cycle(self) -> CollectionResult:
        """Run every collector once, evaluate health and fire alerts.

        Called at start-up and by the manual "refresh" action. Scheduled runs
        use :meth:`_handle_result` instead so each collector is evaluated as
        soon as its own data arrives.
        """
        async with self._cycle_lock:
            started = time.perf_counter()
            results = await asyncio.gather(
                *(collector.run() for collector in self.collectors.values()),
                return_exceptions=True,
            )
            for (name, _), outcome in zip(self.collectors.items(), results, strict=True):
                if isinstance(outcome, BaseException):
                    logger.warning("collector %s crashed: %s", name, outcome)
                    self._record_error(f"collector {name} crashed: {outcome}")
                    self._results[name] = CollectionResult(
                        collector_name=name, errors=[str(outcome)], ok=False
                    )
                else:
                    self._results[name] = outcome

            await self._refresh_state()
            await self._write_metrics(list(self._results.values()))
            await self._evaluate_health_and_alert()

            self._last_cycle_ms = (time.perf_counter() - started) * 1000
            self._cycles += 1
            self._last_cycle_at = utcnow()
            await self._notify_listeners()

            merged = CollectionResult(collector_name="cycle")
            for result in self._results.values():
                merged.metrics.extend(result.metrics)
                for error in result.errors:
                    merged.add_error(f"{result.collector_name}: {error}")
            merged.duration_ms = self._last_cycle_ms
            merged.ok = any(result.ok for result in self._results.values())
            return merged

    async def _handle_result(self, result: CollectionResult) -> None:
        """Fold one collector's result into the live state and re-evaluate."""
        self._results[result.collector_name] = result
        await self._refresh_state()
        await self._write_metrics([result])
        await self._evaluate_health_and_alert()
        await self._notify_listeners()

    async def _refresh_state(self) -> None:
        def data_of(name: str) -> dict[str, Any]:
            result = self._results.get(name)
            return dict(result.data) if result and isinstance(result.data, dict) else {}

        self._snapshot = SystemSnapshot(
            interfaces=data_of("interfaces"),
            connectivity=data_of("connectivity"),
            bandwidth=data_of("bandwidth"),
            ports=data_of("ports"),
            connections=data_of("connections"),
            wifi=data_of("wifi"),
            certificates=data_of("certificates"),
            errors={
                name: list(result.errors)
                for name, result in self._results.items()
                if result.errors
            },
            collected_at=utcnow(),
        )

    async def _write_metrics(self, results: Sequence[CollectionResult]) -> None:
        if self.influx is None:
            return
        metrics: list[dict[str, Any]] = []
        for result in results:
            metrics.extend(result.metrics)
        if not metrics:
            return
        try:
            await self.influx.write_collection_metrics(metrics)
        except Exception as exc:
            logger.warning("metric write failed: %s", exc)
            self._record_error(f"metric write failed: {exc}")

    async def _evaluate_health_and_alert(self) -> None:
        try:
            self._health = self.health_checker.evaluate(self._snapshot)
        except Exception as exc:
            logger.warning("health evaluation failed: %s", exc)
            self._record_error(f"health evaluation failed: {exc}")
            return

        if self.influx is not None:
            try:
                await self.influx.write_collection_metrics(
                    [
                        {
                            "measurement": "health_score",
                            "tags": {"component": component.component},
                            "fields": {"score": float(component.score)},
                        }
                        for component in self._health.components
                    ]
                    + [
                        {
                            "measurement": "health_score",
                            "tags": {"component": "overall"},
                            "fields": {"score": float(self._health.score)},
                        }
                    ]
                )
            except Exception as exc:
                logger.debug("health metric write failed: %s", exc)

        for issue in self._health.issues:
            entry = issue.to_dict()
            if entry["key"] not in {item.get("key") for item in self._issue_history}:
                self._issue_history.append(entry)

        try:
            await self.alert_manager.evaluate(self._health, self._snapshot)
        except Exception as exc:
            logger.warning("alert evaluation failed: %s", exc)
            self._record_error(f"alert evaluation failed: {exc}")

    async def _on_alert(self, record: AlertRecord) -> None:
        self._recent_alerts.append(record)
        await self._notify_listeners()

    async def _prune_alerts(self) -> None:
        try:
            await self.sqlite.prune_alert_events(self.config.alerts.max_events)
            await self.sqlite.prune_diagnostics(self.config.storage.retention.diagnostics)
        except Exception as exc:
            logger.debug("prune failed: %s", exc)

    async def _apply_influx_retention(self) -> None:
        """Apply the configured bucket retention policy once at startup."""
        if self.influx is None:
            return
        retention = self.config.storage.retention.metrics
        try:
            applied = await self.influx.apply_retention(retention)
        except Exception as exc:
            logger.warning("influx retention setup failed: %s", exc)
            return
        if applied:
            logger.info("applied InfluxDB retention: %s", retention)

    async def _probe_influx(self) -> None:
        """Periodically verify InfluxDB reachability for the dashboard."""
        while self._running:
            try:
                if self.influx is not None:
                    if self.config.storage.influxdb.enabled:
                        await self.influx.ping()
                    else:
                        self.influx._available = False
                await asyncio.sleep(60.0)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("influx probe failed: %s", exc)
                await asyncio.sleep(30.0)

    # -- manual actions ------------------------------------------------------

    async def refresh(self, *, collectors: Sequence[str] | None = None) -> dict[str, bool]:
        """Force an immediate collection, optionally for specific collectors."""
        if collectors:
            results = await asyncio.gather(
                *(self.scheduler.run_once(name) for name in collectors), return_exceptions=True
            )
            outcome = {
                name: (value if isinstance(value, bool) else False)
                for name, value in zip(collectors, results, strict=True)
            }
            await self._refresh_state()
            await self._evaluate_health_and_alert()
            await self._notify_listeners()
            return outcome
        await self.run_collection_cycle()
        return dict.fromkeys(self.collectors, True)

    async def diagnose_issue(self, issue_key: str | None = None, *, use_ai: bool = True) -> Diagnosis | None:
        """Diagnose one issue (by key) or the most severe current issue."""
        issue = self.find_issue(issue_key)
        if issue is None:
            return None
        return await self.diagnostic_engine.diagnose(issue, use_ai=use_ai, snapshot=self._snapshot)

    async def execute_fix(
        self,
        diagnosis: Diagnosis,
        fix_index: int,
        *,
        confirmed: bool = False,
    ) -> FixExecutionResult:
        """Delegate fix execution to the diagnostic engine (confirmation enforced there)."""
        return await self.diagnostic_engine.execute_fix(diagnosis, fix_index, confirmed=confirmed)

    def find_issue(self, issue_key: str | None) -> HealthIssue | None:
        """Return a current issue by key, or the most severe one when key is None."""
        if self._health is None:
            return None
        if issue_key is None:
            return self._health.issues[0] if self._health.issues else None
        for issue in self._health.issues:
            if issue.key == issue_key or issue.issue_type == issue_key:
                return issue
        return None

    def subscribe(self, listener: StateListener) -> Callable[[], None]:
        """Register a state listener; returns an unsubscribe callable."""
        self._listeners.append(listener)

        def _unsubscribe() -> None:
            if listener in self._listeners:
                self._listeners.remove(listener)

        return _unsubscribe

    async def _notify_listeners(self) -> None:
        state = self.get_current_state()
        for listener in list(self._listeners):
            try:
                outcome = listener(state)
                if asyncio.iscoroutine(outcome):
                    await outcome
            except Exception as exc:
                logger.debug("state listener failed: %s", exc)

    def _record_error(self, message: str) -> None:
        self._errors.append(f"{utcnow().strftime('%H:%M:%S')} {message}")

    # -- state ---------------------------------------------------------------

    def get_current_state(self) -> SystemState:
        """Snapshot of everything the UI needs right now."""
        from netmon import __brand_tagline__, __version__

        try:
            import socket

            hostname = socket.gethostname()
        except OSError:  # pragma: no cover - defensive
            hostname = "unknown"

        return SystemState(
            health=self._health,
            snapshot=self._snapshot,
            collectors=[collector.describe() for collector in self.collectors.values()],
            scheduler=self.scheduler.stats(),
            alerts=[record.to_dict() for record in reversed(self._recent_alerts)],
            alert_stats=self.alert_manager.stats(),
            influx=self.influx.stats() if self.influx else {"configured": False, "available": False},
            diagnostics=self.diagnostic_engine.describe(),
            started_at=self._started_at,
            last_cycle_at=self._last_cycle_at,
            last_cycle_ms=self._last_cycle_ms,
            cycles=self._cycles,
            errors=list(self._errors),
            issues=list(self._issue_history),
            hostname=hostname,
            version=f"{__version__} - {__brand_tagline__}",
        )

    async def config_changed(self, config: NetMonConfig) -> None:
        """Apply a configuration change to the running monitor."""
        self.config = config
        for name, collector in self.collectors.items():
            interval = config.monitoring.interval_for(name)
            collector.interval = interval
            self.scheduler.set_interval(name, interval)
            self.scheduler.enable(name, name in config.monitoring.enabled_collectors)
        await self._notify_listeners()


__all__ = ["MonitorManager", "SystemState", "utcnow"]
