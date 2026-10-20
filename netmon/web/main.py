"""FastAPI application factory, page routes, WebSocket and SSE streams.

Two lifecycle modes are supported:

* **Caller-managed** (the normal CLI/web mode): the composition root builds
  the :class:`~netmon.core.monitor.MonitorManager`, starts it and passes it to
  :func:`create_app` (or :func:`set_monitor` for the module-level app); the app
  never starts or stops it.
* **Standalone** (``uvicorn netmon.web.main:app``): :func:`get_app` creates the
  module-level app and its lifespan builds a monitor from the loaded
  configuration, starts it and shuts it down cleanly.

All request handlers resolve their dependencies from ``app.state`` so several
app instances can coexist (tests, embedded use) without shared globals.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import logging
import os
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from jinja2 import Undefined

from netmon import __brand_tagline__, __version__
from netmon.config.settings import CONFIG_SECTIONS, NetMonConfig, load_config
from netmon.core.alerts import OPERATORS, AlertManager
from netmon.core.diagnostics.engine import build_engine
from netmon.core.health import HealthChecker, HealthIssue, SystemSnapshot
from netmon.core.monitor import MonitorManager, SystemState
from netmon.storage.influx import InfluxRepository
from netmon.storage.sqlite import SQLiteRepository, open_repository
from netmon.utils import formatting
from netmon.web.api import config as config_api
from netmon.web.api import diagnostics as diagnostics_api
from netmon.web.api import health as health_api
from netmon.web.api import metrics as metrics_api
from netmon.web.auth import BasicAuthMiddleware, credentials_from_env

if TYPE_CHECKING:  # pragma: no cover - typing only
    from netmon.collectors.base import BaseCollector

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

HEARTBEAT_SECONDS = 2.0
SSE_KEEPALIVE_SECONDS = 15.0
SSE_SEEN_ALERTS = 500

DASHBOARD_FRAGMENTS = frozenset({"summary", "connectivity", "interfaces", "alerts"})
INTERFACES_FRAGMENTS = frozenset({"detail", "detail_live"})
DIAGNOSTICS_FRAGMENTS = frozenset({"issues", "history"})
ALERTS_FRAGMENTS = frozenset({"events", "rules", "channels"})

# Select-style settings and the values they accept. Anything else is edited as
# a text, number or JSON field depending on its current Python type.
SETTING_OPTIONS: dict[str, tuple[str, ...]] = {
    "env": ("development", "production", "test"),
    "log_level": ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
    "monitoring.port_scan.protocol": ("tcp", "udp", "both"),
    "alerts.min_severity": ("info", "warning", "critical"),
    "ollama.prompt_template": ("default", "concise", "deep"),
    "tui.theme": ("netmon-dark", "textual-dark", "textual-light"),
}

# Keys that exist in the model but have no effect yet; labelled in the UI so
# operators are not surprised when they change nothing.
RESERVED_SETTINGS = frozenset({"web.refresh_interval"})


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------

FilterFn = Callable[..., Any]


def _undefined_safe(formatter: FilterFn) -> FilterFn:
    """Wrap a formatter so a missing Jinja value reaches it as ``None``.

    Collectors may omit optional fields; without this a filter like
    ``format_bytes`` would receive a Jinja ``Undefined`` and raise instead of
    rendering the documented ``--`` placeholder.
    """

    @functools.wraps(formatter)
    def wrapped(value: Any, *args: Any, **kwargs: Any) -> Any:
        return formatter(None if isinstance(value, Undefined) else value, *args, **kwargs)

    return wrapped


def _time_safe(formatter: FilterFn) -> FilterFn:
    """Wrap a time formatter so ISO-8601 strings and missing values are accepted."""

    @functools.wraps(formatter)
    def wrapped(value: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(value, Undefined):
            value = None
        elif isinstance(value, str):
            value = _parse_iso(value)
        return formatter(value, *args, **kwargs)

    return wrapped


def _build_templates() -> Jinja2Templates:
    """Create the shared Jinja2 environment with NetMon's filters registered."""
    engine = Jinja2Templates(directory=str(TEMPLATES_DIR))
    engine.env.filters.update(
        {
            "format_bytes": _undefined_safe(formatting.format_bytes),
            "format_rate": _undefined_safe(formatting.format_rate),
            "format_bps": _undefined_safe(formatting.format_bps),
            "format_duration": _undefined_safe(formatting.format_duration),
            "format_latency": _undefined_safe(formatting.format_latency),
            "format_percent": _undefined_safe(formatting.format_percent),
            "format_timestamp": _time_safe(formatting.format_timestamp),
            "format_ago": _time_safe(formatting.format_ago),
            "health_glyph": formatting.health_glyph,
            "health_color": formatting.health_color,
            "score_state": formatting.score_state,
            "truncate": formatting.truncate,
            "severity_order": formatting.severity_rank,
            "sparkline": _undefined_safe(formatting.sparkline),
            "health_bar": _undefined_safe(formatting.health_bar),
        }
    )
    engine.env.globals.update(
        {
            "app_name": "NetMon",
            "app_version": __version__,
            "app_tagline": __brand_tagline__,
            "brand": formatting.BRAND_COLORS,
        }
    )
    for name in (
        "base.html",
        "dashboard.html",
        "interfaces.html",
        "diagnostics.html",
        "alerts.html",
        "settings.html",
    ):
        engine.get_template(name)  # warm the cache outside the request path
    return engine


templates = _build_templates()


# ---------------------------------------------------------------------------
# View helpers
# ---------------------------------------------------------------------------


def _parse_iso(value: Any) -> datetime | None:
    """Parse an ISO-8601 string (or pass a datetime through)."""
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def _alert_view(alert: Mapping[str, Any]) -> dict[str, Any]:
    """Alert record with a pre-rendered relative age for templates."""
    view = dict(alert)
    view["age"] = formatting.format_ago(_parse_iso(alert.get("created_at")))
    return view


def _issue_view(issue: Mapping[str, Any] | HealthIssue) -> dict[str, Any]:
    """Health issue (mapping or :class:`HealthIssue`) with a relative age."""
    view = dict(issue) if isinstance(issue, Mapping) else dict(issue.to_dict())
    view["age"] = formatting.format_ago(_parse_iso(view.get("detected_at")))
    return view


def _diagnostic_view(record: Mapping[str, Any]) -> dict[str, Any]:
    """Diagnostic-history row with a pre-rendered relative age."""
    view = dict(record)
    view["age"] = formatting.format_ago(_parse_iso(record.get("created_at")))
    return view


def _history_diagnosis_view(record: Mapping[str, Any]) -> dict[str, Any]:
    """Shape a stored diagnostic row like a live diagnosis payload.

    The web templates render both through the same ``_diagnosis_card.html``
    partial, so history entries and fresh diagnoses look identical.
    """
    source = str(record.get("source") or "rule")
    severity = str(record.get("severity") or "warning")
    if record.get("execution_success") is True:
        state = "ok"
    elif record.get("execution_success") is False:
        state = "critical"
    else:
        state = severity if severity in {"warning", "critical"} else "ok"

    fixes: list[dict[str, Any]] = []
    for index, raw in enumerate(record.get("fixes") or []):
        if not isinstance(raw, Mapping):
            continue
        command = str(raw.get("command") or "").strip()
        if not command:
            continue
        success = raw.get("success")
        fixes.append(
            {
                "index": int(raw.get("index", index)),
                "command": command,
                "explanation": str(raw.get("explanation") or ""),
                "requires_root": bool(raw.get("requires_root")),
                "dangerous": bool(raw.get("dangerous")),
                "executed": bool(raw.get("executed")),
                "success": success if isinstance(success, bool) else None,
            }
        )

    return {
        "id": record.get("id"),
        "issue_type": record.get("issue_type") or "unknown",
        "issue_details": record.get("issue_details") or "",
        "severity": severity,
        "source": source,
        "rule_name": None,
        "model": None,
        "duration_ms": float(record.get("duration_ms") or 0.0),
        "created_at": record.get("created_at"),
        "confidence": float(record.get("confidence") or 0.0),
        "diagnosis": record.get("diagnosis") or "",
        "fixes": fixes,
        "risks": record.get("risks") or "",
        "verify": record.get("verify_command") or "",
        "state": state,
        "ai_attempted": source == "ai",
        "ai_error": None,
    }


def _display_state(health: Mapping[str, Any] | None) -> str:
    """Health state for display: unknown when nothing has been measured."""
    if not health:
        return "unknown"
    components = health.get("components") or []
    if components and all(item.get("state") == "unknown" for item in components):
        return "unknown"
    return str(health.get("state") or "unknown")


def _optional_repository(request: Request) -> SQLiteRepository | None:
    repository: SQLiteRepository | None = getattr(request.app.state, "repository", None)
    if repository is None:
        monitor: MonitorManager | None = getattr(request.app.state, "monitor", None)
        repository = monitor.sqlite if monitor is not None else None
    return repository


def _dashboard_context(request: Request) -> dict[str, Any]:
    """Everything dashboard.html renders on first paint."""
    config = getattr(request.app.state, "config", None)
    state = health_api.current_state(request)
    health = state.health.to_dict() if state is not None and state.health else None
    snapshot = state.snapshot if state is not None else None
    issues = health.get("issues", []) if health else []
    alerts = state.alerts if state is not None else []
    return {
        "active_page": "dashboard",
        "state": state,
        "hostname": state.hostname if state is not None else None,
        "score": round(state.score, 1) if state is not None else 0.0,
        "state_name": _display_state(health),
        "health": health,
        "components": health.get("components", []) if health else [],
        "issues": [_issue_view(issue) for issue in issues][:8],
        "issue_count": len(issues),
        "interfaces": health_api.interface_rows(config, snapshot),
        "connectivity": health_api.connectivity_blocks(snapshot),
        "alerts": [_alert_view(alert) for alert in alerts][:8],
        "alert_stats": state.alert_stats if state is not None else {},
        "collectors": state.collectors if state is not None else [],
        "scheduler": state.scheduler if state is not None else {},
        "influx": state.influx if state is not None else {},
        "diagnostics": state.diagnostics if state is not None else {},
        "errors": state.errors if state is not None else [],
        "cycles": state.cycles if state is not None else 0,
        "uptime_text": formatting.format_duration(state.uptime_seconds) if state is not None else "--",
        "last_cycle_text": formatting.format_ago(state.last_cycle_at) if state is not None else "never",
    }


def _interfaces_context(request: Request) -> dict[str, Any]:
    """Everything interfaces.html renders on first paint."""
    config = getattr(request.app.state, "config", None)
    state = health_api.current_state(request)
    snapshot = state.snapshot if state is not None else None
    raw = (snapshot.interfaces.get("interfaces") if snapshot is not None else None) or {}
    selected_name = request.query_params.get("interface")
    return {
        "active_page": "interfaces",
        "state": state,
        "hostname": state.hostname if state is not None else None,
        "interfaces": health_api.interface_rows(config, snapshot),
        "ignored_interfaces": sorted(
            str(name)
            for name in raw
            if config is not None and config.monitoring.ignores_interface(str(name))
        ),
        "selected": health_api.interface_detail(config, snapshot, selected_name)
        if selected_name
        else None,
        "default_route": (snapshot.interfaces.get("default_route") if snapshot is not None else None) or {},
        "collected_at": snapshot.collected_at.isoformat() if snapshot is not None else None,
        "last_cycle_text": formatting.format_ago(state.last_cycle_at) if state is not None else "never",
    }


async def _diagnostics_context(request: Request) -> dict[str, Any]:
    """Everything diagnostics.html renders on first paint, including history."""
    state = health_api.current_state(request)
    current: list[dict[str, Any]] = []
    if state is not None and state.health:
        current = [issue.to_dict() for issue in state.health.issues]
    if not current and state is not None:
        current = [dict(issue) for issue in state.issues if isinstance(issue, Mapping)]
    history: list[dict[str, Any]] = []
    stats: dict[str, Any] = {}
    repository = _optional_repository(request)
    if repository is not None:
        try:
            history = await repository.list_diagnostics(limit=25)
            stats = await repository.diagnostic_stats()
        except Exception as exc:
            logger.warning("diagnostic history unavailable: %s", exc)
    return {
        "active_page": "diagnostics",
        "state": state,
        "hostname": state.hostname if state is not None else None,
        "issues": [_issue_view(issue) for issue in current],
        "diagnostics": [_diagnostic_view(record) for record in history],
        "stats": stats,
        "diagnostics_runtime": state.diagnostics if state is not None else {},
    }


def _setting_kind(value: Any) -> str:
    """Form control to render for a configuration value."""
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, (list, dict)):
        return "json"
    return "text"


def _setting_items(config: NetMonConfig | None) -> list[tuple[str, list[dict[str, Any]]]]:
    """Group the flattened configuration into ordered, renderable sections.

    The InfluxDB token is omitted entirely: it is environment-only and the
    value exposed by ``flattened`` is a redaction marker, not a secret.
    """
    if config is None:
        return []
    groups: dict[str, list[dict[str, Any]]] = {}
    for key, value in config.flattened(redact_secrets=True).items():
        if key == "storage.influxdb.token":
            continue
        section = key.split(".", 1)[0] if "." in key else "general"
        kind = _setting_kind(value)
        groups.setdefault(section, []).append(
            {
                "key": key,
                "kind": kind,
                "options": SETTING_OPTIONS.get(key, ()),
                "reserved": key in RESERVED_SETTINGS,
                "value": ("true" if value else "false") if isinstance(value, bool) else ("" if value is None else str(value)),
                "json": json.dumps(value, indent=2) if kind == "json" else "",
            }
        )

    ordered: list[tuple[str, list[dict[str, Any]]]] = []
    for section in ("general", *CONFIG_SECTIONS):
        items = groups.pop(section, None)
        if items:
            ordered.append((section, items))
    ordered.extend(groups.items())
    return ordered


def _settings_context(request: Request) -> dict[str, Any]:
    """Everything settings.html renders on first paint."""
    config: NetMonConfig | None = getattr(request.app.state, "config", None)
    state = health_api.current_state(request)
    sections = _setting_items(config)
    return {
        "active_page": "settings",
        "state": state,
        "hostname": state.hostname if state is not None else None,
        "sections": sections,
        "setting_count": sum(len(items) for _, items in sections),
        "config_path": getattr(request.app.state, "config_path", None),
    }


async def _alerts_context(request: Request) -> dict[str, Any]:
    """Everything alerts.html renders on first paint (events, rules, channels)."""
    config: NetMonConfig | None = getattr(request.app.state, "config", None)
    state = health_api.current_state(request)
    rules: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    repository = _optional_repository(request)
    if repository is not None:
        try:
            rules = await repository.list_alert_rules()
            events = await repository.list_alert_events(limit=100)
        except Exception as exc:
            logger.warning("alert data unavailable: %s", exc)

    alert_settings = config.alerts if config is not None else None
    channels: list[dict[str, Any]] = []
    if alert_settings is not None:
        channels = [
            {
                "index": index,
                "type": channel.type,
                "url": channel.url,
                "enabled": channel.enabled,
                "name": channel.display_name(),
            }
            for index, channel in enumerate(alert_settings.channels)
        ]

    selected_name = request.query_params.get("rule")
    selected_rule = (
        next((rule for rule in rules if rule["name"] == selected_name), None)
        if selected_name
        else None
    )
    return {
        "active_page": "alerts",
        "state": state,
        "hostname": state.hostname if state is not None else None,
        "rules": rules,
        "events": [_alert_view(event) for event in events],
        "channels": channels,
        "alerts_enabled": alert_settings.enabled if alert_settings is not None else False,
        "cooldown": alert_settings.cooldown if alert_settings is not None else 0,
        "min_severity": alert_settings.min_severity if alert_settings is not None else "warning",
        "unacknowledged": sum(1 for event in events if not event.get("acknowledged")),
        "operators": sorted(OPERATORS),
        "severities": ("info", "warning", "critical"),
        "metric_hints": (
            "health.score",
            "connectivity.gateway.success",
            "connectivity.avg_latency_ms",
            "connectivity.avg_packet_loss",
            "dns.failure_rate",
            "dns.avg_latency_ms",
            "bandwidth.peak_utilization",
            "certificates.soonest_expiry_days",
        ),
        "selected_rule": selected_rule,
    }


def _render_page(
    request: Request,
    template: str,
    context: dict[str, Any],
    fragments: frozenset[str],
) -> HTMLResponse:
    """Render a full page, or one named HTML fragment for an HTMX swap."""
    fragment = request.query_params.get("fragment")
    context = dict(context)
    context["fragment"] = fragment if fragment in fragments else None
    return templates.TemplateResponse(request, template, context)


# ---------------------------------------------------------------------------
# Application lifecycle
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Own the monitor lifecycle only for standalone (module-level) apps."""
    started = False
    if app.state.owns_monitor and app.state.monitor is None:
        await _start_standalone(app)
        started = True
    try:
        yield
    finally:
        if started:
            await _stop_standalone(app)


def _build_collectors(config: NetMonConfig) -> list[BaseCollector]:
    """Instantiate the configured collectors when the package is importable."""
    try:
        from netmon.collectors import create_collectors

        return list(create_collectors(config))
    except Exception as exc:
        logger.warning("collector factory unavailable (%s); serving without collectors", exc)
        return []


async def _start_standalone(app: FastAPI) -> None:
    """Build, wire and start a monitor for ``uvicorn netmon.web.main:app``."""
    config: NetMonConfig | None = app.state.config
    if config is None:
        config = await asyncio.to_thread(load_config)
        app.state.config = config

    repository: SQLiteRepository | None = app.state.repository
    if repository is None:
        repository = await open_repository(config.storage.resolved_sqlite_path())
        app.state.repository = repository
        app.state.owned_repository = True

    influx: InfluxRepository | None = app.state.influx
    if influx is None:
        influx = InfluxRepository(config.storage.influxdb)
        app.state.influx = influx
        app.state.owned_influx = True

    holder: dict[str, MonitorManager | None] = {"monitor": None}

    def snapshot_provider() -> SystemSnapshot | None:
        monitor = holder["monitor"]
        return monitor.get_current_state().snapshot if monitor is not None else None

    engine = build_engine(config, repository, influx, snapshot_provider=snapshot_provider)
    alert_manager = AlertManager(config.alerts, repository)
    monitor = MonitorManager(
        config,
        _build_collectors(config),
        HealthChecker(config.health),
        engine,
        alert_manager,
        repository,
        influx,
    )
    holder["monitor"] = monitor
    app.state.monitor = monitor
    await monitor.start()
    logger.info("standalone web monitor started")


async def _stop_standalone(app: FastAPI) -> None:
    """Stop the standalone monitor and close the backends it created."""
    monitor: MonitorManager | None = app.state.monitor
    if monitor is not None:
        with contextlib.suppress(Exception):
            await monitor.stop()
        app.state.monitor = None
    if app.state.owned_repository and app.state.repository is not None:
        with contextlib.suppress(Exception):
            await app.state.repository.close()
    if app.state.owned_influx and app.state.influx is not None:
        with contextlib.suppress(Exception):
            await app.state.influx.close()


# ---------------------------------------------------------------------------
# Application factory and module-level binding
# ---------------------------------------------------------------------------


def _bind_state(
    app: FastAPI,
    monitor: MonitorManager | None,
    config: NetMonConfig | None,
    *,
    repository: SQLiteRepository | None,
    influx: InfluxRepository | None,
    owns_monitor: bool,
) -> None:
    """Bind the monitor graph onto ``app.state`` (per-app, never global)."""
    app.state.monitor = monitor
    app.state.config = config
    app.state.repository = (
        repository if repository is not None else (monitor.sqlite if monitor is not None else None)
    )
    app.state.influx = influx if influx is not None else (monitor.influx if monitor is not None else None)
    app.state.owns_monitor = owns_monitor
    app.state.owned_repository = False
    app.state.owned_influx = False
    app.state.config_path = os.environ.get("NETMON_CONFIG_PATH") or None


def _build_app(
    monitor: MonitorManager | None,
    config: NetMonConfig | None,
    *,
    repository: SQLiteRepository | None = None,
    influx: InfluxRepository | None = None,
    owns_monitor: bool = False,
) -> FastAPI:
    """Construct the FastAPI application around an (optional) monitor."""
    app = FastAPI(
        title="NetMon",
        description=f"Network monitor and diagnostic assistant. {__brand_tagline__}",
        version=__version__,
        lifespan=_lifespan,
    )
    _bind_state(
        app,
        monitor,
        config,
        repository=repository,
        influx=influx,
        owns_monitor=owns_monitor,
    )
    if config is not None and credentials_from_env(config) is not None:
        logger.info("web authentication enabled")
    app.add_middleware(BasicAuthMiddleware)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(health_api.router)
    app.include_router(metrics_api.router)
    app.include_router(diagnostics_api.build_router(templates=templates))
    app.include_router(config_api.router)
    _register_pages(app)
    _register_streams(app)
    return app


def create_app(
    monitor: MonitorManager,
    config: NetMonConfig,
    *,
    repository: SQLiteRepository | None = None,
    influx: InfluxRepository | None = None,
) -> FastAPI:
    """Create an app bound to a caller-managed monitor.

    The caller keeps ownership of the monitor lifecycle: the app neither
    starts nor stops it.
    """
    return _build_app(monitor, config, repository=repository, influx=influx, owns_monitor=False)


def set_monitor(
    monitor: MonitorManager,
    config: NetMonConfig,
    *,
    repository: SQLiteRepository | None = None,
    influx: InfluxRepository | None = None,
) -> FastAPI:
    """Bind an externally managed monitor to the module-level app and return it."""
    global _app
    if _app is None:
        _app = create_app(monitor, config, repository=repository, influx=influx)
        return _app
    _bind_state(
        _app,
        monitor,
        config,
        repository=repository,
        influx=influx,
        owns_monitor=False,
    )
    logger.debug("module-level web app bound to a caller-managed monitor")
    return _app


def get_app() -> FastAPI:
    """Return the module-level app, creating it when it does not exist yet.

    A standalone app builds and starts its own monitor in its lifespan, so
    ``uvicorn netmon.web.main:app`` works without an external composition root.
    """
    global _app
    if _app is None:
        _app = _build_app(None, None, owns_monitor=True)
    return _app


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------


def _register_pages(app: FastAPI) -> None:
    """Attach the server-rendered pages and their HTMX fragments."""

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_page(request: Request) -> HTMLResponse:
        """Dashboard: health, components, connectivity, interfaces and charts."""
        return _render_page(
            request, "dashboard.html", _dashboard_context(request), DASHBOARD_FRAGMENTS
        )

    @app.get("/interfaces", response_class=HTMLResponse)
    async def interfaces_page(request: Request) -> HTMLResponse:
        """All interfaces with an HTMX detail expansion per interface."""
        return _render_page(
            request, "interfaces.html", _interfaces_context(request), INTERFACES_FRAGMENTS
        )

    @app.get("/diagnostics", response_class=HTMLResponse)
    async def diagnostics_page(request: Request) -> HTMLResponse:
        """Current issues, one-click diagnosis and diagnostic history."""
        context = await _diagnostics_context(request)
        return _render_page(request, "diagnostics.html", context, DIAGNOSTICS_FRAGMENTS)

    @app.get("/alerts", response_class=HTMLResponse)
    async def alerts_page(request: Request) -> HTMLResponse:
        """Alert events, threshold rules and notification channels."""
        context = await _alerts_context(request)
        return _render_page(request, "alerts.html", context, ALERTS_FRAGMENTS)

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request) -> HTMLResponse:
        """Effective configuration with inline validation and live apply."""
        return _render_page(request, "settings.html", _settings_context(request), frozenset())

    @app.get("/diagnostics/history/{diagnostic_id}", response_class=HTMLResponse)
    async def diagnostic_detail_page(request: Request, diagnostic_id: int) -> HTMLResponse:
        """Full record of one stored diagnosis.

        HTMX requests receive just the diagnosis card so the history table can
        swap it into the result panel; direct navigation gets a complete page
        with the recorded outcome.
        """
        repository = _optional_repository(request)
        record = (
            await repository.get_diagnostic(diagnostic_id) if repository is not None else None
        )
        if record is None:
            raise HTTPException(status_code=404, detail=f"unknown diagnosis: {diagnostic_id}")
        state = health_api.current_state(request)
        hostname = state.hostname if state is not None else None
        diagnosis = _history_diagnosis_view(record)
        if request.query_params.get("fragment") == "diagnosis_result":
            return templates.TemplateResponse(
                request,
                "diagnostics.html",
                {"fragment": "diagnosis_result", "diagnosis": diagnosis, "hostname": hostname},
            )
        return templates.TemplateResponse(
            request,
            "diagnosis_detail.html",
            {
                "active_page": "diagnostics",
                "diagnosis": diagnosis,
                "record": record,
                "state": state,
                "hostname": hostname,
            },
        )


# ---------------------------------------------------------------------------
# Live streams
# ---------------------------------------------------------------------------


def _json_payload(state: SystemState) -> str:
    """Serialise monitor state for the live socket."""
    return json.dumps(state.to_dict(), default=str)


async def _socket_reader(websocket: WebSocket) -> None:
    """Drain client frames so a disconnect is noticed promptly."""
    try:
        while True:
            await websocket.receive()
    except (WebSocketDisconnect, RuntimeError):
        return


def _alert_key(alert: Mapping[str, Any]) -> str:
    """Stable identity for alert de-duplication on the SSE stream."""
    event_id = alert.get("id")
    if event_id is not None:
        return f"id:{event_id}"
    return f"{alert.get('rule_name')}|{alert.get('created_at')}"


def _register_streams(app: FastAPI) -> None:
    """Attach the WebSocket and Server-Sent Events endpoints."""

    @app.websocket("/ws/live")
    async def live_socket(websocket: WebSocket) -> None:
        """Push ``state.to_dict()`` on every change and on a 2s heartbeat."""
        await websocket.accept()
        monitor: MonitorManager | None = getattr(websocket.app.state, "monitor", None)
        if monitor is None:
            await websocket.close(code=1013, reason="monitor is not running")
            return

        queue: asyncio.Queue[SystemState] = asyncio.Queue(maxsize=16)

        def listener(state: SystemState) -> None:
            try:
                queue.put_nowait(state)
            except asyncio.QueueFull:
                logger.debug("live socket is behind; dropping a state update")

        unsubscribe = monitor.subscribe(listener)
        reader = asyncio.create_task(_socket_reader(websocket), name="netmon:ws-reader")
        try:
            await websocket.send_text(_json_payload(monitor.get_current_state()))
            while not reader.done():
                try:
                    state = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_SECONDS)
                    payload = _json_payload(state)
                except TimeoutError:
                    payload = _json_payload(monitor.get_current_state())
                await websocket.send_text(payload)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            unsubscribe()
            reader.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await reader

    @app.get("/sse/alerts")
    async def sse_alerts(request: Request) -> StreamingResponse:
        """Server-Sent Events stream of newly fired alerts."""
        monitor: MonitorManager | None = getattr(request.app.state, "monitor", None)
        if monitor is None:
            raise HTTPException(status_code=503, detail="monitor is not running")
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=200)
        seen: dict[str, None] = {}

        def remember(alert: Mapping[str, Any]) -> bool:
            key = _alert_key(alert)
            if key in seen:
                return False
            seen[key] = None
            while len(seen) > SSE_SEEN_ALERTS:
                seen.pop(next(iter(seen)))
            return True

        for alert in monitor.get_current_state().alerts:
            remember(alert)

        def on_state(state: SystemState) -> None:
            for alert in reversed(state.alerts):
                if not remember(alert):
                    continue
                try:
                    queue.put_nowait(alert)
                except asyncio.QueueFull:
                    logger.debug("dropping an alert for a slow SSE client")

        unsubscribe = monitor.subscribe(on_state)

        async def event_stream() -> AsyncIterator[str]:
            yield ": netmon alert stream connected\n\n"
            try:
                while True:
                    try:
                        alert = await asyncio.wait_for(queue.get(), timeout=SSE_KEEPALIVE_SECONDS)
                    except TimeoutError:
                        yield ": keepalive\n\n"
                        continue
                    yield f"data: {json.dumps(alert, default=str)}\n\n"
            finally:
                unsubscribe()

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )


#: Module-level app used by ``uvicorn netmon.web.main:app``.
_app: FastAPI | None = None
app = get_app()


__all__ = ["app", "create_app", "get_app", "set_monitor"]
