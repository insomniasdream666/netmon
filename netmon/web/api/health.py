"""Health, interface, connectivity and collector endpoints for the web API.

The shared dependency accessors (:func:`get_monitor`, :func:`get_config`,
:func:`get_repository`, :func:`get_influx`) live here because every router
needs them and this module has no router-to-router imports, keeping the web
package free of import cycles.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from netmon.config.settings import NetMonConfig
from netmon.core.health import SystemSnapshot
from netmon.core.monitor import MonitorManager, SystemState
from netmon.storage.influx import MEASUREMENT_INTERFACES, InfluxRepository
from netmon.storage.sqlite import SQLiteRepository
from netmon.utils.formatting import relative_range_to_seconds
from netmon.utils.validation import ValidationError, validate_interface_name

router = APIRouter(tags=["health"])

HISTORY_LIMIT = 500


# ---------------------------------------------------------------------------
# Shared dependency accessors
# ---------------------------------------------------------------------------


def get_monitor(request: Request) -> MonitorManager:
    """Return the monitor bound to this application instance.

    Raises:
        HTTPException: 503 when the application has no running monitor.
    """
    monitor: MonitorManager | None = getattr(request.app.state, "monitor", None)
    if monitor is None:
        raise HTTPException(status_code=503, detail="monitor is not running")
    return monitor


def get_config(request: Request) -> NetMonConfig:
    """Return the effective configuration of this application instance."""
    config: NetMonConfig | None = getattr(request.app.state, "config", None)
    if config is None:
        raise HTTPException(status_code=503, detail="configuration is not loaded")
    return config


def get_repository(request: Request) -> SQLiteRepository:
    """Return the SQLite repository, falling back to the monitor's own."""
    repository: SQLiteRepository | None = getattr(request.app.state, "repository", None)
    if repository is None:
        monitor: MonitorManager | None = getattr(request.app.state, "monitor", None)
        repository = monitor.sqlite if monitor is not None else None
    if repository is None:
        raise HTTPException(status_code=503, detail="SQLite repository is not available")
    return repository


def get_influx(request: Request) -> InfluxRepository | None:
    """Return the time-series repository, or None when none is configured."""
    influx: InfluxRepository | None = getattr(request.app.state, "influx", None)
    if influx is None:
        monitor: MonitorManager | None = getattr(request.app.state, "monitor", None)
        influx = monitor.influx if monitor is not None else None
    return influx


def current_state(request: Request) -> SystemState | None:
    """Current monitor state, or None when no monitor is bound yet."""
    monitor: MonitorManager | None = getattr(request.app.state, "monitor", None)
    return monitor.get_current_state() if monitor is not None else None


# ---------------------------------------------------------------------------
# View helpers shared with the page routes
# ---------------------------------------------------------------------------


def interface_rows(config: NetMonConfig | None, snapshot: SystemSnapshot | None) -> list[dict[str, Any]]:
    """Merge interface and bandwidth snapshots into display rows.

    Interfaces matching ``monitoring.ignored_interfaces`` are filtered out.
    """
    if snapshot is None:
        return []
    interfaces = snapshot.interfaces.get("interfaces") or {}
    bandwidth = snapshot.bandwidth.get("interfaces") or {}
    rows: list[dict[str, Any]] = []
    for name, info in sorted(interfaces.items()):
        if not isinstance(info, Mapping):
            continue
        if config is not None and config.monitoring.ignores_interface(str(name)):
            continue
        row: dict[str, Any] = {"name": str(name)}
        row.update(dict(info))
        traffic = bandwidth.get(name)
        row["bandwidth"] = dict(traffic) if isinstance(traffic, Mapping) else None
        rows.append(row)
    return rows


def interface_detail(
    config: NetMonConfig | None, snapshot: SystemSnapshot | None, name: str
) -> dict[str, Any] | None:
    """One interface with its bandwidth sample, ignored or not; None when absent."""
    if snapshot is None:
        return None
    interfaces = snapshot.interfaces.get("interfaces") or {}
    info = interfaces.get(name)
    if not isinstance(info, Mapping):
        return None
    row: dict[str, Any] = {"name": name}
    row.update(dict(info))
    bandwidth = snapshot.bandwidth.get("interfaces") or {}
    traffic = bandwidth.get(name)
    row["bandwidth"] = dict(traffic) if isinstance(traffic, Mapping) else None
    row["ignored"] = bool(config.monitoring.ignores_interface(name)) if config is not None else False
    return row


def connectivity_blocks(snapshot: SystemSnapshot | None) -> dict[str, Any]:
    """The ping/dns/gateway/internet/traceroute blocks from the snapshot."""
    connectivity = (snapshot.connectivity if snapshot is not None else None) or {}
    return {
        "ping": connectivity.get("ping") or {},
        "dns": connectivity.get("dns") or {},
        "dns_health": connectivity.get("dns_health") or {},
        "gateway": connectivity.get("gateway") or {},
        "internet": connectivity.get("internet") or {},
        "traceroute": connectivity.get("traceroute") or {},
        "collected_at": snapshot.collected_at.isoformat() if snapshot is not None else None,
    }


def health_payload(state: SystemState) -> dict[str, Any]:
    """Overall health plus collector, scheduler and backend status."""
    health = state.health.to_dict() if state.health else None
    ai = state.diagnostics.get("ai") if isinstance(state.diagnostics, Mapping) else None
    return {
        "score": health["score"] if health else 0.0,
        "state": health["state"] if health else "unknown",
        "checked_at": health["checked_at"] if health else None,
        "components": health["components"] if health else [],
        "issues": health["issues"] if health else [],
        "collectors": state.collectors,
        "scheduler": state.scheduler,
        "influx": state.influx,
        "ollama": ai or {"enabled": False},
        "diagnostics": state.diagnostics,
        "hostname": state.hostname,
        "version": state.version,
        "uptime_seconds": round(state.uptime_seconds, 1),
        "cycles": state.cycles,
        "last_cycle_at": state.last_cycle_at.isoformat() if state.last_cycle_at else None,
        "last_cycle_ms": round(state.last_cycle_ms, 2),
        "errors": state.errors,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/api/health")
async def api_health(request: Request) -> dict[str, Any]:
    """Overall score and state, per-component results and backend status."""
    monitor = get_monitor(request)
    return health_payload(monitor.get_current_state())


@router.get("/api/interfaces")
async def api_interfaces(request: Request) -> dict[str, Any]:
    """All monitored interfaces with their current metrics."""
    monitor = get_monitor(request)
    config = get_config(request)
    snapshot = monitor.get_current_state().snapshot
    rows = interface_rows(config, snapshot)
    default_route = (snapshot.interfaces.get("default_route") if snapshot is not None else None) or {}
    return {
        "interfaces": rows,
        "count": len(rows),
        "default_route": default_route,
        "ignored_interfaces": list(config.monitoring.ignored_interfaces),
        "collected_at": snapshot.collected_at.isoformat() if snapshot is not None else None,
    }


@router.get("/api/interfaces/{name}")
async def api_interface(
    request: Request,
    name: str,
    range_token: str = Query("1h", alias="range"),
) -> dict[str, Any]:
    """One interface: current detail plus recent history from InfluxDB."""
    try:
        name = validate_interface_name(name)
        relative_range_to_seconds(range_token)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid range: {range_token!r}") from exc

    monitor = get_monitor(request)
    config = get_config(request)
    snapshot = monitor.get_current_state().snapshot
    detail = interface_detail(config, snapshot, name)

    history: list[dict[str, Any]] = []
    influx = get_influx(request)
    if influx is not None:
        history = await influx.query_range(
            MEASUREMENT_INTERFACES,
            range_token=range_token,
            tag_filters={"interface": name},
            limit=HISTORY_LIMIT,
        )
    if detail is None and not history:
        raise HTTPException(status_code=404, detail=f"unknown interface: {name}")
    return {
        "name": name,
        "current": detail or {"name": name},
        "ignored": bool(detail and detail.get("ignored")),
        "history": history,
        "history_count": len(history),
        "range": range_token,
    }


@router.get("/api/connectivity")
async def api_connectivity(request: Request) -> dict[str, Any]:
    """Ping, DNS, gateway, internet and traceroute results from the snapshot."""
    monitor = get_monitor(request)
    return connectivity_blocks(monitor.get_current_state().snapshot)


@router.get("/api/collectors")
async def api_collectors(request: Request) -> dict[str, Any]:
    """Per-collector runtime status and the scheduler table."""
    state = get_monitor(request).get_current_state()
    return {
        "collectors": state.collectors,
        "count": len(state.collectors),
        "scheduler": state.scheduler,
    }


__all__ = [
    "connectivity_blocks",
    "current_state",
    "get_config",
    "get_influx",
    "get_monitor",
    "get_repository",
    "health_payload",
    "interface_detail",
    "interface_rows",
    "router",
]
