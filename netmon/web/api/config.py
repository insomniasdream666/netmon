"""Configuration, alert-event and alert-rule endpoints.

Configuration updates are validated through
:func:`netmon.config.settings.set_by_path`, persisted to SQLite and YAML and
then applied to the running monitor. The InfluxDB token is environment-only
and cannot be changed through the API.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from netmon.config.settings import CONFIG_SECTIONS, get_by_path, save_config, set_by_path
from netmon.core.alerts import OPERATORS
from netmon.utils.validation import ValidationError
from netmon.web.api.health import get_config, get_monitor, get_repository
from netmon.web.auth import credentials_from_env

router = APIRouter(tags=["config"])

PROTECTED_KEYS = frozenset({"storage.influxdb.token"})
RULE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
VALID_SEVERITIES = frozenset({"info", "warning", "critical"})


class ConfigUpdate(BaseModel):
    """Payload for ``PATCH /api/config/{key}``."""

    value: Any = None


class AlertRulePayload(BaseModel):
    """Payload for the alert-rule create and replace endpoints."""

    model_config = ConfigDict(extra="forbid")

    metric: str = Field(min_length=1, max_length=200)
    operator: str = ">"
    threshold: float = 0.0
    severity: str = "warning"
    enabled: bool = True
    cooldown: int = Field(default=300, ge=0, le=86400)
    channels: list[str] = Field(default_factory=list)
    message_template: str = ""
    description: str = ""

    @field_validator("channels", mode="before")
    @classmethod
    def _split_channels(cls, value: Any) -> Any:
        """Accept a comma-separated string from the HTML form as well as JSON lists."""
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value


class AlertRuleCreate(AlertRulePayload):
    """A rule name is part of the body for browser-friendly ``POST`` requests."""

    name: str = Field(min_length=1, max_length=64)


def _validate_rule_name(name: str) -> None:
    if not RULE_NAME_RE.match(name):
        raise HTTPException(
            status_code=400,
            detail="invalid rule name: use 1-64 letters, digits, dots, dashes or underscores",
        )


def _validate_rule_payload(payload: AlertRulePayload) -> None:
    if payload.operator not in OPERATORS:
        allowed = ", ".join(sorted(OPERATORS))
        raise HTTPException(
            status_code=400,
            detail=f"unknown operator: {payload.operator!r} (expected {allowed})",
        )
    if payload.severity not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=f"unknown severity: {payload.severity!r} (expected info, warning or critical)",
        )


async def _save_rule(request: Request, name: str, payload: AlertRulePayload) -> dict[str, Any]:
    repository = get_repository(request)
    rule_id = await repository.upsert_alert_rule(
        name=name,
        metric=payload.metric,
        operator=payload.operator,
        threshold=payload.threshold,
        severity=payload.severity,
        enabled=payload.enabled,
        cooldown=payload.cooldown,
        channels=payload.channels,
        message_template=payload.message_template,
        description=payload.description,
    )
    rules = await repository.list_alert_rules()
    rule = next((item for item in rules if item["name"] == name), None)
    return {"rule": rule, "id": rule_id}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@router.get("/api/config")
async def api_config(request: Request) -> dict[str, Any]:
    """The effective configuration as flattened ``dotted.key`` -> value pairs."""
    return get_config(request).flattened(redact_secrets=True)


@router.patch("/api/config/{key}")
async def api_config_update(
    request: Request, key: str, payload: ConfigUpdate, response: Response
) -> dict[str, Any]:
    """Validate, persist and apply a single configuration value."""
    candidate = key.strip()
    if candidate in PROTECTED_KEYS or candidate.startswith("storage.influxdb.token"):
        raise HTTPException(
            status_code=400,
            detail=(
                "storage.influxdb.token cannot be changed through the API; "
                "set INFLUX_TOKEN in the environment instead"
            ),
        )

    config = get_config(request)
    value = payload.value
    # The settings form edits lists and objects as JSON textareas. Coerce JSON
    # strings here so both the browser and API clients can use the same field.
    if isinstance(value, str):
        try:
            current = get_by_path(config, candidate)
        except (KeyError, ValidationError):
            current = None
        if isinstance(current, (list, dict)):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as exc:
                raise HTTPException(
                    status_code=400,
                    detail=f"{candidate} expects JSON: {exc.msg}",
                ) from exc

    try:
        updated = set_by_path(config, candidate, value)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        message = str(exc.args[0]) if exc.args else f"unknown config key: {candidate}"
        raise HTTPException(status_code=404, detail=message) from exc
    if updated.web.auth:
        try:
            credentials_from_env(updated)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    repository = get_repository(request)
    await repository.set_config_value(candidate, value)
    config_path = getattr(request.app.state, "config_path", None)
    await asyncio.to_thread(save_config, updated, config_path)

    request.app.state.config = updated
    monitor = get_monitor(request)
    await monitor.config_changed(updated)
    response.headers["HX-Trigger"] = "configChanged"

    return {
        "key": candidate,
        "value": get_by_path(updated, candidate),
        "sections": list(CONFIG_SECTIONS),
        "config": updated.flattened(redact_secrets=True),
    }


# ---------------------------------------------------------------------------
# Alert events
# ---------------------------------------------------------------------------


@router.get("/api/alerts")
async def api_alerts(request: Request, limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    """Recent alert events from SQLite, newest first."""
    repository = get_repository(request)
    events = await repository.list_alert_events(limit=limit)
    return {
        "alerts": events,
        "count": len(events),
        "unacknowledged": sum(1 for event in events if not event["acknowledged"]),
    }


@router.post("/api/alerts/{event_id}/acknowledge")
async def api_acknowledge_alert(
    request: Request, event_id: int, response: Response
) -> dict[str, Any]:
    """Acknowledge one alert event."""
    repository = get_repository(request)
    if not await repository.acknowledge_alert(event_id):
        raise HTTPException(status_code=404, detail=f"unknown alert event: {event_id}")
    response.headers["HX-Trigger"] = "alertsChanged"
    return {"acknowledged": True, "event_id": event_id}


@router.post("/api/alert-channels/{channel_index}/test")
async def api_test_alert_channel(request: Request, channel_index: int) -> dict[str, Any]:
    """Send a synthetic alert to one configured notification channel."""
    config = get_config(request)
    channels = config.alerts.channels
    if channel_index < 0 or channel_index >= len(channels):
        raise HTTPException(status_code=404, detail=f"unknown alert channel: {channel_index}")

    channel = channels[channel_index]
    monitor = get_monitor(request)
    ok, error = await monitor.alert_manager.test_channel(channel)
    return {
        "index": channel_index,
        "channel": channel.display_name(),
        "type": channel.type,
        "enabled": channel.enabled,
        "ok": ok,
        "error": error,
    }


# ---------------------------------------------------------------------------
# Alert rules
# ---------------------------------------------------------------------------


@router.get("/api/alert-rules")
async def api_alert_rules(request: Request) -> dict[str, Any]:
    """All configured alert rules."""
    repository = get_repository(request)
    rules = await repository.list_alert_rules()
    return {"rules": rules, "count": len(rules)}


@router.put("/api/alert-rules/{name}")
async def api_put_alert_rule(
    request: Request, name: str, payload: AlertRulePayload, response: Response
) -> dict[str, Any]:
    """Create or replace an alert rule by name."""
    _validate_rule_name(name)
    _validate_rule_payload(payload)
    result = await _save_rule(request, name, payload)
    response.headers["HX-Trigger"] = "rulesChanged"
    return result


@router.post("/api/alert-rules")
async def api_create_alert_rule(
    request: Request, payload: AlertRuleCreate, response: Response
) -> dict[str, Any]:
    """Create or replace an alert rule with the name in the request body."""
    _validate_rule_name(payload.name)
    _validate_rule_payload(payload)
    result = await _save_rule(request, payload.name, payload)
    response.headers["HX-Trigger"] = "rulesChanged"
    return result


@router.delete("/api/alert-rules/{name}")
async def api_delete_alert_rule(request: Request, name: str, response: Response) -> dict[str, Any]:
    """Delete an alert rule by name."""
    repository = get_repository(request)
    if not await repository.delete_alert_rule(name):
        raise HTTPException(status_code=404, detail=f"unknown alert rule: {name}")
    response.headers["HX-Trigger"] = "rulesChanged"
    return {"deleted": True, "name": name}


__all__ = ["router"]
