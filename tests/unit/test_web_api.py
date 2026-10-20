"""Web API tests for settings and alert-rule management.

These use a minimal app with in-memory repository/monitor stubs so they can
exercise validation, coercion and HTMX response headers without a live server.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from netmon.config.settings import NetMonConfig
from netmon.web.api import config as config_api


class _Repository:
    def __init__(self) -> None:
        self.config_values: dict[str, Any] = {}
        self.rules: dict[str, dict[str, Any]] = {}

    async def set_config_value(self, key: str, value: Any) -> None:
        self.config_values[key] = value

    async def list_alert_rules(self) -> list[dict[str, Any]]:
        return list(self.rules.values())

    async def upsert_alert_rule(self, **values: Any) -> int:
        name = str(values["name"])
        rule = {
            "id": len(self.rules) + 1,
            "name": name,
            "metric": values["metric"],
            "operator": values["operator"],
            "threshold": float(values["threshold"]),
            "severity": values["severity"],
            "enabled": bool(values["enabled"]),
            "cooldown": int(values["cooldown"]),
            "channels": list(values["channels"]),
            "message_template": values["message_template"],
            "description": values["description"],
            "updated_at": "2026-10-20T00:00:00+00:00",
        }
        self.rules[name] = rule
        return int(rule["id"])

    async def delete_alert_rule(self, name: str) -> bool:
        return self.rules.pop(name, None) is not None


class _AlertManager:
    def __init__(self) -> None:
        self.tested: list[Any] = []

    async def test_channel(self, channel: Any) -> tuple[bool, str | None]:
        self.tested.append(channel)
        return True, None


class _Monitor:
    def __init__(self) -> None:
        self.alert_manager = _AlertManager()
        self.configs: list[NetMonConfig] = []

    async def config_changed(self, config: NetMonConfig) -> None:
        self.configs.append(config)


def make_client(tmp_path: Path) -> tuple[TestClient, _Repository, _Monitor]:
    app = FastAPI()
    app.include_router(config_api.router)
    repository = _Repository()
    monitor = _Monitor()
    app.state.config = NetMonConfig()
    app.state.config_path = tmp_path / "config.yaml"
    app.state.repository = repository
    app.state.monitor = monitor
    return TestClient(app), repository, monitor


def test_patch_coerces_json_list_and_triggers_refresh(tmp_path: Path) -> None:
    client, repository, monitor = make_client(tmp_path)

    response = client.patch(
        "/api/config/monitoring.targets.ping",
        json={"value": '["1.1.1.1", "8.8.8.8"]'},
    )

    assert response.status_code == 200
    assert response.json()["value"] == ["1.1.1.1", "8.8.8.8"]
    assert response.headers["HX-Trigger"] == "configChanged"
    assert repository.config_values["monitoring.targets.ping"] == ["1.1.1.1", "8.8.8.8"]
    assert monitor.configs and monitor.configs[0].monitoring.targets.ping == ["1.1.1.1", "8.8.8.8"]
    assert (tmp_path / "config.yaml").exists()


def test_patch_rejects_invalid_json_for_a_list_setting(tmp_path: Path) -> None:
    client, _, _ = make_client(tmp_path)

    response = client.patch(
        "/api/config/monitoring.targets.ping",
        json={"value": "not-json"},
    )

    assert response.status_code == 400
    assert "expects JSON" in response.json()["detail"]


def test_post_alert_rule_accepts_form_strings_and_splits_channels(tmp_path: Path) -> None:
    client, repository, _ = make_client(tmp_path)

    response = client.post(
        "/api/alert-rules",
        json={
            "name": "custom-latency",
            "metric": "connectivity.avg_latency_ms",
            "operator": ">",
            "threshold": "150.5",
            "severity": "warning",
            "enabled": "true",
            "cooldown": "120",
            "channels": "log, ntfy",
            "description": "Latency above 150 ms",
        },
    )

    assert response.status_code == 200
    rule = response.json()["rule"]
    assert rule["threshold"] == 150.5
    assert rule["enabled"] is True
    assert rule["cooldown"] == 120
    assert rule["channels"] == ["log", "ntfy"]
    assert repository.rules["custom-latency"]["severity"] == "warning"
    assert response.headers["HX-Trigger"] == "rulesChanged"


def test_alert_channel_test_and_unknown_index(tmp_path: Path) -> None:
    client, _, monitor = make_client(tmp_path)

    response = client.post("/api/alert-channels/0/test")

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert response.json()["channel"] == "log"
    assert len(monitor.alert_manager.tested) == 1
    assert client.post("/api/alert-channels/99/test").status_code == 404
