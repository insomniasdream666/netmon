"""Unit tests for the configuration system."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from netmon.config.settings import (
    DEFAULT_IGNORED_INTERFACES,
    MonitoringSettings,
    NetMonConfig,
    apply_env_aliases,
    apply_env_overrides,
    get_by_path,
    load_config,
    save_config,
    set_by_path,
    update_many,
)
from netmon.utils.validation import ValidationError


def test_defaults_match_the_specification() -> None:
    config = NetMonConfig()
    assert config.monitoring.intervals.interfaces == 2
    assert config.monitoring.intervals.connectivity == 10
    assert config.monitoring.intervals.bandwidth == 5
    assert config.monitoring.intervals.ports == 300
    assert config.monitoring.intervals.wifi == 30
    assert config.monitoring.intervals.certificates == 3600
    assert config.health.thresholds.latency_warning == 50
    assert config.health.thresholds.latency_critical == 200
    assert config.health.thresholds.bandwidth_util_critical == 95
    assert config.web.port == 8080
    assert config.ollama.model == "llama3:8b"
    assert config.ollama.timeout == 30


def test_interval_for_and_ignore_matching() -> None:
    monitoring = MonitoringSettings()
    assert monitoring.interval_for("wifi") == 30
    assert monitoring.interval_for("does-not-exist") == 30

    assert monitoring.ignores_interface("lo")
    assert monitoring.ignores_interface("docker0")
    assert monitoring.ignores_interface("veth1a2b")
    assert monitoring.ignores_interface("br-abc123")
    assert not monitoring.ignores_interface("eth0")
    assert "lo" in DEFAULT_IGNORED_INTERFACES


def test_get_and_set_by_path_round_trip() -> None:
    config = NetMonConfig()
    assert get_by_path(config, "web.port") == 8080
    assert get_by_path(config, "monitoring.targets.ping") == ["8.8.8.8", "1.1.1.1", "9.9.9.9"]

    updated = set_by_path(config, "web.port", 9090)
    assert updated.web.port == 9090
    assert config.web.port == 8080, "original config must not be mutated"


def test_set_by_path_rejects_unknown_keys_and_invalid_values() -> None:
    config = NetMonConfig()
    with pytest.raises(KeyError):
        set_by_path(config, "web.nonexistent", 1)
    with pytest.raises(ValidationError):
        set_by_path(config, "nope.field", 1)
    with pytest.raises(KeyError):
        get_by_path(config, "web.nonexistent")
    with pytest.raises(ValidationError):
        get_by_path(config, "nope.field")
    with pytest.raises(ValidationError):
        set_by_path(config, "web.port", 99999)
    with pytest.raises(ValidationError):
        set_by_path(config, "monitoring.intervals.wifi", -5)
    with pytest.raises(ValidationError):
        set_by_path(config, "web..port", 1)


def test_update_many_applies_atomically() -> None:
    config = NetMonConfig()
    updated = update_many(
        config,
        {"web.port": 8181, "monitoring.intervals.wifi": 60, "ollama.model": "mistral:7b"},
    )
    assert (updated.web.port, updated.monitoring.intervals.wifi, updated.ollama.model) == (
        8181,
        60,
        "mistral:7b",
    )
    with pytest.raises(ValidationError):
        update_many(config, {"web.port": 8181, "monitoring.intervals.wifi": 0})


def test_flattened_redacts_secrets() -> None:
    config = NetMonConfig()
    config = set_by_path(config, "storage.influxdb.token", "super-secret")
    flat = config.flattened()
    assert flat["storage.influxdb.token"] == "***"
    assert config.flattened(redact_secrets=False)["storage.influxdb.token"] == "super-secret"


def test_env_aliases_override_yaml_values() -> None:
    data = {"ollama": {"host": "http://from-yaml:11434"}}
    merged = apply_env_aliases(
        data,
        {
            "OLLAMA_HOST": "http://from-env:11434",
            "INFLUXDB_URL": "http://influx:8086",
            "INFLUX_TOKEN": "token-123",
            "OLLAMA_TIMEOUT": "45",
            "NETMON_ALERTS_ENABLED": "false",
        },
    )
    assert merged["ollama"]["host"] == "http://from-env:11434"
    assert merged["ollama"]["timeout"] == 45
    assert merged["storage"]["influxdb"]["url"] == "http://influx:8086"
    assert merged["storage"]["influxdb"]["token"] == "token-123"
    assert merged["alerts"]["enabled"] is False

    config = NetMonConfig(**merged)
    assert config.storage.influxdb.token == "token-123"
    assert config.alerts.enabled is False


def test_netmon_prefixed_env_overrides_yaml_values(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"web": {"port": 4321}, "ollama": {"model": "phi3:mini"}}))
    config = load_config(
        path,
        environ={
            "NETMON_WEB__PORT": "9090",
            "NETMON_OLLAMA__MODEL": "llama3:8b",
            "NETMON_MONITORING__TARGETS__PING": '["10.0.0.1", "10.0.0.2"]',
        },
    )
    assert config.web.port == 9090, "nested NETMON_* env must beat config.yaml"
    assert config.ollama.model == "llama3:8b"
    assert config.monitoring.targets.ping == ["10.0.0.1", "10.0.0.2"]


def test_apply_env_overrides_ignores_unrelated_variables() -> None:
    merged = apply_env_overrides(
        {"web": {"port": 8080}},
        {"NETMON_WEB__PORT": "9090", "PATH": "/usr/bin"},
    )
    assert merged["web"]["port"] == 9090
    assert "PATH" not in merged
    assert NetMonConfig(**merged).web.port == 9090


def test_load_config_reads_yaml(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"web": {"port": 4321}, "ollama": {"model": "phi3:mini"}}))
    config = load_config(path)
    assert config.web.port == 4321
    assert config.ollama.model == "phi3:mini"
    assert config.monitoring.intervals.interfaces == 2, "defaults still apply"


def test_load_config_survives_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("web: {port: 70000}\n")
    config = load_config(path)
    assert config.web.port == 8080, "invalid file falls back to defaults"


def test_load_config_ignores_non_mapping_yaml(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("- just\n- a\n- list\n")
    config = load_config(path)
    assert config.web.port == 8080


def test_save_config_round_trip_and_secret_stripping(tmp_path: Path) -> None:
    config = set_by_path(NetMonConfig(), "storage.influxdb.token", "do-not-persist")
    path = save_config(config, tmp_path / "config.yaml")
    assert path.exists()

    saved = yaml.safe_load(path.read_text())
    assert saved["storage"]["influxdb"]["token"] == ""
    assert saved["web"]["port"] == 8080

    reloaded = load_config(path)
    assert reloaded.storage.influxdb.token == ""


def test_save_config_uses_restrictive_permissions(tmp_path: Path) -> None:
    path = save_config(NetMonConfig(), tmp_path / "nested" / "config.yaml")
    mode = path.stat().st_mode & 0o777
    assert mode == 0o600


def test_resolved_sqlite_path_creates_parent(tmp_path: Path) -> None:
    config = set_by_path(NetMonConfig(), "storage.sqlite_path", str(tmp_path / "a" / "b" / "config.db"))
    resolved = config.storage.resolved_sqlite_path()
    assert resolved.parent.exists()


def test_to_dict_is_json_serialisable() -> None:
    import json

    payload = json.loads(json.dumps(NetMonConfig().to_dict()))
    assert payload["monitoring"]["intervals"]["ports"] == 300


def test_flattened_config_round_trips_through_set_by_path() -> None:
    """Regression: every flattened key (including top-level scalars) must be
    settable again — this is what the SQLite config sync does on every start."""
    config = NetMonConfig()
    restored = config
    for key, value in config.flattened(redact_secrets=False).items():
        restored = set_by_path(restored, key, value)
    assert restored.web.port == config.web.port
    assert restored.monitoring.intervals.ports == config.monitoring.intervals.ports
    assert restored.log_level == config.log_level


def test_top_level_scalar_keys_are_addressable() -> None:
    config = NetMonConfig()
    assert get_by_path(config, "log_level") == "INFO"
    assert get_by_path(config, "debug") is False

    updated = set_by_path(config, "log_level", "DEBUG")
    assert updated.log_level == "DEBUG"
    assert config.log_level == "INFO", "original config must not be mutated"

    with pytest.raises(ValidationError):
        set_by_path(config, "not_a_field", 1)


def test_dotenv_file_is_loaded(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "NETMON_WEB_PORT=9999\nINFLUX_TOKEN=dotenv-token\nOLLAMA_MODEL=dotenv-model\n"
    )
    monkeypatch.setenv("NETMON_ENV_FILE", str(env_file))
    for key in ("NETMON_WEB_PORT", "INFLUX_TOKEN", "OLLAMA_MODEL"):
        monkeypatch.delenv(key, raising=False)

    config = load_config(tmp_path / "missing.yaml")
    assert config.web.port == 9999
    assert config.storage.influxdb.token == "dotenv-token"
    assert config.ollama.model == "dotenv-model"


def test_real_environment_wins_over_dotenv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("NETMON_WEB_PORT=9999\n")
    monkeypatch.setenv("NETMON_ENV_FILE", str(env_file))
    monkeypatch.setenv("NETMON_WEB_PORT", "7777")

    config = load_config(tmp_path / "missing.yaml")
    assert config.web.port == 7777


class _StubConfigRepository:
    """Minimal stand-in for the SQLite config mirror."""

    def __init__(self, stored: dict[str, object]) -> None:
        self.stored = stored
        self.written: dict[str, object] | None = None
        self.deleted: str | None = None

    async def get_config_map(self) -> dict[str, object]:
        return dict(self.stored)

    async def set_config_values(self, values: dict[str, object]) -> int:
        self.written = dict(values)
        return len(values)

    async def delete_config_value(self, key: str) -> bool:
        self.deleted = key
        return self.stored.pop(key, None) is not None


async def test_sqlite_config_mirror_does_not_override_newer_config() -> None:
    from netmon.__main__ import _sync_config_to_sqlite

    config = set_by_path(NetMonConfig(), "web.port", 9090)
    repository = _StubConfigRepository({"web.port": 8080})
    merged = await _sync_config_to_sqlite(config, repository)  # type: ignore[arg-type]
    assert merged.web.port == 9090, "YAML/env must not be reverted by a stale SQLite copy"
    assert repository.written is None


async def test_sqlite_config_mirror_seeds_once_without_token() -> None:
    from netmon.__main__ import _sync_config_to_sqlite

    config = set_by_path(NetMonConfig(), "storage.influxdb.token", "secret")
    repository = _StubConfigRepository({})
    merged = await _sync_config_to_sqlite(config, repository)  # type: ignore[arg-type]

    assert merged.storage.influxdb.token == "secret"
    assert repository.written is not None
    assert "storage.influxdb.token" not in repository.written, "env-only secret leaked into SQLite"
    assert repository.written["web.port"] == 8080


async def test_sqlite_config_mirror_scrubs_legacy_token() -> None:
    from netmon.__main__ import _sync_config_to_sqlite

    repository = _StubConfigRepository(
        {"web.port": 8080, "storage.influxdb.token": "legacy-secret"}
    )
    await _sync_config_to_sqlite(NetMonConfig(), repository)  # type: ignore[arg-type]

    assert repository.deleted == "storage.influxdb.token"
    assert "storage.influxdb.token" not in repository.stored
