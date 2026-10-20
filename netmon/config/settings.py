"""Configuration system: Pydantic models, YAML persistence and env overlay.

Resolution order (later wins):

1. Built-in defaults defined by the models below.
2. ``~/.config/netmon/config.yaml`` (or ``NETMON_CONFIG_PATH``).
3. A ``.env`` file (``NETMON_ENV_FILE``, then ``./.env``, then
   ``~/.config/netmon/.env``); real environment variables always win.
4. Friendly aliases for the variables documented in ``.env.example``, such as
   ``OLLAMA_HOST``, ``INFLUXDB_URL`` and ``INFLUX_TOKEN``.
5. ``NETMON_*`` variables using ``__`` as the nested delimiter, for example
   ``NETMON_WEB__PORT=9090``.
6. Explicit overrides passed to :func:`load_config` (used by tests and CLI
   flags).

The effective configuration is mirrored into SQLite on first run for
inspection; it is never re-applied on later startups, so editing
``config.yaml`` or the environment is always safe.
"""

from __future__ import annotations

import contextlib
import fnmatch
import json
import logging
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field
from pydantic import ValidationError as PydanticValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from netmon.utils.validation import ValidationError, validate_dotted_key

logger = logging.getLogger(__name__)

CONFIG_DIR = Path(os.environ.get("NETMON_CONFIG_DIR", "~/.config/netmon")).expanduser()
DEFAULT_YAML_PATH = CONFIG_DIR / "config.yaml"
DEFAULT_DB_PATH = CONFIG_DIR / "config.db"

DEFAULT_IGNORED_INTERFACES: tuple[str, ...] = ("lo", "docker*", "veth*", "br-*", "virbr*", "tun*")


def expand_path(value: str | Path) -> Path:
    """Expand ``~`` and environment variables in a path."""
    return Path(os.path.expandvars(str(value))).expanduser()


# ---------------------------------------------------------------------------
# Nested configuration models
# ---------------------------------------------------------------------------


class IntervalSettings(BaseModel):
    """Per-collector polling intervals, in seconds."""

    model_config = ConfigDict(extra="forbid")

    interfaces: int = Field(default=2, ge=1, le=3600)
    connectivity: int = Field(default=10, ge=1, le=3600)
    bandwidth: int = Field(default=5, ge=1, le=3600)
    ports: int = Field(default=300, ge=10, le=86400)
    connections: int = Field(default=15, ge=1, le=3600)
    wifi: int = Field(default=30, ge=1, le=3600)
    certificates: int = Field(default=3600, ge=60, le=86400)


class TargetSettings(BaseModel):
    """Remote endpoints the connectivity and certificate collectors probe."""

    model_config = ConfigDict(extra="forbid")

    ping: list[str] = Field(default_factory=lambda: ["8.8.8.8", "1.1.1.1", "9.9.9.9"])
    dns: list[str] = Field(default_factory=lambda: ["google.com", "github.com", "cloudflare.com"])
    traceroute: list[str] = Field(default_factory=lambda: ["8.8.8.8"])
    certificates: list[str] = Field(
        default_factory=lambda: ["github.com:443", "google.com:443", "1.1.1.1:443"]
    )
    ports: list[str] = Field(default_factory=lambda: ["127.0.0.1"])


class PortScanSettings(BaseModel):
    """nmap wrapper configuration."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    targets: list[str] = Field(default_factory=lambda: ["127.0.0.1"])
    ports: str = "1-1024"
    protocol: Literal["tcp", "udp", "both"] = "tcp"
    service_detection: bool = True
    arguments: str = "-sV -T4"
    max_targets: int = Field(default=4, ge=1, le=32)


class MonitoringSettings(BaseModel):
    """Everything about how data is collected."""

    model_config = ConfigDict(extra="forbid")

    intervals: IntervalSettings = Field(default_factory=IntervalSettings)
    targets: TargetSettings = Field(default_factory=TargetSettings)
    port_scan: PortScanSettings = Field(default_factory=PortScanSettings)
    ignored_interfaces: list[str] = Field(default_factory=lambda: list(DEFAULT_IGNORED_INTERFACES))
    enabled_collectors: list[str] = Field(
        default_factory=lambda: [
            "interfaces",
            "connectivity",
            "bandwidth",
            "ports",
            "connections",
            "wifi",
            "certificates",
        ]
    )
    history_points: int = Field(default=120, ge=10, le=5000)

    def interval_for(self, collector: str) -> int:
        """Interval in seconds for a named collector, defaulting to 30s."""
        value = getattr(self.intervals, collector, None)
        return int(value) if isinstance(value, int) else 30

    def ignores_interface(self, name: str) -> bool:
        """True when ``name`` matches one of the ignore globs."""
        return any(fnmatch.fnmatch(name, pattern) for pattern in self.ignored_interfaces)


class HealthThresholds(BaseModel):
    """Thresholds that turn raw measurements into health states."""

    model_config = ConfigDict(extra="forbid")

    latency_warning: float = Field(default=50.0, ge=0)
    latency_critical: float = Field(default=200.0, ge=0)
    packet_loss_warning: float = Field(default=1.0, ge=0, le=100)
    packet_loss_critical: float = Field(default=5.0, ge=0, le=100)
    bandwidth_util_warning: float = Field(default=80.0, ge=0, le=100)
    bandwidth_util_critical: float = Field(default=95.0, ge=0, le=100)
    dns_latency_warning: float = Field(default=100.0, ge=0)
    dns_latency_critical: float = Field(default=300.0, ge=0)
    dns_failure_warning: float = Field(default=1.0, ge=0, le=100)
    dns_failure_critical: float = Field(default=50.0, ge=0, le=100)
    wifi_signal_warning: int = Field(default=-70, ge=-120, le=0)
    wifi_signal_critical: int = Field(default=-80, ge=-120, le=0)
    cert_expiry_warning_days: int = Field(default=30, ge=0)
    cert_expiry_critical_days: int = Field(default=7, ge=0)
    interface_error_warning: float = Field(default=1.0, ge=0)
    interface_error_critical: float = Field(default=50.0, ge=0)
    health_score_warning: float = Field(default=80.0, ge=0, le=100)
    health_score_critical: float = Field(default=50.0, ge=0, le=100)
    connection_count_warning: int = Field(default=2000, ge=0)


class HealthSettings(BaseModel):
    """Health scoring configuration."""

    model_config = ConfigDict(extra="forbid")

    thresholds: HealthThresholds = Field(default_factory=HealthThresholds)
    weights: dict[str, float] = Field(
        default_factory=lambda: {
            "interfaces": 1.0,
            "connectivity": 1.5,
            "bandwidth": 1.0,
            "dns": 1.5,
            "wifi": 0.75,
            "certificates": 1.0,
            "connections": 0.5,
        }
    )


class AlertChannel(BaseModel):
    """A notification destination for fired alerts."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["webhook", "ntfy", "discord", "log"] = "log"
    url: str | None = None
    enabled: bool = True
    headers: dict[str, str] = Field(default_factory=dict)

    def display_name(self) -> str:
        """Short label used in the UI."""
        if self.type == "log" or not self.url:
            return self.type
        return f"{self.type}:{self.url.rsplit('/', 1)[-1]}"


class AlertsSettings(BaseModel):
    """Alerting behaviour: enablement, cooldown and channels."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    cooldown: int = Field(default=300, ge=0)
    channels: list[AlertChannel] = Field(default_factory=lambda: [AlertChannel(type="log")])
    min_severity: Literal["info", "warning", "critical"] = "warning"
    max_events: int = Field(default=500, ge=50, le=10000)


class OllamaSettings(BaseModel):
    """Local LLM configuration for AI-assisted diagnostics."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    host: str = "http://localhost:11434"
    model: str = "llama3:8b"
    timeout: float = Field(default=30.0, gt=0, le=600)
    prompt_template: str = "default"
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    max_retries: int = Field(default=1, ge=0, le=5)
    learning_enabled: bool = True
    keep_num_ctx: int = Field(default=4096, ge=512)


class InfluxSettings(BaseModel):
    """InfluxDB 2.x connection settings."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    url: str = "http://localhost:8086"
    token: str = ""
    org: str = "netmon"
    bucket: str = "metrics"
    timeout_ms: int = Field(default=10000, ge=500, le=120000)

    def is_configured(self) -> bool:
        """True when a token is present, meaning writes can be attempted."""
        return bool(self.token)


class RetentionSettings(BaseModel):
    """How long data is kept."""

    model_config = ConfigDict(extra="forbid")

    metrics: str = "30d"
    diagnostics: int = Field(default=90, ge=1, le=3650)


class StorageSettings(BaseModel):
    """Persistence locations."""

    model_config = ConfigDict(extra="forbid")

    sqlite_path: str = str(DEFAULT_DB_PATH)
    influxdb: InfluxSettings = Field(default_factory=InfluxSettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)

    def resolved_sqlite_path(self) -> Path:
        """Expanded SQLite path, creating the parent directory if needed."""
        path = expand_path(self.sqlite_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        return path


class WebSettings(BaseModel):
    """FastAPI server settings."""

    model_config = ConfigDict(extra="forbid")

    host: str = "0.0.0.0"
    port: int = Field(default=8080, ge=1, le=65535)
    auth: bool = False
    refresh_interval: int = Field(default=5, ge=1, le=300)


class TUISettings(BaseModel):
    """Terminal UI preferences."""

    model_config = ConfigDict(extra="forbid")

    refresh_interval: float = Field(default=2.0, ge=0.25, le=60)
    theme: Literal["netmon-dark", "textual-dark", "textual-light"] = "netmon-dark"
    show_sparklines: bool = True


# ---------------------------------------------------------------------------
# Root configuration
# ---------------------------------------------------------------------------

ENV_ALIASES: dict[str, tuple[str, ...]] = {
    # Ollama
    "OLLAMA_HOST": ("ollama", "host"),
    "OLLAMA_MODEL": ("ollama", "model"),
    "OLLAMA_TIMEOUT": ("ollama", "timeout"),
    # InfluxDB
    "INFLUX_URL": ("storage", "influxdb", "url"),
    "INFLUXDB_URL": ("storage", "influxdb", "url"),
    "INFLUX_TOKEN": ("storage", "influxdb", "token"),
    "INFLUXDB_TOKEN": ("storage", "influxdb", "token"),
    "INFLUXDB_ORG": ("storage", "influxdb", "org"),
    "INFLUXDB_BUCKET": ("storage", "influxdb", "bucket"),
    # Storage / paths
    "NETMON_SQLITE_PATH": ("storage", "sqlite_path"),
    # Web
    "NETMON_WEB_HOST": ("web", "host"),
    "NETMON_WEB_PORT": ("web", "port"),
    "NETMON_WEB_AUTH": ("web", "auth"),
    # Application
    "NETMON_ENV": ("env",),
    "NETMON_DEBUG": ("debug",),
    "NETMON_LOG_LEVEL": ("log_level",),
    "NETMON_ALERTS_ENABLED": ("alerts", "enabled"),
}

CONFIG_SECTIONS: tuple[str, ...] = (
    "monitoring",
    "health",
    "alerts",
    "ollama",
    "storage",
    "web",
    "tui",
)

# Top-level scalar settings that are addressable as single-segment keys in
# addition to the dotted section paths.
CONFIG_ROOT_FIELDS: tuple[str, ...] = ("env", "debug", "log_level")


class NetMonConfig(BaseSettings):
    """Root configuration object for the whole application."""

    model_config = SettingsConfigDict(
        env_prefix="NETMON_",
        env_nested_delimiter="__",
        extra="ignore",
        validate_assignment=False,
    )

    env: Literal["development", "production", "test"] = "development"
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)
    health: HealthSettings = Field(default_factory=HealthSettings)
    alerts: AlertsSettings = Field(default_factory=AlertsSettings)
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)
    storage: StorageSettings = Field(default_factory=StorageSettings)
    web: WebSettings = Field(default_factory=WebSettings)
    tui: TUISettings = Field(default_factory=TUISettings)

    # -- serialisation helpers -------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Full configuration as a JSON-serialisable dict."""
        return self.model_dump(mode="json")

    def to_yaml(self) -> str:
        """Configuration rendered as YAML."""
        return yaml.safe_dump(self.to_dict(), sort_keys=False, default_flow_style=False)

    def flattened(self, *, redact_secrets: bool = True) -> dict[str, Any]:
        """Flatten the config into ``dotted.key`` -> value pairs."""
        flat: dict[str, Any] = {}

        def walk(prefix: str, node: Any) -> None:
            if isinstance(node, dict):
                for key, value in node.items():
                    walk(f"{prefix}.{key}" if prefix else str(key), value)
            else:
                flat[prefix] = node

        for key, value in self.to_dict().items():
            walk(key, value)

        if redact_secrets:
            for secret_key in ("storage.influxdb.token",):
                if flat.get(secret_key):
                    flat[secret_key] = "***"
        return flat


def apply_env_aliases(data: dict[str, Any], environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Deep-merge friendly env var aliases into a config dict."""
    source = environ if environ is not None else dict(os.environ)
    merged = _deep_copy(data)
    for env_name, path in ENV_ALIASES.items():
        raw = source.get(env_name)
        if raw is None or raw == "":
            continue
        node = merged
        for part in path[:-1]:
            node = node.setdefault(part, {})
        node[path[-1]] = _coerce_env_value(raw)
    return merged


def apply_env_overrides(data: dict[str, Any], environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Deep-merge ``NETMON_*`` variables into a config dict.

    ``__`` separates nested keys, so ``NETMON_WEB__PORT=9090`` becomes
    ``web.port``. This runs after the YAML file is read, which is what makes
    environment variables authoritative even when the same key is present in
    ``config.yaml``. BaseSettings alone cannot do that: values passed to the
    constructor (the YAML data) take priority over its environment source.
    """
    source = environ if environ is not None else dict(os.environ)
    merged = _deep_copy(data)
    for env_name, raw in source.items():
        if not env_name.startswith("NETMON_") or raw is None or raw == "":
            continue
        parts = [part.lower() for part in env_name[len("NETMON_") :].split("__")]
        if not parts or not parts[0]:
            continue
        node = merged
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = {}
                node[part] = child
            node = child
        node[parts[-1]] = _coerce_env_value(raw)
    return merged


def _coerce_env_value(raw: str) -> Any:
    text = raw.strip()
    lowered = text.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if text.startswith(("[", "{")):
        try:
            return json.loads(text)
        except ValueError:
            return text
    try:
        if "." in text:
            return float(text)
        return int(text)
    except ValueError:
        return text


def _deep_copy(value: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, item in value.items():
        out[key] = _deep_copy(item) if isinstance(item, dict) else item
    return out


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = _deep_copy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _apply_dotenv() -> Path | None:
    """Fold a ``.env`` file into ``os.environ`` without overriding real variables.

    Search order: ``NETMON_ENV_FILE``, the current working directory, then the
    NetMon config directory. Returns the file that was applied, if any.
    """
    candidates: list[Path] = []
    explicit = os.environ.get("NETMON_ENV_FILE")
    if explicit:
        candidates.append(expand_path(explicit))
    candidates.append(Path.cwd() / ".env")
    candidates.append(CONFIG_DIR / ".env")
    for candidate in candidates:
        if not candidate.is_file():
            continue
        try:
            from dotenv import dotenv_values

            values = dotenv_values(candidate)
        except Exception as exc:  # a broken .env must not break startup
            logger.warning("failed to read %s: %s", candidate, exc)
            return None
        for key, value in values.items():
            if value is not None:
                os.environ.setdefault(key, value)
        logger.debug("loaded environment file %s", candidate)
        return candidate
    return None


def load_config(
    path: str | Path | None = None,
    *,
    environ: dict[str, str] | None = None,
    overrides: dict[str, Any] | None = None,
) -> NetMonConfig:
    """Load configuration from defaults, YAML, env vars and explicit overrides.

    When ``environ`` is not given, a ``.env`` file is folded into the process
    environment first (real environment variables win); see :func:`_apply_dotenv`.
    """
    if environ is None:
        _apply_dotenv()
    data: dict[str, Any] = {}

    candidate = expand_path(path) if path else expand_path(
        os.environ.get("NETMON_CONFIG_PATH", str(DEFAULT_YAML_PATH))
    )
    if candidate.exists():
        try:
            loaded = yaml.safe_load(candidate.read_text()) or {}
            if isinstance(loaded, dict):
                data = loaded
            else:
                logger.warning("config file %s does not contain a mapping; ignoring", candidate)
        except (OSError, yaml.YAMLError) as exc:
            logger.warning("failed to read config %s: %s", candidate, exc)

    source_env = environ if environ is not None else dict(os.environ)
    data = apply_env_aliases(data, source_env)
    data = apply_env_overrides(data, source_env)
    if overrides:
        data = _deep_merge(data, overrides)

    # NETMON_* prefixed variables with __ nesting are handled by BaseSettings.
    try:
        return NetMonConfig(**data)
    except PydanticValidationError as exc:
        logger.error("invalid configuration, falling back to defaults: %s", exc)
        return NetMonConfig()


def save_config(config: NetMonConfig, path: str | Path | None = None) -> Path:
    """Write configuration to YAML and return the path written."""
    target = expand_path(path) if path else expand_path(
        os.environ.get("NETMON_CONFIG_PATH", str(DEFAULT_YAML_PATH))
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = config.to_dict()
    # Secrets are environment-only; never persist the InfluxDB token.
    influx = payload.get("storage", {}).get("influxdb", {})
    if isinstance(influx, dict):
        influx["token"] = ""
    target.write_text(yaml.safe_dump(payload, sort_keys=False, default_flow_style=False))
    with contextlib.suppress(OSError):  # pragma: no cover - permissions best effort
        target.chmod(0o600)
    return target


def get_by_path(config: NetMonConfig, key: str) -> Any:
    """Read a value by dotted key, raising :class:`KeyError` when absent."""
    validate_dotted_key(key, allowed_roots=(*CONFIG_SECTIONS, *CONFIG_ROOT_FIELDS))
    node: Any = config.model_dump(mode="json")
    for part in key.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        elif isinstance(node, list):
            try:
                node = node[int(part)]
            except (ValueError, IndexError) as exc:
                raise KeyError(f"unknown config key: {key}") from exc
        else:
            raise KeyError(f"unknown config key: {key}")
    return node


def set_by_path(config: NetMonConfig, key: str, value: Any) -> NetMonConfig:
    """Return a new config with ``key`` set to ``value``.

    The modified payload is re-validated through the Pydantic models, so an
    invalid update raises :class:`~netmon.utils.validation.ValidationError`
    and the caller keeps the previous configuration.
    """
    validate_dotted_key(key, allowed_roots=(*CONFIG_SECTIONS, *CONFIG_ROOT_FIELDS))
    payload = config.model_dump(mode="json")
    parts = key.split(".")
    node: Any = payload
    for part in parts[:-1]:
        if not isinstance(node.get(part), dict):
            raise KeyError(f"unknown config key: {key}")
        node = node[part]
    if parts[-1] not in node:
        raise KeyError(f"unknown config key: {key}")
    node[parts[-1]] = value

    try:
        return NetMonConfig(**payload)
    except PydanticValidationError as exc:
        errors = exc.errors()
        if errors:
            first = errors[0]
            message = first.get("msg", str(exc))
            location = ".".join(str(part) for part in first.get("loc", ())) or key
        else:
            message = str(exc)
            location = key
        raise ValidationError(f"{location}: {message}") from exc


def update_many(config: NetMonConfig, updates: dict[str, Any]) -> NetMonConfig:
    """Apply several dotted-key updates atomically; raises on the first failure."""
    current = config
    for key, value in updates.items():
        current = set_by_path(current, key, value)
    return current
