"""Configuration models, persistence and validation."""

from netmon.config.models import AlertEvent, AlertRule, ConfigEntry, DiagnosticHistory
from netmon.config.settings import (
    NetMonConfig,
    get_by_path,
    load_config,
    save_config,
    set_by_path,
    update_many,
)

__all__ = [
    "AlertEvent",
    "AlertRule",
    "ConfigEntry",
    "DiagnosticHistory",
    "NetMonConfig",
    "get_by_path",
    "load_config",
    "save_config",
    "set_by_path",
    "update_many",
]
