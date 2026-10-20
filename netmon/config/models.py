"""SQLAlchemy models backing the SQLite store.

SQLite holds everything that is *stateful but not time-series*: the effective
configuration, diagnostic history (including the learning-mode feedback used
by the AI engine) and the alert rules/events. Time-series metrics live in
InfluxDB, see :mod:`netmon.storage.influx`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(UTC)


def as_utc(value: datetime | None) -> datetime | None:
    """Normalise a datetime read back from SQLite to timezone-aware UTC.

    SQLite does not persist tzinfo, so values are re-tagged on the way out.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


class Base(DeclarativeBase):
    """Declarative base for all NetMon tables."""


class ConfigEntry(Base):
    """One configuration value, addressed by a dotted key.

    Keys mirror the YAML layout, e.g. ``monitoring.intervals.ping`` or
    ``health.thresholds.latency_warning``. Values are stored as JSON so that
    lists and nested dicts round-trip without extra parsing.
    """

    __tablename__ = "config"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<ConfigEntry {self.key}={self.value!r}>"


class DiagnosticHistory(Base):
    """A recorded diagnosis and, when applicable, the fix that was executed.

    ``source`` distinguishes the fast rule-based path from the AI path so the
    learning mode can bias future prompts toward approaches that worked.
    """

    __tablename__ = "diagnostic_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    issue_type: Mapped[str] = mapped_column(String(64), nullable=False)
    issue_details: Mapped[str] = mapped_column(Text, default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="warning", nullable=False)
    diagnosis: Mapped[str] = mapped_column(Text, default="", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    source: Mapped[str] = mapped_column(String(16), default="rule", nullable=False)
    fixes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    risks: Mapped[str] = mapped_column(Text, default="", nullable=False)
    verify_command: Mapped[str] = mapped_column(Text, default="", nullable=False)
    executed_command: Mapped[str | None] = mapped_column(Text, nullable=True)
    execution_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    execution_success: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    resolution: Mapped[str | None] = mapped_column(String(32), nullable=True)
    learning_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (
        Index("ix_diag_issue_type", "issue_type"),
        Index("ix_diag_created_at", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<DiagnosticHistory #{self.id} {self.issue_type} {self.source}>"


class AlertRule(Base):
    """A threshold rule evaluated against each collection cycle.

    ``metric`` is a dotted metric address such as ``health.latency`` or
    ``interface.eth0.utilization``; ``operator`` is one of
    ``> >= < <= == !=``.
    """

    __tablename__ = "alert_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    metric: Mapped[str] = mapped_column(String(128), nullable=False)
    operator: Mapped[str] = mapped_column(String(4), default=">", nullable=False)
    threshold: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="warning", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    cooldown: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    channels: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    message_template: Mapped[str] = mapped_column(Text, default="", nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<AlertRule {self.name} {self.metric}{self.operator}{self.threshold}>"


class AlertEvent(Base):
    """A fired alert, shown in the TUI alerts screen and the web UI."""

    __tablename__ = "alert_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_name: Mapped[str] = mapped_column(String(128), nullable=False)
    metric: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    value: Mapped[float | None] = mapped_column(Float, nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="warning", nullable=False)
    message: Mapped[str] = mapped_column(Text, default="", nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    delivered: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    delivery_errors: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    acknowledged: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (Index("ix_alert_created_at", "created_at"),)

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<AlertEvent {self.rule_name} {self.severity}>"
