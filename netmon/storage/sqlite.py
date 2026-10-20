"""Async SQLite repository for configuration, diagnostic history and alerts.

SQLite is the system of record for anything that is not a time series. The
repository exposes small, explicit methods rather than leaking SQLAlchemy
objects to the rest of the application, and every method opens a short-lived
session so concurrent callers (TUI, web API, scheduler) cannot share state.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, select, update
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from netmon.config.models import (
    AlertEvent,
    AlertRule,
    Base,
    ConfigEntry,
    DiagnosticHistory,
    as_utc,
)

logger = logging.getLogger(__name__)


class SQLiteRepository:
    """Async access layer over the NetMon SQLite database."""

    def __init__(self, path: str | Path) -> None:
        """Create a repository bound to ``path`` (a file path, not a URL)."""
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._url = f"sqlite+aiosqlite:///{self.path}"
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[Any] | None = None

    # -- lifecycle -----------------------------------------------------------

    @property
    def engine(self) -> AsyncEngine:
        """Lazily created async engine."""
        if self._engine is None:
            self._engine = create_async_engine(
                self._url,
                echo=False,
                future=True,
                connect_args={"timeout": 15},
            )
            self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)
        return self._engine

    def _sessions(self) -> async_sessionmaker[Any]:
        _ = self.engine  # ensure initialised
        assert self._session_factory is not None
        return self._session_factory

    async def init(self) -> None:
        """Create all tables when they do not exist yet."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.debug("sqlite ready at %s", self.path)

    async def close(self) -> None:
        """Dispose the engine, releasing file handles."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None

    async def ping(self) -> bool:
        """True when the database answers a trivial query."""
        try:
            async with self._sessions()() as session:
                await session.execute(select(func.count()).select_from(ConfigEntry))
            return True
        except Exception as exc:
            logger.warning("sqlite ping failed: %s", exc)
            return False

    # -- configuration -------------------------------------------------------

    async def get_config_map(self) -> dict[str, Any]:
        """All stored config entries as ``dotted.key`` -> value."""
        async with self._sessions()() as session:
            rows = (await session.execute(select(ConfigEntry))).scalars().all()
        return {row.key: row.value for row in rows}

    async def get_config_value(self, key: str) -> Any | None:
        """Read a single config value, or None when it is not stored."""
        async with self._sessions()() as session:
            row = await session.get(ConfigEntry, key)
        return row.value if row else None

    async def set_config_value(self, key: str, value: Any) -> None:
        """Upsert a single config value."""
        await self.set_config_values({key: value})

    async def set_config_values(self, values: dict[str, Any]) -> int:
        """Upsert many config values in one transaction; returns rows written."""
        if not values:
            return 0
        now = datetime.now(UTC)
        rows = [{"key": key, "value": value, "updated_at": now} for key, value in values.items()]
        async with self._sessions()() as session:
            statement = sqlite_insert(ConfigEntry).values(rows)
            statement = statement.on_conflict_do_update(
                index_elements=[ConfigEntry.key],
                set_={"value": statement.excluded.value, "updated_at": statement.excluded.updated_at},
            )
            await session.execute(statement)
            await session.commit()
        return len(rows)

    async def delete_config_value(self, key: str) -> bool:
        """Remove a config value; True when a row was deleted."""
        async with self._sessions()() as session:
            result = await session.execute(delete(ConfigEntry).where(ConfigEntry.key == key))
            await session.commit()
        return bool(result.rowcount)

    # -- diagnostic history --------------------------------------------------

    async def add_diagnostic(
        self,
        *,
        issue_type: str,
        issue_details: str = "",
        severity: str = "warning",
        diagnosis: str = "",
        confidence: float = 0.0,
        source: str = "rule",
        fixes: Sequence[dict[str, Any]] | None = None,
        risks: str = "",
        verify_command: str = "",
        duration_ms: float = 0.0,
        learning_note: str | None = None,
    ) -> int:
        """Insert a diagnosis and return its row id."""
        record = DiagnosticHistory(
            issue_type=issue_type,
            issue_details=issue_details,
            severity=severity,
            diagnosis=diagnosis,
            confidence=confidence,
            source=source,
            fixes=list(fixes or []),
            risks=risks,
            verify_command=verify_command,
            duration_ms=duration_ms,
            learning_note=learning_note,
        )
        async with self._sessions()() as session:
            session.add(record)
            await session.commit()
            await session.refresh(record)
        return int(record.id)

    async def get_diagnostic(self, diagnostic_id: int) -> dict[str, Any] | None:
        """Fetch one diagnosis by id."""
        async with self._sessions()() as session:
            row = await session.get(DiagnosticHistory, diagnostic_id)
        return self._diagnostic_to_dict(row) if row else None

    async def list_diagnostics(
        self,
        *,
        limit: int = 50,
        issue_type: str | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Most recent diagnoses first."""
        statement = select(DiagnosticHistory).order_by(DiagnosticHistory.created_at.desc())
        if issue_type:
            statement = statement.where(DiagnosticHistory.issue_type == issue_type)
        statement = statement.limit(limit).offset(offset)
        async with self._sessions()() as session:
            rows = (await session.execute(statement)).scalars().all()
        return [self._diagnostic_to_dict(row) for row in rows]

    async def find_similar_diagnostics(
        self,
        issue_type: str,
        *,
        limit: int = 3,
        successful_only: bool = True,
    ) -> list[dict[str, Any]]:
        """Past diagnoses of the same issue type, used by learning mode.

        Only records with a recorded outcome are considered when
        ``successful_only`` is set, so the AI is not fed untested guesses.
        """
        statement = select(DiagnosticHistory).where(DiagnosticHistory.issue_type == issue_type)
        if successful_only:
            statement = statement.where(DiagnosticHistory.execution_success.is_not(None))
        statement = statement.order_by(DiagnosticHistory.created_at.desc()).limit(limit)
        async with self._sessions()() as session:
            rows = (await session.execute(statement)).scalars().all()
        return [self._diagnostic_to_dict(row) for row in rows]

    async def record_fix_execution(
        self,
        diagnostic_id: int,
        *,
        command: str,
        output: str,
        success: bool,
        resolution: str | None = None,
        learning_note: str | None = None,
    ) -> bool:
        """Attach the outcome of an executed fix to its diagnosis."""
        async with self._sessions()() as session:
            result = await session.execute(
                update(DiagnosticHistory)
                .where(DiagnosticHistory.id == diagnostic_id)
                .values(
                    executed_command=command,
                    execution_output=output[:20000],
                    execution_success=success,
                    resolution=resolution or ("resolved" if success else "unresolved"),
                    learning_note=learning_note,
                )
            )
            await session.commit()
        return bool(result.rowcount)

    async def prune_diagnostics(self, retention_days: int) -> int:
        """Delete diagnoses older than ``retention_days``; returns rows removed."""
        if retention_days <= 0:
            return 0
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        async with self._sessions()() as session:
            result = await session.execute(
                delete(DiagnosticHistory).where(DiagnosticHistory.created_at < cutoff)
            )
            await session.commit()
        return int(result.rowcount or 0)

    async def diagnostic_stats(self) -> dict[str, Any]:
        """Aggregate counts used by the diagnostics screen."""
        async with self._sessions()() as session:
            total = await session.scalar(select(func.count()).select_from(DiagnosticHistory))
            resolved = await session.scalar(
                select(func.count())
                .select_from(DiagnosticHistory)
                .where(DiagnosticHistory.execution_success.is_(True))
            )
            by_type = await session.execute(
                select(DiagnosticHistory.issue_type, func.count())
                .group_by(DiagnosticHistory.issue_type)
                .order_by(func.count().desc())
            )
        return {
            "total": int(total or 0),
            "resolved": int(resolved or 0),
            "by_type": {str(row[0]): int(row[1]) for row in by_type.all()},
        }

    @staticmethod
    def _diagnostic_to_dict(row: DiagnosticHistory) -> dict[str, Any]:
        return {
            "id": int(row.id),
            "issue_type": row.issue_type,
            "issue_details": row.issue_details,
            "severity": row.severity,
            "diagnosis": row.diagnosis,
            "confidence": float(row.confidence),
            "source": row.source,
            "fixes": list(row.fixes or []),
            "risks": row.risks,
            "verify_command": row.verify_command,
            "executed_command": row.executed_command,
            "execution_output": row.execution_output,
            "execution_success": row.execution_success,
            "resolution": row.resolution,
            "learning_note": row.learning_note,
            "duration_ms": float(row.duration_ms),
            "created_at": (as_utc(row.created_at) or datetime.now(UTC)).isoformat(),
        }

    # -- alert rules ---------------------------------------------------------

    async def list_alert_rules(self, *, enabled_only: bool = False) -> list[dict[str, Any]]:
        """All alert rules ordered by severity then name."""
        statement = select(AlertRule).order_by(AlertRule.severity, AlertRule.name)
        if enabled_only:
            statement = statement.where(AlertRule.enabled.is_(True))
        async with self._sessions()() as session:
            rows = (await session.execute(statement)).scalars().all()
        return [self._rule_to_dict(row) for row in rows]

    async def upsert_alert_rule(
        self,
        *,
        name: str,
        metric: str,
        operator: str = ">",
        threshold: float = 0.0,
        severity: str = "warning",
        enabled: bool = True,
        cooldown: int = 300,
        channels: Sequence[str] | None = None,
        message_template: str = "",
        description: str = "",
    ) -> int:
        """Create or update an alert rule by name; returns its id."""
        now = datetime.now(UTC)
        values = {
            "name": name,
            "metric": metric,
            "operator": operator,
            "threshold": float(threshold),
            "severity": severity,
            "enabled": enabled,
            "cooldown": int(cooldown),
            "channels": list(channels or []),
            "message_template": message_template,
            "description": description,
            "updated_at": now,
        }
        async with self._sessions()() as session:
            existing = await session.scalar(select(AlertRule).where(AlertRule.name == name))
            if existing is not None:
                for key, value in values.items():
                    setattr(existing, key, value)
                await session.commit()
                return int(existing.id)
            rule = AlertRule(**values, created_at=now)
            session.add(rule)
            await session.commit()
            await session.refresh(rule)
            return int(rule.id)

    async def set_alert_rule_enabled(self, name: str, enabled: bool) -> bool:
        """Enable or disable a rule by name."""
        async with self._sessions()() as session:
            result = await session.execute(
                update(AlertRule)
                .where(AlertRule.name == name)
                .values(enabled=enabled, updated_at=datetime.now(UTC))
            )
            await session.commit()
        return bool(result.rowcount)

    async def delete_alert_rule(self, name: str) -> bool:
        """Delete a rule by name."""
        async with self._sessions()() as session:
            result = await session.execute(delete(AlertRule).where(AlertRule.name == name))
            await session.commit()
        return bool(result.rowcount)

    @staticmethod
    def _rule_to_dict(row: AlertRule) -> dict[str, Any]:
        return {
            "id": int(row.id),
            "name": row.name,
            "metric": row.metric,
            "operator": row.operator,
            "threshold": float(row.threshold),
            "severity": row.severity,
            "enabled": bool(row.enabled),
            "cooldown": int(row.cooldown),
            "channels": list(row.channels or []),
            "message_template": row.message_template,
            "description": row.description,
            "created_at": (as_utc(row.created_at) or datetime.now(UTC)).isoformat(),
            "updated_at": (as_utc(row.updated_at) or datetime.now(UTC)).isoformat(),
        }

    # -- alert events --------------------------------------------------------

    async def add_alert_event(
        self,
        *,
        rule_name: str,
        severity: str,
        message: str,
        metric: str = "",
        value: float | None = None,
        payload: dict[str, Any] | None = None,
        delivered: bool = False,
        delivery_errors: Sequence[str] | None = None,
    ) -> int:
        """Record a fired alert and return its row id."""
        event = AlertEvent(
            rule_name=rule_name,
            metric=metric,
            value=value,
            severity=severity,
            message=message,
            payload=payload or {},
            delivered=delivered,
            delivery_errors=list(delivery_errors or []),
        )
        async with self._sessions()() as session:
            session.add(event)
            await session.commit()
            await session.refresh(event)
        return int(event.id)

    async def list_alert_events(
        self,
        *,
        limit: int = 100,
        severity: str | None = None,
        unacknowledged_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Recent alert events, newest first."""
        statement = select(AlertEvent).order_by(AlertEvent.created_at.desc())
        if severity:
            statement = statement.where(AlertEvent.severity == severity)
        if unacknowledged_only:
            statement = statement.where(AlertEvent.acknowledged.is_(False))
        statement = statement.limit(limit)
        async with self._sessions()() as session:
            rows = (await session.execute(statement)).scalars().all()
        return [self._event_to_dict(row) for row in rows]

    async def acknowledge_alert(self, event_id: int) -> bool:
        """Mark one alert event as acknowledged."""
        async with self._sessions()() as session:
            result = await session.execute(
                update(AlertEvent).where(AlertEvent.id == event_id).values(acknowledged=True)
            )
            await session.commit()
        return bool(result.rowcount)

    async def acknowledge_all_alerts(self) -> int:
        """Acknowledge every unacknowledged event; returns rows changed."""
        async with self._sessions()() as session:
            result = await session.execute(
                update(AlertEvent)
                .where(AlertEvent.acknowledged.is_(False))
                .values(acknowledged=True)
            )
            await session.commit()
        return int(result.rowcount or 0)

    async def prune_alert_events(self, max_events: int) -> int:
        """Keep only the newest ``max_events`` events; returns rows removed."""
        if max_events <= 0:
            return 0
        async with self._sessions()() as session:
            newest = (
                select(AlertEvent.id)
                .order_by(AlertEvent.created_at.desc())
                .limit(max_events)
                .scalar_subquery()
            )
            result = await session.execute(delete(AlertEvent).where(AlertEvent.id.not_in(newest)))
            await session.commit()
        return int(result.rowcount or 0)

    @staticmethod
    def _event_to_dict(row: AlertEvent) -> dict[str, Any]:
        return {
            "id": int(row.id),
            "rule_name": row.rule_name,
            "metric": row.metric,
            "value": row.value,
            "severity": row.severity,
            "message": row.message,
            "payload": dict(row.payload or {}),
            "delivered": bool(row.delivered),
            "delivery_errors": list(row.delivery_errors or []),
            "acknowledged": bool(row.acknowledged),
            "created_at": (as_utc(row.created_at) or datetime.now(UTC)).isoformat(),
        }

    async def seed_default_rules(self, rules: Sequence[dict[str, Any]]) -> int:
        """Insert default rules that do not exist yet; returns how many were added."""
        if not rules:
            return 0
        existing = {rule["name"] for rule in await self.list_alert_rules()}
        added = 0
        for rule in rules:
            if rule["name"] in existing:
                continue
            await self.upsert_alert_rule(
                name=str(rule["name"]),
                metric=str(rule["metric"]),
                operator=str(rule.get("operator", ">")),
                threshold=float(rule.get("threshold", 0.0)),
                severity=str(rule.get("severity", "warning")),
                enabled=bool(rule.get("enabled", True)),
                cooldown=int(rule.get("cooldown", 300)),
                channels=list(rule.get("channels", [])),
                message_template=str(rule.get("message_template", "")),
                description=str(rule.get("description", "")),
            )
            added += 1
        return added


async def open_repository(path: str | Path) -> SQLiteRepository:
    """Create and initialise a repository in one step."""
    repository = SQLiteRepository(path)
    await repository.init()
    return repository


__all__ = ["SQLiteRepository", "open_repository"]
