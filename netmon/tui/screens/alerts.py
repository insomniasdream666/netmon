"""Alerts screen: recent alert events with severity colouring and acknowledgement.

Events come from the SQLite repository (``list_alert_events``) when one is
available and fall back to the monitor's in-memory ring buffer otherwise.
Pressing ``a`` acknowledges the selected event through the repository.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, ClassVar

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Static

from netmon.core.monitor import SystemState
from netmon.storage.sqlite import SQLiteRepository
from netmon.tui.widgets.status_table import StatusTable
from netmon.utils.formatting import (
    BRAND_COLORS,
    format_ago,
    health_color,
    health_glyph,
    truncate,
)

COLUMNS: tuple[str, ...] = ("Time", "Severity", "Rule", "Metric", "Value", "Message", "Ack")
EVENT_LIMIT = 100

__all__ = ["COLUMNS", "EVENT_LIMIT", "AlertsScreen"]


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO timestamp, tolerating ``None`` and malformed input."""
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


class AlertsScreen(Screen[None]):
    """Recent alert events, newest first.

    Args:
        repository: SQLite repository holding alert events; ``None`` renders the
            monitor's in-memory ring buffer instead.
        id: DOM id.
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("a", "acknowledge", "Acknowledge", show=True),
        Binding("r", "reload", "Reload", show=True),
    ]

    AUTO_FOCUS = "#alerts-table"

    def __init__(self, repository: SQLiteRepository | None = None, *, id: str | None = "alerts") -> None:
        super().__init__(id=id)
        self.repository = repository
        self._state: SystemState | None = None
        self._events: list[dict[str, Any]] = []
        self._loaded = False

    # -- composition ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._header_text(), id="alerts-header")
        with VerticalScroll(id="alerts-scroll"):
            yield Static("RECENT ALERTS", classes="section-title")
            table = StatusTable(id="alerts-table")
            table.set_columns(COLUMNS)
            yield table
            yield Static("DETAIL", classes="section-title")
            yield Static(Text("select an alert to inspect it", style="dim"), id="alert-detail")
            yield Static("", id="alerts-status")
        yield Footer()

    def on_mount(self) -> None:
        if self.repository is not None:
            self.run_worker(self._load_events(), group="alerts", exclusive=True, exit_on_error=False)

    # -- state rendering -----------------------------------------------------

    def refresh_from_state(
        self,
        state: SystemState,
        history: Mapping[str, Sequence[float]] | None = None,
    ) -> None:
        """Update the header; render in-memory alerts when there is no repository."""
        self._state = state
        if not self.is_mounted:
            return
        self.query_one("#alerts-header", Static).update(self._header_text(state))
        if self.repository is None:
            self._events = [dict(item) for item in (state.alerts or []) if isinstance(item, Mapping)]
            self._render_events()

    # -- actions -------------------------------------------------------------

    def action_reload(self) -> None:
        """Reload the event list from the repository."""
        if self.repository is None:
            self._set_status("no repository configured; showing in-memory alerts", state="warning")
            if self._state is not None:
                self.refresh_from_state(self._state)
            return
        self.run_worker(self._load_events(), group="alerts", exclusive=True, exit_on_error=False)

    def action_acknowledge(self) -> None:
        """Acknowledge the selected alert event."""
        if not self.is_mounted:
            return
        table = self.query_one("#alerts-table", StatusTable)
        key = table.selected_key()
        if key is None:
            self._set_status("no alert selected", state="warning")
            return
        try:
            event_id = int(key)
        except ValueError:
            self._set_status("select a stored alert before acknowledging", state="warning")
            return
        if self.repository is None:
            self._set_status("acknowledgement requires a repository", state="warning")
            return
        self.run_worker(
            self._acknowledge(event_id), group="alerts", exclusive=True, exit_on_error=False
        )

    def on_data_table_row_highlighted(self, event: StatusTable.RowHighlighted) -> None:
        """Show the full detail of the highlighted event."""
        key = event.row_key.value
        if key is not None:
            self._update_detail(str(key))

    # -- workers -------------------------------------------------------------

    async def _load_events(self) -> None:
        assert self.repository is not None  # guarded by the caller
        try:
            events = await self.repository.list_alert_events(limit=EVENT_LIMIT)
        except Exception as exc:
            self._set_status(f"could not load alert events: {exc}", state="critical")
            return
        if not self.is_mounted:
            return
        self._events = [dict(event) for event in events]
        self._loaded = True
        self._render_events()
        self._set_status(f"loaded {len(self._events)} alert event(s)", state="ok")

    async def _acknowledge(self, event_id: int) -> None:
        assert self.repository is not None  # guarded by the caller
        try:
            changed = await self.repository.acknowledge_alert(event_id)
        except Exception as exc:
            self._set_status(f"could not acknowledge alert {event_id}: {exc}", state="critical")
            return
        await self._load_events()
        if changed:
            self._set_status(f"alert {event_id} acknowledged", state="ok")
        else:
            self._set_status(f"alert {event_id} was not found", state="warning")

    # -- rendering -----------------------------------------------------------

    def _render_events(self) -> None:
        if not self.is_mounted:
            return
        table = self.query_one("#alerts-table", StatusTable)
        rows: list[tuple[str, Sequence[Any]]] = []
        for position, event in enumerate(self._events):
            severity = str(event.get("severity", "info"))
            key = str(event.get("id") if event.get("id") is not None else f"memory-{position}")
            created = _parse_timestamp(event.get("created_at"))
            acknowledged = bool(event.get("acknowledged"))

            severity_cell = Text()
            severity_cell.append(f"{health_glyph(severity)} ", style=health_color(severity))
            severity_cell.append(severity, style=health_color(severity))

            ack_cell = Text("yes" if acknowledged else "no", style=BRAND_COLORS["muted"])

            value = event.get("value")
            cells: tuple[Any, ...] = (
                format_ago(created),
                severity_cell,
                truncate(str(event.get("rule_name") or "--"), 24),
                truncate(str(event.get("metric") or "--"), 24),
                f"{float(value):.2f}" if isinstance(value, (int, float)) else "--",
                truncate(str(event.get("message") or ""), 64),
                ack_cell,
            )
            rows.append((key, cells))
        table.sync(rows, placeholder="no alert events recorded")

    def _update_detail(self, key: str) -> None:
        panel = self.query_one("#alert-detail", Static)
        event = next(
            (
                item
                for position, item in enumerate(self._events)
                if str(item.get("id") if item.get("id") is not None else f"memory-{position}") == key
            ),
            None,
        )
        if event is None:
            panel.update(Text("select an alert to inspect it", style="dim"))
            return

        severity = str(event.get("severity", "info"))
        body = Text()
        body.append(f"{health_glyph(severity)} ", style=f"bold {health_color(severity)}")
        body.append(str(event.get("rule_name") or "alert"), style="bold")
        body.append(f"   {severity}", style=health_color(severity))
        body.append(f"   {format_ago(_parse_timestamp(event.get('created_at')))}", style=BRAND_COLORS["muted"])
        body.append("\n")
        body.append(str(event.get("message") or ""), style=BRAND_COLORS["text"])
        body.append("\n")
        body.append(
            f"metric {event.get('metric') or '--'}   value {event.get('value')}   "
            f"delivered {'yes' if event.get('delivered') else 'no'}   "
            f"acknowledged {'yes' if event.get('acknowledged') else 'no'}",
            style=BRAND_COLORS["muted"],
        )
        delivery_errors = event.get("delivery_errors") or []
        if delivery_errors:
            body.append("\n")
            body.append(
                "delivery errors: " + ", ".join(str(error) for error in delivery_errors),
                style=BRAND_COLORS["critical"],
            )
        payload = event.get("payload")
        if isinstance(payload, Mapping) and payload:
            body.append("\n")
            body.append("payload: ", style=BRAND_COLORS["muted"])
            body.append(
                ", ".join(f"{name}={value}" for name, value in list(payload.items())[:8]),
                style=BRAND_COLORS["text"],
            )
        panel.update(body)

    def _header_text(self, state: SystemState | None = None) -> Text:
        header = Text()
        header.append("ALERTS", style=f"bold {BRAND_COLORS['info']}")
        if state is None:
            header.append("   waiting for data", style=BRAND_COLORS["muted"])
            return header
        stats = getattr(state, "alert_stats", {}) or {}
        header.append(
            f"   {len(self._events)} event(s)"
            f"   {stats.get('sent', 0)} sent"
            f"   {stats.get('suppressed', 0)} suppressed"
            f"   {stats.get('active_cooldowns', 0)} in cooldown"
            f"   min severity {self._severity_floor()}",
            style=BRAND_COLORS["text"],
        )
        channels = stats.get("channels") or []
        if channels:
            header.append(f"   channels {', '.join(str(name) for name in channels)}", style=BRAND_COLORS["muted"])
        return header

    def _severity_floor(self) -> str:
        state = self._state
        stats = getattr(state, "alert_stats", None) if state is not None else None
        if isinstance(stats, Mapping) and stats.get("min_severity"):
            return str(stats["min_severity"])
        return self.app.config.alerts.min_severity if hasattr(self.app, "config") else "warning"

    def _set_status(self, message: str, *, state: str = "info") -> None:
        if not self.is_mounted:
            return
        try:
            status = self.query_one("#alerts-status", Static)
        except Exception:
            return
        style = BRAND_COLORS["info"] if state == "info" else health_color(state)
        status.update(Text(message, style=style))
