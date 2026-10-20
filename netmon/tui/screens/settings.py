"""Settings screen: read-only view of the effective configuration plus safe edits.

The whole effective configuration is shown as flattened ``dotted.key`` rows.
Editing happens through two text fields: a dotted key and its new value.  The
value is parsed as YAML, re-validated through the Pydantic models with
:func:`~netmon.config.settings.set_by_path`, persisted with
:func:`~netmon.config.settings.save_config` and finally pushed to the running
monitor with :meth:`MonitorManager.config_changed`.  Invalid values never leave
the screen: the error is rendered inline next to the editor.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

import yaml
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Input, Static

from netmon.config.settings import NetMonConfig, save_config, set_by_path
from netmon.core.monitor import MonitorManager, SystemState
from netmon.tui.widgets.status_table import StatusTable
from netmon.utils.formatting import BRAND_COLORS, health_color
from netmon.utils.validation import ValidationError

COLUMNS: tuple[str, ...] = ("Key", "Effective value")

EXAMPLE_KEYS: tuple[str, ...] = (
    "tui.refresh_interval",
    "tui.show_sparklines",
    "monitoring.intervals.interfaces",
    "health.thresholds.latency_warning",
    "alerts.enabled",
    "alerts.min_severity",
    "ollama.model",
    "web.port",
)

__all__ = ["COLUMNS", "EXAMPLE_KEYS", "SettingsScreen"]


def parse_value(raw: str) -> Any:
    """Parse a user-entered value as YAML, treating an empty field as ``""``.

    Raises:
        ValidationError: When the text is not valid YAML.
    """
    text = raw.strip()
    if text == "":
        return ""
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValidationError(f"invalid value: {exc}") from exc


def format_value(value: Any) -> str:
    """Render a configuration value for the read-only table."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) if value else "[]"
    if isinstance(value, Mapping):
        return "{" + ", ".join(f"{key}: {item}" for key, item in value.items()) + "}" if value else "{}"
    return str(value)


class SettingsScreen(Screen[None]):
    """Effective configuration with a guarded dotted-key editor.

    Args:
        monitor: The running :class:`MonitorManager`.
        config: The effective :class:`NetMonConfig`.
        id: DOM id.
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("ctrl+s", "apply", "Apply", show=True),
    ]

    AUTO_FOCUS = "#config-key"

    def __init__(
        self,
        monitor: MonitorManager,
        config: NetMonConfig,
        *,
        id: str | None = "settings",
    ) -> None:
        super().__init__(id=id)
        self.monitor = monitor
        self.config = config
        self._fingerprint: str | None = None

    # -- composition ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._header_text(), id="settings-header")
        with VerticalScroll(id="settings-scroll"):
            yield Static("EFFECTIVE CONFIGURATION", classes="section-title")
            yield Static(
                Text(
                    "read-only view; use the editor below to change a value",
                    style=BRAND_COLORS["muted"],
                )
            )
            table = StatusTable(id="config-table")
            table.set_columns(COLUMNS)
            yield table
            yield Static("EDIT A VALUE", classes="section-title")
            yield Static(
                Text(
                    "enter a dotted key and its new value, then press enter or ctrl+s",
                    style=BRAND_COLORS["muted"],
                )
            )
            with Horizontal(id="config-editor"):
                yield Input(placeholder="dotted.key", id="config-key")
                yield Input(placeholder="value", id="config-value")
                yield Button("Apply", variant="primary", id="config-apply")
            yield Static(Text("", style="dim"), id="config-message")
            yield Static("EXAMPLES  " + "   ".join(EXAMPLE_KEYS), id="config-examples")
        yield Footer()

    def on_mount(self) -> None:
        # ``is_mounted`` only flips to True after the mount completes, so the
        # first render is deferred until the table can be queried.
        self.call_after_refresh(self._render_config)

    # -- state rendering -----------------------------------------------------

    def refresh_from_state(
        self,
        state: SystemState,
        history: Mapping[str, Sequence[float]] | None = None,
    ) -> None:
        """Refresh the read-only table when the effective configuration changed."""
        if not self.is_mounted:
            return
        self.query_one("#settings-header", Static).update(self._header_text(state))
        self._render_config()

    # -- interactions --------------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Pressing enter in either field applies the edit."""
        self.action_apply()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """The Apply button applies the edit."""
        if event.button.id == "config-apply":
            self.action_apply()

    def action_apply(self) -> None:
        """Validate and persist the edit shown in the editor."""
        if not self.is_mounted:
            return
        key = self.query_one("#config-key", Input).value.strip()
        raw_value = self.query_one("#config-value", Input).value
        if not key:
            self._message("enter a dotted configuration key first", state="warning")
            return

        try:
            value = parse_value(raw_value)
            candidate = set_by_path(self.config, key, value)
        except (ValidationError, KeyError, ValueError, TypeError) as exc:
            self._message(f"invalid value for {key}: {exc}", state="critical")
            return

        self._message(f"applying {key} ...", state="info")
        self.run_worker(
            self._persist(key, value, candidate),
            group="config",
            exclusive=True,
            exit_on_error=False,
        )

    # -- workers -------------------------------------------------------------

    async def _persist(self, key: str, value: Any, candidate: NetMonConfig) -> None:
        saved_path: str | None = None
        save_error: str | None = None
        try:
            saved_path = str(save_config(candidate))
        except OSError as exc:  # a read-only config directory must not break the screen
            save_error = str(exc)

        try:
            await self.monitor.config_changed(candidate)
        except Exception as exc:
            self._message(f"could not apply {key} to the running monitor: {exc}", state="critical")
            return

        self.config = candidate
        if hasattr(self.app, "config"):
            self.app.config = candidate  # type: ignore[attr-defined]
        self._fingerprint = None
        if not self.is_mounted:
            return
        self._render_config()
        if save_error is not None:
            self._message(
                f"applied {key} = {format_value(value)}; not saved to disk: {save_error}",
                state="warning",
            )
        else:
            self._message(
                f"applied {key} = {format_value(value)}; saved to {saved_path}", state="ok"
            )

    # -- rendering -----------------------------------------------------------

    def _render_config(self) -> None:
        if not self.is_mounted:
            return
        flat = self.config.flattened()
        fingerprint = "|".join(f"{key}={flat[key]!r}" for key in sorted(flat))
        if fingerprint == self._fingerprint:
            return
        self._fingerprint = fingerprint
        table = self.query_one("#config-table", StatusTable)
        rows: list[tuple[str, Sequence[Any]]] = [
            (key, (key, format_value(flat[key]))) for key in sorted(flat)
        ]
        table.sync(rows, placeholder="configuration unavailable")

    def _message(self, message: str, *, state: str = "info") -> None:
        if not self.is_mounted:
            return
        try:
            widget = self.query_one("#config-message", Static)
        except Exception:
            return
        style = BRAND_COLORS["info"] if state == "info" else health_color(state)
        widget.update(Text(message, style=style))

    def _header_text(self, state: SystemState | None = None) -> Text:
        header = Text()
        header.append("SETTINGS", style=f"bold {BRAND_COLORS['info']}")
        header.append(f"   {len(self.config.flattened())} keys", style=BRAND_COLORS["text"])
        header.append(f"   environment {self.config.env}", style=BRAND_COLORS["muted"])
        header.append(f"   sqlite {self.config.storage.sqlite_path}", style=BRAND_COLORS["muted"])
        header.append(
            f"   influx {'enabled' if self.config.storage.influxdb.enabled else 'disabled'}"
            f"   web {self.config.web.host}:{self.config.web.port}",
            style=BRAND_COLORS["muted"],
        )
        if state is not None:
            header.append(f"   updated {state.cycles} cycle(s)", style=BRAND_COLORS["muted"])
        return header
