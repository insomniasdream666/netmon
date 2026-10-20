"""The NetMon Textual application.

``NetMonApp`` owns the screen stack, the state polling loop and the theme.  It
is deliberately thin: the monitor does the work, the screens render, and the
application only routes state and keystrokes between them.

Threading rules honoured here:

* the monitor is polled with :meth:`textual.message_pump.MessagePump.set_interval`
  on the application's own event loop, never from a thread;
* long-running work (collector refresh, diagnosis, fix execution, database
  queries) runs inside async workers with ``thread=False``;
* the monitor's state listener only stores the snapshot and schedules a
  repaint, so collector callbacks can never block the UI.
"""

from __future__ import annotations

import logging
from collections import deque
from collections.abc import Callable, Mapping
from contextlib import suppress
from typing import Any, ClassVar

from textual.app import App
from textual.binding import Binding, BindingType
from textual.screen import ModalScreen, Screen
from textual.theme import Theme
from textual.timer import Timer

from netmon import __brand_tagline__
from netmon.config.settings import NetMonConfig
from netmon.core.monitor import MonitorManager, SystemState
from netmon.storage.sqlite import SQLiteRepository
from netmon.tui.screens.alerts import AlertsScreen
from netmon.tui.screens.dashboard import HISTORY_KEYS, DashboardScreen
from netmon.tui.screens.diagnostics import DiagnosticsScreen
from netmon.tui.screens.interfaces import InterfacesScreen
from netmon.tui.screens.settings import SettingsScreen
from netmon.utils.formatting import BRAND_COLORS

NETMON_THEME = Theme(
    name="netmon-dark",
    primary=BRAND_COLORS["info"],
    secondary="#1F6FEB",
    warning=BRAND_COLORS["warning"],
    error=BRAND_COLORS["critical"],
    success=BRAND_COLORS["health_ok"],
    accent=BRAND_COLORS["info"],
    foreground=BRAND_COLORS["text"],
    background=BRAND_COLORS["background"],
    surface="#161B22",
    panel="#161B22",
    boost="#1F242C",
    dark=True,
    variables={
        "netmon-bg": BRAND_COLORS["background"],
        "netmon-ok": BRAND_COLORS["health_ok"],
        "netmon-warning": BRAND_COLORS["warning"],
        "netmon-critical": BRAND_COLORS["critical"],
        "netmon-info": BRAND_COLORS["info"],
        "netmon-text": BRAND_COLORS["text"],
        "netmon-muted": BRAND_COLORS["muted"],
    },
)
"""The NetMon dark theme, derived from :data:`netmon.utils.formatting.BRAND_COLORS`."""

DEFAULT_HISTORY_POINTS = 120

logger = logging.getLogger(__name__)

__all__ = ["DEFAULT_HISTORY_POINTS", "NETMON_THEME", "NetMonApp"]


class NetMonApp(App[None]):
    """The NetMon terminal interface.

    Args:
        monitor: The running (or startable) :class:`MonitorManager`.
        config: Effective configuration.
        repository: Optional SQLite repository used by the alerts screen.
    """

    CSS_PATH = "styles.css"
    TITLE = "NetMon"
    SUB_TITLE = __brand_tagline__

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("q", "quit", "Quit"),
        Binding("d", "diagnose", "Diagnose"),
        Binding("i", "show_interfaces", "Interfaces"),
        Binding("a", "show_alerts", "Alerts"),
        Binding("s", "show_settings", "Settings"),
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "back", "Back"),
        Binding("enter", "execute_fix", "Execute fix", show=False),
    ]

    def __init__(
        self,
        monitor: MonitorManager,
        config: NetMonConfig,
        *,
        repository: SQLiteRepository | None = None,
    ) -> None:
        super().__init__()
        self.monitor = monitor
        self.config = config
        self.repository = repository
        self.state: SystemState | None = None
        self._history: dict[str, deque[float]] = {
            key: deque(maxlen=max(10, int(config.monitoring.history_points or DEFAULT_HISTORY_POINTS)))
            for key in HISTORY_KEYS
        }
        self._unsubscribe: Callable[[], None] | None = None
        self._poll_timer: Timer | None = None
        self._render_pending = False
        self._render_failures = 0
        self._started_monitor = False

    # -- public helpers ------------------------------------------------------

    @property
    def history(self) -> dict[str, list[float]]:
        """In-memory metric history used by the dashboard sparklines."""
        return {key: list(values) for key, values in self._history.items()}

    def screen_of_type(self, screen_type: type[Screen[Any]]) -> Screen[Any] | None:
        """Topmost screen of ``screen_type`` in the stack, if any."""
        for screen in reversed(self.screen_stack):
            if isinstance(screen, screen_type):
                return screen
        return None

    # -- lifecycle -----------------------------------------------------------

    async def on_mount(self) -> None:
        """Install the theme, show the dashboard and start polling the monitor."""
        self._install_theme()
        self.push_screen(DashboardScreen(show_sparklines=self.config.tui.show_sparklines))
        interval = max(0.25, float(self.config.tui.refresh_interval))
        self._poll_timer = self.set_interval(interval, self._poll_state, name="netmon-poll")
        try:
            self._unsubscribe = self.monitor.subscribe(self._on_state_change)
        except Exception as exc:  # a monitor without subscribers is still usable
            logger.warning("could not subscribe to the monitor: %s", exc)
        await self._poll_state()
        self.call_after_refresh(self._apply_state)
        self.run_worker(self._startup(), group="monitor", exclusive=True, exit_on_error=False)

    async def on_unmount(self) -> None:
        """Stop polling, detach the listener and stop a monitor we started."""
        if self._poll_timer is not None:
            self._poll_timer.stop()
            self._poll_timer = None
        if self._unsubscribe is not None:
            with suppress(Exception):  # best effort teardown
                self._unsubscribe()
            self._unsubscribe = None
        if self._started_monitor:
            stop = getattr(self.monitor, "stop", None)
            if callable(stop):
                try:
                    await stop()
                except Exception as exc:  # teardown is best effort
                    logger.warning("monitor shutdown failed: %s", exc)

    async def _startup(self) -> None:
        """Start the monitor if the caller did not already do so."""
        start = getattr(self.monitor, "start", None)
        if not callable(start) or getattr(self.monitor, "running", False):
            return
        try:
            await start()
        except Exception as exc:  # surface the failure, keep the UI alive
            self.notify(f"monitor failed to start: {exc}", severity="error", timeout=10)
            return
        self._started_monitor = True
        await self._poll_state()

    def _install_theme(self) -> None:
        """Register and activate the NetMon theme (falling back to Textual's)."""
        self.register_theme(NETMON_THEME)
        requested = str(getattr(self.config.tui, "theme", "netmon-dark"))
        try:
            self.theme = NETMON_THEME.name if requested == "netmon-dark" else requested
        except Exception as exc:  # an unknown theme must not break startup
            logger.warning("unknown theme %s: %s", requested, exc)
            self.theme = NETMON_THEME.name

    # -- state plumbing ------------------------------------------------------

    async def _poll_state(self) -> None:
        """Read the monitor state and repaint the active screen."""
        try:
            state = self.monitor.get_current_state()
        except Exception as exc:  # polling must never crash the app
            logger.error("could not read monitor state: %s", exc)
            return
        self.state = state
        self._sample_history(state)
        self._apply_state()

    def _on_state_change(self, state: SystemState) -> None:
        """Monitor listener: store the snapshot and schedule a repaint."""
        self.state = state
        self._sample_history(state)
        if self._render_pending:
            return
        self._render_pending = True
        try:
            self.call_later(self._apply_state)
        except Exception:  # the app may be shutting down
            self._render_pending = False

    def _apply_state(self) -> None:
        """Repaint the active screen from :attr:`state`."""
        self._render_pending = False
        state = self.state
        if state is None:
            return
        try:
            screen = self.screen
        except Exception:  # no screen during shutdown
            return
        if not getattr(screen, "is_mounted", False):
            # A screen that was just pushed composes its widgets on the next
            # refresh; it renders itself once mounted (see ``_show_screen``).
            return
        refresh = getattr(screen, "refresh_from_state", None)
        if not callable(refresh):
            return
        try:
            refresh(state, self.history)
        except Exception as exc:  # a broken panel must not kill the app
            self._render_failures += 1
            if self._render_failures <= 3:
                logger.error(
                    "render failed on %s: %s", type(screen).__name__, exc, exc_info=True
                )

    def _sample_history(self, state: SystemState) -> None:
        """Append the current metric samples to the in-memory history."""
        snapshot = getattr(state, "snapshot", None)
        samples: dict[str, Any] = {
            "health": state.score if getattr(state, "health", None) is not None else None,
            "latency": _deep_number(snapshot, "connectivity", "internet", "avg_latency_ms"),
            "packet_loss": _deep_number(snapshot, "connectivity", "internet", "avg_packet_loss"),
            "rx_rate": _deep_number(snapshot, "bandwidth", "totals", "rx_bytes_per_sec"),
            "tx_rate": _deep_number(snapshot, "bandwidth", "totals", "tx_bytes_per_sec"),
            "connections": _deep_number(snapshot, "connections", "summary", "total"),
        }
        for key, value in samples.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                history = self._history.get(key)
                if history is not None:
                    history.append(float(value))

    # -- actions -------------------------------------------------------------

    def action_refresh(self) -> None:
        """Force an immediate collection cycle."""
        if isinstance(self.screen, ModalScreen):
            return
        self.notify("refreshing collectors ...", timeout=2)
        self.run_worker(self._run_refresh(), group="refresh", exclusive=True, exit_on_error=False)

    def action_diagnose(self) -> None:
        """Open the diagnostics screen and run a diagnosis."""
        self._show_screen(
            DiagnosticsScreen,
            lambda: DiagnosticsScreen(self.monitor, self.config, auto_diagnose=True),
            trigger="diagnose",
        )

    def action_show_interfaces(self) -> None:
        """Open the interface inventory."""
        self._show_screen(InterfacesScreen, InterfacesScreen)

    def action_show_alerts(self) -> None:
        """Open the alerts screen."""
        self._show_screen(AlertsScreen, lambda: AlertsScreen(self.repository))

    def action_show_settings(self) -> None:
        """Open the settings screen."""
        self._show_screen(SettingsScreen, lambda: SettingsScreen(self.monitor, self.config))

    def action_execute_fix(self) -> None:
        """Forward enter to the diagnostics screen's fix workflow."""
        if isinstance(self.screen, ModalScreen):
            return
        handler = getattr(self.screen, "action_execute_fix", None)
        if callable(handler):
            handler()
            return
        self.notify(
            "open the diagnostics screen (d) and select a fix before executing it",
            severity="warning",
            timeout=4,
        )

    async def _run_refresh(self) -> None:
        """Run a collector cycle in an async worker."""
        try:
            outcome = await self.monitor.refresh()
        except Exception as exc:  # report the failure in the UI
            self.notify(f"refresh failed: {exc}", severity="error", timeout=8)
            return
        await self._poll_state()
        failed = [name for name, ok in (outcome or {}).items() if not ok]
        if failed:
            self.notify(
                f"refresh finished with failures: {', '.join(sorted(failed))}",
                severity="warning",
                timeout=6,
            )
        else:
            self.notify("refresh complete", timeout=3)

    # -- navigation ----------------------------------------------------------

    def _show_screen(
        self,
        screen_type: type[Screen[Any]],
        factory: Callable[[], Screen[Any]],
        *,
        trigger: str | None = None,
    ) -> None:
        """Show a screen, reusing the existing instance when one is already open.

        Args:
            screen_type: Class used to detect an existing instance.
            factory: Builds the screen when it is not open yet.
            trigger: Optional ``action_<name>`` to run on the existing screen.
        """
        if isinstance(self.screen, ModalScreen):
            return
        existing = self.screen_of_type(screen_type)
        if existing is not None:
            while self.screen is not existing and len(self.screen_stack) > 1:
                self.pop_screen()
            if trigger:
                action = getattr(existing, f"action_{trigger}", None)
                if callable(action):
                    action()
            return
        self.push_screen(factory())
        self.call_after_refresh(self._apply_state)


def _deep_number(node: Any, *path: str) -> float | None:
    """Read a numeric value at ``path`` inside nested objects or collector payloads."""
    current: Any = node
    for key in path:
        current = current.get(key) if isinstance(current, Mapping) else getattr(current, key, None)
        if current is None:
            return None
    if isinstance(current, bool) or current is None:
        return None
    if isinstance(current, (int, float)):
        return float(current)
    return None
