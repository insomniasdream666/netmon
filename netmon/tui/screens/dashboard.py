"""The NetMon dashboard: brand header, health cards, interfaces, trends.

The screen is a pure renderer.  It never talks to the monitor itself; the
application pushes :class:`~netmon.core.monitor.SystemState` snapshots into
:meth:`DashboardScreen.refresh_from_state` on every poll, together with the
in-memory metric history used for the sparklines.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import Grid, Horizontal, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Static

from netmon import __brand_tagline__, __version__
from netmon.core.monitor import SystemState
from netmon.tui.widgets.health_card import HealthCard
from netmon.tui.widgets.log_viewer import LogViewer
from netmon.tui.widgets.metric_graph import MetricGraph
from netmon.tui.widgets.status_table import StatusTable, interface_rows
from netmon.utils.formatting import (
    BRAND_COLORS,
    format_ago,
    format_duration,
    format_latency,
    format_percent,
    format_rate,
    health_bar,
    health_color,
    health_glyph,
)

LOGO_LINES: tuple[str, ...] = (
    "  |     |     |     |     |",
    "  |     |     |     |     |",
    "  |     |     |   | |     |",
    "  |   | | |   | | | |   | |",
    "N E T M O N",
)
"""The canonical five-bar NetMon logo (mirrors ``netmon.__main__.LOGO_LINES``)."""

HEALTH_COMPONENTS: tuple[str, ...] = (
    "interfaces",
    "connectivity",
    "dns",
    "bandwidth",
    "wifi",
    "certificates",
    "connections",
)
"""Component names produced by :class:`~netmon.core.health.HealthChecker`."""

HISTORY_KEYS: tuple[str, ...] = (
    "health",
    "latency",
    "packet_loss",
    "rx_rate",
    "tx_rate",
    "connections",
)
"""Metric series kept in memory by the application for the sparklines."""

INTERFACE_COLUMNS: tuple[str, ...] = (
    "Interface",
    "State",
    "IPv4",
    "RX",
    "TX",
    "Util",
    "Errors",
    "Drops",
    "Link",
)

GRAPH_SPECS: tuple[tuple[str, str, Any, str], ...] = (
    ("health", "Health score", lambda value: f"{value:.0f}%", BRAND_COLORS["health_ok"]),
    ("latency", "Latency", format_latency, BRAND_COLORS["info"]),
    ("packet_loss", "Packet loss", format_percent, BRAND_COLORS["warning"]),
    ("rx_rate", "RX rate", format_rate, BRAND_COLORS["info"]),
    ("tx_rate", "TX rate", format_rate, BRAND_COLORS["info"]),
    ("connections", "Connections", lambda value: f"{value:.0f}", BRAND_COLORS["muted"]),
)
"""Sparkline definitions: ``(history key, label, formatter, colour)``."""

__all__ = [
    "GRAPH_SPECS",
    "HEALTH_COMPONENTS",
    "HISTORY_KEYS",
    "INTERFACE_COLUMNS",
    "LOGO_LINES",
    "DashboardScreen",
]


class DashboardScreen(Screen[None]):
    """Overview of health, interfaces, connectivity and metric trends.

    Args:
        show_sparklines: Render the trend sparklines (``config.tui.show_sparklines``).
        id: DOM id.
    """

    # "escape" is also bound on the app; keeping it here documents the
    # screen-local contract and guarantees a Back entry in the footer.
    BINDINGS: ClassVar[list[BindingType]] = [("escape", "app.back", "Back")]

    def __init__(self, *, show_sparklines: bool = True, id: str | None = "dashboard") -> None:
        super().__init__(id=id)
        self.show_sparklines = show_sparklines

    # -- composition ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        with Horizontal(id="dashboard-header"):
            yield Static("\n".join(LOGO_LINES), id="logo", markup=False)
            yield Static(self._initial_summary(), id="health-summary")
        with VerticalScroll(id="dashboard-scroll"):
            with Grid(id="health-grid"):
                for component in HEALTH_COMPONENTS:
                    yield HealthCard(component, id=f"card-{component}")
            yield Static("INTERFACES", classes="section-title")
            table = StatusTable(id="interface-table")
            table.set_columns(INTERFACE_COLUMNS)
            yield table
            yield Static("CONNECTIVITY", classes="section-title")
            yield Static(Text("no connectivity data collected", style="dim"), id="connectivity-panel")
            if self.show_sparklines:
                yield Static("TRENDS", classes="section-title")
                with Grid(id="sparkline-grid"):
                    for key, label, formatter, color in GRAPH_SPECS:
                        yield MetricGraph(
                            label,
                            formatter=formatter,
                            color=color,
                            id=f"graph-{key}",
                        )
            yield Static("MONITOR", classes="section-title")
            yield LogViewer(id="monitor-log")
        yield Footer()

    # -- state rendering -----------------------------------------------------

    def refresh_from_state(
        self,
        state: SystemState,
        history: Mapping[str, Sequence[float]] | None = None,
    ) -> None:
        """Repaint every panel from a monitor state snapshot."""
        if not self.is_mounted:
            return
        self._update_summary(state)
        self._update_cards(state)
        self._update_interfaces(state)
        self._update_connectivity(state)
        if self.show_sparklines:
            self._update_graphs(history or {})
        self._update_log(state)

    # -- panels --------------------------------------------------------------

    def _initial_summary(self) -> Text:
        summary = Text()
        summary.append(f"NETMON {__version__}", style=f"bold {BRAND_COLORS['info']}")
        summary.append("   ")
        summary.append("○ waiting for data", style=BRAND_COLORS["muted"])
        summary.append(f"\n{__brand_tagline__}", style=f"italic {BRAND_COLORS['muted']}")
        return summary

    def _update_summary(self, state: SystemState) -> None:
        panel = self.query_one("#health-summary", Static)
        health = state.health
        state_name = state.state if health else "unknown"
        color = health_color(state_name)
        score = state.score

        summary = Text()
        summary.append(f"NETMON {__version__}", style=f"bold {BRAND_COLORS['info']}")
        summary.append("   ")
        summary.append(f"{health_glyph(state_name)} {state_name.upper()}", style=f"bold {color}")
        summary.append(f"  {score:.0f}%" if health else "  --", style=f"bold {color}")
        summary.append("\n")
        summary.append(health_bar(score, width=22), style=color)
        summary.append("  ")
        summary.append(__brand_tagline__, style=f"italic {BRAND_COLORS['muted']}")
        summary.append("\n")
        summary.append(f"{state.hostname or 'unknown host'}", style=BRAND_COLORS["text"])
        summary.append("   updated ", style=BRAND_COLORS["muted"])
        summary.append(format_ago(state.last_cycle_at), style=BRAND_COLORS["text"])
        summary.append("   cycles ", style=BRAND_COLORS["muted"])
        summary.append(str(state.cycles), style=BRAND_COLORS["text"])
        summary.append("   last cycle ", style=BRAND_COLORS["muted"])
        summary.append(
            f"{state.last_cycle_ms:.0f} ms" if state.cycles else "--", style=BRAND_COLORS["text"]
        )
        summary.append("   uptime ", style=BRAND_COLORS["muted"])
        summary.append(format_duration(state.uptime_seconds), style=BRAND_COLORS["text"])
        issues = len(state.issues)
        if issues:
            summary.append("   issues ", style=BRAND_COLORS["muted"])
            summary.append(str(issues), style=f"bold {BRAND_COLORS['warning']}")
        panel.update(summary)

    def _update_cards(self, state: SystemState) -> None:
        components: dict[str, Any] = {}
        if state.health is not None:
            for result in state.health.components:
                components[result.component] = result
        for component in HEALTH_COMPONENTS:
            card = self.query_one(f"#card-{component}", HealthCard)
            card.update_result(components.get(component))

    def _update_interfaces(self, state: SystemState) -> None:
        table = self.query_one("#interface-table", StatusTable)
        rows = interface_rows(state.snapshot)
        table.sync(rows, placeholder="no interface data collected")

    def _update_connectivity(self, state: SystemState) -> None:
        panel = self.query_one("#connectivity-panel", Static)
        snapshot = state.snapshot
        data: Mapping[str, Any] = getattr(snapshot, "connectivity", None) or {}
        if not isinstance(data, Mapping) or not data:
            panel.update(Text("no connectivity data collected", style="dim"))
            return

        line = Text()
        gateway = data.get("gateway") or {}
        internet = data.get("internet") or {}
        dns_health = data.get("dns_health") or {}
        ping = data.get("ping") or {}

        self._append_line(
            line,
            "GATEWAY",
            str(gateway.get("gateway") or "--"),
            "reachable" if gateway.get("reachable") else "unreachable",
            format_latency(gateway.get("latency_ms")),
            f"loss {format_percent(gateway.get('packet_loss'))}",
            state="ok" if gateway.get("reachable") else "critical",
        )
        self._append_line(
            line,
            "INTERNET",
            "reachable" if internet.get("reachable") else "unreachable",
            f"{internet.get('targets_ok', 0)}/{internet.get('targets_total', 0)} targets",
            format_latency(internet.get("avg_latency_ms")),
            f"loss {format_percent(internet.get('avg_packet_loss'))}",
            state="ok" if internet.get("reachable") else "critical",
        )
        dns = data.get("dns") or {}
        dns_total = dns_health.get("total")
        dns_failures = dns_health.get("failures")
        if dns_total is None and isinstance(dns, Mapping):
            dns_total = len(dns)
            dns_failures = sum(
                1 for info in dns.values() if isinstance(info, Mapping) and not info.get("success")
            )
        self._append_line(
            line,
            "DNS",
            f"{int(dns_total or 0)} queries",
            f"{int(dns_failures or 0)} failures",
            format_latency(dns_health.get("avg_latency_ms")),
            f"rate {format_percent(dns_health.get('failure_rate'))}",
            state="ok" if dns_health.get("healthy", True) else "warning",
        )
        self._append_line(
            line,
            "PING",
            f"{len(ping)} target(s) monitored",
            state="ok" if ping else "unknown",
        )
        panel.update(line)

    @staticmethod
    def _append_line(
        text: Text,
        label: str,
        *columns: str,
        state: str = "unknown",
    ) -> None:
        """Append one aligned status line to the connectivity panel."""
        text.append(f"{label:<10}", style=f"bold {BRAND_COLORS['muted']}")
        text.append(f"{health_glyph(state)} ", style=health_color(state))
        text.append("  ".join(str(column) for column in columns), style=BRAND_COLORS["text"])
        text.append("\n")

    def _update_graphs(self, history: Mapping[str, Sequence[float]]) -> None:
        for key, _label, _formatter, _color in GRAPH_SPECS:
            graph = self.query_one(f"#graph-{key}", MetricGraph)
            graph.update_series(history.get(key, ()))

    def _update_log(self, state: SystemState) -> None:
        viewer = self.query_one("#monitor-log", LogViewer)
        entries: list[tuple[str, str]] = []
        if state.cycles:
            entries.append(
                (
                    "ok",
                    f"collection cycle {state.cycles} completed in {state.last_cycle_ms:.0f} ms",
                )
            )
        for alert in list(state.alerts)[:4]:
            if isinstance(alert, Mapping):
                entries.append(
                    (
                        str(alert.get("severity", "info")),
                        f"{alert.get('rule_name', 'alert')}: {alert.get('message', '')}",
                    )
                )
        for error in list(state.errors)[-4:]:
            entries.append(("error", str(error)))
        if not entries:
            entries.append(("info", "waiting for the first collection cycle"))
        viewer.set_lines(entries)
