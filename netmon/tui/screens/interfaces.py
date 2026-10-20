"""Interface inventory screen: every NIC with counters, rates and link details.

The table comes straight from the ``interfaces`` collector payload and is
enriched with the latest ``bandwidth`` samples; selecting a row shows the full
detail block for that interface.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import BindingType
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Static

from netmon.core.monitor import SystemState
from netmon.tui.widgets.status_table import StatusTable, bandwidth_by_interface, interface_rows
from netmon.utils.formatting import (
    BRAND_COLORS,
    format_ago,
    format_bytes,
    format_percent,
    format_rate,
    health_color,
    health_glyph,
)

COLUMNS: tuple[str, ...] = (
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

__all__ = ["COLUMNS", "InterfacesScreen"]


def _mapping(node: Any, key: str) -> Mapping[str, Any]:
    """Return ``node[key]`` when it is a mapping, else an empty mapping."""
    if not isinstance(node, Mapping):
        return {}
    inner = node.get(key)
    return inner if isinstance(inner, Mapping) else {}


def _join(value: Any) -> str | None:
    """Join a list-ish value into a comma separated string, or ``None``."""
    if isinstance(value, (list, tuple, set)):
        items = [str(item) for item in value if item not in (None, "")]
        return ", ".join(items) or None
    if value in (None, ""):
        return None
    return str(value)


class InterfacesScreen(Screen[None]):
    """Detailed per-interface view.

    Args:
        id: DOM id.
    """

    # "escape" is also bound on the app; keeping it here documents the
    # screen-local contract and guarantees a Back entry in the footer.
    BINDINGS: ClassVar[list[BindingType]] = [("escape", "app.back", "Back")]

    AUTO_FOCUS = "#interfaces-table"

    def __init__(self, *, id: str | None = "interfaces") -> None:
        super().__init__(id=id)
        self._state: SystemState | None = None
        self._selected: str | None = None

    # -- composition ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._header_text(), id="interfaces-header")
        with VerticalScroll(id="interfaces-scroll"):
            yield Static("INTERFACES", classes="section-title")
            table = StatusTable(id="interfaces-table")
            table.set_columns(COLUMNS)
            yield table
            yield Static("DETAIL", classes="section-title")
            yield Static(
                Text("select an interface to inspect it", style="dim"),
                id="interface-detail",
            )
        yield Footer()

    # -- state rendering -----------------------------------------------------

    def refresh_from_state(
        self,
        state: SystemState,
        history: Mapping[str, Sequence[float]] | None = None,
    ) -> None:
        """Repaint the inventory and the detail block."""
        self._state = state
        if not self.is_mounted:
            return
        table = self.query_one("#interfaces-table", StatusTable)
        rows = interface_rows(state.snapshot)
        table.sync(rows, placeholder="no interface data collected")
        if self._selected is None and rows:
            self._selected = rows[0][0]
        self.query_one("#interfaces-header", Static).update(self._header_text(state))
        self._update_detail()

    # -- interactions --------------------------------------------------------

    def on_data_table_row_highlighted(self, event: StatusTable.RowHighlighted) -> None:
        """Follow the cursor with the detail block."""
        key = event.row_key.value
        if key:
            self._selected = str(key)
        self._update_detail()

    # -- rendering -----------------------------------------------------------

    def _header_text(self, state: SystemState | None = None) -> Text:
        header = Text()
        header.append("INTERFACES", style=f"bold {BRAND_COLORS['info']}")
        if state is None:
            header.append("   waiting for data", style=BRAND_COLORS["muted"])
            return header

        interfaces = _mapping(getattr(state.snapshot, "interfaces", None), "interfaces")
        up = sum(
            1 for info in interfaces.values() if isinstance(info, Mapping) and info.get("is_up")
        )
        header.append(f"   {len(interfaces)} detected, {up} up", style=BRAND_COLORS["text"])
        health = getattr(state, "health", None)
        live_issues = getattr(health, "issues", None) if health is not None else None
        count = len(live_issues) if live_issues else len(state.issues)
        header.append(f"   {count} known issue(s)", style=BRAND_COLORS["muted"])
        header.append(f"   updated {format_ago(state.last_cycle_at)}", style=BRAND_COLORS["muted"])
        return header

    def _update_detail(self) -> None:
        panel = self.query_one("#interface-detail", Static)
        state = self._state
        name = self._selected
        if state is None or not name:
            panel.update(Text("select an interface to inspect it", style="dim"))
            return

        interfaces = _mapping(getattr(state.snapshot, "interfaces", None), "interfaces")
        info = interfaces.get(name)
        if not isinstance(info, Mapping):
            panel.update(Text("no data for the selected interface", style="dim"))
            return

        bandwidth = bandwidth_by_interface(state.snapshot).get(name, {})
        wifi_interfaces = _mapping(getattr(state.snapshot, "wifi", None), "interfaces")
        wifi_info = wifi_interfaces.get(name)

        up = bool(info.get("is_up"))
        state_name = "ok" if up else "critical"

        body = Text()
        body.append(f"{health_glyph(state_name)} ", style=f"bold {health_color(state_name)}")
        body.append(name, style="bold")
        body.append("  ")
        body.append(
            str(info.get("state") or ("up" if up else "down")), style=health_color(state_name)
        )
        if info.get("is_wireless"):
            body.append("  wireless", style=BRAND_COLORS["info"])
        if info.get("is_loopback"):
            body.append("  loopback", style=BRAND_COLORS["muted"])
        body.append("\n")

        link_parts = [
            f"{float(info['speed_mbps']):.0f} Mbps" if info.get("speed_mbps") else None,
            str(info.get("duplex")) if info.get("duplex") else None,
            f"MTU {info.get('mtu')}" if info.get("mtu") else None,
        ]
        self._detail_line(body, "IPv4", _join(info.get("ipv4")))
        self._detail_line(body, "IPv6", _join(info.get("ipv6")))
        self._detail_line(body, "MAC", info.get("mac"))
        self._detail_line(body, "LINK", "  ".join(part for part in link_parts if part) or None)
        self._detail_line(
            body,
            "COUNTERS",
            f"rx {format_bytes(info.get('rx_bytes'))} / tx {format_bytes(info.get('tx_bytes'))}",
        )
        self._detail_line(
            body,
            "ERRORS",
            f"errors {int(info.get('rx_errors') or 0)}/{int(info.get('tx_errors') or 0)} "
            f"drops {int(info.get('rx_dropped') or 0)}/{int(info.get('tx_dropped') or 0)}",
        )
        self._detail_line(
            body,
            "RATES",
            f"rx {format_rate(bandwidth.get('rx_bytes_per_sec'))} / "
            f"tx {format_rate(bandwidth.get('tx_bytes_per_sec'))} / "
            f"util {format_percent(bandwidth.get('utilization_percent'))}",
        )
        self._detail_line(body, "GATEWAY", info.get("gateway"))
        self._detail_line(body, "DNS", _join(info.get("dns_servers")))

        if isinstance(wifi_info, Mapping) and wifi_info:
            signal = wifi_info.get("signal_dbm")
            wifi_parts = [
                str(wifi_info.get("ssid") or "not associated"),
                f"{signal} dBm" if signal is not None else None,
                f"ch {wifi_info.get('channel')}" if wifi_info.get("channel") is not None else None,
                str(wifi_info.get("standard") or "") or None,
                f"{wifi_info['bitrate_mbps']} Mbps" if wifi_info.get("bitrate_mbps") else None,
            ]
            self._detail_line(body, "WIFI", "  ".join(part for part in wifi_parts if part))
        panel.update(body)

    @staticmethod
    def _detail_line(text: Text, label: str, value: Any) -> None:
        text.append(f"{label:<10}", style=f"bold {BRAND_COLORS['muted']}")
        text.append("--" if value in (None, "") else str(value), style=BRAND_COLORS["text"])
        text.append("\n")
