"""Status tables: a :class:`~textual.widgets.DataTable` tuned for NetMon screens.

:class:`StatusTable` keeps rows addressable by a stable string key so a
periodic refresh can repaint the table without the cursor jumping and without
flicker when nothing actually changed.  The module also hosts the small
snapshot helpers that turn collector payloads into table rows, so the
dashboard and the interfaces screen render identical numbers.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from rich.text import Text
from textual.widgets import DataTable

from netmon.utils.formatting import (
    format_rate,
    health_color,
    health_glyph,
)

CellValue = str | int | float | Text | None
"""Anything a cell accepts; ``None`` renders as the ``--`` placeholder."""

StatusRow = tuple[str, Sequence[CellValue]]
"""A row: its stable key plus the cell values."""

__all__ = [
    "CellValue",
    "StatusRow",
    "StatusTable",
    "bandwidth_by_interface",
    "cell_text",
    "interface_rows",
]


def cell_text(value: CellValue) -> Text:
    """Normalise a cell value into a Rich :class:`~rich.text.Text` renderable."""
    if isinstance(value, Text):
        return value
    if value is None:
        return Text("--", style="dim")
    return Text(str(value))


def _as_mapping(node: Any, key: str) -> Mapping[str, Any]:
    """Return ``node[key]`` when it is a mapping, else an empty mapping."""
    if not isinstance(node, Mapping):
        return {}
    inner = node.get(key)
    return inner if isinstance(inner, Mapping) else {}


def _number(value: Any) -> float | None:
    """Best-effort numeric coercion; returns ``None`` when not a number."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def bandwidth_by_interface(snapshot: Any) -> dict[str, Mapping[str, Any]]:
    """Per-interface bandwidth samples from a :class:`SystemSnapshot`."""
    interfaces = _as_mapping(getattr(snapshot, "bandwidth", None), "interfaces")
    return {str(name): info for name, info in interfaces.items() if isinstance(info, Mapping)}


def interface_rows(
    snapshot: Any,
    *,
    health_state: str = "ok",
) -> list[StatusRow]:
    """Build the interface summary rows shared by the dashboard and interfaces screen.

    Args:
        snapshot: The monitor's :class:`~netmon.core.health.SystemSnapshot`.
        health_state: Overall health state, used to colour the "State" column.

    Returns:
        ``(key, cells)`` pairs ready for :meth:`StatusTable.sync`.
    """
    interfaces = _as_mapping(getattr(snapshot, "interfaces", None), "interfaces")
    rates = bandwidth_by_interface(snapshot)
    rows: list[StatusRow] = []

    for name in sorted(interfaces):
        info = interfaces[name]
        if not isinstance(info, Mapping):
            continue
        up = bool(info.get("is_up"))
        state = "ok" if up else "critical"
        errors = int(_number(info.get("rx_errors")) or 0) + int(_number(info.get("tx_errors")) or 0)
        dropped = int(_number(info.get("rx_dropped")) or 0) + int(_number(info.get("tx_dropped")) or 0)

        state_cell = Text()
        state_cell.append(f"{health_glyph(state)} ", style=health_color(state))
        state_cell.append("up" if up else "down", style=health_color(state))

        speed = _number(info.get("speed_mbps"))
        speed_text = f"{speed:.0f} Mbps" if speed else None

        rate = rates.get(str(name), {})
        rx_rate = _number(rate.get("rx_bytes_per_sec"))
        tx_rate = _number(rate.get("tx_bytes_per_sec"))
        util = _number(rate.get("utilization_percent"))

        error_cell = Text(str(errors) if errors else "0")
        if errors:
            error_cell.stylize("bold #FF4757")
        drop_cell = Text(str(dropped) if dropped else "0")
        if dropped:
            drop_cell.stylize("bold #FFB800")

        rows.append(
            (
                str(name),
                (
                    str(name),
                    state_cell,
                    ", ".join(str(item) for item in (info.get("ipv4") or [])) or None,
                    format_rate(rx_rate),
                    format_rate(tx_rate),
                    util if util is None else f"{util:.0f}%",
                    error_cell,
                    drop_cell,
                    speed_text,
                ),
            )
        )
    return rows


class StatusTable(DataTable[Text]):
    """A :class:`~textual.widgets.DataTable` that refreshes without flicker.

    Args:
        cursor_type: ``"row"`` (default) or any value ``DataTable`` accepts.
        show_header: Render the header row.
        zebra_stripes: Alternate row shading.
        id: DOM id.
        classes: Extra CSS classes.
    """

    def __init__(
        self,
        *,
        cursor_type: str = "row",
        show_header: bool = True,
        zebra_stripes: bool = True,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(
            cursor_type=cursor_type,  # type: ignore[arg-type]
            show_header=show_header,
            zebra_stripes=zebra_stripes,
            id=id,
            classes=classes,
        )
        self._fingerprint: tuple[Any, ...] | None = None
        self._row_keys: list[str] = []
        self._column_labels: list[str] = []

    # -- columns -------------------------------------------------------------

    @property
    def column_labels(self) -> list[str]:
        """The header labels currently configured."""
        return list(self._column_labels)

    def set_columns(self, columns: Sequence[str]) -> None:
        """(Re)define the header row and drop every existing row."""
        super().clear(columns=True)
        self._column_labels = [str(column) for column in columns]
        if self._column_labels:
            self.add_columns(*self._column_labels)
        self._fingerprint = None
        self._row_keys = []

    # -- rows ----------------------------------------------------------------

    def selected_key(self) -> str | None:
        """Key of the row under the cursor, or ``None`` when empty."""
        index = self.cursor_row
        if 0 <= index < len(self._row_keys):
            return self._row_keys[index]
        return None

    def sync(self, rows: Iterable[StatusRow], *, placeholder: str = "no data collected") -> None:
        """Replace every row, keeping the cursor on the same key when possible.

        Args:
            rows: ``(key, cells)`` pairs; keys must be unique and stable.
            placeholder: Text used for a single filler row when ``rows`` is empty.
        """
        materialised: list[tuple[str, tuple[Text, ...]]] = [
            (str(key), tuple(cell_text(cell) for cell in cells)) for key, cells in rows
        ]
        if not materialised:
            width = max(1, len(self._column_labels))
            cells: tuple[Text, ...] = tuple(
                Text(placeholder, style="dim") if position == 0 else Text("--", style="dim")
                for position in range(width)
            )
            materialised = [("__placeholder__", cells)]

        fingerprint = tuple(
            (key, tuple(f"{cell!s}|{cell.style or ''}" for cell in cells))
            for key, cells in materialised
        )
        if fingerprint == self._fingerprint:
            return

        selected = self.selected_key()
        self._fingerprint = fingerprint
        if self.is_mounted:
            with self.app.batch_update():
                self._replace_rows(materialised, selected)
        else:
            self._replace_rows(materialised, selected)

    def _replace_rows(
        self, rows: Sequence[tuple[str, tuple[Text, ...]]], selected: str | None
    ) -> None:
        """Swap the row set while preserving the logical cursor position."""
        self.clear()
        self._row_keys = []
        for key, cells in rows:
            try:
                self.add_row(*cells, key=key)
            except Exception:
                self.add_row(*cells)
            self._row_keys.append(key)

        if selected is not None and selected in self._row_keys:
            self.move_cursor(row=self._row_keys.index(selected), animate=False, scroll=False)
