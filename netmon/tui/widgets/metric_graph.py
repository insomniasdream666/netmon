"""Sparkline graphs built on the shared :func:`~netmon.utils.formatting.sparkline` helper.

The dashboard keeps a short in-memory history for a handful of metrics and
renders one :class:`MetricGraph` per series.  Graphs degrade gracefully: with
no samples they show a ``no samples yet`` placeholder instead of an empty line.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from rich.text import Text
from textual.widgets import Static

from netmon.utils.formatting import BRAND_COLORS, sparkline

Formatter = Callable[[float], str]
"""Renders the latest sample for display."""

__all__ = ["Formatter", "MetricGraph"]


def _default_formatter(value: float) -> str:
    """Plain one-decimal number, used when no formatter is supplied."""
    return f"{value:.1f}"


class MetricGraph(Static):
    """A labelled sparkline with the current value shown alongside.

    Args:
        label: Series name shown on the first line.
        formatter: Callable rendering the latest sample, e.g.
            :func:`~netmon.utils.formatting.format_rate`.
        width: Maximum number of samples rendered in the sparkline.
        color: Sparkline colour (defaults to the NetMon info blue).
        id: DOM id.
        classes: Extra CSS classes.
    """

    def __init__(
        self,
        label: str,
        *,
        formatter: Formatter | None = None,
        width: int = 24,
        color: str = BRAND_COLORS["info"],
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(id=id, classes=classes or "metric-graph")
        self.label = label
        self.width = max(4, int(width))
        self.color = color
        self._formatter: Formatter = formatter or _default_formatter
        self._values: list[float] = []
        self.update(self._render_body())

    # -- public API ----------------------------------------------------------

    def update_series(self, values: Sequence[float], *, current: float | None = None) -> None:
        """Replace the rendered series.

        Args:
            values: Samples, oldest first; only the last ``width`` are shown.
            current: Explicit "now" value; defaults to the last sample.
        """
        self._values = [float(value) for value in values if isinstance(value, (int, float))]
        self.update(self._render_body(current=current))

    # -- rendering -----------------------------------------------------------

    def _render_body(self, *, current: float | None = None) -> Text:
        body = Text()
        body.append(self.label, style=BRAND_COLORS["muted"])

        if not self._values:
            body.append("\n")
            body.append("no samples yet", style=f"italic {BRAND_COLORS['muted']}")
            return body

        latest = current if current is not None else self._values[-1]
        body.append("  ")
        body.append(self._formatter(float(latest)), style=f"bold {self.color}")
        body.append("\n")
        body.append(sparkline(self._values, width=self.width), style=self.color)
        return body
