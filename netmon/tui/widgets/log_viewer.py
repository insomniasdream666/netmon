"""A colour-coded scrolling log pane shared by the dashboard and diagnostics screens.

Levels are rendered with the branding palette rather than emoji, and every
line is timestamped so a screenshot of the TUI is self-explanatory.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from rich.text import Text
from textual.widgets import RichLog

from netmon.utils.formatting import BRAND_COLORS

LEVEL_STYLES: dict[str, str] = {
    "debug": BRAND_COLORS["muted"],
    "info": BRAND_COLORS["info"],
    "ok": BRAND_COLORS["health_ok"],
    "warning": BRAND_COLORS["warning"],
    "error": BRAND_COLORS["critical"],
    "critical": BRAND_COLORS["critical"],
}
"""Colour per log level; unknown levels fall back to the muted text colour."""

__all__ = ["LEVEL_STYLES", "LogViewer"]


class LogViewer(RichLog):
    """A :class:`~textual.widgets.RichLog` with NetMon severity styling.

    Args:
        max_lines: Ring-buffer size; the oldest lines are dropped first.
        id: DOM id.
        classes: Extra CSS classes.
    """

    def __init__(
        self,
        *,
        max_lines: int = 400,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(
            max_lines=max_lines,
            min_width=1,
            wrap=False,
            markup=False,
            highlight=False,
            auto_scroll=True,
            id=id,
            classes=classes or "log-viewer",
        )

    # -- public API ----------------------------------------------------------

    def log_line(
        self,
        message: str,
        *,
        level: str = "info",
        timestamp: datetime | None = None,
        source: str | None = None,
    ) -> None:
        """Append one timestamped, colour-coded line."""
        self.write(self._line(message, level=level, timestamp=timestamp, source=source))

    def set_lines(
        self,
        entries: Iterable[tuple[str, str]],
        *,
        timestamp: datetime | None = None,
    ) -> None:
        """Replace the pane contents from ``(level, message)`` pairs."""
        self.clear()
        for level, message in entries:
            self.log_line(message, level=level, timestamp=timestamp)

    def clear_lines(self) -> None:
        """Remove every line."""
        self.clear()

    # -- rendering -----------------------------------------------------------

    @staticmethod
    def _line(
        message: str,
        *,
        level: str,
        timestamp: datetime | None,
        source: str | None,
    ) -> Text:
        moment = timestamp or datetime.now(UTC)
        stamp = moment.astimezone(UTC).strftime("%H:%M:%S")
        normalised = str(level).strip().lower()
        style = LEVEL_STYLES.get(normalised, BRAND_COLORS["text"])

        line = Text()
        line.append(f"{stamp} ", style=BRAND_COLORS["muted"])
        line.append(f"{normalised.upper():<5}", style=f"bold {style}")
        if source:
            line.append(f" {source}", style="italic " + BRAND_COLORS["muted"])
        line.append("  ")
        line.append(str(message), style=BRAND_COLORS["text"])
        return line
