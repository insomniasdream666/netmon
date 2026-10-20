"""The per-component health card rendered on the dashboard.

A card shows the component name, its health glyph, the 0-100 score, a text
progress bar and the human-readable message produced by the health checker.
It accepts both :class:`~netmon.core.health.HealthCheckResult` objects and
their serialised dict form, and renders ``--`` placeholders before the first
collection cycle completes.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from rich.text import Text
from textual.widgets import Static

from netmon.core.health import HealthCheckResult
from netmon.utils.formatting import BRAND_COLORS, health_bar, health_color, health_glyph

STATES: tuple[str, ...] = ("ok", "warning", "critical", "unknown")

__all__ = ["HealthCard"]


class HealthCard(Static):
    """A bordered card summarising one health component.

    Args:
        component: Component name, e.g. ``"interfaces"``.
        id: DOM id.
        classes: Extra CSS classes.
    """

    def __init__(
        self,
        component: str,
        *,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(id=id, classes=classes or "health-card")
        self.component = component
        self._data: dict[str, Any] | None = None
        self._state = "unknown"
        self.update(self._render_body())
        self._apply_state_class()

    # -- public API ----------------------------------------------------------

    @property
    def state(self) -> str:
        """Current health state name."""
        return self._state

    @property
    def score(self) -> float:
        """Current 0-100 score, ``0.0`` when nothing was collected."""
        if not self._data:
            return 0.0
        try:
            return float(self._data.get("score") or 0.0)
        except (TypeError, ValueError):
            return 0.0

    def update_result(self, result: HealthCheckResult | Mapping[str, Any] | None) -> None:
        """Update the card from a health result, a dict, or ``None`` for no data."""
        self._data = self._normalise(result)
        self._state = str(self._data.get("state") or "unknown") if self._data else "unknown"
        if self._state not in STATES:
            self._state = "unknown"
        self.update(self._render_body())
        self._apply_state_class()

    # -- rendering -----------------------------------------------------------

    @staticmethod
    def _normalise(result: HealthCheckResult | Mapping[str, Any] | None) -> dict[str, Any] | None:
        if result is None:
            return None
        if isinstance(result, Mapping):
            return dict(result)
        to_dict = getattr(result, "to_dict", None)
        return dict(to_dict()) if callable(to_dict) else None

    def _apply_state_class(self) -> None:
        for state in STATES:
            self.set_class(self._state == state, f"state-{state}")

    def _render_body(self) -> Text:
        """Compose the card body as a Rich Text renderable."""
        data = self._data or {}
        state = self._state if self._data else "unknown"
        color = health_color(state)
        glyph = health_glyph(state)
        score = self.score

        title = Text()
        title.append(f"{glyph} ", style=f"bold {color}")
        title.append(self.component, style="bold")

        if not self._data:
            title.append("  --", style="dim")
            body = Text("\n")
            body.append("[", style=BRAND_COLORS["muted"])
            body.append("-" * 18, style="dim")
            body.append("]", style=BRAND_COLORS["muted"])
            body.append("  --\n", style="dim")
            body.append("waiting for data", style=f"italic {BRAND_COLORS['muted']}")
            title.append("\n")
            return title + body

        score_text = f"{score:.0f}%" if data.get("score") is not None else "--"
        title.append(f"  {score_text}", style=f"bold {color}")

        body = Text("\n")
        body.append(health_bar(score, width=18), style=color)
        body.append("\n")
        message = str(data.get("message") or "no issues reported")
        issues = data.get("issues") or []
        body.append(message, style=BRAND_COLORS["text"])
        if issues:
            severities = {str(issue.get("severity", "warning")) for issue in issues if isinstance(issue, Mapping)}
            worst = "critical" if "critical" in severities else "warning"
            label = "critical" if worst == "critical" else "warning"
            body.append(
                f"\n{len(issues)} {label} issue(s)",
                style=f"bold {health_color(worst)}",
            )
        return title + body
