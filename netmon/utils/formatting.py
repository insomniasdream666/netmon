"""Human-readable formatting helpers shared by the TUI, web UI and CLI.

Branding rules enforced here:

* No emoji anywhere in machine-parseable output.
* Health states use the documented glyphs: ``●`` green, ``◐`` amber,
  ``●`` red, ``○`` dim, ``⟳`` blue.
* Byte/rate values are rendered with binary units for readability while
  still reporting exact numbers where precision matters.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

BYTE_UNITS = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
BIT_UNITS = ("bit", "Kbit", "Mbit", "Gbit", "Tbit")

HEALTH_GLYPHS: dict[str, str] = {
    "ok": "●",
    "healthy": "●",
    "green": "●",
    "warning": "◐",
    "warn": "◐",
    "amber": "◐",
    "degraded": "◐",
    "critical": "●",
    "error": "●",
    "red": "●",
    "unknown": "○",
    "dim": "○",
    "running": "⟳",
    "info": "⟳",
    "blue": "⟳",
}

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "error": 1,
    "warning": 2,
    "degraded": 3,
    "ok": 4,
    "info": 5,
    "unknown": 6,
}

BRAND_COLORS: dict[str, str] = {
    "background": "#0D1117",
    "health_ok": "#00D084",
    "warning": "#FFB800",
    "critical": "#FF4757",
    "info": "#00B4D8",
    "text": "#C9D1D9",
    "muted": "#8B949E",
}


def format_bytes(value: float | int | None, *, precision: int = 1) -> str:
    """Format a byte count using binary units, e.g. ``1.5 MiB``."""
    if value is None:
        return "--"
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return "--"
    sign = "-" if amount < 0 else ""
    amount = abs(amount)
    for unit in BYTE_UNITS:
        if amount < 1024 or unit == BYTE_UNITS[-1]:
            return f"{sign}{amount:.{precision}f} {unit}" if unit != "B" else f"{sign}{amount:.0f} B"
        amount /= 1024
    return f"{sign}{amount:.{precision}f} PiB"


def format_rate(bytes_per_second: float | int | None, *, precision: int = 1) -> str:
    """Format a throughput value as ``1.5 MiB/s``."""
    if bytes_per_second is None:
        return "--"
    return f"{format_bytes(bytes_per_second, precision=precision)}/s"


def format_bps(bits_per_second: float | int | None, *, precision: int = 1) -> str:
    """Format a link speed expressed in bits per second, e.g. ``1.0 Gbit/s``."""
    if bits_per_second is None:
        return "--"
    amount = float(bits_per_second)
    for unit in BIT_UNITS:
        if amount < 1000 or unit == BIT_UNITS[-1]:
            return f"{amount:.{precision}f} {unit}/s"
        amount /= 1000
    return f"{amount:.{precision}f} Tbit/s"


def format_duration(seconds: float | int | None) -> str:
    """Format a duration in seconds as ``1d 2h 3m`` style text."""
    if seconds is None:
        return "--"
    total = int(seconds)
    if total < 0:
        return "--"
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def format_latency(milliseconds: float | int | None) -> str:
    """Format a latency measurement in milliseconds."""
    if milliseconds is None:
        return "--"
    value = float(milliseconds)
    if value >= 1000:
        return f"{value / 1000:.2f} s"
    if value >= 100:
        return f"{value:.0f} ms"
    return f"{value:.1f} ms"


def format_percent(value: float | int | None, *, precision: int = 1) -> str:
    """Format a percentage value."""
    if value is None:
        return "--"
    return f"{float(value):.{precision}f}%"


def format_timestamp(value: datetime | float | int | None, *, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format a datetime or epoch value in local-agnostic UTC text."""
    if value is None:
        return "--"
    if isinstance(value, (int, float)):
        moment = datetime.fromtimestamp(float(value), tz=UTC)
    else:
        moment = value if value.tzinfo else value.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime(fmt)


def format_ago(value: datetime | float | int | None) -> str:
    """Format a timestamp as a relative age, e.g. ``3m ago``."""
    if value is None:
        return "never"
    moment = (
        datetime.fromtimestamp(float(value), tz=UTC)
        if isinstance(value, (int, float))
        else (value if value.tzinfo else value.replace(tzinfo=UTC))
    )
    delta = datetime.now(UTC) - moment
    if delta < timedelta(seconds=0):
        return "just now"
    seconds = int(delta.total_seconds())
    if seconds < 5:
        return "just now"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def health_glyph(state: str) -> str:
    """Map a health state name to its branding glyph."""
    return HEALTH_GLYPHS.get(str(state).strip().lower(), "○")


def health_color(state: str) -> str:
    """Map a health state name to its brand hex colour."""
    normalised = str(state).strip().lower()
    if normalised in {"ok", "healthy", "green"}:
        return BRAND_COLORS["health_ok"]
    if normalised in {"warning", "warn", "amber", "degraded"}:
        return BRAND_COLORS["warning"]
    if normalised in {"critical", "error", "red"}:
        return BRAND_COLORS["critical"]
    if normalised in {"running", "info", "blue"}:
        return BRAND_COLORS["info"]
    return BRAND_COLORS["muted"]


def severity_rank(severity: str) -> int:
    """Sort key for severities; lower means more severe."""
    return SEVERITY_ORDER.get(str(severity).strip().lower(), SEVERITY_ORDER["unknown"])


def truncate(text: str, width: int = 60, *, suffix: str = "...") -> str:
    """Shorten ``text`` to ``width`` characters, adding a suffix when cut."""
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= len(suffix):
        return text[:width]
    return text[: width - len(suffix)] + suffix


def table_row(cells: Iterable[object], widths: Iterable[int]) -> str:
    """Render a fixed-width plain-text table row."""
    parts: list[str] = []
    for cell, width in zip(cells, widths, strict=False):
        text = truncate(str(cell), width - 1)
        parts.append(text.ljust(width))
    return "".join(parts).rstrip()


def sparkline(values: Iterable[float], *, width: int = 24) -> str:
    """Render a compact unicode sparkline for a series of numbers."""
    blocks = "▁▂▃▄▅▆▇█"
    data = [float(v) for v in values][-width:]
    if not data:
        return ""
    low, high = min(data), max(data)
    span = high - low
    if span == 0:
        return blocks[0] * len(data)
    chars = []
    for value in data:
        index = int((value - low) / span * (len(blocks) - 1))
        chars.append(blocks[max(0, min(index, len(blocks) - 1))])
    return "".join(chars)


def health_bar(score: float, *, width: int = 20) -> str:
    """Render a health score as a text progress bar."""
    clamped = max(0.0, min(100.0, float(score)))
    filled = round(clamped / 100 * width)
    return f"[{'#' * filled}{'.' * (width - filled)}] {clamped:.0f}%"


def score_state(score: float, *, warning: float = 80.0, critical: float = 50.0) -> str:
    """Classify a 0-100 health score into a branding state name."""
    if score >= warning:
        return "ok"
    if score >= critical:
        return "warning"
    return "critical"


def relative_range_to_seconds(value: str) -> int:
    """Convert a range token such as ``15m``, ``24h``, ``7d`` to seconds."""
    text = str(value).strip().lower()
    if not text:
        raise ValueError("empty range")
    unit = text[-1]
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if unit in multipliers:
        number = float(text[:-1] or 1)
        return int(number * multipliers[unit])
    return int(float(text))


def parse_range(value: str) -> timedelta:
    """Parse a range token into a :class:`~datetime.timedelta`."""
    return timedelta(seconds=relative_range_to_seconds(value))
