"""Collector contract shared by all seven monitoring collectors.

The base class implements the Template Method pattern: subclasses provide
``collect()`` (and optionally ``setup``/``teardown``), while the base class
handles timing, error isolation, health bookkeeping and metric emission.

Error isolation is a hard requirement: a collector that raises, times out or
returns malformed data must never interrupt the monitoring loop. Failures are
captured in :attr:`CollectionResult.errors` and surfaced in the UI.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(UTC)


@dataclass(slots=True)
class CollectionResult:
    """Outcome of a single collector run.

    Attributes:
        collector_name: Stable identifier, matching the collector's ``name``.
        timestamp: When the collection finished (UTC).
        data: Structured payload; keys depend on the collector.
        errors: Non-fatal problems encountered while collecting.
        duration_ms: Wall-clock collection time in milliseconds.
        metrics: Time-series points ready to be written to InfluxDB.
        ok: False only when the collector produced no usable data at all.
    """

    collector_name: str
    timestamp: datetime = field(default_factory=utcnow)
    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    metrics: list[dict[str, Any]] = field(default_factory=list)
    ok: bool = True

    def add_error(self, message: str) -> None:
        """Record a non-fatal error."""
        if message not in self.errors:
            self.errors.append(message)

    def merge(self, other: CollectionResult) -> None:
        """Fold another result into this one (used for multi-source collectors)."""
        self.data.update(other.data)
        self.metrics.extend(other.metrics)
        for error in other.errors:
            self.add_error(error)

    def as_dict(self) -> dict[str, Any]:
        """Serialise for API/TUI consumption."""
        return {
            "collector": self.collector_name,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "errors": list(self.errors),
            "duration_ms": round(self.duration_ms, 2),
            "ok": self.ok,
            "metric_count": len(self.metrics),
        }


class BaseCollector(ABC):
    """Abstract base for every NetMon collector.

    Subclasses must set :attr:`name` and implement :meth:`collect`. The base
    class supplies a guarded :meth:`run` that never raises, so callers
    (scheduler, TUI, web API) can always rely on receiving a result object.
    """

    #: Stable identifier, also used as the configuration interval key.
    name: str = "collector"

    #: Default polling interval in seconds; overridden from configuration.
    interval: int = 30

    #: Seconds allowed for a single collection before it is abandoned.
    timeout: float = 20.0

    def __init__(self, interval: int | None = None, *, timeout: float | None = None) -> None:
        if interval is not None:
            self.interval = max(1, int(interval))
        if timeout is not None:
            self.timeout = float(timeout)
        self.last_result: CollectionResult | None = None
        self.last_error: str | None = None
        self.run_count: int = 0
        self.failure_count: int = 0
        self._ready = False

    # -- lifecycle -----------------------------------------------------------

    async def setup(self) -> None:
        """Prepare the collector (dependency checks, caches). Optional."""
        self._ready = True

    async def teardown(self) -> None:
        """Release resources held by the collector. Optional."""
        self._ready = False

    @property
    def ready(self) -> bool:
        """Whether :meth:`setup` completed successfully."""
        return self._ready

    # -- collection ----------------------------------------------------------

    @abstractmethod
    async def collect(self) -> CollectionResult:
        """Perform one collection and return its result.

        Implementations should report recoverable problems through the
        returned result's ``errors`` list rather than raising.
        """

    async def run(self) -> CollectionResult:
        """Execute :meth:`collect` with timeout and exception isolation.

        Always returns a :class:`CollectionResult`; never raises.
        """
        started = time.perf_counter()
        try:
            result = await asyncio.wait_for(self.collect(), timeout=self.timeout)
        except TimeoutError:
            result = CollectionResult(
                collector_name=self.name,
                errors=[f"collection timed out after {self.timeout:.0f}s"],
                ok=False,
            )
            self.failure_count += 1
            self.last_error = result.errors[0]
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("collector %s failed: %s", self.name, exc, exc_info=logger.isEnabledFor(logging.DEBUG))
            result = CollectionResult(
                collector_name=self.name,
                errors=[f"{type(exc).__name__}: {exc}"],
                ok=False,
            )
            self.failure_count += 1
            self.last_error = result.errors[0]
        else:
            if result.ok:
                self.last_error = None

        result.duration_ms = (time.perf_counter() - started) * 1000
        if not result.collector_name:
            result.collector_name = self.name
        self.last_result = result
        self.run_count += 1
        return result

    # -- helpers for subclasses ---------------------------------------------

    def result(self, **data: Any) -> CollectionResult:
        """Create a result pre-filled with this collector's name."""
        return CollectionResult(collector_name=self.name, data=data)

    def describe(self) -> dict[str, Any]:
        """Metadata describing this collector's runtime state."""
        return {
            "name": self.name,
            "interval": self.interval,
            "timeout": self.timeout,
            "ready": self.ready,
            "run_count": self.run_count,
            "failure_count": self.failure_count,
            "last_error": self.last_error,
            "last_run": self.last_result.timestamp.isoformat() if self.last_result else None,
            "last_duration_ms": round(self.last_result.duration_ms, 2) if self.last_result else None,
        }
