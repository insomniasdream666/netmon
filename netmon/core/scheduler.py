"""Async scheduler with per-task intervals, jitter and hard error isolation.

NetMon schedules every collector independently rather than running them in one
loop: a slow or failing collector must not delay the others, and each task must
survive its own exceptions. Tasks run immediately on start, then on their own
cadence with a small random jitter so many timers do not align on the same tick.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

TaskCallable = Callable[[], Awaitable[Any]]


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(UTC)


@dataclass
class ScheduledTask:
    """One recurring job."""

    name: str
    func: TaskCallable
    interval: float
    jitter: float = 0.1
    run_immediately: bool = True
    enabled: bool = True
    run_count: int = 0
    failure_count: int = 0
    consecutive_failures: int = 0
    last_error: str | None = None
    last_started: datetime | None = None
    last_finished: datetime | None = None
    last_duration_ms: float | None = None
    total_duration_ms: float = 0.0
    next_run_at: float | None = None
    _task: asyncio.Task[None] | None = field(default=None, repr=False)
    _wake: asyncio.Event | None = field(default=None, repr=False)

    def describe(self) -> dict[str, Any]:
        """Runtime state for the dashboard."""
        return {
            "name": self.name,
            "interval": self.interval,
            "enabled": self.enabled,
            "run_count": self.run_count,
            "failure_count": self.failure_count,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
            "last_started": self.last_started.isoformat() if self.last_started else None,
            "last_duration_ms": round(self.last_duration_ms, 2) if self.last_duration_ms else None,
            "avg_duration_ms": round(self.total_duration_ms / self.run_count, 2) if self.run_count else None,
        }


class Scheduler:
    """Runs async tasks at independent intervals.

    Args:
        jitter: Fraction of the interval used as random spread (0.1 = +/-10%).
        time_provider: Injectable clock, used by tests.
    """

    def __init__(self, *, jitter: float = 0.1, time_provider: Callable[[], float] = time.monotonic) -> None:
        self.jitter = jitter
        self._time = time_provider
        self._tasks: dict[str, ScheduledTask] = {}
        self._running = False
        self._started_at: datetime | None = None

    # -- registration --------------------------------------------------------

    def add(
        self,
        name: str,
        func: TaskCallable,
        interval: float,
        *,
        jitter: float | None = None,
        run_immediately: bool = True,
        enabled: bool = True,
    ) -> ScheduledTask:
        """Register a recurring task, replacing any task with the same name."""
        if interval <= 0:
            raise ValueError(f"interval for task {name!r} must be positive")
        task = ScheduledTask(
            name=name,
            func=func,
            interval=float(interval),
            jitter=self.jitter if jitter is None else jitter,
            run_immediately=run_immediately,
            enabled=enabled,
        )
        self._tasks[name] = task
        if self._running:
            self._spawn(task)
        return task

    def remove(self, name: str) -> bool:
        """Stop and forget a task."""
        task = self._tasks.pop(name, None)
        if task is None:
            return False
        if task._task is not None:
            task._task.cancel()
        return True

    def set_interval(self, name: str, interval: float) -> bool:
        """Change a task's interval at runtime (config hot reload)."""
        task = self._tasks.get(name)
        if task is None or interval <= 0:
            return False
        task.interval = float(interval)
        if task._wake is not None:
            task._wake.set()
        return True

    def enable(self, name: str, enabled: bool = True) -> bool:
        """Enable or pause a task."""
        task = self._tasks.get(name)
        if task is None:
            return False
        task.enabled = enabled
        if task._wake is not None:
            task._wake.set()
        return True

    def get(self, name: str) -> ScheduledTask | None:
        """Look up a task by name."""
        return self._tasks.get(name)

    @property
    def tasks(self) -> dict[str, ScheduledTask]:
        """All registered tasks keyed by name."""
        return dict(self._tasks)

    @property
    def running(self) -> bool:
        """True while the scheduler is active."""
        return self._running

    # -- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Start every registered task."""
        if self._running:
            return
        self._running = True
        self._started_at = utcnow()
        for task in self._tasks.values():
            self._spawn(task)
        logger.debug("scheduler started with %d task(s)", len(self._tasks))

    async def stop(self) -> None:
        """Cancel all tasks and wait for them to unwind."""
        self._running = False
        pending: list[asyncio.Task[None]] = []
        for task in self._tasks.values():
            if task._task is not None and not task._task.done():
                task._task.cancel()
                pending.append(task._task)
            task._task = None
            task._wake = None
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        logger.debug("scheduler stopped")

    def _spawn(self, task: ScheduledTask) -> None:
        task._wake = asyncio.Event()
        task.next_run_at = self._time() if task.run_immediately else self._time() + task.interval
        task._task = asyncio.create_task(self._loop(task), name=f"netmon:{task.name}")

    async def _loop(self, task: ScheduledTask) -> None:
        while self._running:
            try:
                if not task.enabled:
                    assert task._wake is not None
                    with contextlib.suppress(TimeoutError):
                        await asyncio.wait_for(task._wake.wait(), timeout=min(task.interval, 5.0))
                    task._wake.clear()
                    continue

                await self._execute(task)
                delay = self._next_delay(task)
                assert task._wake is not None
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(task._wake.wait(), timeout=delay)
                task._wake.clear()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("scheduler loop for %s recovered from: %s", task.name, exc)
                await asyncio.sleep(1.0)

    def _next_delay(self, task: ScheduledTask) -> float:
        spread = task.interval * task.jitter
        delay = task.interval + random.uniform(-spread, spread) if spread else task.interval
        # Hot-loop guard: never wait less than 100ms *unless* the task interval
        # itself is shorter, in which case the configured cadence wins.
        delay = max(min(0.1, task.interval), delay)
        task.next_run_at = self._time() + delay
        return delay

    async def _execute(self, task: ScheduledTask) -> bool:
        """Run a task once, isolating failures. Returns True on success."""
        started_monotonic = self._time()
        task.last_started = utcnow()
        try:
            await task.func()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            task.failure_count += 1
            task.consecutive_failures += 1
            task.last_error = f"{type(exc).__name__}: {exc}"
            logger.warning("scheduled task %s failed: %s", task.name, exc)
            success = False
        else:
            task.consecutive_failures = 0
            task.last_error = None
            success = True
        finally:
            duration = (self._time() - started_monotonic) * 1000
            task.run_count += 1
            task.last_duration_ms = duration
            task.total_duration_ms += duration
            task.last_finished = utcnow()
        return success

    async def run_once(self, name: str) -> bool:
        """Trigger a task immediately, outside its schedule."""
        task = self._tasks.get(name)
        if task is None:
            return False
        return await self._execute(task)

    async def run_all_now(self) -> dict[str, bool]:
        """Trigger every enabled task once, concurrently."""
        names = [name for name, task in self._tasks.items() if task.enabled]
        results = await asyncio.gather(
            *(self.run_once(name) for name in names), return_exceptions=True
        )
        return {
            name: (outcome if isinstance(outcome, bool) else False)
            for name, outcome in zip(names, results, strict=True)
        }

    # -- introspection -------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Aggregate scheduler state for the dashboard."""
        tasks = [task.describe() for task in self._tasks.values()]
        return {
            "running": self._running,
            "task_count": len(self._tasks),
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "total_runs": sum(task.run_count for task in self._tasks.values()),
            "total_failures": sum(task.failure_count for task in self._tasks.values()),
            "tasks": tasks,
        }


__all__ = ["ScheduledTask", "Scheduler"]
