"""Async subprocess helpers used by every collector and integration.

Every external command in NetMon goes through :func:`run_command` so that
subprocess execution is consistently non-blocking, time-bounded and
shell-free (commands are passed as argument lists, never as shell strings).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shlex
from collections.abc import Sequence
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15.0


@dataclass(slots=True)
class CommandResult:
    """Outcome of a subprocess invocation.

    Attributes:
        command: The argv that was executed, joined for display.
        returncode: Process exit status, or ``-1`` when it never started.
        stdout: Captured standard output.
        stderr: Captured standard error.
        duration_ms: Wall-clock execution time in milliseconds.
        timed_out: True when the process was killed for exceeding its timeout.
        error: Human readable error when the command could not run at all.
    """

    command: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    timed_out: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True when the command exited cleanly."""
        return self.returncode == 0 and not self.timed_out and self.error is None

    @property
    def lines(self) -> list[str]:
        """Non-empty stdout lines, stripped of trailing whitespace."""
        return [line.rstrip() for line in self.stdout.splitlines() if line.strip()]

    def first_line(self) -> str | None:
        """First non-empty stdout line, if any."""
        lines = self.lines
        return lines[0] if lines else None

    def as_dict(self) -> dict[str, object]:
        """Serialise for storage or API output."""
        return {
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": round(self.duration_ms, 2),
            "timed_out": self.timed_out,
            "error": self.error,
            "ok": self.ok,
        }


async def run_command(
    args: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    check: bool = False,
) -> CommandResult:
    """Run ``args`` asynchronously and capture its output.

    The process is never given a shell. On timeout the process is terminated
    and then killed if it refuses to exit, so a hung tool cannot pin a
    collector's task forever.

    Args:
        args: Argument vector, e.g. ``["ip", "-j", "addr", "show"]``.
        timeout: Seconds to wait before terminating the process.
        input_text: Optional text piped to the process' stdin.
        env: Extra environment variables merged over the current environment.
        cwd: Working directory for the child process.
        check: Raise :class:`CommandError` when the command fails.

    Returns:
        A :class:`CommandResult`; failures are reported in the result rather
        than raised unless ``check`` is set.
    """
    import os
    import time

    argv = list(args)
    display = " ".join(shlex.quote(a) for a in argv)
    started = time.perf_counter()

    if not argv:
        return CommandResult(command="", returncode=-1, error="empty command")

    child_env = None
    if env:
        child_env = {**os.environ, **env}

    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if input_text is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=child_env,
            cwd=cwd,
        )
    except FileNotFoundError:
        return CommandResult(
            command=display,
            returncode=-1,
            error=f"executable not found: {argv[0]}",
            duration_ms=(time.perf_counter() - started) * 1000,
        )
    except PermissionError:
        return CommandResult(
            command=display,
            returncode=-1,
            error=f"permission denied: {argv[0]}",
            duration_ms=(time.perf_counter() - started) * 1000,
        )
    except OSError as exc:  # pragma: no cover - defensive
        return CommandResult(
            command=display,
            returncode=-1,
            error=f"{type(exc).__name__}: {exc}",
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    timed_out = False
    try:
        raw_out, raw_err = await asyncio.wait_for(
            process.communicate(input_text.encode() if input_text is not None else None),
            timeout=timeout,
        )
    except TimeoutError:
        timed_out = True
        raw_out, raw_err = b"", b""
        with contextlib.suppress(ProcessLookupError):  # pragma: no cover - already gone
            process.terminate()
        try:
            raw_out, raw_err = await asyncio.wait_for(process.communicate(), timeout=2.0)
        except (TimeoutError, ProcessLookupError):
            with contextlib.suppress(ProcessLookupError):  # pragma: no cover
                process.kill()
            await process.wait()

    result = CommandResult(
        command=display,
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=raw_out.decode(errors="replace"),
        stderr=raw_err.decode(errors="replace"),
        duration_ms=(time.perf_counter() - started) * 1000,
        timed_out=timed_out,
    )
    if timed_out:
        result.error = f"timed out after {timeout:.0f}s"
    elif result.returncode != 0:
        result.error = result.stderr.strip().splitlines()[0] if result.stderr.strip() else None

    if check and not result.ok:
        raise CommandError(result)
    return result


class CommandError(RuntimeError):
    """Raised by :func:`run_command` when ``check=True`` and the command failed."""

    def __init__(self, result: CommandResult) -> None:
        detail = result.error or f"exit status {result.returncode}"
        super().__init__(f"command failed: {result.command} ({detail})")
        self.result = result


@dataclass(slots=True)
class CommandBatch:
    """Runs several commands concurrently with a shared timeout budget."""

    results: dict[str, CommandResult] = field(default_factory=dict)

    async def run_all(
        self,
        commands: dict[str, Sequence[str]],
        *,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> dict[str, CommandResult]:
        """Execute ``commands`` concurrently, keyed by the dict's keys."""
        names = list(commands)
        gathered = await asyncio.gather(
            *(run_command(commands[name], timeout=timeout) for name in names),
            return_exceptions=True,
        )
        for name, outcome in zip(names, gathered, strict=True):
            if isinstance(outcome, BaseException):
                self.results[name] = CommandResult(
                    command=" ".join(commands[name]),
                    returncode=-1,
                    error=f"{type(outcome).__name__}: {outcome}",
                )
            else:
                self.results[name] = outcome
        return self.results


async def run_commands(
    commands: dict[str, Sequence[str]],
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, CommandResult]:
    """Convenience wrapper around :class:`CommandBatch`."""
    return await CommandBatch().run_all(commands, timeout=timeout)


async def which(program: str) -> str | None:
    """Return the absolute path of ``program`` if it is on ``PATH``."""
    result = await run_command(["which", program], timeout=5.0)
    if result.ok:
        return result.first_line()
    return None


async def run_shell(
    command: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    input_text: str | None = None,
) -> CommandResult:
    """Run a shell command line, supporting pipes and redirections.

    Only used for *user-confirmed* fix commands and verification snippets,
    which frequently need pipelines (for example ``openssl s_client ... |
    openssl x509``). Nothing in the collect path uses this helper - collectors
    always call :func:`run_command` with an argument vector.
    """
    import os
    import time

    started = time.perf_counter()
    if not command.strip():
        return CommandResult(command="", returncode=-1, error="empty command")

    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdin=asyncio.subprocess.PIPE if input_text is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=dict(os.environ),
        )
    except OSError as exc:  # pragma: no cover - defensive
        return CommandResult(command=command, returncode=-1, error=f"{type(exc).__name__}: {exc}")

    timed_out = False
    try:
        raw_out, raw_err = await asyncio.wait_for(
            process.communicate(input_text.encode() if input_text is not None else None),
            timeout=timeout,
        )
    except TimeoutError:
        timed_out = True
        with contextlib.suppress(ProcessLookupError):  # pragma: no cover
            process.terminate()
        try:
            raw_out, raw_err = await asyncio.wait_for(process.communicate(), timeout=2.0)
        except (TimeoutError, ProcessLookupError):
            with contextlib.suppress(ProcessLookupError):  # pragma: no cover
                process.kill()
            await process.wait()
            raw_out, raw_err = b"", b""

    result = CommandResult(
        command=command,
        returncode=process.returncode if process.returncode is not None else -1,
        stdout=raw_out.decode(errors="replace"),
        stderr=raw_err.decode(errors="replace"),
        duration_ms=(time.perf_counter() - started) * 1000,
        timed_out=timed_out,
    )
    if timed_out:
        result.error = f"timed out after {timeout:.0f}s"
    return result


async def tool_available(program: str) -> bool:
    """True when ``program`` can be executed on this host."""
    return await which(program) is not None
