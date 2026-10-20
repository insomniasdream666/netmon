"""Systemd integration: service management and unit file rendering.

NetMon ships as a user service (``systemctl --user``) by default because the
network tools it calls mostly work unprivileged; a system service is available
for hosts that need root for SYN scans or raw sockets.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from netmon.utils.async_cmd import run_command

logger = logging.getLogger(__name__)

SERVICE_NAME = "netmon.service"
USER_UNIT_DIR = Path("~/.config/systemd/user").expanduser()
SYSTEM_UNIT_DIR = Path("/etc/systemd/system")

Scope = Literal["user", "system"]


@dataclass(slots=True)
class ServiceStatus:
    """Parsed ``systemctl show`` output for the NetMon unit."""

    unit: str = SERVICE_NAME
    active_state: str | None = None
    sub_state: str | None = None
    main_pid: int | None = None
    enabled: bool | None = None
    error: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def running(self) -> bool:
        """True when the unit is active."""
        return self.active_state == "active"

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the TUI/API."""
        return {
            "unit": self.unit,
            "active_state": self.active_state,
            "sub_state": self.sub_state,
            "main_pid": self.main_pid,
            "enabled": self.enabled,
            "running": self.running,
            "error": self.error,
        }


UNIT_TEMPLATE = """[Unit]
Description=NetMon - {tagline}
Documentation=file://{docs_path}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
WorkingDirectory={working_directory}
Environment=NETMON_ENV=production
Environment=PYTHONUNBUFFERED=1
{environment_lines}Restart=on-failure
RestartSec=5
# Metrics collection is I/O bound; keep the process polite on small hosts.
Nice=5
IOSchedulingClass=best-effort
IOSchedulingPriority=6
NoNewPrivileges={no_new_privileges}
{extra_service}

[Install]
WantedBy={wanted_by}
"""


class SystemdManager:
    """Install, control and inspect the NetMon systemd unit.

    Args:
        scope: ``user`` for a per-user service, ``system`` for a root service.
        unit_name: Override for the unit file name.
    """

    def __init__(self, scope: Scope = "user", *, unit_name: str = SERVICE_NAME) -> None:
        self.scope = scope
        self.unit_name = unit_name

    # -- paths and detection -------------------------------------------------

    @property
    def unit_dir(self) -> Path:
        """Directory holding the unit file for this scope."""
        return USER_UNIT_DIR if self.scope == "user" else SYSTEM_UNIT_DIR

    @property
    def unit_path(self) -> Path:
        """Full path of the unit file."""
        return self.unit_dir / self.unit_name

    def _systemctl(self, *args: str) -> list[str]:
        command = ["systemctl"]
        if self.scope == "user":
            command.append("--user")
        command.extend(args)
        return command

    async def available(self) -> bool:
        """True when systemd is usable for this scope."""
        result = await run_command(self._systemctl("is-system-running"), timeout=8.0)
        # "degraded" still means systemd is running and units can be managed.
        if result.error == "executable not found: systemctl":
            return False
        return result.stdout.strip() != "" or result.returncode in {0, 1, 3}

    # -- rendering and installation ------------------------------------------

    def render_unit(
        self,
        *,
        python_executable: str | None = None,
        arguments: str = "--headless",
        working_directory: str | None = None,
        env: dict[str, str] | None = None,
        no_new_privileges: bool = True,
        docs_path: str | None = None,
    ) -> str:
        """Render the unit file contents."""
        executable = python_executable or sys.executable
        workdir = working_directory or str(Path.cwd())
        exec_start = f"{executable} -m netmon {arguments}".strip()
        environment_lines = "".join(
            f"Environment={key}={value}\n" for key, value in sorted((env or {}).items())
        )
        extra_service = ""
        if self.scope == "system":
            extra_service = (
                "# Capabilities needed for SYN scans and raw sockets.\n"
                "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN\n"
                "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN\n"
            )
        return UNIT_TEMPLATE.format(
            tagline="See your network. Fix it fast.",
            docs_path=docs_path or str(Path(workdir) / "docs"),
            exec_start=exec_start,
            working_directory=workdir,
            environment_lines=environment_lines,
            no_new_privileges=str(no_new_privileges).lower(),
            extra_service=extra_service,
            wanted_by="default.target" if self.scope == "user" else "multi-user.target",
        )

    def install_unit(self, content: str) -> Path:
        """Write the unit file and return its path."""
        self.unit_dir.mkdir(parents=True, exist_ok=True)
        self.unit_path.write_text(content)
        logger.info("wrote systemd unit to %s", self.unit_path)
        return self.unit_path

    async def reload_daemon(self) -> bool:
        """``systemctl daemon-reload``."""
        result = await run_command(self._systemctl("daemon-reload"), timeout=15.0)
        return result.ok

    async def enable(self, *, now: bool = True) -> tuple[bool, str]:
        """Enable (and optionally start) the unit."""
        args = ["enable"]
        if now:
            args.append("--now")
        args.append(self.unit_name)
        result = await run_command(self._systemctl(*args), timeout=30.0)
        return result.ok, (result.stderr or result.stdout).strip()

    async def start(self) -> tuple[bool, str]:
        """Start the unit."""
        result = await run_command(self._systemctl("start", self.unit_name), timeout=30.0)
        return result.ok, (result.stderr or result.stdout).strip()

    async def stop(self) -> tuple[bool, str]:
        """Stop the unit."""
        result = await run_command(self._systemctl("stop", self.unit_name), timeout=30.0)
        return result.ok, (result.stderr or result.stdout).strip()

    async def restart(self) -> tuple[bool, str]:
        """Restart the unit."""
        result = await run_command(self._systemctl("restart", self.unit_name), timeout=30.0)
        return result.ok, (result.stderr or result.stdout).strip()

    async def uninstall(self) -> bool:
        """Stop, disable and delete the unit file."""
        await run_command(self._systemctl("disable", "--now", self.unit_name), timeout=30.0)
        try:
            self.unit_path.unlink(missing_ok=True)
        except OSError as exc:  # pragma: no cover - permissions
            logger.warning("could not remove unit file: %s", exc)
            return False
        return await self.reload_daemon()

    # -- inspection ----------------------------------------------------------

    async def status(self) -> ServiceStatus:
        """Current state of the NetMon unit."""
        result = await run_command(
            self._systemctl(
                "show",
                self.unit_name,
                "-p",
                "ActiveState,SubState,MainPID",
                "--no-pager",
            ),
            timeout=10.0,
        )
        status = ServiceStatus(unit=self.unit_name)
        if not result.ok and not result.stdout:
            status.error = result.error or "systemctl show returned no output"
            return status

        for line in result.stdout.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            if key == "ActiveState":
                status.active_state = value
            elif key == "SubState":
                status.sub_state = value
            elif key == "MainPID":
                try:
                    status.main_pid = int(value)
                except ValueError:
                    status.main_pid = None

        enabled = await run_command(self._systemctl("is-enabled", self.unit_name), timeout=8.0)
        status.enabled = enabled.first_line() == "enabled"
        return status

    def logs_hint(self) -> str:
        """Command the user can run to follow NetMon's logs."""
        scope = "--user " if self.scope == "user" else ""
        return f"journalctl {scope}-u {self.unit_name} -f"

    def logrotate_config(self, log_path: str = "/var/log/netmon/netmon.log") -> str:
        """Render a logrotate stanza for headless deployments."""
        return (
            f"{log_path} {{\n"
            "    daily\n"
            "    rotate 14\n"
            "    compress\n"
            "    delaycompress\n"
            "    missingok\n"
            "    notifempty\n"
            "    create 0640 root root\n"
            "}\n"
        )


__all__ = ["SERVICE_NAME", "SYSTEM_UNIT_DIR", "USER_UNIT_DIR", "ServiceStatus", "SystemdManager"]
