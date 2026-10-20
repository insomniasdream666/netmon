"""NetMon command line interface and application entry point.

``python -m netmon`` starts the Textual TUI, ``--web`` serves the FastAPI
dashboard and ``--headless`` runs the monitor as a service with no UI. The
module also contains :func:`build_monitor`, the composition root that wires
storage, collectors, health checking, alerting and diagnostics together - both
interfaces reuse it so behaviour cannot drift between them.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from netmon import __brand_tagline__, __version__
from netmon.config.settings import (
    CONFIG_SECTIONS,
    NetMonConfig,
    get_by_path,
    load_config,
    save_config,
    set_by_path,
)
from netmon.storage.influx import InfluxRepository
from netmon.storage.sqlite import SQLiteRepository, open_repository
from netmon.utils.validation import ValidationError

LOGO_LINES = (
    "  |     |     |     |     |",
    "  |     |     |     |     |",
    "  |     |     |   | |     |",
    "  |   | | |   | | | |   | |",
    "N E T M O N",
)

logger = logging.getLogger(__name__)

cli = typer.Typer(
    name="netmon",
    help="Network monitoring and AI-assisted diagnostics for Kali Linux.",
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=False,
    invoke_without_command=True,
)


def logo_text() -> str:
    """Five-bar NetMon logo with the brand tagline."""
    bars = "\n".join(LOGO_LINES)
    return f"{bars}\n\n  {__brand_tagline__}"


def configure_logging(level: str, *, log_file: str | None = None) -> None:
    """Configure root logging with a machine-parseable format (no emoji)."""
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
    # Textual and uvicorn are chatty at debug level.
    logging.getLogger("textual").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


async def _sync_config_to_sqlite(config: NetMonConfig, repository: SQLiteRepository) -> NetMonConfig:
    """Seed the SQLite configuration mirror on first run.

    The mirror exists so the effective settings are inspectable next to the
    diagnostic and alert history. It is deliberately *not* re-applied on later
    startups: environment variables and ``config.yaml`` stay authoritative, so
    an edit made outside NetMon is never reverted by a stale copy. The
    environment-only InfluxDB token is never written to SQLite.
    """
    stored = await repository.get_config_map()
    if not stored:
        values = {
            key: value
            for key, value in config.flattened(redact_secrets=False).items()
            if key != "storage.influxdb.token"
        }
        await repository.set_config_values(values)
    elif stored.get("storage.influxdb.token"):
        # Older builds could persist the environment-only token; scrub it.
        await repository.delete_config_value("storage.influxdb.token")
    return config


async def build_monitor(
    config: NetMonConfig,
    *,
    repository: SQLiteRepository | None = None,
    influx: InfluxRepository | None = None,
) -> tuple[Any, SQLiteRepository, InfluxRepository]:
    """Wire the whole application together and return it with its storage.

    Args:
        config: Effective configuration.
        repository: Existing SQLite repository, or None to create one.
        influx: Existing InfluxDB repository, or None to create one.

    Returns:
        ``(monitor, repository, influx)`` so the caller can manage lifetimes.
    """
    from netmon.collectors import create_collectors
    from netmon.core.alerts import AlertManager
    from netmon.core.diagnostics.engine import build_engine
    from netmon.core.health import HealthChecker
    from netmon.core.monitor import MonitorManager
    from netmon.integrations.kali_tools import KaliTools

    repo = repository or await open_repository(config.storage.resolved_sqlite_path())
    config = await _sync_config_to_sqlite(config, repo)

    influx_repo = influx or InfluxRepository(config.storage.influxdb)
    tools = KaliTools()
    collectors = create_collectors(config, tools)
    ai_engine_holder: dict[str, Any] = {}

    engine = build_engine(config, repo, influx_repo, kali_tools=tools)

    alert_manager = AlertManager(config.alerts, repo)
    monitor = MonitorManager(
        config,
        collectors,
        HealthChecker(config.health),
        engine,
        alert_manager,
        repo,
        influx_repo,
    )
    # The diagnostics engine needs live state for context gathering.
    engine.context_gatherer.snapshot_provider = monitor.get_current_state
    ai_engine_holder["engine"] = engine
    return monitor, repo, influx_repo


def _resolve_config(config_path: Path | None, **overrides: Any) -> NetMonConfig:
    config = load_config(config_path)
    if overrides:
        merged = config.model_dump(mode="json")
        for key, value in overrides.items():
            if value is None:
                continue
            section, _, field = key.partition("__")
            if field:
                merged.setdefault(section, {})[field] = value
            else:
                merged[section] = value
        config = NetMonConfig(**merged)
    return config


def show_banner() -> None:
    """Print the branded banner to stdout."""
    typer.echo(logo_text())
    typer.echo("")
    typer.echo(f"  version {__version__}")
    typer.echo("")


# ---------------------------------------------------------------------------
# Main callback - runs the selected interface
# ---------------------------------------------------------------------------


@cli.callback()
def main(
    ctx: typer.Context,
    web: Annotated[bool, typer.Option("--web", help="Serve the web dashboard instead of the TUI.")] = False,
    headless: Annotated[bool, typer.Option("--headless", help="Run the monitor with no interface (daemon).")] = False,
    host: Annotated[str | None, typer.Option("--host", help="Override the web bind address.")] = None,
    port: Annotated[int | None, typer.Option("--port", help="Override the web port.")] = None,
    config_path: Annotated[Path | None, typer.Option("--config", help="Path to config.yaml.")] = None,
    log_level: Annotated[str | None, typer.Option("--log-level", help="DEBUG, INFO, WARNING, ERROR.")] = None,
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Disable the AI diagnosis path.")] = False,
    version: Annotated[bool, typer.Option("--version", help="Print the version and exit.")] = False,
) -> None:
    """Run NetMon (default), the web dashboard or the headless daemon."""
    if version:
        typer.echo(f"netmon {__version__} - {__brand_tagline__}")
        raise typer.Exit()

    if ctx.invoked_subcommand is not None:
        return

    config = _resolve_config(config_path)
    if host:
        config = set_by_path(config, "web.host", host)
    if port:
        config = set_by_path(config, "web.port", port)
    if log_level:
        config = set_by_path(config, "log_level", log_level.upper())
    if no_ai:
        config = set_by_path(config, "ollama.enabled", False)

    configure_logging(config.log_level)

    if web:
        run_web(config)
    elif headless:
        run_headless(config)
    else:
        run_tui(config)


# ---------------------------------------------------------------------------
# Interface runners
# ---------------------------------------------------------------------------


def run_tui(config: NetMonConfig) -> None:
    """Launch the Textual interface."""
    from netmon.core.monitor import MonitorManager
    from netmon.tui.app import NetMonApp

    async def _prepare() -> tuple[MonitorManager, SQLiteRepository, InfluxRepository]:
        return await build_monitor(config)

    monitor, repository, influx = asyncio.run(_prepare())
    app = NetMonApp(monitor, config, repository=repository)
    try:
        app.run()
    finally:
        asyncio.run(_shutdown(monitor, repository, influx))


async def _shutdown(
    monitor: Any,
    repository: SQLiteRepository,
    influx: InfluxRepository | None = None,
) -> None:
    try:
        await monitor.stop()
    finally:
        try:
            await repository.close()
        finally:
            if influx is not None:
                await influx.close()


def run_web(config: NetMonConfig) -> None:
    """Serve the FastAPI dashboard."""
    import uvicorn

    from netmon.web.auth import credentials_from_env
    from netmon.web.main import create_app

    try:
        credentials_from_env(config)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    async def _serve() -> None:
        # One event loop owns the monitor, the storage and the server so the
        # scheduler's tasks stay alive for as long as the dashboard is served.
        monitor, repository, influx = await build_monitor(config)
        application = create_app(monitor, config, repository=repository, influx=influx)
        server = uvicorn.Server(
            uvicorn.Config(
                application,
                host=config.web.host,
                port=config.web.port,
                log_level="warning",
            )
        )
        show_banner()
        typer.echo(f"  dashboard: http://{_display_host(config.web.host)}:{config.web.port}")
        typer.echo("")
        try:
            await monitor.start()
            await server.serve()
        finally:
            await _shutdown(monitor, repository, influx)

    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:  # pragma: no cover - interactive stop
        logger.info("netmon web stopped")


def run_headless(config: NetMonConfig) -> None:
    """Run the monitor forever with no interface (systemd friendly)."""
    configure_logging(config.log_level, log_file=None)

    async def _run() -> None:
        monitor, repository, influx = await build_monitor(config)
        await monitor.start()
        logger.info("netmon headless started: %s", __brand_tagline__)
        try:
            while True:
                await asyncio.sleep(30.0)
                state = monitor.get_current_state()
                logger.info(
                    "health=%.1f state=%s cycles=%d collectors=%d alerts=%d",
                    state.score,
                    state.state,
                    state.cycles,
                    len(state.collectors),
                    len(state.alerts),
                )
        except asyncio.CancelledError:
            pass
        finally:
            await monitor.stop()
            await repository.close()
            if influx is not None:
                await influx.close()

    show_banner()
    typer.echo("  headless mode: Ctrl+C to stop")
    typer.echo("")
    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        logger.info("netmon headless stopped")


def _display_host(host: str) -> str:
    return "localhost" if host in {"0.0.0.0", "::"} else host


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------


@cli.command("diagnose")
def diagnose_command(
    issue: Annotated[str | None, typer.Argument(help="Issue key or type; defaults to the most severe issue.")] = None,
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Use only the rule engine.")] = False,
    config_path: Annotated[Path | None, typer.Option("--config", help="Path to config.yaml.")] = None,
) -> None:
    """Run a diagnosis once and print the structured result."""
    config = _resolve_config(config_path)
    if no_ai:
        config = set_by_path(config, "ollama.enabled", False)
    configure_logging(config.log_level)

    async def _run() -> int:
        monitor, repository, influx = await build_monitor(config)
        try:
            await monitor.run_collection_cycle()
            result = await monitor.diagnose_issue(issue, use_ai=not no_ai)
            if result is None:
                typer.echo("No active issues detected; nothing to diagnose.")
                return 0
            payload = result.to_dict()
            typer.echo("")
            typer.echo(f"DIAGNOSIS   {payload['diagnosis']}")
            typer.echo(f"CONFIDENCE  {payload['confidence']:.0f}%  (source: {payload['source']})")
            if payload.get("ai_error"):
                typer.echo(f"AI NOTE     {payload['ai_error']}")
            typer.echo("")
            typer.echo("FIXES")
            for fix in payload["fixes"]:
                root = " [requires root]" if fix.get("requires_root") else ""
                danger = " [DANGEROUS]" if fix.get("dangerous") else ""
                typer.echo(f"  [{fix['index']}] {fix['command']}{root}{danger}")
                if fix.get("explanation"):
                    typer.echo(f"      {fix['explanation']}")
            typer.echo("")
            typer.echo(f"RISKS       {payload['risks'] or 'none reported'}")
            typer.echo(f"VERIFY      {payload['verify'] or 'n/a'}")
            typer.echo("")
            typer.echo("Fix commands are never executed automatically; run them yourself after review.")
            return 0
        finally:
            await monitor.stop()
            await repository.close()
            if influx is not None:
                await influx.close()

    raise typer.Exit(asyncio.run(_run()))


@cli.command("scan")
def scan_command(
    target: Annotated[str, typer.Argument(help="Target host or CIDR for the port scan.")] = "127.0.0.1",
    ports: Annotated[str, typer.Option("--ports", "-p", help="Port specification, e.g. 1-1024.")] = "1-1024",
    config_path: Annotated[Path | None, typer.Option("--config", help="Path to config.yaml.")] = None,
) -> None:
    """Run a port scan with the configured nmap wrapper."""
    from netmon.integrations.kali_tools import KaliTools

    config = _resolve_config(config_path)
    configure_logging(config.log_level)
    scan = config.monitoring.port_scan

    async def _run() -> int:
        tools = KaliTools()
        typer.echo(f"scanning {target} ports {ports} ({scan.protocol}) ...")
        result = await tools.nmap_scan(
            [target],
            ports=ports,
            protocol=scan.protocol,
            service_detection=scan.service_detection,
            arguments=scan.arguments,
        )
        if result.get("error"):
            typer.echo(f"error: {result['error']}")
            return 1
        for host in result.get("hosts", []):
            typer.echo("")
            typer.echo(f"{host.get('target')} ({host.get('hostname') or 'no hostname'}) state={host.get('state')}")
            for entry in host.get("open_ports", []):
                service = entry.get("service") or "unknown"
                version = " ".join(
                    part for part in (entry.get("product"), entry.get("version")) if part
                )
                typer.echo(f"  {entry['port']:>5}/{entry['protocol']:<4} {service:<12} {version}")
        typer.echo("")
        typer.echo(f"open ports: {result.get('total_open', 0)} (duration {result.get('duration_ms', 0):.0f} ms)")
        return 0

    raise typer.Exit(asyncio.run(_run()))


@cli.command("status")
def status_command(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON instead of text.")] = False,
    config_path: Annotated[Path | None, typer.Option("--config", help="Path to config.yaml.")] = None,
) -> None:
    """Collect once and print the current health summary."""
    config = _resolve_config(config_path)
    configure_logging("WARNING")

    async def _run() -> int:
        monitor, repository, influx = await build_monitor(config)
        try:
            await monitor.run_collection_cycle()
            state = monitor.get_current_state()
            payload = state.to_dict()
            if json_output:
                import json

                typer.echo(json.dumps(payload, indent=2, default=str))
                return 0

            typer.echo("")
            typer.echo(f"HOST        {state.hostname}")
            typer.echo(f"HEALTH      {state.score:.1f}% ({state.state})")
            typer.echo(f"CYCLES      {state.cycles}")
            influx_stats = payload.get("influx") or {}
            typer.echo(
                f"INFLUX      configured={influx_stats.get('configured')} "
                f"available={influx_stats.get('available')}"
            )
            typer.echo("")
            typer.echo("COMPONENTS")
            for component in (payload.get("health") or {}).get("components", []) or []:
                typer.echo(
                    f"  {component['component']:<14} {component['state']:<8} "
                    f"{component['score']:6.1f}  {component['message']}"
                )
            issues = payload.get("issues") or []
            typer.echo("")
            typer.echo(f"ISSUES ({len(issues)})")
            for issue in issues[:10]:
                typer.echo(f"  [{issue['severity']:<8}] {issue['message']}")
            return 0
        finally:
            await monitor.stop()
            await repository.close()
            if influx is not None:
                await influx.close()

    raise typer.Exit(asyncio.run(_run()))


@cli.command("doctor")
def doctor_command(
    config_path: Annotated[Path | None, typer.Option("--config", help="Path to config.yaml.")] = None,
) -> None:
    """Check that required tools, storage and the AI backend are usable."""
    from netmon.integrations.kali_tools import KaliTools
    from netmon.integrations.ollama import OllamaClient
    from netmon.integrations.systemd import SystemdManager

    config = _resolve_config(config_path)
    configure_logging("WARNING")

    async def _run() -> int:
        problems = 0
        typer.echo("")
        typer.echo("TOOLS")
        tools = KaliTools()
        status = tools.tool_status()
        required = {"ip", "ss", "ping"}
        for name, tool in status.items():
            marker = "ok " if tool.available else ("MISSING" if name in required else "absent")
            typer.echo(f"  {name:<12} {marker}")
            if name in required and not tool.available:
                problems += 1

        typer.echo("")
        typer.echo("STORAGE")
        try:
            repository = await open_repository(config.storage.resolved_sqlite_path())
            ok = await repository.ping()
            typer.echo(f"  sqlite       {'ok' if ok else 'unreachable'} ({config.storage.resolved_sqlite_path()})")
            await repository.close()
            if not ok:
                problems += 1
        except Exception as exc:
            typer.echo(f"  sqlite       error: {exc}")
            problems += 1

        influx = InfluxRepository(config.storage.influxdb)
        if not config.storage.influxdb.enabled:
            typer.echo("  influxdb     disabled in configuration")
        elif not influx.configured:
            typer.echo("  influxdb     no token configured (metrics stay in memory only)")
        else:
            available = await influx.ping()
            typer.echo(f"  influxdb     {'ok' if available else 'unreachable'} ({config.storage.influxdb.url})")
            if not available:
                typer.echo(f"               {influx.last_error or 'no detail'}")

        typer.echo("")
        typer.echo("AI")
        client = OllamaClient(
            host=config.ollama.host,
            model=config.ollama.model,
            timeout=config.ollama.timeout,
            max_retries=0,
        )
        try:
            available = await client.available()
            typer.echo(f"  ollama       {'ok' if available else 'unreachable'} ({config.ollama.host})")
            if available:
                models = await client.list_models()
                has_model = await client.has_model()
                typer.echo(f"  model        {config.ollama.model} {'present' if has_model else 'NOT pulled'}")
                if not has_model:
                    typer.echo(f"               available: {', '.join(models[:5]) or 'none'}")
                    typer.echo(f"               run: ollama pull {config.ollama.model}")
        finally:
            await client.close()

        typer.echo("")
        typer.echo("SERVICE")
        manager = SystemdManager("user")
        installed = manager.unit_path.exists()
        typer.echo(f"  unit         {'installed' if installed else 'not installed'} ({manager.unit_path})")
        if installed:
            service_status = await manager.status()
            typer.echo(f"  state        {service_status.active_state or 'unknown'}")

        typer.echo("")
        typer.echo(f"problems: {problems}")
        return 1 if problems else 0

    raise typer.Exit(asyncio.run(_run()))


config_cli = typer.Typer(help="Inspect and edit the NetMon configuration.", no_args_is_help=True)
cli.add_typer(config_cli, name="config")


@config_cli.command("show")
def config_show(
    reveal: Annotated[bool, typer.Option("--reveal", help="Show secret values.")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
    config_path: Annotated[Path | None, typer.Option("--config", help="Path to config.yaml.")] = None,
) -> None:
    """Print the effective configuration."""
    config = _resolve_config(config_path)
    if json_output:
        import json

        payload = config.to_dict()
        if not reveal:
            payload.get("storage", {}).get("influxdb", {}).pop("token", None)
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    for key, value in config.flattened(redact_secrets=not reveal).items():
        typer.echo(f"{key} = {value}")


@config_cli.command("get")
def config_get(
    key: Annotated[str, typer.Argument(help="Dotted key, e.g. web.port.")],
    config_path: Annotated[Path | None, typer.Option("--config", help="Path to config.yaml.")] = None,
) -> None:
    """Print a single configuration value."""
    config = _resolve_config(config_path)
    try:
        typer.echo(get_by_path(config, key))
    except KeyError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc


@config_cli.command("set")
def config_set(
    key: Annotated[str, typer.Argument(help="Dotted key, e.g. web.port.")],
    value: Annotated[str, typer.Argument(help="New value.")],
    config_path: Annotated[Path | None, typer.Option("--config", help="Path to config.yaml.")] = None,
) -> None:
    """Set a configuration value in config.yaml."""
    from netmon.utils.validation import parse_key_value

    config = _resolve_config(config_path)
    try:
        _, coerced = parse_key_value(f"{key}={value}")
        updated = set_by_path(config, key, coerced)
    except (ValidationError, KeyError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc
    path = save_config(updated, config_path)
    typer.echo(f"{key} = {coerced}  (written to {path})")


@config_cli.command("validate")
def config_validate(
    config_path: Annotated[Path | None, typer.Option("--config", help="Path to config.yaml.")] = None,
) -> None:
    """Validate the configuration file."""
    from pydantic import ValidationError as PydanticValidationError

    from netmon.config.settings import NetMonConfig as ConfigModel

    try:
        config = load_config(config_path)
        ConfigModel(**config.model_dump(mode="json"))
    except PydanticValidationError as exc:
        typer.echo(f"invalid configuration: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(f"configuration is valid (sections: {', '.join(CONFIG_SECTIONS)})")


@cli.command("service")
def service_command(
    action: Annotated[str, typer.Argument(help="install, uninstall, start, stop, restart, status.")],
    scope: Annotated[str, typer.Option("--scope", help="user or system.")] = "user",
    config_path: Annotated[Path | None, typer.Option("--config", help="Path to config.yaml.")] = None,
) -> None:
    """Manage the NetMon systemd service."""
    from netmon.integrations.systemd import SystemdManager

    if scope not in {"user", "system"}:
        typer.echo("error: scope must be 'user' or 'system'", err=True)
        raise typer.Exit(1)

    manager = SystemdManager(scope)  # type: ignore[arg-type]

    async def _run() -> int:
        if action == "install":
            project_root = Path(__file__).resolve().parent.parent
            content = manager.render_unit(
                working_directory=str(project_root),
                arguments="--headless",
                env={"NETMON_CONFIG_PATH": str(Path("~/.config/netmon/config.yaml").expanduser())},
            )
            manager.install_unit(content)
            await manager.reload_daemon()
            ok, message = await manager.enable(now=True)
            typer.echo(f"installed {manager.unit_path}")
            typer.echo(f"enable: {'ok' if ok else message}")
            typer.echo(f"logs: {manager.logs_hint()}")
            return 0 if ok else 1
        if action == "uninstall":
            ok = await manager.uninstall()
            typer.echo("removed" if ok else "removal failed (check permissions)")
            return 0 if ok else 1
        if action == "status":
            service_status = await manager.status()
            if service_status.error:
                typer.echo(f"error: {service_status.error}", err=True)
                return 1
            typer.echo(
                f"{service_status.unit}: {service_status.active_state}/{service_status.sub_state} "
                f"pid={service_status.main_pid} enabled={service_status.enabled}"
            )
            return 0
        if action in {"start", "stop", "restart"}:
            handler = getattr(manager, action)
            ok, message = await handler()
            typer.echo(f"{action}: {'ok' if ok else message}")
            return 0 if ok else 1
        typer.echo("error: action must be install, uninstall, start, stop, restart or status", err=True)
        return 1

    raise typer.Exit(asyncio.run(_run()))


@cli.command("version")
def version_command() -> None:
    """Print the NetMon version."""
    typer.echo(f"netmon {__version__}")


def run() -> None:
    """Console-script entry point (``netmon``)."""
    cli()


if __name__ == "__main__":  # pragma: no cover - module entry point
    cli()
