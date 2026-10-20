"""Diagnostic engine: context gathering, rule+AI diagnosis and safe fix execution.

Flow for a single issue:

1. :class:`ContextGatherer` collects metrics (15 minute window), network
   configuration, relevant journal entries and similar past diagnoses.
2. :class:`~netmon.core.diagnostics.rules.RuleEngine` is tried first. Rules are
   instant and deterministic, so a confident match short-circuits the LLM.
3. When the rule path is absent or unsure, the AI path runs against the
   gathered context. Any failure degrades back to the rule verdict.
4. The outcome is recorded in SQLite so learning mode can feed successful past
   fixes back into future prompts.
5. Fixes are never executed automatically: :meth:`DiagnosticEngine.execute_fix`
   requires an explicit ``confirmed=True`` from the interface layer, logs the
   command, captures output and runs the model's verification command.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from netmon.config.settings import NetMonConfig
from netmon.core.diagnostics.ai import AIEngine, AIFix, AIResult
from netmon.core.diagnostics.prompts import PromptBuilder
from netmon.core.diagnostics.rules import RuleEngine, RuleMatch
from netmon.core.health import HealthIssue
from netmon.integrations.kali_tools import KaliTools
from netmon.storage.influx import InfluxRepository
from netmon.storage.sqlite import SQLiteRepository
from netmon.utils.async_cmd import CommandResult, run_shell
from netmon.utils.validation import ValidationError, is_dangerous_command, validate_fix_command

logger = logging.getLogger(__name__)

FIX_TIMEOUT = 60.0
VERIFY_TIMEOUT = 45.0
METRICS_WINDOW = "15m"
LOG_UNITS = ("NetworkManager", "systemd-resolved", "wpa_supplicant", "networking")


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(UTC)


@dataclass(slots=True)
class Fix:
    """A proposed remediation command."""

    index: int
    command: str
    explanation: str = ""
    requires_root: bool = False
    dangerous: bool = False
    executed: bool = False
    success: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the API, TUI and diagnostic history."""
        return {
            "index": self.index,
            "command": self.command,
            "explanation": self.explanation,
            "requires_root": self.requires_root,
            "dangerous": self.dangerous,
            "executed": self.executed,
            "success": self.success,
        }


@dataclass(slots=True)
class Diagnosis:
    """A complete diagnosis, from either the rule or the AI path."""

    issue: dict[str, Any]
    diagnosis: str
    confidence: float
    source: str = "rule"
    fixes: list[Fix] = field(default_factory=list)
    risks: str = ""
    verify: str = ""
    created_at: datetime = field(default_factory=utcnow)
    duration_ms: float = 0.0
    history_id: int | None = None
    ai_attempted: bool = False
    ai_error: str | None = None
    rule_name: str | None = None
    model: str | None = None

    @property
    def issue_type(self) -> str:
        """Issue type this diagnosis addresses."""
        return str(self.issue.get("issue_type", "unknown"))

    @property
    def severity(self) -> str:
        """Severity copied from the originating issue."""
        return str(self.issue.get("severity", "warning"))

    @property
    def state(self) -> str:
        """UI helper: how much trust the diagnosis deserves."""
        if self.confidence >= 80:
            return "ok"
        if self.confidence >= 55:
            return "warning"
        return "unknown"

    def fix(self, index: int) -> Fix | None:
        """Look up a fix by its displayed index."""
        for item in self.fixes:
            if item.index == index:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the API, TUI and history."""
        return {
            "id": self.history_id,
            "issue": self.issue,
            "issue_type": self.issue_type,
            "severity": self.severity,
            "diagnosis": self.diagnosis,
            "confidence": self.confidence,
            "state": self.state,
            "source": self.source,
            "fixes": [fix.to_dict() for fix in self.fixes],
            "risks": self.risks,
            "verify": self.verify,
            "created_at": self.created_at.isoformat(),
            "duration_ms": round(self.duration_ms, 2),
            "ai_attempted": self.ai_attempted,
            "ai_error": self.ai_error,
            "rule_name": self.rule_name,
            "model": self.model,
        }


@dataclass(slots=True)
class FixExecutionResult:
    """Outcome of running a proposed fix plus its verification step."""

    fix_index: int
    command: str
    executed: bool
    success: bool
    exit_code: int
    output: str = ""
    error: str | None = None
    duration_ms: float = 0.0
    verify_command: str = ""
    verify_output: str = ""
    verify_success: bool | None = None
    blocked_reason: str | None = None
    history_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the API and TUI."""
        return {
            "fix_index": self.fix_index,
            "command": self.command,
            "executed": self.executed,
            "success": self.success,
            "exit_code": self.exit_code,
            "output": self.output,
            "error": self.error,
            "duration_ms": round(self.duration_ms, 2),
            "verify_command": self.verify_command,
            "verify_output": self.verify_output,
            "verify_success": self.verify_success,
            "blocked_reason": self.blocked_reason,
            "history_id": self.history_id,
        }


class ContextGatherer:
    """Collects everything the AI prompt needs.

    Every source is optional: a missing InfluxDB, an unavailable journal or a
    host without ``ip`` simply produce smaller context rather than an error.
    """

    def __init__(
        self,
        config: NetMonConfig,
        *,
        kali_tools: KaliTools | None = None,
        influx: InfluxRepository | None = None,
        repository: SQLiteRepository | None = None,
        snapshot_provider: Any = None,
    ) -> None:
        self.config = config
        self.tools = kali_tools or KaliTools()
        self.influx = influx
        self.repository = repository
        self.snapshot_provider = snapshot_provider
        self._log_cache: tuple[float, str] | None = None

    async def gather(self, issue: HealthIssue) -> dict[str, Any]:
        """Build the prompt context for one issue."""
        metrics = await self._metrics(issue)
        network_config = await self._network_config()
        logs = await self._logs()
        history = await self._history(issue)
        return {
            "metrics": metrics,
            "config": network_config,
            "logs": logs,
            "history": history,
            "current_values": self._current_values(issue),
        }

    def as_prompt_context(self, context: Mapping[str, Any]) -> dict[str, Any]:
        """Reduce gathered context to the four keys the prompt template uses."""
        return {
            "metrics": context.get("metrics"),
            "config": context.get("config"),
            "logs": context.get("logs"),
            "history": context.get("history"),
        }

    # -- sources -------------------------------------------------------------

    def _current_values(self, issue: HealthIssue) -> dict[str, Any]:
        snapshot = self._snapshot()
        if snapshot is None:
            return {}
        component = str(issue.details.get("component") or "")
        payload: dict[str, Any] = {}
        if component:
            value = getattr(snapshot, component, None)
            if isinstance(value, Mapping):
                payload[component] = dict(value)
        return payload

    def _snapshot(self) -> Any:
        if callable(self.snapshot_provider):
            try:
                return self.snapshot_provider()
            except Exception as exc:
                logger.debug("snapshot provider failed: %s", exc)
        return None

    async def _metrics(self, issue: HealthIssue) -> dict[str, Any]:
        metrics: dict[str, Any] = {"issue_metric": issue.metric, "issue_value": issue.value}
        snapshot = self._snapshot()
        if snapshot is not None:
            connectivity = getattr(snapshot, "connectivity", {}) or {}
            ping = connectivity.get("ping") or {}
            metrics["ping"] = {
                str(target): {
                    "latency_ms": info.get("latency_ms"),
                    "packet_loss": info.get("packet_loss"),
                    "success": info.get("success"),
                }
                for target, info in list(ping.items())[:5]
                if isinstance(info, Mapping)
            }
            dns = connectivity.get("dns_health") or {}
            if dns:
                metrics["dns_health"] = dict(dns)
            bandwidth = getattr(snapshot, "bandwidth", {}) or {}
            interfaces = bandwidth.get("interfaces") or {}
            metrics["throughput"] = {
                str(name): {
                    "rx_bytes_per_sec": info.get("rx_bytes_per_sec"),
                    "tx_bytes_per_sec": info.get("tx_bytes_per_sec"),
                    "utilization_percent": info.get("utilization_percent"),
                }
                for name, info in list(interfaces.items())[:6]
                if isinstance(info, Mapping)
            }

        if self.influx is not None and issue.metric:
            measurement = _measurement_for(issue)
            if measurement:
                try:
                    series = await self.influx.series(measurement, _field_for(issue, measurement), range_token=METRICS_WINDOW, limit=60)
                    if series:
                        values = [value for _, value in series]
                        metrics["recent_series"] = {
                            "measurement": measurement,
                            "points": len(values),
                            "min": round(min(values), 3),
                            "max": round(max(values), 3),
                            "avg": round(sum(values) / len(values), 3),
                            "latest": round(values[-1], 3),
                        }
                except Exception as exc:
                    logger.debug("metric history unavailable: %s", exc)
        return metrics

    async def _network_config(self) -> dict[str, Any]:
        addresses = await self.tools.ip_addr_json()
        routes = await self.tools.ip_route_json()
        compact_addresses: dict[str, Any] = {}
        for entry in addresses:
            name = str(entry.get("ifname", "?"))
            compact_addresses[name] = {
                "state": entry.get("operstate"),
                "mtu": entry.get("mtu"),
                "addresses": [
                    f"{item.get('family')}:{item.get('local')}"
                    for item in (entry.get("addr_info") or [])
                    if item.get("local")
                ],
            }
        resolver = {}
        if self.config.monitoring.targets.dns:
            resolver = {
                "servers": await self.tools.dns_servers(),
                "configured_targets": list(self.config.monitoring.targets.dns)[:5],
            }
        return {
            "interfaces": compact_addresses,
            "routes": [
                {
                    "dst": route.get("dst"),
                    "gateway": route.get("gateway"),
                    "dev": route.get("dev"),
                    "metric": route.get("metric"),
                }
                for route in routes[:12]
            ],
            "dns": resolver,
            "ignored_interfaces": list(self.config.monitoring.ignored_interfaces),
        }

    async def _logs(self) -> str:
        now = time.monotonic()
        if self._log_cache is not None and now - self._log_cache[0] < 60.0:
            return self._log_cache[1]
        output = await self.tools.journalctl(LOG_UNITS, since="30 min ago", lines=120)
        trimmed = _trim_logs(output)
        self._log_cache = (now, trimmed)
        return trimmed

    async def _history(self, issue: HealthIssue) -> Any:
        if self.repository is None:
            return None
        if not self.config.ollama.learning_enabled:
            return None
        try:
            records = await self.repository.find_similar_diagnostics(
                issue.issue_type, limit=3, successful_only=False
            )
        except Exception as exc:
            logger.debug("history lookup failed: %s", exc)
            return None
        return [
            {
                "diagnosis": record.get("diagnosis"),
                "executed_command": record.get("executed_command"),
                "execution_success": record.get("execution_success"),
                "source": record.get("source"),
            }
            for record in records
        ]


class DiagnosticEngine:
    """Coordinates the rule path, the AI path and diagnostic history.

    Args:
        rule_engine: Deterministic fast path.
        ai_engine: Ollama-backed deep path.
        context_gatherer: Builds prompt context.
        history: SQLite repository used for recording and learning mode.
        ai_confidence_threshold: Rule matches at or above this confidence skip
            the model entirely.
    """

    def __init__(
        self,
        rule_engine: RuleEngine,
        ai_engine: AIEngine,
        context_gatherer: ContextGatherer,
        history: SQLiteRepository,
        *,
        ai_confidence_threshold: float = 70.0,
        config: NetMonConfig | None = None,
    ) -> None:
        self.rule_engine = rule_engine
        self.ai_engine = ai_engine
        self.context_gatherer = context_gatherer
        self.history = history
        self.ai_confidence_threshold = ai_confidence_threshold
        self.config = config
        self.diagnoses: int = 0
        self.ai_diagnoses: int = 0
        self.rule_diagnoses: int = 0
        self.fallbacks: int = 0
        self.errors: int = 0

    # -- diagnosis -----------------------------------------------------------

    async def diagnose(
        self,
        issue: HealthIssue,
        *,
        use_ai: bool = True,
        snapshot: Any = None,
    ) -> Diagnosis:
        """Diagnose one health issue, recording the outcome in history."""
        started = time.perf_counter()
        context = await self.context_gatherer.gather(issue)

        match = self.rule_engine.match(issue, self._rule_context(context, snapshot))
        ai_result: AIResult | None = None
        ai_error: str | None = None

        if match is not None and match.confidence >= self.ai_confidence_threshold:
            diagnosis = self._from_rule(issue, match, started)
        else:
            if use_ai and self.ai_engine.enabled:
                ai_result = await self.ai_engine.diagnose(
                    issue, self.context_gatherer.as_prompt_context(context)
                )
                ai_error = ai_result.error
            diagnosis = self._merge(issue, match, ai_result, ai_error, started)

        diagnosis.duration_ms = (time.perf_counter() - started) * 1000
        await self._record(diagnosis, match)
        self.diagnoses += 1
        return diagnosis

    def _rule_context(self, context: Mapping[str, Any], snapshot: Any) -> dict[str, Any]:
        merged: dict[str, Any] = dict(self.context_gatherer.as_prompt_context(context))
        if snapshot is not None:
            merged["interfaces"] = getattr(snapshot, "interfaces", {}) or {}
            merged["connectivity"] = getattr(snapshot, "connectivity", {}) or {}
            merged["wifi"] = getattr(snapshot, "wifi", {}) or {}
            merged["default_route"] = (getattr(snapshot, "interfaces", {}) or {}).get("default_route", {})
        return merged

    def _from_rule(self, issue: HealthIssue, match: RuleMatch, started: float) -> Diagnosis:
        self.rule_diagnoses += 1
        return Diagnosis(
            issue=issue.to_dict(),
            diagnosis=match.diagnosis,
            confidence=match.confidence,
            source="rule",
            fixes=self._build_fixes(match.fixes),
            risks=match.risks,
            verify=match.verify,
            rule_name=match.rule_name,
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    def _merge(
        self,
        issue: HealthIssue,
        match: RuleMatch | None,
        ai_result: AIResult | None,
        ai_error: str | None,
        started: float,
    ) -> Diagnosis:
        if ai_result is not None and ai_result.diagnosis and ai_result.confidence >= (match.confidence if match else 0.0):
            self.ai_diagnoses += 1
            return Diagnosis(
                issue=issue.to_dict(),
                diagnosis=ai_result.diagnosis,
                confidence=ai_result.confidence,
                source="ai",
                fixes=self._build_fixes([fix.to_dict() for fix in ai_result.fixes]),
                risks=ai_result.risks,
                verify=ai_result.verify,
                rule_name=match.rule_name if match else None,
                ai_attempted=True,
                ai_error=None,
                model=ai_result.model,
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        if match is not None:
            self.rule_diagnoses += 1
            if ai_result is not None or ai_error:
                self.fallbacks += 1
            return Diagnosis(
                issue=issue.to_dict(),
                diagnosis=match.diagnosis,
                confidence=match.confidence,
                source="rule",
                fixes=self._build_fixes(match.fixes),
                risks=match.risks,
                verify=match.verify,
                rule_name=match.rule_name,
                ai_attempted=ai_result is not None or bool(ai_error),
                ai_error=ai_error,
                duration_ms=(time.perf_counter() - started) * 1000,
            )

        self.errors += 1
        if ai_error:
            self.fallbacks += 1
        return Diagnosis(
            issue=issue.to_dict(),
            diagnosis=(
                "No rule matched this issue and the AI path did not produce a diagnosis. "
                "Collect a manual capture with the suggested checks below."
            ),
            confidence=15.0,
            source="fallback",
            fixes=self._build_fixes(_manual_fixes(issue)),
            risks="No remediation is proposed; gather more evidence before changing configuration.",
            verify="ss -tunap; ip -brief addr show; ip route show",
            ai_attempted=bool(ai_error),
            ai_error=ai_error or "AI unavailable or disabled",
            duration_ms=(time.perf_counter() - started) * 1000,
        )

    @staticmethod
    def _build_fixes(raw_fixes: Sequence[Mapping[str, Any]]) -> list[Fix]:
        fixes: list[Fix] = []
        for item in raw_fixes:
            command = str(item.get("command", "")).strip()
            if not command:
                continue
            try:
                command = validate_fix_command(command)
            except ValidationError:
                logger.warning("discarding invalid fix command: %r", command[:80])
                continue
            fixes.append(
                Fix(
                    index=len(fixes),
                    command=command,
                    explanation=str(item.get("explanation", "")),
                    requires_root=str(item.get("requires_root", "")).lower() in {"true", "1", "yes"}
                    or command.startswith("sudo "),
                    dangerous=is_dangerous_command(command),
                )
            )
        return fixes

    async def _record(self, diagnosis: Diagnosis, match: RuleMatch | None) -> None:
        try:
            diagnosis.history_id = await self.history.add_diagnostic(
                issue_type=diagnosis.issue_type,
                issue_details=str(diagnosis.issue.get("message", "")),
                severity=diagnosis.severity,
                diagnosis=diagnosis.diagnosis,
                confidence=diagnosis.confidence,
                source=diagnosis.source,
                fixes=[fix.to_dict() for fix in diagnosis.fixes],
                risks=diagnosis.risks,
                verify_command=diagnosis.verify,
                duration_ms=diagnosis.duration_ms,
                learning_note=match.explanation if match else None,
            )
        except Exception as exc:
            logger.warning("could not record diagnosis: %s", exc)

    # -- fix execution -------------------------------------------------------

    async def execute_fix(
        self,
        diagnosis: Diagnosis,
        fix_index: int,
        *,
        confirmed: bool = False,
        timeout: float = FIX_TIMEOUT,
    ) -> FixExecutionResult:
        """Run a proposed fix and its verification command.

        Refuses to run unless ``confirmed`` is True: NetMon never executes a
        fix silently, and the caller is responsible for having shown the user
        the exact command text.
        """
        fix = diagnosis.fix(fix_index)
        if fix is None:
            return FixExecutionResult(
                fix_index=fix_index,
                command="",
                executed=False,
                success=False,
                exit_code=-1,
                blocked_reason="unknown fix index",
            )

        if not confirmed:
            return FixExecutionResult(
                fix_index=fix_index,
                command=fix.command,
                executed=False,
                success=False,
                exit_code=-1,
                blocked_reason="confirmation required before executing a fix",
            )

        started = time.perf_counter()
        result = await run_shell(fix.command, timeout=timeout)
        duration = (time.perf_counter() - started) * 1000

        fix.executed = True
        fix.success = result.ok

        verify_output = ""
        verify_success: bool | None = None
        if diagnosis.verify:
            verify_result: CommandResult = await run_shell(diagnosis.verify, timeout=VERIFY_TIMEOUT)
            verify_output = _trim_output(verify_result.stdout or verify_result.stderr)
            verify_success = verify_result.ok

        outcome = FixExecutionResult(
            fix_index=fix_index,
            command=fix.command,
            executed=True,
            success=result.ok,
            exit_code=result.returncode,
            output=_trim_output(result.stdout or result.stderr),
            error=result.error,
            duration_ms=duration,
            verify_command=diagnosis.verify,
            verify_output=verify_output,
            verify_success=verify_success,
            history_id=diagnosis.history_id,
        )

        if diagnosis.history_id is not None:
            try:
                await self.history.record_fix_execution(
                    diagnosis.history_id,
                    command=fix.command,
                    output=outcome.output or (outcome.error or ""),
                    success=bool(result.ok and verify_success is not False),
                    resolution=(
                        "resolved"
                        if result.ok and verify_success is not False
                        else "attempted"
                        if result.ok
                        else "failed"
                    ),
                )
            except Exception as exc:
                logger.warning("could not record fix execution: %s", exc)

        return outcome

    async def verify_fix(self, command: str, *, timeout: float = VERIFY_TIMEOUT) -> FixExecutionResult:
        """Run an arbitrary verification command (web/TUI 'verify' button)."""
        result = await run_shell(command, timeout=timeout)
        return FixExecutionResult(
            fix_index=-1,
            command=command,
            executed=True,
            success=result.ok,
            exit_code=result.returncode,
            output=_trim_output(result.stdout or result.stderr),
            error=result.error,
            duration_ms=result.duration_ms,
            verify_command=command,
            verify_output=_trim_output(result.stdout or result.stderr),
            verify_success=result.ok,
        )

    # -- learning mode -------------------------------------------------------

    async def record_outcome(
        self,
        history_id: int,
        *,
        command: str,
        output: str,
        success: bool,
    ) -> bool:
        """Feed an observed outcome back into diagnostic history (learning mode)."""
        try:
            return await self.history.record_fix_execution(
                history_id,
                command=command,
                output=output,
                success=success,
                learning_note="outcome recorded manually",
            )
        except Exception as exc:
            logger.warning("could not record outcome: %s", exc)
            return False

    def describe(self) -> dict[str, Any]:
        """Runtime counters for the dashboard and diagnostics screen."""
        return {
            "diagnoses": self.diagnoses,
            "ai_diagnoses": self.ai_diagnoses,
            "rule_diagnoses": self.rule_diagnoses,
            "fallbacks": self.fallbacks,
            "errors": self.errors,
            "ai_confidence_threshold": self.ai_confidence_threshold,
            "rules": self.rule_engine.describe(),
            "coverage": self.rule_engine.coverage(),
            "ai": self.ai_engine.describe(),
        }


def _manual_fixes(issue: HealthIssue) -> list[dict[str, str]]:
    """Fallback suggestions when neither path produced a fix."""
    checks = list(issue.suggested_checks) or [
        "ip -brief addr show",
        "ip route show",
        "ss -tunap | head -20",
    ]
    return [
        {"command": command, "explanation": "Manual evidence gathering for this issue."}
        for command in checks[:4]
    ]


def _measurement_for(issue: HealthIssue) -> str | None:
    component = str(issue.details.get("component") or issue.component or "")
    mapping = {
        "interfaces": "interface_metrics",
        "connectivity": "connectivity",
        "dns": "connectivity",
        "bandwidth": "bandwidth",
        "wifi": "wifi",
        "certificates": "certificates",
        "connections": "connections",
    }
    return mapping.get(component)


def _field_for(issue: HealthIssue, measurement: str) -> str:
    metric = issue.metric or ""
    if metric:
        return metric.rsplit(".", 1)[-1]
    defaults = {
        "interface_metrics": "rx_bytes",
        "connectivity": "latency_ms",
        "bandwidth": "rx_bytes_per_sec",
        "wifi": "signal_dbm",
        "certificates": "days_remaining",
        "connections": "total",
    }
    return defaults.get(measurement, "value")


def _trim_output(text: str, limit: int = 4000) -> str:
    cleaned = (text or "").strip()
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[:limit] + "\n... (truncated)"


def _trim_logs(text: str, limit: int = 3000) -> str:
    if not text:
        return "no relevant journal entries"
    lines = [line for line in text.splitlines() if line.strip()]
    trimmed = "\n".join(lines[-60:])
    if len(trimmed) > limit:
        trimmed = trimmed[-limit:]
    return trimmed or "no relevant journal entries"


def build_engine(
    config: NetMonConfig,
    repository: SQLiteRepository,
    influx: InfluxRepository | None = None,
    *,
    kali_tools: KaliTools | None = None,
    snapshot_provider: Any = None,
) -> DiagnosticEngine:
    """Construct a fully wired :class:`DiagnosticEngine` from configuration."""
    tools = kali_tools or KaliTools()
    from netmon.integrations.ollama import OllamaClient

    client = OllamaClient(
        host=config.ollama.host,
        model=config.ollama.model,
        timeout=config.ollama.timeout,
        max_retries=config.ollama.max_retries,
    )
    prompt_builder = PromptBuilder(template=config.ollama.prompt_template)
    ai_engine = AIEngine(client, prompt_builder, settings=config.ollama)
    context_gatherer = ContextGatherer(
        config,
        kali_tools=tools,
        influx=influx,
        repository=repository,
        snapshot_provider=snapshot_provider,
    )
    return DiagnosticEngine(
        RuleEngine(),
        ai_engine,
        context_gatherer,
        repository,
        config=config,
    )


__all__ = [
    "AIFix",
    "ContextGatherer",
    "Diagnosis",
    "DiagnosticEngine",
    "Fix",
    "FixExecutionResult",
    "build_engine",
    "utcnow",
]
