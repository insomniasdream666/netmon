"""Unit tests for the diagnostic engine: rule fast path, AI merge, fallbacks
and the fix-execution confirmation gate."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from netmon.config.settings import NetMonConfig
from netmon.core.diagnostics.ai import AIFix, AIResult
from netmon.core.diagnostics.engine import DiagnosticEngine, build_engine
from netmon.core.diagnostics.rules import RuleEngine, RuleMatch
from netmon.core.health import HealthIssue
from netmon.storage.sqlite import SQLiteRepository, open_repository

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeGatherer:
    """Collects nothing; records that it was asked."""

    def __init__(self) -> None:
        self.calls = 0

    async def gather(self, issue: HealthIssue) -> dict[str, Any]:
        self.calls += 1
        return {
            "metrics": {"issue_metric": issue.metric, "issue_value": issue.value},
            "config": {"interfaces": {"eth0": {"state": "UP"}}},
            "logs": "systemd-resolved: timeout",
            "history": [{"diagnosis": "past fix", "execution_success": True}],
            "current_values": {},
        }

    def as_prompt_context(self, context: dict[str, Any]) -> dict[str, Any]:
        return {key: context.get(key) for key in ("metrics", "config", "logs", "history")}


class FakeRuleEngine:
    """Deterministic stand-in for :class:`RuleEngine`."""

    def __init__(self, match: RuleMatch | None) -> None:
        self.match_result = match
        self.calls = 0

    def match(self, issue: HealthIssue, context: Any = None) -> RuleMatch | None:
        self.calls += 1
        return self.match_result

    def coverage(self) -> dict[str, int]:
        return {}

    def describe(self) -> list[dict[str, str]]:
        return []


class FakeAIEngine:
    """Returns a canned :class:`AIResult`."""

    def __init__(self, result: AIResult | None = None, *, enabled: bool = True) -> None:
        self.result = result
        self.enabled = enabled
        self.calls = 0

    async def diagnose(self, issue: HealthIssue, context: Any = None) -> AIResult:
        self.calls += 1
        if self.result is not None:
            return self.result
        return AIResult(diagnosis="", confidence=0.0, error="no result configured")

    def describe(self) -> dict[str, Any]:
        return {"enabled": self.enabled}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_issue(**overrides: Any) -> HealthIssue:
    defaults: dict[str, Any] = {
        "issue_type": "dns_failure",
        "component": "dns",
        "message": "DNS resolution is failing for all configured resolvers",
        "severity": "critical",
        "details": {"component": "dns"},
        "metric": "connectivity.dns.success_rate",
        "value": 0.0,
        "threshold": 90.0,
        "evidence": ["success_rate=0%"],
        "suggested_checks": ["resolvectl status", "dig @8.8.8.8 example.com"],
    }
    defaults.update(overrides)
    return HealthIssue(**defaults)


def make_match(*, confidence: float = 90.0, fixes: list[dict[str, str]] | None = None) -> RuleMatch:
    return RuleMatch(
        rule_name="dns-failure",
        diagnosis="systemd-resolved is not answering queries.",
        confidence=confidence,
        fixes=fixes
        if fixes is not None
        else [{"command": "resolvectl status", "explanation": "inspect the resolver"}],
        risks="Flushing caches briefly interrupts resolution.",
        verify="resolvectl query example.com",
    )


async def open_engine(
    tmp_path: Path,
    *,
    match: RuleMatch | None,
    ai_result: AIResult | None = None,
    ai_enabled: bool = True,
    threshold: float = 70.0,
) -> tuple[DiagnosticEngine, SQLiteRepository, FakeRuleEngine, FakeAIEngine]:
    repository = await open_repository(tmp_path / "diagnostics.db")
    rule_engine = FakeRuleEngine(match)
    ai_engine = FakeAIEngine(ai_result, enabled=ai_enabled)
    engine = DiagnosticEngine(
        rule_engine,  # type: ignore[arg-type]
        ai_engine,  # type: ignore[arg-type]
        FakeGatherer(),  # type: ignore[arg-type]
        repository,
        ai_confidence_threshold=threshold,
    )
    return engine, repository, rule_engine, ai_engine


# ---------------------------------------------------------------------------
# Rule fast path
# ---------------------------------------------------------------------------


async def test_confident_rule_match_skips_the_ai_engine(tmp_path: Path) -> None:
    engine, repository, _, ai_engine = await open_engine(
        tmp_path, match=make_match(confidence=92.0)
    )
    try:
        diagnosis = await engine.diagnose(make_issue())

        assert diagnosis.source == "rule"
        assert diagnosis.rule_name == "dns-failure"
        assert diagnosis.confidence == 92.0
        assert ai_engine.calls == 0, "a confident rule match must not call Ollama"
        assert engine.rule_diagnoses == 1 and engine.ai_diagnoses == 0

        assert diagnosis.history_id is not None
        record = await repository.get_diagnostic(diagnosis.history_id)
        assert record is not None
        assert record["source"] == "rule"
        assert record["diagnosis"] == diagnosis.diagnosis
    finally:
        await repository.close()


async def test_rule_fixes_are_indexed_and_validated(tmp_path: Path) -> None:
    match = make_match(
        fixes=[
            {"command": "resolvectl flush-caches", "explanation": "drop stale entries"},
            {"command": "   ", "explanation": "blank commands are dropped"},
            {
                "command": "systemctl restart systemd-resolved",
                "explanation": "restart the resolver",
                "requires_root": "true",
            },
        ]
    )
    engine, repository, _, _ = await open_engine(tmp_path, match=match)
    try:
        diagnosis = await engine.diagnose(make_issue())
        assert [fix.index for fix in diagnosis.fixes] == [0, 1]
        assert [fix.command for fix in diagnosis.fixes] == [
            "resolvectl flush-caches",
            "systemctl restart systemd-resolved",
        ]
        assert diagnosis.fixes[1].requires_root is True
        assert diagnosis.fix(1) is diagnosis.fixes[1]
        assert diagnosis.fix(9) is None
    finally:
        await repository.close()


# ---------------------------------------------------------------------------
# AI merge
# ---------------------------------------------------------------------------


async def test_ai_result_wins_over_low_confidence_rule(tmp_path: Path) -> None:
    ai_result = AIResult(
        diagnosis="The stub resolver upstream is misconfigured.",
        confidence=88.0,
        fixes=[AIFix(command="resolvectl flush-caches", explanation="clear the cache")],
        risks="None for a read-only check.",
        verify="dig example.com",
        model="llama3:8b",
    )
    engine, repository, _, ai_engine = await open_engine(
        tmp_path, match=make_match(confidence=40.0), ai_result=ai_result
    )
    try:
        diagnosis = await engine.diagnose(make_issue())

        assert ai_engine.calls == 1
        assert diagnosis.source == "ai"
        assert diagnosis.model == "llama3:8b"
        assert diagnosis.confidence == 88.0
        assert diagnosis.rule_name == "dns-failure", "the matched rule is kept as provenance"
        assert diagnosis.ai_attempted is True
        assert diagnosis.ai_error is None
        assert diagnosis.fixes[0].command == "resolvectl flush-caches"
        assert engine.ai_diagnoses == 1
    finally:
        await repository.close()


async def test_sudo_ai_fix_requires_root_and_is_flagged(tmp_path: Path) -> None:
    ai_result = AIResult(
        diagnosis="Restart the resolver.",
        confidence=75.0,
        fixes=[
            AIFix(command="systemctl restart systemd-resolved", requires_root=True),
            AIFix(command="rm -rf /var/cache/resolve", explanation="very bad idea"),
        ],
        model="llama3:8b",
    )
    engine, repository, _, _ = await open_engine(
        tmp_path, match=None, ai_result=ai_result
    )
    try:
        diagnosis = await engine.diagnose(make_issue())
        assert diagnosis.source == "ai"
        assert diagnosis.fixes[0].requires_root is True
        assert diagnosis.fixes[1].dangerous is True, "destructive commands must be flagged"
    finally:
        await repository.close()


async def test_ai_failure_falls_back_to_rule_and_counts(tmp_path: Path) -> None:
    ai_result = AIResult(diagnosis="", confidence=0.0, error="connection refused")
    engine, repository, _, ai_engine = await open_engine(
        tmp_path, match=make_match(confidence=55.0), ai_result=ai_result
    )
    try:
        diagnosis = await engine.diagnose(make_issue())

        assert ai_engine.calls == 1
        assert diagnosis.source == "rule"
        assert diagnosis.ai_attempted is True
        assert diagnosis.ai_error == "connection refused"
        assert engine.fallbacks == 1
    finally:
        await repository.close()


async def test_no_rule_and_disabled_ai_produces_fallback_diagnosis(tmp_path: Path) -> None:
    engine, repository, _, ai_engine = await open_engine(
        tmp_path, match=None, ai_enabled=False
    )
    try:
        diagnosis = await engine.diagnose(make_issue())

        assert ai_engine.calls == 0
        assert diagnosis.source == "fallback"
        assert diagnosis.confidence == 15.0
        assert diagnosis.ai_error == "AI unavailable or disabled"
        assert [fix.command for fix in diagnosis.fixes] == [
            "resolvectl status",
            "dig @8.8.8.8 example.com",
        ], "fallback fixes use the issue's suggested checks"
        assert engine.errors == 1
    finally:
        await repository.close()


async def test_use_ai_false_keeps_rule_path(tmp_path: Path) -> None:
    engine, repository, _, ai_engine = await open_engine(
        tmp_path, match=make_match(confidence=80.0)
    )
    try:
        diagnosis = await engine.diagnose(make_issue(), use_ai=False)
        assert diagnosis.source == "rule"
        assert ai_engine.calls == 0
    finally:
        await repository.close()


# ---------------------------------------------------------------------------
# Fix execution gate
# ---------------------------------------------------------------------------


async def test_execute_fix_refuses_without_confirmation(tmp_path: Path) -> None:
    engine, repository, _, _ = await open_engine(tmp_path, match=make_match())
    try:
        diagnosis = await engine.diagnose(make_issue())
        outcome = await engine.execute_fix(diagnosis, 0)

        assert outcome.executed is False
        assert outcome.success is False
        assert outcome.exit_code == -1
        assert outcome.blocked_reason is not None
        assert "confirmation" in outcome.blocked_reason.lower()

        record = await repository.get_diagnostic(diagnosis.history_id or 0)
        assert record is not None and record["execution_success"] is None
    finally:
        await repository.close()


async def test_execute_fix_unknown_index(tmp_path: Path) -> None:
    engine, repository, _, _ = await open_engine(tmp_path, match=make_match())
    try:
        diagnosis = await engine.diagnose(make_issue())
        outcome = await engine.execute_fix(diagnosis, 99, confirmed=True)
        assert outcome.executed is False
        assert outcome.blocked_reason == "unknown fix index"
    finally:
        await repository.close()


async def test_confirmed_fix_runs_and_updates_history(tmp_path: Path) -> None:
    match = make_match(
        fixes=[{"command": "true", "explanation": "harmless no-op used by the test"}]
    )
    match.verify = "true"
    engine, repository, _, _ = await open_engine(tmp_path, match=match)
    try:
        diagnosis = await engine.diagnose(make_issue())
        outcome = await engine.execute_fix(diagnosis, 0, confirmed=True)

        assert outcome.executed is True
        assert outcome.success is True
        assert outcome.exit_code == 0
        assert outcome.verify_success is True
        assert diagnosis.fixes[0].executed is True

        record = await repository.get_diagnostic(diagnosis.history_id or 0)
        assert record is not None
        assert record["execution_success"] is True
        assert record["executed_command"] == "true"
        assert record["resolution"] == "resolved", "successful fix + verify marks the issue resolved"
    finally:
        await repository.close()


# ---------------------------------------------------------------------------
# Wiring and serialisation
# ---------------------------------------------------------------------------


async def test_build_engine_wires_real_components(tmp_path: Path) -> None:
    repository = await open_repository(tmp_path / "wired.db")
    try:
        config = NetMonConfig()
        engine = build_engine(config, repository)

        assert isinstance(engine.rule_engine, RuleEngine)
        assert engine.ai_engine.describe()["model"] == config.ollama.model
        described = engine.describe()
        assert described["rules"], "the real rule set must be present"
        assert "coverage" in described
    finally:
        await repository.close()


async def test_diagnosis_serialisation_round_trip(tmp_path: Path) -> None:
    engine, repository, _, _ = await open_engine(tmp_path, match=make_match(confidence=85.0))
    try:
        diagnosis = await engine.diagnose(make_issue())
        payload = diagnosis.to_dict()

        assert payload["state"] == "ok"
        assert payload["issue_type"] == "dns_failure"
        assert payload["severity"] == "critical"
        assert payload["source"] == "rule"
        assert payload["fixes"][0]["command"] == "resolvectl status"
        assert payload["created_at"]

        low = diagnosis.confidence
        diagnosis.confidence = 30.0
        assert diagnosis.to_dict()["state"] == "unknown"
        diagnosis.confidence = low
    finally:
        await repository.close()
