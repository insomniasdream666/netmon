"""Prompt templates and the builder that fills them.

The output contract is fixed: the model must return a single JSON object with
``diagnosis``, ``confidence``, ``fixes``, ``risks`` and ``verify`` keys. Every
template below ends with that contract so the parser in
:mod:`netmon.integrations.ollama` can rely on it.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

SYSTEM_PROMPT = (
    "You are a senior network engineer. Diagnose the issue and return ONLY valid JSON.\n"
    "Rules:\n"
    "1. Return a single JSON object; no prose, no markdown fences.\n"
    "2. Fixes must be shell commands that are safe to run on Kali Linux.\n"
    "3. Prefer read-only diagnostics before any state-changing command.\n"
    "4. Never invent interfaces, IP addresses or file paths not present in the context.\n"
    "5. If the context is insufficient, say so in the diagnosis and lower the confidence.\n"
    "6. Keep every command idempotent where possible; never suggest rebooting first.\n"
    "7. Confidence is an integer percentage (0-100) reflecting how certain you are."
)

USER_PROMPT_TEMPLATE = """Issue: {issue_type} - {issue_details}
Recent Metrics (15min): {metrics}
Network Config: {config}
Relevant Logs: {logs}
Similar Past Issues: {history}

Return JSON:
{{
  "diagnosis": "one-sentence root cause",
  "confidence": 0-100,
  "fixes": [{{"command": "cmd", "explanation": "why"}}],
  "risks": "what could go wrong",
  "verify": "command to confirm fix"
}}"""

CONCISE_TEMPLATE = """Issue: {issue_type} - {issue_details}
Evidence: {evidence}
Metrics: {metrics}
Config: {config}

Return JSON with keys diagnosis, confidence, fixes (max 2), risks, verify."""

DEEP_TEMPLATE = """You are diagnosing a network fault on a Kali Linux workstation.

## Reported issue
type: {issue_type}
severity: {severity}
details: {issue_details}
detected: {detected_at}

## Evidence collected by NetMon
{evidence}

## Metrics, last 15 minutes
{metrics}

## Current network configuration
{config}

## Relevant logs
{logs}

## Similar past issues and whether the fix worked
{history}

Return JSON:
{{
  "diagnosis": "one-sentence root cause",
  "confidence": 0-100,
  "fixes": [{{"command": "cmd", "explanation": "why"}}],
  "risks": "what could go wrong",
  "verify": "command to confirm fix"
}}"""

TEMPLATES: dict[str, str] = {
    "default": USER_PROMPT_TEMPLATE,
    "concise": CONCISE_TEMPLATE,
    "deep": DEEP_TEMPLATE,
}

FALLBACK_HISTORY = "none recorded"
FALLBACK_LOGS = "no relevant journal entries"
MAX_FIELD_CHARS = 4000


@dataclass(slots=True)
class PromptBuilder:
    """Render context into a prompt for the configured template.

    Args:
        template: Template name from :data:`TEMPLATES`.
        max_chars: Hard cap on the rendered prompt to protect small models.
    """

    template: str = "default"
    max_chars: int = 12000

    def render(
        self,
        *,
        issue_type: str,
        issue_details: str = "",
        severity: str = "warning",
        detected_at: str = "",
        evidence: Sequence[str] | None = None,
        metrics: Mapping[str, Any] | str | None = None,
        config: Mapping[str, Any] | str | None = None,
        logs: str | None = None,
        history: Sequence[Mapping[str, Any]] | str | None = None,
    ) -> str:
        """Build the user prompt.

        Structured values are JSON-encoded so the model sees stable field names
        rather than Python repr output.
        """
        prompt = self._template().format(
            issue_type=issue_type or "unknown",
            issue_details=_truncate(_describe(issue_details), 800),
            severity=severity or "warning",
            detected_at=detected_at or "now",
            evidence=_format_evidence(evidence),
            metrics=_format_block(metrics, default="no metrics available"),
            config=_format_block(config, default="network configuration unavailable"),
            logs=_truncate(str(logs).strip() if logs else FALLBACK_LOGS, MAX_FIELD_CHARS),
            history=_format_history(history),
        )
        if len(prompt) > self.max_chars:
            prompt = prompt[: self.max_chars] + "\n... (context truncated)"
        return prompt

    def system_prompt(self) -> str:
        """The system prompt sent with every request."""
        return SYSTEM_PROMPT

    def _template(self) -> str:
        return TEMPLATES.get(self.template, USER_PROMPT_TEMPLATE)


def _template() -> str:  # pragma: no cover - retained for backwards compatibility
    return USER_PROMPT_TEMPLATE


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _describe(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return str(value)


def _format_block(value: Mapping[str, Any] | str | None, *, default: str) -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip() or default
    if not value:
        return default
    try:
        text = json.dumps(value, default=str, indent=2, sort_keys=True)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        text = str(value)
    return _truncate(text, MAX_FIELD_CHARS)


def _format_evidence(evidence: Sequence[str] | None) -> str:
    if not evidence:
        return "none captured"
    return "\n".join(f"- {_truncate(str(item), 300)}" for item in list(evidence)[:20])


def _format_history(history: Sequence[Mapping[str, Any]] | str | None) -> str:
    if history is None:
        return FALLBACK_HISTORY
    if isinstance(history, str):
        return history.strip() or FALLBACK_HISTORY
    lines: list[str] = []
    for entry in list(history)[:5]:
        diagnosis = _truncate(str(entry.get("diagnosis", "")), 160)
        command = _truncate(str(entry.get("executed_command") or ""), 120)
        outcome = entry.get("execution_success")
        outcome_text = "worked" if outcome is True else "did not work" if outcome is False else "untested"
        lines.append(f"- {diagnosis} | fix: {command or 'n/a'} | outcome: {outcome_text}")
    return "\n".join(lines) if lines else FALLBACK_HISTORY


__all__ = [
    "CONCISE_TEMPLATE",
    "DEEP_TEMPLATE",
    "SYSTEM_PROMPT",
    "TEMPLATES",
    "USER_PROMPT_TEMPLATE",
    "PromptBuilder",
]
