"""AI-assisted diagnosis via a local Ollama model.

The engine is a thin, defensive wrapper around :class:`OllamaClient`: it builds
the prompt from gathered context, enforces the JSON output contract, coerces
the model's response into NetMon's domain types and degrades to the rule engine
whenever the model is unavailable, slow or malformed.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from netmon.config.settings import OllamaSettings
from netmon.core.diagnostics.prompts import PromptBuilder
from netmon.core.health import HealthIssue
from netmon.integrations.ollama import OllamaClient, OllamaUnavailable

logger = logging.getLogger(__name__)

MAX_FIXES = 6
VALID_SEVERITIES = {"info", "warning", "critical"}


@dataclass(slots=True)
class AIFix:
    """A single command proposed by the model."""

    command: str
    explanation: str = ""
    requires_root: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the API and diagnostic history."""
        return {
            "command": self.command,
            "explanation": self.explanation,
            "requires_root": self.requires_root,
        }


@dataclass(slots=True)
class AIResult:
    """Structured output of one AI diagnosis."""

    diagnosis: str
    confidence: float
    fixes: list[AIFix] = field(default_factory=list)
    risks: str = ""
    verify: str = ""
    model: str = ""
    duration_ms: float = 0.0
    attempts: int = 1
    raw: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise for logging and history."""
        return {
            "diagnosis": self.diagnosis,
            "confidence": self.confidence,
            "fixes": [fix.to_dict() for fix in self.fixes],
            "risks": self.risks,
            "verify": self.verify,
            "model": self.model,
            "duration_ms": round(self.duration_ms, 2),
            "attempts": self.attempts,
            "error": self.error,
        }


def coerce_confidence(value: Any) -> float:
    """Coerce a model-reported confidence into 0-100.

    Models occasionally answer with a 0-1 float, a string percentage or a word;
    all of those are normalised rather than rejected.
    """
    if isinstance(value, str):
        text = value.strip().rstrip("%").strip()
        word_map = {"high": 80.0, "medium": 55.0, "low": 25.0, "certain": 95.0}
        if text.lower() in word_map:
            return word_map[text.lower()]
        try:
            value = float(text)
        except ValueError:
            return 50.0
    if isinstance(value, bool):
        return 50.0
    if isinstance(value, (int, float)):
        number = float(value)
        if 0 < number <= 1:
            return round(number * 100, 2)
        return max(0.0, min(100.0, round(number, 2)))
    return 50.0


def parse_fixes(payload: Any) -> list[AIFix]:
    """Parse the ``fixes`` field, which may be strings, dicts or nested lists."""
    fixes: list[AIFix] = []
    if not payload:
        return fixes
    if isinstance(payload, Mapping):
        payload = [payload]
    if isinstance(payload, str):
        payload = [payload]
    if not isinstance(payload, Sequence):
        return fixes

    for item in list(payload)[:MAX_FIXES]:
        if isinstance(item, str):
            command = item.strip()
            explanation = ""
        elif isinstance(item, Mapping):
            command = str(item.get("command") or item.get("cmd") or "").strip()
            explanation = str(item.get("explanation") or item.get("why") or "").strip()
        else:
            continue
        if not command:
            continue
        needs_root = isinstance(item, Mapping) and bool(item.get("requires_root"))
        if command.startswith("sudo "):
            needs_root = True
            command = command[len("sudo ") :]
        fixes.append(AIFix(command=command, explanation=explanation, requires_root=needs_root))
    return fixes


class AIEngine:
    """Runs the AI deep path of diagnosis.

    Args:
        client: Ollama client used for completions.
        prompt_builder: Renders issue + context into a prompt.
        settings: AI settings (model, temperature, enable/disable).
    """

    def __init__(
        self,
        client: OllamaClient,
        prompt_builder: PromptBuilder,
        *,
        settings: OllamaSettings | None = None,
    ) -> None:
        self.client = client
        self.prompt_builder = prompt_builder
        self.settings = settings
        self.call_count = 0
        self.failure_count = 0
        self.last_error: str | None = None

    @property
    def enabled(self) -> bool:
        """False when AI diagnosis is switched off in configuration."""
        return bool(self.settings.enabled) if self.settings else True

    async def available(self) -> bool:
        """True when the Ollama server responds and the model is present."""
        if not self.enabled:
            return False
        if not await self.client.available():
            return False
        return await self.client.has_model(self.settings.model if self.settings else None)

    async def diagnose(self, issue: HealthIssue, context: Mapping[str, Any]) -> AIResult:
        """Request a structured diagnosis for ``issue``.

        Never raises: unreachable servers, timeouts and malformed JSON all come
        back as an :class:`AIResult` with ``error`` set so the engine can fall
        back to the rule path.
        """
        if not self.enabled:
            return AIResult(diagnosis="", confidence=0.0, error="AI diagnostics disabled")

        prompt = self.prompt_builder.render(
            issue_type=issue.issue_type,
            issue_details=issue.message,
            severity=issue.severity,
            detected_at=issue.detected_at.isoformat(),
            evidence=issue.evidence,
            metrics=context.get("metrics"),
            config=context.get("config"),
            logs=context.get("logs"),
            history=context.get("history"),
        )
        model = self.settings.model if self.settings else None
        temperature = self.settings.temperature if self.settings else 0.2
        num_ctx = self.settings.keep_num_ctx if self.settings else 4096

        try:
            payload, response, error = await self.client.diagnose_json(
                prompt,
                system=self.prompt_builder.system_prompt(),
                model=model,
                temperature=temperature,
                num_ctx=num_ctx,
            )
        except OllamaUnavailable as exc:
            self.failure_count += 1
            self.last_error = str(exc)
            return AIResult(diagnosis="", confidence=0.0, error=str(exc))

        if payload is None:
            self.failure_count += 1
            self.last_error = error or "no parsed payload"
            raw_text = (response.content[:500] if response else "")
            return AIResult(
                diagnosis="",
                confidence=0.0,
                error=error or "model returned unparseable output",
                raw={"text": raw_text},
            )

        result = self._to_result(payload, response)
        self.call_count += 1
        self.last_error = None
        return result

    def _to_result(self, payload: Mapping[str, Any], response: Any) -> AIResult:
        diagnosis = str(payload.get("diagnosis") or payload.get("root_cause") or "").strip()
        confidence = coerce_confidence(payload.get("confidence", payload.get("score", 50)))
        fixes = parse_fixes(payload.get("fixes") or payload.get("commands"))
        risks = str(payload.get("risks") or payload.get("risk") or "").strip()
        verify = str(payload.get("verify") or payload.get("verification") or "").strip()
        if verify.startswith("sudo "):
            verify = verify[len("sudo ") :]

        if not diagnosis:
            diagnosis = "The model did not return a diagnosis."
            confidence = min(confidence, 20.0)

        return AIResult(
            diagnosis=diagnosis,
            confidence=confidence,
            fixes=fixes,
            risks=risks or "No risks reported by the model; review commands before running them.",
            verify=verify,
            model=getattr(response, "model", "") or "",
            duration_ms=float(getattr(response, "duration_ms", 0.0) or 0.0),
            attempts=int(getattr(response, "attempts", 1) or 1),
            raw={"parsed": dict(payload)},
        )

    def describe(self) -> dict[str, Any]:
        """Runtime status for the settings screen and API."""
        settings = self.settings
        return {
            "enabled": self.enabled,
            "model": settings.model if settings else self.client.model,
            "host": settings.host if settings else self.client.host,
            "temperature": settings.temperature if settings else None,
            "calls": self.call_count,
            "failures": self.failure_count,
            "last_error": self.last_error,
        }


__all__ = ["AIEngine", "AIFix", "AIResult", "coerce_confidence", "parse_fixes"]
