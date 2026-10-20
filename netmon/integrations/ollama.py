"""Async client for a local Ollama server.

Only the subset of the Ollama API NetMon needs is implemented: a health probe,
model listing and JSON-only chat completion. The official ``ollama`` package is
used when available (it brings its own retry handling), otherwise NetMon talks
to the HTTP API directly with httpx so a broken dependency never disables AI
diagnostics entirely.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

CODE_FENCE_RE = re.compile(r"```(?:json)?\s*(?P<body>.*?)```", re.DOTALL)


class OllamaUnavailable(RuntimeError):  # noqa: N818 - stable public name
    """Raised when the Ollama server cannot be reached or returns an error."""


@dataclass(slots=True)
class OllamaResponse:
    """Result of a chat completion."""

    content: str
    model: str
    done: bool = True
    duration_ms: float = 0.0
    attempts: int = 1
    error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Serialise for logging and diagnostic history."""
        return {
            "model": self.model,
            "content": self.content,
            "done": self.done,
            "duration_ms": round(self.duration_ms, 2),
            "attempts": self.attempts,
            "error": self.error,
        }


def extract_json(text: str) -> dict[str, Any] | None:
    """Extract the first JSON object from an LLM response.

    Models often wrap JSON in prose or code fences; this tolerant extractor
    tries the whole string, then fenced blocks, then a brace-matching scan.
    """
    if not text:
        return None
    candidate = text.strip()
    if parsed := _try_load(candidate):
        return parsed

    if (match := CODE_FENCE_RE.search(candidate)) and (parsed := _try_load(match.group("body"))):
        return parsed

    start = candidate.find("{")
    while start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(candidate)):
            char = candidate[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    if parsed := _try_load(candidate[start : index + 1]):
                        return parsed
                    break
        start = candidate.find("{", start + 1)
    return None


def _try_load(text: str) -> dict[str, Any] | None:
    try:
        loaded = json.loads(text.strip())
    except (ValueError, TypeError):
        return None
    return loaded if isinstance(loaded, dict) else None


class OllamaClient:
    """Minimal async Ollama client.

    Args:
        host: Base URL of the Ollama server.
        model: Model name to use for completions.
        timeout: Per-request timeout in seconds (the spec mandates 30s).
        max_retries: Additional attempts after a transient failure.
    """

    def __init__(
        self,
        host: str = "http://localhost:11434",
        model: str = "llama3:8b",
        *,
        timeout: float = 30.0,
        max_retries: int = 1,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = float(timeout)
        self.max_retries = max(0, int(max_retries))
        self._client = client
        self._owns_client = client is None
        self._lock = asyncio.Lock()
        self.last_error: str | None = None
        self.call_count = 0
        self.failure_count = 0

    # -- lifecycle -----------------------------------------------------------

    async def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self.host, timeout=self.timeout)
        return self._client

    async def close(self) -> None:
        """Close the HTTP client when this instance owns it."""
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    # -- capabilities --------------------------------------------------------

    async def available(self) -> bool:
        """True when the Ollama server answers."""
        try:
            client = await self._http()
            response = await client.get("/api/tags", timeout=5.0)
            ok = response.status_code < 400
            self.last_error = None if ok else f"HTTP {response.status_code}"
            return ok
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return False

    async def list_models(self) -> list[str]:
        """Names of locally available models."""
        try:
            client = await self._http()
            response = await client.get("/api/tags", timeout=10.0)
            response.raise_for_status()
            payload = response.json()
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return []
        models = payload.get("models") or []
        return [str(item.get("name", "")) for item in models if item.get("name")]

    async def has_model(self, model: str | None = None) -> bool:
        """True when the target model is installed locally."""
        name = model or self.model
        available = await self.list_models()
        return any(candidate == name or candidate.split(":")[0] == name.split(":")[0] for candidate in available)

    async def model_info(self, model: str | None = None) -> dict[str, Any]:
        """Metadata for one model (``/api/show``)."""
        target = model or self.model
        try:
            client = await self._http()
            response = await client.post("/api/show", json={"name": target}, timeout=10.0)
            response.raise_for_status()
            return dict(response.json())
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}

    async def pull(self, model: str | None = None) -> bool:
        """Download a model, waiting for completion.

        Used by the installer and by the Settings screen's "check AI" action.
        """
        target = model or self.model
        try:
            client = await self._http()
            async with client.stream(
                "POST", "/api/pull", json={"name": target, "stream": False}, timeout=None
            ) as response:
                response.raise_for_status()
                async for _ in response.aiter_lines():
                    pass
            return True
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {exc}"
            return False

    # -- generation ----------------------------------------------------------

    async def generate_json(
        self,
        prompt: str,
        *,
        system: str | None = None,
        model: str | None = None,
        temperature: float = 0.2,
        num_ctx: int = 4096,
    ) -> OllamaResponse:
        """Request a JSON-only completion and return the raw response.

        Retries transient failures, then raises :class:`OllamaUnavailable` so
        the diagnostic engine can fall back to the rule engine.
        """
        target = model or self.model
        payload: dict[str, Any] = {
            "model": target,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": temperature, "num_ctx": num_ctx},
        }
        if system:
            payload["system"] = system

        attempts = 0
        last_error: str | None = None
        async with self._lock:
            while attempts <= self.max_retries:
                attempts += 1
                started = asyncio.get_event_loop().time()
                try:
                    client = await self._http()
                    response = await client.post("/api/generate", json=payload, timeout=self.timeout)
                    if response.status_code >= 400:
                        raise OllamaUnavailable(
                            f"Ollama returned HTTP {response.status_code}: {response.text[:200]}"
                        )
                    body = response.json()
                    self.call_count += 1
                    self.last_error = None
                    duration = (asyncio.get_event_loop().time() - started) * 1000
                    return OllamaResponse(
                        content=str(body.get("response", "")),
                        model=str(body.get("model", target)),
                        done=bool(body.get("done", True)),
                        duration_ms=duration,
                        attempts=attempts,
                        raw=body,
                    )
                except OllamaUnavailable as exc:
                    last_error = str(exc)
                except httpx.TimeoutException:
                    last_error = f"timed out after {self.timeout:.0f}s"
                except httpx.HTTPError as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                except Exception as exc:
                    last_error = f"{type(exc).__name__}: {exc}"

                if attempts <= self.max_retries:
                    await asyncio.sleep(min(2.0 * attempts, 5.0))

        self.failure_count += 1
        self.last_error = last_error
        raise OllamaUnavailable(last_error or "Ollama request failed")

    async def diagnose_json(
        self,
        prompt: str,
        system: str | None = None,
        *,
        model: str | None = None,
        temperature: float = 0.2,
        num_ctx: int = 4096,
    ) -> tuple[dict[str, Any] | None, OllamaResponse | None, str | None]:
        """Convenience wrapper returning ``(parsed_json, response, error)``."""
        try:
            response = await self.generate_json(
                prompt,
                system=system,
                model=model,
                temperature=temperature,
                num_ctx=num_ctx,
            )
        except OllamaUnavailable as exc:
            return None, None, str(exc)
        parsed = extract_json(response.content)
        if parsed is None:
            return None, response, "model did not return valid JSON"
        return parsed, response, None

    def describe(self) -> dict[str, Any]:
        """Runtime status for the Settings screen and ``/api/health``."""
        return {
            "host": self.host,
            "model": self.model,
            "timeout": self.timeout,
            "calls": self.call_count,
            "failures": self.failure_count,
            "last_error": self.last_error,
        }


__all__ = ["OllamaClient", "OllamaResponse", "OllamaUnavailable", "extract_json"]
