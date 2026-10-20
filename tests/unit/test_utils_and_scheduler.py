"""Unit tests for the scheduler, utilities and Ollama response parsing."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC
from pathlib import Path

import pytest

from netmon.core.scheduler import Scheduler
from netmon.integrations.ollama import OllamaClient, OllamaUnavailable, extract_json
from netmon.utils.async_cmd import CommandResult, run_command, run_commands, run_shell, which
from netmon.utils.formatting import (
    format_ago,
    format_bytes,
    format_duration,
    format_latency,
    format_percent,
    format_rate,
    health_color,
    health_glyph,
    parse_range,
    relative_range_to_seconds,
    score_state,
    severity_rank,
    sparkline,
    truncate,
)
from netmon.utils.validation import (
    ValidationError,
    is_dangerous_command,
    parse_key_value,
    validate_dotted_key,
    validate_fix_command,
    validate_host_port,
    validate_interface_name,
    validate_ip,
    validate_port_spec,
    validate_url,
)

# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------


async def test_scheduler_runs_tasks_at_their_interval() -> None:
    scheduler = Scheduler(jitter=0.0)
    calls: list[str] = []

    async def tick() -> None:
        calls.append("tick")

    scheduler.add("tick", tick, 0.05)
    await scheduler.start()
    await asyncio.sleep(0.19)
    await scheduler.stop()

    assert len(calls) >= 3, f"expected several runs, saw {len(calls)}"
    task = scheduler.get("tick")
    assert task is not None and task.run_count >= 3
    assert task.last_duration_ms is not None
    assert scheduler.stats()["total_runs"] >= 3


async def test_scheduler_isolates_failures_and_keeps_running() -> None:
    scheduler = Scheduler(jitter=0.0)
    attempts: list[int] = []

    async def flaky() -> None:
        attempts.append(1)
        raise RuntimeError("boom")

    scheduler.add("flaky", flaky, 0.03)
    await scheduler.start()
    await asyncio.sleep(0.12)
    await scheduler.stop()

    task = scheduler.get("flaky")
    assert task is not None
    assert task.failure_count >= 2
    assert task.last_error is not None and "boom" in task.last_error
    assert len(attempts) >= 2, "a failing task keeps being scheduled"


async def test_scheduler_task_timeout_does_not_stop_loop() -> None:
    scheduler = Scheduler(jitter=0.0)
    finished: list[str] = []

    async def slow() -> None:
        await asyncio.sleep(0.5)
        finished.append("slow")

    scheduler.add("slow", slow, 0.02)
    await scheduler.start()
    await asyncio.sleep(0.1)
    await scheduler.stop()
    assert finished == [], "cancelled slow task must not complete after shutdown"


async def test_scheduler_enable_disable_and_interval_change() -> None:
    scheduler = Scheduler(jitter=0.0)
    calls: list[int] = []

    async def tick() -> None:
        calls.append(1)

    scheduler.add("tick", tick, 0.02)
    assert scheduler.enable("tick", False) is True
    await scheduler.start()
    await asyncio.sleep(0.08)
    count_while_disabled = len(calls)
    await scheduler.stop()
    assert count_while_disabled == 0

    assert scheduler.enable("tick", True) is True
    assert scheduler.set_interval("tick", 0.01) is True
    assert scheduler.set_interval("missing", 1.0) is False
    assert scheduler.get("tick").interval == 0.01  # type: ignore[union-attr]


async def test_scheduler_run_once_and_run_all_now() -> None:
    scheduler = Scheduler()
    calls: list[str] = []

    async def make(name: str):
        async def _job() -> None:
            calls.append(name)

        return _job

    scheduler.add("a", await make("a"), 60)
    scheduler.add("b", await make("b"), 60)

    assert await scheduler.run_once("a") is True
    assert await scheduler.run_once("missing") is False
    results = await scheduler.run_all_now()
    assert results == {"a": True, "b": True}
    assert calls == ["a", "a", "b"]


async def test_scheduler_rejects_invalid_interval() -> None:
    scheduler = Scheduler()

    async def noop() -> None:
        return None

    with pytest.raises(ValueError):
        scheduler.add("bad", noop, 0)


async def test_scheduler_remove() -> None:
    scheduler = Scheduler()

    async def noop() -> None:
        return None

    scheduler.add("x", noop, 5)
    assert scheduler.remove("x") is True
    assert scheduler.remove("x") is False
    assert scheduler.tasks == {}


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


async def test_run_command_success_and_failure() -> None:
    ok = await run_command(["echo", "hello world"])
    assert ok.ok and ok.returncode == 0
    assert ok.first_line() == "hello world"
    assert ok.duration_ms > 0

    missing = await run_command(["definitely-not-a-real-binary-xyz"])
    assert not missing.ok
    assert missing.error and "not found" in missing.error
    assert missing.returncode == -1


async def test_run_command_timeout_is_terminated() -> None:
    result = await run_command(["sleep", "5"], timeout=0.3)
    assert result.timed_out is True
    assert not result.ok
    assert result.error and "timed out" in result.error


async def test_run_command_check_raises() -> None:
    from netmon.utils.async_cmd import CommandError

    with pytest.raises(CommandError):
        await run_command(["false"], check=True)


async def test_run_commands_runs_concurrently() -> None:
    results = await run_commands({"a": ["echo", "a"], "b": ["echo", "b"]})
    assert set(results) == {"a", "b"}
    assert all(result.ok for result in results.values())


async def test_run_shell_supports_pipelines() -> None:
    result = await run_shell("echo 'latency 42ms' | grep -o '[0-9]*ms'")
    assert result.ok
    assert result.stdout.strip() == "42ms"

    empty = await run_shell("   ")
    assert not empty.ok and empty.error == "empty command"


async def test_command_result_serialisation() -> None:
    result = CommandResult(command="echo hi", returncode=0, stdout="hi\n", stderr="", duration_ms=1.234)
    payload = result.as_dict()
    assert payload["ok"] is True
    assert payload["duration_ms"] == 1.23
    assert result.lines == ["hi"]


async def test_which_finds_and_misses() -> None:
    assert await which("sh")
    assert await which("definitely-not-a-real-binary-xyz") is None


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "--"),
        (0, "0 B"),
        (999, "999 B"),
        (1024, "1.0 KiB"),
        (1536, "1.5 KiB"),
        (1024**3, "1.0 GiB"),
    ],
)
def test_format_bytes(value: float | None, expected: str) -> None:
    assert format_bytes(value) == expected


def test_format_rate_latency_percent_duration() -> None:
    assert format_rate(1024) == "1.0 KiB/s"
    assert format_rate(None) == "--"
    assert format_latency(12.34) == "12.3 ms"
    assert format_latency(150.0) == "150 ms"
    assert format_latency(1500.0) == "1.50 s"
    assert format_percent(93.456) == "93.5%"
    assert format_duration(45) == "45s"
    assert format_duration(125) == "2m 5s"
    assert format_duration(3700) == "1h 1m"
    assert format_duration(90000) == "1d 1h 0m"


def test_format_ago() -> None:
    from datetime import datetime, timedelta

    assert format_ago(None) == "never"
    assert format_ago(datetime.now(UTC)) == "just now"
    assert format_ago(datetime.now(UTC) - timedelta(seconds=30)) == "30s ago"
    assert format_ago(datetime.now(UTC) - timedelta(minutes=5)) == "5m ago"
    assert format_ago(datetime.now(UTC) - timedelta(hours=3)) == "3h ago"
    assert format_ago(datetime.now(UTC) - timedelta(days=2)) == "2d ago"


def test_health_glyphs_and_colors_follow_branding() -> None:
    assert health_glyph("ok") == "\u25cf"
    assert health_glyph("warning") == "\u25d0"
    assert health_glyph("critical") == "\u25cf"
    assert health_glyph("unknown") == "\u25cb"
    assert health_glyph("running") == "\u27f3"

    assert health_color("ok") == "#00D084"
    assert health_color("warning") == "#FFB800"
    assert health_color("critical") == "#FF4757"
    assert health_color("running") == "#00B4D8"
    assert health_color("mystery") == "#8B949E"


def test_severity_rank_and_score_state() -> None:
    assert severity_rank("critical") < severity_rank("warning") < severity_rank("info")
    assert score_state(95) == "ok"
    assert score_state(60) == "warning"
    assert score_state(20) == "critical"


def test_sparkline_and_truncate() -> None:
    line = sparkline([1, 2, 3, 4, 5])
    assert len(line) == 5
    assert sparkline([]) == ""
    assert sparkline([3, 3, 3]) == "\u2581\u2581\u2581"

    assert truncate("abcdefghij", 5) == "ab..."
    assert truncate("abc", 5) == "abc"
    assert truncate("abc", 0) == ""


def test_range_parsing() -> None:
    assert relative_range_to_seconds("15m") == 900
    assert relative_range_to_seconds("24h") == 86400
    assert relative_range_to_seconds("7d") == 604800
    assert relative_range_to_seconds("30s") == 30
    assert parse_range("1h").total_seconds() == 3600
    with pytest.raises(ValueError):
        relative_range_to_seconds("")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_validate_ip_network_host_and_port() -> None:
    assert validate_ip("192.168.1.10") == "192.168.1.10"
    with pytest.raises(ValidationError):
        validate_ip("192.168.1.300")
    assert validate_host_port("github.com:443") == ("github.com", 443)
    assert validate_host_port("[::1]:8080") == ("::1", 8080)
    with pytest.raises(ValidationError):
        validate_host_port("no-port")
    assert validate_port_spec("22,80,443") == "22,80,443"
    assert validate_port_spec("1-1024") == "1-1024"
    with pytest.raises(ValidationError):
        validate_port_spec("1024-1")
    with pytest.raises(ValidationError):
        validate_port_spec("abc")


def test_validate_interface_and_url_and_key() -> None:
    assert validate_interface_name("wlan0") == "wlan0"
    assert validate_interface_name("eth0.100") == "eth0.100"
    with pytest.raises(ValidationError):
        validate_interface_name("bad name")
    assert validate_url("https://ntfy.sh/topic") == "https://ntfy.sh/topic"
    with pytest.raises(ValidationError):
        validate_url("ftp://example.com")
    assert validate_dotted_key("web.port") == "web.port"
    with pytest.raises(ValidationError):
        validate_dotted_key("web..port")
    with pytest.raises(ValidationError):
        validate_dotted_key("other.field", allowed_roots=("web",))


def test_dangerous_command_detection_and_fix_validation() -> None:
    assert is_dangerous_command("rm -rf / --no-preserve-root")
    assert is_dangerous_command("mkfs.ext4 /dev/sda1")
    assert not is_dangerous_command("ip route show")

    assert validate_fix_command("  ip   route   show ") == "ip route show"
    with pytest.raises(ValidationError):
        validate_fix_command("   ")
    with pytest.raises(ValidationError):
        validate_fix_command("x" * 600)


def test_parse_key_value_coercion() -> None:
    assert parse_key_value("web.port=9090") == ("web.port", 9090)
    assert parse_key_value("ollama.timeout=45.5") == ("ollama.timeout", 45.5)
    assert parse_key_value("alerts.enabled=false") == ("alerts.enabled", False)
    assert parse_key_value("monitoring.targets.ping=1.1.1.1,8.8.8.8") == (
        "monitoring.targets.ping",
        ["1.1.1.1", "8.8.8.8"],
    )
    assert parse_key_value("web.host=0.0.0.0") == ("web.host", "0.0.0.0")
    with pytest.raises(ValidationError):
        parse_key_value("no-equals-sign")


# ---------------------------------------------------------------------------
# Ollama response parsing
# ---------------------------------------------------------------------------


def test_extract_json_handles_common_model_formats() -> None:
    assert extract_json('{"diagnosis": "ok"}') == {"diagnosis": "ok"}
    assert extract_json('Here you go:\n```json\n{"diagnosis": "fenced"}\n```') == {"diagnosis": "fenced"}
    assert extract_json('```\n{"diagnosis": "bare fence"}\n```') == {"diagnosis": "bare fence"}
    assert extract_json('Sure! {"diagnosis": "nested", "fixes": [{"command": "ip a"}]} hope that helps') == {
        "diagnosis": "nested",
        "fixes": [{"command": "ip a"}],
    }
    assert extract_json('{"broken": ') is None
    assert extract_json("") is None
    assert extract_json("[1, 2, 3]") is None


def test_extract_json_survives_braces_inside_strings() -> None:
    payload = {"diagnosis": "route {template} broken", "confidence": 70}
    text = f"result: {json.dumps(payload)}"
    assert extract_json(text) == payload


async def test_ollama_client_reports_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    client = OllamaClient(host="http://127.0.0.1:1", model="test", timeout=0.5, max_retries=0)
    try:
        assert await client.available() is False
        assert await client.list_models() == []
        with pytest.raises(OllamaUnavailable):
            await client.generate_json("prompt")
        assert client.failure_count == 1
        assert client.last_error
        assert client.describe()["failures"] == 1
    finally:
        await client.close()


async def test_ollama_client_parses_generate_response() -> None:
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": "llama3:8b"}]})
        if request.url.path == "/api/generate":
            body = json.loads(request.content)
            assert body["format"] == "json"
            assert body["options"]["temperature"] == 0.2
            return httpx.Response(
                200,
                json={
                    "model": "llama3:8b",
                    "response": '{"diagnosis": "dns broken", "confidence": 0.8, '
                    '"fixes": ["sudo resolvectl flush-caches", {"command": "dig google.com", "explanation": "test"}], '
                    '"risks": "none", "verify": "dig google.com"}',
                    "done": True,
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    http_client = httpx.AsyncClient(transport=transport, base_url="http://ollama.test")
    client = OllamaClient(
        host="http://ollama.test", model="llama3:8b", client=http_client, max_retries=0
    )
    try:
        assert await client.available() is True
        assert await client.has_model() is True

        payload, response, error = await client.diagnose_json("prompt", system="sys")
        assert error is None
        assert response is not None
        assert payload is not None and payload["diagnosis"] == "dns broken"
        assert client.call_count == 1
    finally:
        await http_client.aclose()


async def test_ollama_client_retries_then_succeeds() -> None:
    import httpx

    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) == 1:
            return httpx.Response(500, text="server error")
        return httpx.Response(200, json={"model": "m", "response": '{"diagnosis": "ok", "confidence": 50}'})

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://ollama.test")
    client = OllamaClient(host="http://ollama.test", model="m", client=http_client, max_retries=2)
    try:
        response = await client.generate_json("prompt")
        assert len(attempts) == 2
        assert response.attempts == 2
    finally:
        await http_client.aclose()


async def test_ollama_diagnose_json_reports_unparseable_output() -> None:
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"model": "m", "response": "I cannot answer that."})

    http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://ollama.test")
    client = OllamaClient(host="http://ollama.test", model="m", client=http_client, max_retries=0)
    try:
        payload, response, error = await client.diagnose_json("prompt")
        assert payload is None
        assert response is not None
        assert error == "model did not return valid JSON"
    finally:
        await http_client.aclose()


def test_ollama_client_describe() -> None:
    client = OllamaClient(host="http://localhost:11434/", model="llama3:8b", timeout=30)
    described = client.describe()
    assert described["host"] == "http://localhost:11434"
    assert described["model"] == "llama3:8b"
    assert described["timeout"] == 30.0


async def test_prompt_builder_renders_all_context_fields() -> None:
    from netmon.core.diagnostics.prompts import PromptBuilder

    # The "deep" template carries every context field (the default template
    # intentionally omits evidence/severity to stay small).
    builder = PromptBuilder(template="deep")
    prompt = builder.render(
        issue_type="dns_failure",
        issue_details="resolution failing",
        severity="critical",
        detected_at="2026-10-18T12:00:00+00:00",
        evidence=["failure_rate=100%", "resolver=127.0.0.53"],
        metrics={"latency_ms": 120.0},
        config={"interfaces": {"eth0": {"addresses": ["ipv4:10.0.0.5"]}}},
        logs="systemd-resolved: timeout",
        history=[{"diagnosis": "stub resolver stuck", "executed_command": "resolvectl flush-caches", "execution_success": True}],
    )
    assert "dns_failure" in prompt
    assert "critical" in prompt
    assert "2026-10-18T12:00:00+00:00" in prompt
    assert "failure_rate=100%" in prompt
    assert "latency_ms" in prompt
    assert "systemd-resolved: timeout" in prompt
    assert "resolvectl flush-caches" in prompt
    assert "worked" in prompt
    assert '"diagnosis"' in prompt
    assert builder.system_prompt().startswith("You are a senior network engineer")


def test_prompt_builder_falls_back_when_context_missing() -> None:
    from netmon.core.diagnostics.prompts import PromptBuilder

    prompt = PromptBuilder(template="concise").render(issue_type="unknown_issue")
    assert "unknown_issue" in prompt
    assert "no metrics available" in prompt
    assert "none captured" in prompt

    default_prompt = PromptBuilder().render(issue_type="unknown_issue")
    assert "none recorded" in default_prompt, "missing history must use the recorded fallback"
    assert "no relevant journal entries" in default_prompt


def test_prompt_builder_truncates_long_context() -> None:
    from netmon.core.diagnostics.prompts import PromptBuilder

    builder = PromptBuilder(max_chars=400)
    prompt = builder.render(issue_type="x", logs="y" * 5000)
    assert len(prompt) <= 400 + len("\n... (context truncated)")
    assert prompt.endswith("(context truncated)")


def test_templates_by_name() -> None:
    from netmon.core.diagnostics.prompts import TEMPLATES, PromptBuilder

    for name in TEMPLATES:
        rendered = PromptBuilder(template=name).render(issue_type="t")
        assert "diagnosis" in rendered


def test_sqlite_url_and_path_expansion(tmp_path: Path) -> None:
    from netmon.storage.sqlite import SQLiteRepository

    repository = SQLiteRepository(tmp_path / "sub" / "db.sqlite")
    assert repository.path.parent.exists()
