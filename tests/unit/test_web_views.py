"""Unit tests for web view helpers that do not need a running server."""

from __future__ import annotations

from pathlib import Path

from netmon.web.main import _history_diagnosis_view, templates

ROOT = Path(__file__).resolve().parents[2]


def test_history_diagnosis_view_maps_a_stored_record() -> None:
    record = {
        "id": 9,
        "issue_type": "latency_high",
        "issue_details": "1.1.1.1: 700.6 ms latency",
        "severity": "critical",
        "diagnosis": "Congestion on the uplink.",
        "confidence": 65.0,
        "source": "rule",
        "fixes": [
            {
                "index": 0,
                "command": "mtr --report 1.1.1.1",
                "explanation": "Find the slow hop.",
                "requires_root": False,
                "dangerous": False,
                "executed": True,
                "success": True,
            }
        ],
        "risks": "Read-only.",
        "verify_command": "ping -c 10 1.1.1.1",
        "execution_success": True,
        "duration_ms": 721.0,
        "created_at": "2026-10-20T00:29:09+00:00",
    }

    view = _history_diagnosis_view(record)

    assert view["id"] == 9
    assert view["issue_type"] == "latency_high"
    assert view["state"] == "ok", "a successful fix marks the recorded diagnosis resolved"
    assert view["confidence"] == 65.0
    assert view["verify"] == "ping -c 10 1.1.1.1"
    assert view["fixes"][0]["command"] == "mtr --report 1.1.1.1"
    assert view["fixes"][0]["executed"] is True
    assert view["fixes"][0]["success"] is True


def test_history_diagnosis_view_defaults_unknown_fields() -> None:
    view = _history_diagnosis_view({"id": 1, "severity": "warning"})

    assert view["issue_type"] == "unknown"
    assert view["confidence"] == 0.0
    assert view["fixes"] == []
    assert view["state"] == "warning"
    assert view["verify"] == ""


def test_setting_items_group_and_skip_secret() -> None:
    from netmon.config.settings import NetMonConfig
    from netmon.web.main import _setting_items

    sections = _setting_items(NetMonConfig())
    by_section = {name: {item["key"]: item for item in items} for name, items in sections}
    flat = {key: item for items in by_section.values() for key, item in items.items()}

    assert sections[0][0] == "general"
    assert "storage.influxdb.token" not in flat
    assert flat["debug"]["kind"] == "bool"
    assert flat["web.port"]["kind"] == "int"
    assert flat["tui.refresh_interval"]["kind"] == "float"
    assert flat["monitoring.targets.ping"]["kind"] == "json"
    assert flat["env"]["options"] == ("development", "production", "test")
    assert flat["web.auth"]["reserved"] is True


def test_alert_rule_payload_accepts_form_channel_string() -> None:
    from netmon.web.api.config import AlertRuleCreate

    payload = AlertRuleCreate(
        name="custom-latency",
        metric="connectivity.avg_latency_ms",
        channels="log, ntfy",
    )

    assert payload.channels == ["log", "ntfy"]
    assert payload.enabled is True


def test_alerts_events_fragment_updates_header_count() -> None:
    html = templates.env.get_template("alerts.html").render(
        fragment="events", unacknowledged=4, events=[]
    )

    assert 'id="unack-count"' in html
    assert 'hx-swap-oob="outerHTML"' in html
    assert "4 unacknowledged" in html


def test_web_assets_are_vendored_for_offline_use() -> None:
    base = (ROOT / "netmon/web/templates/base.html").read_text(encoding="utf-8")

    assert "unpkg.com" not in base
    assert "cdn.jsdelivr.net" not in base
    assert "/static/vendor/htmx.min.js" in base
    assert "/static/vendor/chart.umd.min.js" in base

    vendor = ROOT / "netmon/web/static/vendor"
    for name in ("htmx.min.js", "chart.umd.min.js", "HTMX-LICENSE.txt", "CHARTJS-LICENSE.md"):
        assert (vendor / name).stat().st_size > 500
