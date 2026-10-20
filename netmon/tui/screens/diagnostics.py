"""Diagnostics screen: issue list, structured diagnosis and guarded fix execution.

The screen mirrors the rule/AI diagnosis contract one-to-one: a diagnosis is
rendered as ``DIAGNOSIS`` / ``CONFIDENCE`` / ``FIXES`` / ``RISKS`` / ``VERIFY``
sections, and a fix is never executed without the operator confirming the exact
command in a modal dialog first.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, ClassVar

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Footer, LoadingIndicator, Static

from netmon.config.settings import NetMonConfig
from netmon.core.diagnostics.engine import Diagnosis, Fix, FixExecutionResult
from netmon.core.monitor import MonitorManager, SystemState
from netmon.tui.widgets.status_table import StatusTable
from netmon.utils.formatting import (
    BRAND_COLORS,
    format_ago,
    format_duration,
    health_color,
    health_glyph,
    severity_rank,
    truncate,
)

ISSUE_COLUMNS: tuple[str, ...] = ("Severity", "Component", "Issue", "Metric", "Detected")
FIX_COLUMNS: tuple[str, ...] = ("#", "Command", "Root", "Risk", "State")

__all__ = [
    "FIX_COLUMNS",
    "ISSUE_COLUMNS",
    "DiagnosticsScreen",
    "FixConfirmScreen",
    "render_diagnosis",
    "render_execution",
]


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse an ISO timestamp, tolerating ``None`` and malformed input."""
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _severity_cell(severity: str, *, text: str | None = None) -> Text:
    """A glyph-prefixed, severity-coloured table cell."""
    state = "critical" if severity in {"critical", "error"} else severity
    cell = Text()
    cell.append(f"{health_glyph(state)} ", style=health_color(state))
    cell.append(text if text is not None else severity, style=health_color(state))
    return cell


def _fix_state_cell(fix: Fix) -> Text:
    """Execution state cell for the fixes table."""
    if not fix.executed:
        return Text("pending", style=BRAND_COLORS["muted"])
    state = "ok" if fix.success else "critical"
    cell = Text()
    cell.append(f"{health_glyph(state)} ", style=health_color(state))
    cell.append("executed" if fix.success else "failed", style=health_color(state))
    return cell


def render_diagnosis(diagnosis: Diagnosis) -> Text:
    """Render a :class:`Diagnosis` in the fixed section layout used by the TUI."""
    issue = diagnosis.issue if isinstance(diagnosis.issue, Mapping) else {}
    severity = str(issue.get("severity") or diagnosis.severity)
    body = Text()

    body.append(f"{health_glyph(severity)} ", style=f"bold {health_color(severity)}")
    body.append(diagnosis.issue_type, style="bold")
    body.append("   ")
    body.append(str(issue.get("message") or "no issue message"), style=BRAND_COLORS["text"])
    body.append("\n")

    meta = [
        f"component {issue.get('component', 'unknown')}",
        f"severity {severity}",
        f"source {diagnosis.source}",
        f"duration {diagnosis.duration_ms:.0f} ms",
        f"recorded {format_ago(diagnosis.created_at)}",
    ]
    if diagnosis.rule_name:
        meta.append(f"rule {diagnosis.rule_name}")
    if diagnosis.model:
        meta.append(f"model {diagnosis.model}")
    body.append("   ".join(meta), style=BRAND_COLORS["muted"])

    body.append("\n\nDIAGNOSIS\n", style=f"bold {BRAND_COLORS['info']}")
    body.append(
        f"  {diagnosis.diagnosis.strip() or 'no diagnosis text'}\n", style=BRAND_COLORS["text"]
    )

    body.append("\nCONFIDENCE\n", style=f"bold {BRAND_COLORS['info']}")
    confidence_state = diagnosis.state
    body.append(f"  {diagnosis.confidence:.0f}%", style=f"bold {health_color(confidence_state)}")
    body.append(f"   {confidence_state}", style=health_color(confidence_state))
    if diagnosis.ai_attempted:
        body.append("   ai attempted", style=BRAND_COLORS["muted"])
    if diagnosis.ai_error:
        body.append(
            f"   ai error: {truncate(diagnosis.ai_error, 70)}", style=BRAND_COLORS["warning"]
        )
    body.append("\n")

    body.append("\nFIXES\n", style=f"bold {BRAND_COLORS['info']}")
    if diagnosis.fixes:
        for fix in diagnosis.fixes:
            flags: list[str] = []
            if fix.requires_root:
                flags.append("root required")
            if fix.dangerous:
                flags.append("dangerous")
            if fix.executed:
                flags.append("executed" if fix.success else "executed (failed)")
            body.append(f"  [{fix.index}] ", style=f"bold {BRAND_COLORS['info']}")
            body.append(f"{fix.command}\n", style=BRAND_COLORS["text"])
            if fix.explanation:
                body.append(f"      {fix.explanation}\n", style=BRAND_COLORS["muted"])
            if flags:
                body.append(f"      {', '.join(flags)}\n", style=BRAND_COLORS["warning"])
    else:
        body.append("  no remediation commands were proposed\n", style=BRAND_COLORS["muted"])

    body.append("\nRISKS\n", style=f"bold {BRAND_COLORS['info']}")
    body.append(f"  {diagnosis.risks.strip() or 'none recorded'}\n", style=BRAND_COLORS["text"])

    body.append("\nVERIFY\n", style=f"bold {BRAND_COLORS['info']}")
    body.append(
        f"  {diagnosis.verify.strip() or 'no verification command supplied'}\n",
        style=BRAND_COLORS["text"],
    )
    return body


def render_execution(result: FixExecutionResult) -> Text:
    """Render a :class:`FixExecutionResult` including its verification step."""
    body = Text()
    outcome_state = "ok" if result.success else "critical"
    body.append(f"{health_glyph(outcome_state)} ", style=f"bold {health_color(outcome_state)}")
    body.append("EXECUTION RESULT", style="bold")
    body.append(
        f"   exit {result.exit_code}   {format_duration(result.duration_ms / 1000)}\n",
        style=BRAND_COLORS["muted"],
    )
    body.append(f"  command  {result.command or '--'}\n", style=BRAND_COLORS["text"])
    if result.blocked_reason:
        body.append(f"  blocked  {result.blocked_reason}\n", style=f"bold {BRAND_COLORS['warning']}")
    body.append(
        f"  executed {'yes' if result.executed else 'no'}   "
        f"success {'yes' if result.success else 'no'}\n",
        style=BRAND_COLORS["text"],
    )
    if result.error:
        body.append(f"  error    {result.error}\n", style=BRAND_COLORS["critical"])

    body.append("\nOUTPUT\n", style=f"bold {BRAND_COLORS['info']}")
    output = (result.output or "").strip()
    if output:
        for line in output.splitlines()[:40]:
            body.append(f"  {line}\n", style=BRAND_COLORS["text"])
    else:
        body.append("  no output captured\n", style=BRAND_COLORS["muted"])

    body.append("\nVERIFY\n", style=f"bold {BRAND_COLORS['info']}")
    if not result.verify_command:
        body.append("  no verification command supplied\n", style=BRAND_COLORS["muted"])
        return body

    verify_state = (
        "ok" if result.verify_success else "critical" if result.verify_success is False else "unknown"
    )
    body.append(f"  {health_glyph(verify_state)} ", style=health_color(verify_state))
    body.append(f"{result.verify_command}\n", style=BRAND_COLORS["text"])
    verify_output = (result.verify_output or "").strip()
    if verify_output:
        for line in verify_output.splitlines()[:40]:
            body.append(f"      {line}\n", style=BRAND_COLORS["text"])
    else:
        body.append("      no verification output\n", style=BRAND_COLORS["muted"])
    return body


class FixConfirmScreen(ModalScreen[bool]):
    """Modal confirmation showing the exact command before it is executed.

    The modal never executes anything itself: it dismisses with ``True`` only
    when the operator explicitly confirms, and the caller then runs the fix.

    Args:
        fix: The proposed fix.
        diagnosis: Diagnosis the fix belongs to (used for the verify hint).
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "cancel", "Cancel"),
        Binding("n", "cancel", "Cancel"),
        Binding("y", "confirm", "Execute"),
    ]

    def __init__(self, fix: Fix, diagnosis: Diagnosis | None = None) -> None:
        super().__init__(id="fix-confirm")
        self.fix = fix
        self.diagnosis = diagnosis

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Static(f"EXECUTE FIX [{self.fix.index}]", id="confirm-title")
            yield Static(
                Text(self.fix.command, style=f"bold {BRAND_COLORS['health_ok']}"),
                id="confirm-command",
            )
            yield Static(
                Text(
                    self.fix.explanation.strip() or "no explanation supplied",
                    style=BRAND_COLORS["text"],
                ),
                id="confirm-explanation",
            )
            if self.fix.dangerous or self.fix.requires_root:
                warning = Text()
                warning.append("WARNING  ", style=f"bold {BRAND_COLORS['critical']}")
                if self.fix.dangerous:
                    warning.append(
                        "this command is flagged as dangerous and can change or destroy network state. ",
                        style=BRAND_COLORS["critical"],
                    )
                if self.fix.requires_root:
                    warning.append(
                        "root privileges are required; it will fail without sudo access.",
                        style=BRAND_COLORS["warning"],
                    )
                yield Static(warning, id="confirm-warning")
            if self.diagnosis is not None and self.diagnosis.verify:
                verify = Text()
                verify.append("VERIFY  ", style=f"bold {BRAND_COLORS['muted']}")
                verify.append(self.diagnosis.verify, style=BRAND_COLORS["text"])
                yield Static(verify, id="confirm-verify")
            with Horizontal(id="confirm-buttons"):
                yield Button("Execute fix", variant="error", id="confirm-execute")
                yield Button("Cancel", variant="primary", id="confirm-cancel")

    def on_mount(self) -> None:
        """Focus the safe choice so a stray Enter cannot run the command."""
        self.query_one("#confirm-cancel", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Dismiss with the operator's explicit choice."""
        self.dismiss(event.button.id == "confirm-execute")

    def action_confirm(self) -> None:
        """Confirm execution of the fix."""
        self.dismiss(True)

    def action_cancel(self) -> None:
        """Abort execution of the fix."""
        self.dismiss(False)


class DiagnosticsScreen(Screen[None]):
    """Issue list plus the structured diagnosis workflow.

    Args:
        monitor: The running :class:`MonitorManager`.
        config: Effective configuration.
        auto_diagnose: Run a diagnosis as soon as the screen mounts.
        id: DOM id.
    """

    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("enter", "execute_fix", "Execute fix", show=True),
    ]

    AUTO_FOCUS = "#issues-table"

    def __init__(
        self,
        monitor: MonitorManager,
        config: NetMonConfig,
        *,
        auto_diagnose: bool = False,
        id: str | None = "diagnostics",
    ) -> None:
        super().__init__(id=id)
        self.monitor = monitor
        self.config = config
        self.auto_diagnose = auto_diagnose
        self._state: SystemState | None = None
        self._diagnosis: Diagnosis | None = None
        self._loading = False
        self._executing = False

    # -- composition ---------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Static(self._header_text(), id="diagnostics-header")
        with VerticalScroll(id="diagnostics-scroll"):
            yield Static("ISSUES", classes="section-title")
            issues = StatusTable(id="issues-table")
            issues.set_columns(ISSUE_COLUMNS)
            yield issues
            yield Static("DIAGNOSIS", classes="section-title")
            yield Static(Text("press d to run a diagnosis", style="dim"), id="diagnosis-output")
            yield LoadingIndicator(id="diagnosis-loading")
            yield Static(
                "FIXES  (select a fix and press enter to review and execute)",
                classes="section-title",
            )
            fixes = StatusTable(id="fixes-table")
            fixes.set_columns(FIX_COLUMNS)
            yield fixes
            yield Static("", id="diagnosis-status")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#diagnosis-loading", LoadingIndicator).display = False
        if self.auto_diagnose:
            # ``is_mounted`` only flips to True after the mount completes, so the
            # first diagnosis is deferred until the screen can be queried.
            self.call_after_refresh(self.action_diagnose)

    # -- state rendering -----------------------------------------------------

    def refresh_from_state(
        self,
        state: SystemState,
        history: Mapping[str, Sequence[float]] | None = None,
    ) -> None:
        """Refresh the issue list; a diagnosis only changes when requested."""
        self._state = state
        if not self.is_mounted:
            return
        self.query_one("#diagnostics-header", Static).update(self._header_text(state))
        table = self.query_one("#issues-table", StatusTable)
        ranked: list[tuple[int, tuple[str, Sequence[Any]]]] = []
        for issue in self._current_issues():
            severity = str(issue.get("severity", "warning"))
            key = str(issue.get("key") or f"{issue.get('issue_type')}:{issue.get('component')}")
            cells: tuple[Any, ...] = (
                _severity_cell(severity),
                str(issue.get("component", "--")),
                truncate(str(issue.get("message", "")), 60),
                str(issue.get("metric") or "--"),
                format_ago(_parse_timestamp(issue.get("detected_at"))),
            )
            ranked.append((severity_rank(severity), (key, cells)))
        ranked.sort(key=lambda item: item[0])
        table.sync([row for _rank, row in ranked], placeholder="no active issues detected")

    # -- actions -------------------------------------------------------------

    def action_diagnose(self) -> None:
        """Diagnose the selected issue, or the most severe one when none is selected."""
        if self._loading or not self.is_mounted:
            return
        issue_key: str | None = None
        table = self.query_one("#issues-table", StatusTable)
        if table.row_count:
            issue_key = table.selected_key()
        self.run_worker(
            self._run_diagnosis(issue_key), group="diagnosis", exclusive=True, exit_on_error=False
        )

    def action_execute_fix(self) -> None:
        """Open the confirmation modal for the selected fix."""
        if self._executing or not self.is_mounted:
            return
        diagnosis = self._diagnosis
        if diagnosis is None:
            self._set_status("run a diagnosis before executing a fix", state="warning")
            return
        index = self._selected_fix_index(diagnosis)
        if index is None:
            self._set_status("select a fix from the FIXES table first", state="warning")
            return
        fix = diagnosis.fix(index)
        if fix is None:
            self._set_status(f"fix {index} is no longer available", state="warning")
            return
        self.app.push_screen(FixConfirmScreen(fix, diagnosis), self._on_fix_confirmed)

    def on_data_table_row_selected(self, event: StatusTable.RowSelected) -> None:
        """Enter on a table: diagnose an issue, or review a fix."""
        table_id = event.data_table.id
        if table_id == "issues-table":
            self.action_diagnose()
        elif table_id == "fixes-table":
            self.action_execute_fix()

    # -- workers -------------------------------------------------------------

    async def _run_diagnosis(self, issue_key: str | None) -> None:
        self._loading = True
        self._set_loading(True)
        self._set_status(
            f"⟳ diagnosing {issue_key or 'the most severe issue'} ...", state="info", sticky=True
        )
        try:
            diagnosis = await self.monitor.diagnose_issue(issue_key, use_ai=True)
        except Exception as exc:
            self._set_status(f"diagnosis failed: {exc}", state="critical")
            return None
        finally:
            self._loading = False
            self._set_loading(False)

        if not self.is_mounted:
            return None

        if diagnosis is None:
            self._diagnosis = None
            self._update_output(Text("no active issue to diagnose", style=BRAND_COLORS["muted"]))
            self.query_one("#fixes-table", StatusTable).sync([])
            self._set_status("nothing to diagnose", state="warning")
            return None

        self._render_diagnosis(diagnosis)
        self._set_status(
            f"diagnosis complete in {diagnosis.duration_ms:.0f} ms "
            f"({diagnosis.source}, confidence {diagnosis.confidence:.0f}%)",
            state="ok",
        )
        return None

    async def _run_fix(self, index: int) -> None:
        diagnosis = self._diagnosis
        if diagnosis is None:
            return None
        self._executing = True
        self._set_loading(True)
        self._set_status(f"⟳ executing fix {index} ...", state="info", sticky=True)
        try:
            result = await self.monitor.execute_fix(diagnosis, index, confirmed=True)
        except Exception as exc:
            self._set_status(f"fix execution failed: {exc}", state="critical")
            return None
        finally:
            self._executing = False
            self._set_loading(False)

        if not self.is_mounted:
            return None

        body = render_diagnosis(diagnosis)
        body.append("\n\n")
        body.append_text(render_execution(result))
        self._update_output(body)
        self._refresh_fixes(diagnosis)
        self._set_status(
            f"fix {index} {'succeeded' if result.success else 'failed'} (exit {result.exit_code})",
            state="ok" if result.success else "critical",
        )
        return None

    def _on_fix_confirmed(self, confirmed: bool | None) -> None:
        """Callback for :class:`FixConfirmScreen`; only ``True`` runs the command."""
        if not confirmed:
            self._set_status("fix cancelled; nothing was executed", state="warning")
            return
        diagnosis = self._diagnosis
        if diagnosis is None:
            return
        index = self._selected_fix_index(diagnosis)
        if index is None:
            return
        self.run_worker(self._run_fix(index), group="fix", exclusive=True, exit_on_error=False)

    # -- rendering helpers ---------------------------------------------------

    def _current_issues(self) -> list[dict[str, Any]]:
        """Live issues when the health checker has run, else the issue history."""
        state = self._state
        if state is None:
            return []
        health = getattr(state, "health", None)
        issues = getattr(health, "issues", None) if health is not None else None
        if issues:
            return [issue.to_dict() for issue in issues]
        history = getattr(state, "issues", None) or []
        return [dict(item) for item in history if isinstance(item, Mapping)]

    def _selected_fix_index(self, diagnosis: Diagnosis) -> int | None:
        table = self.query_one("#fixes-table", StatusTable)
        key = table.selected_key()
        if key is not None:
            try:
                return int(key)
            except ValueError:
                return None
        return diagnosis.fixes[0].index if diagnosis.fixes else None

    def _update_output(self, body: Text) -> None:
        if not self.is_mounted:
            return
        self.query_one("#diagnosis-output", Static).update(body)

    def _render_diagnosis(self, diagnosis: Diagnosis) -> None:
        self._diagnosis = diagnosis
        self._update_output(render_diagnosis(diagnosis))
        self._refresh_fixes(diagnosis)
        if diagnosis.fixes:
            self.query_one("#fixes-table", StatusTable).focus()

    def _refresh_fixes(self, diagnosis: Diagnosis) -> None:
        if not self.is_mounted:
            return
        table = self.query_one("#fixes-table", StatusTable)
        rows = [
            (
                str(fix.index),
                (
                    str(fix.index),
                    fix.command,
                    "yes" if fix.requires_root else "no",
                    "yes" if fix.dangerous else "no",
                    _fix_state_cell(fix),
                ),
            )
            for fix in diagnosis.fixes
        ]
        table.sync(rows, placeholder="no fixes proposed")

    def _set_loading(self, loading: bool) -> None:
        if not self.is_mounted:
            return
        try:
            indicator = self.query_one("#diagnosis-loading", LoadingIndicator)
        except Exception:
            return
        indicator.display = loading

    def _set_status(self, message: str, *, state: str = "info", sticky: bool = False) -> None:
        if not self.is_mounted:
            return
        try:
            status = self.query_one("#diagnosis-status", Static)
        except Exception:
            return
        style = BRAND_COLORS["info"] if state == "info" else health_color(state)
        status.update(Text(message, style=style))
        if not sticky and state in {"ok", "critical"}:
            self.set_timer(6.0, lambda: status.update(Text("")))

    def _header_text(self, state: SystemState | None = None) -> Text:
        header = Text()
        header.append("DIAGNOSTICS", style=f"bold {BRAND_COLORS['info']}")
        if state is None:
            header.append("   waiting for data", style=BRAND_COLORS["muted"])
            return header
        runtime = getattr(state, "diagnostics", {}) or {}
        header.append(
            f"   {runtime.get('diagnoses', 0)} diagnoses"
            f"   {runtime.get('rule_diagnoses', 0)} rule"
            f"   {runtime.get('ai_diagnoses', 0)} ai"
            f"   confidence floor {runtime.get('ai_confidence_threshold', 0)}%",
            style=BRAND_COLORS["text"],
        )
        header.append(
            f"   ollama {'enabled' if self.config.ollama.enabled else 'disabled'}"
            f" ({self.config.ollama.model})",
            style=BRAND_COLORS["muted"],
        )
        return header
