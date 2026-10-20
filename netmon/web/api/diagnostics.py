"""Diagnosis, fix execution and diagnostic-history endpoints.

The diagnose and fix routes answer with JSON for API clients. When the
request carries the HTMX header (``HX-Request: true``) they answer with an
HTML fragment rendered from ``diagnostics.html`` so the page can swap the
result straight into the DOM.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from netmon.core.diagnostics.engine import Diagnosis, Fix
from netmon.web.api.health import get_monitor, get_repository

MAX_HISTORY = 500


class DiagnoseRequest(BaseModel):
    """Payload for ``POST /api/diagnose``."""

    issue_key: str | None = None
    issue_type: str | None = None
    use_ai: bool = True


class FixRequest(BaseModel):
    """Payload for ``POST /api/fix``.

    ``confirm`` is deliberately untyped: only the literal JSON value ``true``
    is accepted, so a client cannot accidentally run a fix with a truthy
    string or number.
    """

    diagnosis_id: int
    fix_index: int
    confirm: Any = False


def build_router(*, templates: Jinja2Templates | None = None) -> APIRouter:
    """Build the diagnostics router, optionally with an HTML fragment renderer."""
    router = APIRouter(tags=["diagnostics"])

    def render_fragment(request: Request, block: str, context: dict[str, Any]) -> Response:
        if templates is None:
            raise HTTPException(status_code=503, detail="HTML rendering is unavailable")
        return templates.TemplateResponse(
            request, "diagnostics.html", {**context, "fragment": block}
        )

    @router.post("/api/diagnose")
    async def api_diagnose(request: Request, payload: DiagnoseRequest) -> Response:
        """Diagnose the named issue, or the most severe current issue.

        Returns 404 when no active issue matches and 503 when neither a rule
        nor the AI path produced a diagnosis.
        """
        monitor = get_monitor(request)
        key = payload.issue_key or payload.issue_type
        if monitor.find_issue(key) is None:
            detail = f"no active issue matched {key!r}" if key else "there are no active issues"
            raise HTTPException(status_code=404, detail=detail)

        diagnosis = await monitor.diagnose_issue(key, use_ai=payload.use_ai)
        if diagnosis is None:
            raise HTTPException(status_code=404, detail="the issue disappeared before diagnosis")
        body = diagnosis.to_dict()

        if diagnosis.source == "fallback":
            reason = diagnosis.ai_error or "AI diagnosis unavailable and no rule matched this issue"
            if _wants_html(request):
                return render_fragment(request, "diagnosis_result", {"diagnosis": body})
            return JSONResponse(status_code=503, content={"detail": reason, "diagnosis": body})

        if _wants_html(request):
            return render_fragment(request, "diagnosis_result", {"diagnosis": body})
        return JSONResponse(content=body)

    @router.post("/api/fix")
    async def api_fix(request: Request, payload: FixRequest) -> Response:
        """Execute one fix of a recorded diagnosis after explicit confirmation."""
        if payload.confirm is not True:
            raise HTTPException(
                status_code=400,
                detail="confirmation required: only confirm=true is accepted",
            )
        monitor = get_monitor(request)
        repository = get_repository(request)
        record = await repository.get_diagnostic(payload.diagnosis_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"unknown diagnosis: {payload.diagnosis_id}")

        diagnosis = _diagnosis_from_record(record)
        if diagnosis.fix(payload.fix_index) is None:
            raise HTTPException(
                status_code=404,
                detail=f"diagnosis {payload.diagnosis_id} has no fix {payload.fix_index}",
            )

        result = await monitor.execute_fix(diagnosis, payload.fix_index, confirmed=True)
        body = result.to_dict()
        if _wants_html(request):
            return render_fragment(
                request, "fix_result", {"fix_result": body, "diagnosis": record}
            )
        return JSONResponse(content=body)

    @router.get("/api/diagnostics/history")
    async def api_history(
        request: Request,
        limit: int = Query(50, ge=1, le=MAX_HISTORY),
        issue_type: str | None = Query(None, min_length=1, max_length=100),
    ) -> dict[str, Any]:
        """Recent diagnoses from SQLite, newest first."""
        repository = get_repository(request)
        records = await repository.list_diagnostics(limit=limit, issue_type=issue_type)
        return {
            "diagnostics": records,
            "count": len(records),
            "limit": limit,
            "issue_type": issue_type,
            "stats": await repository.diagnostic_stats(),
        }

    @router.get("/api/diagnostics/{diagnostic_id}")
    async def api_diagnostic(request: Request, diagnostic_id: int) -> dict[str, Any]:
        """One recorded diagnosis by id."""
        repository = get_repository(request)
        record = await repository.get_diagnostic(diagnostic_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"unknown diagnosis: {diagnostic_id}")
        return record

    return router


def _wants_html(request: Request) -> bool:
    """True when the caller is HTMX rather than a JSON API client."""
    return request.headers.get("hx-request", "").strip().lower() == "true"


def _diagnosis_from_record(record: Mapping[str, Any]) -> Diagnosis:
    """Rebuild a :class:`Diagnosis` from a stored diagnostic-history row.

    Fixes are re-validated by the diagnostic engine at execution time; this
    only restores the data needed by ``MonitorManager.execute_fix``.
    """
    fixes: list[Fix] = []
    for index, raw in enumerate(record.get("fixes") or []):
        if not isinstance(raw, Mapping):
            continue
        command = str(raw.get("command") or "").strip()
        if not command:
            continue
        fixes.append(
            Fix(
                index=int(raw.get("index", index)),
                command=command,
                explanation=str(raw.get("explanation") or ""),
                requires_root=bool(raw.get("requires_root")),
                dangerous=bool(raw.get("dangerous")),
                executed=bool(raw.get("executed")),
                success=raw.get("success") if isinstance(raw.get("success"), bool) else None,
            )
        )
    return Diagnosis(
        issue={
            "issue_type": record.get("issue_type"),
            "message": record.get("issue_details"),
            "severity": record.get("severity"),
        },
        diagnosis=str(record.get("diagnosis") or ""),
        confidence=float(record.get("confidence") or 0.0),
        source=str(record.get("source") or "rule"),
        fixes=fixes,
        risks=str(record.get("risks") or ""),
        verify=str(record.get("verify_command") or ""),
        history_id=int(record["id"]),
    )


__all__ = ["build_router"]
