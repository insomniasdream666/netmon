"""Time-series endpoints backed by InfluxDB with an in-memory fallback.

The endpoint returns both the raw rows and Chart.js-ready series so the
browser does not have to reshape rows into datasets.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from netmon.storage.influx import ALL_MEASUREMENTS
from netmon.utils.formatting import relative_range_to_seconds
from netmon.web.api.health import get_influx

router = APIRouter(tags=["metrics"])

INTERVAL_RE = re.compile(r"^\d{1,5}[smhdw]$")
MAX_SERIES = 12
MAX_POINTS_PER_SERIES = 240


@router.get("/api/metrics/{measurement}")
async def api_metrics(
    request: Request,
    measurement: str,
    range_token: str = Query("1h", alias="range"),
    interval: str | None = Query(None),
    field: list[str] | None = Query(None),
    tag: list[str] | None = Query(None),
    limit: int = Query(1000, ge=1, le=5000),
) -> dict[str, Any]:
    """Time series rows for one measurement.

    Query parameters:

    * ``range``: relative range token (``15m``, ``1h``, ``24h``, ...).
    * ``interval``: optional aggregation window (``10s``, ``1m``, ...).
    * ``field``: repeatable field filter.
    * ``tag``: repeatable ``key:value`` tag filter.
    * ``limit``: maximum number of raw rows.
    """
    if measurement not in ALL_MEASUREMENTS:
        raise HTTPException(
            status_code=404,
            detail=f"unknown measurement: {measurement} (expected one of {', '.join(ALL_MEASUREMENTS)})",
        )
    try:
        relative_range_to_seconds(range_token)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid range: {range_token!r}") from exc
    if interval is not None and not INTERVAL_RE.match(interval):
        raise HTTPException(status_code=400, detail=f"invalid interval: {interval!r}")

    tag_filters: dict[str, str] = {}
    for item in tag or []:
        key, separator, value = item.partition(":")
        if not separator or not key.strip():
            raise HTTPException(status_code=400, detail=f"invalid tag filter: {item!r} (expected key:value)")
        tag_filters[key.strip()] = value

    fields = [name for name in (field or []) if name]
    influx = get_influx(request)
    if influx is None:
        return {
            "measurement": measurement,
            "range": range_token,
            "interval": interval,
            "fields": fields,
            "tag_filters": tag_filters,
            "rows": [],
            "series": [],
            "count": 0,
            "available": False,
            "configured": False,
        }

    rows = await influx.query_range(
        measurement,
        range_token=range_token,
        interval=interval,
        fields=fields or None,
        tag_filters=tag_filters or None,
        limit=limit,
    )
    return {
        "measurement": measurement,
        "range": range_token,
        "interval": interval,
        "fields": fields,
        "tag_filters": tag_filters,
        "rows": rows,
        "series": _build_series(rows),
        "count": len(rows),
        "available": influx.available,
        "configured": influx.configured,
    }


def _build_series(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group rows into one time-ordered series per field/tag combination."""
    grouped: dict[tuple[str, tuple[tuple[str, str], ...]], dict[str, Any]] = {}
    for row in rows:
        field_name = str(row.get("field") or "")
        tags = row.get("tags") or {}
        group_key = (field_name, tuple(sorted((str(k), str(v)) for k, v in tags.items())))
        bucket = grouped.setdefault(
            group_key,
            {"field": field_name, "tags": {str(k): str(v) for k, v in tags.items()}, "points": []},
        )
        raw = row.get("value")
        if raw is None:
            continue
        try:
            value = float(raw)
        except (TypeError, ValueError):
            continue
        bucket["points"].append({"time": row.get("time"), "value": value})

    series: list[dict[str, Any]] = []
    for bucket in grouped.values():
        points = sorted(bucket["points"], key=lambda point: str(point.get("time") or ""))
        if not points:
            continue
        series.append(
            {
                "label": _series_label(bucket["field"], bucket["tags"]),
                "field": bucket["field"],
                "tags": bucket["tags"],
                "points": points[-MAX_POINTS_PER_SERIES:],
            }
        )
    series.sort(key=lambda item: item["label"])
    return series[:MAX_SERIES]


def _series_label(field_name: str, tags: dict[str, str]) -> str:
    if not tags:
        return field_name
    descriptor = " ".join(f"{key}={value}" for key, value in sorted(tags.items()))
    return f"{field_name} {descriptor}"


__all__ = ["router"]
