"""InfluxDB time-series storage with an in-memory fallback.

The ``influxdb-client`` package is synchronous, so every call is dispatched to
a worker thread with :func:`asyncio.to_thread` to keep the event loop free.

Graceful degradation is deliberate: when InfluxDB is unconfigured or
unreachable, points are still appended to a bounded in-memory ring buffer so
the TUI and web dashboard keep rendering recent history instead of erroring.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from netmon.config.settings import InfluxSettings
from netmon.utils.formatting import relative_range_to_seconds

logger = logging.getLogger(__name__)

MEASUREMENT_INTERFACES = "interface_metrics"
MEASUREMENT_CONNECTIVITY = "connectivity"
MEASUREMENT_HEALTH = "health_score"
MEASUREMENT_PORTS = "port_scan"
MEASUREMENT_BANDWIDTH = "bandwidth"
MEASUREMENT_CONNECTIONS = "connections"
MEASUREMENT_WIFI = "wifi"
MEASUREMENT_CERTIFICATES = "certificates"

ALL_MEASUREMENTS: tuple[str, ...] = (
    MEASUREMENT_INTERFACES,
    MEASUREMENT_CONNECTIVITY,
    MEASUREMENT_HEALTH,
    MEASUREMENT_PORTS,
    MEASUREMENT_BANDWIDTH,
    MEASUREMENT_CONNECTIONS,
    MEASUREMENT_WIFI,
    MEASUREMENT_CERTIFICATES,
)

MEMORY_BUFFER_SIZE = 2000


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(UTC)


@dataclass(slots=True)
class MetricPoint:
    """A single time-series point."""

    measurement: str
    fields: dict[str, float | int | str | bool]
    tags: dict[str, str] = field(default_factory=dict)
    time: datetime = field(default_factory=utcnow)

    def as_dict(self) -> dict[str, Any]:
        """Serialise for the in-memory store and the REST API."""
        return {
            "measurement": self.measurement,
            "tags": dict(self.tags),
            "fields": dict(self.fields),
            "time": self.time.isoformat(),
        }


class InfluxRepository:
    """Writes and queries time-series metrics.

    Args:
        settings: Connection details; when ``token`` is empty the repository
            operates in memory-only mode.
        memory_buffer_size: Number of points retained per measurement when
            InfluxDB is unavailable.
    """

    def __init__(self, settings: InfluxSettings, *, memory_buffer_size: int = MEMORY_BUFFER_SIZE) -> None:
        self.settings = settings
        self._client: Any | None = None
        self._write_api: Any | None = None
        self._query_api: Any | None = None
        self._lock = asyncio.Lock()
        self._memory: dict[str, deque[MetricPoint]] = {}
        self._memory_limit = memory_buffer_size
        self._available: bool | None = None
        self._last_error: str | None = None
        self._write_count = 0
        self._failure_count = 0

    # -- state ---------------------------------------------------------------

    @property
    def configured(self) -> bool:
        """True when a token is present so InfluxDB writes can be attempted."""
        return self.settings.enabled and self.settings.is_configured()

    @property
    def available(self) -> bool | None:
        """Last known reachability: True, False, or None when never probed."""
        return self._available

    @property
    def last_error(self) -> str | None:
        """Most recent failure message, for display in the UI."""
        return self._last_error

    def stats(self) -> dict[str, Any]:
        """Write counters used by health checks and the dashboard."""
        return {
            "configured": self.configured,
            "available": self._available,
            "writes": self._write_count,
            "failures": self._failure_count,
            "last_error": self._last_error,
            "memory_points": {name: len(points) for name, points in self._memory.items()},
        }

    # -- lifecycle -----------------------------------------------------------

    def _ensure_client(self) -> Any:
        if self._client is None:
            from influxdb_client import InfluxDBClient
            from influxdb_client.client.write_api import SYNCHRONOUS

            self._client = InfluxDBClient(
                url=self.settings.url,
                token=self.settings.token,
                org=self.settings.org,
                timeout=self.settings.timeout_ms,
            )
            self._write_api = self._client.write_api(write_options=SYNCHRONOUS)
            self._query_api = self._client.query_api()
        return self._client

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        client, self._client = self._client, None
        self._write_api = None
        self._query_api = None
        if client is not None:
            await asyncio.to_thread(client.close)

    async def ping(self) -> bool:
        """Probe InfluxDB health; updates :attr:`available`."""
        if not self.configured:
            self._available = False
            self._last_error = None
            return False
        try:
            client = await asyncio.to_thread(self._ensure_client)
            healthy = await asyncio.to_thread(client.ping)
            self._available = bool(healthy)
            if healthy:
                self._last_error = None
            else:
                self._last_error = "influxdb ping returned unhealthy"
            return self._available
        except Exception as exc:
            self._available = False
            self._last_error = f"{type(exc).__name__}: {exc}"
            logger.debug("influx ping failed: %s", exc)
            return False

    # -- writes --------------------------------------------------------------

    def _remember(self, points: Sequence[MetricPoint]) -> None:
        for point in points:
            buffer = self._memory.setdefault(point.measurement, deque(maxlen=self._memory_limit))
            buffer.append(point)

    async def write_points(self, points: Sequence[MetricPoint]) -> bool:
        """Persist points to InfluxDB, always mirroring them in memory.

        Returns True when the points reached InfluxDB; False when the write
        was skipped or failed (memory mirroring still happened).
        """
        if not points:
            return True
        self._remember(points)

        if not self.configured:
            self._available = False
            return False

        try:
            from influxdb_client import Point

            payload = []
            for item in points:
                point = Point(item.measurement).time(item.time)
                for key, value in item.tags.items():
                    point = point.tag(str(key), str(value))
                for field_name, field_value in item.fields.items():
                    if field_value is None:
                        continue
                    point = point.field(str(field_name), field_value)
                payload.append(point)

            async with self._lock:
                self._ensure_client()
                write_api = self._write_api
                assert write_api is not None
                await asyncio.to_thread(
                    write_api.write,
                    bucket=self.settings.bucket,
                    org=self.settings.org,
                    record=payload,
                )
            self._write_count += len(points)
            self._available = True
            self._last_error = None
            return True
        except Exception as exc:
            self._failure_count += 1
            self._available = False
            self._last_error = f"{type(exc).__name__}: {exc}"
            logger.debug("influx write failed: %s", exc)
            return False

    async def write_collection_metrics(self, metrics: Iterable[dict[str, Any]]) -> int:
        """Write collector-emitted metric dicts.

        Each dict uses the shape ``{"measurement": str, "fields": {...},
        "tags": {...}}`` as produced by the collectors.
        """
        points: list[MetricPoint] = []
        for raw in metrics:
            measurement = raw.get("measurement")
            fields = raw.get("fields")
            if not measurement or not isinstance(fields, dict):
                continue
            points.append(
                MetricPoint(
                    measurement=str(measurement),
                    fields={str(k): v for k, v in fields.items() if v is not None},
                    tags={str(k): str(v) for k, v in (raw.get("tags") or {}).items()},
                    time=raw.get("time") or utcnow(),
                )
            )
        if not points:
            return 0
        await self.write_points(points)
        return len(points)

    # -- queries -------------------------------------------------------------

    def memory_series(
        self,
        measurement: str,
        *,
        since: datetime | None = None,
        limit: int = 200,
    ) -> list[MetricPoint]:
        """Points retained in memory for a measurement, oldest first."""
        buffer = self._memory.get(measurement)
        if not buffer:
            return []
        points = list(buffer)
        if since is not None:
            points = [p for p in points if p.time >= since]
        return points[-limit:]

    async def query_range(
        self,
        measurement: str,
        *,
        range_token: str = "1h",
        interval: str | None = None,
        fields: Sequence[str] | None = None,
        tag_filters: dict[str, str] | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """Query a measurement over a time range.

        Falls back to the in-memory buffer whenever InfluxDB is unavailable,
        so callers always receive a list they can render.
        """
        seconds = relative_range_to_seconds(range_token)
        since = utcnow() - timedelta(seconds=seconds)
        fallback = self._memory_query(measurement, since=since, tag_filters=tag_filters, limit=limit)

        if not self.configured:
            return fallback

        try:
            query = self._build_flux(measurement, range_token, interval, fields, tag_filters)
            async with self._lock:
                self._ensure_client()
                query_api = self._query_api
                assert query_api is not None
                tables = await asyncio.to_thread(
                    query_api.query, query=query, org=self.settings.org
                )
            rows: list[dict[str, Any]] = []
            for table in tables:
                for record in table.records:
                    rows.append(
                        {
                            "measurement": measurement,
                            "time": record.get_time().isoformat()
                            if hasattr(record.get_time(), "isoformat")
                            else str(record.get_time()),
                            "field": record.get_field(),
                            "value": record.get_value(),
                            "tags": {
                                key: value
                                for key, value in record.values.items()
                                if key
                                not in {
                                    "_value",
                                    "_field",
                                    "_measurement",
                                    "_time",
                                    "_start",
                                    "_stop",
                                    "result",
                                    "table",
                                }
                            },
                        }
                    )
            self._available = True
            self._last_error = None
            return rows[:limit] if rows else fallback
        except Exception as exc:
            self._failure_count += 1
            self._available = False
            self._last_error = f"{type(exc).__name__}: {exc}"
            logger.debug("influx query failed, using memory fallback: %s", exc)
            return fallback

    def _memory_query(
        self,
        measurement: str,
        *,
        since: datetime,
        tag_filters: dict[str, str] | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for point in self.memory_series(measurement, since=since, limit=limit):
            if tag_filters and any(point.tags.get(k) != v for k, v in tag_filters.items()):
                continue
            for field_name, value in point.fields.items():
                rows.append(
                    {
                        "measurement": measurement,
                        "time": point.time.isoformat(),
                        "field": field_name,
                        "value": value,
                        "tags": dict(point.tags),
                        "source": "memory",
                    }
                )
        return rows

    def _build_flux(
        self,
        measurement: str,
        range_token: str,
        interval: str | None,
        fields: Sequence[str] | None,
        tag_filters: dict[str, str] | None,
    ) -> str:
        """Build the Flux query used by :meth:`query_range`.

        Tag and field names come from NetMon's own schemas, but values are
        escaped so a hostile target string cannot break out of the literal.
        """
        lines = [
            f'from(bucket: "{_escape(self.settings.bucket)}")',
            f"  |> range(start: -{range_token})",
            f'  |> filter(fn: (r) => r._measurement == "{_escape(measurement)}")',
        ]
        if fields:
            field_filter = " or ".join(f'r._field == "{_escape(str(name))}"' for name in fields)
            lines.append(f"  |> filter(fn: (r) => {field_filter})")
        if tag_filters:
            for key, value in tag_filters.items():
                lines.append(
                    f'  |> filter(fn: (r) => r["{_escape(str(key))}"] == "{_escape(str(value))}")'
                )
        if interval:
            lines.append(f"  |> aggregateWindow(every: {interval}, fn: mean, createEmpty: false)")
        lines.append('  |> yield(name: "netmon")')
        return "\n".join(lines)

    async def latest(
        self,
        measurement: str,
        *,
        tag_filters: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Most recent point of a measurement, from InfluxDB or memory."""
        rows = await self.query_range(
            measurement, range_token="1h", tag_filters=tag_filters, limit=100
        )
        if not rows:
            return None
        return max(rows, key=lambda row: str(row.get("time", "")))

    async def series(
        self,
        measurement: str,
        field: str,
        *,
        range_token: str = "15m",
        tag_filters: dict[str, str] | None = None,
        limit: int = 240,
    ) -> list[tuple[str, float]]:
        """Time-ordered ``(timestamp, value)`` pairs for one field.

        Convenience accessor used by sparklines and the web charts.
        """
        rows = await self.query_range(
            measurement,
            range_token=range_token,
            fields=[field],
            tag_filters=tag_filters,
            limit=limit,
        )
        pairs: list[tuple[str, float]] = []
        for row in rows:
            if row.get("field") != field:
                continue
            try:
                value = float(row["value"])
            except (TypeError, ValueError, KeyError):
                continue
            pairs.append((str(row.get("time", "")), value))
        pairs.sort(key=lambda item: item[0])
        return pairs

    async def apply_retention(self, retention: str) -> bool:
        """Ask InfluxDB to apply a bucket retention policy.

        InfluxDB 2.x sets retention on the bucket itself; this updates it when
        the token has permission and silently no-ops otherwise.
        """
        if not self.configured:
            return False
        try:
            from influxdb_client import BucketsApi
            from influxdb_client.domain.bucket_retention_rules import BucketRetentionRules

            rules = BucketRetentionRules(type="expire", every_seconds=relative_range_to_seconds(retention))

            def _update() -> None:
                client = self._ensure_client()
                buckets_api = BucketsApi(client)
                found = buckets_api.find_buckets(name=self.settings.bucket)
                for bucket in getattr(found, "buckets", []) or []:
                    if bucket.name == self.settings.bucket:
                        bucket.retention_rules = [rules]
                        buckets_api.update_bucket(bucket=bucket)

            await asyncio.to_thread(_update)
            return True
        except Exception as exc:
            logger.warning("could not apply retention policy: %s", exc)
            return False


def _escape(value: str) -> str:
    """Escape a string for embedding in a Flux literal."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


__all__ = [
    "ALL_MEASUREMENTS",
    "MEASUREMENT_BANDWIDTH",
    "MEASUREMENT_CERTIFICATES",
    "MEASUREMENT_CONNECTIONS",
    "MEASUREMENT_CONNECTIVITY",
    "MEASUREMENT_HEALTH",
    "MEASUREMENT_INTERFACES",
    "MEASUREMENT_PORTS",
    "MEASUREMENT_WIFI",
    "InfluxRepository",
    "MetricPoint",
]
