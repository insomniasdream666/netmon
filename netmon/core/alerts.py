"""Alert evaluation, cooldown handling and notification delivery.

Two complementary paths produce alerts:

1. **Health-issue driven** - every :class:`~netmon.core.health.HealthIssue`
   with warning or critical severity becomes an alert candidate.
2. **Metric-rule driven** - operator/threshold rules stored in SQLite are
   evaluated against a flat metric map extracted from the health report.

Both paths share the same cooldown table and delivery pipeline. Delivery is
best-effort: a failing webhook never blocks the monitoring loop, and the
error is recorded alongside the alert event for display in the UI.
"""

from __future__ import annotations

import asyncio
import logging
import operator as operator_module
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from netmon.config.settings import AlertChannel, AlertsSettings
from netmon.core.health import HealthIssue, HealthState, OverallHealth, SystemSnapshot, utcnow
from netmon.storage.sqlite import SQLiteRepository

logger = logging.getLogger(__name__)

AlertListener = Callable[["AlertRecord"], Awaitable[None] | None]

OPERATORS: dict[str, Callable[[float, float], bool]] = {
    ">": operator_module.gt,
    ">=": operator_module.ge,
    "<": operator_module.lt,
    "<=": operator_module.le,
    "==": operator_module.eq,
    "!=": operator_module.ne,
}

SEVERITY_ORDER: dict[str, int] = {"info": 2, "warning": 1, "critical": 0}

DEFAULT_RULES: tuple[dict[str, Any], ...] = (
    {
        "name": "gateway-unreachable",
        "metric": "connectivity.gateway.success",
        "operator": "==",
        "threshold": 0.0,
        "severity": "critical",
        "description": "Default gateway does not respond to ICMP",
    },
    {
        "name": "high-latency",
        "metric": "connectivity.avg_latency_ms",
        "operator": ">",
        "threshold": 200.0,
        "severity": "warning",
        "description": "Average RTT to internet targets above threshold",
    },
    {
        "name": "packet-loss",
        "metric": "connectivity.avg_packet_loss",
        "operator": ">",
        "threshold": 5.0,
        "severity": "critical",
        "description": "Packet loss above the critical threshold",
    },
    {
        "name": "dns-failures",
        "metric": "dns.failure_rate",
        "operator": ">",
        "threshold": 50.0,
        "severity": "critical",
        "description": "More than half of DNS lookups failed",
    },
    {
        "name": "bandwidth-saturated",
        "metric": "bandwidth.peak_utilization",
        "operator": ">",
        "threshold": 95.0,
        "severity": "warning",
        "description": "An interface is close to link saturation",
    },
    {
        "name": "certificate-expiring",
        "metric": "certificates.soonest_expiry_days",
        "operator": "<",
        "threshold": 7.0,
        "severity": "critical",
        "description": "A monitored TLS certificate expires within a week",
    },
    {
        "name": "health-score-low",
        "metric": "health.score",
        "operator": "<",
        "threshold": 50.0,
        "severity": "critical",
        "description": "Overall health score below the critical threshold",
    },
)


@dataclass(slots=True)
class AlertRecord:
    """A fired alert, delivered to channels and listeners."""

    rule_name: str
    severity: str
    message: str
    metric: str = ""
    value: float | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    channels: tuple[str, ...] = ()
    created_at: datetime = field(default_factory=utcnow)
    event_id: int | None = None
    delivered: bool = False
    delivery_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the API, TUI and SSE stream."""
        return {
            "id": self.event_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "message": self.message,
            "metric": self.metric,
            "value": self.value,
            "payload": self.payload,
            "channels": list(self.channels),
            "created_at": self.created_at.isoformat(),
            "delivered": self.delivered,
            "delivery_errors": list(self.delivery_errors),
        }


class AlertManager:
    """Evaluates rules, applies cooldowns and delivers notifications.

    Args:
        settings: Alerting configuration (channels, cooldown, severity floor).
        repository: SQLite repository used to persist rules and events.
        client: Optional pre-built HTTP client; one is created when omitted.
    """

    def __init__(
        self,
        settings: AlertsSettings,
        repository: SQLiteRepository,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self._client = client
        self._owns_client = client is None
        self._cooldowns: dict[str, float] = {}
        self._listeners: list[AlertListener] = []
        self._lock = asyncio.Lock()
        self._sent_count = 0
        self._suppressed_count = 0

    # -- lifecycle -----------------------------------------------------------

    async def start(self, *, seed_rules: bool = True) -> None:
        """Create the HTTP client and seed the default rule set."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=10.0, follow_redirects=True)
        if seed_rules:
            try:
                added = await self.repository.seed_default_rules(DEFAULT_RULES)
                if added:
                    logger.info("seeded %d default alert rule(s)", added)
            except Exception as exc:
                logger.warning("could not seed default alert rules: %s", exc)

    async def stop(self) -> None:
        """Close the HTTP client when this manager owns it."""
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    def subscribe(self, listener: AlertListener) -> Callable[[], None]:
        """Register a listener (web socket / SSE broadcast); returns an unsubscribe callable."""
        self._listeners.append(listener)

        def _unsubscribe() -> None:
            if listener in self._listeners:
                self._listeners.remove(listener)

        return _unsubscribe

    # -- evaluation ----------------------------------------------------------

    async def evaluate(
        self,
        health: OverallHealth,
        snapshot: SystemSnapshot | None = None,
    ) -> list[AlertRecord]:
        """Run both alert paths and dispatch everything not in cooldown."""
        if not self.settings.enabled:
            return []

        candidates: list[AlertRecord] = []
        candidates.extend(self._from_issues(health.issues))

        metrics = build_metric_map(health, snapshot) if snapshot is not None else build_metric_map(health)
        try:
            rules = await self.repository.list_alert_rules(enabled_only=True)
        except Exception as exc:
            logger.warning("could not load alert rules: %s", exc)
            rules = []
        candidates.extend(self._from_rules(rules, metrics))

        fired: list[AlertRecord] = []
        for record in candidates:
            if not self._meets_severity_floor(record.severity):
                continue
            if await self._in_cooldown(record.rule_name, record.severity):
                self._suppressed_count += 1
                continue
            await self._dispatch(record)
            fired.append(record)

        self._prune_cooldowns()
        return fired

    def _from_issues(self, issues: list[HealthIssue]) -> list[AlertRecord]:
        records: list[AlertRecord] = []
        for issue in issues:
            if issue.severity not in {"warning", "critical"}:
                continue
            records.append(
                AlertRecord(
                    rule_name=issue.issue_type,
                    severity=issue.severity,
                    message=issue.message,
                    metric=issue.metric or "",
                    value=issue.value,
                    payload={
                        "component": issue.component,
                        "details": issue.details,
                        "threshold": issue.threshold,
                        "evidence": issue.evidence,
                        "issue_key": issue.key,
                    },
                    created_at=issue.detected_at,
                )
            )
        return records

    def _from_rules(
        self,
        rules: Sequence[Mapping[str, Any]],
        metrics: Mapping[str, float | None],
    ) -> list[AlertRecord]:
        records: list[AlertRecord] = []
        for rule in rules:
            metric_name = str(rule.get("metric", ""))
            value = metrics.get(metric_name)
            if value is None:
                continue
            comparison = OPERATORS.get(str(rule.get("operator", ">")))
            if comparison is None:
                continue
            threshold = float(rule.get("threshold", 0.0))
            try:
                triggered = comparison(float(value), threshold)
            except (TypeError, ValueError):
                continue
            if not triggered:
                continue
            template = str(rule.get("message_template") or "")
            message = (
                template.format(
                    metric=metric_name, value=value, threshold=threshold, name=rule.get("name", "")
                )
                if template
                else f"{metric_name} is {float(value):.2f} (threshold {rule.get('operator')} {threshold:g})"
            )
            routing = tuple(
                label
                for label in (str(item).strip() for item in (rule.get("channels") or []))
                if label
            )
            records.append(
                AlertRecord(
                    rule_name=str(rule.get("name", metric_name)),
                    severity=str(rule.get("severity", "warning")),
                    message=message,
                    metric=metric_name,
                    value=float(value),
                    channels=routing,
                    payload={
                        "threshold": threshold,
                        "operator": rule.get("operator"),
                        "description": rule.get("description", ""),
                        "source": "rule",
                    },
                )
            )
        return records

    def _meets_severity_floor(self, severity: str) -> bool:
        floor = SEVERITY_ORDER.get(self.settings.min_severity, 1)
        return SEVERITY_ORDER.get(severity, 1) <= floor

    # -- cooldown ------------------------------------------------------------

    async def _in_cooldown(self, rule_name: str, severity: str) -> bool:
        async with self._lock:
            now = time.monotonic()
            last = self._cooldowns.get(rule_name)
            # Re-throttle alerts use a quarter of the configured cooldown so a
            # persistent critical problem still resurfaces.
            cooldown = float(self.settings.cooldown)
            if severity == "critical":
                cooldown = min(cooldown, max(30.0, cooldown / 4))
            if last is not None and (now - last) < cooldown:
                return True
            self._cooldowns[rule_name] = now
            return False

    def _prune_cooldowns(self) -> None:
        cutoff = max(float(self.settings.cooldown) * 4, 3600.0)
        now = time.monotonic()
        stale = [name for name, stamp in self._cooldowns.items() if now - stamp > cutoff]
        for name in stale:
            self._cooldowns.pop(name, None)

    def reset_cooldowns(self) -> None:
        """Clear cooldown state (used by tests and the manual 're-arm' action)."""
        self._cooldowns.clear()

    # -- delivery ------------------------------------------------------------

    @staticmethod
    def _channel_labels(channel: AlertChannel) -> set[str]:
        labels = {channel.type, channel.display_name()}
        if channel.url:
            labels.add(channel.url)
        return {label.strip().casefold() for label in labels if label and label.strip()}

    def _select_channels(self, routing: tuple[str, ...]) -> list[AlertChannel]:
        """Resolve rule routing labels to configured channels.

        An empty routing list means every enabled channel (the historical
        behaviour). Labels match a channel type, display name or URL. Unknown
        labels fall back to all enabled channels so a typo cannot silently
        drop a critical alert; a label that matches only disabled channels
        deliberately delivers nothing.
        """
        configured = list(self.settings.channels)
        requested = {label.strip().casefold() for label in routing if label and label.strip()}
        if not requested:
            return [channel for channel in configured if channel.enabled]

        matched = [channel for channel in configured if requested & self._channel_labels(channel)]
        if not matched:
            logger.warning(
                "alert routing labels %s matched no configured channels; using all enabled channels",
                ", ".join(sorted(requested)),
            )
            return [channel for channel in configured if channel.enabled]
        return [channel for channel in matched if channel.enabled]

    async def _dispatch(self, record: AlertRecord) -> None:
        errors: list[str] = []
        delivered = False

        channels = self._select_channels(record.channels)
        if record.channels and not channels:
            errors.append(
                "no enabled channel matched rule routing: " + ", ".join(record.channels)
            )
        for channel in channels:
            ok, error = await self._deliver(channel, record)
            delivered = delivered or ok
            if error:
                errors.append(error)

        record.delivered = delivered
        record.delivery_errors = errors
        self._sent_count += 1

        try:
            record.event_id = await self.repository.add_alert_event(
                rule_name=record.rule_name,
                severity=record.severity,
                message=record.message,
                metric=record.metric,
                value=record.value,
                payload=record.payload,
                delivered=delivered,
                delivery_errors=errors,
            )
        except Exception as exc:
            logger.warning("could not persist alert event: %s", exc)

        await self._notify_listeners(record)
        if errors:
            logger.warning("alert %s delivered with errors: %s", record.rule_name, "; ".join(errors))
        else:
            logger.info("alert fired: [%s] %s", record.severity, record.message)

    async def _deliver(self, channel: AlertChannel, record: AlertRecord) -> tuple[bool, str | None]:
        try:
            if channel.type == "log" or not channel.url:
                logger.warning("ALERT [%s] %s", record.severity, record.message)
                return True, None
            if self._client is None:
                return False, "http client unavailable"
            if channel.type in {"ntfy"}:
                return await self._send_ntfy(channel, record)
            if channel.type == "discord":
                return await self._send_discord(channel, record)
            return await self._send_webhook(channel, record)
        except httpx.HTTPError as exc:
            return False, f"{channel.type}: {type(exc).__name__}: {exc}"
        except Exception as exc:
            return False, f"{channel.type}: {type(exc).__name__}: {exc}"

    async def _send_ntfy(self, channel: AlertChannel, record: AlertRecord) -> tuple[bool, str | None]:
        assert self._client is not None
        priority = {"critical": "urgent", "warning": "high", "info": "default"}.get(record.severity, "default")
        headers = {
            "Title": f"NetMon {record.severity}: {record.rule_name}",
            "Priority": priority,
            "Tags": "netmon," + record.severity,
            **dict(channel.headers),
        }
        assert channel.url is not None
        response = await self._client.post(channel.url, content=record.message.encode(), headers=headers)
        return self._response_status(channel, response)

    async def _send_discord(self, channel: AlertChannel, record: AlertRecord) -> tuple[bool, str | None]:
        assert self._client is not None and channel.url is not None
        embed = {
            "title": f"NetMon {record.severity.upper()}: {record.rule_name}",
            "description": record.message,
            "fields": [
                {"name": "metric", "value": record.metric or "-", "inline": True},
                {
                    "name": "value",
                    "value": f"{record.value:.2f}" if record.value is not None else "-",
                    "inline": True,
                },
            ],
        }
        response = await self._client.post(
            channel.url, json={"embeds": [embed]}, headers=dict(channel.headers)
        )
        return self._response_status(channel, response)

    async def _send_webhook(self, channel: AlertChannel, record: AlertRecord) -> tuple[bool, str | None]:
        assert self._client is not None and channel.url is not None
        response = await self._client.post(
            channel.url, json=record.to_dict(), headers=dict(channel.headers)
        )
        return self._response_status(channel, response)

    @staticmethod
    def _response_status(channel: AlertChannel, response: httpx.Response) -> tuple[bool, str | None]:
        if response.status_code < 400:
            return True, None
        return False, f"{channel.type}: HTTP {response.status_code} from {channel.url}"

    async def _notify_listeners(self, record: AlertRecord) -> None:
        for listener in list(self._listeners):
            try:
                outcome = listener(record)
                if asyncio.iscoroutine(outcome):
                    await outcome
            except Exception as exc:
                logger.debug("alert listener failed: %s", exc)

    # -- introspection -------------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Counters used by the dashboard."""
        return {
            "enabled": self.settings.enabled,
            "sent": self._sent_count,
            "suppressed": self._suppressed_count,
            "active_cooldowns": len(self._cooldowns),
            "channels": [channel.display_name() for channel in self.settings.channels],
        }

    async def test_channel(self, channel: AlertChannel) -> tuple[bool, str | None]:
        """Send a synthetic alert to one channel (Settings screen action)."""
        probe = AlertRecord(
            rule_name="test-alert",
            severity="info",
            message="NetMon test alert: channel configuration is working.",
            metric="test",
            value=1.0,
        )
        return await self._deliver(channel, probe)


def build_metric_map(
    health: OverallHealth,
    snapshot: SystemSnapshot | None = None,
) -> dict[str, float | None]:
    """Flatten a health report (and optional snapshot) into rule-evaluable metrics."""
    metrics: dict[str, float | None] = {}
    if health.state != str(HealthState.UNKNOWN):
        # A score measured from no data would read as a critical failure, so it
        # is omitted entirely until at least one component can be evaluated.
        metrics["health.score"] = float(health.score)

    for component in health.components:
        for key, value in component.metrics.items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                metrics[f"{component.component}.{key}"] = float(value)

        for issue in component.issues:
            if issue.value is None:
                continue
            if issue.metric and issue.metric.startswith(component.component):
                metrics[issue.metric] = float(issue.value)
            else:
                metrics[f"{component.component}.{issue.issue_type}"] = float(issue.value)

    if snapshot is not None:
        connectivity = snapshot.connectivity or {}
        internet = connectivity.get("internet") or {}
        if internet.get("avg_latency_ms") is not None:
            metrics["connectivity.avg_latency_ms"] = float(internet["avg_latency_ms"])
        if internet.get("avg_packet_loss") is not None:
            metrics["connectivity.avg_packet_loss"] = float(internet["avg_packet_loss"])
        gateway = connectivity.get("gateway") or {}
        if gateway:
            metrics["connectivity.gateway.success"] = 1.0 if gateway.get("reachable") else 0.0
            if gateway.get("latency_ms") is not None:
                metrics["gateway.latency_ms"] = float(gateway["latency_ms"])
        dns_health = connectivity.get("dns_health") or {}
        if dns_health.get("failure_rate") is not None:
            metrics["dns.failure_rate"] = float(dns_health["failure_rate"])
        if dns_health.get("avg_latency_ms") is not None:
            metrics["dns.avg_latency_ms"] = float(dns_health["avg_latency_ms"])

        for name, info in (snapshot.bandwidth.get("interfaces") or {}).items():
            if isinstance(info, Mapping) and info.get("utilization_percent") is not None:
                metrics[f"bandwidth.{name}.utilization_percent"] = float(info["utilization_percent"])

        for name, info in (snapshot.interfaces.get("interfaces") or {}).items():
            if not isinstance(info, Mapping):
                continue
            metrics[f"interface.{name}.is_up"] = 1.0 if info.get("is_up") else 0.0

        for name, info in (snapshot.wifi.get("interfaces") or {}).items():
            if isinstance(info, Mapping) and info.get("signal_dbm") is not None:
                metrics[f"wifi.{name}.signal_dbm"] = float(info["signal_dbm"])

        for target, info in (snapshot.certificates.get("certificates") or {}).items():
            if isinstance(info, Mapping) and info.get("days_remaining") is not None:
                metrics[f"certificates.{target}.days_remaining"] = float(info["days_remaining"])

        summary = (snapshot.connections or {}).get("summary") or {}
        if summary.get("total") is not None:
            metrics["connections.total"] = float(summary["total"])

    return metrics


def utc() -> datetime:
    """Timezone-aware current UTC time (alias kept for symmetry)."""
    return datetime.now(UTC)


__all__ = ["DEFAULT_RULES", "OPERATORS", "AlertManager", "AlertRecord", "build_metric_map", "utc"]
