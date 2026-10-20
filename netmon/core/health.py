"""Health evaluation: turns raw collector output into states, scores and issues.

The checker is deliberately pure: it receives a :class:`SystemSnapshot` (the
merged output of the collectors) and returns an :class:`OverallHealth`
containing per-component results, a weighted 0-100 score and the list of
:class:`HealthIssue` objects that the alert manager and diagnostic engine
consume downstream.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from netmon.config.settings import HealthSettings

logger = logging.getLogger(__name__)


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(UTC)


class HealthState(StrEnum):
    """Branding states shared by the TUI, web UI and alerts."""

    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

    @property
    def glyph(self) -> str:
        """Signal glyph used throughout the UI."""
        return {
            HealthState.OK: "\u25cf",
            HealthState.WARNING: "\u25d0",
            HealthState.CRITICAL: "\u25cf",
            HealthState.UNKNOWN: "\u25cb",
        }[self]

    @classmethod
    def from_score(cls, score: float, warning: float = 80.0, critical: float = 50.0) -> HealthState:
        """Classify a 0-100 score into a state."""
        if score >= warning:
            return cls.OK
        if score >= critical:
            return cls.WARNING
        return cls.CRITICAL


SEVERITY_WEIGHT: dict[str, float] = {"ok": 0.0, "warning": 1.0, "critical": 2.0}


@dataclass(slots=True)
class HealthIssue:
    """A single detected problem, the unit of work for the diagnostic engine."""

    issue_type: str
    component: str
    message: str
    severity: str = "warning"
    details: dict[str, Any] = field(default_factory=dict)
    metric: str | None = None
    value: float | None = None
    threshold: float | None = None
    evidence: list[str] = field(default_factory=list)
    suggested_checks: list[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=utcnow)

    @property
    def key(self) -> str:
        """Stable identity used for alert cooldown and issue de-duplication."""
        fingerprint = f"{self.issue_type}|{self.component}|{self.metric or ''}"
        digest = hashlib.sha1(fingerprint.encode(), usedforsecurity=False).hexdigest()[:12]
        return f"{self.issue_type}:{self.component}:{digest}"

    @property
    def severity_rank(self) -> int:
        """0 for critical, 1 for warning, 2 otherwise."""
        return {"critical": 0, "warning": 1}.get(self.severity, 2)

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the TUI, REST API and diagnostic history."""
        return {
            "key": self.key,
            "issue_type": self.issue_type,
            "component": self.component,
            "message": self.message,
            "severity": self.severity,
            "details": dict(self.details),
            "metric": self.metric,
            "value": self.value,
            "threshold": self.threshold,
            "evidence": list(self.evidence),
            "suggested_checks": list(self.suggested_checks),
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass(slots=True)
class HealthCheckResult:
    """Health of one component (interfaces, dns, wifi, ...)."""

    component: str
    state: str
    score: float
    message: str
    issues: list[HealthIssue] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    checked_at: datetime = field(default_factory=utcnow)

    @property
    def has_issues(self) -> bool:
        """True when at least one issue was detected."""
        return bool(self.issues)

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the API/TUI."""
        return {
            "component": self.component,
            "state": self.state,
            "score": round(self.score, 2),
            "message": self.message,
            "issues": [issue.to_dict() for issue in self.issues],
            "metrics": self.metrics,
            "checked_at": self.checked_at.isoformat(),
        }


@dataclass(slots=True)
class OverallHealth:
    """Aggregate health across all components."""

    score: float
    state: str
    components: list[HealthCheckResult] = field(default_factory=list)
    issues: list[HealthIssue] = field(default_factory=list)
    checked_at: datetime = field(default_factory=utcnow)

    def component(self, name: str) -> HealthCheckResult | None:
        """Look up one component result by name."""
        for result in self.components:
            if result.component == name:
                return result
        return None

    def issues_of(self, severity: str) -> list[HealthIssue]:
        """All issues with the given severity."""
        return [issue for issue in self.issues if issue.severity == severity]

    def to_dict(self) -> dict[str, Any]:
        """Serialise for the API/TUI."""
        return {
            "score": round(self.score, 2),
            "state": self.state,
            "issues": [issue.to_dict() for issue in self.issues],
            "components": [component.to_dict() for component in self.components],
            "checked_at": self.checked_at.isoformat(),
        }


@dataclass(slots=True)
class SystemSnapshot:
    """Merged collector output consumed by :class:`HealthChecker`.

    Keys mirror the collector ``data`` payloads documented in
    ``docs/COLLECTOR_CONTRACT.md``.
    """

    interfaces: Mapping[str, Any] = field(default_factory=dict)
    connectivity: Mapping[str, Any] = field(default_factory=dict)
    bandwidth: Mapping[str, Any] = field(default_factory=dict)
    ports: Mapping[str, Any] = field(default_factory=dict)
    connections: Mapping[str, Any] = field(default_factory=dict)
    wifi: Mapping[str, Any] = field(default_factory=dict)
    certificates: Mapping[str, Any] = field(default_factory=dict)
    errors: dict[str, list[str]] = field(default_factory=dict)
    collected_at: datetime = field(default_factory=utcnow)

    def collector_errors(self) -> dict[str, list[str]]:
        """Errors keyed by collector name."""
        return {name: list(items) for name, items in self.errors.items() if items}


class HealthChecker:
    """Evaluate a :class:`SystemSnapshot` against configured thresholds.

    Args:
        settings: Health settings providing thresholds and component weights.
    """

    def __init__(self, settings: HealthSettings) -> None:
        self.settings = settings

    @property
    def thresholds(self) -> Any:
        """Configured thresholds (shortcut)."""
        return self.settings.thresholds

    # -- public API ----------------------------------------------------------

    def evaluate(self, snapshot: SystemSnapshot) -> OverallHealth:
        """Evaluate every component and compute the weighted overall score."""
        components = [
            self._check_interfaces(snapshot.interfaces),
            self._check_connectivity(snapshot.connectivity),
            self._check_dns(snapshot.connectivity),
            self._check_bandwidth(snapshot.bandwidth),
            self._check_wifi(snapshot.wifi),
            self._check_certificates(snapshot.certificates),
            self._check_connections(snapshot.connections),
        ]
        issues = [issue for component in components for issue in component.issues]
        issues.sort(key=lambda issue: (issue.severity_rank, issue.component))

        score = self._weighted_score(components)
        if all(component.state == str(HealthState.UNKNOWN) for component in components):
            # Nothing has been measured yet: a zero score is meaningless, so
            # report "unknown" instead of reading as a critical failure.
            state = HealthState.UNKNOWN
        else:
            state = HealthState.from_score(
                score, self.thresholds.health_score_warning, self.thresholds.health_score_critical
            )
        return OverallHealth(
            score=score,
            state=str(state),
            components=components,
            issues=issues,
            checked_at=snapshot.collected_at,
        )

    def _weighted_score(self, components: list[HealthCheckResult]) -> float:
        weights = self.settings.weights
        total_weight = 0.0
        accumulated = 0.0
        for component in components:
            if component.state == str(HealthState.UNKNOWN):
                continue
            weight = float(weights.get(component.component, 1.0))
            if weight <= 0:
                continue
            accumulated += component.score * weight
            total_weight += weight
        if total_weight == 0:
            return 0.0
        return max(0.0, min(100.0, accumulated / total_weight))

    # -- component checks ----------------------------------------------------

    def _check_interfaces(self, data: Mapping[str, Any]) -> HealthCheckResult:
        interfaces = data.get("interfaces") or {}
        if not interfaces:
            return self._unknown("interfaces", "no interface data collected")

        issues: list[HealthIssue] = []
        scored: list[float] = []
        up_count = 0

        for name, info in sorted(interfaces.items()):
            if not isinstance(info, Mapping):
                continue
            if info.get("is_loopback"):
                continue
            is_up = bool(info.get("is_up"))
            if is_up:
                up_count += 1

            errors = int(info.get("rx_errors") or 0) + int(info.get("tx_errors") or 0)
            dropped = int(info.get("rx_dropped") or 0) + int(info.get("tx_dropped") or 0)

            if not is_up:
                issues.append(
                    HealthIssue(
                        issue_type="interface_down",
                        component="interfaces",
                        message=f"Interface {name} is down",
                        severity="critical",
                        details={"interface": name, "state": info.get("state")},
                        metric=f"interface.{name}.is_up",
                        evidence=[f"{name}: down", f"addresses: {info.get('ipv4') or []}"],
                        suggested_checks=[
                            f"ip link show {name}",
                            "journalctl -u NetworkManager --since='10 min ago' --no-pager",
                        ],
                    )
                )
                scored.append(0.0)
                continue

            if errors >= self.thresholds.interface_error_critical:
                severity, penalty = "critical", 25.0
            elif errors >= self.thresholds.interface_error_warning:
                severity, penalty = "warning", 60.0
            else:
                severity, penalty = None, 100.0

            if severity:
                issues.append(
                    HealthIssue(
                        issue_type="interface_errors",
                        component="interfaces",
                        message=f"Interface {name} reports {errors} errors, {dropped} drops",
                        severity=severity,
                        details={"interface": name, "rx_errors": info.get("rx_errors"),
                                  "tx_errors": info.get("tx_errors"), "dropped": dropped},
                        metric=f"interface.{name}.errors",
                        value=float(errors),
                        threshold=float(self.thresholds.interface_error_warning),
                        evidence=[f"{name}: errors={errors} dropped={dropped}"],
                        suggested_checks=[
                            f"ip -s link show {name}",
                            f"ethtool -S {name}",
                        ],
                    )
                )
            scored.append(penalty)

        if not scored:
            return self._unknown("interfaces", "only loopback interfaces present")

        score = sum(scored) / len(scored)
        state = HealthState.from_score(
            score, self.thresholds.health_score_warning, self.thresholds.health_score_critical
        )
        message = f"{up_count} of {len(scored)} interface(s) up"
        return HealthCheckResult(
            component="interfaces",
            state=str(state),
            score=score,
            message=message,
            issues=issues,
            metrics={"up": up_count, "total": len(scored)},
        )

    def _check_connectivity(self, data: Mapping[str, Any]) -> HealthCheckResult:
        ping = data.get("ping") or {}
        gateway = data.get("gateway") or {}
        internet = data.get("internet") or {}
        if not ping and not gateway and not internet:
            return self._unknown("connectivity", "no connectivity data collected")

        issues: list[HealthIssue] = []
        penalties: list[float] = []

        if gateway:
            if not gateway.get("reachable"):
                issues.append(
                    HealthIssue(
                        issue_type="gateway_unreachable",
                        component="connectivity",
                        message=f"Default gateway {gateway.get('gateway') or 'unknown'} is unreachable",
                        severity="critical",
                        details=dict(gateway),
                        metric="connectivity.gateway.latency_ms",
                        value=gateway.get("latency_ms"),
                        evidence=[
                            f"gateway={gateway.get('gateway') or 'unknown'}",
                            f"packet_loss={gateway.get('packet_loss')}%",
                        ],
                        suggested_checks=[
                            "ip route show",
                            "arp -an",
                            "ping -c 3 $(ip route | awk '/default/ {print $3; exit}')",
                        ],
                    )
                )
                penalties.append(0.0)
            else:
                penalties.append(100.0)

        for target, info in sorted(ping.items()):
            if not isinstance(info, Mapping):
                continue
            loss = float(info.get("packet_loss") or 0.0)
            latency = info.get("latency_ms")
            if not info.get("success"):
                issues.append(
                    HealthIssue(
                        issue_type="internet_unreachable",
                        component="connectivity",
                        message=f"Ping to {target} failed",
                        severity="critical",
                        details={"target": target, **dict(info)},
                        metric=f"connectivity.{target}.success",
                        value=0.0,
                        evidence=[f"{target}: loss={loss}%"],
                        suggested_checks=[
                            "ip route show",
                            "resolvectl status",
                            f"ping -c 3 {target}",
                        ],
                    )
                )
                penalties.append(0.0)
                continue

            if loss >= self.thresholds.packet_loss_critical:
                severity, penalty = "critical", 20.0
            elif loss >= self.thresholds.packet_loss_warning:
                severity, penalty = "warning", 65.0
            else:
                penalty = 100.0
                severity = ""

            if latency is None:
                scored = penalty
            elif float(latency) >= self.thresholds.latency_critical:
                severity, scored = "critical", min(penalty, 30.0)
            elif float(latency) >= self.thresholds.latency_warning:
                severity, scored = "warning", min(penalty, 70.0)
            else:
                scored = penalty

            if severity:
                issues.append(
                    HealthIssue(
                        issue_type="packet_loss_high" if loss >= self.thresholds.packet_loss_warning else "latency_high",
                        component="connectivity",
                        message=(
                            f"{target}: {float(latency):.1f} ms latency, {loss:.1f}% loss"
                            if latency is not None
                            else f"{target}: {loss:.1f}% packet loss"
                        ),
                        severity=severity,
                        details={"target": target, **dict(info)},
                        metric=f"connectivity.{target}.latency_ms",
                        value=float(latency) if latency is not None else loss,
                        threshold=float(self.thresholds.latency_warning),
                        evidence=[f"latency={latency} ms", f"loss={loss}%"],
                        suggested_checks=[
                            "ping -c 10 8.8.8.8",
                            "mtr --report --report-cycles 10 8.8.8.8",
                        ],
                    )
                )
            penalties.append(scored)

        if not penalties:
            return self._unknown("connectivity", "no reachable targets configured")

        score = sum(penalties) / len(penalties)
        state = HealthState.from_score(
            score, self.thresholds.health_score_warning, self.thresholds.health_score_critical
        )
        avg_latency = internet.get("avg_latency_ms")
        message = (
            f"avg latency {float(avg_latency):.1f} ms" if avg_latency is not None else "connectivity unknown"
        )
        return HealthCheckResult(
            component="connectivity",
            state=str(state),
            score=score,
            message=message,
            issues=issues,
            metrics={
                "avg_latency_ms": avg_latency,
                "avg_packet_loss": internet.get("avg_packet_loss"),
                "targets_ok": internet.get("targets_ok"),
                "targets_total": internet.get("targets_total"),
            },
        )

    def _check_dns(self, data: Mapping[str, Any]) -> HealthCheckResult:
        dns = data.get("dns") or {}
        health = data.get("dns_health") or {}
        if not dns:
            return self._unknown("dns", "no DNS data collected")

        issues: list[HealthIssue] = []
        failure_rate = float(health.get("failure_rate") or 0.0)
        avg_latency = health.get("avg_latency_ms")
        failed = [name for name, info in dns.items() if isinstance(info, Mapping) and not info.get("success")]

        if failure_rate >= self.thresholds.dns_failure_critical or (
            failed and len(failed) == len(dns)
        ):
            severity, score = "critical", 10.0
        elif failure_rate >= self.thresholds.dns_failure_warning:
            severity, score = "warning", 60.0
        elif avg_latency is not None and float(avg_latency) >= self.thresholds.dns_latency_critical:
            severity, score = "critical", 35.0
        elif avg_latency is not None and float(avg_latency) >= self.thresholds.dns_latency_warning:
            severity, score = "warning", 75.0
        else:
            severity, score = "", 100.0

        if severity:
            failed_text = ", ".join(failed) if failed else "none"
            issues.append(
                HealthIssue(
                    issue_type="dns_failure" if failed else "dns_latency_high",
                    component="dns",
                    message=(
                        f"DNS resolution failing for {failed_text}"
                        if failed
                        else f"DNS latency {float(avg_latency):.0f} ms is above threshold"
                        if avg_latency is not None
                        else "DNS health degraded"
                    ),
                    severity=severity,
                    details={"failure_rate": failure_rate, "failed": failed, "dns": dict(dns)},
                    metric="connectivity.dns.latency_ms",
                    value=float(avg_latency) if avg_latency is not None else failure_rate,
                    threshold=float(self.thresholds.dns_latency_warning),
                    evidence=[f"failure_rate={failure_rate}%", f"avg_latency={avg_latency} ms"],
                    suggested_checks=[
                        "resolvectl status",
                        "cat /etc/resolv.conf",
                        "dig +short google.com @1.1.1.1",
                    ],
                )
            )

        state = HealthState.from_score(
            score, self.thresholds.health_score_warning, self.thresholds.health_score_critical
        )
        return HealthCheckResult(
            component="dns",
            state=str(state),
            score=score,
            message=(
                f"avg {float(avg_latency):.0f} ms, {failure_rate:.0f}% failures"
                if avg_latency is not None
                else f"{failure_rate:.0f}% failures"
            ),
            issues=issues,
            metrics={"avg_latency_ms": avg_latency, "failure_rate": failure_rate},
        )

    def _check_bandwidth(self, data: Mapping[str, Any]) -> HealthCheckResult:
        interfaces = data.get("interfaces") or {}
        if not interfaces:
            return self._unknown("bandwidth", "no bandwidth data collected")

        issues: list[HealthIssue] = []
        utilizations: list[float] = []
        for name, info in sorted(interfaces.items()):
            if not isinstance(info, Mapping):
                continue
            util = info.get("utilization_percent")
            if util is None:
                continue
            util = float(util)
            utilizations.append(util)
            if util >= self.thresholds.bandwidth_util_critical:
                severity, score = "critical", 25.0
            elif util >= self.thresholds.bandwidth_util_warning:
                severity, score = "warning", 70.0
            else:
                severity, score = "", 100.0
            if severity:
                issues.append(
                    HealthIssue(
                        issue_type="bandwidth_saturated",
                        component="bandwidth",
                        message=f"{name} at {util:.0f}% of link capacity",
                        severity=severity,
                        details={"interface": name, **dict(info)},
                        metric=f"bandwidth.{name}.utilization_percent",
                        value=util,
                        threshold=float(self.thresholds.bandwidth_util_warning),
                        evidence=[
                            f"rx={info.get('rx_bytes_per_sec')} B/s",
                            f"tx={info.get('tx_bytes_per_sec')} B/s",
                        ],
                        suggested_checks=[
                            "ss -tunap | head -40",
                            f"nload {name}" if name else "nload",
                        ],
                    )
                )

        if not utilizations:
            return self._unknown("bandwidth", "link speed unknown, utilization not measurable")

        score = sum(
            25.0
            if util >= self.thresholds.bandwidth_util_critical
            else 70.0
            if util >= self.thresholds.bandwidth_util_warning
            else 100.0
            for util in utilizations
        ) / len(utilizations)
        state = HealthState.from_score(
            score, self.thresholds.health_score_warning, self.thresholds.health_score_critical
        )
        peak = max(utilizations)
        return HealthCheckResult(
            component="bandwidth",
            state=str(state),
            score=score,
            message=f"peak utilization {peak:.0f}%",
            issues=issues,
            metrics={"peak_utilization": peak, "interfaces": len(utilizations)},
        )

    def _check_wifi(self, data: Mapping[str, Any]) -> HealthCheckResult:
        if not data or data.get("has_wifi") is False:
            return HealthCheckResult(
                component="wifi",
                state=str(HealthState.UNKNOWN),
                score=0.0,
                message="no wireless interface present",
                metrics={"has_wifi": False},
            )
        interfaces = data.get("interfaces") or {}
        if not interfaces:
            return self._unknown("wifi", "wireless interface present but no data")

        issues: list[HealthIssue] = []
        scores: list[float] = []
        for name, info in sorted(interfaces.items()):
            if not isinstance(info, Mapping):
                continue
            if not info.get("connected"):
                issues.append(
                    HealthIssue(
                        issue_type="wifi_disconnected",
                        component="wifi",
                        message=f"{name} is not associated with an access point",
                        severity="warning",
                        details={"interface": name, **dict(info)},
                        metric=f"wifi.{name}.connected",
                        value=0.0,
                        evidence=[f"{name}: not connected", f"error={info.get('error')}"],
                        suggested_checks=[
                            "nmcli device status",
                            f"iw dev {name} link",
                            "journalctl -u NetworkManager --since='10 min ago' --no-pager",
                        ],
                    )
                )
                scores.append(40.0)
                continue

            signal = info.get("signal_dbm")
            if signal is None:
                scores.append(100.0)
                continue
            signal = int(signal)
            if signal <= self.thresholds.wifi_signal_critical:
                severity, score = "critical", 30.0
            elif signal <= self.thresholds.wifi_signal_warning:
                severity, score = "warning", 65.0
            else:
                severity, score = "", 100.0

            if severity:
                issues.append(
                    HealthIssue(
                        issue_type="wifi_weak_signal",
                        component="wifi",
                        message=f"{name} signal {signal} dBm is weak (SSID {info.get('ssid')})",
                        severity=severity,
                        details={"interface": name, **dict(info)},
                        metric=f"wifi.{name}.signal_dbm",
                        value=float(signal),
                        threshold=float(self.thresholds.wifi_signal_warning),
                        evidence=[
                            f"signal={signal} dBm",
                            f"bitrate={info.get('bitrate_mbps')} Mbps",
                            f"channel={info.get('channel')}",
                        ],
                        suggested_checks=[
                            "iw dev " + str(name) + " link",
                            "nmcli -f IN-USE,SSID,SIGNAL,CHAN device wifi list",
                        ],
                    )
                )
            scores.append(score)

        if not scores:
            return self._unknown("wifi", "no wireless metrics available")
        score = sum(scores) / len(scores)
        state = HealthState.from_score(
            score, self.thresholds.health_score_warning, self.thresholds.health_score_critical
        )
        return HealthCheckResult(
            component="wifi",
            state=str(state),
            score=score,
            message=f"{len(scores)} wireless interface(s) monitored",
            issues=issues,
            metrics={"interfaces": len(scores)},
        )

    def _check_certificates(self, data: Mapping[str, Any]) -> HealthCheckResult:
        certificates = data.get("certificates") or {}
        if not certificates:
            return self._unknown("certificates", "no certificate data collected")

        issues: list[HealthIssue] = []
        scores: list[float] = []
        for target, info in sorted(certificates.items()):
            if not isinstance(info, Mapping):
                continue
            if info.get("error"):
                scores.append(50.0)
                continue
            days = info.get("days_remaining")
            if info.get("expired") or (days is not None and int(days) < 0):
                issues.append(
                    HealthIssue(
                        issue_type="cert_expired",
                        component="certificates",
                        message=f"TLS certificate for {target} has expired",
                        severity="critical",
                        details={"target": target, **dict(info)},
                        metric=f"certificates.{target}.days_remaining",
                        value=float(days or 0),
                        threshold=0.0,
                        evidence=[f"not_after={info.get('not_after')}"],
                        suggested_checks=[
                            f"openssl s_client -connect {target} -servername {info.get('host')} </dev/null 2>/dev/null | openssl x509 -noout -dates",
                        ],
                    )
                )
                scores.append(0.0)
                continue
            if days is None:
                scores.append(75.0)
                continue
            days = int(days)
            if days <= self.thresholds.cert_expiry_critical_days:
                severity, score = "critical", 25.0
            elif days <= self.thresholds.cert_expiry_warning_days:
                severity, score = "warning", 70.0
            else:
                severity, score = "", 100.0
            if severity:
                issues.append(
                    HealthIssue(
                        issue_type="cert_expiring",
                        component="certificates",
                        message=f"TLS certificate for {target} expires in {days} days",
                        severity=severity,
                        details={"target": target, **dict(info)},
                        metric=f"certificates.{target}.days_remaining",
                        value=float(days),
                        threshold=float(self.thresholds.cert_expiry_warning_days),
                        evidence=[f"not_after={info.get('not_after')}", f"issuer={info.get('issuer')}"],
                        suggested_checks=[
                            f"openssl s_client -connect {target} -servername {info.get('host')} </dev/null 2>/dev/null | openssl x509 -noout -dates -issuer",
                        ],
                    )
                )
            scores.append(score)

        if not scores:
            return self._unknown("certificates", "no parseable certificates")
        score = sum(scores) / len(scores)
        state = HealthState.from_score(
            score, self.thresholds.health_score_warning, self.thresholds.health_score_critical
        )
        soonest = min(
            (
                int(info["days_remaining"])
                for info in certificates.values()
                if isinstance(info, Mapping) and info.get("days_remaining") is not None
            ),
            default=None,
        )
        return HealthCheckResult(
            component="certificates",
            state=str(state),
            score=score,
            message=f"{len(scores)} certificate(s), soonest expiry in {soonest} days"
            if soonest is not None
            else f"{len(scores)} certificate(s) monitored",
            issues=issues,
            metrics={"checked": len(scores), "soonest_expiry_days": soonest},
        )

    def _check_connections(self, data: Mapping[str, Any]) -> HealthCheckResult:
        summary = data.get("summary") or {}
        if not summary:
            return self._unknown("connections", "no connection data collected")

        total = int(summary.get("total") or 0)
        issues: list[HealthIssue] = []
        if total >= self.thresholds.connection_count_warning:
            issues.append(
                HealthIssue(
                    issue_type="connection_overload",
                    component="connections",
                    message=f"{total} active connections exceeds the configured ceiling",
                    severity="warning",
                    details=dict(summary),
                    metric="connections.total",
                    value=float(total),
                    threshold=float(self.thresholds.connection_count_warning),
                    evidence=[f"established={summary.get('established')}", f"listen={summary.get('listen')}"],
                    suggested_checks=["ss -tunap | wc -l", "ss -tunap | sort | head -30"],
                )
            )
            score = 70.0
        else:
            score = 100.0

        state = HealthState.from_score(
            score, self.thresholds.health_score_warning, self.thresholds.health_score_critical
        )
        return HealthCheckResult(
            component="connections",
            state=str(state),
            score=score,
            message=f"{total} connections ({summary.get('established', 0)} established)",
            issues=issues,
            metrics=dict(summary),
        )

    @staticmethod
    def _unknown(component: str, message: str) -> HealthCheckResult:
        return HealthCheckResult(
            component=component,
            state=str(HealthState.UNKNOWN),
            score=0.0,
            message=message,
        )


__all__ = [
    "HealthCheckResult",
    "HealthChecker",
    "HealthIssue",
    "HealthState",
    "OverallHealth",
    "SystemSnapshot",
]
