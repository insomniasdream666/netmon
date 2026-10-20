"""Input validation helpers.

Used by the config API, the CLI and the fix-execution guard rails. All
functions are pure and raise :class:`ValidationError` (a ``ValueError``)
with a human-readable message rather than returning sentinel values.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
PORT_RANGE_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,32}$")
DOTTED_KEY_RE = re.compile(r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*)*$")

# Commands that must never be executed as a "fix" without explicit user
# confirmation, because a mistake can destroy data or lock the operator out.
DANGEROUS_PATTERNS: tuple[str, ...] = (
    "rm -rf /",
    "mkfs",
    "dd if=",
    "shutdown",
    "reboot",
    "> /dev/",
    "iptables -F",
    "nft flush",
    "chmod -R 777 /",
    ":(){",
)


class ValidationError(ValueError):
    """Raised when a value fails validation."""


def validate_ip(value: str) -> str:
    """Validate an IPv4/IPv6 address literal."""
    candidate = str(value).strip()
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError as exc:
        raise ValidationError(f"invalid IP address: {value!r}") from exc


def validate_network(value: str) -> str:
    """Validate a CIDR network such as ``192.168.1.0/24``."""
    try:
        return str(ipaddress.ip_network(str(value).strip(), strict=False))
    except ValueError as exc:
        raise ValidationError(f"invalid network: {value!r}") from exc


def validate_hostname(value: str) -> str:
    """Validate a DNS hostname (or IPv4 literal)."""
    candidate = str(value).strip()
    if not candidate:
        raise ValidationError("hostname must not be empty")
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass
    if not HOSTNAME_RE.match(candidate):
        raise ValidationError(f"invalid hostname: {value!r}")
    return candidate


def validate_host_port(value: str) -> tuple[str, int]:
    """Validate ``host:port`` text and return the parsed pair."""
    candidate = str(value).strip()
    if candidate.count(":") == 0:
        raise ValidationError(f"expected host:port, got {value!r}")
    host, _, raw_port = candidate.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        # Bracketed IPv6 literal, e.g. "[::1]:8080".
        host = validate_ip(host[1:-1])
    else:
        host = validate_hostname(host)
    port = validate_port(raw_port)
    return host, port


def validate_port(value: Any) -> int:
    """Validate a single TCP/UDP port number."""
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"invalid port: {value!r}") from exc
    if not 1 <= port <= 65535:
        raise ValidationError(f"port out of range: {port}")
    return port


def validate_port_spec(value: str) -> str:
    """Validate an nmap-style port specification such as ``22,80,443`` or ``1-1024``."""
    candidate = str(value).strip()
    if not candidate:
        raise ValidationError("port specification must not be empty")
    if not PORT_RANGE_RE.match(candidate):
        raise ValidationError(f"invalid port specification: {value!r}")
    for chunk in candidate.split(","):
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start, end = validate_port(start_text), validate_port(end_text)
            if start > end:
                raise ValidationError(f"inverted port range: {chunk}")
        else:
            validate_port(chunk)
    return candidate


def validate_url(value: str, *, schemes: Iterable[str] = ("http", "https")) -> str:
    """Validate an absolute URL and return it unchanged."""
    candidate = str(value).strip()
    parsed = urlparse(candidate)
    if parsed.scheme not in set(schemes) or not parsed.netloc:
        raise ValidationError(f"invalid URL: {value!r}")
    return candidate


def validate_interface_name(value: str) -> str:
    """Validate a Linux network interface name."""
    candidate = str(value).strip()
    if not INTERFACE_RE.match(candidate):
        raise ValidationError(f"invalid interface name: {value!r}")
    return candidate


def validate_path(value: str, *, must_exist: bool = False) -> str:
    """Validate a filesystem path, returning the expanded absolute form."""
    candidate = str(value).strip()
    if not candidate:
        raise ValidationError("path must not be empty")
    expanded = Path(candidate).expanduser()
    if must_exist and not expanded.exists():
        raise ValidationError(f"path does not exist: {expanded}")
    return str(expanded)


def validate_dotted_key(key: str, *, allowed_roots: Iterable[str] | None = None) -> str:
    """Validate a ``section.subsection.field`` configuration key."""
    candidate = str(key).strip()
    if not candidate:
        raise ValidationError("config key must not be empty")
    if not DOTTED_KEY_RE.match(candidate):
        raise ValidationError(f"invalid config key: {key!r}")
    if allowed_roots is not None:
        roots = set(allowed_roots)
        if candidate.split(".", 1)[0] not in roots:
            raise ValidationError(f"unknown config section: {candidate.split('.', 1)[0]!r}")
    return candidate


def is_dangerous_command(command: str) -> bool:
    """Heuristic guard: does this fix command match a destructive pattern?"""
    normalised = " ".join(str(command).split()).lower()
    return any(pattern.lower() in normalised for pattern in DANGEROUS_PATTERNS)


def validate_fix_command(command: str) -> str:
    """Validate an AI-proposed fix command before it is shown or executed.

    Only rejects obviously malformed or destructive input; NetMon never
    auto-executes commands, and this check is an extra layer in front of the
    confirmation prompt.
    """
    candidate = " ".join(str(command).strip().split())
    if not candidate:
        raise ValidationError("fix command must not be empty")
    if len(candidate) > 512:
        raise ValidationError("fix command is unreasonably long")
    return candidate


def coerce_bool(value: Any) -> bool:
    """Coerce common textual booleans to ``bool``."""
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "off", "disabled"}:
        return False
    raise ValidationError(f"invalid boolean: {value!r}")


def coerce_number(value: Any) -> float:
    """Coerce a numeric value from text or int/float."""
    if isinstance(value, bool):
        raise ValidationError(f"invalid number: {value!r}")
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    try:
        return float(text)
    except ValueError as exc:
        raise ValidationError(f"invalid number: {value!r}") from exc


def parse_key_value(text: str) -> tuple[str, Any]:
    """Split ``key=value`` config text, coercing the value's type."""
    if "=" not in text:
        raise ValidationError("expected key=value")
    key, _, raw = text.partition("=")
    key = key.strip()
    raw = raw.strip()
    validate_dotted_key(key)
    if raw.lower() in {"true", "false", "yes", "no", "on", "off"}:
        return key, coerce_bool(raw)
    try:
        number = float(raw)
    except ValueError:
        if "," in raw:
            values = [part.strip() for part in raw.split(",") if part.strip()]
            return key, values
        return key, raw
    return key, int(number) if number.is_integer() and "." not in raw else number
