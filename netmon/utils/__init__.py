"""Cross-cutting utilities: async subprocesses, formatting and validation."""

from netmon.utils.async_cmd import CommandResult, run_command, run_commands, tool_available
from netmon.utils.formatting import (
    format_ago,
    format_bytes,
    format_duration,
    format_latency,
    format_percent,
    format_rate,
    format_timestamp,
    health_glyph,
    sparkline,
)
from netmon.utils.validation import (
    ValidationError,
    is_dangerous_command,
    validate_dotted_key,
    validate_fix_command,
    validate_host_port,
    validate_interface_name,
    validate_port_spec,
)

__all__ = [
    "CommandResult",
    "ValidationError",
    "format_ago",
    "format_bytes",
    "format_duration",
    "format_latency",
    "format_percent",
    "format_rate",
    "format_timestamp",
    "health_glyph",
    "is_dangerous_command",
    "run_command",
    "run_commands",
    "sparkline",
    "tool_available",
    "validate_dotted_key",
    "validate_fix_command",
    "validate_host_port",
    "validate_interface_name",
    "validate_port_spec",
]
