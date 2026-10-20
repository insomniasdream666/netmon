"""Connections collector: active sockets from ``ss`` (psutil fallback).

:meth:`KaliTools.ss_connections` returns structured :class:`SocketEntry`
objects for TCP and UDP sockets. The collector derives the contract's
``summary`` counters, bounded ``listening`` / ``established`` sample lists
(100 entries each) and the top remote addresses and processes (10 each) so
the payload stays small even on busy hosts.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from netmon.collectors.base import BaseCollector, CollectionResult
from netmon.config.settings import NetMonConfig
from netmon.integrations.kali_tools import KaliTools, SocketEntry

logger = logging.getLogger(__name__)

MEASUREMENT = "connections"
MAX_LIST_ENTRIES = 100
TOP_COUNT = 10
ESTABLISHED_STATES = {"ESTAB", "ESTABLISHED"}
LISTEN_STATES = {"LISTEN", "UNCONN"}
TIME_WAIT_STATES = {"TIME-WAIT", "TIME_WAIT"}


class ConnectionsCollector(BaseCollector):
    """Summarises active sockets and surfaces listeners and top talkers."""

    name = "connections"
    timeout = 20.0

    def __init__(self, config: NetMonConfig, tools: KaliTools | None = None) -> None:
        """Store configuration and the tool wrapper used for ``ss``."""
        super().__init__(interval=config.monitoring.interval_for(self.name))
        self.config = config
        self.tools = tools or KaliTools()

    async def collect(self) -> CollectionResult:
        """Collect sockets and build the summary plus sample lists."""
        result = self.result()
        now = datetime.now(UTC)
        entries = await self._socket_entries(result)

        if not entries:
            result.ok = False
            result.add_error("no socket data collected from ss or the psutil fallback")
            result.data.update(
                {
                    "summary": {
                        "total": 0,
                        "tcp": 0,
                        "udp": 0,
                        "unix": 0,
                        "established": 0,
                        "listen": 0,
                        "time_wait": 0,
                    },
                    "listening": [],
                    "established": [],
                    "top_remote": [],
                    "top_processes": [],
                }
            )
            return result

        summary = {
            "total": len(entries),
            "tcp": sum(1 for entry in entries if entry.protocol == "tcp"),
            "udp": sum(1 for entry in entries if entry.protocol == "udp"),
            "unix": sum(1 for entry in entries if entry.family == "unix"),
            "established": sum(1 for entry in entries if self._state(entry) in ESTABLISHED_STATES),
            "listen": sum(1 for entry in entries if self._state(entry) in LISTEN_STATES),
            "time_wait": sum(1 for entry in entries if self._state(entry) in TIME_WAIT_STATES),
        }
        result.data.update(
            {
                "summary": summary,
                "listening": [
                    self._listening_entry(entry)
                    for entry in entries
                    if self._state(entry) in LISTEN_STATES
                ][:MAX_LIST_ENTRIES],
                "established": [
                    self._established_entry(entry)
                    for entry in entries
                    if self._state(entry) in ESTABLISHED_STATES
                ][:MAX_LIST_ENTRIES],
                "top_remote": self._top_remote(entries),
                "top_processes": self._top_processes(entries),
            }
        )
        result.metrics.append(
            {
                "measurement": MEASUREMENT,
                "tags": {},
                "fields": {
                    "total": summary["total"],
                    "tcp": summary["tcp"],
                    "udp": summary["udp"],
                    "established": summary["established"],
                    "listen": summary["listen"],
                    "time_wait": summary["time_wait"],
                },
                "time": now,
            }
        )
        return result

    # -- payload helpers -----------------------------------------------------

    async def _socket_entries(self, result: CollectionResult) -> list[SocketEntry]:
        """Sockets via ``ss``, falling back to the KaliTools psutil path.

        Some ``ss`` peer formats (for example ``[::]:*``) can fail the shared
        parser; the documented psutil fallback keeps the sample usable and the
        parse problem is reported in ``result.errors``.
        """
        try:
            entries = await self.tools.ss_connections()
        except Exception as exc:
            logger.debug("ss socket parsing failed: %s", exc)
            result.add_error(f"ss parsing failed, using psutil fallback: {exc}")
            entries = []
        if entries:
            return entries
        # ``_psutil_connections`` is KaliTools' own documented fallback.
        return await asyncio.to_thread(self.tools._psutil_connections)

    @staticmethod
    def _state(entry: SocketEntry) -> str:
        """Upper-cased socket state, as reported by ``ss`` or psutil."""
        return entry.state.upper()

    @staticmethod
    def _listening_entry(entry: SocketEntry) -> dict[str, Any]:
        """One listener, in the contract's compact shape."""
        return {
            "protocol": entry.protocol,
            "local_address": entry.local_address,
            "local_port": entry.local_port,
            "process": entry.process,
            "pid": entry.pid,
            "family": entry.family,
        }

    @staticmethod
    def _established_entry(entry: SocketEntry) -> dict[str, Any]:
        """One established connection, including its remote endpoint."""
        return {
            "protocol": entry.protocol,
            "local_address": entry.local_address,
            "local_port": entry.local_port,
            "remote_address": entry.remote_address,
            "remote_port": entry.remote_port,
            "state": entry.state,
            "process": entry.process,
            "pid": entry.pid,
            "family": entry.family,
        }

    @staticmethod
    def _top_remote(entries: list[SocketEntry]) -> list[dict[str, Any]]:
        """Ten remote addresses with the most established connections."""
        counts: Counter[str] = Counter()
        for entry in entries:
            if entry.remote_address and entry.state.upper() in ESTABLISHED_STATES:
                counts[entry.remote_address] += 1
        ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:TOP_COUNT]
        return [{"address": address, "count": count} for address, count in ordered]

    @staticmethod
    def _top_processes(entries: list[SocketEntry]) -> list[dict[str, Any]]:
        """Ten processes holding the most sockets."""
        counts: Counter[tuple[str, int]] = Counter()
        for entry in entries:
            if entry.process:
                counts[(entry.process, int(entry.pid or 0))] += 1
        ordered = sorted(
            counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1])
        )[:TOP_COUNT]
        return [
            {"name": name, "pid": pid or None, "connections": count}
            for (name, pid), count in ordered
        ]


__all__ = ["ConnectionsCollector"]
