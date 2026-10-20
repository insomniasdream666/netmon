"""Network data collectors.

Each collector subclasses :class:`netmon.collectors.base.BaseCollector` and
returns a :class:`~netmon.collectors.base.CollectionResult` from ``collect()``.
:func:`create_collectors` is the factory used by the application composition
root; it builds every enabled collector and skips any whose optional system
dependency is missing on this host.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from netmon.collectors.base import BaseCollector, CollectionResult

if TYPE_CHECKING:  # pragma: no cover - import cycle guard for type checkers
    from netmon.config.settings import NetMonConfig
    from netmon.integrations.kali_tools import KaliTools

logger = logging.getLogger(__name__)

#: Collector names in the order they should be registered.
COLLECTOR_NAMES: tuple[str, ...] = (
    "interfaces",
    "connectivity",
    "bandwidth",
    "ports",
    "connections",
    "wifi",
    "certificates",
)


def create_collectors(
    config: NetMonConfig,
    tools: KaliTools | None = None,
) -> list[BaseCollector]:
    """Instantiate the collectors enabled in ``config``.

    Collectors whose module cannot be imported (for example because a system
    dependency is absent) are skipped with a warning instead of aborting
    start-up, so a partially capable host still runs NetMon.

    Args:
        config: Effective configuration, providing intervals, targets and the
            enabled collector list.
        tools: Shared :class:`~netmon.integrations.kali_tools.KaliTools`
            instance; one is created when omitted.

    Returns:
        Collector instances in :data:`COLLECTOR_NAMES` order.
    """
    from netmon.integrations.kali_tools import KaliTools as _KaliTools

    shared_tools = tools or _KaliTools()
    enabled = set(config.monitoring.enabled_collectors)

    factories: dict[str, str] = {
        "interfaces": "netmon.collectors.interfaces:InterfacesCollector",
        "connectivity": "netmon.collectors.connectivity:ConnectivityCollector",
        "bandwidth": "netmon.collectors.bandwidth:BandwidthCollector",
        "ports": "netmon.collectors.ports:PortsCollector",
        "connections": "netmon.collectors.connections:ConnectionsCollector",
        "wifi": "netmon.collectors.wifi:WifiCollector",
        "certificates": "netmon.collectors.certificates:CertificatesCollector",
    }

    collectors: list[BaseCollector] = []
    for name in COLLECTOR_NAMES:
        if name not in enabled:
            logger.debug("collector %s disabled by configuration", name)
            continue
        if name == "ports" and not config.monitoring.port_scan.enabled:
            logger.debug("port scanning disabled by configuration")
            continue
        target = factories.get(name)
        if target is None:
            continue
        try:
            module_name, class_name = target.split(":")
            module = __import__(module_name, fromlist=[class_name])
            collector_class = getattr(module, class_name)
            collector = collector_class(config, shared_tools)
        except Exception as exc:
            logger.warning("collector %s unavailable: %s", name, exc)
            continue
        collectors.append(collector)
    return collectors


__all__ = ["COLLECTOR_NAMES", "BaseCollector", "CollectionResult", "create_collectors"]
