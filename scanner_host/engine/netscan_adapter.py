"""Adapter around the legacy scan engine functions.

This module keeps legacy scanning functionality intact while offering
lightweight helpers that can be reused by the FastAPI host. Any
behavioral changes should be implemented here rather than in the shared
engine module to avoid breaking the standalone experience.
"""
from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional

from scanner_host.engine.netscan_core import (
    get_active_ipv4_interfaces,
    ping,
)


class NetworkInterfaces:
    """Expose utilities to list interfaces using the legacy helper."""

    @staticmethod
    def active_ipv4() -> List[Dict[str, str]]:
        return get_active_ipv4_interfaces()


def ping_host(target: str) -> Optional[float]:
    """Ping a target using the same implementation as ``netscan``.

    Args:
        target: IPv4 address or hostname.

    Returns:
        RTT in milliseconds if the host responds, otherwise ``None``.
    """

    try:
        rtt = ping(target, timeout=2)
    except Exception:
        return None
    if rtt is None:
        return None
    # ``ping`` returns seconds; convert to ms for API consumers.
    return float(rtt) * 1000.0


def normalize_cidr(ip: str, prefix: int) -> str:
    """Normalize an address/prefix pair into CIDR notation."""

    try:
        net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        return str(net)
    except Exception:
        return f"{ip}/{prefix}"


__all__ = ["NetworkInterfaces", "ping_host", "normalize_cidr"]
