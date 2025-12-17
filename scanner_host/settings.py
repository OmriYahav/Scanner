from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import List


@dataclass
class HostSettings:
    api_port: int = 8000
    service_name: str = "NetLinker Host"
    version: str = "0.1.0"
    capabilities: List[str] = field(
        default_factory=lambda: ["pairing", "ws", "ping", "mdns"]
    )

    @property
    def hostname(self) -> str:
        return socket.gethostname()

    @property
    def service_instance_name(self) -> str:
        return f"{self.service_name} - {self.hostname}"

    @property
    def host_ip(self) -> str:
        try:
            # Attempt to derive a sensible LAN IP.
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            sock.close()
            return ip
        except Exception:
            return "127.0.0.1"


def get_settings() -> HostSettings:
    return HostSettings()


__all__ = ["HostSettings", "get_settings"]
