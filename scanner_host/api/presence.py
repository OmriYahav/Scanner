from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional

from scanner_host.auth.pairing import DeviceToken


HEARTBEAT_TIMEOUT = 30


@dataclass
class ConnectedDevice:
    device_id: str
    device_name: str
    token: str
    last_seen: float = field(default_factory=time.time)

    @property
    def online(self) -> bool:
        return (time.time() - self.last_seen) < HEARTBEAT_TIMEOUT


class PresenceRegistry:
    def __init__(self):
        self._devices: Dict[str, ConnectedDevice] = {}
        self._lock = Lock()

    def register(self, token: DeviceToken) -> ConnectedDevice:
        with self._lock:
            entry = ConnectedDevice(
                device_id=token.device_id,
                device_name=token.device_name,
                token=token.token,
            )
            self._devices[token.device_id] = entry
            return entry

    def heartbeat(self, device_id: str):
        with self._lock:
            if device_id in self._devices:
                self._devices[device_id].last_seen = time.time()

    def disconnect(self, device_id: str):
        with self._lock:
            if device_id in self._devices:
                self._devices[device_id].last_seen = 0

    def list_devices(self) -> List[Dict[str, object]]:
        with self._lock:
            return [
                {
                    "device_id": d.device_id,
                    "device_name": d.device_name,
                    "last_seen": d.last_seen,
                    "online": d.online,
                }
                for d in self._devices.values()
            ]

    def online_count(self) -> int:
        with self._lock:
            return sum(1 for d in self._devices.values() if d.online)


__all__ = ["PresenceRegistry", "ConnectedDevice", "HEARTBEAT_TIMEOUT"]
