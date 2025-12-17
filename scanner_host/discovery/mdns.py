from __future__ import annotations

import asyncio
import logging
import socket
from typing import Optional

from zeroconf import IPVersion, ServiceInfo, Zeroconf

from scanner_host.settings import HostSettings

LOGGER = logging.getLogger(__name__)


class MdnsAdvertiser:
    def __init__(self, settings: HostSettings):
        self.settings = settings
        self.zeroconf: Optional[Zeroconf] = None
        self.info: Optional[ServiceInfo] = None
        self.mdns_enabled = False

    async def start(self):
        desc = {
            "version": self.settings.version,
            "capabilities": ",".join(self.settings.capabilities),
            "api_port": str(self.settings.api_port),
        }
        service_type = "_netlinker._tcp.local."
        try:
            address_bytes = [socket.inet_aton(self.settings.host_ip)]
            interfaces = [self.settings.host_ip]
        except OSError:
            address_bytes = []
            interfaces = None
        self.info = ServiceInfo(
            service_type,
            f"{self.settings.service_instance_name}.{service_type}",
            addresses=address_bytes,
            port=self.settings.api_port,
            properties=desc,
            server=f"{self.settings.hostname}.local.",
        )
        try:
            self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only, interfaces=interfaces)
        except Exception:
            LOGGER.exception("Failed to initialize Zeroconf")
            self.mdns_enabled = False
            return
        for attempt in range(3):
            try:
                await asyncio.to_thread(self.zeroconf.register_service, self.info)
                self.mdns_enabled = True
                LOGGER.info(
                    "mDNS advertised as %s on %s:%s", service_type, self.settings.host_ip, self.settings.api_port
                )
                return
            except Exception:
                LOGGER.exception("Failed to start mDNS advertisement (attempt %s)", attempt + 1)
                await asyncio.sleep(0.5)
        self.mdns_enabled = False
        try:
            await asyncio.to_thread(self.zeroconf.close)
        except Exception:
            LOGGER.exception("Failed to close Zeroconf after failed advertisement")

    async def stop(self):
        if self.zeroconf and self.info:
            try:
                await asyncio.to_thread(self.zeroconf.unregister_service, self.info)
            except Exception:
                LOGGER.exception("Failed to unregister mDNS service")
            try:
                await asyncio.to_thread(self.zeroconf.close)
            except Exception:
                LOGGER.exception("Failed to close Zeroconf")
            self.zeroconf = None
            self.info = None
        self.mdns_enabled = False


__all__ = ["MdnsAdvertiser"]
