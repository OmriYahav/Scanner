from __future__ import annotations

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

    def start(self):
        desc = {
            "version": self.settings.version,
            "capabilities": ",".join(self.settings.capabilities),
            "api_port": str(self.settings.api_port),
        }
        service_type = "_netlinker._tcp.local."
        try:
            address_bytes = [socket.inet_aton(self.settings.host_ip)]
        except OSError:
            address_bytes = []
        self.info = ServiceInfo(
            service_type,
            f"{self.settings.service_instance_name}.{service_type}",
            addresses=address_bytes,
            port=self.settings.api_port,
            properties=desc,
            server=f"{self.settings.hostname}.local.",
        )
        self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
        try:
            self.zeroconf.register_service(self.info)
            LOGGER.info(
                "mDNS advertised as %s on port %s", self.settings.service_instance_name, self.settings.api_port
            )
        except Exception:
            LOGGER.exception("Failed to start mDNS advertisement")

    def stop(self):
        if self.zeroconf and self.info:
            try:
                self.zeroconf.unregister_service(self.info)
            except Exception:
                LOGGER.exception("Failed to unregister mDNS service")
            self.zeroconf.close()
            self.zeroconf = None


__all__ = ["MdnsAdvertiser"]
