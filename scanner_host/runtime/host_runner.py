from __future__ import annotations

import asyncio
import logging
import threading
import time
from typing import Optional

import uvicorn

from scanner_host.api.app import build_app
from scanner_host.discovery.mdns import MdnsAdvertiser
from scanner_host.settings import HostSettings, get_settings

LOGGER = logging.getLogger(__name__)


class HostRuntime:
    """Lightweight controller to run the FastAPI host inside the GUI process."""

    def __init__(self, settings: Optional[HostSettings] = None):
        self.settings = settings or get_settings()
        self.advertiser = MdnsAdvertiser(self.settings)
        self._app = build_app(self.settings, self.advertiser)
        self._server: Optional[uvicorn.Server] = None
        self._thread: Optional[threading.Thread] = None
        self._started = False

    @property
    def base_url(self) -> str:
        return f"http://{self.settings.host_ip}:{self.settings.api_port}"

    def start(self) -> None:
        if self._started:
            return

        config = uvicorn.Config(
            self._app,
            host="0.0.0.0",
            port=self.settings.api_port,
            log_level="info",
            lifespan="on",
        )
        server = uvicorn.Server(config)
        server.install_signal_handlers = False
        self._server = server

        def _run() -> None:
            LOGGER.info("Starting embedded host at %s", self.base_url)
            asyncio.run(server.serve())

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        self._started = True

    def stop(self) -> None:
        if not self._started or not self._server:
            return
        LOGGER.info("Stopping embedded host")
        self._server.should_exit = True
        if self._thread:
            self._thread.join(timeout=5)
        self._started = False

    def run(self) -> None:
        """Start the host and block the current thread until interrupted."""

        self.start()
        try:
            while True:
                time.sleep(0.5)
        except KeyboardInterrupt:
            LOGGER.info("Interrupted; shutting down host")
        finally:
            self.stop()


__all__ = ["HostRuntime"]
