from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRouter
from fastapi.staticfiles import StaticFiles

from scanner_host.auth.pairing import DeviceToken, PairingManager
from scanner_host.api.presence import HEARTBEAT_TIMEOUT, PresenceRegistry
from scanner_host.discovery.mdns import MdnsAdvertiser
from scanner_host.engine.netscan_adapter import ping_host
from scanner_host.settings import HostSettings

LOGGER = logging.getLogger(__name__)

router = APIRouter()


def get_pairing_manager() -> PairingManager:
    return router._pairing_manager  # type: ignore[attr-defined]


def get_presence_registry() -> PresenceRegistry:
    return router._presence_registry  # type: ignore[attr-defined]


def auth_dependency(
    authorization: Optional[str] = Header(default=None, convert_underscores=False),
    pairing_manager: PairingManager = Depends(get_pairing_manager),
) -> DeviceToken:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    data = pairing_manager.validate_token(token)
    if not data:
        raise HTTPException(status_code=401, detail="Invalid token")
    return data


@router.get("/status")
def status(settings: HostSettings = Depends(lambda: router._settings), presence: PresenceRegistry = Depends(get_presence_registry)):
    return {
        "service_name": settings.service_name,
        "service_instance": settings.service_instance_name,
        "version": settings.version,
        "hostname": settings.hostname,
        "host_name": settings.hostname,
        "ip": settings.host_ip,
        "api_port": settings.api_port,
        "capabilities": settings.capabilities,
        "connected": presence.online_count(),
        "devices": presence.list_devices(),
    }


@router.post("/pair/start")
def start_pairing(pairing: PairingManager = Depends(get_pairing_manager)):
    session = pairing.start_pairing()
    return {
        "pairing_id": session.pairing_id,
        "expires_at": session.expires_at,
        "expires_in": session.expires_in,
    }


@router.get("/pair/code")
def get_pairing_code(pairing: PairingManager = Depends(get_pairing_manager)):
    session = pairing.active_pairing()
    if not session:
        raise HTTPException(status_code=404, detail="No active pairing")
    return {"code": session.code, "expires_at": session.expires_at, "expires_in": session.expires_in}


@router.post("/pair/confirm")
def confirm_pairing(payload: Dict[str, str], pairing: PairingManager = Depends(get_pairing_manager)):
    code = payload.get("code")
    device_id = payload.get("device_id")
    device_name = payload.get("device_name")
    if not code or not device_id or not device_name:
        raise HTTPException(status_code=400, detail="Missing fields")
    token = pairing.confirm_pairing(code=code, device_id=device_id, device_name=device_name)
    if not token:
        raise HTTPException(status_code=403, detail="Invalid or expired code")
    return {"token": token.token, "expires_at": token.expires_at}


@router.post("/tests/ping")
def run_ping(payload: Dict[str, str], _: DeviceToken = Depends(auth_dependency)):
    target = payload.get("target")
    if not target:
        raise HTTPException(status_code=400, detail="Missing target")
    rtt_ms = ping_host(target)
    return {"target": target, "rtt_ms": rtt_ms}


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    settings: HostSettings = Depends(lambda: router._settings),
    pairing_manager: PairingManager = Depends(get_pairing_manager),
    presence: PresenceRegistry = Depends(get_presence_registry),
):
    await websocket.accept()
    token_info: Optional[DeviceToken] = None
    try:
        # Expect an initial hello message
        initial = await websocket.receive_text()
        data = json.loads(initial)
        if data.get("type") != "hello":
            await websocket.close(code=4000)
            return
        token = data.get("token")
        token_info = pairing_manager.validate_token(token) if token else None
        if not token_info:
            await websocket.close(code=4001)
            return
        presence.register(token_info)
        await websocket.send_json(
            {
                "type": "welcome",
                "service": settings.service_name,
                "heartbeat_timeout": HEARTBEAT_TIMEOUT,
            }
        )
        while True:
            msg = await asyncio.wait_for(websocket.receive_text(), timeout=HEARTBEAT_TIMEOUT)
            payload = json.loads(msg)
            if payload.get("type") == "heartbeat":
                presence.heartbeat(token_info.device_id)
                await websocket.send_json({"type": "ack", "ts": datetime.utcnow().isoformat()})
            else:
                LOGGER.debug("Unknown payload: %s", payload)
    except asyncio.TimeoutError:
        LOGGER.info("Heartbeat timeout for %s", token_info.device_name if token_info else "unknown")
    except WebSocketDisconnect:
        LOGGER.info("WebSocket disconnected")
    except Exception:
        LOGGER.exception("WebSocket error")
    finally:
        if token_info:
            presence.disconnect(token_info.device_id)
            await websocket.close()


def build_app(settings: HostSettings, advertiser: MdnsAdvertiser) -> FastAPI:
    app = FastAPI(title="Scanner Host")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    router._pairing_manager = PairingManager()  # type: ignore[attr-defined]
    router._presence_registry = PresenceRegistry()  # type: ignore[attr-defined]
    router._settings = settings  # type: ignore[attr-defined]

    app.include_router(router)

    static_dir = Path(__file__).parent.parent / "webui" / "static"
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="webui")

    @app.on_event("startup")
    async def on_startup():
        await advertiser.start()

    @app.on_event("shutdown")
    async def on_shutdown():
        await advertiser.stop()

    return app


__all__ = ["build_app"]
