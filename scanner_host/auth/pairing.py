from __future__ import annotations

import secrets
import string
import time
from dataclasses import dataclass
from threading import Lock
from typing import Dict, Optional


@dataclass
class PairingSession:
    pairing_id: str
    code: str
    created_at: float
    expires_at: float

    @property
    def expires_in(self) -> float:
        return max(0.0, self.expires_at - time.time())


@dataclass
class DeviceToken:
    token: str
    device_id: str
    device_name: str
    issued_at: float
    expires_at: float


class PairingManager:
    def __init__(self, code_ttl_seconds: int = 300, token_ttl_seconds: int = 86400):
        self.code_ttl_seconds = code_ttl_seconds
        self.token_ttl_seconds = token_ttl_seconds
        self._lock = Lock()
        self._active_pairing: Optional[PairingSession] = None
        self._tokens: Dict[str, DeviceToken] = {}

    def _generate_code(self) -> str:
        digits = string.digits
        return "".join(secrets.choice(digits) for _ in range(6))

    def start_pairing(self) -> PairingSession:
        now = time.time()
        with self._lock:
            pairing = PairingSession(
                pairing_id=secrets.token_hex(8),
                code=self._generate_code(),
                created_at=now,
                expires_at=now + self.code_ttl_seconds,
            )
            self._active_pairing = pairing
            return pairing

    def active_pairing(self) -> Optional[PairingSession]:
        with self._lock:
            if self._active_pairing and self._active_pairing.expires_at < time.time():
                self._active_pairing = None
            return self._active_pairing

    def confirm_pairing(self, code: str, device_id: str, device_name: str) -> Optional[DeviceToken]:
        now = time.time()
        with self._lock:
            pairing = self.active_pairing()
            if not pairing or pairing.code != code:
                return None
            token = DeviceToken(
                token=secrets.token_urlsafe(24),
                device_id=device_id,
                device_name=device_name,
                issued_at=now,
                expires_at=now + self.token_ttl_seconds,
            )
            self._tokens[token.token] = token
            self._active_pairing = None
            return token

    def validate_token(self, token: str) -> Optional[DeviceToken]:
        with self._lock:
            data = self._tokens.get(token)
            if not data:
                return None
            if data.expires_at < time.time():
                self._tokens.pop(token, None)
                return None
            return data

    def list_tokens(self) -> Dict[str, DeviceToken]:
        with self._lock:
            return dict(self._tokens)


__all__ = ["PairingManager", "DeviceToken", "PairingSession"]
