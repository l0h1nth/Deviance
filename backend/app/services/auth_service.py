import base64
import hashlib
import hmac
import json
import time

from app.config import get_settings


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class AuthService:
    def __init__(self):
        self.settings = get_settings()

    def authenticate(self, username: str, password: str) -> bool:
        return hmac.compare_digest(username, self.settings.admin_username) and hmac.compare_digest(password, self.settings.admin_password)

    def create_token(self, username: str) -> tuple[str, int]:
        expires_in = self.settings.auth_token_hours * 3600
        payload = {"sub": username, "role": "administrator", "exp": int(time.time()) + expires_in}
        body = _encode(json.dumps(payload, separators=(",", ":")).encode())
        signature = _encode(hmac.new(self.settings.auth_secret.encode(), body.encode(), hashlib.sha256).digest())
        return f"{body}.{signature}", expires_in

    def verify_token(self, token: str) -> dict | None:
        try:
            body, supplied_signature = token.split(".", 1)
            expected_signature = _encode(hmac.new(self.settings.auth_secret.encode(), body.encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(supplied_signature, expected_signature): return None
            payload = json.loads(_decode(body))
            if int(payload.get("exp", 0)) <= int(time.time()): return None
            if payload.get("sub") != self.settings.admin_username: return None
            return payload
        except (ValueError, TypeError, json.JSONDecodeError):
            return None

