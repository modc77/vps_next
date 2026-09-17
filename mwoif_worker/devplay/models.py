from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any


def _first(mapping: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return default


def jwt_exp(token: str) -> int | None:
    """Read JWT exp for expiry metadata only; this is not signature verification."""
    try:
        parts = str(token or "").split(".")
        if len(parts) < 2:
            return None
        raw = parts[1] + "=" * ((-len(parts[1])) % 4)
        payload = json.loads(base64.urlsafe_b64decode(raw.encode("ascii")))
        value = payload.get("exp")
        return int(value) if value is not None else None
    except Exception:
        return None


def _looks_like_login_payload(value: dict[str, Any]) -> bool:
    token_keys = {
        "game_access_token", "gameAccessToken",
        "refresh_token", "refreshToken",
        "oven_access_token", "ovenAccessToken",
    }
    return len(set(value) & token_keys) >= 2


def find_login_payload(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        if _looks_like_login_payload(value):
            return value
        for child in value.values():
            hit = find_login_payload(child)
            if hit is not None:
                return hit
    elif isinstance(value, list):
        for child in value:
            hit = find_login_payload(child)
            if hit is not None:
                return hit
    elif isinstance(value, str):
        text = value.strip()
        if text.startswith("{") or text.startswith("["):
            try:
                return find_login_payload(json.loads(text))
            except Exception:
                return None
    return None


@dataclass(slots=True)
class LoginBundle:
    mid: str
    refresh_token: str
    game_access_token: str
    oven_access_token: str
    device_secret: str = ""
    expired_date_ms: int = 0

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "LoginBundle":
        member = payload.get("member") if isinstance(payload.get("member"), dict) else {}
        mid = str(
            _first(member, "mid", "player_id", "playerId", default="")
            or _first(payload, "mid", "player_id", "playerId", default="")
        ).strip()
        refresh = str(_first(payload, "refresh_token", "refreshToken", default="")).strip()
        game = str(_first(payload, "game_access_token", "gameAccessToken", default="")).strip()
        oven = str(_first(payload, "oven_access_token", "ovenAccessToken", default="")).strip()
        device_secret = str(_first(payload, "device_secret", "deviceSecret", default="")).strip()

        exp_ms = 0
        explicit = _first(payload, "expiredDate", "expired_date", "expiredDateMs", default=0)
        try:
            exp_ms = int(explicit or 0)
        except Exception:
            exp_ms = 0
        if exp_ms and exp_ms < 10_000_000_000:
            exp_ms *= 1000
        if not exp_ms:
            exp = jwt_exp(game) or jwt_exp(oven)
            if exp:
                exp_ms = int(exp) * 1000

        if not mid:
            raise ValueError("ServerLoginResponse has no member.mid")
        if not refresh or not game or not oven:
            raise ValueError("ServerLoginResponse is missing required session token fields")
        return cls(mid, refresh, game, oven, device_secret, exp_ms)

    def safe_summary(self) -> dict[str, Any]:
        return {
            "member_present": bool(self.mid),
            "refresh_token_present": bool(self.refresh_token),
            "game_access_token_present": bool(self.game_access_token),
            "oven_access_token_present": bool(self.oven_access_token),
            "device_secret_present": bool(self.device_secret),
            "expiry_present": bool(self.expired_date_ms),
        }
