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
    """Read JWT exp without treating it as signature verification."""
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


def _looks_like_login_payload(d: dict[str, Any]) -> bool:
    keys = set(d)
    token_keys = {
        "game_access_token", "gameAccessToken",
        "refresh_token", "refreshToken",
        "oven_access_token", "ovenAccessToken",
    }
    return len(keys & token_keys) >= 2


def find_login_payload(value: Any) -> dict[str, Any] | None:
    """Find ServerLoginResponse-like data without logging the secret values."""
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
                pass
    return None


@dataclass(slots=True)
class LoginBundle:
    mid: str
    refresh_token: str
    game_access_token: str
    oven_access_token: str
    device_secret: str = ""
    login_type: str = "email"
    expired_date_ms: int = 0

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "LoginBundle":
        member = payload.get("member")
        if not isinstance(member, dict):
            member = {}
        mid = str(
            _first(member, "mid", "player_id", "playerId", default="")
            or _first(payload, "mid", "player_id", "playerId", default="")
        ).strip()
        refresh = str(_first(payload, "refresh_token", "refreshToken", default="")).strip()
        game = str(_first(payload, "game_access_token", "gameAccessToken", default="")).strip()
        oven = str(_first(payload, "oven_access_token", "ovenAccessToken", default="")).strip()
        device_secret = str(_first(payload, "device_secret", "deviceSecret", default="")).strip()
        login_type = str(_first(payload, "login_type", "loginType", default="email") or "email")

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
        if not refresh:
            raise ValueError("ServerLoginResponse has no refresh_token")
        if not game:
            raise ValueError("ServerLoginResponse has no game_access_token")
        if not oven:
            raise ValueError("ServerLoginResponse has no oven_access_token")

        return cls(
            mid=mid,
            refresh_token=refresh,
            game_access_token=game,
            oven_access_token=oven,
            device_secret=device_secret,
            login_type=login_type,
            expired_date_ms=exp_ms,
        )

    def public_summary(self) -> dict[str, Any]:
        return {
            "mid_present": bool(self.mid),
            "refresh_present": bool(self.refresh_token),
            "game_present": bool(self.game_access_token),
            "oven_present": bool(self.oven_access_token),
            "device_secret_present": bool(self.device_secret),
            "game_exp": jwt_exp(self.game_access_token),
            "oven_exp": jwt_exp(self.oven_access_token),
            "expired_date_ms": self.expired_date_ms,
            "login_type": self.login_type,
            "secret_output": "NONE",
        }
