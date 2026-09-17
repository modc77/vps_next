from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mwoif.auth.models import LoginBundle, jwt_exp
from mwoif.core.redact import secret_fingerprint


@dataclass(slots=True)
class AuthRecord:
    schema: str
    account_kind: str
    account_id: int
    mid: str
    refresh_token: str
    game_access_token: str
    oven_access_token: str
    device_secret: str
    fgs_id: str
    device_id: str
    login_type: str
    metadata: dict[str, str]
    imported_at: str

    @classmethod
    def from_login_bundle(
        cls,
        *,
        account_kind: str,
        account_id: int,
        bundle: LoginBundle,
        fgs_id: str,
        device_id: str,
        metadata: dict[str, str],
        imported_at: str,
    ) -> "AuthRecord":
        return cls(
            schema="mwoif-heart-v3-auth-runtime",
            account_kind=account_kind,
            account_id=account_id,
            mid=bundle.mid,
            refresh_token=bundle.refresh_token,
            game_access_token=bundle.game_access_token,
            oven_access_token=bundle.oven_access_token,
            device_secret=bundle.device_secret,
            fgs_id=fgs_id,
            device_id=device_id,
            login_type=bundle.login_type or "email",
            metadata=metadata,
            imported_at=imported_at,
        )

    @property
    def ready(self) -> bool:
        return bool(self.mid and self.game_access_token)

    def public_summary(self) -> dict[str, Any]:
        return {
            "mid_present": bool(self.mid),
            "refresh_present": bool(self.refresh_token),
            "refresh_fp": secret_fingerprint(self.refresh_token),
            "game_present": bool(self.game_access_token),
            "game_exp": jwt_exp(self.game_access_token),
            "oven_present": bool(self.oven_access_token),
            "oven_exp": jwt_exp(self.oven_access_token),
            "device_secret_present": bool(self.device_secret),
            "fgs_id_present": bool(self.fgs_id),
            "device_id_present": bool(self.device_id),
            "login_type": self.login_type,
            "secretOutput": "NONE",
        }


@dataclass(slots=True)
class SessionRecord:
    schema: str
    account_kind: str
    account_id: int
    member_seq: int
    current_lv: int
    session_key: str
    source: str
    imported_at: str

    @property
    def established(self) -> bool:
        return self.member_seq > 0 and bool(self.session_key)

    def public_summary(self) -> dict[str, Any]:
        return {
            "member_seq_present": self.member_seq > 0,
            "current_lv": self.current_lv,
            "session_key_present": bool(self.session_key),
            "secretOutput": "NONE",
        }
