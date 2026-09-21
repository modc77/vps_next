from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urljoin

from mwoif.net.http_pool import pooled_post_bytes
from mwoif.session.ds_v4 import compact_json_bytes, encode_v4
from mwoif.session.game_session import (
    INIT_MEMBER_ENDPOINT,
    _decode_init_member_response_data,
    build_init_member_payload,
)
from mwoif.session.models import AuthRecord, SessionRecord


Event = Callable[[str], None]


class InviteSnapshotError(RuntimeError):
    pass


@dataclass(slots=True)
class InviteMemberSnapshot:
    session: SessionRecord
    friend_invite_count: int

    def public_summary(self) -> dict[str, Any]:
        return {
            "memberSeq": "present" if self.session.member_seq > 0 else "missing",
            "lv": self.session.current_lv,
            "friendInviteCount": self.friend_invite_count,
            "session": "present" if self.session.established else "missing",
            "secretOutput": "NONE",
        }


def _deep_find(obj: Any, key: str):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for value in obj.values():
            hit = _deep_find(value, key)
            if hit not in (None, ""):
                return hit
    elif isinstance(obj, list):
        for value in obj:
            hit = _deep_find(value, key)
            if hit not in (None, ""):
                return hit
    return None


def fetch_invite_member_snapshot(
    cfg,
    *,
    slot: str,
    auth: AuthRecord,
    event_cb: Event | None = None,
) -> InviteMemberSnapshot:
    payload, missing = build_init_member_payload(cfg, auth)
    if missing:
        raise InviteSnapshotError("INITMEMBER3_MISSING:" + ",".join(missing))

    encoded = encode_v4(compact_json_bytes(payload))
    base = str(cfg.server.get("game_base_url") or "").rstrip("/") + "/"
    url = urljoin(base, INIT_MEMBER_ENDPOINT)
    if event_cb:
        event_cb(f"INVITE SNAPSHOT START slot={slot} endpoint={INIT_MEMBER_ENDPOINT}")

    started = time.monotonic()
    try:
        status_code, response_body, _ = pooled_post_bytes(
            url=url,
            body=encoded.form_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=float(cfg.server.get("timeout_seconds") or 20),
            verify=bool(cfg.server.get("verify_ssl", True)),
        )
    except Exception as exc:
        raise InviteSnapshotError(f"INITMEMBER3_NETWORK_ERROR:{type(exc).__name__}") from exc

    try:
        wrapper = json.loads(response_body.decode("utf-8-sig"))
    except Exception as exc:
        raise InviteSnapshotError(f"INITMEMBER3_WRAPPER_INVALID:http={status_code}") from exc

    response_code = wrapper.get("responseCode") if isinstance(wrapper, dict) else None
    if not (200 <= int(status_code) < 300) or response_code != 200:
        raise InviteSnapshotError(
            f"INITMEMBER3_REJECTED:http={status_code}:responseCode={response_code}"
        )

    try:
        obj, _decode_mode, _decode_profile = _decode_init_member_response_data(
            wrapper.get("responseData") or ""
        )
    except Exception as exc:
        raise InviteSnapshotError(f"INITMEMBER3_DECODE_ERROR:{type(exc).__name__}") from exc

    try:
        member_seq = int(_deep_find(obj, "memberSeq") or 0)
        current_lv = int(_deep_find(obj, "lv") or _deep_find(obj, "currentLv") or 0)
        session_key = str(_deep_find(obj, "sessionKey") or "")
        raw_count = _deep_find(obj, "friendInviteCount")
        if raw_count in (None, ""):
            raise ValueError("friendInviteCount missing")
        friend_invite_count = int(raw_count)
    except Exception as exc:
        raise InviteSnapshotError("INITMEMBER3_INVITE_FIELDS_INVALID") from exc

    if member_seq <= 0 or not session_key:
        raise InviteSnapshotError("INITMEMBER3_SESSION_MISSING")
    if friend_invite_count < 0:
        raise InviteSnapshotError("FRIEND_INVITE_COUNT_INVALID")

    session = SessionRecord(
        schema="mwoif-heart-v3-session-runtime",
        account_kind=auth.account_kind,
        account_id=auth.account_id,
        member_seq=member_seq,
        current_lv=current_lv,
        session_key=session_key,
        source="email_login_initMember3_invite_snapshot",
        imported_at=datetime.now(timezone.utc).isoformat(),
    )
    if event_cb:
        event_cb(
            "INVITE SNAPSHOT OK "
            f"slot={slot} lv={current_lv} friendInviteCount={friend_invite_count} "
            f"elapsedMs={round((time.monotonic() - started) * 1000)} secretOutput=NONE"
        )
    return InviteMemberSnapshot(session=session, friend_invite_count=friend_invite_count)
