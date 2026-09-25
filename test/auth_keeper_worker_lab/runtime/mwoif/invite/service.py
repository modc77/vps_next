from __future__ import annotations

from typing import Any

from mwoif.friend.proto import encode_string
from mwoif.friend.service import _grpc_call
from mwoif.session.models import AuthRecord


INVITE_METHOD = "/service.api.InvitationAPI/SetReferrer"


class InviteServiceError(ValueError):
    pass


def build_set_referrer_request(referrer_player_id: str) -> bytes:
    value = str(referrer_player_id or "").strip()
    if not value:
        raise InviteServiceError("REFERRER_PLAYER_ID_MISSING")
    if len(value) > 128:
        raise InviteServiceError("REFERRER_PLAYER_ID_INVALID")
    return encode_string(2, value)


def set_referrer(
    *,
    cfg,
    auth: AuthRecord,
    referrer_player_id: str,
    slot: str = "INVITE",
    timeout: float = 15.0,
    live: bool = False,
) -> dict[str, Any]:
    body = build_set_referrer_request(referrer_player_id)
    return _grpc_call(
        cfg=cfg,
        slot=slot,
        auth=auth,
        action="invite-set-referrer",
        method_path=INVITE_METHOD,
        request_body=body,
        timeout=max(3.0, float(timeout)),
        live=bool(live),
        schema={
            "request": "service.api.SetReferrerRequest",
            "field_2": "referrer_player_id:string",
        },
    )
