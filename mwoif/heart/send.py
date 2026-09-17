from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mwoif.heart.common import build_url, common_ds_fields, post_ds_v4, redacted_payload
from mwoif.session.ds_v4 import compact_json_bytes, decode_v4_form_body, encode_v4
from mwoif.session.models import AuthRecord, SessionRecord

SEND_LIFE_MAIL_ENDPOINT = "game/sendLifeMail2.ds"


@dataclass(frozen=True, slots=True)
class HeartSendRequest:
    from_member_seq: int
    to_member_seq: int
    request_id: str = ""

    def as_native_map(self) -> dict[str, Any]:
        return {"fromMemberSeq": self.from_member_seq, "toMemberSeq": self.to_member_seq, "requestId": self.request_id}


def build_heart_send_payload(*, cfg, actor_session: SessionRecord, target_session: SessionRecord, actor_auth: AuthRecord) -> tuple[HeartSendRequest, dict[str, Any], dict[str, str], dict[str, str]]:
    if not target_session.established:
        raise ValueError("target session is not established")
    req = HeartSendRequest(from_member_seq=int(actor_session.member_seq), to_member_seq=int(target_session.member_seq))
    common, missing, sources = common_ds_fields(cfg=cfg, actor_session=actor_session, actor_auth=actor_auth, endpoint=SEND_LIFE_MAIL_ENDPOINT)
    payload = {"fromMemberSeq": req.from_member_seq, "toMemberSeq": req.to_member_seq, "requestId": req.request_id}
    payload.update(common)
    return req, payload, missing, sources


def heart_send(*, cfg, actor_slot: str, target_slot: str, actor_session: SessionRecord, target_session: SessionRecord, actor_auth: AuthRecord, live: bool = False, timeout: float = 20.0) -> dict[str, Any]:
    req, payload, missing, sources = build_heart_send_payload(cfg=cfg, actor_session=actor_session, target_session=target_session, actor_auth=actor_auth)
    plaintext = compact_json_bytes(payload)
    encoded = encode_v4(plaintext)
    self_check = decode_v4_form_body(encoded.form_body).rstrip(b" ") == plaintext
    url = build_url(cfg, SEND_LIFE_MAIL_ENDPOINT)
    result: dict[str, Any] = {
        "ok": bool(self_check and not missing),
        "read_only": not live,
        "network_action_enabled": False,
        "action": "heart-send",
        "endpoint": SEND_LIFE_MAIL_ENDPOINT,
        "url_present": bool(url),
        "actor": actor_slot.upper(),
        "target": target_slot.upper(),
        "request": req.as_native_map(),
        "payload_redacted": redacted_payload(payload),
        "missing_live_fields": sorted(missing),
        "runtime_field_sources": sources,
        "crypto_self_check": self_check,
        "form_body_len": len(encoded.form_body),
        "form_body_fp": encoded.body_sha256[:12],
        "secretOutput": "NONE",
    }
    if not self_check:
        result.update({"ok": False, "error": "DS_V4_SELF_CHECK_FAILED"})
        return result
    if missing:
        result.update({"ok": False, "error": "DS_COMMON_FIELDS_MISSING"})
        return result
    if not live:
        result["write_guard"] = "PREVIEW_ONLY_ADD_--live_TO_SEND"
        return result
    if not url:
        result.update({"ok": False, "error": "GAME_BASE_URL_MISSING"})
        return result
    http_ok, info = post_ds_v4(cfg=cfg, url=url, body=encoded.form_body, timeout=timeout)
    result["network_action_enabled"] = True
    result.update(info.get("public", info))
    wrapper = info.get("wrapper") if isinstance(info, dict) else None
    app_code = wrapper.get("responseCode") if isinstance(wrapper, dict) else None
    result["ok"] = bool(http_ok and (app_code in (None, 200)))
    if not result["ok"]:
        result.setdefault("error", "SEND_LIFE_MAIL_FAILED")
    return result
