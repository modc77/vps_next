from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mwoif.heart.common import build_url, common_ds_fields, post_ds_v4, redacted_payload
from mwoif.session.ds_v4 import compact_json_bytes, decode_v4_form_body, encode_v4
from mwoif.session.models import AuthRecord, SessionRecord

ACCEPT_LIFE_MAIL_ENDPOINT = "game/acceptLifeMail4.ds"


@dataclass(frozen=True, slots=True)
class HeartReceiveRequest:
    member_seq: int
    life_mail_box_seq_list: tuple[int, ...]

    def as_native_map(self) -> dict[str, Any]:
        return {"memberSeq": self.member_seq, "lifeMailBoxSeqList": list(self.life_mail_box_seq_list)}


def build_heart_receive_request(actor_session: SessionRecord, life_mail_box_seqs: list[int] | tuple[int, ...]) -> HeartReceiveRequest:
    if not actor_session.established:
        raise ValueError("actor session is not established")
    seqs: list[int] = []
    seen: set[int] = set()
    for raw in life_mail_box_seqs:
        seq = int(raw)
        if seq <= 0:
            raise ValueError("lifeMailBoxSeq must be > 0")
        if seq in seen:
            continue
        seen.add(seq)
        seqs.append(seq)
    if not seqs:
        raise ValueError("at least one seq is required")
    return HeartReceiveRequest(member_seq=int(actor_session.member_seq), life_mail_box_seq_list=tuple(seqs))


def heart_receive(*, cfg, actor_slot: str, actor_session: SessionRecord, actor_auth: AuthRecord, life_mail_box_seqs: list[int] | tuple[int, ...], live: bool = False, timeout: float = 20.0) -> dict[str, Any]:
    req = build_heart_receive_request(actor_session, life_mail_box_seqs)
    common, missing, sources = common_ds_fields(cfg=cfg, actor_session=actor_session, actor_auth=actor_auth, endpoint=ACCEPT_LIFE_MAIL_ENDPOINT)
    payload = {"memberSeq": req.member_seq, "lifeMailBoxSeqList": list(req.life_mail_box_seq_list)}
    for key, value in common.items():
        if key == "memberSeq":
            continue
        payload[key] = value
    plaintext = compact_json_bytes(payload)
    encoded = encode_v4(plaintext)
    self_check = decode_v4_form_body(encoded.form_body).rstrip(b" ") == plaintext
    url = build_url(cfg, ACCEPT_LIFE_MAIL_ENDPOINT)
    result: dict[str, Any] = {"ok": bool(self_check and not missing), "read_only": not live, "network_action_enabled": False, "action": "heart-receive", "endpoint": ACCEPT_LIFE_MAIL_ENDPOINT, "url_present": bool(url), "actor": actor_slot.upper(), "request": req.as_native_map(), "payload_redacted": redacted_payload(payload), "missing_live_fields": sorted(missing), "runtime_field_sources": sources, "crypto_self_check": self_check, "form_body_len": len(encoded.form_body), "form_body_fp": encoded.body_sha256[:12], "secretOutput": "NONE"}
    if not self_check:
        result.update({"ok": False, "error": "DS_V4_SELF_CHECK_FAILED"})
        return result
    if missing:
        result.update({"ok": False, "error": "DS_COMMON_FIELDS_MISSING"})
        return result
    if not live:
        result["write_guard"] = "PREVIEW_ONLY_ADD_--live_TO_RECEIVE"
        return result
    if not url:
        result.update({"ok": False, "error": "GAME_BASE_URL_MISSING"})
        return result
    http_ok, info = post_ds_v4(cfg=cfg, url=url, body=encoded.form_body, timeout=timeout)
    result["network_action_enabled"] = True
    result.update(info.get("public", info))
    wrapper = info.get("wrapper") if isinstance(info, dict) else None
    app_code = wrapper.get("responseCode") if isinstance(wrapper, dict) else None
    app_message = wrapper.get("responseMessage") if isinstance(wrapper, dict) else None
    result["ok"] = bool(http_ok and app_code == 200 and app_message == "COMPLETE")
    if not result["ok"]:
        result.setdefault("error", "ACCEPT_LIFE_MAIL_NOT_COMPLETE")
    return result
