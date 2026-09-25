from __future__ import annotations

import json
from typing import Any

from mwoif.heart.common import build_url, common_ds_fields, post_ds_v4, redacted_payload
from mwoif.session.ds_v4 import compact_json_bytes, decode_v4_data_b64, decode_v4_form_body, encode_v4
from mwoif.session.models import AuthRecord, SessionRecord

MY_MAIL_LIST_ENDPOINT = "game/myMailList.ds"


def build_mail_list_payload(*, cfg, session: SessionRecord, auth: AuthRecord) -> tuple[dict[str, Any], dict[str, str], dict[str, str]]:
    common, missing, sources = common_ds_fields(cfg=cfg, actor_session=session, actor_auth=auth, endpoint=MY_MAIL_LIST_ENDPOINT)
    payload = {"memberSeq": int(session.member_seq)}
    payload.update(common)
    return payload, missing, sources


def _as_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return None


def _insert_dt_sort_value(value: Any) -> float:
    if value in (None, ""):
        return 0.0
    try:
        return float(value)
    except Exception:
        return 0.0


def extract_life_mail_items(decoded_response: Any, *, from_member_seq: int | None = None) -> list[dict[str, Any]]:
    if not isinstance(decoded_response, dict):
        return []
    mail_list = decoded_response.get("mailList")
    if not isinstance(mail_list, list):
        return []
    items: list[dict[str, Any]] = []
    for index, item in enumerate(mail_list):
        if not isinstance(item, dict):
            continue
        seq = _as_int(item.get("seq"))
        sender = _as_int(item.get("fromMemberSeq"))
        if seq is None or sender is None:
            continue
        if from_member_seq is not None and sender != int(from_member_seq):
            continue
        items.append({"index": index, "seq": seq, "fromMemberSeq": sender, "insertDt": item.get("insertDt")})
    items.sort(key=lambda x: _insert_dt_sort_value(x.get("insertDt")), reverse=True)
    return items


def mailbox_read(*, cfg, slot: str, session: SessionRecord, auth: AuthRecord, from_member_seq: int | None = None, live: bool = True, timeout: float = 20.0) -> dict[str, Any]:
    payload, missing, sources = build_mail_list_payload(cfg=cfg, session=session, auth=auth)
    plaintext = compact_json_bytes(payload)
    encoded = encode_v4(plaintext)
    self_check = decode_v4_form_body(encoded.form_body).rstrip(b" ") == plaintext
    url = build_url(cfg, MY_MAIL_LIST_ENDPOINT)
    result: dict[str, Any] = {
        "ok": bool(self_check and not missing),
        "read_only": True,
        "network_action_enabled": False,
        "action": "heart-mail-list",
        "endpoint": MY_MAIL_LIST_ENDPOINT,
        "url_present": bool(url),
        "slot": slot.upper(),
        "from_member_seq": from_member_seq,
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
        result["read_guard"] = "PREVIEW_ONLY_ADD_--live_TO_READ_MAILBOX"
        return result
    if not url:
        result.update({"ok": False, "error": "GAME_BASE_URL_MISSING"})
        return result
    http_ok, info = post_ds_v4(cfg=cfg, url=url, body=encoded.form_body, timeout=timeout)
    result["network_action_enabled"] = True
    result.update(info.get("public", info))
    wrapper = info.get("wrapper") if isinstance(info, dict) else None
    if not isinstance(wrapper, dict):
        result.update({"ok": False, "error": "MAIL_LIST_HTTP_JSON_INVALID"})
        return result
    data_b64 = wrapper.get("responseData") or ""
    if not data_b64:
        result.update({"ok": bool(http_ok and wrapper.get("responseCode") == 200), "decoded_response_present": False, "life_mail_candidates": [], "suggested_life_mail_seq": None})
        return result
    try:
        decoded_text = decode_v4_data_b64(str(data_b64)).rstrip(b" ").decode("utf-8")
        decoded_obj = json.loads(decoded_text)
    except Exception as exc:
        result.update({"ok": False, "error": "MAIL_LIST_RESPONSE_DECODE_FAILED", "message": f"{type(exc).__name__}: {exc}", "response_data_len": len(str(data_b64))})
        return result
    candidates = extract_life_mail_items(decoded_obj, from_member_seq=from_member_seq)
    result.update({"ok": bool(http_ok and wrapper.get("responseCode") == 200), "decoded_response_present": True, "decoded_top_level_keys": sorted(decoded_obj.keys())[:24] if isinstance(decoded_obj, dict) else [], "mail_list_count": len(decoded_obj.get("mailList", [])) if isinstance(decoded_obj, dict) and isinstance(decoded_obj.get("mailList"), list) else 0, "life_mail_candidates": candidates, "suggested_life_mail_seq": candidates[0]["seq"] if candidates else None, "selection_policy": "LATEST_INSERT_DT_FROM_REQUESTED_SENDER" if from_member_seq is not None else "LATEST_INSERT_DT"})
    return result
