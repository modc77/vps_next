from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urljoin

from mwoif.heart.common import build_url, common_ds_fields, post_ds_v4, redacted_payload
from mwoif.net.http_pool import pooled_post_bytes
from mwoif.session.ds_v4 import compact_json_bytes, decode_v4_data_b64, decode_v4_form_body, encode_v4
from mwoif.session.game_session import INIT_MEMBER_ENDPOINT, _decode_init_member_response_data, build_init_member_payload
from mwoif.session.models import AuthRecord, SessionRecord


GIFT_DRAW_ENDPOINT = "shop/buyStuff.ds"
GIFT_DRAW_STUFF_SEQ = 0x324
GIFT_DRAW_PRICE = 0
GIFT_DRAW_BUY_TYPE = 0
Event = Callable[[str], None]


class GiftDrawError(RuntimeError):
    pass


@dataclass(slots=True)
class GiftPointSnapshot:
    session: SessionRecord
    current_point: int
    gift_count: int
    today_point: int

    def public_summary(self) -> dict[str, Any]:
        return {
            "memberSeq": "present" if self.session.member_seq > 0 else "missing",
            "lv": self.session.current_lv,
            "currentPoint": self.current_point,
            "giftCount": self.gift_count,
            "todayPoint": self.today_point,
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


def _point_result(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        return {}
    cash_info = obj.get("cashInfo")
    if isinstance(cash_info, dict):
        point_result = cash_info.get("pointResult")
        if isinstance(point_result, dict):
            return point_result
    hit = _deep_find(obj, "pointResult")
    return hit if isinstance(hit, dict) else {}


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def fetch_gift_snapshot(
    cfg,
    *,
    slot: str,
    auth: AuthRecord,
    event_cb: Event | None = None,
) -> GiftPointSnapshot:
    payload, missing = build_init_member_payload(cfg, auth)
    if missing:
        raise GiftDrawError("INITMEMBER3_MISSING:" + ",".join(missing))

    encoded = encode_v4(compact_json_bytes(payload))
    base = str(cfg.server.get("game_base_url") or "").rstrip("/") + "/"
    url = urljoin(base, INIT_MEMBER_ENDPOINT)
    if event_cb:
        event_cb(f"GIFT SNAPSHOT START slot={slot} endpoint={INIT_MEMBER_ENDPOINT}")

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
        raise GiftDrawError(f"INITMEMBER3_NETWORK_ERROR:{type(exc).__name__}") from exc

    try:
        wrapper = json.loads(response_body.decode("utf-8-sig"))
    except Exception as exc:
        raise GiftDrawError(f"INITMEMBER3_WRAPPER_INVALID:http={status_code}") from exc

    response_code = wrapper.get("responseCode") if isinstance(wrapper, dict) else None
    if not (200 <= int(status_code) < 300) or response_code != 200:
        raise GiftDrawError(f"INITMEMBER3_REJECTED:http={status_code}:responseCode={response_code}")

    try:
        obj, _decode_mode, _decode_profile = _decode_init_member_response_data(wrapper.get("responseData") or "")
    except Exception as exc:
        raise GiftDrawError(f"INITMEMBER3_DECODE_ERROR:{type(exc).__name__}") from exc

    point_result = _point_result(obj)
    member_seq = _as_int(_deep_find(obj, "memberSeq"))
    current_lv = _as_int(_deep_find(obj, "lv") or _deep_find(obj, "currentLv"))
    session_key = str(_deep_find(obj, "sessionKey") or "")
    current_point = _as_int(point_result.get("currentPoint"), -1)
    gift_count = _as_int(point_result.get("giftCount"), -1)
    today_point = _as_int(point_result.get("todayPoint"), -1)

    if member_seq <= 0 or not session_key:
        raise GiftDrawError("INITMEMBER3_SESSION_MISSING")
    if current_point < 0 or gift_count < 0:
        raise GiftDrawError("INITMEMBER3_GIFT_POINT_FIELDS_MISSING")

    session = SessionRecord(
        schema="mwoif-heart-v3-session-runtime",
        account_kind=auth.account_kind,
        account_id=auth.account_id,
        member_seq=member_seq,
        current_lv=current_lv,
        session_key=session_key,
        source="email_login_initMember3_gift_snapshot",
        imported_at=datetime.now(timezone.utc).isoformat(),
    )
    if event_cb:
        event_cb(
            "GIFT SNAPSHOT OK "
            f"slot={slot} lv={current_lv} currentPoint={current_point}/100 giftCount={gift_count} "
            f"elapsedMs={round((time.monotonic() - started) * 1000)} secretOutput=NONE"
        )
    return GiftPointSnapshot(
        session=session,
        current_point=current_point,
        gift_count=gift_count,
        today_point=today_point,
    )


def _decode_response_data(wrapper: dict[str, Any] | None) -> Any:
    if not isinstance(wrapper, dict):
        return None
    encoded = str(wrapper.get("responseData") or "").strip()
    if not encoded:
        return None
    raw = decode_v4_data_b64(encoded).rstrip(b" ")
    if not raw:
        return None
    return json.loads(raw.decode("utf-8-sig"))


def _safe_value(value: Any, key: str = "") -> Any:
    normalized = key.lower().replace("_", "").replace("-", "")
    if any(part in normalized for part in ("session", "token", "secret", "password", "authorization", "accesskey", "apikey")):
        return "<REDACTED>" if value not in (None, "", [], {}) else value
    if isinstance(value, dict):
        return {str(k): _safe_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe_value(v, key) for v in value]
    return value


def _interesting_rows(value: Any, path: str = "$") -> list[dict[str, Any]]:
    wanted = (
        "resultitem",
        "reward",
        "stuffseq",
        "resultstuffseq",
        "type",
        "qty",
        "currentpoint",
        "giftcount",
        "todaypoint",
        "coin",
        "gem",
    )
    rows: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            normalized = str(key).lower().replace("_", "").replace("-", "")
            if any(part in normalized for part in wanted):
                if isinstance(child, (dict, list)):
                    rows.append({"path": child_path, "type": type(child).__name__, "size": len(child)})
                else:
                    rows.append({"path": child_path, "value": _safe_value(child, str(key))})
            rows.extend(_interesting_rows(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value[:100]):
            rows.extend(_interesting_rows(child, f"{path}[{index}]"))
    return rows


def gift_draw(
    *,
    cfg,
    slot: str,
    session: SessionRecord,
    auth: AuthRecord,
    live: bool = False,
    timeout: float = 20.0,
) -> dict[str, Any]:
    common, missing, sources = common_ds_fields(
        cfg=cfg,
        actor_session=session,
        actor_auth=auth,
        endpoint=GIFT_DRAW_ENDPOINT,
    )
    payload = dict(common)
    payload.update({
        "stuffSeq": GIFT_DRAW_STUFF_SEQ,
        "price": GIFT_DRAW_PRICE,
        "buyType": GIFT_DRAW_BUY_TYPE,
    })
    plaintext = compact_json_bytes(payload)
    encoded = encode_v4(plaintext)
    self_check = decode_v4_form_body(encoded.form_body).rstrip(b" ") == plaintext
    url = build_url(cfg, GIFT_DRAW_ENDPOINT)

    result: dict[str, Any] = {
        "ok": bool(self_check and not missing),
        "read_only": not live,
        "network_action_enabled": False,
        "action": "gift-draw",
        "endpoint": GIFT_DRAW_ENDPOINT,
        "request_mode": "NATIVE_BUY_STUFF_GIFT_DRAW",
        "native_contract": {
            "stuffSeq": GIFT_DRAW_STUFF_SEQ,
            "price": GIFT_DRAW_PRICE,
            "buyType": GIFT_DRAW_BUY_TYPE,
            "qty": "OMITTED_WHEN_1",
        },
        "url_present": bool(url),
        "slot": slot.upper(),
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
        result["write_guard"] = "PREVIEW_ONLY_ADD_--live_TO_BUY_GIFT_DRAW_STUFF_0x324"
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

    try:
        decoded = _decode_response_data(wrapper)
        result["response_data_decoded"] = decoded is not None
        result["response_interesting"] = _interesting_rows(decoded)[:120] if decoded is not None else []
        if isinstance(decoded, dict):
            result["response_root_keys"] = sorted(str(k) for k in decoded.keys())
            result["response_safe"] = _safe_value(decoded)
    except Exception as exc:
        result["response_data_decoded"] = False
        result["response_decode_error"] = type(exc).__name__

    if not result["ok"]:
        result.setdefault("error", "GIFT_DRAW_NOT_COMPLETE")
    return result
