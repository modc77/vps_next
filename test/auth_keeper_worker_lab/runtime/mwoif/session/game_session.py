from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urljoin, urlsplit

import secrets
from zoneinfo import ZoneInfo

from mwoif.session.models import AuthRecord, SessionRecord
from mwoif.net.http_pool import pooled_post_bytes
from mwoif.session.ds_v4 import compact_json_bytes, decode_v4_data_b64, decode_v4_form_body, encode_v4


_CABLE_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _meta(auth: AuthRecord, *keys: str, default: str = "") -> str:
    for key in keys:
        value = auth.metadata.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def _parse_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _timezone_distance_seconds(auth: AuthRecord, timezone_name: str, explicit: int | None = None) -> tuple[int | None, str]:
    if explicit is not None:
        return int(explicit), "CLI_OVERRIDE"
    for key in ("time-zone-distance", "timeZoneDistance", "timezone-distance", "timezone_distance"):
        parsed = _parse_int(auth.metadata.get(key))
        if parsed is not None:
            return parsed, f"AUTH_METADATA:{key}"
    try:
        now = datetime.now(ZoneInfo(timezone_name))
        offset = now.utcoffset()
        if offset is not None:
            return int(offset.total_seconds()), "ZONEINFO"
    except Exception:
        pass
    return None, "MISSING"


def _new_cable(length: int = 20) -> str:
    return "".join(secrets.choice(_CABLE_ALPHABET) for _ in range(length))


def _game_process_ms(auth: AuthRecord, explicit: int | None = None) -> tuple[int | None, str]:
    if explicit is not None:
        return max(0, int(explicit)), "CLI_OVERRIDE"
    base = None
    source_key = ""
    for key in ("game-process-elapsed-ms", "game_process_elapsed_ms", "gameProcessElapsedMs"):
        parsed = _parse_int(auth.metadata.get(key))
        if parsed is not None and parsed >= 0:
            base = parsed
            source_key = key
            break
    if base is None:
        return None, "MISSING"
    delta_ms = 0
    try:
        imported = datetime.fromisoformat(auth.imported_at.replace("Z", "+00:00"))
        if imported.tzinfo is None:
            imported = imported.replace(tzinfo=timezone.utc)
        delta_ms = max(0, int((datetime.now(timezone.utc) - imported.astimezone(timezone.utc)).total_seconds() * 1000))
    except Exception:
        delta_ms = 0
    return base + delta_ms, f"AUTH_METADATA:{source_key}+IMPORT_AGE"

INIT_MEMBER_ENDPOINT = "member/initMember3.ds"
Event = Callable[[str], None]


class SessionBootstrapError(RuntimeError):
    pass


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value).strip()


def _first(*values: Any) -> str:
    for value in values:
        text = _text(value)
        if text:
            return text
    return ""


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _context_path(cfg, value: Any) -> Path | None:
    text = _text(value)
    if not text:
        return None
    path = Path(text)
    if not path.is_absolute():
        path = cfg.root / path
    return path


def _load_private_login_query(cfg) -> dict[str, str]:
    """Read only local LAB private WebView context to reuse real runtime fields.

    This does not print or return cookies/tokens. It is used for non-secret
    initMember3 request fields such as push_token, semi_device_id, and the
    app/device identifiers the game itself placed in the login URL.
    """
    web = _dict(_dict(cfg.raw.get("v2")).get("login_web_context"))
    candidates: list[Path] = []
    for raw_path in (
        os.environ.get("MWOIF_DEVPLAY_WEB_CONTEXT_FILE"),
        web.get("private_context_file"),
        "state/login_web_context.private.json",
    ):
        path = _context_path(cfg, raw_path)
        if path and path not in candidates:
            candidates.append(path)

    query: dict[str, str] = {}
    for path in candidates:
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        for key in ("url", "login_url", "raw_url"):
            url = _text(data.get(key))
            if not url:
                continue
            try:
                parsed = urlsplit(url)
                values = parse_qs(parsed.query, keep_blank_values=True)
                for name, items in values.items():
                    if items:
                        query[name] = _text(items[0])
            except Exception:
                pass
        raw_query = _dict(data.get("query"))
        for name, value in raw_query.items():
            query[str(name)] = _text(value)
    return query



def _safe_fp(value: Any) -> str:
    text = _text(value)
    if not text:
        return "NONE"
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]


def _json_from_bytes(blob: bytes) -> Any:
    text = blob.strip(b" \t\r\n\x00").decode("utf-8-sig")
    return json.loads(text)


def _json_from_text(text: str) -> Any:
    parsed = json.loads(text.strip())
    # Some wrappers double-encode responseData as a JSON string. Decode one more
    # layer only when it is still clearly JSON text, never print the value.
    if isinstance(parsed, str) and parsed.strip()[:1] in "[{":
        return json.loads(parsed.strip())
    return parsed


def _base64_decode_variants(text: str) -> list[tuple[str, bytes]]:
    compact = "".join(text.strip().split())
    if not compact:
        return []
    padded = compact + ("=" * ((-len(compact)) % 4))
    out: list[tuple[str, bytes]] = []
    for name, decoder in (
        ("urlsafe-base64", base64.urlsafe_b64decode),
        ("standard-base64", base64.b64decode),
    ):
        try:
            blob = decoder(padded.encode("ascii"))
        except Exception:
            continue
        if blob and (not out or blob != out[-1][1]):
            out.append((name, blob))
    return out


def _decode_init_member_response_data(data: Any) -> tuple[Any, str, str]:
    """Decode initMember3 responseData without exposing raw session material.

    initMember3 is now reaching responseCode=200. This helper accepts the
    observed V1 DS-v4 encrypted response shape, plus safe fallbacks for server
    variants where responseData is already JSON, a full form body, or a plain
    base64 JSON blob. Errors report only type/length/fingerprint and attempted
    modes, never responseData or sessionKey.
    """
    if isinstance(data, (dict, list)):
        return data, "wrapper-object", "type=object"

    text = _text(data)
    profile = f"type={type(data).__name__} len={len(text)} fp={_safe_fp(text)}"
    if not text:
        raise ValueError("responseData empty")

    tried: list[str] = []

    if text.lstrip()[:1] in "[{":
        tried.append("json-text")
        try:
            return _json_from_text(text), "json-text", profile
        except Exception as exc:
            tried.append(f"json-text:{type(exc).__name__}")

    form_text = text
    if text.startswith("data="):
        form_text = "isEncryptedData=4&" + text
    if form_text.startswith("isEncryptedData=4&data="):
        tried.append("v4-form")
        try:
            return _json_from_bytes(decode_v4_form_body(form_text)), "v4-form", profile
        except Exception as exc:
            tried.append(f"v4-form:{type(exc).__name__}:{str(exc)[:80]}")

    tried.append("v4-responseData")
    try:
        return _json_from_bytes(decode_v4_data_b64(text)), "v4-responseData", profile
    except Exception as exc:
        tried.append(f"v4-responseData:{type(exc).__name__}:{str(exc)[:80]}")

    for b64_mode, blob in _base64_decode_variants(text):
        tried.append(b64_mode)
        try:
            return _json_from_bytes(blob), b64_mode + ":json", profile
        except Exception as exc:
            tried.append(f"{b64_mode}:json:{type(exc).__name__}")
        try:
            return _json_from_bytes(gzip.decompress(blob)), b64_mode + ":gzip-json", profile
        except Exception as exc:
            tried.append(f"{b64_mode}:gzip:{type(exc).__name__}")
        try:
            return _json_from_bytes(zlib.decompress(blob)), b64_mode + ":zlib-json", profile
        except Exception as exc:
            tried.append(f"{b64_mode}:zlib:{type(exc).__name__}")

    raise ValueError(profile + " tried=" + "|".join(tried) + " secretOutput=NONE")

def _maybe_json(value: Any) -> Any:
    text = _text(value)
    if not text:
        return ""
    if text[:1] in "[{":
        try:
            return json.loads(text)
        except Exception:
            return text
    return text


def _boolish(value: Any) -> bool | str:
    text = _text(value).lower()
    if text == "true":
        return True
    if text == "false":
        return False
    return _text(value)


def _split_ids(value: Any) -> list[str] | str:
    text = _text(value)
    if not text:
        return ""
    parsed = _maybe_json(text)
    if isinstance(parsed, (list, dict)):
        return parsed
    for sep in (",", "|", ";"):
        if sep in text:
            return [x.strip() for x in text.split(sep) if x.strip()]
    return text


def _build_agreement(cfg, private_query: dict[str, str]) -> Any:
    explicit = cfg.devplay.get("agreement")
    if explicit not in (None, ""):
        return _maybe_json(explicit)

    # Runtime evidence from LAB login URL. Kept as a compact object so the field
    # is present without inventing secret values. If the server requires a more
    # exact native agreement string, the next step is to export initMember3 from
    # LAB rather than guess here.
    keys = (
        "agree_ad_day_push",
        "agree_ad_night_push",
        "agree_dt",
        "terms_updates_ids",
        "terms_updates_values",
        "use_terms_v2",
    )
    out: dict[str, Any] = {}
    for key in keys:
        value = private_query.get(key)
        if value in (None, ""):
            continue
        if key in {"agree_ad_day_push", "agree_ad_night_push", "use_terms_v2"}:
            out[key] = _boolish(value)
        else:
            out[key] = _maybe_json(value)
    return out


def _public_present_profile(payload: dict[str, Any]) -> str:
    keys = (
        "mid", "playerId", "agreementSeq", "pushToken", "accessToken",
        "agreement", "mobclixSignature", "macAddress", "semiDeviceId",
        "fgsId", "deviceId", "loginPlatform",
    )
    parts: list[str] = []
    for key in keys:
        value = payload.get(key)
        present = value not in (None, "", [], {})
        parts.append(f"{key}:{'Y' if present else 'N'}")
    return ",".join(parts)


def build_init_member_payload(cfg, auth: AuthRecord) -> tuple[dict[str, Any], list[str]]:
    private_query = _load_private_login_query(cfg)
    timezone_name = _meta(auth, "timezone", default=str(cfg.devplay.get("timezone") or "Asia/Bangkok"))
    country = _meta(auth, "country", default=str(cfg.devplay.get("location_country") or private_query.get("country_code") or "US"))
    version = _meta(auth, "version", default=str(cfg.game.get("version") or private_query.get("lc.app_version") or ""))
    build_version = _meta(auth, "version-code", "version_code", default=str(cfg.game.get("build_version") or private_query.get("lc.app_build") or ""))
    os_type = _meta(auth, "os.type", "osType", default=str(cfg.devplay.get("os_type") or "A"))
    os_version = _meta(auth, "os_version", "os-version", default=str(cfg.devplay.get("os_version") or private_query.get("lc.os_version") or "12"))
    market_type = _meta(auth, "market_type", "market-type", default=str(cfg.devplay.get("market_type") or private_query.get("lc.store") or "GOOGLE_PLAY"))
    locale = _meta(auth, "locale", default=str(cfg.devplay.get("locale") or private_query.get("lc.locale_on_game") or "en-US"))
    device_name = _meta(auth, "device-name", "device_name", default=str(cfg.devplay.get("device_name") or private_query.get("lc.device.model") or ""))
    device_model = _meta(auth, "device-model", "device_model", default=str(cfg.devplay.get("device_model") or private_query.get("lc.device.model") or device_name))
    device_id = _meta(auth, "device-id", "device_id") or auth.device_id or str(cfg.devplay.get("device_id") or private_query.get("device_id") or "")
    fgs_id = _meta(auth, "fgs-id", "fgs_id") or auth.fgs_id or private_query.get("lc.fgs_id") or private_query.get("lc.new_fgs_id") or ""
    login_platform = _meta(auth, "login_platform", "login-platform", default=str(cfg.devplay.get("login_platform") or "email"))
    semi_device_id = _first(
        _meta(auth, "semiDeviceId", "semi_device_id", default=""),
        cfg.devplay.get("semi_device_id"),
        private_query.get("lc.semi_device_id"),
    )
    push_token = _first(
        _meta(auth, "pushToken", "push_token", default=""),
        cfg.devplay.get("push_token"),
        private_query.get("push_token"),
    )
    ms, _ = _game_process_ms(auth)
    tz_distance, _ = _timezone_distance_seconds(auth, timezone_name)

    agreement_seq = cfg.devplay.get("agreementSeq")
    if agreement_seq in (None, ""):
        agreement_seq = _split_ids(private_query.get("terms_updates_ids"))
    else:
        agreement_seq = _maybe_json(agreement_seq)

    payload: dict[str, Any] = {
        "pid": INIT_MEMBER_ENDPOINT,
        # Ghidra 5.5 FUN_013CA56C adds these native keys for initMember3.
        "mid": auth.mid,
        "playerId": auth.mid,
        "agreementSeq": agreement_seq,
        "pushToken": push_token,
        "accessToken": auth.game_access_token,
        "agreement": _build_agreement(cfg, private_query),
        "mobclixSignature": _first(cfg.devplay.get("mobclix_signature"), cfg.devplay.get("mobclixSignature")),
        "macAddress": _first(cfg.devplay.get("mac_address"), cfg.devplay.get("macAddress")),
        # Existing common DS fields used by the proven V1 request family.
        "socialUidCommon": auth.mid,
        "ver": version,
        "buildVer": build_version,
        "cc": country,
        "ms": int(ms or 0),
        "osType": os_type,
        "osVersion": os_version,
        "timeZone": timezone_name,
        "timeZoneDistance": int(tz_distance or 0),
        "marketType": market_type,
        "carrier": _meta(auth, "carrier", default=""),
        "fgsId": fgs_id,
        "semiDeviceId": semi_device_id,
        "locale": locale,
        "deviceId": device_id,
        "deviceName": device_name,
        "deviceModel": device_model,
        "loginPlatform": login_platform,
        "cable": _new_cable(),
    }
    required = [
        "mid", "playerId", "pushToken", "accessToken", "socialUidCommon",
        "ver", "buildVer", "cc", "osType", "osVersion", "timeZone",
        "marketType", "fgsId", "semiDeviceId", "locale", "deviceId",
        "deviceName", "deviceModel", "loginPlatform", "cable",
    ]
    return payload, [k for k in required if payload.get(k) in (None, "")]


def _deep_find(obj: Any, key: str):
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            hit = _deep_find(v, key)
            if hit not in (None, ""):
                return hit
    elif isinstance(obj, list):
        for v in obj:
            hit = _deep_find(v, key)
            if hit not in (None, ""):
                return hit
    return None


def bootstrap_session(cfg, slot: str, auth: AuthRecord, event_cb: Event | None = None) -> SessionRecord:
    import requests

    payload, missing = build_init_member_payload(cfg, auth)
    if missing:
        raise SessionBootstrapError("initMember3 missing common fields: " + ",".join(missing))
    plaintext = compact_json_bytes(payload)
    encoded = encode_v4(plaintext)
    if decode_v4_form_body(encoded.form_body).rstrip(b" ") != plaintext:
        raise SessionBootstrapError("DS v4 self-check failed")

    base = str(cfg.server.get("game_base_url") or "").rstrip("/") + "/"
    url = urljoin(base, INIT_MEMBER_ENDPOINT)
    if event_cb:
        event_cb(f"SESSION INIT START slot={slot}")
        event_cb(
            "SESSION INIT PROFILE "
            f"payload_keys={len(payload)} present={_public_present_profile(payload)} secretOutput=NONE"
        )
    started = time.monotonic()
    try:
        status_code, response_body, _response_headers = pooled_post_bytes(
            url=url,
            body=encoded.form_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=float(cfg.server.get("timeout_seconds") or 20),
            verify=bool(cfg.server.get("verify_ssl", True)),
        )
    except Exception as exc:
        raise SessionBootstrapError(f"initMember3 transport failed: {type(exc).__name__}") from exc

    try:
        wrapper = json.loads(response_body.decode("utf-8-sig"))
    except Exception as exc:
        raise SessionBootstrapError(f"initMember3 HTTP {status_code}: wrapper is not JSON") from exc
    code = wrapper.get("responseCode") if isinstance(wrapper, dict) else None
    msg = wrapper.get("responseMessage") if isinstance(wrapper, dict) else None
    if not (200 <= status_code < 300) or code != 200:
        raise SessionBootstrapError(
            f"initMember3 failed HTTP={status_code} responseCode={code} "
            f"message={str(msg)[:80]} profile={_public_present_profile(payload)} secretOutput=NONE"
        )

    data_b64 = wrapper.get("responseData") or ""
    if not data_b64:
        raise SessionBootstrapError("initMember3 responseData is empty")
    try:
        obj, decode_mode, decode_profile = _decode_init_member_response_data(data_b64)
    except Exception as exc:
        raise SessionBootstrapError(f"initMember3 decode failed: {type(exc).__name__}: {exc}") from exc

    if event_cb:
        top_keys = sorted(obj.keys())[:12] if isinstance(obj, dict) else []
        event_cb(
            "SESSION INIT DECODE "
            f"mode={decode_mode} profile={decode_profile} top_keys={','.join(map(str, top_keys))} secretOutput=NONE"
        )

    try:
        member_seq = int(_deep_find(obj, "memberSeq") or 0)
        current_lv = int(_deep_find(obj, "lv") or _deep_find(obj, "currentLv") or 0)
        session_key = str(_deep_find(obj, "sessionKey") or "")
    except Exception as exc:
        raise SessionBootstrapError("initMember3 session fields have invalid type") from exc
    if member_seq <= 0 or not session_key:
        top = sorted(obj.keys()) if isinstance(obj, dict) else []
        raise SessionBootstrapError("initMember3 did not return memberSeq/sessionKey; keys=" + ",".join(top[:40]))

    if event_cb:
        event_cb(f"SESSION INIT OK slot={slot} memberSeq=present lv={current_lv} {round((time.monotonic()-started)*1000)}ms")
    return SessionRecord(
        schema="mwoif-heart-v3-session-runtime",
        account_kind=auth.account_kind,
        account_id=auth.account_id,
        member_seq=member_seq,
        current_lv=current_lv,
        session_key=session_key,
        source="email_login_initMember3",
        imported_at=datetime.now(timezone.utc).isoformat(),
    )
