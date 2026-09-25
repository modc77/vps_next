from __future__ import annotations

import secrets
import string
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin
from zoneinfo import ZoneInfo

from mwoif.session.models import AuthRecord, SessionRecord
from mwoif.net.http_pool import pooled_post_bytes

_CABLE_ALPHABET = string.ascii_letters + string.digits

REQUIRED_DS_FIELDS = (
    "memberSeq", "sessionKey", "socialUidCommon", "ver", "buildVer", "cc",
    "osType", "osVersion", "timeZone", "marketType", "fgsId", "locale",
    "deviceId", "deviceName", "deviceModel", "accessToken", "loginPlatform", "cable",
)


def build_url(cfg, endpoint: str) -> str:
    base = str(cfg.server.get("game_base_url") or "").strip()
    if not base:
        return ""
    if not base.endswith("/"):
        base += "/"
    return urljoin(base, endpoint)


def meta(auth: AuthRecord, *keys: str, default: str = "") -> str:
    for key in keys:
        value = auth.metadata.get(key)
        if value not in (None, ""):
            return str(value)
    return default


def parse_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def timezone_distance_seconds(auth: AuthRecord, timezone_name: str, explicit: int | None = None) -> tuple[int | None, str]:
    if explicit is not None:
        return int(explicit), "CLI_OVERRIDE"
    for key in ("time-zone-distance", "timeZoneDistance", "timezone-distance", "timezone_distance"):
        parsed = parse_int(auth.metadata.get(key))
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


def new_cable(length: int = 20) -> str:
    return "".join(secrets.choice(_CABLE_ALPHABET) for _ in range(length))


def game_process_ms(auth: AuthRecord, explicit: int | None = None) -> tuple[int | None, str]:
    if explicit is not None:
        return max(0, int(explicit)), "CLI_OVERRIDE"
    base = None
    source_key = ""
    for key in ("game-process-elapsed-ms", "game_process_elapsed_ms", "gameProcessElapsedMs"):
        parsed = parse_int(auth.metadata.get(key))
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


def common_ds_fields(*, cfg, actor_session: SessionRecord, actor_auth: AuthRecord, endpoint: str, ms: int | None = None, cable: str | None = None, fgs_id: str | None = None, timezone_distance: int | None = None) -> tuple[dict[str, Any], dict[str, str], dict[str, str]]:
    if not actor_session.established:
        raise ValueError("actor session is not established")
    if not actor_auth.ready:
        raise ValueError("actor Auth context is not ready")

    timezone_name = meta(actor_auth, "timezone", default=str(cfg.devplay.get("timezone") or ""))
    country = meta(actor_auth, "country", default=str(cfg.devplay.get("location_country") or "US"))
    version = meta(actor_auth, "version", default=str(cfg.game.get("version") or ""))
    build_version = meta(actor_auth, "version-code", "version_code", default=str(cfg.game.get("build_version") or ""))
    os_type = meta(actor_auth, "os.type", "osType", default=str(cfg.devplay.get("os_type") or "A"))
    os_version = meta(actor_auth, "os_version", "os-version", default=str(cfg.devplay.get("os_version") or ""))
    market_type = meta(actor_auth, "market_type", "market-type", default=str(cfg.devplay.get("market_type") or "GOOGLE_PLAY"))
    locale = meta(actor_auth, "locale", default=str(cfg.devplay.get("locale") or "en-US"))
    device_name = meta(actor_auth, "device-name", "device_name", default=str(cfg.devplay.get("device_name") or cfg.devplay.get("model") or ""))
    device_model = meta(actor_auth, "device-model", "device_model", default=str(cfg.devplay.get("device_model") or device_name))
    device_id = meta(actor_auth, "device-id", "device_id") or actor_auth.device_id or str(cfg.devplay.get("device_id") or "")
    resolved_fgs_id = str(fgs_id).strip() if fgs_id not in (None, "") else (meta(actor_auth, "fgs-id", "fgs_id") or actor_auth.fgs_id)
    login_platform = meta(actor_auth, "login_platform", "login-platform", default=str(cfg.devplay.get("login_platform") or "email"))

    resolved_ms, ms_source = game_process_ms(actor_auth, explicit=ms)
    resolved_tz_distance, tz_source = timezone_distance_seconds(actor_auth, timezone_name, explicit=timezone_distance)

    payload: dict[str, Any] = {
        "pid": endpoint,
        "memberSeq": int(actor_session.member_seq),
        "sessionKey": actor_session.session_key,
        "currentLv": int(actor_session.current_lv),
        "socialUidCommon": actor_auth.mid,
        "ver": version,
        "buildVer": build_version,
        "cc": country,
        "ms": int(resolved_ms or 0),
        "osType": os_type,
        "osVersion": os_version,
        "timeZone": timezone_name,
        "timeZoneDistance": int(resolved_tz_distance or 0),
        "marketType": market_type,
        "carrier": meta(actor_auth, "carrier", default=""),
        "fgsId": resolved_fgs_id,
        "locale": locale,
        "deviceId": device_id,
        "deviceName": device_name,
        "deviceModel": device_model,
        "accessToken": actor_auth.game_access_token,
        "loginPlatform": login_platform,
        "cable": cable or new_cable(),
    }
    missing = {key: "missing" for key in REQUIRED_DS_FIELDS if payload.get(key) in (None, "")}
    if resolved_ms is None:
        missing["ms"] = "missing game-process-elapsed-ms"
    if resolved_tz_distance is None:
        missing["timeZoneDistance"] = "missing time-zone-distance"
    sources = {
        "ms": ms_source,
        "timeZoneDistance": tz_source,
        "fgsId": "CLI_OVERRIDE" if fgs_id not in (None, "") else ("AUTH_METADATA" if resolved_fgs_id else "MISSING"),
        "cable": "CLI_OVERRIDE" if cable else "GENERATED_20_CHAR_ALNUM",
        "loginPlatform": "AUTH_METADATA_OR_EMAIL_FALLBACK",
    }
    return payload, missing, sources


def redacted_payload(payload: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if key in {"sessionKey", "accessToken"}:
            out[key] = f"<REDACTED len={len(str(value))}>" if value else "<MISSING>"
        elif key == "cable":
            out[key] = f"<GENERATED len={len(str(value))}>" if value else "<MISSING>"
        else:
            out[key] = value
    return out


def post_ds_v4(*, cfg, url: str, body: bytes, timeout: float) -> tuple[bool, dict[str, Any]]:
    import json
    started = time.monotonic()
    try:
        status_code, response_body, _response_headers = pooled_post_bytes(
            url=url,
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
            verify=bool(cfg.server.get("verify_ssl", True)),
        )
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        wrapper: dict[str, Any] | None = None
        try:
            parsed = json.loads(response_body.decode("utf-8-sig"))
            if isinstance(parsed, dict):
                wrapper = parsed
        except Exception:
            wrapper = None
        info = {
            "elapsed_ms": elapsed_ms,
            "http_status": status_code,
            "response_bytes": len(response_body or b""),
            "response_code": wrapper.get("responseCode") if wrapper else None,
            "response_message": wrapper.get("responseMessage") if wrapper else None,
            "response_data_present": bool(wrapper and wrapper.get("responseData")),
            "wrapper_json_present": wrapper is not None,
        }
        return bool(200 <= status_code < 300), {"wrapper": wrapper, "public": info}
    except Exception as exc:
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        return False, {"error": "HTTP_REQUEST_FAILED", "message": f"{type(exc).__name__}: {exc}", "elapsed_ms": elapsed_ms}
