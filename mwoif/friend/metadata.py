from __future__ import annotations

from typing import Any

from mwoif.session.models import AuthRecord

NATIVE_ORDER = [
    "authorization",
    "player-id",
    "combo-name",
    "index-file-hash",
    "version",
    "version-code",
    "timezone",
    "country",
    "os.type",
    "os_version",
    "login_platform",
    "market_type",
    "fgs-id",
    "locale",
    "device-id",
    "device-name",
    "device-model",
]


def _put_if_missing(values: dict[str, str], key: str, value: Any) -> None:
    if not values.get(key) and value not in (None, ""):
        values[key] = str(value)


def fixed_auth_metadata(cfg, *, mid: str) -> dict[str, str]:
    dev = cfg.devplay
    game = cfg.game
    server = cfg.server
    values = {
        "runtime-metadata-version": dev.get("runtime_metadata_version", "V3_FROM_V2_PASS"),
        "player-id": mid,
        "version": game.get("version", ""),
        "version-code": game.get("build_version", ""),
        "timezone": dev.get("timezone", "Asia/Bangkok"),
        "country": dev.get("location_country", "US"),
        "os.type": dev.get("os_type", "A"),
        "os_version": dev.get("os_version", "12"),
        "locale": dev.get("locale", "en-US"),
        "device-name": dev.get("device_name", dev.get("model", "")),
        "device-model": dev.get("device_model", dev.get("model", "")),
        "device-id": dev.get("device_id", ""),
        "index-file-hash": game.get("index_file_hash", ""),
        "time-zone-distance": dev.get("time_zone_distance", "25200"),
        "market_type": dev.get("market_type", "GOOGLE_PLAY"),
        "login_platform": dev.get("login_platform", "email"),
        "friend-grpc-target": server.get("friend_grpc_target", ""),
    }
    return {str(k): str(v) for k, v in values.items() if v not in (None, "")}


def build_metadata(
    *,
    cfg,
    slot: str,
    auth: AuthRecord,
    extra: dict[str, Any] | None = None,
) -> tuple[list[tuple[str, str]], list[str]]:
    if not auth.ready:
        raise ValueError("auth context is not ready")
    if not auth.game_access_token:
        raise ValueError("game_access_token is required")
    if not auth.mid:
        raise ValueError("MID/player-id is required")

    values: dict[str, str] = fixed_auth_metadata(cfg, mid=auth.mid)
    values.update({str(k): str(v) for k, v in auth.metadata.items() if v not in (None, "")})

    values["authorization"] = "Bearer " + auth.game_access_token
    values["player-id"] = auth.mid
    _put_if_missing(values, "fgs-id", auth.fgs_id)
    _put_if_missing(values, "device-id", auth.device_id)

    if extra:
        for k, v in extra.items():
            if v not in (None, ""):
                values[str(k)] = str(v)

    metadata = [(key, values[key]) for key in NATIVE_ORDER if values.get(key) not in (None, "")]
    missing_dynamic = [key for key in ("combo-name", "login_platform", "fgs-id") if not values.get(key)]
    return metadata, missing_dynamic


def redacted_metadata(items: list[tuple[str, str]]) -> list[list[str]]:
    out: list[list[str]] = []
    for key, value in items:
        if key == "authorization":
            token_len = max(0, len(value) - len("Bearer "))
            value = f"Bearer <REDACTED len={token_len}>"
        out.append([key, value])
    return out
