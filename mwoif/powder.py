from __future__ import annotations

import json
import re
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


POWDER_BUY_ENDPOINT = "shop/buyStuff.ds"
POWDER_CONSUME_ENDPOINT = "shop/consumeTreasure.ds"
NORMAL_BOX_PRICE = 5000
NORMAL_BOX_BUY_TYPE = 0
TREASURE_ID_RE = re.compile(r"^(?P<group_seq>\d+):(?P<tag>\d+)@(?P<uuid>[^@]+)$")
Event = Callable[[str], None]


class PowderError(RuntimeError):
    pass


@dataclass(slots=True, frozen=True)
class TreasureRef:
    raw_id: str
    group_seq: int
    tag: int
    uuid: str

    def request_item(self) -> dict[str, Any]:
        return {"groupSeq": self.group_seq, "tag": self.tag, "uuid": self.uuid}


@dataclass(slots=True)
class PowderSnapshot:
    session: SessionRecord
    coin: int
    powder: int
    shard: int
    inventory_ids: tuple[str, ...]
    treasures: tuple[TreasureRef, ...]

    def public_summary(self) -> dict[str, Any]:
        return {
            "memberSeq": "present" if self.session.member_seq > 0 else "missing",
            "lv": self.session.current_lv,
            "coin": self.coin,
            "powder": self.powder,
            "shard": self.shard,
            "inventoryCount": len(self.inventory_ids),
            "treasureCount": len(self.treasures),
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


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def parse_treasure_id(raw_id: str) -> TreasureRef | None:
    m = TREASURE_ID_RE.fullmatch(str(raw_id or "").strip())
    if not m:
        return None
    group_seq = int(m.group("group_seq"))
    if not 1_300_000 <= group_seq <= 1_399_999:
        return None
    return TreasureRef(
        raw_id=str(raw_id),
        group_seq=group_seq,
        tag=int(m.group("tag")),
        uuid=m.group("uuid"),
    )


def _inventory_ids(obj: Any) -> tuple[str, ...]:
    rows = obj.get("inventoryItemList") if isinstance(obj, dict) else None
    if not isinstance(rows, list):
        return ()
    out: list[str] = []
    for row in rows:
        if isinstance(row, dict):
            raw = str(row.get("id") or "").strip()
            if raw:
                out.append(raw)
    return tuple(out)


def fetch_powder_snapshot(cfg, *, slot: str, auth: AuthRecord, event_cb: Event | None = None) -> PowderSnapshot:
    payload, missing = build_init_member_payload(cfg, auth)
    if missing:
        raise PowderError("INITMEMBER3_MISSING:" + ",".join(missing))

    encoded = encode_v4(compact_json_bytes(payload))
    base = str(cfg.server.get("game_base_url") or "").rstrip("/") + "/"
    url = urljoin(base, INIT_MEMBER_ENDPOINT)
    if event_cb:
        event_cb(f"POWDER SNAPSHOT START slot={slot} endpoint={INIT_MEMBER_ENDPOINT}")

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
        raise PowderError(f"INITMEMBER3_NETWORK_ERROR:{type(exc).__name__}") from exc

    try:
        wrapper = json.loads(response_body.decode("utf-8-sig"))
    except Exception as exc:
        raise PowderError(f"INITMEMBER3_WRAPPER_INVALID:http={status_code}") from exc

    response_code = wrapper.get("responseCode") if isinstance(wrapper, dict) else None
    if not (200 <= int(status_code) < 300) or response_code != 200:
        raise PowderError(f"INITMEMBER3_REJECTED:http={status_code}:responseCode={response_code}")

    try:
        obj, _, _ = _decode_init_member_response_data(wrapper.get("responseData") or "")
    except Exception as exc:
        raise PowderError(f"INITMEMBER3_DECODE_ERROR:{type(exc).__name__}") from exc

    member_seq = _as_int(_deep_find(obj, "memberSeq"))
    current_lv = _as_int(_deep_find(obj, "lv") or _deep_find(obj, "currentLv"))
    session_key = str(_deep_find(obj, "sessionKey") or "")
    cash_info = obj.get("cashInfo") if isinstance(obj, dict) else None
    cash_info = cash_info if isinstance(cash_info, dict) else {}
    coin = _as_int(cash_info.get("coin", _deep_find(obj, "coin")), -1)
    powder = _as_int(cash_info.get("powder", _deep_find(obj, "powder")), -1)
    shard = _as_int(cash_info.get("shard", _deep_find(obj, "shard")), -1)
    inventory_ids = _inventory_ids(obj)
    treasures = tuple(x for raw in inventory_ids if (x := parse_treasure_id(raw)) is not None)

    if member_seq <= 0 or not session_key:
        raise PowderError("INITMEMBER3_SESSION_MISSING")
    if min(coin, powder, shard) < 0:
        raise PowderError("INITMEMBER3_POWDER_FIELDS_MISSING")

    session = SessionRecord(
        schema="mwoif-powder-v1-session-runtime",
        account_kind=auth.account_kind,
        account_id=auth.account_id,
        member_seq=member_seq,
        current_lv=current_lv,
        session_key=session_key,
        source="email_login_initMember3_powder_snapshot",
        imported_at=datetime.now(timezone.utc).isoformat(),
    )
    if event_cb:
        event_cb(
            f"POWDER SNAPSHOT OK slot={slot} lv={current_lv} coin={coin} powder={powder} "
            f"shard={shard} treasureCount={len(treasures)} elapsedMs={round((time.monotonic()-started)*1000)}"
        )
    return PowderSnapshot(session, coin, powder, shard, inventory_ids, treasures)


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


def _request(cfg, auth: AuthRecord, session: SessionRecord, endpoint: str, body_fields: dict[str, Any], *, live: bool, timeout: float, action: str) -> dict[str, Any]:
    common, missing, sources = common_ds_fields(
        cfg=cfg,
        actor_session=session,
        actor_auth=auth,
        endpoint=endpoint,
    )
    payload = dict(common)
    payload.update(body_fields)
    plaintext = compact_json_bytes(payload)
    encoded = encode_v4(plaintext)
    self_check = decode_v4_form_body(encoded.form_body).rstrip(b" ") == plaintext
    url = build_url(cfg, endpoint)
    result: dict[str, Any] = {
        "ok": bool(self_check and not missing),
        "read_only": not live,
        "network_action_enabled": False,
        "action": action,
        "endpoint": endpoint,
        "payload_redacted": redacted_payload(payload),
        "missing_live_fields": sorted(missing),
        "runtime_field_sources": sources,
        "crypto_self_check": self_check,
        "secretOutput": "NONE",
    }
    if not self_check:
        result.update({"ok": False, "error": "DS_V4_SELF_CHECK_FAILED"})
        return result
    if missing:
        result.update({"ok": False, "error": "DS_COMMON_FIELDS_MISSING"})
        return result
    if not live:
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
        if isinstance(decoded, dict):
            result["response_root_keys"] = sorted(str(k) for k in decoded.keys())
    except Exception as exc:
        result["response_data_decoded"] = False
        result["response_decode_error"] = type(exc).__name__
    return result


def buy_normal_box(cfg, *, auth: AuthRecord, session: SessionRecord, stuff_seq: int, live: bool, timeout: float = 20.0) -> dict[str, Any]:
    return _request(
        cfg,
        auth,
        session,
        POWDER_BUY_ENDPOINT,
        {"stuffSeq": int(stuff_seq), "price": NORMAL_BOX_PRICE, "buyType": NORMAL_BOX_BUY_TYPE},
        live=live,
        timeout=timeout,
        action="powder-buy-normal-box",
    )


def consume_treasure(cfg, *, auth: AuthRecord, session: SessionRecord, treasure: TreasureRef, powder_qty: int, shard_qty: int, live: bool, timeout: float = 20.0) -> dict[str, Any]:
    return _request(
        cfg,
        auth,
        session,
        POWDER_CONSUME_ENDPOINT,
        {"itemList": [treasure.request_item()], "powderQty": int(powder_qty), "shardQty": int(shard_qty)},
        live=live,
        timeout=timeout,
        action="powder-consume-new-treasure",
    )

SHOP_GET_INFO_METHOD = "/service.api.ShopAPI/GetShopInfo"


def _proto_varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not (b & 0x80):
            return value, pos
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")
    raise ValueError("truncated varint")


def _scan_proto_scalars(
    data: bytes,
    *,
    path: tuple[int, ...] = (),
    depth: int = 0,
    max_depth: int = 7,
    max_fields: int = 5000,
) -> list[dict[str, Any]]:
    pos = 0
    seen = 0
    out: list[dict[str, Any]] = []
    while pos < len(data) and seen < max_fields:
        seen += 1
        tag, pos = _proto_varint(data, pos)
        field = tag >> 3
        wire_type = tag & 7
        if field <= 0:
            raise ValueError("invalid field")
        current = path + (field,)
        parent = path
        if wire_type == 0:
            value, pos = _proto_varint(data, pos)
            out.append({"path": list(current), "parent": list(parent), "kind": "varint", "value": value})
        elif wire_type == 1:
            if pos + 8 > len(data):
                raise ValueError("truncated fixed64")
            raw = data[pos:pos + 8]
            pos += 8
            out.append({"path": list(current), "parent": list(parent), "kind": "fixed64", "hex": raw.hex()})
        elif wire_type == 2:
            size, pos = _proto_varint(data, pos)
            if size < 0 or pos + size > len(data):
                raise ValueError("truncated length field")
            raw = data[pos:pos + size]
            pos += size
            try:
                text_value = raw.decode("utf-8")
                if text_value and text_value.isprintable() and len(text_value) <= 256:
                    out.append({"path": list(current), "parent": list(parent), "kind": "utf8", "value": text_value})
            except Exception:
                pass
            if depth < max_depth and raw:
                try:
                    out.extend(
                        _scan_proto_scalars(
                            raw,
                            path=current,
                            depth=depth + 1,
                            max_depth=max_depth,
                            max_fields=max_fields,
                        )
                    )
                except Exception:
                    pass
        elif wire_type == 5:
            if pos + 4 > len(data):
                raise ValueError("truncated fixed32")
            raw = data[pos:pos + 4]
            pos += 4
            out.append({"path": list(current), "parent": list(parent), "kind": "fixed32", "hex": raw.hex()})
        else:
            raise ValueError(f"unsupported wire type {wire_type}")
    return out


def _shop_info_enricher(raw: bytes) -> dict[str, Any]:
    try:
        scalars = _scan_proto_scalars(raw)
    except Exception as exc:
        return {
            "shop_info_scan_ok": False,
            "shop_info_scan_error": type(exc).__name__,
            "shop_info_response_bytes": len(raw),
        }

    price_hits = [x for x in scalars if x.get("kind") == "varint" and x.get("value") == NORMAL_BOX_PRICE]
    candidates: list[dict[str, Any]] = []
    seen_parents: set[tuple[int, ...]] = set()
    for hit in price_hits:
        parent = tuple(hit.get("parent") or ())
        if parent in seen_parents:
            continue
        seen_parents.add(parent)
        siblings = [x for x in scalars if tuple(x.get("parent") or ()) == parent]
        candidates.append({
            "parent": list(parent),
            "fields": siblings[:40],
        })

    printable = [x for x in scalars if x.get("kind") == "utf8"]
    small_varints = [
        x for x in scalars
        if x.get("kind") == "varint" and 0 <= int(x.get("value") or 0) <= 10_000_000
    ]
    return {
        "shop_info_scan_ok": True,
        "shop_info_response_bytes": len(raw),
        "shop_info_scalar_count": len(scalars),
        "shop_info_price5000_hits": len(price_hits),
        "shop_info_price5000_candidates": candidates[:20],
        "shop_info_strings": printable[:200],
        "shop_info_varints": small_varints[:400],
    }


def get_shop_info(cfg, *, auth: AuthRecord, timeout: float = 12.0, execute: bool = True) -> dict[str, Any]:
    from mwoif.friend.service import _grpc_call

    result = _grpc_call(
        cfg=cfg,
        slot="POWDER_SHOP",
        auth=auth,
        action="powder-shop-info",
        method_path=SHOP_GET_INFO_METHOD,
        request_body=b"",
        timeout=timeout,
        live=bool(execute),
        read_only_action=True,
        schema={"request": "empty-protobuf-probe", "purpose": "resolve Treasure Shop contract"},
        response_enricher=_shop_info_enricher if execute else None,
    )
    result["transport"] = "shop-grpc"
    return result

POWDER_CONFIG_CHECK_ENDPOINT = "check/configCheck.ds"


def _safe_config_candidates(obj: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    wanted = ("url", "index", "resource", "cdn", "hash", "file", "contents", "version")
    secretish = ("token", "session", "password", "secret", "auth", "access")

    def walk(value: Any, path: tuple[str, ...] = ()) -> None:
        if len(out) >= 200:
            return
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, path + (str(key),))
        elif isinstance(value, list):
            for index, child in enumerate(value[:100]):
                walk(child, path + (str(index),))
        elif isinstance(value, (str, int, float, bool)) or value is None:
            key_path = ".".join(path)
            lowered = key_path.lower()
            if any(x in lowered for x in secretish):
                return
            if any(x in lowered for x in wanted):
                text_value = "" if value is None else str(value)
                if len(text_value) > 500:
                    text_value = text_value[:500] + "..."
                out.append({"path": key_path, "value": text_value})

    walk(obj)
    return out


def config_check(cfg, *, auth: AuthRecord, session: SessionRecord, live: bool = True, timeout: float = 20.0) -> dict[str, Any]:
    common, missing, sources = common_ds_fields(
        cfg=cfg,
        actor_session=session,
        actor_auth=auth,
        endpoint=POWDER_CONFIG_CHECK_ENDPOINT,
    )
    payload = dict(common)
    plaintext = compact_json_bytes(payload)
    encoded = encode_v4(plaintext)
    self_check = decode_v4_form_body(encoded.form_body).rstrip(b" ") == plaintext
    result: dict[str, Any] = {
        "ok": bool(self_check and not missing),
        "read_only": True,
        "network_action_enabled": False,
        "action": "powder-config-check-read-only",
        "endpoint": POWDER_CONFIG_CHECK_ENDPOINT,
        "payload_redacted": redacted_payload(payload),
        "missing_live_fields": sorted(missing),
        "runtime_field_sources": sources,
        "crypto_self_check": self_check,
        "secretOutput": "NONE",
    }
    if not self_check:
        result.update({"ok": False, "error": "DS_V4_SELF_CHECK_FAILED"})
        return result
    if missing:
        result.update({"ok": False, "error": "DS_COMMON_FIELDS_MISSING"})
        return result
    if not live:
        return result

    http_ok, info = post_ds_v4(
        cfg=cfg,
        url=build_url(cfg, POWDER_CONFIG_CHECK_ENDPOINT),
        body=encoded.form_body,
        timeout=timeout,
    )
    result["network_action_enabled"] = True
    public = info.get("public", info) if isinstance(info, dict) else {}
    if isinstance(public, dict):
        result.update(public)
    wrapper = info.get("wrapper") if isinstance(info, dict) else None
    app_code = wrapper.get("responseCode") if isinstance(wrapper, dict) else None
    app_message = wrapper.get("responseMessage") if isinstance(wrapper, dict) else None
    result["response_code"] = app_code
    result["response_message"] = app_message
    result["ok"] = bool(http_ok and app_code == 200)

    try:
        decoded = _decode_response_data(wrapper)
        result["response_data_decoded"] = decoded is not None
        result["config_response_decoded"] = isinstance(decoded, (dict, list))
        if isinstance(decoded, dict):
            result["config_root_keys"] = sorted(str(k) for k in decoded.keys())[:200]
            result["config_candidates"] = _safe_config_candidates(decoded)
        elif isinstance(decoded, list):
            result["config_root_type"] = "list"
            result["config_candidates"] = _safe_config_candidates(decoded)
    except Exception as exc:
        result["response_data_decoded"] = False
        result["config_response_decoded"] = False
        result["config_discovery_error"] = type(exc).__name__
    return result
