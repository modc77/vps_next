from __future__ import annotations

import hashlib
import os
import time
import threading
from typing import Any, Callable

from mwoif.friend.capacity import parse_friend_list_response
from mwoif.friend.metadata import build_metadata, redacted_metadata
from mwoif.friend.proto import (
    build_handle_friend_request,
    build_remove_friend_request,
    build_send_friend_request,
)
from mwoif.friend.wire import WireError, inspect_message
from mwoif.session.models import AuthRecord

LIST_FRIENDS_METHOD = "/service.api.FriendAPI/ListFriends"
SEND_FRIEND_REQUEST_METHOD = "/service.api.FriendAPI/SendFriendRequest"
HANDLE_FRIEND_REQUEST_METHOD = "/service.api.FriendAPI/HandleFriendRequest"
REMOVE_FRIEND_METHOD = "/service.api.FriendAPI/RemoveFriend"

_GRPC_CHANNELS: dict[str, Any] = {}
_GRPC_CHANNELS_LOCK = threading.RLock()


def _shared_grpc_channel(target: str):
    import grpc  # type: ignore
    with _GRPC_CHANNELS_LOCK:
        channel = _GRPC_CHANNELS.get(target)
        if channel is None:
            channel = grpc.secure_channel(
                target,
                grpc.ssl_channel_credentials(),
                options=(
                    ("grpc.keepalive_time_ms", 30000),
                    ("grpc.keepalive_timeout_ms", 10000),
                    ("grpc.keepalive_permit_without_calls", 1),
                    ("grpc.enable_retries", 1),
                ),
            )
            _GRPC_CHANNELS[target] = channel
        return channel



def _clean_target(value: Any) -> str:
    target = str(value or "").strip()
    if not target:
        return ""
    for prefix in ("grpc://", "grpcs://", "https://", "http://"):
        if target.lower().startswith(prefix):
            target = target[len(prefix):]
            break
    target = target.strip().rstrip("/")
    if "/" in target:
        target = target.split("/", 1)[0]
    if target and ":" not in target:
        target = f"{target}:443"
    return target


def resolve_friend_grpc_target(*, cfg, auth: AuthRecord) -> tuple[str, str]:
    for key in ("friend-grpc-target", "friend_grpc_target", "grpc-target", "grpc_target", "game-grpc-target", "game_grpc_target", "grpc"):
        target = _clean_target(auth.metadata.get(key))
        if target:
            return target, f"auth.metadata.{key}"
    env_target = _clean_target(os.getenv("MWOIF_FRIEND_GRPC_TARGET", ""))
    if env_target:
        return env_target, "env:MWOIF_FRIEND_GRPC_TARGET"
    target = _clean_target(cfg.server.get("friend_grpc_target", ""))
    if target:
        return target, "config.server.friend_grpc_target"
    return "", "missing"


def classify_failure(code: str) -> str:
    return {
        "UNAUTHENTICATED": "auth_token_or_authorization",
        "PERMISSION_DENIED": "auth_or_common_metadata",
        "INVALID_ARGUMENT": "protobuf_or_required_metadata",
        "UNIMPLEMENTED": "wrong_method_path_or_service",
        "FAILED_PRECONDITION": "account_or_server_state",
        "UNAVAILABLE": "dns_tls_connectivity_or_backend",
        "DEADLINE_EXCEEDED": "network_or_backend_timeout",
    }.get(code, "grpc_or_server")


def _public_request_summary(action: str, body: bytes, schema: dict[str, Any]) -> dict[str, Any]:
    return {"action": action, "request_bytes": len(body), "request_fp": hashlib.sha256(body).hexdigest()[:12], "schema": schema}


def _grpc_call(
    *,
    cfg,
    slot: str,
    auth: AuthRecord,
    action: str,
    method_path: str,
    request_body: bytes,
    extra_metadata: dict[str, Any] | None = None,
    timeout: float = 12.0,
    live: bool = False,
    schema: dict[str, Any] | None = None,
    read_only_action: bool = False,
    response_enricher: Callable[[bytes], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    target, target_source = resolve_friend_grpc_target(cfg=cfg, auth=auth)
    base = {
        "ok": True,
        "read_only": bool(read_only_action or not live),
        "network_action_enabled": bool(live and target),
        "transport": "friend-grpc",
        "host": target,
        "host_source": target_source,
        "method": method_path,
        **_public_request_summary(action, request_body, schema or {}),
        "secretOutput": "NONE",
    }
    if not target:
        base.update({"ok": False, "network_action_enabled": False, "error": "FRIEND_GRPC_TARGET_MISSING", "message": "Set MWOIF_FRIEND_GRPC_TARGET or keep config default from V1-pass target."})
        return base
    metadata, missing = build_metadata(cfg=cfg, slot=slot, auth=auth, extra=extra_metadata)
    base["metadata"] = redacted_metadata(metadata)
    base["missing_dynamic_metadata"] = missing
    if not live:
        base["write_guard"] = "PREVIEW_ONLY_ADD_--live_TO_EXECUTE"
        base["network_action_enabled"] = False
        return base
    try:
        import grpc  # type: ignore
    except Exception as exc:
        base.update({"ok": False, "network_action_enabled": False, "error": "GRPCIO_MISSING", "message": str(exc)})
        return base
    channel = _shared_grpc_channel(target)
    method = channel.unary_unary(method_path, request_serializer=lambda x: x, response_deserializer=lambda x: x)
    started = time.monotonic()
    try:
        raw = method(request_body, timeout=timeout, metadata=metadata)
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        try:
            fields = inspect_message(raw)
            wire_error = None
        except WireError as exc:
            fields = []
            wire_error = str(exc)
        base.update({"ok": True, "read_only": bool(read_only_action), "network_action_enabled": True, "elapsed_ms": elapsed_ms, "response_bytes": len(raw), "wire_fields": fields, "wire_error": wire_error})
        if response_enricher is not None:
            try:
                extra = response_enricher(raw) or {}
                if isinstance(extra, dict):
                    base.update(extra)
            except Exception as exc:
                base["response_parse_error"] = f"{type(exc).__name__}: {exc}"
        return base
    except grpc.RpcError as exc:
        elapsed_ms = round((time.monotonic() - started) * 1000, 1)
        code = exc.code()
        code_name = code.name if code is not None else "UNKNOWN"
        base.update({"ok": False, "read_only": bool(read_only_action), "network_action_enabled": True, "elapsed_ms": elapsed_ms, "grpc_code": code_name, "grpc_details": exc.details() or "", "failure_class": classify_failure(code_name)})
        return base


def list_friends(*, cfg, slot: str, auth: AuthRecord, timeout: float = 12.0, live: bool = True, capacity: int = 300, include_player_ids: bool = False) -> dict[str, Any]:
    def enrich(raw: bytes) -> dict[str, Any]:
        parsed = parse_friend_list_response(raw, capacity=capacity)
        public = parsed.public_dict()
        if include_player_ids:
            public["friend_player_ids"] = list(parsed.friend_player_ids)
            public["candidate_groups"] = [
                {"path": list(path), "count": len(ids)}
                for path, ids in parsed.relationship_groups()
            ]
            public["candidate_group_player_ids"] = [
                {"path": list(path), "player_ids": list(ids)}
                for path, ids in parsed.relationship_groups()
            ]
        return public

    return _grpc_call(
        cfg=cfg,
        slot=slot,
        auth=auth,
        action="friend-list",
        method_path=LIST_FRIENDS_METHOD,
        request_body=b"",
        timeout=timeout,
        live=live,
        read_only_action=True,
        schema={"request": "empty-confirmed-game-path"},
        response_enricher=enrich if live else None,
    )


def send_friend_request(*, cfg, slot: str, auth: AuthRecord, target_mid: str, source_type: int = 2, timeout: float = 12.0, live: bool = False) -> dict[str, Any]:
    body = build_send_friend_request(target_mid, source_type)
    return _grpc_call(cfg=cfg, slot=slot, auth=auth, action="friend-add", method_path=SEND_FRIEND_REQUEST_METHOD, request_body=body, timeout=timeout, live=live, schema={"field_2": "player_id:string", "field_3": "source_type:varint", "source_type": source_type})


def handle_friend_request(*, cfg, slot: str, auth: AuthRecord, target_mid: str, accept: bool = True, timeout: float = 12.0, live: bool = False) -> dict[str, Any]:
    body = build_handle_friend_request(target_mid, accept)
    return _grpc_call(cfg=cfg, slot=slot, auth=auth, action="friend-accept" if accept else "friend-reject", method_path=HANDLE_FRIEND_REQUEST_METHOD, request_body=body, timeout=timeout, live=live, schema={"field_2": "player_id:string", "field_3": "accept:bool", "accept": bool(accept)})


def remove_friend(*, cfg, slot: str, auth: AuthRecord, target_mids: list[str] | tuple[str, ...], timeout: float = 12.0, live: bool = False) -> dict[str, Any]:
    body = build_remove_friend_request(target_mids)
    return _grpc_call(cfg=cfg, slot=slot, auth=auth, action="friend-remove", method_path=REMOVE_FRIEND_METHOD, request_body=body, timeout=timeout, live=live, schema={"field_2": "player_ids:repeated string", "count": len(target_mids)})
