from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from typing import Mapping
from urllib.parse import urlsplit

_PROTOCOL = "signed-v3"
_CANONICAL_PREFIX = "MWOIF-WORK-V3"


class WorkSecurityError(RuntimeError):
    pass


def _api_key(value: str | None = None) -> str:
    key = str(value if value is not None else os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
    if len(key) < 32 or len(key) > 512:
        raise WorkSecurityError("MWOIF_WORKER_API_KEY_INVALID")
    return key


def _path(url: str) -> str:
    parts = urlsplit(str(url or "").strip())
    host = (parts.hostname or "").lower()
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    if parts.scheme.lower() not in {"http", "https"} or not host:
        raise WorkSecurityError("WORK_URL_INVALID")
    if not loopback and parts.scheme.lower() != "https":
        raise WorkSecurityError("WORK_HTTPS_REQUIRED")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise WorkSecurityError("WORK_URL_INVALID")
    path = parts.path or "/"
    if "/work/" not in path:
        raise WorkSecurityError("WORK_PATH_INVALID")
    return path


def canonical(timestamp: str, nonce: str, method: str, path: str, body: bytes) -> str:
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{_CANONICAL_PREFIX}\n{timestamp}\n{nonce}\n{method.upper()}\n{path}\n{body_hash}"


def signature(api_key: str, timestamp: str, nonce: str, method: str, path: str, body: bytes) -> str:
    raw = canonical(timestamp, nonce, method, path, body).encode("utf-8")
    return hmac.new(api_key.encode("utf-8"), raw, hashlib.sha256).hexdigest()


def signed_headers(
    url: str,
    body: bytes,
    *,
    api_key: str | None = None,
    extra: Mapping[str, str] | None = None,
    method: str = "POST",
) -> dict[str, str]:
    key = _api_key(api_key)
    path = _path(url)
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-MWOIF-Worker-Key": key,
        "X-MWOIF-Worker-Protocol": _PROTOCOL,
        "X-MWOIF-Worker-Timestamp": timestamp,
        "X-MWOIF-Worker-Nonce": nonce,
        "X-MWOIF-Worker-Signature": signature(key, timestamp, nonce, method, path, body),
    }
    if extra:
        for name, value in extra.items():
            if value is None:
                continue
            headers[str(name)] = str(value)
    return headers


def protocol_name() -> str:
    return _PROTOCOL
