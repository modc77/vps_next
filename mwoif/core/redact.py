from __future__ import annotations

import hashlib
import re
from typing import Any

_SECRET_KEYS = (
    "password",
    "passwd",
    "pwd",
    "token",
    "cookie",
    "sessionkey",
    "session_key",
    "refresh",
    "access",
    "secret",
    "authorization",
    "auth",
)

_EMAIL_RE = re.compile(r"(?P<local>[^@\s]{1,64})@(?P<domain>[^@\s]{1,255})")


def normalize_email(email: str) -> str:
    return email.strip().lower()


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def email_hash(email: str) -> str:
    return sha256_hex(normalize_email(email))


def mask_email(email: str | None) -> str | None:
    if not email:
        return None
    email = normalize_email(email)
    m = _EMAIL_RE.fullmatch(email)
    if not m:
        return "<invalid-email>"
    local = m.group("local")
    domain = m.group("domain")
    if len(local) <= 2:
        masked_local = local[0] + "*" if local else "*"
    elif len(local) <= 5:
        masked_local = local[0] + "***" + local[-1]
    else:
        masked_local = local[:2] + "***" + local[-2:]
    return f"{masked_local}@{domain}"


def secret_fingerprint(value: str | bytes | None, length: int = 12) -> str:
    if value is None:
        return "NONE"
    if isinstance(value, bytes):
        data = value
    else:
        data = str(value).encode("utf-8", errors="replace")
    if not data:
        return "NONE"
    return hashlib.sha256(data).hexdigest()[:length]


def looks_like_secret_key(key: str) -> bool:
    k = key.lower().replace("-", "_")
    return any(part in k for part in _SECRET_KEYS)


def redact_value(key: str, value: Any) -> Any:
    if value is None:
        return None
    if looks_like_secret_key(key):
        text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
        return {
            "present": bool(text),
            "len": len(text),
            "fp": secret_fingerprint(text),
            "secret_output": "NONE",
        }
    if "email" in key.lower():
        return mask_email(str(value))
    return value


def redact_mapping(mapping: dict[str, Any]) -> dict[str, Any]:
    return {key: redact_value(key, value) for key, value in mapping.items()}
