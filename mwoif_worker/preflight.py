from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

_ROOT = Path(__file__).resolve().parents[1]

_REQUIRED_URLS = [
    "MWOIF_WEB_HEARTBEAT_URL",
    "MWOIF_WEB_JOB_CLAIM_URL",
    "MWOIF_WEB_JOB_CLAIM_RELEASE_URL",
    "MWOIF_WEB_WORKER_RECOVERY_URL",
    "MWOIF_WEB_RECEIVER_CREDENTIAL_URL",
    "MWOIF_WEB_RECEIVER_RESULT_URL",
    "MWOIF_WEB_SENDER_BATCH_LEASE_URL",
    "MWOIF_WEB_SENDER_BATCH_CREDENTIALS_URL",
    "MWOIF_WEB_HEART_BATCH_RESULT_URL",
    "MWOIF_WEB_SENDER_RECOVERY_CREDENTIALS_URL",
    "MWOIF_WEB_HEART_RECOVERY_RESULT_URL",
    "MWOIF_WEB_CONTROL_CREDENTIAL_URL",
    "MWOIF_WEB_CONTROL_RESULT_URL",
    "MWOIF_WEB_PROVIDER_ALERT_URL",
]


def run_preflight() -> dict:
    if load_dotenv is not None:
        load_dotenv(_ROOT / ".env", override=False)
    errors: list[str] = []
    worker_code = str(os.getenv("MWOIF_WORKER_CODE") or "").strip().upper()
    api_key = str(os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
    if len(api_key) < 32 or len(api_key) > 512:
        errors.append("MWOIF_WORKER_API_KEY_INVALID")
    if not worker_code or len(worker_code) > 64 or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in worker_code):
        errors.append("MWOIF_WORKER_CODE_INVALID")
    for name in _REQUIRED_URLS:
        raw = str(os.getenv(name) or "").strip()
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
        loopback = host in {"127.0.0.1", "localhost", "::1"}
        if not host or parts.scheme.lower() not in {"http", "https"} or (not loopback and parts.scheme.lower() != "https") or "/work/" not in (parts.path or ""):
            errors.append(f"{name}_INVALID")
    for name in ["MWOIF_DEVPLAY_WEB_CONTEXT_FILE", "MWOIF_DEVPLAY_HTTP_EXACT_TEMPLATE_FILE"]:
        raw = str(os.getenv(name) or "").strip()
        path = Path(raw)
        if not path.is_absolute():
            path = _ROOT / path
        if not path.is_file():
            errors.append(f"{name}_MISSING")

    persist_enabled = str(os.getenv("MWOIF_SENDER_SESSION_PERSIST_ENABLED") or "1").strip().lower() not in {"0", "false", "no", "off"}
    if persist_enabled:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
        except Exception:
            errors.append("SENDER_SESSION_CRYPTO_MISSING")
        raw_store = str(os.getenv("MWOIF_SENDER_SESSION_STORE_DIR") or "state/sender-session-cache").strip()
        store = Path(raw_store)
        if not store.is_absolute():
            store = _ROOT / store
        try:
            store.mkdir(parents=True, exist_ok=True)
            probe = store / ".write-test"
            probe.write_bytes(b"ok")
            probe.unlink(missing_ok=True)
        except Exception:
            errors.append("SENDER_SESSION_STORE_NOT_WRITABLE")
    return {
        "ok": not errors,
        "code": "PREFLIGHT_OK" if not errors else "PREFLIGHT_FAILED",
        "errors": errors,
        "protocol": "signed-v3",
        "secretOutput": "NONE",
    }
