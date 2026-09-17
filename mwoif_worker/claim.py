from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from mwoif.net.http_pool import pooled_post_bytes
from mwoif_worker.runtime_context import current_runtime_id
from mwoif_worker.work_security import signed_headers

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if load_dotenv is not None:
    load_dotenv(os.path.join(_ROOT, ".env"), override=False)


class ClaimConfigError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass(slots=True)
class ClaimResult:
    ok: bool
    claimed: bool
    code: str
    message: str
    retryable: bool
    http_status: int
    elapsed_ms: float
    job: dict[str, Any] | None = None
    claim_token_present: bool = False
    next_poll_ms: int | None = None
    claim_token: str | None = field(default=None, repr=False)

    def safe_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "claimed": self.claimed,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "http_status": self.http_status,
            "elapsed_ms": self.elapsed_ms,
            "claim_token_present": self.claim_token_present,
            "secretOutput": "NONE",
        }
        if self.job is not None:
            payload["job"] = self.job
        if self.next_poll_ms is not None:
            payload["next_poll_ms"] = self.next_poll_ms
        return payload


_STATE_LOCK = threading.RLock()
_STATE_BY_RUNTIME: dict[str, dict[str, Any]] = {}


def _api_key() -> str:
    value = str(os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
    if len(value) < 32:
        raise ClaimConfigError("MWOIF_WORKER_API_KEY_NOT_CONFIGURED")
    if len(value) > 512:
        raise ClaimConfigError("MWOIF_WORKER_API_KEY_INVALID")
    return value


def _worker_code() -> str:
    value = str(os.getenv("MWOIF_WORKER_CODE") or "LOCAL-01").strip().upper()
    if not value or len(value) > 64:
        raise ClaimConfigError("MWOIF_WORKER_CODE_INVALID")
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
    if any(ch not in allowed for ch in value):
        raise ClaimConfigError("MWOIF_WORKER_CODE_INVALID")
    return value


def _claim_url() -> str:
    url = str(
        os.getenv("MWOIF_WEB_JOB_CLAIM_URL")
        or "http://127.0.0.1/M_woif/work/jobs/claim.php"
    ).strip()
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    if scheme not in {"http", "https"} or not host:
        raise ClaimConfigError("MWOIF_WEB_JOB_CLAIM_URL_INVALID")
    if not path.endswith("/work/jobs/claim.php"):
        raise ClaimConfigError("MWOIF_WEB_JOB_CLAIM_URL_INVALID")
    if parts.username is not None or parts.password is not None:
        raise ClaimConfigError("MWOIF_WEB_JOB_CLAIM_URL_INVALID")
    if parts.query or parts.fragment:
        raise ClaimConfigError("MWOIF_WEB_JOB_CLAIM_URL_INVALID")
    if not loopback and scheme != "https":
        raise ClaimConfigError("MWOIF_WEB_JOB_CLAIM_HTTPS_REQUIRED")
    return url


def _timeout_seconds() -> int:
    raw = str(os.getenv("MWOIF_WORKER_CLAIM_TIMEOUT_SECONDS") or "10").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ClaimConfigError("MWOIF_WORKER_CLAIM_TIMEOUT_SECONDS_INVALID") from exc
    if value < 3 or value > 30:
        raise ClaimConfigError("MWOIF_WORKER_CLAIM_TIMEOUT_SECONDS_INVALID")
    return value


def _runtime_key() -> str:
    value = str(current_runtime_id() or "manual").strip()
    return value or "manual"


def _state_path() -> Path:
    """Compatibility shim for pre-P10.3 callers.

    Claim state is memory-backed in P10.3. The returned path is an opaque
    runtime-scoped identifier only; no claim state is read from or written to it.
    """
    runtime_key = _runtime_key().replace("/", "_").replace("\\", "_")
    return Path(_ROOT) / "state" / "runtimes" / runtime_key / "claim.memory"


def _read_state(path: Path | None = None, worker_code: str | None = None) -> dict[str, Any] | None:
    """Read the active claim from the in-memory runtime store.

    `path` is accepted for backwards compatibility with receiver_login,
    sender_login and claim_release.
    """
    del path
    runtime_key = _runtime_key()
    with _STATE_LOCK:
        state = _STATE_BY_RUNTIME.get(runtime_key)
        if not isinstance(state, dict):
            return None
        if worker_code is not None and str(state.get("worker_code") or "") != str(worker_code):
            return None
        return dict(state)


def _get_or_create_state(worker_code: str) -> dict[str, Any]:
    runtime_key = _runtime_key()
    with _STATE_LOCK:
        state = _STATE_BY_RUNTIME.get(runtime_key)
        if isinstance(state, dict):
            token = state.get("claim_token")
            token_hash = state.get("claim_token_hash")
            if (
                state.get("worker_code") == worker_code
                and isinstance(token, str)
                and len(token) >= 32
                and isinstance(token_hash, str)
                and len(token_hash) == 64
                and hashlib.sha256(token.encode("utf-8")).hexdigest() == token_hash
            ):
                return state
        token = secrets.token_urlsafe(32)
        state = {
            "schema": "mwoif-p10.3-claim-memory-v1",
            "worker_code": worker_code,
            "phase": "pending",
            "claim_token": token,
            "claim_token_hash": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _STATE_BY_RUNTIME[runtime_key] = state
        return state


def _update_state(data: dict[str, Any]) -> None:
    with _STATE_LOCK:
        _STATE_BY_RUNTIME[_runtime_key()] = data


def _clear_state(path: Path | None = None) -> None:
    del path
    with _STATE_LOCK:
        _STATE_BY_RUNTIME.pop(_runtime_key(), None)


def _safe_json_object(raw: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("CLAIM_RESPONSE_INVALID") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError("CLAIM_RESPONSE_INVALID")
    return decoded


def _safe_job(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    allowed = {
        "work_type",
        "wcr_id",
        "request_ref",
        "sj_id",
        "job_no",
        "order_no",
        "service_code",
        "target_value",
        "completed_value",
        "priority",
        "slot_no",
        "claim_expires_at",
        "claim_lease_seconds",
        "claim_token_fp",
        "receiver_payload_included",
        "target_type",
        "target_id",
        "control_payload",
    }
    return {str(k): v for k, v in value.items() if k in allowed}


def _payload_poll_ms(payload: dict[str, Any], default: int) -> int:
    raw = payload.get("next_poll_ms")
    try:
        value = int(raw)
    except Exception:
        value = default
    return max(500, min(30000, value))


def claim_once(version: str, claim_lane: str = "auto") -> ClaimResult:
    started = time.perf_counter()
    try:
        api_key = _api_key()
        worker_code = _worker_code()
        url = _claim_url()
        timeout = _timeout_seconds()
    except ClaimConfigError as exc:
        return ClaimResult(
            False,
            False,
            str(exc),
            "Worker claim configuration is incomplete",
            False,
            0,
            (time.perf_counter() - started) * 1000.0,
            next_poll_ms=30000,
        )

    lane = str(claim_lane or "auto").strip().lower()
    if lane not in {"auto", "control", "heart"}:
        return ClaimResult(
            False,
            False,
            "CLAIM_LANE_INVALID",
            "Worker claim lane is invalid",
            False,
            0,
            (time.perf_counter() - started) * 1000.0,
            next_poll_ms=30000,
        )

    state = _get_or_create_state(worker_code)
    token = str(state["claim_token"])
    token_hash = str(state["claim_token_hash"])

    body = json.dumps(
        {
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "claim_token_hash": token_hash,
            "claim_lane": lane,
            "control_types": [
                "DEVPLAY_CHECK",
                "JOB_PAUSE",
                "JOB_RESUME",
                "JOB_CANCEL",
                "ACCOUNT_SESSION_PURGE",
                "ACCOUNT_LOGIN_CHECK",
                "WORKER_DRAIN",
            ] if lane != "heart" else [],
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    headers = signed_headers(
        url,
        body,
        api_key=api_key,
        extra={"User-Agent": "MWOIF-Services-Worker/claim-r7"},
    )

    try:
        status, raw, response_headers = pooled_post_bytes(
            url=url,
            body=body,
            headers=headers,
            timeout=float(timeout),
            verify=True,
        )
    except Exception:
        return ClaimResult(
            False,
            False,
            "CLAIM_NETWORK_ERROR",
            "Worker link is temporarily unavailable",
            True,
            0,
            (time.perf_counter() - started) * 1000.0,
            next_poll_ms=5000,
        )

    payload: dict[str, Any]
    try:
        if len(raw) > 65536:
            raise RuntimeError("CLAIM_RESPONSE_TOO_LARGE")
        payload = _safe_json_object(raw)
    except Exception:
        retry_ms = 30000 if status in {401, 403, 429} else 5000
        return ClaimResult(
            False,
            False,
            "CLAIM_ACCESS_DENIED" if status == 403 else "CLAIM_RESPONSE_INVALID",
            "Worker endpoint returned an unexpected response",
            status >= 500 or status in {403, 408, 425, 429},
            status,
            (time.perf_counter() - started) * 1000.0,
            next_poll_ms=retry_ms,
        )

    next_poll_ms = _payload_poll_ms(payload, 3000 if lane == "heart" else 1000)

    if status >= 400:
        code = str(payload.get("code") or ("CLAIM_ACCESS_DENIED" if status == 403 else "CLAIM_HTTP_ERROR"))
        retryable = bool(payload.get("retryable", status >= 500 or status in {408, 409, 425, 429}))
        if status in {400, 401, 403, 415, 422} or code in {"WORKER_CAPACITY_FULL", "WORKER_NOT_READY"}:
            _clear_state()
        return ClaimResult(
            False,
            False,
            code,
            str(payload.get("message") or "Worker claim request was not accepted"),
            retryable,
            status,
            (time.perf_counter() - started) * 1000.0,
            next_poll_ms=next_poll_ms,
        )

    ok = bool(payload.get("ok"))
    claimed = bool(payload.get("claimed"))
    code = str(payload.get("code") or "CLAIM_REJECTED")
    job = _safe_job(payload.get("job"))

    if ok and claimed and job is not None:
        state.update({"phase": "claimed", "job": job, "claimed_at": datetime.now(timezone.utc).isoformat()})
        _update_state(state)
        return ClaimResult(
            True,
            True,
            code,
            str(payload.get("message") or "Job claimed"),
            False,
            status,
            (time.perf_counter() - started) * 1000.0,
            job=job,
            claim_token_present=True,
            next_poll_ms=0,
            claim_token=token,
        )

    normal_wait_codes = {
        "NO_JOB_AVAILABLE",
        "WORKER_CAPACITY_FULL",
        "WORKER_NOT_READY",
        "JOB_CLAIM_BUSY",
    }
    if ok and not claimed and code in normal_wait_codes:
        _clear_state()
        return ClaimResult(
            True,
            False,
            code,
            str(payload.get("message") or "Worker is waiting for work"),
            True,
            status,
            (time.perf_counter() - started) * 1000.0,
            next_poll_ms=next_poll_ms,
        )

    _clear_state()
    return ClaimResult(
        False,
        False,
        code,
        str(payload.get("message") or "Job claim rejected"),
        bool(payload.get("retryable", True)),
        status,
        (time.perf_counter() - started) * 1000.0,
        next_poll_ms=next_poll_ms,
    )


def clear_claim_state() -> None:
    _clear_state()
