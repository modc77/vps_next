from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from mwoif_worker.work_security import signed_headers


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass(slots=True)
class StartupRecoveryResult:
    ok: bool
    code: str
    retryable: bool
    elapsed_ms: float
    safe_requeued: int = 0
    recovery_requeued: int = 0
    protected_jobs: int = 0
    control_requeued: int = 0
    released_slots: int = 0
    active_jobs: int = 0


def _url() -> str:
    value = str(
        os.getenv("MWOIF_WEB_WORKER_RECOVERY_URL")
        or "https://mwoifmod.xyz/work/jobs/recover-worker.php"
    ).strip()
    parts = urlsplit(value)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise ValueError("WORKER_RECOVERY_URL_INVALID")
    if not (parts.path or "").endswith("/work/jobs/recover-worker.php"):
        raise ValueError("WORKER_RECOVERY_URL_INVALID")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise ValueError("WORKER_RECOVERY_URL_INVALID")
    return value


def _worker_code() -> str:
    value = str(os.getenv("MWOIF_WORKER_CODE") or "LOCAL-01").strip().upper()
    if not value:
        raise ValueError("WORKER_CODE_INVALID")
    return value


def _api_key() -> str:
    value = str(os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
    if len(value) < 32:
        raise ValueError("WORKER_API_KEY_NOT_CONFIGURED")
    return value


def recover_worker_startup(version: str) -> StartupRecoveryResult:
    started = time.perf_counter()
    try:
        url = _url()
        worker_code = _worker_code()
        api_key = _api_key()
    except Exception as exc:
        return StartupRecoveryResult(
            ok=False,
            code=str(exc)[:80] or "WORKER_RECOVERY_CONFIG_ERROR",
            retryable=False,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    boot_id = secrets.token_hex(16)
    body = json.dumps(
        {
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "boot_id": boot_id,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers=signed_headers(url, body, api_key=api_key, extra={"User-Agent": "MWOIF-Services-Worker/recovery-r7"}),
    )

    try:
        with build_opener(_NoRedirect()).open(request, timeout=12) as response:
            status = int(getattr(response, "status", 200))
            raw = response.read(65537)
            if len(raw) > 65536:
                raise RuntimeError("WORKER_RECOVERY_RESPONSE_TOO_LARGE")
            payload = json.loads(raw.decode("utf-8"))
    except HTTPError as exc:
        status = int(exc.code or 0)
        try:
            raw = exc.read(65537)
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except Exception:
            payload = {}
        return StartupRecoveryResult(
            ok=False,
            code=str(payload.get("code") or "WORKER_RECOVERY_HTTP_ERROR"),
            retryable=bool(payload.get("retryable", status >= 500 or status in {408, 409, 425, 429})),
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )
    except (URLError, TimeoutError, OSError):
        return StartupRecoveryResult(
            ok=False,
            code="WORKER_RECOVERY_NETWORK_ERROR",
            retryable=True,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )
    except Exception:
        return StartupRecoveryResult(
            ok=False,
            code="WORKER_RECOVERY_RESPONSE_INVALID",
            retryable=True,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    if not isinstance(payload, dict) or not bool(payload.get("ok")) or not (200 <= status < 300):
        return StartupRecoveryResult(
            ok=False,
            code=str(payload.get("code") or "WORKER_RECOVERY_REJECTED") if isinstance(payload, dict) else "WORKER_RECOVERY_RESPONSE_INVALID",
            retryable=bool(payload.get("retryable", True)) if isinstance(payload, dict) else True,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    def n(name: str) -> int:
        try:
            return max(0, int(payload.get(name) or 0))
        except Exception:
            return 0

    return StartupRecoveryResult(
        ok=True,
        code=str(payload.get("code") or "WORKER_STARTUP_RECOVERY_OK"),
        retryable=False,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
        safe_requeued=n("safe_requeued"),
        recovery_requeued=n("recovery_requeued"),
        protected_jobs=n("protected_jobs"),
        control_requeued=n("control_requeued"),
        released_slots=n("released_slots"),
        active_jobs=n("active_jobs"),
    )
