from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener

from mwoif_worker.claim import (
    _NoRedirect,
    _api_key,
    _clear_state,
    _read_state,
    _safe_json_object,
    _state_path,
    _worker_code,
)
from mwoif_worker.work_security import signed_headers


@dataclass(slots=True)
class ClaimReleaseResult:
    ok: bool
    released: bool
    code: str
    message: str
    retryable: bool
    http_status: int
    elapsed_ms: float
    sj_id: int | None = None


def _release_url() -> str:
    url = str(
        os.getenv("MWOIF_WEB_JOB_CLAIM_RELEASE_URL")
        or "http://127.0.0.1/M_woif/work/jobs/claim-release.php"
    ).strip()
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    if scheme not in {"http", "https"} or not host:
        raise RuntimeError("MWOIF_WEB_JOB_CLAIM_RELEASE_URL_INVALID")
    if not (parts.path or "").endswith("/work/jobs/claim-release.php"):
        raise RuntimeError("MWOIF_WEB_JOB_CLAIM_RELEASE_URL_INVALID")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise RuntimeError("MWOIF_WEB_JOB_CLAIM_RELEASE_URL_INVALID")
    if not loopback and scheme != "https":
        raise RuntimeError("MWOIF_WEB_JOB_CLAIM_RELEASE_HTTPS_REQUIRED")
    return url


def release_active_claim(version: str, *, expected_sj_id: int | None = None) -> ClaimReleaseResult:
    started = time.perf_counter()
    try:
        worker_code = _worker_code()
        api_key = _api_key()
        path = _state_path()
        state = _read_state(path, worker_code)
        url = _release_url()
    except Exception as exc:
        return ClaimReleaseResult(
            False,
            False,
            str(exc)[:80] or "CLAIM_RELEASE_CONFIG_ERROR",
            "Worker claim release configuration is incomplete",
            False,
            0,
            (time.perf_counter() - started) * 1000.0,
        )

    if not isinstance(state, dict) or state.get("phase") != "claimed":
        return ClaimReleaseResult(
            True,
            False,
            "NO_ACTIVE_LOCAL_CLAIM",
            "No active local claim exists",
            False,
            200,
            (time.perf_counter() - started) * 1000.0,
        )

    job = state.get("job") if isinstance(state.get("job"), dict) else {}
    sj_id = int(job.get("sj_id") or 0)
    token = str(state.get("claim_token") or "")
    if sj_id < 1 or len(token) < 32:
        return ClaimReleaseResult(
            False,
            False,
            "LOCAL_CLAIM_STATE_INVALID",
            "Local claim state is invalid",
            False,
            0,
            (time.perf_counter() - started) * 1000.0,
            sj_id or None,
        )
    if expected_sj_id is not None and int(expected_sj_id) != sj_id:
        return ClaimReleaseResult(
            False,
            False,
            "LOCAL_CLAIM_JOB_MISMATCH",
            "Local claim does not match the active job",
            False,
            0,
            (time.perf_counter() - started) * 1000.0,
            sj_id,
        )

    body = json.dumps(
        {
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "sj_id": sj_id,
            "reason": "graceful_shutdown",
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers=signed_headers(url, body, api_key=api_key, extra={"X-MWOIF-Claim-Token": token, "User-Agent": "MWOIF-Services-Worker/claim-release-r7"}),
    )

    try:
        with build_opener(_NoRedirect()).open(request, timeout=15) as response:
            status = int(getattr(response, "status", 200))
            raw = response.read(65537)
            if len(raw) > 65536:
                raise RuntimeError("CLAIM_RELEASE_RESPONSE_TOO_LARGE")
            payload = _safe_json_object(raw)
    except HTTPError as exc:
        status = int(exc.code or 0)
        try:
            raw = exc.read(65537)
            payload = _safe_json_object(raw) if raw else {}
        except Exception:
            payload = {}
        return ClaimReleaseResult(
            False,
            False,
            str(payload.get("code") or "CLAIM_RELEASE_HTTP_ERROR"),
            str(payload.get("message") or "Claim release request failed"),
            bool(payload.get("retryable", status >= 500 or status in {408, 409, 425, 429})),
            status,
            (time.perf_counter() - started) * 1000.0,
            sj_id,
        )
    except (URLError, TimeoutError, OSError):
        return ClaimReleaseResult(
            False,
            False,
            "CLAIM_RELEASE_NETWORK_ERROR",
            "Claim release endpoint is unreachable",
            True,
            0,
            (time.perf_counter() - started) * 1000.0,
            sj_id,
        )
    except Exception:
        return ClaimReleaseResult(
            False,
            False,
            "CLAIM_RELEASE_RESPONSE_INVALID",
            "Claim release response is invalid",
            True,
            0,
            (time.perf_counter() - started) * 1000.0,
            sj_id,
        )

    ok = bool(payload.get("ok"))
    released = bool(payload.get("released"))
    code = str(payload.get("code") or "CLAIM_RELEASE_REJECTED")
    if ok and released:
        _clear_state(path)
    return ClaimReleaseResult(
        ok,
        released,
        code,
        str(payload.get("message") or ("Claim released" if released else "Claim release completed")),
        bool(payload.get("retryable", not ok)),
        status,
        (time.perf_counter() - started) * 1000.0,
        sj_id,
    )
