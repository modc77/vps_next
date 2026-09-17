from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from mwoif_worker.work_security import signed_headers

from .sender_lease import (
    SenderLeaseConfigError,
    _active_claim,
    _api_key,
    _clear,
    _read_json,
    _sender_state_path,
    _worker_code,
)

_ROOT = Path(__file__).resolve().parents[1]


class SenderRotationConfigError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass(slots=True)
class SenderRotationResult:
    ok: bool
    released: bool
    code: str
    message: str
    retryable: bool
    http_status: int
    elapsed_ms: float
    sj_id: int | None = None
    sga_id: int | None = None
    outcome: str | None = None
    pair_cooldown_set: bool = False
    cooldown_until: str | None = None

    def safe_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "released": self.released,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "http_status": self.http_status,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "sj_id": self.sj_id,
            "sga_id": self.sga_id,
            "outcome": self.outcome,
            "pair_cooldown_set": self.pair_cooldown_set,
            "cooldown_until": self.cooldown_until,
            "next_sender_required": self.released,
            "secretOutput": "NONE",
        }


def _release_url() -> str:
    url = str(
        os.getenv("MWOIF_WEB_SENDER_RELEASE_URL")
        or "http://127.0.0.1/M_woif/work/jobs/sender-release.php"
    ).strip()
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    loopback = host in {"127.0.0.1", "localhost", "::1"}

    if scheme not in {"http", "https"} or not host:
        raise SenderRotationConfigError("MWOIF_WEB_SENDER_RELEASE_URL_INVALID")
    if not path.endswith("/work/jobs/sender-release.php"):
        raise SenderRotationConfigError("MWOIF_WEB_SENDER_RELEASE_URL_INVALID")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise SenderRotationConfigError("MWOIF_WEB_SENDER_RELEASE_URL_INVALID")
    if not loopback and scheme != "https":
        raise SenderRotationConfigError("MWOIF_WEB_SENDER_RELEASE_HTTPS_REQUIRED")
    return url


def _timeout_seconds() -> int:
    raw = str(os.getenv("MWOIF_WORKER_SENDER_RELEASE_TIMEOUT_SECONDS") or "10").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise SenderRotationConfigError("MWOIF_WORKER_SENDER_RELEASE_TIMEOUT_SECONDS_INVALID") from exc
    if value < 3 or value > 30:
        raise SenderRotationConfigError("MWOIF_WORKER_SENDER_RELEASE_TIMEOUT_SECONDS_INVALID")
    return value


def _active_sender_state(worker_code: str, sj_id: int) -> tuple[Path, dict[str, Any], int, str]:
    path = _sender_state_path()
    state = _read_json(path)
    if not isinstance(state, dict):
        raise SenderRotationConfigError("P5_ACTIVE_SENDER_LEASE_MISSING")
    if state.get("worker_code") != worker_code or int(state.get("sj_id") or 0) != sj_id:
        raise SenderRotationConfigError("P5_ACTIVE_SENDER_LEASE_INVALID")

    token = state.get("sender_lease_token")
    sender = state.get("sender")
    sga_id = state.get("sga_id")
    if not isinstance(token, str) or len(token) < 32:
        raise SenderRotationConfigError("P5_ACTIVE_SENDER_LEASE_INVALID")
    if not isinstance(sender, dict):
        raise SenderRotationConfigError("P5_ACTIVE_SENDER_LEASE_INVALID")
    try:
        sender_id = int(sga_id or sender.get("sga_id") or 0)
    except Exception as exc:
        raise SenderRotationConfigError("P5_ACTIVE_SENDER_LEASE_INVALID") from exc
    if sender_id < 1:
        raise SenderRotationConfigError("P5_ACTIVE_SENDER_LEASE_INVALID")
    return path, state, sender_id, token


def _safe_json(raw: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("SENDER_RELEASE_RESPONSE_INVALID") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError("SENDER_RELEASE_RESPONSE_INVALID")
    return decoded


def sender_release_once(version: str, outcome: str, error_code: str = "") -> SenderRotationResult:
    started = time.perf_counter()
    outcome = str(outcome or "").strip().lower()
    if outcome not in {"delivered", "retryable_failure", "failed"}:
        return SenderRotationResult(
            ok=False,
            released=False,
            code="SENDER_RELEASE_OUTCOME_INVALID",
            message="Sender release outcome is invalid",
            retryable=False,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            outcome=outcome or None,
        )

    error_code = str(error_code or "").strip().upper()[:80]

    try:
        api_key = _api_key()
        worker_code = _worker_code()
        sj_id, claim_token = _active_claim(worker_code)
        state_path, _state, sga_id, sender_lease_token = _active_sender_state(worker_code, sj_id)
        url = _release_url()
        timeout = _timeout_seconds()
    except (SenderLeaseConfigError, SenderRotationConfigError) as exc:
        return SenderRotationResult(
            ok=False,
            released=False,
            code=str(exc),
            message="P5.1 sender rotation configuration/lease is incomplete",
            retryable=False,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            outcome=outcome,
        )

    body = json.dumps(
        {
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "sj_id": sj_id,
            "sga_id": sga_id,
            "outcome": outcome,
            "error_code": error_code,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    request = Request(
        url,
        data=body,
        method="POST",
        headers=signed_headers(url, body, api_key=api_key, extra={"X-MWOIF-Claim-Token": claim_token, "X-MWOIF-Sender-Lease-Token": sender_lease_token, "User-Agent": "MWOIF-Services-Worker/sender-release-r7"}),
    )
    opener = build_opener(_NoRedirect())

    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            raw = response.read(65537)
            if len(raw) > 65536:
                raise RuntimeError("SENDER_RELEASE_RESPONSE_TOO_LARGE")
            payload = _safe_json(raw)
    except HTTPError as exc:
        status = int(exc.code or 0)
        try:
            raw = exc.read(65537)
            payload = _safe_json(raw) if raw and len(raw) <= 65536 else {}
        except Exception:
            payload = {}
        return SenderRotationResult(
            ok=False,
            released=False,
            code=str(payload.get("code") or "SENDER_RELEASE_HTTP_ERROR"),
            message=str(payload.get("message") or "Sender release request failed"),
            retryable=bool(payload.get("retryable", status >= 500 or status in {408, 409, 425, 429})),
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sga_id=sga_id,
            outcome=outcome,
        )
    except (URLError, TimeoutError, OSError):
        # Keep the local sender lease state. Retrying with the same token is idempotent.
        return SenderRotationResult(
            ok=False,
            released=False,
            code="SENDER_RELEASE_NETWORK_ERROR",
            message="Sender release endpoint is unreachable",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sga_id=sga_id,
            outcome=outcome,
        )
    except Exception:
        return SenderRotationResult(
            ok=False,
            released=False,
            code="SENDER_RELEASE_RESPONSE_INVALID",
            message="Sender release response is invalid",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sga_id=sga_id,
            outcome=outcome,
        )

    ok = bool(payload.get("ok"))
    released = bool(payload.get("released"))
    code = str(payload.get("code") or "SENDER_RELEASE_REJECTED")
    sender = payload.get("sender") if isinstance(payload.get("sender"), dict) else {}

    if ok and released:
        remote_sga = int(sender.get("sga_id") or 0)
        if remote_sga != sga_id:
            return SenderRotationResult(
                ok=False,
                released=False,
                code="SENDER_RELEASE_RESPONSE_INVALID",
                message="Sender release response does not match the active sender",
                retryable=True,
                http_status=status,
                elapsed_ms=(time.perf_counter() - started) * 1000.0,
                sj_id=sj_id,
                sga_id=sga_id,
                outcome=outcome,
            )

        pair_set = bool(sender.get("pair_cooldown_set"))
        cooldown_until = sender.get("cooldown_until")
        if cooldown_until is not None and not isinstance(cooldown_until, str):
            cooldown_until = None

        # The lease has been durably released. Clearing local state causes the next
        # p5-sender-lease call to generate a fresh token and select the next eligible pair.
        _clear(state_path)
        return SenderRotationResult(
            ok=True,
            released=True,
            code=code,
            message=str(payload.get("message") or "Sender released"),
            retryable=False,
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sga_id=sga_id,
            outcome=outcome,
            pair_cooldown_set=pair_set,
            cooldown_until=cooldown_until,
        )

    return SenderRotationResult(
        ok=False,
        released=False,
        code=code,
        message=str(payload.get("message") or "Sender release rejected"),
        retryable=bool(payload.get("retryable", True)),
        http_status=status,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
        sj_id=sj_id,
        sga_id=sga_id,
        outcome=outcome,
    )
