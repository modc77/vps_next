from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None

from mwoif_worker.claim import _read_state, _state_path, _worker_code
from mwoif_worker.devplay.login_check import DevPlayLoginChecker
from mwoif_worker.work_security import signed_headers

_ROOT = Path(__file__).resolve().parents[1]
if load_dotenv is not None:
    load_dotenv(_ROOT / ".env", override=False)

Event = Callable[[str], None]


class SenderLoginConfigError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass(slots=True)
class SenderLoginResult:
    ok: bool
    code: str
    message: str
    retryable: bool
    http_status: int
    elapsed_ms: float
    sj_id: int | None = None
    sga_id: int | None = None
    login_code: str = ""
    member_present: bool = False
    sender_identity_fp: str = ""
    result_recorded: bool = False

    def safe_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "http_status": self.http_status,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "sj_id": self.sj_id,
            "sga_id": self.sga_id,
            "login_code": self.login_code,
            "member_present": self.member_present,
            "sender_identity_fp": self.sender_identity_fp,
            "result_recorded": self.result_recorded,
            "credential_persisted": False,
            "session_persisted": False,
            "secretOutput": "NONE",
        }


def _api_key() -> str:
    value = str(os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
    if len(value) < 32:
        raise SenderLoginConfigError("MWOIF_WORKER_API_KEY_NOT_CONFIGURED")
    if len(value) > 512:
        raise SenderLoginConfigError("MWOIF_WORKER_API_KEY_INVALID")
    return value


def _endpoint_url(env_name: str, default: str, suffix: str) -> str:
    url = str(os.getenv(env_name) or default).strip()
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    loopback = host in {"127.0.0.1", "localhost", "::1"}

    if scheme not in {"http", "https"} or not host:
        raise SenderLoginConfigError(f"{env_name}_INVALID")
    if not path.endswith(suffix):
        raise SenderLoginConfigError(f"{env_name}_INVALID")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise SenderLoginConfigError(f"{env_name}_INVALID")
    if not loopback and scheme != "https":
        raise SenderLoginConfigError(f"{env_name}_HTTPS_REQUIRED")
    return url


def _credential_url() -> str:
    return _endpoint_url(
        "MWOIF_WEB_SENDER_CREDENTIAL_URL",
        "http://127.0.0.1/M_woif/work/jobs/sender-credential.php",
        "/work/jobs/sender-credential.php",
    )


def _result_url() -> str:
    return _endpoint_url(
        "MWOIF_WEB_SENDER_LOGIN_RESULT_URL",
        "http://127.0.0.1/M_woif/work/jobs/sender-login-result.php",
        "/work/jobs/sender-login-result.php",
    )


def _timeout_seconds() -> int:
    raw = str(os.getenv("MWOIF_WORKER_SENDER_LOGIN_TIMEOUT_SECONDS") or "15").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise SenderLoginConfigError("MWOIF_WORKER_SENDER_LOGIN_TIMEOUT_SECONDS_INVALID") from exc
    if value < 3 or value > 60:
        raise SenderLoginConfigError("MWOIF_WORKER_SENDER_LOGIN_TIMEOUT_SECONDS_INVALID")
    return value


def _sender_state_path() -> Path:
    raw = str(os.getenv("MWOIF_P5_SENDER_LEASE_STATE_FILE") or "state/p5_sender_lease.private.json").strip()
    if not raw:
        raise SenderLoginConfigError("MWOIF_P5_SENDER_LEASE_STATE_FILE_INVALID")
    path = Path(raw)
    if not path.is_absolute():
        path = _ROOT / path
    return path.resolve()


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _active_claim_and_sender() -> tuple[str, int, str, int, str]:
    worker_code = _worker_code()
    claim_state = _read_state(_state_path(), worker_code)
    if not isinstance(claim_state, dict):
        raise SenderLoginConfigError("P3_ACTIVE_CLAIM_MISSING")

    claim_token = claim_state.get("claim_token")
    job = claim_state.get("job")
    if not isinstance(claim_token, str) or len(claim_token) < 32 or not isinstance(job, dict):
        raise SenderLoginConfigError("P3_ACTIVE_CLAIM_INVALID")
    try:
        sj_id = int(job.get("sj_id") or 0)
    except Exception as exc:
        raise SenderLoginConfigError("P3_ACTIVE_CLAIM_INVALID") from exc
    if sj_id < 1 or str(job.get("service_code") or "") != "HEART_PUMP":
        raise SenderLoginConfigError("P3_ACTIVE_CLAIM_INVALID")

    sender_state = _read_json(_sender_state_path())
    if not isinstance(sender_state, dict):
        raise SenderLoginConfigError("P5_ACTIVE_SENDER_LEASE_MISSING")
    if sender_state.get("worker_code") != worker_code or int(sender_state.get("sj_id") or 0) != sj_id:
        raise SenderLoginConfigError("P5_ACTIVE_SENDER_LEASE_INVALID")
    if str(sender_state.get("phase") or "") != "leased":
        raise SenderLoginConfigError("P5_ACTIVE_SENDER_LEASE_INVALID")

    sender_token = sender_state.get("sender_lease_token")
    sender_hash = sender_state.get("sender_lease_token_hash")
    if not isinstance(sender_token, str) or len(sender_token) < 32:
        raise SenderLoginConfigError("P5_ACTIVE_SENDER_LEASE_INVALID")
    if not isinstance(sender_hash, str) or len(sender_hash) != 64:
        raise SenderLoginConfigError("P5_ACTIVE_SENDER_LEASE_INVALID")
    if hashlib.sha256(sender_token.encode("utf-8")).hexdigest() != sender_hash:
        raise SenderLoginConfigError("P5_ACTIVE_SENDER_LEASE_INVALID")

    try:
        sga_id = int(sender_state.get("sga_id") or 0)
    except Exception as exc:
        raise SenderLoginConfigError("P5_ACTIVE_SENDER_LEASE_INVALID") from exc
    if sga_id < 1:
        raise SenderLoginConfigError("P5_ACTIVE_SENDER_LEASE_INVALID")

    return worker_code, sj_id, claim_token, sga_id, sender_token


def _safe_json(raw: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("WORK_RESPONSE_INVALID") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError("WORK_RESPONSE_INVALID")
    return decoded


def _request_json(
    *,
    url: str,
    api_key: str,
    claim_token: str,
    sender_lease_token: str,
    payload: dict[str, Any],
    timeout: int,
) -> tuple[int, dict[str, Any]]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers=signed_headers(url, body, api_key=api_key, extra={"X-MWOIF-Claim-Token": claim_token, "X-MWOIF-Sender-Lease-Token": sender_lease_token, "User-Agent": "MWOIF-Services-Worker/sender-login-r7"}),
    )
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            raw = response.read(65537)
            if len(raw) > 65536:
                raise RuntimeError("WORK_RESPONSE_TOO_LARGE")
            return status, _safe_json(raw)
    except HTTPError as exc:
        status = int(exc.code or 0)
        try:
            raw = exc.read(65537)
            data = _safe_json(raw) if raw and len(raw) <= 65536 else {}
        except Exception:
            data = {}
        return status, {
            "ok": bool(data.get("ok", False)),
            "code": str(data.get("code") or "WORK_HTTP_ERROR"),
            "message": str(data.get("message") or "Worker endpoint request failed"),
            "retryable": bool(data.get("retryable", status >= 500 or status in {408, 409, 425, 429})),
        }


def sender_login_once(version: str, event_cb: Event | None = None) -> SenderLoginResult:
    started = time.perf_counter()
    try:
        api_key = _api_key()
        worker_code, sj_id, claim_token, sga_id, sender_lease_token = _active_claim_and_sender()
        credential_url = _credential_url()
        result_url = _result_url()
        timeout = _timeout_seconds()
    except SenderLoginConfigError as exc:
        return SenderLoginResult(
            ok=False,
            code=str(exc),
            message="P6 Sender Login configuration/lease is incomplete",
            retryable=False,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    request_payload = {
        "worker_code": worker_code,
        "version": str(version or "")[:64],
        "sj_id": sj_id,
        "sga_id": sga_id,
    }

    try:
        status, payload = _request_json(
            url=credential_url,
            api_key=api_key,
            claim_token=claim_token,
            sender_lease_token=sender_lease_token,
            payload=request_payload,
            timeout=timeout,
        )
    except (URLError, TimeoutError, OSError):
        return SenderLoginResult(
            ok=False,
            code="SENDER_CREDENTIAL_NETWORK_ERROR",
            message="Sender credential endpoint is unreachable",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sga_id=sga_id,
        )
    except Exception:
        return SenderLoginResult(
            ok=False,
            code="SENDER_CREDENTIAL_RESPONSE_INVALID",
            message="Sender credential endpoint returned an invalid response",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sga_id=sga_id,
        )

    if not bool(payload.get("ok")) or status < 200 or status >= 300:
        return SenderLoginResult(
            ok=False,
            code=str(payload.get("code") or "SENDER_CREDENTIAL_REJECTED"),
            message=str(payload.get("message") or "Sender credential request was rejected"),
            retryable=bool(payload.get("retryable", status >= 500 or status == 409)),
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sga_id=sga_id,
        )

    credential = payload.get("credential")
    remote_job = payload.get("job")
    remote_sender = payload.get("sender")
    if not isinstance(credential, dict) or not isinstance(remote_job, dict) or not isinstance(remote_sender, dict):
        return SenderLoginResult(
            ok=False,
            code="SENDER_CREDENTIAL_RESPONSE_INVALID",
            message="Sender credential response is incomplete",
            retryable=True,
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sga_id=sga_id,
        )

    try:
        remote_sj_id = int(remote_job.get("sj_id") or 0)
        remote_sga_id = int(remote_sender.get("sga_id") or 0)
    except Exception:
        remote_sj_id = 0
        remote_sga_id = 0

    email = str(credential.get("email") or "").strip()
    password = str(credential.get("password") or "")
    if remote_sj_id != sj_id or remote_sga_id != sga_id or not email or not password:
        password = ""
        credential = {}
        return SenderLoginResult(
            ok=False,
            code="SENDER_CREDENTIAL_RESPONSE_INVALID",
            message="Sender credential response does not match the active lease",
            retryable=True,
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sga_id=sga_id,
        )

    identity_fp = hashlib.sha256(email.lower().encode("utf-8", "ignore")).hexdigest()[:12]
    if event_cb:
        event_cb(f"P6 SENDER credential fetched sj_id={sj_id} sga_id={sga_id} identity={identity_fp} secretOutput=NONE")

    checker = DevPlayLoginChecker()
    login = checker.check(email, password, event_cb=event_cb)

    # Never persist sender email/password or DevPlay session bundle in P6.
    password = ""
    credential = {}
    email = ""

    report_payload = {
        "worker_code": worker_code,
        "version": str(version or "")[:64],
        "sj_id": sj_id,
        "sga_id": sga_id,
        "login_ok": bool(login.ok and login.credential_valid),
        "login_code": str(login.code or "DEVPLAY_LOGIN_FAILED")[:80],
        "retryable": bool(login.retryable),
        "member_present": bool(login.member_id),
        "elapsed_ms": round(float(login.elapsed_ms), 1),
    }

    try:
        report_status, report = _request_json(
            url=result_url,
            api_key=api_key,
            claim_token=claim_token,
            sender_lease_token=sender_lease_token,
            payload=report_payload,
            timeout=timeout,
        )
    except (URLError, TimeoutError, OSError):
        return SenderLoginResult(
            ok=False,
            code="SENDER_LOGIN_RESULT_NETWORK_ERROR",
            message="Sender login completed but result could not be reported",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sga_id=sga_id,
            login_code=login.code,
            member_present=bool(login.member_id),
            sender_identity_fp=identity_fp,
            result_recorded=False,
        )
    except Exception:
        return SenderLoginResult(
            ok=False,
            code="SENDER_LOGIN_RESULT_INVALID",
            message="Sender login result endpoint returned an invalid response",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sga_id=sga_id,
            login_code=login.code,
            member_present=bool(login.member_id),
            sender_identity_fp=identity_fp,
            result_recorded=False,
        )

    recorded = bool(report.get("ok")) and 200 <= report_status < 300
    if not recorded:
        return SenderLoginResult(
            ok=False,
            code=str(report.get("code") or "SENDER_LOGIN_RESULT_REJECTED"),
            message=str(report.get("message") or "Sender login result was rejected"),
            retryable=bool(report.get("retryable", report_status >= 500 or report_status == 409)),
            http_status=report_status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sga_id=sga_id,
            login_code=login.code,
            member_present=bool(login.member_id),
            sender_identity_fp=identity_fp,
            result_recorded=False,
        )

    login_ok = bool(login.ok and login.credential_valid)
    return SenderLoginResult(
        ok=login_ok,
        code="SENDER_LOGIN_OK" if login_ok else str(login.code or "SENDER_LOGIN_FAILED"),
        message="Sender DevPlay login passed" if login_ok else "Sender DevPlay login failed",
        retryable=False if login_ok else bool(login.retryable),
        http_status=report_status,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
        sj_id=sj_id,
        sga_id=sga_id,
        login_code=login.code,
        member_present=bool(login.member_id),
        sender_identity_fp=identity_fp,
        result_recorded=True,
    )
