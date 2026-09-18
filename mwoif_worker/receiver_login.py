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


class ReceiverLoginConfigError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass(slots=True)
class ReceiverLoginResult:
    ok: bool
    code: str
    message: str
    retryable: bool
    http_status: int
    elapsed_ms: float
    sj_id: int | None = None
    login_code: str = ""
    member_present: bool = False
    receiver_identity_fp: str = ""
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
            "login_code": self.login_code,
            "member_present": self.member_present,
            "receiver_identity_fp": self.receiver_identity_fp,
            "result_recorded": self.result_recorded,
            "credential_persisted": False,
            "session_persisted": False,
            "secretOutput": "NONE",
        }


def _api_key() -> str:
    value = str(os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
    if len(value) < 32:
        raise ReceiverLoginConfigError("MWOIF_WORKER_API_KEY_NOT_CONFIGURED")
    if len(value) > 512:
        raise ReceiverLoginConfigError("MWOIF_WORKER_API_KEY_INVALID")
    return value


def _endpoint_url(env_name: str, default: str, suffix: str) -> str:
    url = str(os.getenv(env_name) or default).strip()
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    loopback = host in {"127.0.0.1", "localhost", "::1"}

    if scheme not in {"http", "https"} or not host:
        raise ReceiverLoginConfigError(f"{env_name}_INVALID")
    if not path.endswith(suffix):
        raise ReceiverLoginConfigError(f"{env_name}_INVALID")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise ReceiverLoginConfigError(f"{env_name}_INVALID")
    if not loopback and scheme != "https":
        raise ReceiverLoginConfigError(f"{env_name}_HTTPS_REQUIRED")
    return url


def _credential_url() -> str:
    return _endpoint_url(
        "MWOIF_WEB_RECEIVER_CREDENTIAL_URL",
        "http://127.0.0.1/M_woif/work/jobs/receiver-credential.php",
        "/work/jobs/receiver-credential.php",
    )


def _result_url() -> str:
    return _endpoint_url(
        "MWOIF_WEB_RECEIVER_RESULT_URL",
        "http://127.0.0.1/M_woif/work/jobs/receiver-login-result.php",
        "/work/jobs/receiver-login-result.php",
    )


def _timeout_seconds() -> int:
    raw = str(os.getenv("MWOIF_WORKER_RECEIVER_TIMEOUT_SECONDS") or "15").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ReceiverLoginConfigError("MWOIF_WORKER_RECEIVER_TIMEOUT_SECONDS_INVALID") from exc
    if value < 3 or value > 60:
        raise ReceiverLoginConfigError("MWOIF_WORKER_RECEIVER_TIMEOUT_SECONDS_INVALID")
    return value


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
    payload: dict[str, Any],
    timeout: int,
) -> tuple[int, dict[str, Any]]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers=signed_headers(url, body, api_key=api_key, extra={"X-MWOIF-Claim-Token": claim_token, "User-Agent": "MWOIF-Services-Worker/receiver-r7"}),
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
        # Only return the safe error envelope. Never propagate credential-shaped fields.
        return status, {
            "ok": bool(data.get("ok", False)),
            "code": str(data.get("code") or "WORK_HTTP_ERROR"),
            "message": str(data.get("message") or "Worker endpoint request failed"),
            "retryable": bool(data.get("retryable", status >= 500 or status in {408, 409, 425, 429})),
        }


def _active_claim() -> tuple[str, int, str]:
    worker_code = _worker_code()
    path = _state_path()
    state = _read_state(path, worker_code)
    if not isinstance(state, dict):
        raise ReceiverLoginConfigError("P3_ACTIVE_CLAIM_MISSING")
    token = state.get("claim_token")
    job = state.get("job")
    if not isinstance(token, str) or len(token) < 32 or not isinstance(job, dict):
        raise ReceiverLoginConfigError("P3_ACTIVE_CLAIM_INVALID")
    try:
        sj_id = int(job.get("sj_id") or 0)
    except Exception as exc:
        raise ReceiverLoginConfigError("P3_ACTIVE_CLAIM_INVALID") from exc
    if sj_id < 1 or str(job.get("service_code") or "") not in {"HEART_PUMP", "FRIEND_FILL_300", "FRIEND_CLEAR"}:
        raise ReceiverLoginConfigError("P3_ACTIVE_CLAIM_INVALID")
    return worker_code, sj_id, token


def receiver_login_once(version: str, event_cb: Event | None = None) -> ReceiverLoginResult:
    started = time.perf_counter()
    try:
        api_key = _api_key()
        worker_code, sj_id, claim_token = _active_claim()
        credential_url = _credential_url()
        result_url = _result_url()
        timeout = _timeout_seconds()
    except ReceiverLoginConfigError as exc:
        return ReceiverLoginResult(
            ok=False,
            code=str(exc),
            message="P4 Receiver Login configuration/claim is incomplete",
            retryable=False,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    request_payload = {
        "worker_code": worker_code,
        "version": str(version or "")[:64],
        "sj_id": sj_id,
    }

    try:
        status, payload = _request_json(
            url=credential_url,
            api_key=api_key,
            claim_token=claim_token,
            payload=request_payload,
            timeout=timeout,
        )
    except (URLError, TimeoutError, OSError):
        return ReceiverLoginResult(
            ok=False,
            code="RECEIVER_CREDENTIAL_NETWORK_ERROR",
            message="Receiver credential endpoint is unreachable",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
        )
    except Exception:
        return ReceiverLoginResult(
            ok=False,
            code="RECEIVER_CREDENTIAL_RESPONSE_INVALID",
            message="Receiver credential endpoint returned an invalid response",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
        )

    if not bool(payload.get("ok")) or status < 200 or status >= 300:
        return ReceiverLoginResult(
            ok=False,
            code=str(payload.get("code") or "RECEIVER_CREDENTIAL_REJECTED"),
            message=str(payload.get("message") or "Receiver credential request was rejected"),
            retryable=bool(payload.get("retryable", status >= 500 or status == 409)),
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
        )

    credential = payload.get("credential")
    remote_job = payload.get("job")
    if not isinstance(credential, dict) or not isinstance(remote_job, dict):
        return ReceiverLoginResult(
            ok=False,
            code="RECEIVER_CREDENTIAL_RESPONSE_INVALID",
            message="Receiver credential response is incomplete",
            retryable=True,
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
        )

    try:
        remote_sj_id = int(remote_job.get("sj_id") or 0)
    except Exception:
        remote_sj_id = 0
    email = str(credential.get("email") or "").strip()
    password = str(credential.get("password") or "")
    if remote_sj_id != sj_id or not email or not password:
        password = ""
        return ReceiverLoginResult(
            ok=False,
            code="RECEIVER_CREDENTIAL_RESPONSE_INVALID",
            message="Receiver credential response does not match the active claim",
            retryable=True,
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
        )

    identity_fp = hashlib.sha256(email.lower().encode("utf-8", "ignore")).hexdigest()[:12]
    if event_cb:
        event_cb(f"P4 RECEIVER credential fetched sj_id={sj_id} identity={identity_fp} secretOutput=NONE")

    checker = DevPlayLoginChecker()
    login = checker.check(email, password, event_cb=event_cb)
    # Never persist the credential. Release references immediately after the login call.
    password = ""
    credential = {}

    report_payload = {
        "worker_code": worker_code,
        "version": str(version or "")[:64],
        "sj_id": sj_id,
        "login_ok": bool(login.ok and login.credential_valid),
        "login_code": str(login.code or "DEVPLAY_LOGIN_FAILED")[:80],
        "retryable": bool(login.retryable),
        "member_id": str(login.member_id or "")[:128],
        "elapsed_ms": round(float(login.elapsed_ms), 1),
    }

    try:
        report_status, report = _request_json(
            url=result_url,
            api_key=api_key,
            claim_token=claim_token,
            payload=report_payload,
            timeout=timeout,
        )
    except (URLError, TimeoutError, OSError):
        return ReceiverLoginResult(
            ok=False,
            code="RECEIVER_LOGIN_RESULT_NETWORK_ERROR",
            message="Receiver login completed but result could not be reported",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            login_code=login.code,
            member_present=bool(login.member_id),
            receiver_identity_fp=identity_fp,
            result_recorded=False,
        )
    except Exception:
        return ReceiverLoginResult(
            ok=False,
            code="RECEIVER_LOGIN_RESULT_INVALID",
            message="Receiver login result endpoint returned an invalid response",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            login_code=login.code,
            member_present=bool(login.member_id),
            receiver_identity_fp=identity_fp,
            result_recorded=False,
        )

    recorded = bool(report.get("ok")) and 200 <= report_status < 300
    if not recorded:
        return ReceiverLoginResult(
            ok=False,
            code=str(report.get("code") or "RECEIVER_LOGIN_RESULT_REJECTED"),
            message=str(report.get("message") or "Receiver login result was rejected"),
            retryable=bool(report.get("retryable", report_status >= 500 or report_status == 409)),
            http_status=report_status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            login_code=login.code,
            member_present=bool(login.member_id),
            receiver_identity_fp=identity_fp,
            result_recorded=False,
        )

    login_ok = bool(login.ok and login.credential_valid)
    return ReceiverLoginResult(
        ok=login_ok,
        code="RECEIVER_LOGIN_OK" if login_ok else str(login.code or "RECEIVER_LOGIN_FAILED"),
        message="Receiver DevPlay login passed" if login_ok else "Receiver DevPlay login failed",
        retryable=False if login_ok else bool(login.retryable),
        http_status=report_status,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
        sj_id=sj_id,
        login_code=login.code,
        member_present=bool(login.member_id),
        receiver_identity_fp=identity_fp,
        result_recorded=True,
    )
