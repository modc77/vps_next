from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from mwoif_worker.devplay.login_check import DevPlayLoginChecker
from mwoif_worker.job_control import JobControlRegistry
from mwoif_worker.provider_alert import send_provider_incident_alert
from mwoif_worker.provider_guard import get_provider_guard
from mwoif_worker.receiver_relationships import ReceiverRelationshipError, receiver_relationship_prepare_capacity, receiver_relationship_readiness
from mwoif_worker.sender_session_pool import get_login_circuit, get_sender_session_pool
from mwoif_worker.work_security import signed_headers

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

_ROOT = Path(__file__).resolve().parents[1]
if load_dotenv is not None:
    load_dotenv(_ROOT / ".env", override=False)

Event = Callable[[str], None]


class ControlConfigError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(slots=True)
class ControlProcessResult:
    ok: bool
    committed: bool
    code: str
    result_code: str
    retryable: bool
    elapsed_ms: float


def _api_key() -> str:
    value = str(os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
    if len(value) < 32 or len(value) > 512:
        raise ControlConfigError("MWOIF_WORKER_API_KEY_INVALID")
    return value


def _worker_code() -> str:
    value = str(os.getenv("MWOIF_WORKER_CODE") or "LOCAL-01").strip().upper()
    if not value or len(value) > 64 or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in value):
        raise ControlConfigError("MWOIF_WORKER_CODE_INVALID")
    return value


def _endpoint(env_name: str, suffix: str) -> str:
    value = str(os.getenv(env_name) or "").strip()
    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not host
        or parts.path != suffix
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or (not loopback and parts.scheme.lower() != "https")
    ):
        raise ControlConfigError(f"{env_name}_INVALID")
    return value


def _timeout() -> int:
    try:
        value = int(str(os.getenv("MWOIF_WORKER_CONTROL_TIMEOUT_SECONDS") or "15").strip())
    except ValueError as exc:
        raise ControlConfigError("MWOIF_WORKER_CONTROL_TIMEOUT_SECONDS_INVALID") from exc
    if value < 5 or value > 45:
        raise ControlConfigError("MWOIF_WORKER_CONTROL_TIMEOUT_SECONDS_INVALID")
    return value


def _safe_json(raw: bytes) -> dict[str, Any]:
    if len(raw) > 65536:
        raise RuntimeError("CONTROL_RESPONSE_TOO_LARGE")
    decoded = json.loads(raw.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise RuntimeError("CONTROL_RESPONSE_INVALID")
    return decoded


def _post(url: str, payload: dict[str, Any], api_key: str, claim_token: str, timeout: int) -> tuple[int, dict[str, Any]]:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers=signed_headers(
            url,
            body,
            api_key=api_key,
            extra={
                "X-MWOIF-Claim-Token": claim_token,
                "User-Agent": "MWOIF-Services-Worker/control-r7",
            },
        ),
    )
    try:
        with build_opener(_NoRedirect()).open(request, timeout=timeout) as response:
            return int(getattr(response, "status", 200)), _safe_json(response.read(65537))
    except HTTPError as exc:
        status = int(exc.code or 0)
        try:
            raw = exc.read(65537)
            return status, _safe_json(raw) if raw else {}
        except Exception:
            return status, {}


def _commit_result(
    *,
    version: str,
    request_id: int,
    safe_result: dict[str, Any],
    api_key: str,
    claim_token: str,
    result_url: str,
    timeout: int,
    event_cb: Event | None,
) -> ControlProcessResult:
    started = time.perf_counter()
    worker_code = _worker_code()
    result_code = str(safe_result.get("code") or "")[:80]
    body = {
        "worker_code": worker_code,
        "version": str(version or "")[:64],
        "swcr_id": request_id,
        "result": {
            "ok": bool(safe_result.get("ok")),
            "credential_valid": bool(safe_result.get("credential_valid", False)),
            "code": result_code or "CONTROL_RESULT_INVALID",
            "stage": str(safe_result.get("stage") or "CONTROL")[:40],
            "retryable": bool(safe_result.get("retryable", False)),
            "elapsed_ms": max(0.0, min(120000.0, float(safe_result.get("elapsed_ms") or 0.0))),
            "account_login_ok": bool(safe_result.get("account_login_ok", False)),
            "game_session_ok": bool(safe_result.get("game_session_ok", False)),
            "friend_api_ok": bool(safe_result.get("friend_api_ok", False)),
            "relationship_ready": bool(safe_result.get("relationship_ready", False)),
            "friends_bound": max(0, min(300, int(safe_result.get("friends_bound") or 0))),
            "pending_count": max(0, min(300, int(safe_result.get("pending_count") or 0))),
            "capacity": max(1, min(300, int(safe_result.get("capacity") or 300))),
            "available_at_least": max(0, min(300, int(safe_result.get("available_at_least") or 0))),
            "required_free_slots": max(1, min(300, int(safe_result.get("required_free_slots") or 100))),
            "removed_count": max(0, min(300, int(safe_result.get("removed_count") or 0))),
            "friends_before": max(0, min(300, int(safe_result.get("friends_before") or 0))),
        },
    }
    last_code = "CONTROL_RESULT_NETWORK_ERROR"
    for attempt in range(1, 4):
        try:
            status, payload = _post(result_url, body, api_key, claim_token, timeout)
        except (URLError, TimeoutError, OSError):
            status, payload = 0, {}
        except Exception:
            status, payload = 0, {}
        if status == 200 and bool(payload.get("ok")):
            if event_cb is not None:
                event_cb(f"CONTROL COMMIT wcr_id={request_id} result={result_code} secretOutput=NONE")
            return ControlProcessResult(True, True, "CONTROL_RESULT_COMMITTED", result_code, False, (time.perf_counter() - started) * 1000.0)
        last_code = str(payload.get("code") or "CONTROL_RESULT_NETWORK_ERROR")[:80]
        retryable = bool(payload.get("retryable", status == 0 or status >= 500 or status in {408, 409, 425, 429}))
        if not retryable:
            return ControlProcessResult(False, False, last_code, result_code, False, (time.perf_counter() - started) * 1000.0)
        if attempt < 3:
            time.sleep(0.35 * attempt)
    return ControlProcessResult(False, False, last_code, result_code, True, (time.perf_counter() - started) * 1000.0)


def _credential_check(
    *,
    version: str,
    request_id: int,
    api_key: str,
    claim_token: str,
    credential_url: str,
    timeout: int,
) -> tuple[dict[str, Any] | None, str, bool]:
    try:
        status, payload = _post(
            credential_url,
            {"worker_code": _worker_code(), "version": str(version or "")[:64], "swcr_id": request_id},
            api_key,
            claim_token,
            timeout,
        )
    except (URLError, TimeoutError, OSError):
        return None, "CONTROL_CREDENTIAL_NETWORK_ERROR", True
    except Exception:
        return None, "CONTROL_CREDENTIAL_RESPONSE_INVALID", True
    if status != 200 or not bool(payload.get("ok")):
        return None, str(payload.get("code") or "CONTROL_CREDENTIAL_FAILED")[:80], bool(payload.get("retryable", status >= 500 or status in {408, 409, 425, 429}))
    credential = payload.get("credential")
    if not isinstance(credential, dict):
        return None, "CONTROL_CREDENTIAL_INVALID", True
    return credential, "", False


def _full_receiver_account_check(email: str, password: str) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        from mwoif_worker.heart_one import _login_and_session

        cfg, auth, _session = _login_and_session(
            email=email,
            password=password,
            account_kind="receiver-check",
            account_id=0,
            slot="R",
            event_cb=None,
        )
    except Exception as exc:
        code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        stage = str(getattr(exc, "stage", None) or "LOGIN")[:40].upper()
        retryable = bool(getattr(exc, "retryable", True))
        login_ok = stage.startswith("SESSION") or code == "INITMEMBER3_FAILED"
        return {
            "ok": False,
            "credential_valid": login_ok,
            "code": code or "DEVPLAY_LOGIN_FAILED",
            "stage": "GAME_SESSION" if login_ok else "LOGIN",
            "retryable": retryable,
            "elapsed_ms": (time.perf_counter() - started) * 1000.0,
            "account_login_ok": login_ok,
            "game_session_ok": False,
            "friend_api_ok": False,
            "relationship_ready": False,
            "friends_bound": 0,
            "pending_count": 0,
            "capacity": 300,
            "available_at_least": 0,
            "required_free_slots": 100,
        }

    try:
        readiness = receiver_relationship_readiness(
            cfg,
            auth,
            required_free_slots=100,
            capacity=300,
        )
    except ReceiverRelationshipError as exc:
        return {
            "ok": False,
            "credential_valid": True,
            "code": str(exc.code or "FRIEND_LIST_FAILED")[:80],
            "stage": "FRIEND_API",
            "retryable": bool(exc.retryable),
            "elapsed_ms": (time.perf_counter() - started) * 1000.0,
            "account_login_ok": True,
            "game_session_ok": True,
            "friend_api_ok": False,
            "relationship_ready": False,
            "friends_bound": 0,
            "pending_count": 0,
            "capacity": 300,
            "available_at_least": 0,
            "required_free_slots": 100,
        }
    except Exception:
        return {
            "ok": False,
            "credential_valid": True,
            "code": "FRIEND_LIST_FAILED",
            "stage": "FRIEND_API",
            "retryable": True,
            "elapsed_ms": (time.perf_counter() - started) * 1000.0,
            "account_login_ok": True,
            "game_session_ok": True,
            "friend_api_ok": False,
            "relationship_ready": False,
            "friends_bound": 0,
            "pending_count": 0,
            "capacity": 300,
            "available_at_least": 0,
            "required_free_slots": 100,
        }

    return {
        "ok": True,
        "credential_valid": True,
        "code": "ACCOUNT_CHECK_OK",
        "stage": "READINESS",
        "retryable": False,
        "elapsed_ms": (time.perf_counter() - started) * 1000.0,
        "account_login_ok": True,
        "game_session_ok": True,
        "friend_api_ok": True,
        "relationship_ready": bool(readiness.relationship_ready),
        "friends_bound": int(readiness.friends_bound),
        "pending_count": int(readiness.pending_count),
        "capacity": int(readiness.capacity),
        "available_at_least": int(readiness.available_at_least),
        "required_free_slots": int(readiness.required_free_slots),
    }



def _prepare_receiver_capacity(email: str, password: str, event_cb: Event | None) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        from mwoif_worker.heart_one import _login_and_session

        cfg, auth, _session = _login_and_session(
            email=email,
            password=password,
            account_kind="receiver-capacity",
            account_id=0,
            slot="R",
            event_cb=None,
        )
    except Exception as exc:
        code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        stage = str(getattr(exc, "stage", None) or "LOGIN")[:40].upper()
        login_ok = stage.startswith("SESSION") or code == "INITMEMBER3_FAILED"
        return {
            "ok": False,
            "credential_valid": login_ok,
            "code": code or "DEVPLAY_LOGIN_FAILED",
            "stage": "GAME_SESSION" if login_ok else "LOGIN",
            "retryable": bool(getattr(exc, "retryable", True)),
            "elapsed_ms": (time.perf_counter() - started) * 1000.0,
            "account_login_ok": login_ok,
            "game_session_ok": False,
            "friend_api_ok": False,
            "relationship_ready": False,
        }

    try:
        prepared = receiver_relationship_prepare_capacity(
            cfg,
            auth,
            event_cb=event_cb,
            target_friends=200,
            capacity=300,
        )
    except ReceiverRelationshipError as exc:
        return {
            "ok": False,
            "credential_valid": True,
            "code": str(exc.code or "RECEIVER_CAPACITY_PREP_FAILED")[:80],
            "stage": "CAPACITY",
            "retryable": bool(exc.retryable),
            "elapsed_ms": (time.perf_counter() - started) * 1000.0,
            "account_login_ok": True,
            "game_session_ok": True,
            "friend_api_ok": True,
            "relationship_ready": False,
        }

    return {
        "ok": True,
        "credential_valid": True,
        "code": "RECEIVER_CAPACITY_READY",
        "stage": "CAPACITY",
        "retryable": False,
        "elapsed_ms": (time.perf_counter() - started) * 1000.0,
        "account_login_ok": True,
        "game_session_ok": True,
        "friend_api_ok": True,
        "relationship_ready": prepared.available_slots >= 100,
        "friends_bound": prepared.friends_after,
        "pending_count": prepared.pending_after,
        "capacity": 300,
        "available_at_least": prepared.available_slots,
        "required_free_slots": 100,
        "removed_count": prepared.trimmed_friends,
        "friends_before": prepared.friends_before,
    }

def process_control_request(
    version: str,
    job: dict[str, Any],
    claim_token: str,
    *,
    registry: JobControlRegistry | None = None,
    drain_event=None,
    event_cb: Event | None = None,
    resume_hook: Callable[[int], None] | None = None,
) -> ControlProcessResult:
    started = time.perf_counter()
    work_type = str(job.get("work_type") or "").strip().upper()
    try:
        request_id = int(job.get("wcr_id") or 0)
        target_id = int(job.get("target_id") or 0)
    except Exception:
        request_id, target_id = 0, 0
    supported = {
        "DEVPLAY_CHECK",
        "RECEIVER_CAPACITY_PREP",
        "JOB_PAUSE",
        "JOB_RESUME",
        "JOB_CANCEL",
        "ACCOUNT_SESSION_PURGE",
        "ACCOUNT_LOGIN_CHECK",
        "WORKER_DRAIN",
    }
    if work_type not in supported or request_id < 1 or len(claim_token) < 32:
        return ControlProcessResult(False, False, "CONTROL_JOB_INVALID", "", False, (time.perf_counter() - started) * 1000.0)

    try:
        api_key = _api_key()
        credential_url = _endpoint("MWOIF_WEB_CONTROL_CREDENTIAL_URL", "/work/worker/control-credential.php")
        result_url = _endpoint("MWOIF_WEB_CONTROL_RESULT_URL", "/work/worker/control-result.php")
        timeout = _timeout()
    except ControlConfigError as exc:
        return ControlProcessResult(False, False, str(exc), "", False, (time.perf_counter() - started) * 1000.0)

    safe_result: dict[str, Any]

    if work_type in {"DEVPLAY_CHECK", "RECEIVER_CAPACITY_PREP", "ACCOUNT_LOGIN_CHECK"}:
        provider_guard = get_provider_guard()
        if provider_guard.is_open():
            safe_result = {
                "ok": False, "credential_valid": False, "code": "PROVIDER_IP_CIRCUIT_OPEN",
                "stage": "PROVIDER", "retryable": True, "elapsed_ms": 0.0,
            }
            return _commit_result(
                version=version, request_id=request_id, safe_result=safe_result, api_key=api_key,
                claim_token=claim_token, result_url=result_url, timeout=timeout, event_cb=event_cb,
            )
        credential, code, retryable = _credential_check(
            version=version,
            request_id=request_id,
            api_key=api_key,
            claim_token=claim_token,
            credential_url=credential_url,
            timeout=timeout,
        )
        if credential is None:
            return ControlProcessResult(False, False, code, "", retryable, (time.perf_counter() - started) * 1000.0)
        email = str(credential.get("email") or "").strip()
        password = str(credential.get("password") or "")
        credential.clear()
        if not email or not password:
            password = ""
            return ControlProcessResult(False, False, "CONTROL_CREDENTIAL_INVALID", "", False, (time.perf_counter() - started) * 1000.0)
        try:
            if work_type == "DEVPLAY_CHECK":
                safe_result = _full_receiver_account_check(email, password)
            elif work_type == "RECEIVER_CAPACITY_PREP":
                safe_result = _prepare_receiver_capacity(email, password, event_cb)
            else:
                login_result = DevPlayLoginChecker().check(email, password, event_cb=None)
                safe_result = {
                    "ok": bool(login_result.ok),
                    "credential_valid": bool(login_result.credential_valid),
                    "code": str(login_result.code or "")[:80],
                    "stage": str(login_result.stage or "LOGIN")[:40],
                    "retryable": bool(login_result.retryable),
                    "elapsed_ms": float(login_result.elapsed_ms or 0.0),
                }
        except Exception:
            safe_result = {"ok": False, "credential_valid": False, "code": "P1_INTERNAL_ERROR", "stage": "LOGIN", "retryable": True, "elapsed_ms": 0.0}
        finally:
            email = ""
            password = ""

        account_key = target_id if target_id > 0 else request_id
        if bool(safe_result.get("account_login_ok", safe_result.get("ok"))) and bool(safe_result.get("credential_valid")):
            provider_guard.record_success(account_key)
        else:
            opened, snapshot = provider_guard.record_failure(
                account_key,
                str(safe_result.get("code") or "P1_INTERNAL_ERROR"),
                stage=str(safe_result.get("stage") or "LOGIN"),
                retryable=bool(safe_result.get("retryable", False)),
            )
            if opened:
                if provider_guard.mark_alert_sent():
                    alert_ok = send_provider_incident_alert(version, snapshot)
                    if event_cb is not None:
                        event_cb(f"P6.2 PROVIDER ALERT sent={str(alert_ok).lower()} secretOutput=NONE")
                safe_result.update({"code": "PROVIDER_IP_LIMIT_SUSPECTED", "stage": "PROVIDER", "retryable": True})
            elif provider_guard.is_open():
                safe_result.update({"code": "PROVIDER_IP_CIRCUIT_OPEN", "stage": "PROVIDER", "retryable": True})

    elif work_type == "ACCOUNT_SESSION_PURGE":
        if target_id < 1:
            return ControlProcessResult(False, False, "CONTROL_TARGET_INVALID", "", False, (time.perf_counter() - started) * 1000.0)
        removed = get_sender_session_pool().invalidate(target_id)
        safe_result = {"ok": True, "credential_valid": False, "code": "ACCOUNT_SESSION_PURGED" if removed else "ACCOUNT_SESSION_ALREADY_EMPTY", "stage": "SESSION_PURGE", "retryable": False, "elapsed_ms": (time.perf_counter() - started) * 1000.0}

    elif work_type in {"JOB_PAUSE", "JOB_CANCEL"}:
        if target_id < 1 or registry is None:
            return ControlProcessResult(False, False, "CONTROL_TARGET_INVALID", "", False, (time.perf_counter() - started) * 1000.0)
        mode = "pause" if work_type == "JOB_PAUSE" else "cancel"
        accepted, signal = registry.request(target_id, mode)
        if not accepted:
            return ControlProcessResult(False, False, "JOB_CONTROL_CONFLICT", "", True, (time.perf_counter() - started) * 1000.0)
        if signal is not None and not signal.wait_safe(float(max(10, timeout * 2))):
            return ControlProcessResult(False, False, "JOB_CONTROL_SAFEPOINT_TIMEOUT", "", True, (time.perf_counter() - started) * 1000.0)
        safe_result = {"ok": True, "credential_valid": False, "code": "JOB_PAUSE_SAFE" if mode == "pause" else "JOB_CANCEL_SAFE", "stage": "SAFEPOINT", "retryable": False, "elapsed_ms": (time.perf_counter() - started) * 1000.0}

    elif work_type == "JOB_RESUME":
        if target_id < 1:
            return ControlProcessResult(False, False, "CONTROL_TARGET_INVALID", "", False, (time.perf_counter() - started) * 1000.0)
        if registry is not None:
            registry.unregister(target_id)
        safe_result = {"ok": True, "credential_valid": False, "code": "JOB_RESUME_READY", "stage": "CONTROL", "retryable": False, "elapsed_ms": (time.perf_counter() - started) * 1000.0}

    elif work_type == "WORKER_DRAIN":
        safe_result = {"ok": True, "credential_valid": False, "code": "WORKER_DRAIN_ACCEPTED", "stage": "CONTROL", "retryable": False, "elapsed_ms": (time.perf_counter() - started) * 1000.0}

    else:
        return ControlProcessResult(False, False, "CONTROL_TYPE_UNSUPPORTED", "", False, (time.perf_counter() - started) * 1000.0)

    committed = _commit_result(
        version=version,
        request_id=request_id,
        safe_result=safe_result,
        api_key=api_key,
        claim_token=claim_token,
        result_url=result_url,
        timeout=timeout,
        event_cb=event_cb,
    )
    if committed.committed:
        if work_type in {"JOB_PAUSE", "JOB_CANCEL"} and registry is not None:
            _, signal = registry.request(target_id, "cancel" if work_type == "JOB_CANCEL" else "pause")
            if signal is not None:
                signal.mark_applied()
        if work_type == "JOB_RESUME":
            provider_was_open = get_provider_guard().is_open()
            login_state = str(get_login_circuit().snapshot().get("state") or "closed")
            get_provider_guard().reset()
            get_login_circuit().reset()
            if resume_hook is not None:
                try:
                    resume_hook(target_id)
                except Exception:
                    pass
            if event_cb is not None:
                event_cb(
                    f"P6.2 PROVIDER RESET source=admin-resume sj_id={target_id} "
                    f"providerWasOpen={str(provider_was_open).lower()} loginCircuitWas={login_state} secretOutput=NONE"
                )
        if work_type == "WORKER_DRAIN" and drain_event is not None:
            drain_event.set()
    return committed
