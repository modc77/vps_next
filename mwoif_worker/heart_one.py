from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from mwoif_worker.work_security import signed_headers

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None

from mwoif.auth.config_adapter import build_devplay_runtime_config
from mwoif.core.config import load_config
from mwoif.friend.service import handle_friend_request, remove_friend, send_friend_request
from mwoif.heart.mailbox import mailbox_read
from mwoif.heart.receive import heart_receive
from mwoif.heart.send import heart_send
from mwoif.session.game_session import SessionBootstrapError, bootstrap_session
from mwoif.session.models import AuthRecord, SessionRecord
from mwoif.net.http_pool import thread_http_session

from mwoif_worker.config import WorkerConfig
from mwoif_worker.devplay.context import LoginWebContext, load_login_web_context
from mwoif_worker.devplay.exact_template import ExactTemplateReplayer
from mwoif_worker.devplay.models import LoginBundle as WorkerLoginBundle
from mwoif_worker.sender_lease import _clear as _clear_sender_state
from mwoif_worker.sender_lease import _read_json as _read_json_file
from mwoif_worker.sender_lease import _sender_state_path
from mwoif_worker.sender_login import (
    SenderLoginConfigError,
    _active_claim_and_sender,
    _api_key,
    _credential_url as _sender_credential_url,
    _request_json as _sender_request_json,
    _timeout_seconds as _sender_timeout_seconds,
)
from mwoif_worker.receiver_login import (
    ReceiverLoginConfigError,
    _credential_url as _receiver_credential_url,
    _request_json as _receiver_request_json,
    _timeout_seconds as _receiver_timeout_seconds,
)

_ROOT = Path(__file__).resolve().parents[1]
if load_dotenv is not None:
    load_dotenv(_ROOT / ".env", override=False)

Event = Callable[[str], None]


class HeartOneConfigError(RuntimeError):
    pass


class HeartOneRuntimeError(RuntimeError):
    def __init__(self, code: str, stage: str, message: str, *, retryable: bool = True, send_committed: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.stage = stage
        self.retryable = retryable
        self.send_committed = send_committed


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass(slots=True)
class HeartOneResult:
    ok: bool
    code: str
    message: str
    retryable: bool
    http_status: int
    elapsed_ms: float
    sj_id: int | None = None
    sga_id: int | None = None
    outcome: str = ""
    progress_value: int | None = None
    target_value: int | None = None
    pair_cooldown_set: bool = False
    cooldown_until: str | None = None
    sender_released: bool = False
    cleanup_ok: bool | None = None
    resumed_phase: str = ""

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
            "outcome": self.outcome,
            "progress_value": self.progress_value,
            "target_value": self.target_value,
            "pair_cooldown_set": self.pair_cooldown_set,
            "cooldown_until": self.cooldown_until,
            "sender_released": self.sender_released,
            "cleanup_ok": self.cleanup_ok,
            "resumed_phase": self.resumed_phase,
            "credential_persisted": False,
            "session_persisted": False,
            "secretOutput": "NONE",
        }


def _event(cb: Event | None, text: str) -> None:
    if cb:
        cb(text)


def _runtime_state_path() -> Path:
    raw = str(os.getenv("MWOIF_P7_HEART_ONE_STATE_FILE") or "state/p7_heart_one.private.json").strip()
    if not raw:
        raise HeartOneConfigError("MWOIF_P7_HEART_ONE_STATE_FILE_INVALID")
    path = Path(raw)
    if not path.is_absolute():
        path = _ROOT / path
    return path.resolve()


def _write_state(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _clear_state(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _result_url() -> str:
    url = str(
        os.getenv("MWOIF_WEB_HEART_DELIVERY_RESULT_URL")
        or "http://127.0.0.1/M_woif/work/jobs/heart-delivery-result.php"
    ).strip()
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    if scheme not in {"http", "https"} or not host:
        raise HeartOneConfigError("MWOIF_WEB_HEART_DELIVERY_RESULT_URL_INVALID")
    if not path.endswith("/work/jobs/heart-delivery-result.php"):
        raise HeartOneConfigError("MWOIF_WEB_HEART_DELIVERY_RESULT_URL_INVALID")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise HeartOneConfigError("MWOIF_WEB_HEART_DELIVERY_RESULT_URL_INVALID")
    if not loopback and scheme != "https":
        raise HeartOneConfigError("MWOIF_WEB_HEART_DELIVERY_RESULT_HTTPS_REQUIRED")
    return url


def _result_timeout_seconds() -> int:
    raw = str(os.getenv("MWOIF_WORKER_HEART_RESULT_TIMEOUT_SECONDS") or "15").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise HeartOneConfigError("MWOIF_WORKER_HEART_RESULT_TIMEOUT_SECONDS_INVALID") from exc
    if value < 3 or value > 60:
        raise HeartOneConfigError("MWOIF_WORKER_HEART_RESULT_TIMEOUT_SECONDS_INVALID")
    return value


def _float_env(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = str(os.getenv(name) or str(default)).strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise HeartOneConfigError(f"{name}_INVALID") from exc
    if value < minimum or value > maximum:
        raise HeartOneConfigError(f"{name}_INVALID")
    return value


def _int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = str(os.getenv(name) or str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise HeartOneConfigError(f"{name}_INVALID") from exc
    if value < minimum or value > maximum:
        raise HeartOneConfigError(f"{name}_INVALID")
    return value


def _request_result(
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
        headers=signed_headers(url, body, api_key=api_key, extra={"X-MWOIF-Claim-Token": claim_token, "X-MWOIF-Sender-Lease-Token": sender_lease_token, "User-Agent": "MWOIF-Services-Worker/heart-one-r7"}),
    )
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            raw = response.read(65537)
            if len(raw) > 65536:
                raise RuntimeError("HEART_RESULT_RESPONSE_TOO_LARGE")
            decoded = json.loads(raw.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise RuntimeError("HEART_RESULT_RESPONSE_INVALID")
            return status, decoded
    except HTTPError as exc:
        status = int(exc.code or 0)
        try:
            raw = exc.read(65537)
            decoded = json.loads(raw.decode("utf-8")) if raw and len(raw) <= 65536 else {}
            if not isinstance(decoded, dict):
                decoded = {}
        except Exception:
            decoded = {}
        return status, {
            "ok": bool(decoded.get("ok", False)),
            "code": str(decoded.get("code") or "HEART_RESULT_HTTP_ERROR"),
            "message": str(decoded.get("message") or "Heart result endpoint request failed"),
            "retryable": bool(decoded.get("retryable", status >= 500 or status in {408, 409, 425, 429})),
        }


def _fetch_credentials(
    *,
    version: str,
    api_key: str,
    worker_code: str,
    sj_id: int,
    claim_token: str,
    sga_id: int,
    sender_lease_token: str,
) -> tuple[dict[str, str], dict[str, str]]:
    receiver_status, receiver_payload = _receiver_request_json(
        url=_receiver_credential_url(),
        api_key=api_key,
        claim_token=claim_token,
        payload={"worker_code": worker_code, "version": str(version or "")[:64], "sj_id": sj_id},
        timeout=_receiver_timeout_seconds(),
    )
    if not bool(receiver_payload.get("ok")) or not (200 <= receiver_status < 300):
        raise HeartOneRuntimeError(
            str(receiver_payload.get("code") or "RECEIVER_CREDENTIAL_REJECTED"),
            "RECEIVER_CREDENTIAL",
            str(receiver_payload.get("message") or "Receiver credential request failed"),
            retryable=bool(receiver_payload.get("retryable", True)),
        )
    receiver_credential = receiver_payload.get("credential")
    receiver_job = receiver_payload.get("job")
    if not isinstance(receiver_credential, dict) or not isinstance(receiver_job, dict):
        raise HeartOneRuntimeError("RECEIVER_CREDENTIAL_RESPONSE_INVALID", "RECEIVER_CREDENTIAL", "Receiver credential response is incomplete")
    if int(receiver_job.get("sj_id") or 0) != sj_id:
        raise HeartOneRuntimeError("RECEIVER_CREDENTIAL_RESPONSE_INVALID", "RECEIVER_CREDENTIAL", "Receiver credential response job mismatch")

    sender_status, sender_payload = _sender_request_json(
        url=_sender_credential_url(),
        api_key=api_key,
        claim_token=claim_token,
        sender_lease_token=sender_lease_token,
        payload={"worker_code": worker_code, "version": str(version or "")[:64], "sj_id": sj_id, "sga_id": sga_id},
        timeout=_sender_timeout_seconds(),
    )
    if not bool(sender_payload.get("ok")) or not (200 <= sender_status < 300):
        raise HeartOneRuntimeError(
            str(sender_payload.get("code") or "SENDER_CREDENTIAL_REJECTED"),
            "SENDER_CREDENTIAL",
            str(sender_payload.get("message") or "Sender credential request failed"),
            retryable=bool(sender_payload.get("retryable", True)),
        )
    sender_credential = sender_payload.get("credential")
    sender_job = sender_payload.get("job")
    sender_remote = sender_payload.get("sender")
    if not isinstance(sender_credential, dict) or not isinstance(sender_job, dict) or not isinstance(sender_remote, dict):
        raise HeartOneRuntimeError("SENDER_CREDENTIAL_RESPONSE_INVALID", "SENDER_CREDENTIAL", "Sender credential response is incomplete")
    if int(sender_job.get("sj_id") or 0) != sj_id or int(sender_remote.get("sga_id") or 0) != sga_id:
        raise HeartOneRuntimeError("SENDER_CREDENTIAL_RESPONSE_INVALID", "SENDER_CREDENTIAL", "Sender credential response lease mismatch")

    receiver = {
        "email": str(receiver_credential.get("email") or "").strip(),
        "password": str(receiver_credential.get("password") or ""),
    }
    sender = {
        "email": str(sender_credential.get("email") or "").strip(),
        "password": str(sender_credential.get("password") or ""),
    }
    if not receiver["email"] or not receiver["password"] or not sender["email"] or not sender["password"]:
        raise HeartOneRuntimeError("HEART_CREDENTIAL_RESPONSE_INVALID", "CREDENTIAL", "Heart runtime credential payload is incomplete")
    return receiver, sender


def _legacy_auth(
    *,
    context: LoginWebContext,
    bundle: WorkerLoginBundle,
    account_kind: str,
    account_id: int,
) -> AuthRecord:
    q = context.query
    imported_at = datetime.now(timezone.utc).isoformat()
    fgs_id = q.get("lc.fgs_id") or q.get("lc.new_fgs_id") or ""
    device_id = q.get("device_id") or ""
    metadata = {
        "login_platform": "email",
        "fgs-id": fgs_id,
        "fgs_id": fgs_id,
        "device-id": device_id,
        "device_id": device_id,
        "timezone": q.get("timezone") or q.get("lc.timezone") or "Asia/Bangkok",
        "country": q.get("country_code") or q.get("lc.location_country") or "US",
        "version": q.get("lc.app_version") or "",
        "version-code": q.get("lc.app_build") or "",
        "os_version": q.get("lc.os_version") or "12",
        "market_type": q.get("lc.store") or "GOOGLE_PLAY",
        "locale": q.get("lc.locale_on_game") or "en-US",
        "device-name": q.get("lc.device.model") or "",
        "device-model": q.get("lc.device.model") or "",
        "semiDeviceId": q.get("lc.semi_device_id") or "",
        "pushToken": q.get("push_token") or "",
        "game-process-elapsed-ms": "0",
        "time-zone-distance": str(os.getenv("MWOIF_DEVPLAY_TIME_ZONE_DISTANCE") or "25200"),
    }
    metadata = {k: str(v) for k, v in metadata.items() if v not in (None, "")}
    return AuthRecord(
        schema="mwoif-heart-v3-auth-runtime",
        account_kind=account_kind,
        account_id=account_id,
        mid=bundle.mid,
        refresh_token=bundle.refresh_token,
        game_access_token=bundle.game_access_token,
        oven_access_token=bundle.oven_access_token,
        device_secret=bundle.device_secret,
        fgs_id=fgs_id,
        device_id=device_id,
        login_type="email",
        metadata=metadata,
        imported_at=imported_at,
    )


def _login_and_session(
    *,
    email: str,
    password: str,
    account_kind: str,
    account_id: int,
    slot: str,
    event_cb: Event | None,
):
    cfg = WorkerConfig.load()
    context = load_login_web_context(cfg.web_context_file, cfg.login_url)
    if not context.complete:
        raise HeartOneRuntimeError("WEB_CONTEXT_INCOMPLETE", "CONFIG", "Private DevPlay web context is incomplete", retryable=False)
    replayer = ExactTemplateReplayer(
        template_file=cfg.exact_template_file,
        timeout_seconds=cfg.timeout_seconds,
        verify_ssl=cfg.verify_ssl,
        warmup_get=cfg.warmup_get,
        # P7.3.1: reuse the TCP/TLS pool per login worker thread. Cookies are
        # cleared between accounts, while the underlying keep-alive sockets stay
        # warm for the next Sender handled by the same worker.
        session_factory=lambda: thread_http_session(clear_cookies=True),
    )
    replay = replayer.replay(context=context, email=email, password=password, event_cb=event_cb)
    if not replay.ok or replay.bundle is None:
        raise HeartOneRuntimeError(replay.code or "DEVPLAY_LOGIN_FAILED", f"LOGIN_{slot}", replay.message or "DevPlay login failed", retryable=replay.retryable)

    legacy_cfg = build_devplay_runtime_config(load_config(_ROOT / ".env"))
    auth = _legacy_auth(context=context, bundle=replay.bundle, account_kind=account_kind, account_id=account_id)
    try:
        session = bootstrap_session(legacy_cfg, slot, auth, event_cb=event_cb)
    except SessionBootstrapError as exc:
        raise HeartOneRuntimeError("INITMEMBER3_FAILED", f"SESSION_{slot}", str(exc), retryable=True) from exc
    return legacy_cfg, auth, session


def _summary(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": bool(result.get("ok")),
        "http_status": result.get("http_status"),
        "response_code": result.get("response_code"),
        "response_message": result.get("response_message"),
        "grpc_code": result.get("grpc_code"),
        "error": result.get("error"),
        "elapsed_ms": result.get("elapsed_ms"),
    }


def _explicit_send_failure(result: dict[str, Any]) -> bool:
    # A decoded server response with an application code other than 200 is an
    # explicit rejection. Transport/no-wrapper failures are treated as unknown.
    return result.get("http_status") is not None and result.get("response_code") not in (None, 200)


def _poll_mailbox(*, cfg, receiver_session: SessionRecord, receiver_auth: AuthRecord, sender_member_seq: int, attempts: int, delay: float, event_cb: Event | None) -> tuple[int | None, list[dict[str, Any]]]:
    steps: list[dict[str, Any]] = []
    for attempt in range(1, max(1, attempts) + 1):
        result = mailbox_read(
            cfg=cfg,
            slot="R",
            session=receiver_session,
            auth=receiver_auth,
            from_member_seq=sender_member_seq,
            live=True,
            timeout=float(cfg.workflow.get("ds_timeout_seconds") or 20),
        )
        steps.append({"stage": "MAILBOX", "attempt": attempt, **_summary(result)})
        seq = result.get("suggested_life_mail_seq") if bool(result.get("ok")) else None
        if seq:
            _event(event_cb, f"P7 STEP MAILBOX OK attempt={attempt} seq=present secretOutput=NONE")
            return int(seq), steps
        if attempt < max(1, attempts):
            _event(event_cb, f"P7 STEP MAILBOX WAIT attempt={attempt}/{attempts} secretOutput=NONE")
            time.sleep(max(0.0, delay))
    return None, steps


def _report_pending(
    *,
    version: str,
    api_key: str,
    worker_code: str,
    sj_id: int,
    claim_token: str,
    sga_id: int,
    sender_lease_token: str,
    state: dict[str, Any],
) -> HeartOneResult:
    started = time.perf_counter()
    outcome = str(state.get("outcome") or "")
    payload = {
        "worker_code": worker_code,
        "version": str(version or "")[:64],
        "sj_id": sj_id,
        "sga_id": sga_id,
        "outcome": outcome,
        "error_code": str(state.get("error_code") or "")[:80],
        "receiver_member_seq": int(state.get("receiver_member_seq") or 0),
        "cleanup_ok": bool(state.get("cleanup_ok", True)),
        "send_committed": bool(state.get("send_committed", outcome in {"delivered", "recovery_required"})),
        "runtime_ms": int(float(state.get("runtime_ms") or 0.0)),
    }
    try:
        status, response = _request_result(
            url=_result_url(),
            api_key=api_key,
            claim_token=claim_token,
            sender_lease_token=sender_lease_token,
            payload=payload,
            timeout=_result_timeout_seconds(),
        )
    except (URLError, TimeoutError, OSError):
        return HeartOneResult(False, "HEART_RESULT_NETWORK_ERROR", "Heart result could not be reported", True, 0, (time.perf_counter()-started)*1000, sj_id, sga_id, outcome=outcome)
    except Exception:
        return HeartOneResult(False, "HEART_RESULT_RESPONSE_INVALID", "Heart result endpoint returned an invalid response", True, 0, (time.perf_counter()-started)*1000, sj_id, sga_id, outcome=outcome)

    if not bool(response.get("ok")) or not (200 <= status < 300):
        return HeartOneResult(
            False,
            str(response.get("code") or "HEART_RESULT_REJECTED"),
            str(response.get("message") or "Heart result was rejected"),
            bool(response.get("retryable", status >= 500 or status == 409)),
            status,
            (time.perf_counter()-started)*1000,
            sj_id,
            sga_id,
            outcome=outcome,
        )

    job = response.get("job") if isinstance(response.get("job"), dict) else {}
    sender = response.get("sender") if isinstance(response.get("sender"), dict) else {}
    return HeartOneResult(
        ok=outcome == "delivered",
        code=str(response.get("code") or "HEART_RESULT_RECORDED"),
        message=str(response.get("message") or "Heart result recorded"),
        retryable=False,
        http_status=status,
        elapsed_ms=(time.perf_counter()-started)*1000,
        sj_id=sj_id,
        sga_id=sga_id,
        outcome=outcome,
        progress_value=int(job.get("completed_value") or 0) if job else None,
        target_value=int(job.get("target_value") or 0) if job else None,
        pair_cooldown_set=bool(sender.get("pair_cooldown_set")),
        cooldown_until=str(sender.get("cooldown_until") or "") or None,
        sender_released=bool(sender.get("lease_released")),
        cleanup_ok=bool(state.get("cleanup_ok", True)),
        resumed_phase=str(state.get("phase") or ""),
    )


def heart_one_once(version: str, *, live: bool, event_cb: Event | None = None) -> HeartOneResult:
    started = time.perf_counter()
    if not live:
        return HeartOneResult(False, "LIVE_CONFIRMATION_REQUIRED", "P7 performs one real Heart delivery; use the live runner", False, 0, 0.0)

    try:
        api_key = _api_key()
        worker_code, sj_id, claim_token, sga_id, sender_lease_token = _active_claim_and_sender()
        state_path = _runtime_state_path()
        settle_seconds = _float_env("MWOIF_HEART_FRIEND_SETTLE_SECONDS", 1.25, 0.0, 10.0)
        mailbox_attempts = _int_env("MWOIF_HEART_ROUND_MAILBOX_ATTEMPTS", 5, 1, 20)
        mailbox_delay = _float_env("MWOIF_HEART_ROUND_MAILBOX_DELAY_SECONDS", 2.0, 0.05, 10.0)
    except (SenderLoginConfigError, HeartOneConfigError) as exc:
        return HeartOneResult(False, str(exc), "P7 Heart runtime configuration/lease is incomplete", False, 0, (time.perf_counter()-started)*1000)

    state = _read_json_file(state_path)
    if isinstance(state, dict) and (
        int(state.get("sj_id") or 0) != sj_id or int(state.get("sga_id") or 0) != sga_id or state.get("worker_code") != worker_code
    ):
        _clear_state(state_path)
        state = None

    if isinstance(state, dict) and str(state.get("phase") or "").endswith("pending_report"):
        result = _report_pending(
            version=version,
            api_key=api_key,
            worker_code=worker_code,
            sj_id=sj_id,
            claim_token=claim_token,
            sga_id=sga_id,
            sender_lease_token=sender_lease_token,
            state=state,
        )
        if result.http_status and (result.code in {"HEART_DELIVERY_RECORDED", "HEART_DELIVERY_RECOVERED", "HEART_ATTEMPT_RECORDED", "HEART_RECOVERY_RECORDED"}):
            _clear_state(state_path)
            _clear_sender_state(_sender_state_path())
        return result

    phase = str(state.get("phase") or "start") if isinstance(state, dict) else "start"
    resumed_phase = phase if phase != "start" else ""
    steps: list[dict[str, Any]] = list(state.get("steps") or []) if isinstance(state, dict) and isinstance(state.get("steps"), list) else []
    selected_seq = int(state.get("selected_mail_seq") or 0) if isinstance(state, dict) else 0

    try:
        receiver_cred, sender_cred = _fetch_credentials(
            version=version,
            api_key=api_key,
            worker_code=worker_code,
            sj_id=sj_id,
            claim_token=claim_token,
            sga_id=sga_id,
            sender_lease_token=sender_lease_token,
        )
        _event(event_cb, f"P7 credentials ready sj_id={sj_id} sga_id={sga_id} secrets=REDACTED secretOutput=NONE")

        receiver_cfg, receiver_auth, receiver_session = _login_and_session(
            email=receiver_cred["email"],
            password=receiver_cred["password"],
            account_kind="receiver",
            account_id=sj_id,
            slot="R",
            event_cb=event_cb,
        )
        sender_cfg, sender_auth, sender_session = _login_and_session(
            email=sender_cred["email"],
            password=sender_cred["password"],
            account_kind="sender",
            account_id=sga_id,
            slot="S",
            event_cb=event_cb,
        )
        # Credentials are no longer needed after login/session bootstrap.
        receiver_cred = {"email": "", "password": ""}
        sender_cred = {"email": "", "password": ""}

        cfg = sender_cfg
        if str(receiver_cfg.server.get("game_base_url")) != str(sender_cfg.server.get("game_base_url")):
            raise HeartOneRuntimeError("RUNTIME_CONFIG_MISMATCH", "CONFIG", "Receiver/Sender runtime game endpoints differ", retryable=False)

        source_type = int(cfg.workflow.get("friend_source_type") or 2)
        grpc_timeout = float(cfg.workflow.get("grpc_timeout_seconds") or 12)
        ds_timeout = float(cfg.workflow.get("ds_timeout_seconds") or 20)

        if phase == "start":
            add = send_friend_request(
                cfg=cfg,
                slot="S",
                auth=sender_auth,
                target_mid=receiver_auth.mid,
                source_type=source_type,
                timeout=grpc_timeout,
                live=True,
            )
            steps.append({"stage": "ADD", **_summary(add)})
            if not bool(add.get("ok")):
                raise HeartOneRuntimeError(str(add.get("grpc_code") or add.get("error") or "FRIEND_ADD_FAILED"), "ADD", "Friend add failed before Heart send", retryable=True)
            phase = "friend_added"
            _write_state(state_path, {"schema":"mwoif-p7-heart-one-v1","worker_code":worker_code,"sj_id":sj_id,"sga_id":sga_id,"phase":phase,"steps":steps,"created_at":datetime.now(timezone.utc).isoformat()})
            _event(event_cb, "P7 STEP ADD OK secretOutput=NONE")

        if phase == "friend_added":
            accept = handle_friend_request(
                cfg=cfg,
                slot="R",
                auth=receiver_auth,
                target_mid=sender_auth.mid,
                accept=True,
                timeout=grpc_timeout,
                live=True,
            )
            steps.append({"stage": "ACCEPT", **_summary(accept)})
            if not bool(accept.get("ok")):
                raise HeartOneRuntimeError(str(accept.get("grpc_code") or accept.get("error") or "FRIEND_ACCEPT_FAILED"), "ACCEPT", "Friend accept failed before Heart send", retryable=True)
            phase = "friend_accepted"
            _write_state(state_path, {"schema":"mwoif-p7-heart-one-v1","worker_code":worker_code,"sj_id":sj_id,"sga_id":sga_id,"phase":phase,"steps":steps,"created_at":datetime.now(timezone.utc).isoformat()})
            _event(event_cb, "P7 STEP ACCEPT OK secretOutput=NONE")
            if settle_seconds:
                time.sleep(settle_seconds)

        if phase == "friend_accepted":
            send = heart_send(
                cfg=cfg,
                actor_slot="S",
                target_slot="R",
                actor_session=sender_session,
                target_session=receiver_session,
                actor_auth=sender_auth,
                live=True,
                timeout=ds_timeout,
            )
            steps.append({"stage": "SEND", **_summary(send)})
            if bool(send.get("ok")):
                phase = "send_committed"
                _write_state(state_path, {"schema":"mwoif-p7-heart-one-v1","worker_code":worker_code,"sj_id":sj_id,"sga_id":sga_id,"phase":phase,"steps":steps,"sender_member_seq":int(sender_session.member_seq),"created_at":datetime.now(timezone.utc).isoformat()})
                _event(event_cb, "P7 STEP SEND OK committed=true secretOutput=NONE")
            else:
                seq, mailbox_steps = _poll_mailbox(
                    cfg=cfg,
                    receiver_session=receiver_session,
                    receiver_auth=receiver_auth,
                    sender_member_seq=int(sender_session.member_seq),
                    attempts=min(mailbox_attempts, 3),
                    delay=min(mailbox_delay, 1.0),
                    event_cb=event_cb,
                )
                steps.extend(mailbox_steps)
                if seq:
                    phase = "mail_found"
                    selected_seq = seq
                    _write_state(state_path, {"schema":"mwoif-p7-heart-one-v1","worker_code":worker_code,"sj_id":sj_id,"sga_id":sga_id,"phase":phase,"steps":steps,"sender_member_seq":int(sender_session.member_seq),"selected_mail_seq":selected_seq,"created_at":datetime.now(timezone.utc).isoformat()})
                    _event(event_cb, "P7 SEND response failed but mailbox confirms commit secretOutput=NONE")
                elif _explicit_send_failure(send):
                    raise HeartOneRuntimeError(str(send.get("error") or "SEND_LIFE_MAIL_REJECTED"), "SEND", "Heart send was explicitly rejected", retryable=True, send_committed=False)
                else:
                    raise HeartOneRuntimeError("SEND_OUTCOME_UNKNOWN", "SEND", "Heart send transport outcome is unknown; recovery is required", retryable=True, send_committed=True)

        if phase == "send_committed":
            seq, mailbox_steps = _poll_mailbox(
                cfg=cfg,
                receiver_session=receiver_session,
                receiver_auth=receiver_auth,
                sender_member_seq=int(sender_session.member_seq),
                attempts=mailbox_attempts,
                delay=mailbox_delay,
                event_cb=event_cb,
            )
            steps.extend(mailbox_steps)
            if not seq:
                raise HeartOneRuntimeError("LIFE_MAIL_SEQ_NOT_FOUND", "MAILBOX", "Heart send was committed but Receiver mailbox did not expose the mail item", retryable=True, send_committed=True)
            selected_seq = seq
            phase = "mail_found"
            _write_state(state_path, {"schema":"mwoif-p7-heart-one-v1","worker_code":worker_code,"sj_id":sj_id,"sga_id":sga_id,"phase":phase,"steps":steps,"sender_member_seq":int(sender_session.member_seq),"selected_mail_seq":selected_seq,"created_at":datetime.now(timezone.utc).isoformat()})

        if phase == "mail_found":
            if selected_seq <= 0:
                raise HeartOneRuntimeError("LIFE_MAIL_SEQ_MISSING", "RECEIVE", "Saved Heart mail sequence is invalid", retryable=True, send_committed=True)
            receive = heart_receive(
                cfg=cfg,
                actor_slot="R",
                actor_session=receiver_session,
                actor_auth=receiver_auth,
                life_mail_box_seqs=[selected_seq],
                live=True,
                timeout=ds_timeout,
            )
            steps.append({"stage": "RECEIVE", **_summary(receive)})
            if not bool(receive.get("ok")):
                raise HeartOneRuntimeError(str(receive.get("error") or "HEART_RECEIVE_FAILED"), "RECEIVE", "Heart was sent but Receiver could not confirm receipt", retryable=True, send_committed=True)
            phase = "delivered_pending_report"
            state = {
                "schema":"mwoif-p7-heart-one-v1",
                "worker_code":worker_code,
                "sj_id":sj_id,
                "sga_id":sga_id,
                "phase":phase,
                "outcome":"delivered",
                "send_committed":True,
                "receiver_member_seq":int(receiver_session.member_seq),
                "cleanup_ok":True,
                "steps":steps,
                "created_at":datetime.now(timezone.utc).isoformat(),
            }
            _write_state(state_path, state)
            _event(event_cb, "P7 STEP RECEIVE OK delivered=true progress_pending=true secretOutput=NONE")

            remove = remove_friend(
                cfg=cfg,
                slot="S",
                auth=sender_auth,
                target_mids=[receiver_auth.mid],
                timeout=grpc_timeout,
                live=True,
            )
            steps.append({"stage": "REMOVE", **_summary(remove)})
            state["cleanup_ok"] = bool(remove.get("ok"))
            state["steps"] = steps
            state["runtime_ms"] = round((time.perf_counter()-started)*1000.0, 1)
            _write_state(state_path, state)
            _event(event_cb, f"P7 STEP REMOVE {'OK' if state['cleanup_ok'] else 'FAILED'} delivery_remains_committed=true secretOutput=NONE")

        state = _read_json_file(state_path)
        if not isinstance(state, dict) or str(state.get("phase") or "") != "delivered_pending_report":
            raise HeartOneRuntimeError("P7_STATE_INVALID", "REPORT", "Heart delivery state is unavailable", retryable=True, send_committed=True)

        result = _report_pending(
            version=version,
            api_key=api_key,
            worker_code=worker_code,
            sj_id=sj_id,
            claim_token=claim_token,
            sga_id=sga_id,
            sender_lease_token=sender_lease_token,
            state=state,
        )
        result.resumed_phase = resumed_phase
        if result.http_status and result.code in {"HEART_DELIVERY_RECORDED", "HEART_DELIVERY_RECOVERED"}:
            _clear_state(state_path)
            _clear_sender_state(_sender_state_path())
        return result

    except HeartOneRuntimeError as exc:
        outcome = "recovery_required" if exc.send_committed else "retryable_failure"
        state = {
            "schema":"mwoif-p7-heart-one-v1",
            "worker_code":worker_code,
            "sj_id":sj_id,
            "sga_id":sga_id,
            "phase":f"{outcome}_pending_report",
            "outcome":outcome,
            "send_committed":bool(exc.send_committed),
            "error_code":str(exc.code or "P7_HEART_FAILED")[:80],
            "receiver_member_seq":0,
            "cleanup_ok":False,
            "steps":steps,
            "runtime_ms":round((time.perf_counter()-started)*1000.0,1),
            "created_at":datetime.now(timezone.utc).isoformat(),
        }
        _write_state(state_path, state)
        result = _report_pending(
            version=version,
            api_key=api_key,
            worker_code=worker_code,
            sj_id=sj_id,
            claim_token=claim_token,
            sga_id=sga_id,
            sender_lease_token=sender_lease_token,
            state=state,
        )
        result.resumed_phase = resumed_phase
        if result.http_status and result.code in {"HEART_ATTEMPT_RECORDED", "HEART_RECOVERY_RECORDED", "HEART_RESULT_RECOVERED"}:
            _clear_state(state_path)
            _clear_sender_state(_sender_state_path())
        # Preserve the runtime failure code in stdout when PHP report succeeded.
        if result.http_status and result.http_status < 300 and outcome != "delivered":
            result.ok = False
            result.retryable = exc.retryable
            result.message = str(exc)
        return result
    except (URLError, TimeoutError, OSError):
        return HeartOneResult(False, "P7_NETWORK_ERROR", "P7 Heart runtime network request failed", True, 0, (time.perf_counter()-started)*1000.0, sj_id, sga_id)
    except Exception as exc:
        # Never include raw exception text because third-party libraries can place
        # endpoint/request material in it. Public output stays generic.
        return HeartOneResult(False, "P7_RUNTIME_INTERNAL_ERROR", "P7 Heart runtime could not complete", True, 0, (time.perf_counter()-started)*1000.0, sj_id, sga_id)
