from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.error import URLError
from urllib.parse import urlsplit

from mwoif.friend.service import handle_friend_request, remove_friend, send_friend_request
from mwoif.heart.mailbox import mailbox_read
from mwoif.heart.receive import heart_receive
from mwoif.heart.send import heart_send
from mwoif.session.models import AuthRecord, SessionRecord

from mwoif_worker.claim import claim_once, _clear_state as _clear_claim_state, _state_path as _claim_state_path
from mwoif_worker.claim_release import release_active_claim
from mwoif_worker.heartbeat import _api_key as _worker_api_key
from mwoif_worker.receiver_login import (
    _active_claim,
    _credential_url as _receiver_credential_url,
    _request_json,
    _result_url as _receiver_result_url,
    _timeout_seconds as _receiver_timeout_seconds,
)
from mwoif_worker.heart_one import _login_and_session, _summary, _explicit_send_failure
from mwoif_worker.shard_scheduler import ElasticShardPool
from mwoif_worker.sender_session_pool import get_login_circuit, get_sender_session_pool, is_ip_suspect_code
from mwoif_worker.provider_alert import send_provider_incident_alert
from mwoif_worker.provider_guard import get_provider_guard
from mwoif_worker.receiver_relationships import ReceiverRelationshipError, receiver_relationship_preflight

Event = Callable[[str], None]
_ROOT = Path(__file__).resolve().parents[1]


class HeartWaveError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


@dataclass(slots=True)
class WaveSender:
    sga_id: int
    lease_token: str
    email: str = ""
    password: str = ""
    auth: AuthRecord | None = None
    session: SessionRecord | None = None
    outcome: str = "retryable_failure"
    error_code: str = ""
    failure_stage: str = ""
    cleanup_ok: bool = False
    send_class: str = ""
    mail_seq: int | None = None
    steps: dict[str, Any] = field(default_factory=dict)

    @property
    def member_seq(self) -> int | None:
        if self.session is None or not self.session.established:
            return None
        return int(self.session.member_seq)

    @property
    def mid(self) -> str:
        return str(self.auth.mid) if self.auth is not None else ""


@dataclass(slots=True)
class HeartWaveResult:
    ok: bool
    code: str
    message: str
    retryable: bool
    elapsed_ms: float
    sj_id: int | None = None
    start_progress: int = 0
    progress_value: int = 0
    target_value: int = 0
    delivered_this_run: int = 0
    batches: int = 0
    failed_attempts: int = 0
    recovery_required: bool = False

    def safe_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "sj_id": self.sj_id,
            "start_progress": self.start_progress,
            "progress_value": self.progress_value,
            "target_value": self.target_value,
            "delivered_this_run": self.delivered_this_run,
            "batches": self.batches,
            "failed_attempts": self.failed_attempts,
            "recovery_required": self.recovery_required,
            "mode": "performance-wave-catchup-v1",
            "secretOutput": "NONE",
        }


def _event(cb: Event | None, text: str) -> None:
    if cb:
        cb(text)


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(str(os.getenv(name) or default).strip())
    except Exception:
        value = default
    return max(lo, min(hi, value))


def _env_float(name: str, default: float, lo: float, hi: float) -> float:
    try:
        value = float(str(os.getenv(name) or default).strip())
    except Exception:
        value = default
    return max(lo, min(hi, value))


def _endpoint(env_name: str, default: str, suffix: str) -> str:
    url = str(os.getenv(env_name) or default).strip()
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    scheme = parts.scheme.lower()
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    if scheme not in {"http", "https"} or not host or not (parts.path or "").endswith(suffix):
        raise HeartWaveError(f"{env_name}_INVALID", f"{env_name} is invalid", retryable=False)
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise HeartWaveError(f"{env_name}_INVALID", f"{env_name} is invalid", retryable=False)
    if not loopback and scheme != "https":
        raise HeartWaveError(f"{env_name}_HTTPS_REQUIRED", f"{env_name} must use HTTPS outside loopback", retryable=False)
    return url


def _batch_lease_url() -> str:
    return _endpoint(
        "MWOIF_WEB_SENDER_BATCH_LEASE_URL",
        "http://127.0.0.1/M_woif/work/jobs/sender-batch-lease.php",
        "/work/jobs/sender-batch-lease.php",
    )


def _batch_credentials_url() -> str:
    return _endpoint(
        "MWOIF_WEB_SENDER_BATCH_CREDENTIALS_URL",
        "http://127.0.0.1/M_woif/work/jobs/sender-batch-credentials.php",
        "/work/jobs/sender-batch-credentials.php",
    )


def _batch_result_url() -> str:
    return _endpoint(
        "MWOIF_WEB_HEART_BATCH_RESULT_URL",
        "http://127.0.0.1/M_woif/work/jobs/heart-batch-result.php",
        "/work/jobs/heart-batch-result.php",
    )


def _login_replace_url() -> str:
    batch_url = _batch_lease_url()
    old_suffix = "/work/jobs/sender-batch-lease.php"
    if not batch_url.endswith(old_suffix):
        raise HeartWaveError("MWOIF_WEB_SENDER_BATCH_LEASE_URL_INVALID", "Sender batch lease URL is invalid", retryable=False)
    return batch_url[:-len(old_suffix)] + "/work/jobs/sender-login-replace.php"


def _recovery_credentials_url() -> str:
    return _endpoint(
        "MWOIF_WEB_SENDER_RECOVERY_CREDENTIALS_URL",
        "http://127.0.0.1/M_woif/work/jobs/sender-recovery-credentials.php",
        "/work/jobs/sender-recovery-credentials.php",
    )


def _recovery_result_url() -> str:
    return _endpoint(
        "MWOIF_WEB_HEART_RECOVERY_RESULT_URL",
        "http://127.0.0.1/M_woif/work/jobs/heart-recovery-result.php",
        "/work/jobs/heart-recovery-result.php",
    )


def _request_json_retry(*, url: str, api_key: str, claim_token: str, payload: dict[str, Any], timeout: int, attempts: int = 3) -> tuple[int, dict[str, Any]]:
    last_exc: BaseException | None = None
    attempts = max(1, min(5, int(attempts)))
    for attempt in range(1, attempts + 1):
        try:
            status, data = _request_json(
                url=url, api_key=api_key, claim_token=claim_token,
                payload=payload, timeout=timeout,
            )
            retryable_http = status in {408, 425, 429} or status >= 500
            if retryable_http and attempt < attempts and bool(data.get("retryable", True)):
                time.sleep(0.15 * attempt)
                continue
            return status, data
        except (URLError, TimeoutError, OSError) as exc:
            last_exc = exc
            if attempt >= attempts:
                break
            time.sleep(0.15 * attempt)
    raise HeartWaveError("WORK_API_NETWORK_ERROR", "Worker PHP API is unreachable", retryable=True) from last_exc


def _fetch_receiver_session(version: str, event_cb: Event | None):
    api_key = _worker_api_key()
    worker_code, sj_id, claim_token = _active_claim()
    timeout = _receiver_timeout_seconds()
    status, payload = _request_json_retry(
        url=_receiver_credential_url(),
        api_key=api_key,
        claim_token=claim_token,
        payload={"worker_code": worker_code, "version": str(version or "")[:64], "sj_id": sj_id},
        timeout=timeout,
    )
    if not bool(payload.get("ok")) or not (200 <= status < 300):
        raise HeartWaveError(str(payload.get("code") or "RECEIVER_CREDENTIAL_REJECTED"), str(payload.get("message") or "Receiver credential request failed"), retryable=bool(payload.get("retryable", True)))
    cred = payload.get("credential")
    if not isinstance(cred, dict):
        raise HeartWaveError("RECEIVER_CREDENTIAL_RESPONSE_INVALID", "Receiver credential response is incomplete")
    email = str(cred.get("email") or "").strip()
    password = str(cred.get("password") or "")
    if not email or not password:
        raise HeartWaveError("RECEIVER_CREDENTIAL_RESPONSE_INVALID", "Receiver credential response is incomplete")

    login_started = time.perf_counter()
    try:
        cfg, auth, session = _login_and_session(
            email=email,
            password=password,
            account_kind="receiver",
            account_id=sj_id,
            slot="R",
            event_cb=event_cb,
        )
        login_ok = True
        login_code = "DEVPLAY_LOGIN_OK"
        retryable = False
    except Exception as exc:
        login_ok = False
        login_code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        retryable = bool(getattr(exc, "retryable", True))
        cfg = auth = session = None
    finally:
        password = ""
        cred = {}

    report_status, report = _request_json_retry(
        url=_receiver_result_url(),
        api_key=api_key,
        claim_token=claim_token,
        payload={
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "sj_id": sj_id,
            "login_ok": login_ok,
            "login_code": login_code,
            "retryable": retryable,
            "member_id": str(getattr(auth, "mid", "") or "")[:128],
            "elapsed_ms": round((time.perf_counter() - login_started) * 1000.0, 1),
        },
        timeout=timeout,
    )
    if not bool(report.get("ok")) or not (200 <= report_status < 300):
        raise HeartWaveError(str(report.get("code") or "RECEIVER_LOGIN_RESULT_REJECTED"), str(report.get("message") or "Receiver login result was rejected"), retryable=bool(report.get("retryable", True)))
    if not login_ok or cfg is None or auth is None or session is None:
        raise HeartWaveError(login_code, "Receiver DevPlay/session login failed", retryable=retryable)
    return worker_code, sj_id, claim_token, api_key, cfg, auth, session


def _lease_batch(version: str, *, worker_code: str, sj_id: int, claim_token: str, api_key: str, count: int) -> tuple[list[WaveSender], int]:
    raw_tokens = [secrets.token_urlsafe(32) for _ in range(count)]
    hashes = [hashlib.sha256(t.encode("utf-8")).hexdigest() for t in raw_tokens]
    preferred = get_sender_session_pool().preferred_ids()
    payload = {
        "worker_code": worker_code,
        "version": str(version or "")[:64],
        "sj_id": sj_id,
        "requested_count": count,
        "lease_token_hashes": hashes,
    }
    if preferred:
        payload["preferred_sga_ids"] = preferred
    status, data = _request_json_retry(url=_batch_lease_url(), api_key=api_key, claim_token=claim_token, payload=payload, timeout=20, attempts=3)
    if not bool(data.get("ok")) or not (200 <= status < 300):
        raise HeartWaveError(str(data.get("code") or "SENDER_BATCH_LEASE_REJECTED"), str(data.get("message") or "Sender batch lease failed"), retryable=bool(data.get("retryable", True)))
    if not bool(data.get("leased")):
        raise HeartWaveError(str(data.get("code") or "NO_READY_HEART_SENDER"), str(data.get("message") or "No Sender batch available"), retryable=bool(data.get("retryable", True)))
    batch_no = int(data.get("batch_no") or 0)
    rows = data.get("senders")
    if batch_no < 1 or batch_no > 1_000_000 or not isinstance(rows, list) or not rows:
        raise HeartWaveError("SENDER_BATCH_LEASE_RESPONSE_INVALID", "Sender batch lease response is invalid")
    works: list[WaveSender] = []
    seen: set[int] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        sga_id = int(row.get("sga_id") or 0)
        idx = int(row.get("lease_token_index") if row.get("lease_token_index") is not None else -1)
        if sga_id < 1 or idx < 0 or idx >= len(raw_tokens) or sga_id in seen:
            raise HeartWaveError("SENDER_BATCH_LEASE_RESPONSE_INVALID", "Sender batch lease response is invalid")
        seen.add(sga_id)
        works.append(WaveSender(sga_id=sga_id, lease_token=raw_tokens[idx]))
    return works, batch_no


def _fetch_batch_credentials(version: str, *, worker_code: str, sj_id: int, claim_token: str, api_key: str, works: list[WaveSender]) -> None:
    status, data = _request_json_retry(
        url=_batch_credentials_url(),
        api_key=api_key,
        claim_token=claim_token,
        payload={
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "sj_id": sj_id,
            "senders": [{"sga_id": w.sga_id, "lease_token": w.lease_token} for w in works],
        },
        timeout=30,
    )
    if not bool(data.get("ok")) or not (200 <= status < 300):
        raise HeartWaveError(str(data.get("code") or "SENDER_BATCH_CREDENTIAL_REJECTED"), str(data.get("message") or "Sender batch credential request failed"), retryable=bool(data.get("retryable", True)))
    rows = data.get("credentials")
    if not isinstance(rows, list):
        raise HeartWaveError("SENDER_BATCH_CREDENTIAL_RESPONSE_INVALID", "Sender batch credential response is invalid")
    by_id = {w.sga_id: w for w in works}
    for row in rows:
        if not isinstance(row, dict):
            continue
        sga_id = int(row.get("sga_id") or 0)
        work = by_id.get(sga_id)
        if work is None:
            continue
        work.email = str(row.get("email") or "").strip()
        work.password = str(row.get("password") or "")
    if any(not w.email or not w.password for w in works):
        for w in works:
            w.password = ""
        raise HeartWaveError("SENDER_BATCH_CREDENTIAL_RESPONSE_INVALID", "One or more Sender credentials are missing")


def _hydrate_cached_sender_sessions(works: list[WaveSender], event_cb: Event | None = None) -> int:
    pool = get_sender_session_pool()
    hits = 0
    for work in works:
        cached = pool.get(work.sga_id)
        if cached is None:
            continue
        work.auth, work.session = cached
        work.steps["LOGIN_SOURCE"] = "cache"
        work.error_code = ""
        hits += 1
    if hits:
        stats = pool.stats()
        _event(
            event_cb,
            f"P10.1 SESSION CACHE HYDRATE hits={hits}/{len(works)} pool={stats['size']} "
            f"persistentHits={stats['persistent_hits']} ttl={stats['ttl_seconds']}s secretOutput=NONE",
        )
    return hits


def _session_cache_error(code: str) -> bool:
    value = str(code or "").strip().upper()
    if not value:
        return False
    if "UNAUTH" in value:
        return True
    if "SESSION" in value and ("INVALID" in value or "EXPIRED" in value):
        return True
    if "TOKEN" in value and ("INVALID" in value or "EXPIRED" in value):
        return True
    return value in {"HTTP_401", "401", "GRPC_UNAUTHENTICATED"}

def _invalidate_stale_cached_sender_sessions(works: list[WaveSender], event_cb: Event | None = None) -> int:
    pool = get_sender_session_pool()
    removed = 0
    for work in works:
        if work.steps.get("LOGIN_SOURCE") != "cache":
            continue
        if _session_cache_error(work.error_code) and pool.invalidate(work.sga_id):
            removed += 1
    if removed:
        _event(event_cb, f"P10.1 SESSION CACHE INVALIDATE count={removed} secretOutput=NONE")
    return removed

_REPLACEABLE_LOGIN_CODES = {
    "DEVPLAY_LOGIN_RESPONSE_INVALID",
    "DEVPLAY_LOGIN_FAILED",
    "SENDER_LOGIN_FAILED",
    "DEVPLAY_TIMEOUT",
    "DEVPLAY_NETWORK_ERROR",
    "DEVPLAY_LOGIN_HTTP_RETRYABLE",
    "DEVPLAY_LOGIN_REDIRECT_BLOCKED",
}


def _replaceable_login_failures(works: list[WaveSender]) -> list[WaveSender]:
    return [w for w in works if str(w.error_code or "").upper() in _REPLACEABLE_LOGIN_CODES]


def _replace_failed_login_senders(
    version: str, *, worker_code: str, sj_id: int, claim_token: str, api_key: str,
    failed: list[WaveSender], event_cb: Event | None,
) -> tuple[list[WaveSender], set[int]]:
    if not failed:
        return [], set()
    raw_tokens = [secrets.token_urlsafe(32) for _ in failed]
    hashes = [hashlib.sha256(token.encode("utf-8")).hexdigest() for token in raw_tokens]
    status, data = _request_json_retry(
        url=_login_replace_url(),
        api_key=api_key,
        claim_token=claim_token,
        payload={
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "sj_id": sj_id,
            "failed_senders": [
                {
                    "sga_id": w.sga_id,
                    "lease_token": w.lease_token,
                    "error_code": str(w.error_code or "SENDER_LOGIN_FAILED")[:80],
                }
                for w in failed
            ],
            "replacement_token_hashes": hashes,
        },
        timeout=20,
        attempts=3,
    )
    if not bool(data.get("ok")) or not (200 <= status < 300):
        raise HeartWaveError(
            str(data.get("code") or "SENDER_LOGIN_REPLACE_REJECTED"),
            str(data.get("message") or "Sender login replacement failed"),
            retryable=bool(data.get("retryable", True)),
        )
    replaced_ids_raw = data.get("replaced_failed_sga_ids")
    replaced_ids = {int(v) for v in replaced_ids_raw if isinstance(v, int) or str(v).isdigit()} if isinstance(replaced_ids_raw, list) else set()
    rows = data.get("senders")
    if not isinstance(rows, list):
        rows = []
    replacements: list[WaveSender] = []
    seen: set[int] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            sga_id = int(row.get("sga_id") or 0)
            idx = int(row.get("lease_token_index") if row.get("lease_token_index") is not None else -1)
        except Exception:
            continue
        if sga_id < 1 or idx < 0 or idx >= len(raw_tokens) or sga_id in seen:
            raise HeartWaveError("SENDER_LOGIN_REPLACE_RESPONSE_INVALID", "Sender login replacement response is invalid")
        seen.add(sga_id)
        replacements.append(WaveSender(sga_id=sga_id, lease_token=raw_tokens[idx]))
    _event(
        event_cb,
        f"P10 LOGIN FAILOVER requested={len(failed)} replaced={len(replacements)} "
        f"retired={len(replaced_ids)} code={str(data.get('code') or '')} secretOutput=NONE",
    )
    return replacements, replaced_ids


def _login_senders(works: list[WaveSender], *, workers: int, event_cb: Event | None, log_every: int = 10) -> tuple[list[WaveSender], list[WaveSender]]:
    ok: list[WaveSender] = []
    failed: list[WaveSender] = []
    lock = threading.Lock()
    pool_state = get_sender_session_pool()
    circuit = get_login_circuit()
    provider_guard = get_provider_guard()

    def one(work: WaveSender) -> WaveSender:
        if provider_guard.is_open():
            work.error_code = "PROVIDER_IP_CIRCUIT_OPEN"
            work.failure_stage = "LOGIN"
            work.steps["LOGIN_SOURCE"] = "provider_circuit"
            work.password = ""
            return work
        if work.auth is not None and work.session is not None and work.session.established:
            work.steps["LOGIN_SOURCE"] = "cache"
            work.error_code = ""
            work.failure_stage = ""
            work.password = ""
            return work
        probe = False
        try:
            circuit_mode = circuit.before_login(work.sga_id, event_cb=event_cb)
            if circuit_mode == "blocked":
                work.error_code = "DEVPLAY_IP_THROTTLE_SUSPECTED"
                work.steps["LOGIN_SOURCE"] = "circuit_blocked"
                return work
            probe = circuit_mode == "probe"
            email_for_cache = work.email
            _cfg, auth, session = _login_and_session(
                email=work.email,
                password=work.password,
                account_kind="sender",
                account_id=work.sga_id,
                slot="S",
                event_cb=None,
            )
            work.auth = auth
            work.session = session
            work.outcome = "retryable_failure"
            work.error_code = ""
            work.failure_stage = ""
            work.steps["LOGIN_SOURCE"] = "fresh"
            pool_state.put(work.sga_id, email_for_cache, auth, session)
            provider_guard.record_success(work.sga_id)
            circuit.record_success(work.sga_id, probe, event_cb=event_cb)
        except Exception as exc:
            code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
            work.error_code = code
            work.failure_stage = "LOGIN"
            work.steps["LOGIN_SOURCE"] = "fresh_failed"
            opened, _snapshot = provider_guard.record_failure(work.sga_id, code, stage="LOGIN", retryable=bool(getattr(exc, "retryable", False)))
            if opened or provider_guard.is_open():
                work.error_code = "PROVIDER_IP_LIMIT_SUSPECTED" if opened else "PROVIDER_IP_CIRCUIT_OPEN"
            circuit.record_failure(work.sga_id, code, probe, event_cb=event_cb)
        finally:
            work.password = ""
        return work

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(works))), thread_name_prefix="p72-login") as pool:
        futures = {pool.submit(one, w): w for w in works}
        done = 0
        for future in as_completed(futures):
            work = future.result()
            done += 1
            with lock:
                (ok if work.auth is not None and work.session is not None else failed).append(work)
            if done == 1 or done == len(works) or done % max(1, log_every) == 0:
                cache_hits = sum(1 for w in ok if w.steps.get("LOGIN_SOURCE") == "cache")
                _event(event_cb, f"P7.2 LOGIN {done}/{len(works)} ok={len(ok)} fail={len(failed)} cache={cache_hits} secretOutput=NONE")

    circuit_state = circuit.snapshot()
    if str(circuit_state.get("state")) in {"open", "half_open"}:
        for work in failed:
            if is_ip_suspect_code(work.error_code):
                work.error_code = "DEVPLAY_IP_THROTTLE_SUSPECTED"
    return ok, failed


def _parallel_stage(works: list[WaveSender], *, max_workers: int, fn, stage: str, event_cb: Event | None, log_every: int = 10) -> tuple[list[WaveSender], list[WaveSender]]:
    if not works:
        return [], []
    passed: list[WaveSender] = []
    failed: list[WaveSender] = []
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(works))), thread_name_prefix=f"p72-{stage.lower()}") as pool:
        fmap = {pool.submit(fn, w): w for w in works}
        done = 0
        for future in as_completed(fmap):
            work = fmap[future]
            done += 1
            try:
                result = future.result()
                work.steps[stage] = _summary(result)
                if bool(result.get("ok")):
                    passed.append(work)
                    work.error_code = ""
                else:
                    work.error_code = str(result.get("grpc_code") or result.get("response_code") or result.get("error") or f"{stage}_FAILED")[:80]
                    failed.append(work)
            except Exception as exc:
                work.error_code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
                failed.append(work)
            if done == 1 or done == len(works) or done % max(1, log_every) == 0:
                _event(event_cb, f"P7.2 {stage} {done}/{len(works)} ok={len(passed)} fail={len(failed)} secretOutput=NONE")
    return passed, failed


def _elastic_prepare_shards(
    works: list[WaveSender], *,
    shard_pool: ElasticShardPool,
    shard_job_key: str,
    chunk_size: int,
    login_workers_per_slot: int,
    add_workers_per_slot: int,
    cfg,
    receiver_auth: AuthRecord,
    source_type: int,
    grpc_timeout: float,
    stop_event: threading.Event | None,
    event_cb: Event | None,
) -> tuple[list[WaveSender], list[WaveSender], list[WaveSender], list[WaveSender], dict[str, int]]:
    """Prepare Sender chunks through the shared elastic execution-slot pool.

    Receiver-side ACCEPT/SEND/mailbox work stays outside this function and
    remains single-coordinator per Job. Each slot only owns a Sender chunk
    through Login + ADD, which is a safe non-preemptive boundary.
    """
    if not works:
        return [], [], [], [], {"shards": 0, "peak": 0, "wall_ms": 0, "login_max_ms": 0, "add_max_ms": 0}

    chunks = [works[i:i + chunk_size] for i in range(0, len(works), chunk_size)]
    login_ok_all: list[WaveSender] = []
    login_failed_all: list[WaveSender] = []
    add_ok_all: list[WaveSender] = []
    add_failed_all: list[WaveSender] = []
    lock = threading.RLock()
    active_local = 0
    peak_local = 0
    completed_chunks = 0
    login_max_ms = 0
    add_max_ms = 0
    started = time.perf_counter()

    def run_chunk(chunk_no: int, chunk: list[WaveSender]) -> None:
        nonlocal active_local, peak_local, completed_chunks, login_max_ms, add_max_ms
        if stop_event is not None and stop_event.is_set():
            return
        with shard_pool.slot(shard_job_key, stop_event=stop_event) as lease:
            with lock:
                active_local += 1
                peak_local = max(peak_local, active_local)
            _event(
                event_cb,
                f"P8.1 SHARD #{chunk_no} START execSlot={lease.slot_no} size={len(chunk)} "
                f"allocation={lease.allocation}/{shard_pool.total_slots} activeJobs={lease.active_jobs} secretOutput=NONE",
            )
            t0 = time.perf_counter()
            login_ok, login_failed = _login_senders(
                chunk,
                workers=min(login_workers_per_slot, len(chunk)),
                event_cb=None,
                log_every=max(1, len(chunk)),
            )
            login_ms_local = int(round((time.perf_counter() - t0) * 1000.0))
            for work in login_failed:
                work.outcome = "retryable_failure"
                work.error_code = work.error_code or "SENDER_LOGIN_FAILED"

            t1 = time.perf_counter()
            if get_provider_guard().is_open():
                add_ok = []
                add_failed = list(login_ok)
                for work in add_failed:
                    work.outcome = "retryable_failure"
                    work.error_code = "PROVIDER_IP_CIRCUIT_OPEN"
                    work.failure_stage = "LOGIN"
            else:
                add_ok, add_failed = _parallel_stage(
                    login_ok,
                    max_workers=min(add_workers_per_slot, max(1, len(login_ok))),
                    stage="ADD",
                    event_cb=None,
                    log_every=max(1, len(login_ok)),
                    fn=lambda w: send_friend_request(
                        cfg=cfg, slot="S", auth=w.auth, target_mid=receiver_auth.mid,
                        source_type=source_type, timeout=grpc_timeout, live=True,
                    ),
                )
            add_ms_local = int(round((time.perf_counter() - t1) * 1000.0))
            for work in add_failed:
                work.outcome = "retryable_failure"
                if not work.error_code:
                    work.error_code = "FRIEND_ADD_FAILED"
                if not work.failure_stage:
                    work.failure_stage = "ADD"

            with lock:
                login_ok_all.extend(login_ok)
                login_failed_all.extend(login_failed)
                add_ok_all.extend(add_ok)
                add_failed_all.extend(add_failed)
                login_max_ms = max(login_max_ms, login_ms_local)
                add_max_ms = max(add_max_ms, add_ms_local)
                completed_chunks += 1
                active_local -= 1
                done = completed_chunks
                ok_count = len(add_ok_all)
                fail_count = len(login_failed_all) + len(add_failed_all)
            _event(
                event_cb,
                f"P8.1 SHARD #{chunk_no} DONE execSlot={lease.slot_no} prepared={len(add_ok)}/{len(chunk)} "
                f"login={login_ms_local/1000:.2f}s add={add_ms_local/1000:.2f}s "
                f"chunks={done}/{len(chunks)} totalPrepared={ok_count} failed={fail_count} secretOutput=NONE",
            )

    # Each Job may have many chunks (e.g. 1000 Hearts), but the shared pool
    # decides how many may execute at once. Waiting chunks do not own a slot.
    local_waiters = min(len(chunks), shard_pool.total_slots + 2)
    with ThreadPoolExecutor(max_workers=max(1, local_waiters), thread_name_prefix="p81-shard") as pool:
        futures = [pool.submit(run_chunk, idx, chunk) for idx, chunk in enumerate(chunks, 1)]
        for future in as_completed(futures):
            future.result()

    wall_ms = int(round((time.perf_counter() - started) * 1000.0))
    return (
        login_ok_all,
        login_failed_all,
        add_ok_all,
        add_failed_all,
        {
            "shards": len(chunks),
            "peak": peak_local,
            "wall_ms": wall_ms,
            "login_max_ms": login_max_ms,
            "add_max_ms": add_max_ms,
        },
    )


def _mailbox_map(*, cfg, receiver_session: SessionRecord, receiver_auth: AuthRecord, works: list[WaveSender], attempts: int, delay: float, event_cb: Event | None) -> dict[int, int]:
    wanted = {int(w.member_seq): w for w in works if w.member_seq}
    found: dict[int, int] = {}
    for attempt in range(1, attempts + 1):
        result = mailbox_read(cfg=cfg, slot="R", session=receiver_session, auth=receiver_auth, from_member_seq=None, live=True, timeout=float(cfg.workflow.get("ds_timeout_seconds") or 20))
        if bool(result.get("ok")):
            for item in result.get("life_mail_candidates") or []:
                try:
                    sender_seq = int(item.get("fromMemberSeq"))
                    mail_seq = int(item.get("seq"))
                except Exception:
                    continue
                if sender_seq in wanted and sender_seq not in found:
                    found[sender_seq] = mail_seq
        _event(event_cb, f"P7.2 MAILBOX attempt={attempt} found={len(found)}/{len(wanted)} secretOutput=NONE")
        if len(found) >= len(wanted):
            break
        if attempt < attempts:
            time.sleep(delay)
    return found


def _receive_safe(*, cfg, receiver_session: SessionRecord, receiver_auth: AuthRecord, works: list[WaveSender], event_cb: Event | None) -> tuple[list[WaveSender], list[WaveSender]]:
    if not works:
        return [], []
    seqs = [int(w.mail_seq or 0) for w in works if int(w.mail_seq or 0) > 0]
    try:
        result = heart_receive(cfg=cfg, actor_slot="R", actor_session=receiver_session, actor_auth=receiver_auth, life_mail_box_seqs=seqs, live=True, timeout=float(cfg.workflow.get("ds_timeout_seconds") or 20))
    except Exception as exc:
        code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        _event(event_cb, f"P7.2 RECEIVE BATCH EXCEPTION code={code} fallback=verify+single secretOutput=NONE")
        result = {"ok": False, "error": code}
    if bool(result.get("ok")):
        _event(event_cb, f"P7.2 RECEIVE delivered={len(works)}/{len(works)} unresolved=0 secretOutput=NONE")
        return list(works), []

    # Conservative recovery from V3: disappeared mailbox seqs are treated as committed;
    # still-present seqs are retried individually. Exceptions never trigger a blind resend.
    try:
        verify = mailbox_read(cfg=cfg, slot="R", session=receiver_session, auth=receiver_auth, from_member_seq=None, live=True, timeout=float(cfg.workflow.get("ds_timeout_seconds") or 20))
    except Exception as exc:
        code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        _event(event_cb, f"P7.2 RECEIVE VERIFY EXCEPTION code={code} secretOutput=NONE")
        verify = {"ok": False}
    verify_ok = bool(verify.get("ok"))
    present: set[int] = set()
    if verify_ok:
        for item in verify.get("life_mail_candidates") or []:
            try:
                present.add(int(item.get("seq")))
            except Exception:
                pass
    delivered: list[WaveSender] = []
    unresolved: list[WaveSender] = []
    for work in works:
        seq = int(work.mail_seq or 0)
        if verify_ok and seq not in present:
            delivered.append(work)
            continue
        if not verify_ok:
            work.error_code = "MAILBOX_VERIFY_FAILED_AFTER_RECEIVE"
            unresolved.append(work)
            continue
        try:
            single = heart_receive(cfg=cfg, actor_slot="R", actor_session=receiver_session, actor_auth=receiver_auth, life_mail_box_seqs=[seq], live=True, timeout=float(cfg.workflow.get("ds_timeout_seconds") or 20))
        except Exception as exc:
            work.error_code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
            unresolved.append(work)
            continue
        if bool(single.get("ok")):
            delivered.append(work)
        else:
            work.error_code = str(single.get("error") or single.get("response_code") or "HEART_RECEIVE_FAILED")[:80]
            unresolved.append(work)
    _event(event_cb, f"P7.2 RECEIVE delivered={len(delivered)}/{len(works)} unresolved={len(unresolved)} secretOutput=NONE")
    return delivered, unresolved


def _fetch_orphan_recovery_credentials(version: str, *, worker_code: str, sj_id: int, claim_token: str, api_key: str) -> list[WaveSender]:
    status, data = _request_json_retry(
        url=_recovery_credentials_url(), api_key=api_key, claim_token=claim_token,
        payload={"worker_code": worker_code, "version": str(version or "")[:64], "sj_id": sj_id},
        timeout=30, attempts=3,
    )
    if not bool(data.get("ok")) or not (200 <= status < 300):
        raise HeartWaveError(str(data.get("code") or "ORPHAN_SENDER_CREDENTIAL_REJECTED"), str(data.get("message") or "Sender recovery credential request failed"), retryable=bool(data.get("retryable", True)))
    rows = data.get("credentials")
    if not isinstance(rows, list) or not rows:
        return []
    works: list[WaveSender] = []
    seen: set[int] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        sga_id = int(row.get("sga_id") or 0)
        email = str(row.get("email") or "").strip()
        password = str(row.get("password") or "")
        if sga_id < 1 or sga_id in seen or not email or not password:
            for w in works:
                w.password = ""
            raise HeartWaveError("ORPHAN_SENDER_CREDENTIAL_RESPONSE_INVALID", "Sender recovery credential response is invalid", retryable=False)
        seen.add(sga_id)
        works.append(WaveSender(sga_id=sga_id, lease_token="", email=email, password=password))
    return works


def _report_orphan_recovery(version: str, *, worker_code: str, sj_id: int, claim_token: str, api_key: str, recovery_id: str, works: list[WaveSender], runtime_ms: int, receiver_member_seq: int) -> dict[str, Any]:
    status, data = _request_json_retry(
        url=_recovery_result_url(), api_key=api_key, claim_token=claim_token,
        payload={
            "worker_code": worker_code, "version": str(version or "")[:64], "sj_id": sj_id,
            "recovery_id": recovery_id, "runtime_ms": max(0, int(runtime_ms)),
            "receiver_member_seq": int(receiver_member_seq),
            "results": [
                {"sga_id": w.sga_id, "outcome": w.outcome, "error_code": str(w.error_code or "")[:80], "cleanup_ok": bool(w.cleanup_ok)}
                for w in works
            ],
        }, timeout=30, attempts=3,
    )
    if not bool(data.get("ok")) or not (200 <= status < 300):
        raise HeartWaveError(str(data.get("code") or "HEART_ORPHAN_RECOVERY_REJECTED"), str(data.get("message") or "Heart orphan recovery result was rejected"), retryable=bool(data.get("retryable", True)))
    return data


def _recover_orphan_batch(version: str, *, worker_code: str, sj_id: int, claim_token: str, api_key: str, cfg, receiver_auth: AuthRecord, receiver_session: SessionRecord, login_workers: int, mailbox_attempts: int, mailbox_delay: float, grpc_timeout: float, event_cb: Event | None) -> dict[str, Any] | None:
    works = _fetch_orphan_recovery_credentials(version, worker_code=worker_code, sj_id=sj_id, claim_token=claim_token, api_key=api_key)
    if not works:
        return None
    recovery_started = time.perf_counter()
    ids = sorted(w.sga_id for w in works)
    recovery_id = hashlib.sha256((str(sj_id) + ":" + ",".join(str(i) for i in ids)).encode("utf-8")).hexdigest()[:40]
    _event(event_cb, f"P7.2 RECOVERY START sj_id={sj_id} orphanLeases={len(works)} secretOutput=NONE")

    login_ok, login_failed = _login_senders(works, workers=login_workers, event_cb=event_cb)
    for w in login_failed:
        w.outcome = "recovery_required"
        w.error_code = w.error_code or "ORPHAN_SENDER_LOGIN_FAILED"

    found = _mailbox_map(cfg=cfg, receiver_session=receiver_session, receiver_auth=receiver_auth, works=login_ok, attempts=mailbox_attempts, delay=mailbox_delay, event_cb=event_cb)
    mail_ready: list[WaveSender] = []
    for w in login_ok:
        member_seq = int(w.member_seq or 0)
        seq = int(found.get(member_seq) or 0)
        if seq > 0:
            w.mail_seq = seq
            mail_ready.append(w)
        else:
            w.outcome = "recovery_required"
            w.error_code = "ORPHAN_LIFE_MAIL_NOT_FOUND"

    delivered, unresolved = _receive_safe(cfg=cfg, receiver_session=receiver_session, receiver_auth=receiver_auth, works=mail_ready, event_cb=event_cb)
    delivered_ids = {w.sga_id for w in delivered}
    unresolved_ids = {w.sga_id for w in unresolved}
    for w in works:
        if w.sga_id in delivered_ids:
            w.outcome = "delivered"
            w.error_code = ""
        elif w.sga_id in unresolved_ids:
            w.outcome = "recovery_required"
            w.error_code = w.error_code or "ORPHAN_RECEIVE_UNRESOLVED"

    mids = [w.mid for w in delivered if w.mid]
    cleanup_ok = True
    if mids:
        try:
            cleanup = remove_friend(cfg=cfg, slot="R", auth=receiver_auth, target_mids=mids, timeout=grpc_timeout, live=True)
            cleanup_ok = bool(cleanup.get("ok"))
        except Exception:
            cleanup_ok = False
    for w in delivered:
        w.cleanup_ok = cleanup_ok
    if not cleanup_ok:
        for w in delivered:
            w.outcome = "recovery_required"
            w.error_code = "ORPHAN_FRIEND_CLEANUP_FAILED"

    report = _report_orphan_recovery(
        version, worker_code=worker_code, sj_id=sj_id, claim_token=claim_token, api_key=api_key,
        recovery_id=recovery_id, works=works, runtime_ms=int(round((time.perf_counter()-recovery_started)*1000.0)),
        receiver_member_seq=int(receiver_session.member_seq),
    )
    job = report.get("job") if isinstance(report.get("job"), dict) else {}
    _event(event_cb, f"P7.2 RECOVERY DONE delivered={len(delivered)}/{len(works)} progress={job.get('completed_value','?')}/{job.get('target_value','?')} status={job.get('status','?')} secretOutput=NONE")
    for w in works:
        w.password = ""
        w.email = ""
    return report


def _report_batch(version: str, *, worker_code: str, sj_id: int, claim_token: str, api_key: str, batch_no: int, works: list[WaveSender], runtime_ms: int, receiver_member_seq: int, metrics: dict[str, Any], pause_reason: str = "") -> dict[str, Any]:
    status, data = _request_json_retry(
        url=_batch_result_url(),
        api_key=api_key,
        claim_token=claim_token,
        payload={
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "sj_id": sj_id,
            "batch_no": batch_no,
            "runtime_ms": max(0, int(runtime_ms)),
            "receiver_member_seq": int(receiver_member_seq),
            "metrics": metrics,
            "pause_reason": str(pause_reason or "")[:80],
            "results": [
                {
                    "sga_id": w.sga_id,
                    "lease_token": w.lease_token,
                    "outcome": w.outcome,
                    "error_code": str(w.error_code or "")[:80],
                    "failure_stage": str(w.failure_stage or "")[:24],
                    "cleanup_ok": bool(w.cleanup_ok),
                }
                for w in works
            ],
        },
        timeout=30,
    )
    if not bool(data.get("ok")) or not (200 <= status < 300):
        raise HeartWaveError(str(data.get("code") or "HEART_BATCH_RESULT_REJECTED"), str(data.get("message") or "Heart batch result was rejected"), retryable=bool(data.get("retryable", True)))
    return data


def heart_wave_run(version: str, *, live: bool, event_cb: Event | None = None, stop_event: threading.Event | None = None, shard_pool: ElasticShardPool | None = None, shard_job_key: str = "") -> HeartWaveResult:
    started = time.perf_counter()
    if not live:
        return HeartWaveResult(False, "P7_2_LIVE_GUARD_REQUIRED", "--live-heart-wave is required", False, 0.0)

    batch_size = _env_int("MWOIF_HEART_TURBO_BATCH_SIZE", 100, 5, 100)
    wave_size = _env_int("MWOIF_HEART_TURBO_WAVE_SIZE", 10, 5, 50)
    login_workers = _env_int("MWOIF_HEART_TURBO_LOGIN_WORKERS", 40, 1, 50)
    add_workers = _env_int("MWOIF_HEART_TURBO_ADD_WORKERS", 50, 1, 50)
    accept_workers = _env_int("MWOIF_HEART_TURBO_ACCEPT_WORKERS", 3, 1, 50)
    send_workers = _env_int("MWOIF_HEART_TURBO_SEND_WORKERS", 14, 1, 50)
    accept_attempts = _env_int("MWOIF_HEART_TURBO_ACCEPT_ATTEMPTS", 1, 1, 4)
    mailbox_attempts = _env_int("MWOIF_HEART_TURBO_MAILBOX_ATTEMPTS", 8, 1, 20)
    wave_stagger = _env_float("MWOIF_HEART_TURBO_WAVE_STAGGER_SECONDS", 0.20, 0.0, 1.0)
    add_settle = _env_float("MWOIF_HEART_TURBO_ADD_SETTLE_SECONDS", 0.45, 0.0, 2.0)
    friend_settle = _env_float("MWOIF_HEART_TURBO_FRIEND_SETTLE_SECONDS", 0.22, 0.0, 2.0)
    accept_retry_delay = _env_float("MWOIF_HEART_TURBO_RETRY_DELAY_SECONDS", 0.16, 0.05, 1.0)
    mailbox_delay = _env_float("MWOIF_HEART_TURBO_MAILBOX_DELAY_SECONDS", 0.25, 0.05, 2.0)
    progress_log_every = _env_int("MWOIF_HEART_TURBO_PROGRESS_LOG_EVERY", 10, 1, 100)
    max_no_progress = _env_int("MWOIF_HEART_TURBO_MAX_NO_PROGRESS_BATCHES", 3, 1, 20)
    shard_chunk_size = _env_int("MWOIF_HEART_SHARD_CHUNK_SIZE", 10, 5, 50)
    shard_login_workers = _env_int("MWOIF_HEART_SHARD_LOGIN_WORKERS", 10, 1, 20)
    shard_add_workers = _env_int("MWOIF_HEART_SHARD_ADD_WORKERS", 10, 1, 20)
    # P8.2.3 Receiver mutation tuning. Live measurements showed lane=4 caused
    # 37-40 initial INTERNAL misses, while lane=3 reduced the initial tail to
    # about 10. Keep the first ACCEPT lane at 3, then drain only the remaining
    # Sender accepts through a single Receiver-write lane. SEND remains parallel
    # after each successful ACCEPT; duplicate-safety/mailbox rules are unchanged.
    accept_catchup_passes = _env_int("MWOIF_HEART_TURBO_ACCEPT_CATCHUP_PASSES", 3, 0, 5)
    accept_catchup_workers = _env_int("MWOIF_HEART_TURBO_ACCEPT_CATCHUP_WORKERS", 1, 1, 20)
    accept_catchup_delay = _env_float("MWOIF_HEART_TURBO_ACCEPT_CATCHUP_DELAY_SECONDS", 0.25, 0.05, 1.50)

    if stop_event is not None and stop_event.is_set():
        stop_mode = str(getattr(stop_event, "mode", "drain") or "drain").lower()
        if stop_mode in {"pause", "cancel"}:
            marker = getattr(stop_event, "mark_safe", None)
            if callable(marker):
                marker()
            return HeartWaveResult(True, f"HEART_WAVE_{stop_mode.upper()}_SAFEPOINT", "Job control reached a safe boundary before Heart execution", False, (time.perf_counter()-started)*1000.0)
        released = release_active_claim(version)
        if released.ok:
            return HeartWaveResult(True, "HEART_WAVE_DRAINED_BEFORE_START", "Worker drain requested before Heart execution", False, (time.perf_counter()-started)*1000.0, released.sj_id)
        return HeartWaveResult(False, released.code or "HEART_WAVE_DRAIN_RELEASE_FAILED", "Worker could not release the pending claim safely", released.retryable, (time.perf_counter()-started)*1000.0, released.sj_id, recovery_required=True)

    claim = claim_once(version)
    if not claim.ok or not claim.claimed or not isinstance(claim.job, dict):
        return HeartWaveResult(False, claim.code, claim.message, claim.retryable, (time.perf_counter()-started)*1000.0)
    sj_id = int(claim.job.get("sj_id") or 0)
    target = int(claim.job.get("target_value") or 0)
    progress = int(claim.job.get("completed_value") or 0)
    start_progress = progress
    if sj_id < 1 or target < 1:
        return HeartWaveResult(False, "P7_2_JOB_INVALID", "Claimed Heart job is invalid", False, (time.perf_counter()-started)*1000.0, sj_id or None)

    try:
        worker_code, active_sj_id, claim_token, api_key, cfg, receiver_auth, receiver_session = _fetch_receiver_session(version, event_cb)
        if active_sj_id != sj_id:
            raise HeartWaveError("HEART_WAVE_JOB_CHANGED", "Active claim changed during Receiver login", retryable=False)
    except HeartWaveError as exc:
        return HeartWaveResult(False, exc.code, str(exc), exc.retryable, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target)
    except Exception as exc:
        return HeartWaveResult(False, str(getattr(exc, "code", None) or type(exc).__name__), "Receiver session setup failed", True, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target)

    delivered_total = 0
    failed_total = 0
    batches = 0
    no_progress_batches = 0
    source_type = int(cfg.workflow.get("friend_source_type") or 2)
    grpc_timeout = float(cfg.workflow.get("grpc_timeout_seconds") or 12)
    ds_timeout = float(cfg.workflow.get("ds_timeout_seconds") or 20)
    _event(event_cb, f"P7.2 TURBO START sj_id={sj_id} progress={progress}/{target} batch={batch_size} wave={wave_size} secretOutput=NONE")

    # Crash-safe preflight: an earlier process may have SEND-confirmed leases that
    # never reached PHP batch-result because it died during RECEIVE. Recover those
    # exact Sender->mail pairs before leasing any fresh Sender, so no duplicate SEND occurs.
    try:
        recovery_report = _recover_orphan_batch(
            version, worker_code=worker_code, sj_id=sj_id, claim_token=claim_token, api_key=api_key,
            cfg=cfg, receiver_auth=receiver_auth, receiver_session=receiver_session,
            login_workers=login_workers, mailbox_attempts=mailbox_attempts, mailbox_delay=mailbox_delay,
            grpc_timeout=grpc_timeout, event_cb=event_cb,
        )
    except HeartWaveError as exc:
        return HeartWaveResult(False, exc.code, str(exc), exc.retryable, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total, True)
    except Exception as exc:
        code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        return HeartWaveResult(False, code, "Orphan Heart batch recovery failed safely", True, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total, True)
    if isinstance(recovery_report, dict):
        remote_job = recovery_report.get("job") if isinstance(recovery_report.get("job"), dict) else {}
        progress = max(progress, int(remote_job.get("completed_value") or progress))
        target = int(remote_job.get("target_value") or target)
        remote_status = str(remote_job.get("status") or "claimed")
        if remote_status == "completed" or progress >= target:
            try:
                _clear_claim_state(_claim_state_path())
            except Exception:
                pass
            return HeartWaveResult(True, "HEART_WAVE_COMPLETED", "Heart job completed after orphan batch recovery", False, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, progress-start_progress, batches, failed_total)
        if remote_status == "paused":
            try:
                _clear_claim_state(_claim_state_path())
            except Exception:
                pass
            return HeartWaveResult(False, "HEART_WAVE_RECOVERY_REQUIRED", "Orphan Heart batch requires manual review", True, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, progress-start_progress, batches, failed_total, True)

    try:
        receiver_relationship_preflight(
            cfg, receiver_auth, event_cb=event_cb, target_friends=200, capacity=300,
        )
    except ReceiverRelationshipError as exc:
        return HeartWaveResult(False, exc.code, str(exc), exc.retryable, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total)
    except Exception:
        return HeartWaveResult(False, "RECEIVER_RELATIONSHIP_PREFLIGHT_FAILED", "Receiver relationship preflight failed safely", True, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total)

    while progress < target:
        if get_provider_guard().is_open():
            snapshot = get_provider_guard().snapshot()
            if get_provider_guard().mark_alert_sent():
                alert_ok = send_provider_incident_alert(version, snapshot)
                _event(event_cb, f"P6.2 PROVIDER ALERT sent={str(alert_ok).lower()} secretOutput=NONE")
            return HeartWaveResult(False, "PROVIDER_IP_CIRCUIT_OPEN", "Provider/public-IP login circuit is open", True, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total)
        if stop_event is not None and stop_event.is_set():
            stop_mode = str(getattr(stop_event, "mode", "drain") or "drain").lower()
            if stop_mode in {"pause", "cancel"}:
                marker = getattr(stop_event, "mark_safe", None)
                if callable(marker):
                    marker()
                _event(event_cb, f"P11 CONTROL SAFE sj_id={sj_id} mode={stop_mode} progress={progress}/{target} claimReleased=false secretOutput=NONE")
                return HeartWaveResult(True, f"HEART_WAVE_{stop_mode.upper()}_SAFEPOINT", "Job control reached a safe batch boundary", False, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total)
            released = release_active_claim(version, expected_sj_id=sj_id)
            if released.ok and released.released:
                _event(event_cb, f"P9 DRAIN SAFE sj_id={sj_id} progress={progress}/{target} claimReleased=true secretOutput=NONE")
                return HeartWaveResult(True, "HEART_WAVE_DRAINED_SAFE", "Worker drained at a safe batch boundary and returned the job to queue", False, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total)
            _event(event_cb, f"P9 DRAIN HOLD sj_id={sj_id} code={released.code} claimReleased=false secretOutput=NONE")
            return HeartWaveResult(False, released.code or "HEART_WAVE_DRAIN_RELEASE_FAILED", "Worker could not release the active claim safely", released.retryable, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total, True)

        renew = claim_once(version)
        if not renew.ok or not renew.claimed or not isinstance(renew.job, dict) or int(renew.job.get("sj_id") or 0) != sj_id:
            return HeartWaveResult(False, renew.code, renew.message, renew.retryable, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total)
        progress = max(progress, int(renew.job.get("completed_value") or 0))
        target = int(renew.job.get("target_value") or target)
        if progress >= target:
            break

        batches += 1
        wanted = min(batch_size, target - progress)
        batch_started = time.perf_counter()
        stage_started = batch_started
        prepare_ms = 0
        login_ms = 0
        add_ms = 0
        wave_ms = 0
        catchup_ms = 0
        mailbox_receive_ms = 0
        commit_ms = 0
        shard_prepare_ms = 0
        shard_count = 0
        shard_peak = 0
        try:
            works, durable_batch_no = _lease_batch(version, worker_code=worker_code, sj_id=sj_id, claim_token=claim_token, api_key=api_key, count=wanted)
            _event(event_cb, f"P7.2 BATCH #{durable_batch_no} LEASED {len(works)}/{wanted} secretOutput=NONE")
            _hydrate_cached_sender_sessions(works, event_cb=event_cb)
            credential_works = [w for w in works if w.auth is None or w.session is None]
            if credential_works:
                _fetch_batch_credentials(version, worker_code=worker_code, sj_id=sj_id, claim_token=claim_token, api_key=api_key, works=credential_works)
            prepare_ms = int(round((time.perf_counter() - stage_started) * 1000.0))
        except HeartWaveError as exc:
            return HeartWaveResult(False, exc.code, str(exc), exc.retryable, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total)

        if shard_pool is not None and shard_job_key:
            login_ok, login_failed, add_ok, add_failed, shard_stats = _elastic_prepare_shards(
                works,
                shard_pool=shard_pool,
                shard_job_key=shard_job_key,
                chunk_size=shard_chunk_size,
                login_workers_per_slot=shard_login_workers,
                add_workers_per_slot=shard_add_workers,
                cfg=cfg,
                receiver_auth=receiver_auth,
                source_type=source_type,
                grpc_timeout=grpc_timeout,
                stop_event=None,
                event_cb=event_cb,
            )
            shard_prepare_ms = int(shard_stats.get("wall_ms") or 0)
            shard_count = int(shard_stats.get("shards") or 0)
            shard_peak = int(shard_stats.get("peak") or 0)
            # These remain useful diagnostics but overlap in wall-clock time
            # across shard slots. P8.1 PERF reports shardPrepare separately.
            login_ms = int(shard_stats.get("login_max_ms") or 0)
            add_ms = int(shard_stats.get("add_max_ms") or 0)
        else:
            stage_started = time.perf_counter()
            login_ok, login_failed = _login_senders(works, workers=login_workers, event_cb=event_cb, log_every=progress_log_every)
            login_ms = int(round((time.perf_counter() - stage_started) * 1000.0))
            for w in login_failed:
                w.outcome = "retryable_failure"
                w.error_code = w.error_code or "SENDER_LOGIN_FAILED"

            stage_started = time.perf_counter()
            if get_provider_guard().is_open():
                add_ok = []
                add_failed = list(login_ok)
                for w in add_failed:
                    w.outcome = "retryable_failure"
                    w.error_code = "PROVIDER_IP_CIRCUIT_OPEN"
                    w.failure_stage = "LOGIN"
            else:
                add_ok, add_failed = _parallel_stage(
                    login_ok,
                    max_workers=add_workers,
                    stage="ADD",
                    event_cb=event_cb,
                    log_every=progress_log_every,
                    fn=lambda w: send_friend_request(cfg=cfg, slot="S", auth=w.auth, target_mid=receiver_auth.mid, source_type=source_type, timeout=grpc_timeout, live=True),
                )
            add_ms = int(round((time.perf_counter() - stage_started) * 1000.0))
            for w in add_failed:
                w.outcome = "retryable_failure"
                if not w.error_code:
                    w.error_code = "FRIEND_ADD_FAILED"
                if not w.failure_stage:
                    w.failure_stage = "ADD"

        provider_guard = get_provider_guard()
        if provider_guard.is_open():
            snapshot = provider_guard.snapshot()
            if provider_guard.mark_alert_sent():
                alert_ok = send_provider_incident_alert(version, snapshot)
                _event(event_cb, f"P6.2 PROVIDER ALERT sent={str(alert_ok).lower()} secretOutput=NONE")
            pending_created = [w for w in add_ok if w.mid]
            if pending_created:
                reject_workers = min(10, len(pending_created))
                with ThreadPoolExecutor(max_workers=max(1, reject_workers), thread_name_prefix="provider-pending-reject") as reject_pool:
                    reject_futures = [
                        reject_pool.submit(
                            handle_friend_request, cfg=cfg, slot="R", auth=receiver_auth,
                            target_mid=w.mid, accept=False, timeout=grpc_timeout, live=True,
                        ) for w in pending_created
                    ]
                    for future in as_completed(reject_futures):
                        try:
                            future.result()
                        except Exception:
                            pass
            for w in works:
                if w.outcome != "delivered":
                    w.outcome = "retryable_failure"
                    w.error_code = "PROVIDER_IP_LIMIT_SUSPECTED"
                    w.failure_stage = "LOGIN"
            runtime_ms = int(round((time.perf_counter() - batch_started) * 1000.0))
            report = _report_batch(
                version, worker_code=worker_code, sj_id=sj_id, claim_token=claim_token, api_key=api_key,
                batch_no=durable_batch_no, works=works, runtime_ms=runtime_ms,
                receiver_member_seq=int(receiver_session.member_seq),
                metrics={"ready_count": len(login_ok), "add_count": len(add_ok), "provider_incident": True},
                pause_reason="PROVIDER_IP_LIMIT_SUSPECTED",
            )
            job_remote = report.get("job") if isinstance(report.get("job"), dict) else {}
            return HeartWaveResult(False, "PROVIDER_IP_LIMIT_SUSPECTED", "Provider/public-IP login incident detected; job paused", True, (time.perf_counter()-started)*1000.0, sj_id, start_progress, int(job_remote.get("completed_value") or progress), target, delivered_total, batches, failed_total)

        login_failover_rounds = 0
        login_replaced_total = 0
        initial_replaceable = _replaceable_login_failures(login_failed)
        if initial_replaceable:
            max_replace_rounds = _env_int("MWOIF_HEART_LOGIN_REPLACEMENT_ROUNDS", 4, 1, 8)
            replaceable_ids = {w.sga_id for w in initial_replaceable}
            active_works: dict[int, WaveSender] = {w.sga_id: w for w in works if w.sga_id not in replaceable_ids}
            final_login_failed: list[WaveSender] = [w for w in login_failed if w.sga_id not in replaceable_ids]
            pending_failed = list(initial_replaceable)

            for replace_round in range(1, max_replace_rounds + 1):
                if not pending_failed:
                    break
                login_failover_rounds = replace_round
                try:
                    replacements, retired_ids = _replace_failed_login_senders(
                        version,
                        worker_code=worker_code,
                        sj_id=sj_id,
                        claim_token=claim_token,
                        api_key=api_key,
                        failed=pending_failed,
                        event_cb=event_cb,
                    )
                except HeartWaveError as exc:
                    _event(
                        event_cb,
                        f"P10 LOGIN FAILOVER HOLD round={replace_round} code={exc.code} "
                        f"pending={len(pending_failed)} secretOutput=NONE",
                    )
                    for work in pending_failed:
                        active_works[work.sga_id] = work
                        final_login_failed.append(work)
                    pending_failed = []
                    break

                unreplaced = [w for w in pending_failed if w.sga_id not in retired_ids]
                for work in unreplaced:
                    active_works[work.sga_id] = work
                    final_login_failed.append(work)
                pending_failed = []
                login_replaced_total += len(replacements)
                if not replacements:
                    break

                try:
                    _hydrate_cached_sender_sessions(replacements, event_cb=event_cb)
                    replacement_credential_works = [w for w in replacements if w.auth is None or w.session is None]
                    if replacement_credential_works:
                        _fetch_batch_credentials(
                            version,
                            worker_code=worker_code,
                            sj_id=sj_id,
                            claim_token=claim_token,
                            api_key=api_key,
                            works=replacement_credential_works,
                        )
                except HeartWaveError as exc:
                    for work in replacements:
                        work.outcome = "retryable_failure"
                        work.error_code = exc.code or "SENDER_BATCH_CREDENTIAL_REJECTED"
                        active_works[work.sga_id] = work
                        final_login_failed.append(work)
                    _event(
                        event_cb,
                        f"P10 LOGIN FAILOVER CREDENTIAL_FAIL round={replace_round} "
                        f"count={len(replacements)} code={exc.code} secretOutput=NONE",
                    )
                    break

                if shard_pool is not None and shard_job_key:
                    repl_login_ok, repl_login_failed, repl_add_ok, repl_add_failed, repl_stats = _elastic_prepare_shards(
                        replacements,
                        shard_pool=shard_pool,
                        shard_job_key=shard_job_key,
                        chunk_size=shard_chunk_size,
                        login_workers_per_slot=shard_login_workers,
                        add_workers_per_slot=shard_add_workers,
                        cfg=cfg,
                        receiver_auth=receiver_auth,
                        source_type=source_type,
                        grpc_timeout=grpc_timeout,
                        stop_event=None,
                        event_cb=event_cb,
                    )
                    shard_prepare_ms += int(repl_stats.get("wall_ms") or 0)
                    shard_count += int(repl_stats.get("shards") or 0)
                    shard_peak = max(shard_peak, int(repl_stats.get("peak") or 0))
                else:
                    repl_login_ok, repl_login_failed = _login_senders(
                        replacements,
                        workers=min(login_workers, len(replacements)),
                        event_cb=event_cb,
                        log_every=max(1, min(progress_log_every, len(replacements))),
                    )
                    for work in repl_login_failed:
                        work.outcome = "retryable_failure"
                        work.error_code = work.error_code or "SENDER_LOGIN_FAILED"
                    repl_add_ok, repl_add_failed = _parallel_stage(
                        repl_login_ok,
                        max_workers=min(add_workers, max(1, len(repl_login_ok))),
                        stage="ADD",
                        event_cb=event_cb,
                        log_every=max(1, min(progress_log_every, len(repl_login_ok))),
                        fn=lambda w: send_friend_request(
                            cfg=cfg, slot="S", auth=w.auth, target_mid=receiver_auth.mid,
                            source_type=source_type, timeout=grpc_timeout, live=True,
                        ),
                    )
                    for work in repl_add_failed:
                        work.outcome = "retryable_failure"
                        work.error_code = work.error_code or "FRIEND_ADD_FAILED"
                        work.failure_stage = "ADD"

                login_ok.extend(repl_login_ok)
                add_ok.extend(repl_add_ok)
                add_failed.extend(repl_add_failed)
                for work in repl_login_ok:
                    active_works[work.sga_id] = work

                next_replaceable = _replaceable_login_failures(repl_login_failed)
                next_replaceable_ids = {w.sga_id for w in next_replaceable}
                for work in repl_login_failed:
                    if work.sga_id not in next_replaceable_ids:
                        active_works[work.sga_id] = work
                        final_login_failed.append(work)

                if next_replaceable and replace_round < max_replace_rounds:
                    pending_failed = next_replaceable
                    _event(
                        event_cb,
                        f"P10 LOGIN FAILOVER ROUND {replace_round} next={len(next_replaceable)} "
                        f"ready={len(repl_login_ok)} secretOutput=NONE",
                    )
                else:
                    for work in next_replaceable:
                        active_works[work.sga_id] = work
                        final_login_failed.append(work)
                    pending_failed = []

            works = list(active_works.values())
            seen_failed: set[int] = set()
            login_failed = []
            for work in final_login_failed:
                if work.sga_id in active_works and work.sga_id not in seen_failed:
                    seen_failed.add(work.sga_id)
                    login_failed.append(work)
            _event(
                event_cb,
                f"P10 LOGIN FAILOVER DONE rounds={login_failover_rounds} replaced={login_replaced_total} "
                f"finalLoginFail={len(login_failed)} activeBatch={len(works)}/{wanted} secretOutput=NONE",
            )

        if add_settle > 0 and add_ok:
            time.sleep(add_settle)

        accept_sem = threading.Semaphore(max(1, accept_workers))
        send_sem = threading.Semaphore(max(1, send_workers))
        state_lock = threading.RLock()
        accepted: list[WaveSender] = []
        accept_failed: list[WaveSender] = []
        send_confirmed: list[WaveSender] = []
        send_explicit_failed: list[WaveSender] = []
        send_unknown: list[WaveSender] = []
        _event(
            event_cb,
            f"P8.2.3 ACCEPT DRAIN initialLane={accept_workers} initialAttempts={accept_attempts} "
            f"catchupLane={accept_catchup_workers} catchupPasses={accept_catchup_passes} "
            f"catchupDelay={accept_catchup_delay:.2f}s secretOutput=NONE",
        )

        def pipeline_one(work: WaveSender, wave_no: int) -> None:
            last_accept: dict[str, Any] | None = None
            accepted_here = False
            for attempt in range(1, accept_attempts + 1):
                if attempt > 1:
                    time.sleep(accept_retry_delay * (1.0 + 0.55 * (attempt - 2)) + (work.sga_id % 11) * 0.009)
                try:
                    with accept_sem:
                        last_accept = handle_friend_request(cfg=cfg, slot="R", auth=receiver_auth, target_mid=work.auth.mid, accept=True, timeout=grpc_timeout, live=True)
                except Exception as exc:
                    last_accept = {"ok": False, "error": str(getattr(exc, "code", None) or type(exc).__name__)}
                if bool(last_accept.get("ok")):
                    accepted_here = True
                    break
            if not accepted_here:
                work.outcome = "retryable_failure"
                work.error_code = str((last_accept or {}).get("grpc_code") or (last_accept or {}).get("response_code") or (last_accept or {}).get("error") or "FRIEND_ACCEPT_FAILED")[:80]
                work.failure_stage = "ACCEPT"
                with state_lock:
                    accept_failed.append(work)
                return
            with state_lock:
                accepted.append(work)
            if friend_settle > 0:
                time.sleep(friend_settle + (work.sga_id % 7) * 0.008)
            try:
                with send_sem:
                    sent = heart_send(cfg=cfg, actor_slot="S", target_slot="R", actor_session=work.session, target_session=receiver_session, actor_auth=work.auth, live=True, timeout=ds_timeout)
                work.steps["SEND"] = _summary(sent)
                if bool(sent.get("ok")):
                    work.send_class = "confirmed"
                    with state_lock:
                        send_confirmed.append(work)
                elif _explicit_send_failure(sent):
                    work.send_class = "explicit_failed"
                    work.error_code = str(sent.get("error") or sent.get("response_code") or "SEND_FAILED")[:80]
                    work.failure_stage = "SEND"
                    with state_lock:
                        send_explicit_failed.append(work)
                else:
                    work.send_class = "unknown"
                    work.error_code = "SEND_OUTCOME_UNKNOWN"
                    work.failure_stage = "SEND"
                    with state_lock:
                        send_unknown.append(work)
            except Exception:
                work.send_class = "unknown"
                work.error_code = "SEND_OUTCOME_UNKNOWN"
                work.failure_stage = "SEND"
                with state_lock:
                    send_unknown.append(work)

        stage_started = time.perf_counter()
        with ThreadPoolExecutor(max_workers=min(50, max(1, len(add_ok))), thread_name_prefix="p72-wave") as pool:
            futures = []
            for wave_no, start in enumerate(range(0, len(add_ok), wave_size), 1):
                wave = add_ok[start:start + wave_size]
                _event(event_cb, f"P7.2 WAVE #{wave_no} start={len(wave)} accept={accept_workers} send={send_workers} secretOutput=NONE")
                for w in wave:
                    futures.append(pool.submit(pipeline_one, w, wave_no))
                if start + wave_size < len(add_ok) and wave_stagger > 0:
                    time.sleep(wave_stagger)
            for future in as_completed(futures):
                future.result()
        wave_ms = int(round((time.perf_counter() - stage_started) * 1000.0))

        # P7.3 ACCEPT catch-up: V3 live benchmarks showed that the long tail is
        # receiver-side friend-state propagation, not Sender login or ADD.
        # Keep those already leased/logged-in Sender sessions and retry ACCEPT
        # in delayed, lower-pressure passes. A recovered ACCEPT goes straight
        # to SEND; no new lease/login is paid for this Sender.
        stage_started = time.perf_counter()
        pending_accept = list(accept_failed)
        initial_accept_miss = len(pending_accept)
        accept_failed = []
        catchup_recovered = 0
        for catchup_pass in range(1, accept_catchup_passes + 1):
            if not pending_accept:
                break
            delay = accept_catchup_delay + (catchup_pass - 1) * 0.12
            if delay > 0:
                time.sleep(delay)
            # Keep receiver mutation pressure stable instead of creating a
            # synchronized retry burst. A narrow lane lets the backend commit
            # each friend-state write before too many sibling writes race it.
            pass_workers = max(1, min(accept_catchup_workers, len(pending_accept)))
            catchup_sem = threading.Semaphore(pass_workers)
            next_pending: list[WaveSender] = []
            pass_recovered: list[WaveSender] = []
            pass_fail_codes: dict[str, int] = {}
            pass_lock = threading.Lock()
            _event(event_cb, f"P8.2.3 CATCHUP #{catchup_pass} start={len(pending_accept)} lane={pass_workers} secretOutput=NONE")

            def catchup_one(work: WaveSender) -> None:
                accepted_here = False
                last_accept: dict[str, Any] | None = None
                try:
                    with catchup_sem:
                        last_accept = handle_friend_request(
                            cfg=cfg, slot="R", auth=receiver_auth,
                            target_mid=work.auth.mid, accept=True,
                            timeout=grpc_timeout, live=True,
                        )
                    accepted_here = bool(last_accept.get("ok"))
                except Exception as exc:
                    last_accept = {"ok": False, "error": str(getattr(exc, "code", None) or type(exc).__name__)}

                if not accepted_here:
                    work.error_code = str((last_accept or {}).get("grpc_code") or (last_accept or {}).get("response_code") or (last_accept or {}).get("error") or "FRIEND_ACCEPT_FAILED")[:80]
                    work.failure_stage = "ACCEPT"
                    public_code = work.error_code or "FRIEND_ACCEPT_FAILED"
                    with pass_lock:
                        next_pending.append(work)
                        pass_fail_codes[public_code] = pass_fail_codes.get(public_code, 0) + 1
                    return

                work.error_code = ""
                work.outcome = "retryable_failure"
                with state_lock:
                    accepted.append(work)
                with pass_lock:
                    pass_recovered.append(work)
                if friend_settle > 0:
                    time.sleep(max(0.05, friend_settle * 0.75) + (work.sga_id % 7) * 0.006)
                try:
                    with send_sem:
                        sent = heart_send(
                            cfg=cfg, actor_slot="S", target_slot="R",
                            actor_session=work.session, target_session=receiver_session,
                            actor_auth=work.auth, live=True, timeout=ds_timeout,
                        )
                    work.steps[f"SEND_CATCHUP_{catchup_pass}"] = _summary(sent)
                    if bool(sent.get("ok")):
                        work.send_class = f"confirmed_catchup_{catchup_pass}"
                        with state_lock:
                            send_confirmed.append(work)
                    elif _explicit_send_failure(sent):
                        work.send_class = f"explicit_failed_catchup_{catchup_pass}"
                        work.error_code = str(sent.get("error") or sent.get("response_code") or "SEND_FAILED")[:80]
                        with state_lock:
                            send_explicit_failed.append(work)
                    else:
                        work.send_class = f"unknown_catchup_{catchup_pass}"
                        work.error_code = "SEND_OUTCOME_UNKNOWN"
                        with state_lock:
                            send_unknown.append(work)
                except Exception:
                    work.send_class = f"unknown_catchup_{catchup_pass}"
                    work.error_code = "SEND_OUTCOME_UNKNOWN"
                    with state_lock:
                        send_unknown.append(work)

            with ThreadPoolExecutor(
                max_workers=max(1, min(50, pass_workers + send_workers, len(pending_accept))),
                thread_name_prefix=f"p73-catchup-{catchup_pass}",
            ) as pool:
                futures = [pool.submit(catchup_one, work) for work in pending_accept]
                for future in as_completed(futures):
                    future.result()
            catchup_recovered += len(pass_recovered)
            pending_accept = next_pending
            fail_codes = ",".join(f"{k}:{v}" for k, v in sorted(pass_fail_codes.items())) or "none"
            _event(
                event_cb,
                f"P8.2.3 CATCHUP #{catchup_pass} recovered={len(pass_recovered)} "
                f"remaining={len(pending_accept)} failCodes={fail_codes} secretOutput=NONE",
            )

        accept_failed = pending_accept
        catchup_ms = int(round((time.perf_counter() - stage_started) * 1000.0))

        # Mailbox-first duplicate safety for all send outcomes.
        sent_candidates: list[WaveSender] = []
        _seen_sent: set[int] = set()
        for _work in (send_confirmed + send_explicit_failed + send_unknown):
            if _work.sga_id in _seen_sent:
                continue
            _seen_sent.add(_work.sga_id)
            sent_candidates.append(_work)
        stage_started = time.perf_counter()
        found = _mailbox_map(cfg=cfg, receiver_session=receiver_session, receiver_auth=receiver_auth, works=sent_candidates, attempts=mailbox_attempts, delay=mailbox_delay, event_cb=event_cb)
        for w in sent_candidates:
            if w.member_seq in found:
                w.mail_seq = found[int(w.member_seq)]

        # Explicit first-pass failures proven absent from mailbox get exactly one bounded
        # retry. The retry outcome is classified again so a confirmed/unknown second SEND
        # is never downgraded to a safe retryable failure merely because mail is delayed.
        retry_candidates = [w for w in send_explicit_failed if not w.mail_seq]
        if retry_candidates:
            retry_confirmed: list[WaveSender] = []
            retry_explicit_failed: list[WaveSender] = []
            retry_unknown: list[WaveSender] = []
            retry_lock = threading.Lock()

            def retry_send_one(work: WaveSender) -> WaveSender:
                try:
                    sent = heart_send(
                        cfg=cfg, actor_slot="S", target_slot="R",
                        actor_session=work.session, target_session=receiver_session,
                        actor_auth=work.auth, live=True, timeout=ds_timeout,
                    )
                    work.steps["SEND_RETRY"] = _summary(sent)
                    if bool(sent.get("ok")):
                        work.send_class = "confirmed_retry"
                        work.error_code = ""
                        bucket = retry_confirmed
                    elif _explicit_send_failure(sent):
                        work.send_class = "explicit_failed_retry"
                        work.error_code = str(sent.get("error") or sent.get("response_code") or "SEND_EXPLICIT_FAILED")[:80]
                        bucket = retry_explicit_failed
                    else:
                        work.send_class = "unknown_retry"
                        work.error_code = "SEND_RETRY_OUTCOME_UNKNOWN"
                        bucket = retry_unknown
                except Exception:
                    work.send_class = "unknown_retry"
                    work.error_code = "SEND_RETRY_OUTCOME_UNKNOWN"
                    bucket = retry_unknown
                with retry_lock:
                    bucket.append(work)
                return work

            retry_workers = min(8, send_workers, len(retry_candidates))
            with ThreadPoolExecutor(max_workers=max(1, retry_workers), thread_name_prefix="p72-send-retry") as pool:
                futures = [pool.submit(retry_send_one, w) for w in retry_candidates]
                for future in as_completed(futures):
                    future.result()

            retry_all = retry_confirmed + retry_explicit_failed + retry_unknown
            retry_found = _mailbox_map(
                cfg=cfg, receiver_session=receiver_session, receiver_auth=receiver_auth,
                works=retry_all, attempts=min(4, mailbox_attempts), delay=mailbox_delay, event_cb=event_cb,
            )
            for w in retry_all:
                if w.member_seq in retry_found:
                    w.mail_seq = retry_found[int(w.member_seq)]
                elif w.send_class == "explicit_failed_retry":
                    w.outcome = "retryable_failure"
                    w.error_code = w.error_code or "SEND_EXPLICIT_FAILED"
                else:
                    # A confirmed/unknown retry without mailbox proof is ambiguous.
                    # Pause/recover instead of ever issuing a third SEND.
                    w.outcome = "recovery_required"
                    w.error_code = w.error_code or "LIFE_MAIL_SEQ_NOT_FOUND_AFTER_RETRY"

        mail_ready: list[WaveSender] = []
        for w in sent_candidates:
            if w.mail_seq:
                mail_ready.append(w)
            elif w.send_class in {"explicit_failed", "explicit_failed_retry"}:
                if w.outcome != "recovery_required":
                    w.outcome = "retryable_failure"
                    w.error_code = w.error_code or "SEND_EXPLICIT_FAILED"
            else:
                # Confirmed/unknown SEND without mailbox proof must never be blindly resent.
                w.outcome = "recovery_required"
                w.error_code = w.error_code or "LIFE_MAIL_SEQ_NOT_FOUND"

        delivered, receive_unresolved = _receive_safe(cfg=cfg, receiver_session=receiver_session, receiver_auth=receiver_auth, works=mail_ready, event_cb=event_cb)
        mailbox_receive_ms = int(round((time.perf_counter() - stage_started) * 1000.0))
        delivered_ids = {w.sga_id for w in delivered}
        for w in delivered:
            w.outcome = "delivered"
            w.error_code = ""
            w.failure_stage = ""
        for w in receive_unresolved:
            w.outcome = "recovery_required"
            w.error_code = w.error_code or "HEART_RECEIVE_FAILED"
            w.failure_stage = "RECEIVE"

        # Free receiver friend slots for Sender attempts that reached ADD/ACCEPT but
        # did not become a confirmed delivery. This mirrors the proven V3 cleanup
        # path and prevents friend-capacity leakage across batches.
        stage_cleanup_targets: list[WaveSender] = []
        _stage_seen: set[int] = set()
        for _work in (accept_failed + send_explicit_failed + send_unknown):
            if _work.sga_id in _stage_seen or not _work.mid:
                continue
            _stage_seen.add(_work.sga_id)
            stage_cleanup_targets.append(_work)
        stage_cleanup_ok = True
        if stage_cleanup_targets:
            try:
                stage_cleanup = remove_friend(
                    cfg=cfg, slot="R", auth=receiver_auth,
                    target_mids=[w.mid for w in stage_cleanup_targets],
                    timeout=grpc_timeout, live=True,
                )
                stage_cleanup_ok = bool(stage_cleanup.get("ok"))
            except Exception:
                stage_cleanup_ok = False

        # One receiver-side bulk cleanup for successfully received Hearts.
        cleanup_ok = True
        mids = [w.mid for w in delivered if w.mid]
        if mids:
            try:
                cleanup = remove_friend(cfg=cfg, slot="R", auth=receiver_auth, target_mids=mids, timeout=grpc_timeout, live=True)
                cleanup_ok = bool(cleanup.get("ok"))
            except Exception:
                cleanup_ok = False
        for w in delivered:
            w.cleanup_ok = cleanup_ok

        batch_runtime_ms = int(round((time.perf_counter() - batch_started) * 1000.0))
        metrics = {
            "ready_count": len(login_ok),
            "add_count": len(add_ok),
            "accept_count": len(accepted),
            "send_count": len([w for w in sent_candidates if w.mail_seq or w.send_class == "confirmed"]),
            "mail_count": len(mail_ready),
            "wave_size": wave_size,
            "wave_stagger_ms": int(round(wave_stagger * 1000)),
            "login_workers": login_workers,
            "session_cache_hits": len([w for w in works if w.steps.get("LOGIN_SOURCE") == "cache"]),
            "session_fresh_logins": len([w for w in works if w.steps.get("LOGIN_SOURCE") == "fresh"]),
            "session_pool_size": int(get_sender_session_pool().stats().get("size") or 0),
            "login_circuit_state": str(get_login_circuit().snapshot().get("state") or "closed"),
            "login_failover_rounds": login_failover_rounds,
            "login_replaced_count": login_replaced_total,
            "login_final_failures": len(login_failed),
            "add_workers": add_workers,
            "accept_workers": accept_workers,
            "send_workers": send_workers,
            "progress_log_every": progress_log_every,
            "stage_cleanup_ok": bool(stage_cleanup_ok),
            "delivery_cleanup_ok": bool(cleanup_ok),
            "accept_catchup_passes": accept_catchup_passes,
            "accept_catchup_recovered": catchup_recovered,
            "prepare_ms": prepare_ms,
            "login_ms": login_ms,
            "add_ms": add_ms,
            "wave_ms": wave_ms,
            "catchup_ms": catchup_ms,
            "mailbox_receive_ms": mailbox_receive_ms,
            "shard_prepare_ms": shard_prepare_ms,
            "shard_count": shard_count,
            "shard_peak": shard_peak,
            "shard_chunk_size": shard_chunk_size if shard_pool is not None else 0,
        }
        failed_stage_counts: dict[str, int] = {}
        failed_code_counts: dict[str, int] = {}
        for _work in works:
            if _work.outcome == "delivered":
                continue
            _stage = str(_work.failure_stage or "UNKNOWN").upper()
            _code = str(_work.error_code or "UNKNOWN").upper()[:80]
            failed_stage_counts[_stage] = failed_stage_counts.get(_stage, 0) + 1
            failed_code_counts[_code] = failed_code_counts.get(_code, 0) + 1
        if failed_stage_counts:
            stage_text = ",".join(f"{k}:{v}" for k, v in sorted(failed_stage_counts.items()))
            code_text = ",".join(f"{k}:{v}" for k, v in sorted(failed_code_counts.items()))
            _event(event_cb, f"P6.1 BATCH FAILURES stages={stage_text} codes={code_text} secretOutput=NONE")

        _invalidate_stale_cached_sender_sessions(works, event_cb=event_cb)
        pool_stats = get_sender_session_pool().stats()
        circuit_stats = get_login_circuit().snapshot()
        _event(
            event_cb,
            f"P10.1 SESSION POOL size={pool_stats['size']} hits={pool_stats['hits']} persistentHits={pool_stats['persistent_hits']} "
            f"misses={pool_stats['misses']} writes={pool_stats['persistent_writes']} persistErrors={pool_stats['persistent_errors']} "
            f"ttl={pool_stats['ttl_seconds']}s maxAge={pool_stats['persistent_max_age_seconds']}s "
            f"circuit={circuit_stats['state']} remaining={circuit_stats['remaining_seconds']}s secretOutput=NONE",
        )
        commit_started = time.perf_counter()
        projected_no_progress = no_progress_batches + (0 if delivered_ids else 1)
        pause_reason = "FRIEND_CLEANUP_FAILED" if (not stage_cleanup_ok or not cleanup_ok) else ""
        if not pause_reason and not delivered_ids and projected_no_progress >= max_no_progress:
            pause_reason = "HEART_WAVE_NO_PROGRESS_LIMIT"
            _event(
                event_cb,
                f"P6.1 NO PROGRESS PAUSE batches={projected_no_progress}/{max_no_progress} "
                f"sj_id={sj_id} secretOutput=NONE",
            )
        try:
            report = _report_batch(
                version,
                worker_code=worker_code,
                sj_id=sj_id,
                claim_token=claim_token,
                api_key=api_key,
                batch_no=durable_batch_no,
                works=works,
                runtime_ms=batch_runtime_ms,
                receiver_member_seq=int(receiver_session.member_seq),
                metrics=metrics,
                pause_reason=pause_reason,
            )
        finally:
            # Credentials/session tokens remain in process memory only; drop plaintext fields immediately.
            for w in works:
                w.password = ""
                w.email = ""

        commit_ms = int(round((time.perf_counter() - commit_started) * 1000.0))
        job_remote = report.get("job") if isinstance(report.get("job"), dict) else {}
        progress_new = int(job_remote.get("completed_value") or progress)
        status_new = str(job_remote.get("status") or "claimed")
        delivered_batch = int((report.get("batch") or {}).get("delivered_count") or 0) if isinstance(report.get("batch"), dict) else len(delivered_ids)
        recovery_batch = int((report.get("batch") or {}).get("recovery_count") or 0) if isinstance(report.get("batch"), dict) else len(receive_unresolved)
        failed_batch = len([w for w in works if w.outcome in {"retryable_failure", "failed"}])
        delivered_total += delivered_batch
        failed_total += failed_batch
        _event(event_cb, f"P7.2 BATCH #{durable_batch_no} DONE delivered={delivered_batch}/{len(works)} progress={progress_new}/{target} runtime={batch_runtime_ms/1000:.2f}s recovery={recovery_batch} secretOutput=NONE")
        _event(event_cb, f"P7.3 PERF BATCH #{durable_batch_no} prepare={prepare_ms/1000:.2f}s login={login_ms/1000:.2f}s add={add_ms/1000:.2f}s wave={wave_ms/1000:.2f}s catchup={catchup_ms/1000:.2f}s mailReceive={mailbox_receive_ms/1000:.2f}s commit={commit_ms/1000:.2f}s secretOutput=NONE")
        _event(event_cb, f"P8.2.3 PERF BATCH #{durable_batch_no} initialLane={accept_workers} initialMiss={initial_accept_miss} catchupLane={accept_catchup_workers} catchupPasses={accept_catchup_passes} catchupRecovered={catchup_recovered} catchupRemain={len(accept_failed)} catchup={catchup_ms/1000:.2f}s secretOutput=NONE")
        if shard_pool is not None and shard_job_key:
            allocation_now = shard_pool.snapshot(shard_job_key)
            _event(
                event_cb,
                f"P8.1 PERF BATCH #{durable_batch_no} shardPrepare={shard_prepare_ms/1000:.2f}s "
                f"shards={shard_count} chunk={shard_chunk_size} peakSlots={shard_peak} "
                f"allocationNow={allocation_now.get('allocation',0)}/{shard_pool.total_slots} "
                f"activeJobs={allocation_now.get('active_jobs',0)} secretOutput=NONE",
            )

        if recovery_batch > 0 or status_new == "paused":
            try:
                _clear_claim_state(_claim_state_path())
            except Exception:
                pass
            return HeartWaveResult(False, "HEART_WAVE_RECOVERY_REQUIRED", "A Heart batch requires recovery before automatic processing can continue", True, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress_new, target, delivered_total, batches, failed_total, True)

        progress = progress_new
        if status_new == "completed" or progress >= target:
            try:
                _clear_claim_state(_claim_state_path())
            except Exception:
                pass
            _event(event_cb, f"P7.2 TURBO COMPLETE sj_id={sj_id} progress={progress}/{target} batches={batches} secretOutput=NONE")
            return HeartWaveResult(True, "HEART_WAVE_COMPLETED", "Heart job completed by Adaptive Wave worker", False, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total)

        if delivered_batch <= 0:
            no_progress_batches += 1
            if no_progress_batches >= max_no_progress:
                return HeartWaveResult(False, "HEART_WAVE_NO_PROGRESS_LIMIT", "Adaptive Wave made no delivery progress for too many batches", True, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total)
        else:
            no_progress_batches = 0

    try:
        _clear_claim_state(_claim_state_path())
    except Exception:
        pass
    return HeartWaveResult(True, "HEART_WAVE_COMPLETED", "Heart job completed by Adaptive Wave worker", False, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, delivered_total, batches, failed_total)
