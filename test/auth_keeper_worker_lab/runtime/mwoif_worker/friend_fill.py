from __future__ import annotations

import hashlib
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from mwoif.friend.service import handle_friend_request, list_friends, send_friend_request
from mwoif.session.models import AuthRecord
from mwoif_worker.claim import _clear_state as _clear_claim_state, _state_path as _claim_state_path
from mwoif_worker.heart_wave import (
    HeartWaveError,
    WaveSender,
    _fetch_receiver_session,
    _hydrate_cached_sender_sessions,
    _invalidate_stale_cached_sender_sessions,
    _login_senders,
    _request_json_retry,
)
from mwoif_worker.provider_guard import get_provider_guard
from mwoif_worker.sender_session_pool import get_sender_session_pool
from mwoif_worker.shard_scheduler import ElasticShardPool

Event = Callable[[str], None]
_PENDING_PATH = (3, 1, 1)
_IGNORED_PATHS = {(4,)}


class FriendFillError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class FriendState:
    count: int
    ids: frozenset[str]
    path: tuple[int, ...] | None
    pending_count: int
    pending_ids: frozenset[str]


@dataclass(slots=True)
class FriendFillResult:
    ok: bool
    code: str
    message: str
    retryable: bool
    elapsed_ms: float
    sj_id: int | None = None
    start_progress: int = 0
    progress_value: int = 0
    target_value: int = 300
    delivered_this_run: int = 0
    batches: int = 0
    failed_attempts: int = 0
    recovery_required: bool = False


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


def _failure_summary(works: list[WaveSender]) -> str:
    counts = Counter(str(work.error_code or "UNKNOWN")[:80] for work in works if work.error_code)
    if not counts:
        return "none"
    return ",".join(f"{code}:{count}" for code, count in counts.most_common(6))


def _next_fill_wanted(progress: int, batch_size: int, target: int = 300) -> int:
    progress = max(0, min(target, int(progress)))
    if progress >= target:
        return 0
    boundary = min(target, ((progress // batch_size) + 1) * batch_size)
    return max(1, boundary - progress)


def _endpoint(env_name: str, default: str, suffix: str) -> str:
    url = str(os.getenv(env_name) or default).strip()
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    scheme = parts.scheme.lower()
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    if scheme not in {"http", "https"} or not host or not (parts.path or "").endswith(suffix):
        raise FriendFillError(f"{env_name}_INVALID", f"{env_name} is invalid", retryable=False)
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise FriendFillError(f"{env_name}_INVALID", f"{env_name} is invalid", retryable=False)
    if not loopback and scheme != "https":
        raise FriendFillError(f"{env_name}_HTTPS_REQUIRED", f"{env_name} must use HTTPS outside loopback", retryable=False)
    return url


def _lease_url() -> str:
    return _endpoint(
        "MWOIF_WEB_FRIEND_HELPER_BATCH_LEASE_URL",
        "http://127.0.0.1/M_woif/work/jobs/friend-helper-batch-lease.php",
        "/work/jobs/friend-helper-batch-lease.php",
    )


def _credentials_url() -> str:
    return _endpoint(
        "MWOIF_WEB_FRIEND_HELPER_BATCH_CREDENTIALS_URL",
        "http://127.0.0.1/M_woif/work/jobs/friend-helper-batch-credentials.php",
        "/work/jobs/friend-helper-batch-credentials.php",
    )


def _result_url() -> str:
    return _endpoint(
        "MWOIF_WEB_FRIEND_BATCH_RESULT_URL",
        "http://127.0.0.1/M_woif/work/jobs/friend-batch-result.php",
        "/work/jobs/friend-batch-result.php",
    )


def _groups(result: dict[str, Any]) -> dict[tuple[int, ...], frozenset[str]]:
    out: dict[tuple[int, ...], frozenset[str]] = {}
    rows = result.get("candidate_group_player_ids")
    if not isinstance(rows, list):
        return out
    for row in rows:
        if not isinstance(row, dict):
            continue
        raw_path = row.get("path")
        raw_ids = row.get("player_ids")
        if not isinstance(raw_path, list) or not raw_path or not isinstance(raw_ids, list):
            continue
        try:
            path = tuple(int(v) for v in raw_path)
        except Exception:
            continue
        ids = frozenset(str(v).strip() for v in raw_ids if str(v).strip())
        if ids:
            out[path] = ids
    return out


def _read_state(
    cfg,
    receiver_auth: AuthRecord,
    *,
    timeout: float,
    preferred_path: tuple[int, ...] | None = None,
    anchors: set[str] | None = None,
) -> FriendState:
    result = list_friends(
        cfg=cfg,
        slot="R",
        auth=receiver_auth,
        timeout=timeout,
        live=True,
        capacity=300,
        include_player_ids=True,
    )
    if not bool(result.get("ok")):
        code = str(result.get("grpc_code") or result.get("error") or "FRIEND_LIST_FAILED")[:80]
        raise FriendFillError(code, "Receiver friend list request failed", retryable=True)
    mapping = _groups(result)
    confidence = str(result.get("parser_confidence") or "none").lower()
    if int(result.get("response_bytes") or 0) > 0 and not mapping and confidence == "none":
        raise FriendFillError("FRIEND_LIST_PARSE_FAILED", "Receiver friend list could not be parsed", retryable=True)

    pending = mapping.get(_PENDING_PATH, frozenset())
    candidates = [(path, ids) for path, ids in mapping.items() if path != _PENDING_PATH and path not in _IGNORED_PATHS]
    selected_path: tuple[int, ...] | None = None
    selected_ids: frozenset[str] = frozenset()

    if anchors:
        ranked = sorted(
            candidates,
            key=lambda item: (len(item[1].intersection(anchors)), len(item[1]), len(item[0])),
            reverse=True,
        )
        if ranked and len(ranked[0][1].intersection(anchors)) > 0:
            selected_path, selected_ids = ranked[0]
    if selected_path is None and preferred_path is not None and preferred_path in mapping and preferred_path != _PENDING_PATH and preferred_path not in _IGNORED_PATHS:
        selected_path = preferred_path
        selected_ids = mapping[preferred_path]
    if selected_path is None and candidates:
        selected_path, selected_ids = max(candidates, key=lambda item: (len(item[1]), len(item[0])))

    return FriendState(
        count=min(300, len(selected_ids)),
        ids=selected_ids,
        path=selected_path,
        pending_count=len(pending),
        pending_ids=pending,
    )


def _read_stable_state(
    cfg,
    receiver_auth: AuthRecord,
    *,
    timeout: float,
    preferred_path: tuple[int, ...] | None = None,
    anchors: set[str] | None = None,
    attempts: int = 5,
    delay: float = 0.35,
) -> FriendState:
    attempts = max(1, min(8, attempts))
    previous: FriendState | None = None
    last: FriendState | None = None
    for attempt in range(attempts):
        current = _read_state(
            cfg,
            receiver_auth,
            timeout=timeout,
            preferred_path=preferred_path,
            anchors=anchors,
        )
        last = current
        if previous is not None and previous.count == current.count and previous.path == current.path and previous.ids == current.ids:
            return current
        previous = current
        if attempt + 1 < attempts:
            time.sleep(delay)
    if last is None:
        raise FriendFillError("FRIEND_LIST_EMPTY_STATE", "Receiver friend state is unavailable", retryable=True)
    return last


def _lease_helpers(
    version: str,
    *,
    worker_code: str,
    sj_id: int,
    claim_token: str,
    api_key: str,
    count: int,
    existing_friend_ids: frozenset[str] = frozenset(),
) -> tuple[list[WaveSender], int]:
    raw_tokens = [secrets.token_urlsafe(32) for _ in range(count)]
    hashes = [hashlib.sha256(token.encode("utf-8")).hexdigest() for token in raw_tokens]
    payload: dict[str, Any] = {
        "worker_code": worker_code,
        "version": str(version or "")[:64],
        "sj_id": sj_id,
        "requested_count": count,
        "lease_token_hashes": hashes,
    }
    preferred = get_sender_session_pool().preferred_ids_excluding_mids(set(existing_friend_ids))
    if preferred:
        payload["preferred_sga_ids"] = preferred
    status, data = _request_json_retry(
        url=_lease_url(),
        api_key=api_key,
        claim_token=claim_token,
        payload=payload,
        timeout=20,
        attempts=3,
    )
    if not bool(data.get("ok")) or not (200 <= status < 300):
        raise FriendFillError(str(data.get("code") or "FRIEND_HELPER_LEASE_REJECTED"), str(data.get("message") or "Friend helper lease failed"), retryable=bool(data.get("retryable", True)))
    if not bool(data.get("leased")):
        raise FriendFillError(str(data.get("code") or "NO_READY_FRIEND_HELPER"), str(data.get("message") or "No friend helper is available"), retryable=bool(data.get("retryable", True)))
    batch_no = int(data.get("batch_no") or 0)
    rows = data.get("helpers")
    if batch_no < 1 or not isinstance(rows, list) or not rows:
        raise FriendFillError("FRIEND_HELPER_LEASE_RESPONSE_INVALID", "Friend helper lease response is invalid", retryable=True)
    works: list[WaveSender] = []
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
            raise FriendFillError("FRIEND_HELPER_LEASE_RESPONSE_INVALID", "Friend helper lease response is invalid", retryable=True)
        seen.add(sga_id)
        works.append(WaveSender(sga_id=sga_id, lease_token=raw_tokens[idx]))
    if not works:
        raise FriendFillError("NO_READY_FRIEND_HELPER", "No friend helper is available", retryable=True)
    return works, batch_no


def _fetch_credentials(
    version: str,
    *,
    worker_code: str,
    sj_id: int,
    claim_token: str,
    api_key: str,
    works: list[WaveSender],
) -> None:
    status, data = _request_json_retry(
        url=_credentials_url(),
        api_key=api_key,
        claim_token=claim_token,
        payload={
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "sj_id": sj_id,
            "helpers": [{"sga_id": w.sga_id, "lease_token": w.lease_token} for w in works],
        },
        timeout=30,
        attempts=3,
    )
    if not bool(data.get("ok")) or not (200 <= status < 300):
        raise FriendFillError(str(data.get("code") or "FRIEND_HELPER_CREDENTIAL_REJECTED"), str(data.get("message") or "Friend helper credential request failed"), retryable=bool(data.get("retryable", True)))
    rows = data.get("credentials")
    if not isinstance(rows, list):
        raise FriendFillError("FRIEND_HELPER_CREDENTIAL_RESPONSE_INVALID", "Friend helper credential response is invalid", retryable=True)
    by_id = {w.sga_id: w for w in works}
    for row in rows:
        if not isinstance(row, dict):
            continue
        try:
            sga_id = int(row.get("sga_id") or 0)
        except Exception:
            continue
        work = by_id.get(sga_id)
        if work is None:
            continue
        work.email = str(row.get("email") or "").strip()
        work.password = str(row.get("password") or "")
    if any((w.auth is None or w.session is None) and (not w.email or not w.password) for w in works):
        for work in works:
            work.password = ""
        raise FriendFillError("FRIEND_HELPER_CREDENTIAL_RESPONSE_INVALID", "One or more friend helper credentials are missing", retryable=True)


def _prepare_helpers(
    works: list[WaveSender],
    *,
    shard_pool: ElasticShardPool | None,
    shard_job_key: str,
    cfg,
    receiver_auth: AuthRecord,
    source_type: int,
    grpc_timeout: float,
    chunk_size: int,
    existing_friend_ids: frozenset[str],
    event_cb: Event | None,
) -> tuple[list[WaveSender], list[WaveSender]]:
    if not works:
        return [], []
    chunks = [works[i:i + chunk_size] for i in range(0, len(works), chunk_size)]
    add_ok_all: list[WaveSender] = []
    failed_all: list[WaveSender] = []
    lock = threading.RLock()

    def run_chunk(chunk_no: int, chunk: list[WaveSender]) -> None:
        def body(slot_no: int, allocation: int, active_jobs: int) -> None:
            _event(event_cb, f"FRIEND_FILL SHARD #{chunk_no} START execSlot={slot_no} size={len(chunk)} allocation={allocation} activeJobs={active_jobs} secretOutput=NONE")
            login_ok, login_failed = _login_senders(chunk, workers=len(chunk), event_cb=None, log_every=max(1, len(chunk)))
            for work in login_failed:
                work.outcome = "retryable_failure"
                work.error_code = work.error_code or "FRIEND_HELPER_LOGIN_FAILED"
                work.failure_stage = work.failure_stage or "LOGIN"

            add_ok: list[WaveSender] = []
            add_failed: list[WaveSender] = []
            already_friend: list[WaveSender] = []
            login_candidates: list[WaveSender] = []
            for work in login_ok:
                if work.mid and work.mid in existing_friend_ids:
                    work.outcome = "added"
                    work.error_code = ""
                    work.failure_stage = ""
                    already_friend.append(work)
                else:
                    login_candidates.append(work)

            if get_provider_guard().is_open():
                for work in login_candidates:
                    work.outcome = "retryable_failure"
                    work.error_code = "PROVIDER_IP_CIRCUIT_OPEN"
                    work.failure_stage = "LOGIN"
                    add_failed.append(work)
            elif login_candidates:
                def add_one(work: WaveSender) -> WaveSender:
                    try:
                        result = send_friend_request(
                            cfg=cfg,
                            slot="S",
                            auth=work.auth,
                            target_mid=receiver_auth.mid,
                            source_type=source_type,
                            timeout=grpc_timeout,
                            live=True,
                        )
                        work.steps["ADD"] = {"ok": bool(result.get("ok"))}
                        if bool(result.get("ok")):
                            work.error_code = ""
                            return work
                        work.error_code = str(result.get("grpc_code") or result.get("response_code") or result.get("error") or "FRIEND_ADD_FAILED")[:80]
                    except Exception as exc:
                        work.error_code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
                    work.failure_stage = "ADD"
                    return work

                with ThreadPoolExecutor(max_workers=len(login_candidates), thread_name_prefix="friend-add") as pool:
                    futures = {pool.submit(add_one, work): work for work in login_candidates}
                    for future in as_completed(futures):
                        work = future.result()
                        if work.error_code:
                            add_failed.append(work)
                        else:
                            add_ok.append(work)
            with lock:
                add_ok_all.extend(add_ok)
                failed_all.extend(login_failed)
                failed_all.extend(add_failed)
            shard_failed = login_failed + add_failed
            _event(event_cb, f"FRIEND_FILL SHARD #{chunk_no} DONE add={len(add_ok)}/{len(chunk)} already={len(already_friend)} failed={len(shard_failed)} failCodes={_failure_summary(shard_failed)} secretOutput=NONE")

        if shard_pool is not None and shard_job_key:
            with shard_pool.slot(shard_job_key) as lease:
                body(lease.slot_no, lease.allocation, lease.active_jobs)
        else:
            body(chunk_no, len(chunks), 1)

    with ThreadPoolExecutor(max_workers=max(1, min(len(chunks), shard_pool.total_slots if shard_pool is not None else len(chunks))), thread_name_prefix="friend-shard") as pool:
        futures = [pool.submit(run_chunk, i + 1, chunk) for i, chunk in enumerate(chunks)]
        for future in as_completed(futures):
            future.result()
    return add_ok_all, failed_all


def _refresh_cached_add_failures(
    works: list[WaveSender],
    *,
    version: str,
    worker_code: str,
    sj_id: int,
    claim_token: str,
    api_key: str,
    cfg,
    receiver_auth: AuthRecord,
    source_type: int,
    grpc_timeout: float,
    event_cb: Event | None,
) -> tuple[list[WaveSender], list[WaveSender]]:
    retryable = [
        work for work in works
        if work.failure_stage == "ADD"
        and work.steps.get("LOGIN_SOURCE") == "cache"
        and str(work.error_code or "").upper() not in {"PROVIDER_IP_CIRCUIT_OPEN", "PROVIDER_IP_LIMIT_SUSPECTED"}
    ]
    if not retryable:
        return [], works

    pool = get_sender_session_pool()
    for work in retryable:
        pool.invalidate(work.sga_id)
        work.auth = None
        work.session = None
        work.error_code = ""
        work.failure_stage = ""
        work.steps["LOGIN_SOURCE"] = "refresh_required"

    try:
        _fetch_credentials(
            version,
            worker_code=worker_code,
            sj_id=sj_id,
            claim_token=claim_token,
            api_key=api_key,
            works=retryable,
        )
    except Exception as exc:
        code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        for work in retryable:
            work.error_code = code
            work.failure_stage = "LOGIN"
        _event(event_cb, f"FRIEND_FILL CACHE REFRESH credentials=failed count={len(retryable)} code={code} secretOutput=NONE")
        return [], works

    login_ok, login_failed = _login_senders(
        retryable,
        workers=max(1, min(10, len(retryable))),
        event_cb=None,
        log_every=max(1, len(retryable)),
    )

    recovered: list[WaveSender] = []
    still_failed: list[WaveSender] = list(login_failed)

    def retry_add(work: WaveSender) -> WaveSender:
        try:
            result = send_friend_request(
                cfg=cfg,
                slot="S",
                auth=work.auth,
                target_mid=receiver_auth.mid,
                source_type=source_type,
                timeout=grpc_timeout,
                live=True,
            )
            if bool(result.get("ok")):
                work.error_code = ""
                work.failure_stage = ""
                work.steps["ADD_REFRESH_RETRY"] = {"ok": True}
                return work
            work.error_code = str(result.get("grpc_code") or result.get("response_code") or result.get("error") or "FRIEND_ADD_FAILED")[:80]
        except Exception as exc:
            work.error_code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        work.failure_stage = "ADD"
        work.steps["ADD_REFRESH_RETRY"] = {"ok": False}
        return work

    if login_ok:
        with ThreadPoolExecutor(max_workers=max(1, min(10, len(login_ok))), thread_name_prefix="friend-add-refresh") as executor:
            futures = [executor.submit(retry_add, work) for work in login_ok]
            for future in as_completed(futures):
                work = future.result()
                (recovered if not work.error_code else still_failed).append(work)

    retry_ids = {work.sga_id for work in retryable}
    untouched = [work for work in works if work.sga_id not in retry_ids]
    remaining = untouched + still_failed
    _event(
        event_cb,
        f"FRIEND_FILL CACHE REFRESH attempted={len(retryable)} recovered={len(recovered)} remaining={len(still_failed)} failCodes={_failure_summary(still_failed)} secretOutput=NONE",
    )
    return recovered, remaining


def _cleanup_pending_requests(
    cfg,
    receiver_auth: AuthRecord,
    pending_ids: frozenset[str],
    *,
    grpc_timeout: float,
    preferred_path: tuple[int, ...] | None,
    event_cb: Event | None,
) -> FriendState | None:
    if not pending_ids:
        return None
    current_pending = set(pending_ids)
    total_rejected = 0
    failures: Counter[str] = Counter()
    state: FriendState | None = None
    _event(event_cb, f"FRIEND_FILL PENDING CLEANUP start={len(current_pending)} secretOutput=NONE")
    for sweep in range(1, 4):
        if not current_pending:
            break
        sweep_rejected = 0
        unresolved_this_sweep: set[str] = set()
        for mid in sorted(current_pending):
            last_code = "FRIEND_PENDING_REJECT_FAILED"
            ok = False
            for attempt in range(1, 3):
                if attempt > 1:
                    time.sleep(0.20)
                try:
                    result = handle_friend_request(
                        cfg=cfg,
                        slot="R",
                        auth=receiver_auth,
                        target_mid=mid,
                        accept=False,
                        timeout=grpc_timeout,
                        live=True,
                    )
                    if bool(result.get("ok")):
                        ok = True
                        break
                    last_code = str(result.get("grpc_code") or result.get("response_code") or result.get("error") or last_code)[:80]
                except Exception as exc:
                    last_code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
            if ok:
                sweep_rejected += 1
                total_rejected += 1
            else:
                failures[last_code] += 1
                unresolved_this_sweep.add(mid)
        current_pending = unresolved_this_sweep
        try:
            state = _read_stable_state(
                cfg,
                receiver_auth,
                timeout=grpc_timeout,
                preferred_path=preferred_path,
                attempts=4,
                delay=0.30,
            )
            current_pending = set(state.pending_ids)
        except FriendFillError:
            pass
        _event(
            event_cb,
            f"FRIEND_FILL PENDING CLEANUP sweep={sweep}/3 rejected={sweep_rejected} remaining={len(current_pending)} secretOutput=NONE",
        )
        if current_pending and sweep < 3:
            time.sleep(0.35)
    fail_summary = "none" if not failures else ",".join(f"{code}:{count}" for code, count in failures.most_common(6))
    _event(
        event_cb,
        f"FRIEND_FILL PENDING CLEANUP done rejected={total_rejected} remaining={len(current_pending)} failCodes={fail_summary} secretOutput=NONE",
    )
    return state


def _accept_helpers(
    works: list[WaveSender],
    *,
    cfg,
    receiver_auth: AuthRecord,
    grpc_timeout: float,
    workers: int,
    attempts: int,
    event_cb: Event | None,
) -> tuple[list[WaveSender], list[WaveSender]]:
    if not works:
        return [], []
    accepted: list[WaveSender] = []
    failed: list[WaveSender] = []
    lock = threading.Lock()

    def one(work: WaveSender) -> WaveSender:
        last_code = "FRIEND_ACCEPT_FAILED"
        for attempt in range(1, attempts + 1):
            if attempt > 1:
                time.sleep(0.20 * attempt)
            try:
                result = handle_friend_request(
                    cfg=cfg,
                    slot="R",
                    auth=receiver_auth,
                    target_mid=work.mid,
                    accept=True,
                    timeout=grpc_timeout,
                    live=True,
                )
                if bool(result.get("ok")):
                    work.error_code = ""
                    work.steps["ACCEPT"] = {"ok": True}
                    return work
                last_code = str(result.get("grpc_code") or result.get("response_code") or result.get("error") or last_code)[:80]
            except Exception as exc:
                last_code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        work.error_code = last_code
        work.failure_stage = "ACCEPT"
        return work

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(works))), thread_name_prefix="friend-accept") as pool:
        futures = [pool.submit(one, work) for work in works]
        done = 0
        for future in as_completed(futures):
            work = future.result()
            done += 1
            with lock:
                (accepted if not work.error_code else failed).append(work)
            if done == len(works) or done % 10 == 0:
                _event(event_cb, f"FRIEND_FILL ACCEPT {done}/{len(works)} ok={len(accepted)} fail={len(failed)} secretOutput=NONE")
    return accepted, failed


def _report_batch(
    version: str,
    *,
    worker_code: str,
    sj_id: int,
    claim_token: str,
    api_key: str,
    batch_no: int,
    before_count: int,
    after_count: int,
    accepted_count: int,
    works: list[WaveSender],
    runtime_ms: int,
    pause_reason: str = "",
) -> dict[str, Any]:
    helpers = []
    for work in works:
        outcome = "added" if work.outcome == "added" else ("failed" if work.outcome == "failed" else "retryable")
        helpers.append({
            "sga_id": work.sga_id,
            "lease_token": work.lease_token,
            "outcome": outcome,
            "error_code": str(work.error_code or "")[:80],
            "failure_stage": str(work.failure_stage or "")[:32],
        })
    status, data = _request_json_retry(
        url=_result_url(),
        api_key=api_key,
        claim_token=claim_token,
        payload={
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "sj_id": sj_id,
            "batch_no": batch_no,
            "before_count": max(0, min(300, int(before_count))),
            "after_count": max(0, min(300, int(after_count))),
            "accepted_count": max(0, min(100, int(accepted_count))),
            "runtime_ms": max(0, int(runtime_ms)),
            "pause_reason": str(pause_reason or "")[:80],
            "helpers": helpers,
        },
        timeout=30,
        attempts=3,
    )
    if not bool(data.get("ok")) or not (200 <= status < 300):
        raise FriendFillError(str(data.get("code") or "FRIEND_BATCH_RESULT_REJECTED"), str(data.get("message") or "Friend batch result was rejected"), retryable=bool(data.get("retryable", True)))
    return data


def friend_fill_run(
    version: str,
    *,
    live: bool,
    event_cb: Event | None = None,
    stop_event: threading.Event | None = None,
    shard_pool: ElasticShardPool | None = None,
    shard_job_key: str = "",
) -> FriendFillResult:
    del live
    started = time.perf_counter()
    target = 300
    batch_size = _env_int("MWOIF_FRIEND_FILL_BATCH_SIZE", 100, 10, 100)
    chunk_size = _env_int("MWOIF_FRIEND_FILL_SHARD_CHUNK_SIZE", 10, 5, 20)
    accept_workers = _env_int("MWOIF_FRIEND_FILL_ACCEPT_WORKERS", 3, 1, 10)
    accept_attempts = _env_int("MWOIF_FRIEND_FILL_ACCEPT_ATTEMPTS", 3, 1, 4)
    grpc_timeout = _env_float("MWOIF_FRIEND_FILL_GRPC_TIMEOUT_SECONDS", 12.0, 3.0, 30.0)
    settle_attempts = _env_int("MWOIF_FRIEND_FILL_VERIFY_ATTEMPTS", 6, 2, 10)
    settle_delay = _env_float("MWOIF_FRIEND_FILL_VERIFY_DELAY_SECONDS", 0.45, 0.10, 2.0)
    max_no_progress = _env_int("MWOIF_FRIEND_FILL_MAX_NO_PROGRESS_BATCHES", 3, 2, 20)

    try:
        worker_code, sj_id, claim_token, api_key, cfg, receiver_auth, _receiver_session = _fetch_receiver_session(version, event_cb)
    except Exception as exc:
        code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        retryable = bool(getattr(exc, "retryable", True))
        return FriendFillResult(False, code, str(exc), retryable, (time.perf_counter() - started) * 1000.0)

    source_type = int(cfg.workflow.get("friend_source_type") or 2)
    try:
        state = _read_stable_state(cfg, receiver_auth, timeout=grpc_timeout, attempts=3, delay=0.30)
    except FriendFillError as exc:
        return FriendFillResult(False, exc.code, str(exc), exc.retryable, (time.perf_counter() - started) * 1000.0, sj_id=sj_id)

    start_progress = state.count
    progress = state.count
    friend_path = state.path
    batches = 0
    failed_total = 0
    added_total = 0
    no_progress = 0
    _event(event_cb, f"FRIEND_FILL START sj_id={sj_id} current={progress}/300 missing={max(0,300-progress)} pending={state.pending_count} secretOutput=NONE")

    if progress >= target:
        if state.pending_count > 0:
            cleaned_state = _cleanup_pending_requests(
                cfg,
                receiver_auth,
                state.pending_ids,
                grpc_timeout=grpc_timeout,
                preferred_path=friend_path,
                event_cb=event_cb,
            )
            if cleaned_state is not None:
                state = cleaned_state
                friend_path = state.path or friend_path
                progress = state.count
        try:
            report = _report_batch(
                version,
                worker_code=worker_code,
                sj_id=sj_id,
                claim_token=claim_token,
                api_key=api_key,
                batch_no=0,
                before_count=progress,
                after_count=progress,
                accepted_count=0,
                works=[],
                runtime_ms=int((time.perf_counter() - started) * 1000.0),
            )
            remote = report.get("job") if isinstance(report.get("job"), dict) else {}
            progress = int(remote.get("completed_value") or progress)
            _clear_claim_state(_claim_state_path())
            return FriendFillResult(True, "FRIEND_FILL_COMPLETED", "Friend list already reached 300/300", False, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, progress, target, 0, 0, 0)
        except Exception as exc:
            code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
            return FriendFillResult(False, code, str(exc), bool(getattr(exc, "retryable", True)), (time.perf_counter() - started) * 1000.0, sj_id, start_progress, progress, target)

    while progress < target:
        mode = str(getattr(stop_event, "mode", "") or "").lower()
        if stop_event is not None and stop_event.is_set():
            code = "FRIEND_FILL_CANCEL_SAFEPOINT" if mode == "cancel" else "FRIEND_FILL_PAUSE_SAFEPOINT"
            return FriendFillResult(False, code, "Friend fill stopped at a safe batch boundary", False, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, progress, target, added_total, batches, failed_total)

        try:
            live_before = _read_stable_state(
                cfg,
                receiver_auth,
                timeout=grpc_timeout,
                preferred_path=friend_path,
                attempts=3,
                delay=0.30,
            )
            friend_path = live_before.path or friend_path
            progress = live_before.count
        except FriendFillError as exc:
            return FriendFillResult(False, exc.code, str(exc), exc.retryable, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, progress, target, added_total, batches, failed_total)

        if progress >= target:
            if live_before.pending_count > 0:
                cleaned_state = _cleanup_pending_requests(
                    cfg,
                    receiver_auth,
                    live_before.pending_ids,
                    grpc_timeout=grpc_timeout,
                    preferred_path=friend_path,
                    event_cb=event_cb,
                )
                if cleaned_state is not None:
                    live_before = cleaned_state
                    friend_path = live_before.path or friend_path
                    progress = live_before.count
            try:
                report = _report_batch(version, worker_code=worker_code, sj_id=sj_id, claim_token=claim_token, api_key=api_key, batch_no=0, before_count=progress, after_count=progress, accepted_count=0, works=[], runtime_ms=int((time.perf_counter()-started)*1000.0))
                remote = report.get("job") if isinstance(report.get("job"), dict) else {}
                progress = int(remote.get("completed_value") or progress)
                _clear_claim_state(_claim_state_path())
                return FriendFillResult(True, "FRIEND_FILL_COMPLETED", "Friend list reached exactly 300/300", False, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, added_total, batches, failed_total)
            except Exception as exc:
                code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
                return FriendFillResult(False, code, str(exc), bool(getattr(exc, "retryable", True)), (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, added_total, batches, failed_total)

        wanted = _next_fill_wanted(progress, batch_size, target)
        batch_started = time.perf_counter()
        works: list[WaveSender] = []
        batch_no = 0
        try:
            works, batch_no = _lease_helpers(
                version,
                worker_code=worker_code,
                sj_id=sj_id,
                claim_token=claim_token,
                api_key=api_key,
                count=wanted,
                existing_friend_ids=live_before.ids,
            )
            _event(event_cb, f"FRIEND_FILL BATCH #{batch_no} LEASED {len(works)}/{wanted} before={progress}/300 secretOutput=NONE")
            _hydrate_cached_sender_sessions(works, event_cb=event_cb)
            credential_works = [w for w in works if w.auth is None or w.session is None]
            if credential_works:
                _fetch_credentials(version, worker_code=worker_code, sj_id=sj_id, claim_token=claim_token, api_key=api_key, works=credential_works)
        except (FriendFillError, HeartWaveError) as exc:
            code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
            retryable = bool(getattr(exc, "retryable", True))
            if works and batch_no > 0:
                for work in works:
                    work.outcome = "retryable_failure"
                    work.error_code = code
                    work.failure_stage = "CONTROL"
                try:
                    _report_batch(
                        version,
                        worker_code=worker_code,
                        sj_id=sj_id,
                        claim_token=claim_token,
                        api_key=api_key,
                        batch_no=batch_no,
                        before_count=progress,
                        after_count=progress,
                        accepted_count=0,
                        works=works,
                        runtime_ms=int((time.perf_counter() - batch_started) * 1000.0),
                    )
                except Exception as report_exc:
                    report_code = str(getattr(report_exc, "code", None) or type(report_exc).__name__)[:80]
                    return FriendFillResult(False, report_code, str(report_exc), True, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, added_total, batches, failed_total, True)
            return FriendFillResult(False, code, str(exc), retryable, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, added_total, batches, failed_total)

        add_ok, failed = _prepare_helpers(
            works,
            shard_pool=shard_pool,
            shard_job_key=shard_job_key,
            cfg=cfg,
            receiver_auth=receiver_auth,
            source_type=source_type,
            grpc_timeout=grpc_timeout,
            chunk_size=chunk_size,
            existing_friend_ids=live_before.ids,
            event_cb=event_cb,
        )
        refreshed_ok, failed = _refresh_cached_add_failures(
            failed,
            version=version,
            worker_code=worker_code,
            sj_id=sj_id,
            claim_token=claim_token,
            api_key=api_key,
            cfg=cfg,
            receiver_auth=receiver_auth,
            source_type=source_type,
            grpc_timeout=grpc_timeout,
            event_cb=event_cb,
        )
        if refreshed_ok:
            add_ok.extend(refreshed_ok)
        _invalidate_stale_cached_sender_sessions(failed, event_cb=event_cb)

        accepted, accept_failed = _accept_helpers(
            add_ok,
            cfg=cfg,
            receiver_auth=receiver_auth,
            grpc_timeout=grpc_timeout,
            workers=accept_workers,
            attempts=accept_attempts,
            event_cb=event_cb,
        )

        anchors = {work.mid for work in works if work.mid}
        try:
            live_after = _read_stable_state(
                cfg,
                receiver_auth,
                timeout=grpc_timeout,
                preferred_path=friend_path,
                anchors=anchors,
                attempts=settle_attempts,
                delay=settle_delay,
            )
            friend_path = live_after.path or friend_path
            if live_after.count >= target and live_after.pending_count > 0:
                cleaned_state = _cleanup_pending_requests(
                    cfg,
                    receiver_auth,
                    live_after.pending_ids,
                    grpc_timeout=grpc_timeout,
                    preferred_path=friend_path,
                    event_cb=event_cb,
                )
                if cleaned_state is not None:
                    live_after = cleaned_state
                    friend_path = live_after.path or friend_path
        except FriendFillError as exc:
            for work in works:
                if work.outcome != "added" and not work.error_code:
                    work.error_code = exc.code
                    work.failure_stage = "VERIFY"
            live_after = FriendState(progress, frozenset(), friend_path, 0, frozenset())

        for work in works:
            if work.mid and work.mid in live_after.ids:
                work.outcome = "added"
                work.error_code = ""
                work.failure_stage = ""
            elif work.error_code:
                work.outcome = "retryable_failure" if work.failure_stage in {"LOGIN", "ADD", "ACCEPT", "VERIFY"} else "failed"
            else:
                work.outcome = "retryable_failure"
                work.error_code = "FRIEND_NOT_VERIFIED"
                work.failure_stage = "VERIFY"

        pause_reason = ""
        if get_provider_guard().is_open():
            snapshot = get_provider_guard().snapshot()
            pause_reason = "PROVIDER_IP_LIMIT_SUSPECTED" if snapshot.distinct_accounts >= snapshot.threshold else "PROVIDER_IP_CIRCUIT_OPEN"
            for work in works:
                if work.outcome != "added" and work.failure_stage == "LOGIN":
                    work.error_code = pause_reason

        after_count = live_after.count
        accepted_count = len(accepted)
        try:
            report = _report_batch(
                version,
                worker_code=worker_code,
                sj_id=sj_id,
                claim_token=claim_token,
                api_key=api_key,
                batch_no=batch_no,
                before_count=progress,
                after_count=after_count,
                accepted_count=accepted_count,
                works=works,
                runtime_ms=int((time.perf_counter() - batch_started) * 1000.0),
                pause_reason=pause_reason,
            )
        except FriendFillError as exc:
            return FriendFillResult(False, exc.code, str(exc), exc.retryable, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, added_total, batches, failed_total, True)

        batches += 1
        failed_batch = sum(1 for work in works if work.outcome != "added")
        failed_total += failed_batch
        remote = report.get("job") if isinstance(report.get("job"), dict) else {}
        remote_progress = int(remote.get("completed_value") if remote.get("completed_value") is not None else after_count)
        remote_status = str(remote.get("status") or "claimed")
        added_batch = max(0, remote_progress - progress)
        added_total += added_batch
        _event(event_cb, f"FRIEND_FILL BATCH #{batch_no} DONE before={progress}/300 after={remote_progress}/300 added={added_batch} helpers={len(works)} failed={failed_batch} failCodes={_failure_summary([w for w in works if w.outcome != 'added'])} secretOutput=NONE")
        previous_progress = progress
        progress = remote_progress
        if progress > previous_progress and (progress % batch_size == 0 or progress >= target):
            _event(event_cb, f"FRIEND_FILL STEP COMPLETE boundary={progress}/300 secretOutput=NONE")

        for work in works:
            work.password = ""
            work.email = ""

        if remote_status == "completed" or progress >= target:
            try:
                _clear_claim_state(_claim_state_path())
            except Exception:
                pass
            _event(event_cb, f"FRIEND_FILL COMPLETE sj_id={sj_id} progress=300/300 batches={batches} secretOutput=NONE")
            return FriendFillResult(True, "FRIEND_FILL_COMPLETED", "Friend list reached exactly 300/300", False, (time.perf_counter()-started)*1000.0, sj_id, start_progress, 300, target, added_total, batches, failed_total)

        if remote_status == "paused" or pause_reason:
            try:
                _clear_claim_state(_claim_state_path())
            except Exception:
                pass
            return FriendFillResult(False, pause_reason or "FRIEND_FILL_PROVIDER_PAUSED", "Friend fill paused for Provider/IP recovery", True, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, added_total, batches, failed_total)

        if progress <= live_before.count:
            no_progress += 1
        else:
            no_progress = 0
        if no_progress >= max_no_progress:
            _event(event_cb, f"FRIEND_FILL STALL progress={progress}/300 noProgress={no_progress}/{max_no_progress} action=stop-retryable secretOutput=NONE")
            return FriendFillResult(False, "FRIEND_FILL_NO_PROGRESS_LIMIT", "Friend fill made no verified progress for too many batches", True, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, added_total, batches, failed_total)

    try:
        _clear_claim_state(_claim_state_path())
    except Exception:
        pass
    return FriendFillResult(True, "FRIEND_FILL_COMPLETED", "Friend list reached exactly 300/300", False, (time.perf_counter()-started)*1000.0, sj_id, start_progress, progress, target, added_total, batches, failed_total)
