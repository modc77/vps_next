from __future__ import annotations

import os
import threading
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from mwoif.friend.service import handle_friend_request, remove_friend
from mwoif_worker.claim import _clear_state as _clear_claim_state, _state_path as _claim_state_path
from mwoif_worker.friend_fill import FriendFillError, FriendState, _read_stable_state
from mwoif_worker.heart_wave import _fetch_receiver_session, _request_json_retry

Event = Callable[[str], None]


class FriendClearError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


@dataclass(slots=True)
class FriendClearResult:
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


def _result_url() -> str:
    explicit = str(os.getenv("MWOIF_WEB_FRIEND_CLEAR_RESULT_URL") or "").strip()
    if explicit:
        raw = explicit
    else:
        raw = str(os.getenv("MWOIF_WEB_JOB_CLAIM_URL") or "http://127.0.0.1/M_woif/work/jobs/claim.php").strip()
        parts = urlsplit(raw)
        path = parts.path or ""
        if not path.endswith("/work/jobs/claim.php"):
            raise FriendClearError("MWOIF_WEB_FRIEND_CLEAR_RESULT_URL_INVALID", "Friend clear result URL is unavailable", retryable=False)
        raw = urlunsplit((parts.scheme, parts.netloc, path[: -len("claim.php")] + "friend-clear-result.php", "", ""))
    parts = urlsplit(raw)
    host = (parts.hostname or "").lower()
    scheme = parts.scheme.lower()
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    if scheme not in {"http", "https"} or not host or not (parts.path or "").endswith("/work/jobs/friend-clear-result.php"):
        raise FriendClearError("MWOIF_WEB_FRIEND_CLEAR_RESULT_URL_INVALID", "Friend clear result URL is invalid", retryable=False)
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise FriendClearError("MWOIF_WEB_FRIEND_CLEAR_RESULT_URL_INVALID", "Friend clear result URL is invalid", retryable=False)
    if not loopback and scheme != "https":
        raise FriendClearError("MWOIF_WEB_FRIEND_CLEAR_RESULT_URL_HTTPS_REQUIRED", "Friend clear result URL must use HTTPS", retryable=False)
    return raw


def _report(
    version: str,
    *,
    worker_code: str,
    sj_id: int,
    claim_token: str,
    api_key: str,
    batch_no: int,
    initial_count: int,
    current_count: int,
    pending_count: int,
    runtime_ms: int,
    final: bool,
) -> dict[str, Any]:
    status, data = _request_json_retry(
        url=_result_url(),
        api_key=api_key,
        claim_token=claim_token,
        payload={
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "sj_id": sj_id,
            "batch_no": batch_no,
            "initial_count": initial_count,
            "current_count": current_count,
            "pending_count": pending_count,
            "runtime_ms": max(0, int(runtime_ms)),
            "final": bool(final),
        },
        timeout=30,
        attempts=3,
    )
    if not bool(data.get("ok")) or not (200 <= status < 300):
        raise FriendClearError(
            str(data.get("code") or "FRIEND_CLEAR_RESULT_REJECTED"),
            str(data.get("message") or "Friend clear result was rejected"),
            retryable=bool(data.get("retryable", True)),
        )
    return data


def _failure_code(result: dict[str, Any] | None) -> str:
    if not isinstance(result, dict):
        return "UNKNOWN"
    return str(result.get("grpc_code") or result.get("response_code") or result.get("error") or "UNKNOWN")[:80]


def _clear_pending(
    cfg,
    receiver_auth,
    state: FriendState,
    *,
    grpc_timeout: float,
    verify_attempts: int,
    verify_delay: float,
    event_cb: Event | None,
) -> FriendState:
    current = state
    if current.pending_count < 1:
        return current
    failures: Counter[str] = Counter()
    total = 0
    _event(event_cb, f"FRIEND_CLEAR PENDING CLEANUP start={current.pending_count} secretOutput=NONE")
    for sweep in range(1, 4):
        if current.pending_count < 1:
            break
        rejected = 0
        for mid in sorted(current.pending_ids):
            ok = False
            last_code = "FRIEND_PENDING_REJECT_FAILED"
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
                    last_code = _failure_code(result)
                except Exception as exc:
                    last_code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
            if ok:
                rejected += 1
                total += 1
            else:
                failures[last_code] += 1
        try:
            current = _read_stable_state(
                cfg,
                receiver_auth,
                timeout=grpc_timeout,
                preferred_path=current.path,
                attempts=verify_attempts,
                delay=verify_delay,
            )
        except FriendFillError as exc:
            raise FriendClearError(exc.code, str(exc), retryable=exc.retryable) from exc
        _event(event_cb, f"FRIEND_CLEAR PENDING CLEANUP sweep={sweep}/3 rejected={rejected} remaining={current.pending_count} secretOutput=NONE")
        if current.pending_count > 0 and sweep < 3:
            time.sleep(0.35)
    summary = "none" if not failures else ",".join(f"{code}:{count}" for code, count in failures.most_common(6))
    _event(event_cb, f"FRIEND_CLEAR PENDING CLEANUP done rejected={total} remaining={current.pending_count} failCodes={summary} secretOutput=NONE")
    if current.pending_count > 0:
        raise FriendClearError("FRIEND_CLEAR_PENDING_STALLED", "Pending friend requests could not be cleared", retryable=True)
    return current


def friend_clear_run(
    version: str,
    *,
    live: bool,
    event_cb: Event | None = None,
    stop_event: threading.Event | None = None,
) -> FriendClearResult:
    del live
    started = time.perf_counter()
    batch_size = _env_int("MWOIF_FRIEND_CLEAR_BATCH_SIZE", 100, 10, 100)
    grpc_timeout = _env_float("MWOIF_FRIEND_CLEAR_GRPC_TIMEOUT_SECONDS", 12.0, 3.0, 30.0)
    verify_attempts = _env_int("MWOIF_FRIEND_CLEAR_VERIFY_ATTEMPTS", 5, 2, 10)
    verify_delay = _env_float("MWOIF_FRIEND_CLEAR_VERIFY_DELAY_SECONDS", 0.35, 0.10, 2.0)
    max_retry = _env_int("MWOIF_FRIEND_CLEAR_REMOVE_ATTEMPTS", 3, 1, 3)

    try:
        worker_code, sj_id, claim_token, api_key, cfg, receiver_auth, _receiver_session = _fetch_receiver_session(version, event_cb)
    except Exception as exc:
        code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        return FriendClearResult(False, code, str(exc), bool(getattr(exc, "retryable", True)), (time.perf_counter() - started) * 1000.0)

    try:
        state = _read_stable_state(cfg, receiver_auth, timeout=grpc_timeout, attempts=3, delay=0.25)
    except FriendFillError as exc:
        return FriendClearResult(False, exc.code, str(exc), exc.retryable, (time.perf_counter() - started) * 1000.0, sj_id=sj_id)

    initial_count = state.count
    target_value = max(1, initial_count)
    batches = 0
    failed_attempts = 0
    removed_total = 0
    _event(event_cb, f"FRIEND_CLEAR START sj_id={sj_id} current={state.count}/300 pending={state.pending_count} secretOutput=NONE")

    try:
        sync = _report(
            version,
            worker_code=worker_code,
            sj_id=sj_id,
            claim_token=claim_token,
            api_key=api_key,
            batch_no=0,
            initial_count=initial_count,
            current_count=state.count,
            pending_count=state.pending_count,
            runtime_ms=int((time.perf_counter() - started) * 1000.0),
            final=False,
        )
        remote = sync.get("job") if isinstance(sync.get("job"), dict) else {}
        target_value = max(1, int(remote.get("target_value") or target_value))
    except Exception as exc:
        code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        return FriendClearResult(False, code, str(exc), bool(getattr(exc, "retryable", True)), (time.perf_counter() - started) * 1000.0, sj_id, 0, 0, target_value, 0, batches, failed_attempts, True)

    dynamic_chunk = batch_size
    while state.count > 0:
        mode = str(getattr(stop_event, "mode", "") or "").lower()
        if stop_event is not None and stop_event.is_set():
            code = "FRIEND_CLEAR_CANCEL_SAFEPOINT" if mode == "cancel" else "FRIEND_CLEAR_PAUSE_SAFEPOINT"
            progress = max(0, target_value - state.count)
            return FriendClearResult(False, code, "Friend clear stopped at a safe batch boundary", False, (time.perf_counter() - started) * 1000.0, sj_id, 0, progress, target_value, removed_total, batches, failed_attempts)

        before = state.count
        targets = sorted(state.ids)[: min(dynamic_chunk, before)]
        if not targets:
            return FriendClearResult(False, "FRIEND_CLEAR_IDS_MISSING", "Friend ids are unavailable for removal", True, (time.perf_counter() - started) * 1000.0, sj_id, 0, max(0, target_value-before), target_value, removed_total, batches, failed_attempts)

        batch_started = time.perf_counter()
        rpc_ok = False
        last_code = "FRIEND_REMOVE_FAILED"
        for attempt in range(1, max_retry + 1):
            try:
                result = remove_friend(
                    cfg=cfg,
                    slot="R",
                    auth=receiver_auth,
                    target_mids=targets,
                    timeout=grpc_timeout,
                    live=True,
                )
                rpc_ok = bool(result.get("ok"))
                last_code = "OK" if rpc_ok else _failure_code(result)
            except Exception as exc:
                rpc_ok = False
                last_code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
            if rpc_ok:
                break
            failed_attempts += 1
            if attempt < max_retry:
                time.sleep(0.20 * attempt)

        try:
            after = _read_stable_state(
                cfg,
                receiver_auth,
                timeout=grpc_timeout,
                preferred_path=state.path,
                attempts=verify_attempts,
                delay=verify_delay,
            )
        except FriendFillError as exc:
            return FriendClearResult(False, exc.code, str(exc), exc.retryable, (time.perf_counter() - started) * 1000.0, sj_id, 0, max(0, target_value-before), target_value, removed_total, batches, failed_attempts)

        removed = max(0, before - after.count)
        if removed < 1:
            failed_attempts += 1
            if dynamic_chunk > 1:
                dynamic_chunk = max(1, dynamic_chunk // 2)
                _event(event_cb, f"FRIEND_CLEAR RETRY before={before}/300 requested={len(targets)} rpcOk={str(rpc_ok).lower()} code={last_code} removed=0 nextChunk={dynamic_chunk} secretOutput=NONE")
                state = after
                continue
            return FriendClearResult(False, "FRIEND_CLEAR_NO_PROGRESS_LIMIT", f"Friend clear made no verified progress ({last_code})", True, (time.perf_counter() - started) * 1000.0, sj_id, 0, max(0, target_value-before), target_value, removed_total, batches, failed_attempts)

        batches += 1
        removed_total += removed
        state = after
        dynamic_chunk = batch_size
        _event(event_cb, f"FRIEND_CLEAR BATCH #{batches} DONE before={before}/300 requested={len(targets)} removed={removed} after={state.count}/300 rpcOk={str(rpc_ok).lower()} code={last_code} secretOutput=NONE")

        try:
            report = _report(
                version,
                worker_code=worker_code,
                sj_id=sj_id,
                claim_token=claim_token,
                api_key=api_key,
                batch_no=batches,
                initial_count=initial_count,
                current_count=state.count,
                pending_count=state.pending_count,
                runtime_ms=int((time.perf_counter() - batch_started) * 1000.0),
                final=False,
            )
            remote = report.get("job") if isinstance(report.get("job"), dict) else {}
            target_value = max(1, int(remote.get("target_value") or target_value))
        except Exception as exc:
            code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
            return FriendClearResult(False, code, str(exc), bool(getattr(exc, "retryable", True)), (time.perf_counter() - started) * 1000.0, sj_id, 0, max(0, target_value-state.count), target_value, removed_total, batches, failed_attempts, True)

    try:
        state = _clear_pending(
            cfg,
            receiver_auth,
            state,
            grpc_timeout=grpc_timeout,
            verify_attempts=verify_attempts,
            verify_delay=verify_delay,
            event_cb=event_cb,
        )
    except FriendClearError as exc:
        return FriendClearResult(False, exc.code, str(exc), exc.retryable, (time.perf_counter() - started) * 1000.0, sj_id, 0, target_value, target_value, removed_total, batches, failed_attempts)

    try:
        final_state = _read_stable_state(
            cfg,
            receiver_auth,
            timeout=grpc_timeout,
            preferred_path=state.path,
            attempts=verify_attempts,
            delay=verify_delay,
        )
    except FriendFillError as exc:
        return FriendClearResult(False, exc.code, str(exc), exc.retryable, (time.perf_counter() - started) * 1000.0, sj_id, 0, target_value, target_value, removed_total, batches, failed_attempts)

    if final_state.count != 0 or final_state.pending_count != 0:
        return FriendClearResult(False, "FRIEND_CLEAR_VERIFY_INCOMPLETE", "Friend clear final verification is incomplete", True, (time.perf_counter() - started) * 1000.0, sj_id, 0, max(0, target_value-final_state.count), target_value, removed_total, batches, failed_attempts)

    try:
        final = _report(
            version,
            worker_code=worker_code,
            sj_id=sj_id,
            claim_token=claim_token,
            api_key=api_key,
            batch_no=batches,
            initial_count=initial_count,
            current_count=0,
            pending_count=0,
            runtime_ms=int((time.perf_counter() - started) * 1000.0),
            final=True,
        )
        remote = final.get("job") if isinstance(final.get("job"), dict) else {}
        target_value = max(1, int(remote.get("target_value") or target_value))
    except Exception as exc:
        code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        return FriendClearResult(False, code, str(exc), bool(getattr(exc, "retryable", True)), (time.perf_counter() - started) * 1000.0, sj_id, 0, target_value, target_value, removed_total, batches, failed_attempts, True)

    try:
        _clear_claim_state(_claim_state_path())
    except Exception:
        pass
    _event(event_cb, f"FRIEND_CLEAR COMPLETE sj_id={sj_id} friends=0/300 pending=0 removed={removed_total} batches={batches} secretOutput=NONE")
    return FriendClearResult(True, "FRIEND_CLEAR_COMPLETED", "All friends and pending requests were cleared", False, (time.perf_counter() - started) * 1000.0, sj_id, 0, target_value, target_value, removed_total, batches, failed_attempts)
