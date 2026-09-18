from __future__ import annotations

import os
import signal
import threading
import time
from pathlib import Path
from typing import Callable

from mwoif.net.http_pool import reset_http_pools
from mwoif_worker.api_server import run_api
from mwoif_worker.claim import claim_once, clear_claim_state
from mwoif_worker.heartbeat import send_heartbeat
from mwoif_worker.control_request import process_control_request
from mwoif_worker.job_control import JobControlRegistry
from mwoif_worker.memory_guard import collect as memory_collect, policy_from_env as memory_policy_from_env, snapshot as memory_snapshot
from mwoif_worker.heart_wave import heart_wave_run
from mwoif_worker.friend_fill import friend_fill_run
from mwoif_worker.friend_clear import friend_clear_run
from mwoif_worker.process_lock import WorkerProcessLock, WorkerProcessLockError, worker_process_lock_path
from mwoif_worker.observability import OBSERVABILITY
from mwoif_worker.provider_guard import get_provider_guard
from mwoif_worker.provider_recovery import (
    provider_auto_recovery_enabled,
    provider_recovery_min_interval_seconds,
    run_provider_router_recovery,
)
from mwoif_worker.runtime_context import runtime_scope
from mwoif_worker.sender_session_pool import get_login_circuit
from mwoif_worker.shard_scheduler import ElasticShardPool
from mwoif_worker.startup_recovery import recover_worker_startup

Event = Callable[[str], None]

class _LongRunPoolGuard:
    def __init__(self, idle_seconds: int, max_age_seconds: int, *, reset_cb=reset_http_pools, clock=time.monotonic) -> None:
        self._idle_seconds = max(1, int(idle_seconds))
        self._max_age_seconds = max(self._idle_seconds, int(max_age_seconds))
        self._reset_cb = reset_cb
        self._clock = clock
        self._lock = threading.RLock()
        now = float(self._clock())
        self._active = 0
        self._idle_since = now
        self._last_recycle = now
        self._force_reason = ""

    def before_job(self) -> dict[str, object]:
        with self._lock:
            now = float(self._clock())
            idle_for = max(0.0, now - self._idle_since) if self._active == 0 else 0.0
            age = max(0.0, now - self._last_recycle)
            reason = ""
            if self._active == 0:
                if self._force_reason:
                    reason = self._force_reason
                elif idle_for >= self._idle_seconds:
                    reason = "idle"
                elif age >= self._max_age_seconds:
                    reason = "age"
                if reason:
                    self._reset_cb()
                    self._last_recycle = now
                    self._force_reason = ""
            self._active += 1
            return {
                "recycled": bool(reason),
                "reason": reason,
                "idle_seconds": idle_for,
                "age_seconds": age,
                "active_jobs": self._active,
            }

    def after_job(self, code: str = "") -> dict[str, object]:
        with self._lock:
            now = float(self._clock())
            self._active = max(0, self._active - 1)
            if str(code or "") == "INITMEMBER3_FAILED":
                self._force_reason = "initmember3-failed"
            if self._active == 0:
                self._idle_since = now
            return {
                "active_jobs": self._active,
                "force_reason": self._force_reason,
            }

    def active_jobs(self) -> int:
        with self._lock:
            return int(self._active)


def _event(cb: Event | None, text: str) -> None:
    if cb:
        cb(text)


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(str(os.getenv(name) or default).strip())
    except Exception:
        value = default
    return max(lo, min(hi, value))


def worker_service_run(version: str, *, event_cb: Event | None = None) -> int:
    drain_event = threading.Event()
    shutdown_event = threading.Event()
    control_registry = JobControlRegistry(drain_event)
    memory_recycle_event = threading.Event()
    stop_event = shutdown_event
    poll_seconds = _env_int("MWOIF_WORKER_SERVICE_POLL_SECONDS", 3, 2, 30)
    heartbeat_seconds = _env_int("MWOIF_HEARTBEAT_INTERVAL_SECONDS", 30, 10, 300)
    concurrent_jobs = _env_int("MWOIF_WORKER_CONCURRENT_JOBS", 10, 1, 64)
    control_runners = _env_int("MWOIF_WORKER_CONTROL_RUNNERS", 3, 1, 4)
    control_poll_ms = _env_int("MWOIF_WORKER_CONTROL_POLL_MS", 1000, 750, 5000)
    total_shard_slots = _env_int("MWOIF_HEART_TOTAL_SHARD_SLOTS", 10, 1, 64)
    pool_idle_recycle_seconds = _env_int("MWOIF_HTTP_POOL_IDLE_RECYCLE_SECONDS", 15, 5, 3600)
    pool_max_age_seconds = _env_int("MWOIF_HTTP_POOL_MAX_AGE_SECONDS", 600, 30, 86400)
    drain_warn_seconds = _env_int("MWOIF_WORKER_DRAIN_WARN_SECONDS", 120, 30, 900)
    shard_pool = ElasticShardPool(total_shard_slots)
    OBSERVABILITY.configure(runners=concurrent_jobs, shard_slots=total_shard_slots)
    longrun_pool_guard = _LongRunPoolGuard(pool_idle_recycle_seconds, pool_max_age_seconds)
    output_lock = threading.Lock()
    runner_threads: list[threading.Thread] = []
    control_threads: list[threading.Thread] = []
    claim_gate = threading.Lock()
    control_claim_gate = threading.Lock()
    claim_pace_lock = threading.Lock()
    heart_next_claim_at = 0.0
    control_next_claim_at = 0.0
    safety_holds: set[int] = set()
    safety_lock = threading.Lock()
    process_lock = WorkerProcessLock(worker_process_lock_path(Path(__file__).resolve().parents[1]))
    claim_health_lock = threading.Lock()
    claim_failure_streak = 0
    claim_backoff_until = 0.0
    web_link_lock = threading.Lock()
    web_link_degraded = False
    web_link_reason = ""

    def claim_backoff_wait() -> float:
        with claim_health_lock:
            return max(0.0, claim_backoff_until - time.monotonic())

    def claim_health(code: str, ok: bool) -> None:
        nonlocal claim_failure_streak, claim_backoff_until
        bad = str(code or "") in {
            "CLAIM_NETWORK_ERROR",
            "CLAIM_RESPONSE_INVALID",
            "CLAIM_ACCESS_DENIED",
            "CLAIM_HTTP_ERROR",
            "CLAIM_STATE_IO_ERROR",
        }
        with claim_health_lock:
            if ok or not bad:
                claim_failure_streak = 0
                claim_backoff_until = 0.0
                return
            claim_failure_streak = min(8, claim_failure_streak + 1)
            delay = float(min(30, max(3, 2 ** max(1, claim_failure_streak))))
            claim_backoff_until = max(claim_backoff_until, time.monotonic() + delay)

    def paced_claim(lane: str):
        nonlocal heart_next_claim_at, control_next_claim_at
        if lane == "control":
            gate = control_claim_gate
            idle_interval = max(0.10, control_poll_ms / 1000.0)
        else:
            gate = claim_gate
            idle_interval = float(max(1, poll_seconds))

        with gate:
            now = time.monotonic()
            with claim_pace_lock:
                next_at = control_next_claim_at if lane == "control" else heart_next_claim_at
                if now < next_at:
                    return None, max(0.01, next_at - now)

            result = claim_once(version, lane)
            now = time.monotonic()
            with claim_pace_lock:
                server_wait = max(0.0, float(result.next_poll_ms or 0) / 1000.0)
                if result.ok and result.claimed:
                    next_at = now
                elif result.ok and not result.claimed:
                    next_at = now + max(idle_interval, server_wait)
                else:
                    next_at = now + max(min(3.0, idle_interval), server_wait)

                if lane == "control":
                    control_next_claim_at = next_at
                else:
                    heart_next_claim_at = next_at
            return result, 0.0

    def emit(text: str) -> None:
        # Three Heart engines can emit at the same time. Keep every event as one
        # complete line so production logs remain readable and secret-safe.
        with output_lock:
            _event(event_cb, text)

    def web_link_pause(reason: str) -> None:
        nonlocal web_link_degraded, web_link_reason
        reason = str(reason or "network")[:80]
        with web_link_lock:
            if web_link_degraded and web_link_reason == reason:
                return
            first = not web_link_degraded
            web_link_degraded = True
            web_link_reason = reason
        if first:
            emit(
                f"WORKER WEB LINK PAUSED reason={reason} mode=backoff-no-spam "
                "requests=paused-until-retry secretOutput=NONE"
            )

    def web_link_ok() -> None:
        nonlocal web_link_degraded, web_link_reason
        with web_link_lock:
            was_degraded = web_link_degraded
            web_link_degraded = False
            web_link_reason = ""
        if was_degraded:
            emit("WORKER WEB LINK RECOVERED protocol=signed-v3 secretOutput=NONE")

    def _provider_runtime_rearm() -> None:
        nonlocal claim_failure_streak, claim_backoff_until, heart_next_claim_at, control_next_claim_at
        with claim_health_lock:
            claim_failure_streak = 0
            claim_backoff_until = 0.0
        with claim_pace_lock:
            heart_next_claim_at = 0.0
            control_next_claim_at = 0.0
        web_link_ok()

    def admin_resume_rearm(job_id: int) -> None:
        _provider_runtime_rearm()
        emit(
            f"P6.2 PROVIDER RESUME ARMED sj_id={int(job_id)} claimBackoff=cleared "
            "newClaims=true secretOutput=NONE"
        )

    def provider_auto_recovery_thread() -> None:
        if not provider_auto_recovery_enabled():
            return
        last_incident = 0
        last_attempt_at = 0.0
        wait_logged_incident = 0
        min_interval = provider_recovery_min_interval_seconds()
        while not drain_event.wait(1.0):
            guard = get_provider_guard()
            if not guard.is_open():
                wait_logged_incident = 0
                continue
            snapshot = guard.snapshot()
            incident = int(snapshot.opened_at_unix or 0)
            if incident < 1 or incident == last_incident:
                continue
            active_jobs = longrun_pool_guard.active_jobs()
            if active_jobs > 0:
                if wait_logged_incident != incident:
                    emit(
                        f"P6.2 AUTO ROUTER RECOVERY WAIT safeBoundary=false activeJobs={active_jobs} "
                        "secretOutput=NONE"
                    )
                    wait_logged_incident = incident
                continue
            since_last = time.monotonic() - last_attempt_at if last_attempt_at > 0 else float(min_interval)
            if since_last < float(min_interval):
                if wait_logged_incident != -incident:
                    emit(
                        f"P6.2 AUTO ROUTER RECOVERY HOLD cooldown={int(max(1.0, min_interval-since_last))}s "
                        "providerHold=true secretOutput=NONE"
                    )
                    wait_logged_incident = -incident
                continue

            last_incident = incident
            last_attempt_at = time.monotonic()
            emit(
                f"P6.2 AUTO ROUTER RECOVERY START distinct={snapshot.distinct_accounts}/{snapshot.threshold} "
                f"primary={snapshot.primary_code or 'UNKNOWN'} safeBoundary=true secretOutput=NONE"
            )
            result = run_provider_router_recovery(version, snapshot, event_cb=emit)
            if not result.ok:
                emit(
                    f"P6.2 AUTO ROUTER RECOVERY FAIL code={result.code} providerHold=true "
                    f"elapsed={result.elapsed_ms/1000:.2f}s secretOutput=NONE"
                )
                continue

            guard.reset()
            get_login_circuit().reset()
            reset_http_pools()
            _provider_runtime_rearm()
            emit(
                f"P6.2 AUTO ROUTER RECOVERY DONE resumedJobs={result.resumed_jobs} "
                f"elapsed={result.elapsed_ms/1000:.2f}s newClaims=true secretOutput=NONE"
            )

    def claim_is_link_problem(claim) -> bool:
        return str(getattr(claim, "code", "") or "") in {
            "CLAIM_NETWORK_ERROR",
            "CLAIM_RESPONSE_INVALID",
            "CLAIM_ACCESS_DENIED",
            "CLAIM_HTTP_ERROR",
        }

    # Ctrl+C / SIGTERM become a graceful stop request. Every P7.3.4 engine
    # observes the shared stop event only at safe batch boundaries.
    old_handlers: dict[int, object] = {}

    def request_stop(signum, _frame) -> None:  # type: ignore[no-untyped-def]
        if not drain_event.is_set():
            emit(f"P9 WORKER DRAIN REQUEST signal={signum} waiting-for-safe-batch-boundary newClaims=false activeBatches=finish-current secretOutput=NONE")
        OBSERVABILITY.set_draining(True)
        drain_event.set()

    for sig in (signal.SIGINT, getattr(signal, "SIGTERM", signal.SIGINT)):
        try:
            old_handlers[int(sig)] = signal.getsignal(sig)
            signal.signal(sig, request_stop)
        except Exception:
            pass

    def api_thread() -> None:
        try:
            run_api()
        except Exception:
            emit("WORKER SERVICE P1 API FAIL bind/start error secretOutput=NONE")

    def heartbeat_thread(initial_wait: int) -> None:
        if stop_event.wait(max(10, min(300, initial_wait))):
            return
        while not stop_event.is_set():
            try:
                result = send_heartbeat(version)
            except Exception:
                web_link_pause("heartbeat-network")
                stop_event.wait(min(heartbeat_seconds * 2, 60))
                continue
            if result.ok:
                worker = result.worker or {}
                emit(
                    f"WORKER SERVICE HEARTBEAT online active={worker.get('active_jobs',0)}/{worker.get('capacity',0)} "
                    f"runners={concurrent_jobs} secretOutput=NONE"
                )
                interval = int(result.heartbeat_interval_seconds or heartbeat_seconds)
            else:
                if result.code in {"HEARTBEAT_NETWORK_ERROR", "HEARTBEAT_RESPONSE_INVALID", "HEARTBEAT_ACCESS_DENIED", "HEARTBEAT_HTTP_ERROR"}:
                    web_link_pause(str(result.code).lower())
                else:
                    web_link_pause("heartbeat-auth")
                interval = min(heartbeat_seconds * 2, 60)
            stop_event.wait(max(10, min(300, interval)))

    try:
        memory_initial = memory_snapshot()
        memory_policy = memory_policy_from_env(memory_initial)
    except Exception:
        memory_initial = None
        memory_policy = None

    def memory_guard_thread() -> None:
        if memory_policy is None:
            emit("P8.2.5 MEMORY GUARD DISABLED reason=platform-probe-failed secretOutput=NONE")
            return
        emit(
            f"P8.2.5 MEMORY GUARD READY soft={memory_policy.soft_rss_mb}MB "
            f"hard={memory_policy.hard_rss_mb}MB minFree={memory_policy.min_free_mb}MB "
            f"interval={memory_policy.interval_seconds}s secretOutput=NONE"
        )
        soft_latched = False
        while not shutdown_event.wait(memory_policy.interval_seconds):
            try:
                snap = memory_snapshot()
            except Exception:
                continue

            low_system = snap.available_mb > 0 and snap.available_mb <= memory_policy.min_free_mb
            hard_process = snap.rss_mb > 0 and snap.rss_mb >= memory_policy.hard_rss_mb
            soft_process = snap.rss_mb > 0 and snap.rss_mb >= memory_policy.soft_rss_mb

            if hard_process or low_system:
                reason = "process-hard" if hard_process else "system-low-free"
                emit(
                    f"P8.2.5 MEMORY RECYCLE REQUEST reason={reason} rss={snap.rss_mb:.0f}MB "
                    f"free={snap.available_mb:.0f}MB active={longrun_pool_guard.active_jobs()} "
                    "policy=graceful-drain-then-restart secretOutput=NONE"
                )
                memory_recycle_event.set()
                OBSERVABILITY.set_draining(True)
                drain_event.set()
                return

            if soft_process:
                memory_collect()
                if not soft_latched:
                    emit(
                        f"P8.2.5 MEMORY SOFT GC rss={snap.rss_mb:.0f}MB free={snap.available_mb:.0f}MB "
                        f"active={longrun_pool_guard.active_jobs()} secretOutput=NONE"
                    )
                    soft_latched = True
            elif soft_latched and snap.rss_mb < memory_policy.soft_rss_mb * 0.85:
                soft_latched = False

    def hold_runner(runner_no: int, *, sj_id: object, code: str) -> None:
        with safety_lock:
            safety_holds.add(runner_no)
        OBSERVABILITY.set_safety_hold(runner_no, True)
        emit(
            f"P8 RUNTIME #{runner_no} WORKER SERVICE SAFETY HOLD sj_id={sj_id} code={code} "
            "runtime-isolated=true other-runtimes-continue=true operator-review-required secretOutput=NONE"
        )
        # Keep this runtime occupied instead of accidentally claiming another
        # job. The ambiguous claim/state remains available for recovery after a
        # clean operator restart; unrelated runtimes may continue working.
        while not drain_event.wait(1.0):
            pass

    def control_runner(control_no: int) -> None:
        runtime_id = f"control-{control_no:02d}"
        with runtime_scope(runtime_id):
            emit(f"P8.2.6 CONTROL LANE #{control_no} READY runtime={runtime_id} secretOutput=NONE")
            while not drain_event.is_set():
                backoff = claim_backoff_wait()
                if backoff > 0:
                    drain_event.wait(min(8.0, backoff))
                    continue
                try:
                    claim, pace_wait = paced_claim("control")
                    if claim is None:
                        drain_event.wait(min(max(0.01, pace_wait), max(0.25, control_poll_ms / 1000.0)))
                        continue
                    claim_health(claim.code, claim.ok)
                    pool_state = longrun_pool_guard.before_job() if claim.ok and claim.claimed else None
                except Exception:
                    claim_health("CLAIM_RESPONSE_INVALID", False)
                    web_link_pause("claim-response")
                    drain_event.wait(max(1.0, claim_backoff_wait()))
                    continue

                if claim.ok and not claim.claimed:
                    idle_wait = max(control_poll_ms / 1000.0, float(claim.next_poll_ms or 0) / 1000.0)
                    drain_event.wait(idle_wait)
                    continue
                if not claim.ok:
                    if claim_is_link_problem(claim):
                        web_link_pause(str(claim.code).lower())
                        drain_event.wait(max(1.0, claim_backoff_wait(), float(claim.next_poll_ms or 0) / 1000.0))
                        continue
                    web_link_pause("claim-auth")
                    drain_event.wait(max(30.0, float(claim.next_poll_ms or 0) / 1000.0))
                    continue
                web_link_ok()
                if not claim.claimed:
                    drain_event.wait(max(0.25, control_poll_ms / 1000.0))
                    continue

                job = claim.job or {}
                work_type = str(job.get("work_type") or "").upper()
                supported_controls = {
                    "DEVPLAY_CHECK", "RECEIVER_CAPACITY_PREP", "JOB_PAUSE", "JOB_RESUME", "JOB_CANCEL",
                    "ACCOUNT_SESSION_PURGE", "ACCOUNT_LOGIN_CHECK", "WORKER_DRAIN",
                }
                if work_type not in supported_controls:
                    clear_claim_state()
                    if isinstance(pool_state, dict):
                        longrun_pool_guard.after_job("CONTROL_LANE_PROTOCOL_ERROR")
                    emit(
                        f"P11 CONTROL LANE #{control_no} FAIL code=CONTROL_LANE_PROTOCOL_ERROR "
                        "secretOutput=NONE"
                    )
                    drain_event.wait(1.0)
                    continue

                wcr_id = job.get("wcr_id")
                emit(
                    f"P11 CONTROL START lane={control_no} wcr_id={wcr_id} "
                    f"type={work_type} secretOutput=NONE"
                )
                try:
                    control = process_control_request(
                        version,
                        job,
                        str(claim.claim_token or ""),
                        registry=control_registry,
                        drain_event=drain_event,
                        event_cb=emit,
                        resume_hook=admin_resume_rearm,
                    )
                except Exception:
                    control = None

                if control is not None and control.committed:
                    clear_claim_state()
                    longrun_pool_guard.after_job(control.result_code or control.code)
                    emit(
                        f"P11 CONTROL DONE lane={control_no} wcr_id={wcr_id} "
                        f"result={control.result_code} elapsed={control.elapsed_ms/1000:.2f}s secretOutput=NONE"
                    )
                    drain_event.wait(0.05)
                    continue

                failure_code = control.code if control is not None else "CONTROL_UNHANDLED_ERROR"
                retryable = bool(control.retryable) if control is not None else True
                longrun_pool_guard.after_job(failure_code)
                emit(
                    f"P11 CONTROL FAIL lane={control_no} wcr_id={wcr_id} "
                    f"code={failure_code} retryable={str(retryable).lower()} secretOutput=NONE"
                )
                if not retryable:
                    clear_claim_state()
                drain_event.wait(0.50 if retryable else 0.10)

    def job_runner(runner_no: int) -> None:
        runtime_id = f"runtime-{runner_no:02d}"
        with runtime_scope(runtime_id):
            emit(f"P8 RUNTIME #{runner_no} READY runtime={runtime_id} state=isolated secretOutput=NONE")
            provider_hold_logged = False
            while not drain_event.is_set():
                provider_guard = get_provider_guard()
                if provider_guard.is_open():
                    if not provider_hold_logged:
                        snapshot = provider_guard.snapshot()
                        emit(
                            f"P6.2 PROVIDER HOLD runtime={runner_no} distinct={snapshot.distinct_accounts}/"
                            f"{snapshot.threshold} newClaims=false controlLane=active secretOutput=NONE"
                        )
                        provider_hold_logged = True
                    drain_event.wait(2.0)
                    continue
                provider_hold_logged = False
                backoff = claim_backoff_wait()
                if backoff > 0:
                    drain_event.wait(min(8.0, backoff))
                    continue
                try:
                    claim, pace_wait = paced_claim("heart")
                    if claim is None:
                        drain_event.wait(min(max(0.01, pace_wait), float(max(1, poll_seconds))))
                        continue
                    claim_health(claim.code, claim.ok)
                    pool_state = longrun_pool_guard.before_job() if claim.ok and claim.claimed else None
                except Exception:
                    claim_health("CLAIM_RESPONSE_INVALID", False)
                    web_link_pause("claim-response")
                    drain_event.wait(max(1.0, claim_backoff_wait()))
                    continue

                if claim.ok and not claim.claimed:
                    idle_wait = max(float(poll_seconds), float(claim.next_poll_ms or 0) / 1000.0)
                    drain_event.wait(idle_wait)
                    continue
                if not claim.ok:
                    if claim_is_link_problem(claim):
                        web_link_pause(str(claim.code).lower())
                        drain_event.wait(max(1.0, claim_backoff_wait(), float(claim.next_poll_ms or 0) / 1000.0))
                        continue
                    web_link_pause("claim-auth")
                    drain_event.wait(max(30.0, float(claim.next_poll_ms or 0) / 1000.0))
                    continue
                web_link_ok()
                if not claim.claimed:
                    drain_event.wait(poll_seconds)
                    continue

                job = claim.job or {}
                sj_id = job.get("sj_id")
                slot_no = job.get("slot_no")
                if isinstance(pool_state, dict) and bool(pool_state.get("recycled")):
                    OBSERVABILITY.pool_recycled()
                    emit(
                        f"P8.2.4 LONGRUN HTTP POOL RECYCLE reason={pool_state.get('reason')} "
                        f"idle={float(pool_state.get('idle_seconds') or 0.0):.1f}s "
                        f"age={float(pool_state.get('age_seconds') or 0.0):.1f}s secretOutput=NONE"
                    )

                if str(job.get("work_type") or "").upper() in {"DEVPLAY_CHECK", "RECEIVER_CAPACITY_PREP"}:
                    wcr_id = job.get("wcr_id")
                    fallback_control_type = str(job.get("work_type") or "").upper()
                    emit(
                        f"P8.2.5 CONTROL START runtime={runner_no} wcr_id={wcr_id} "
                        f"type={fallback_control_type} secretOutput=NONE"
                    )
                    try:
                        control = process_control_request(
                            version,
                            job,
                            str(claim.claim_token or ""),
                            event_cb=emit,
                            resume_hook=admin_resume_rearm,
                        )
                    except Exception:
                        control = None
                    if control is not None and control.committed:
                        clear_claim_state()
                        longrun_pool_guard.after_job(control.result_code or control.code)
                        emit(
                            f"P8.2.5 CONTROL DONE runtime={runner_no} wcr_id={wcr_id} "
                            f"result={control.result_code} elapsed={control.elapsed_ms/1000:.2f}s secretOutput=NONE"
                        )
                        drain_event.wait(0.15)
                        continue

                    failure_code = control.code if control is not None else "CONTROL_UNHANDLED_ERROR"
                    retryable = bool(control.retryable) if control is not None else True
                    longrun_pool_guard.after_job(failure_code)
                    emit(
                        f"P8.2.5 CONTROL FAIL runtime={runner_no} wcr_id={wcr_id} "
                        f"code={failure_code} retryable={str(retryable).lower()} secretOutput=NONE"
                    )
                    # Keep the exact claim token state on retryable failures so the next
                    # claim recovers the same control request instead of duplicating it.
                    if not retryable:
                        clear_claim_state()
                    drain_event.wait(1.0 if retryable else 0.25)
                    continue

                def runtime_event(text: str) -> None:
                    emit(f"P8 RUNTIME #{runner_no} SLOT={slot_no} | {text}")

                OBSERVABILITY.job_started()
                emit(
                    f"P8 RUNTIME #{runner_no} JOB START slot={slot_no} sj_id={sj_id} "
                    f"target={job.get('target_value')} progress={job.get('completed_value')} secretOutput=NONE"
                )
                shard_job_key = f"sj-{sj_id}"
                shard_pool.register(shard_job_key)
                alloc = shard_pool.snapshot(shard_job_key)
                emit(
                    f"P8.1 RUNTIME #{runner_no} SHARD POOL REGISTER sj_id={sj_id} "
                    f"allocation={alloc['allocation']}/{total_shard_slots} activeJobs={alloc['active_jobs']} secretOutput=NONE"
                )
                job_control_signal = control_registry.register(sj_id, runner_no)
                service_code = str(job.get("service_code") or "").upper()
                try:
                    if service_code == "FRIEND_FILL_300":
                        result = friend_fill_run(
                            version,
                            live=True,
                            event_cb=runtime_event,
                            stop_event=job_control_signal,
                            shard_pool=shard_pool,
                            shard_job_key=shard_job_key,
                        )
                    elif service_code == "FRIEND_CLEAR":
                        result = friend_clear_run(
                            version,
                            live=True,
                            event_cb=runtime_event,
                            stop_event=job_control_signal,
                        )
                    else:
                        result = heart_wave_run(
                            version,
                            live=True,
                            event_cb=runtime_event,
                            stop_event=job_control_signal,
                            shard_pool=shard_pool,
                            shard_job_key=shard_job_key,
                        )
                except Exception as exc:
                    control_registry.unregister(sj_id)
                    shard_pool.unregister(shard_job_key)
                    longrun_pool_guard.after_job(str(getattr(exc, "code", None) or type(exc).__name__)[:80])
                    OBSERVABILITY.job_finished(completed=False)
                    emit(
                        f"P8.1 RUNTIME #{runner_no} SHARD POOL RELEASE sj_id={sj_id} reason=exception secretOutput=NONE"
                    )
                    safe_code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
                    hold_runner(runner_no, sj_id=sj_id, code=f"UNHANDLED_JOB_ERROR/{safe_code}")
                    return

                shard_pool.unregister(shard_job_key)
                longrun_pool_guard.after_job(str(result.code or ""))
                emit(
                    f"P8.1 RUNTIME #{runner_no} SHARD POOL RELEASE sj_id={sj_id} reason=job-boundary secretOutput=NONE"
                )

                if str(result.code or "") in {
                    "HEART_WAVE_PAUSE_SAFEPOINT",
                    "HEART_WAVE_CANCEL_SAFEPOINT",
                    "FRIEND_FILL_PAUSE_SAFEPOINT",
                    "FRIEND_FILL_CANCEL_SAFEPOINT",
                    "FRIEND_CLEAR_PAUSE_SAFEPOINT",
                    "FRIEND_CLEAR_CANCEL_SAFEPOINT",
                }:
                    mode = "pause" if "PAUSE" in str(result.code or "") else "cancel"
                    emit(
                        f"P11 RUNTIME #{runner_no} CONTROL HOLD sj_id={sj_id} mode={mode} "
                        "safe=true waitingApply=true secretOutput=NONE"
                    )
                    applied = job_control_signal.wait_applied(45.0)
                    clear_claim_state()
                    control_registry.unregister(sj_id)
                    OBSERVABILITY.job_finished(completed=False)
                    if not applied:
                        emit(
                            f"P11 RUNTIME #{runner_no} CONTROL APPLY TIMEOUT sj_id={sj_id} mode={mode} "
                            "secretOutput=NONE"
                        )
                        drain_event.wait(2.0)
                    else:
                        emit(
                            f"P11 RUNTIME #{runner_no} CONTROL APPLIED sj_id={sj_id} mode={mode} "
                            "secretOutput=NONE"
                        )
                    continue

                pending_mode = str(job_control_signal.mode or "").lower()
                if not result.ok and pending_mode in {"pause", "cancel"} and not result.recovery_required:
                    job_control_signal.mark_safe()
                    emit(
                        f"P11 RUNTIME #{runner_no} CONTROL SAFE sj_id={sj_id} mode={pending_mode} "
                        f"reason=job-boundary-error code={result.code} secretOutput=NONE"
                    )
                    applied = job_control_signal.wait_applied(45.0)
                    clear_claim_state()
                    control_registry.unregister(sj_id)
                    OBSERVABILITY.job_finished(completed=False)
                    if applied:
                        emit(
                            f"P11 RUNTIME #{runner_no} CONTROL APPLIED sj_id={sj_id} mode={pending_mode} "
                            "secretOutput=NONE"
                        )
                    else:
                        emit(
                            f"P11 RUNTIME #{runner_no} CONTROL APPLY TIMEOUT sj_id={sj_id} mode={pending_mode} "
                            "secretOutput=NONE"
                        )
                    continue

                control_registry.unregister(sj_id)

                if result.ok:
                    OBSERVABILITY.job_finished(completed=True)
                    emit(
                        f"P8 RUNTIME #{runner_no} JOB DONE slot={slot_no} sj_id={result.sj_id} "
                        f"code={result.code} progress={result.progress_value}/{result.target_value} "
                        f"elapsed={result.elapsed_ms/1000:.2f}s secretOutput=NONE"
                    )
                    continue

                OBSERVABILITY.job_finished(completed=False)
                emit(
                    f"P8 RUNTIME #{runner_no} JOB STOP slot={slot_no} sj_id={result.sj_id} "
                    f"code={result.code} progress={result.progress_value}/{result.target_value} "
                    f"retryable={str(result.retryable).lower()} secretOutput=NONE"
                )
                # Preserve P7 safety: ambiguous SEND/recovery state is never
                # hot-looped or blindly resent. Isolate only this runtime.
                if result.recovery_required and result.code != "HEART_WAVE_RECOVERY_REQUIRED":
                    hold_runner(runner_no, sj_id=result.sj_id, code=result.code)
                    return
                if not result.retryable and str(result.code or "").startswith("RECEIVER_"):
                    hold_runner(runner_no, sj_id=result.sj_id, code=result.code)
                    return
                drain_event.wait(3 if result.retryable else 5)

    try:
        process_lock.acquire()
    except WorkerProcessLockError:
        emit("P9 WORKER START ABORT code=WORKER_PROCESS_ALREADY_RUNNING secretOutput=NONE")
        for sig_num, handler in old_handlers.items():
            try:
                signal.signal(sig_num, handler)  # type: ignore[arg-type]
            except Exception:
                pass
        return 3

    threading.Thread(target=api_thread, name="mwoif-p1-api", daemon=True).start()
    emit(
        f"WORKER SERVICE START mode=web-auto engine=r7-phase7b-full-account-check base=p8.2.6-dedicated-control-lane "
        f"multiJob=true controlPull=true dedicatedControl=true signedV3=true replayGuard=true ramGuard=true "
        f"autoRouterRecovery={str(provider_auto_recovery_enabled()).lower()} runners={concurrent_jobs} "
        f"controlRunners={control_runners} controlPollMs={control_poll_ms} shardSlots={total_shard_slots} secretOutput=NONE"
    )

    # Startup barrier: do not allow any runner to claim before the Worker has a
    # fresh heartbeat and PHP/DB reports enough slots for this process.
    initial_heartbeat = None
    for attempt in range(1, 4):
        try:
            initial_heartbeat = send_heartbeat(version)
        except Exception:
            initial_heartbeat = None
            emit(
                f"WORKER SERVICE STARTUP HEARTBEAT FAIL attempt={attempt}/3 "
                "code=UNHANDLED_HEARTBEAT_ERROR secretOutput=NONE"
            )
        else:
            if initial_heartbeat.ok:
                worker = initial_heartbeat.worker or {}
                capacity = int(worker.get("capacity") or 0)
                if capacity < concurrent_jobs:
                    emit(
                        f"WORKER SERVICE START ABORT code=WORKER_CAPACITY_TOO_SMALL "
                        f"dbCapacity={capacity} runners={concurrent_jobs} run-setup-p8=true secretOutput=NONE"
                    )
                    drain_event.set()
                    shutdown_event.set()
                    process_lock.release()
                    for sig_num, handler in old_handlers.items():
                        try:
                            signal.signal(sig_num, handler)  # type: ignore[arg-type]
                        except Exception:
                            pass
                    return 1
                emit(
                    f"WORKER SERVICE READY heartbeat=ok active={worker.get('active_jobs',0)}/{capacity} "
                    f"runners={concurrent_jobs} secretOutput=NONE"
                )
                break
            emit(
                f"WORKER SERVICE STARTUP HEARTBEAT FAIL attempt={attempt}/3 "
                f"code={initial_heartbeat.code} secretOutput=NONE"
            )
        if attempt < 3:
            shutdown_event.wait(1)

    if initial_heartbeat is None or not initial_heartbeat.ok:
        emit("WORKER SERVICE START ABORT code=WORKER_HEARTBEAT_NOT_READY retryable=true secretOutput=NONE")
        drain_event.set()
        shutdown_event.set()
        process_lock.release()
        for sig_num, handler in old_handlers.items():
            try:
                signal.signal(sig_num, handler)  # type: ignore[arg-type]
            except Exception:
                pass
        return 1

    try:
        startup_recovery = recover_worker_startup(version)
    except Exception as exc:
        startup_recovery = None
        emit(
            f"P10.2 STARTUP RECOVERY FAIL code=UNHANDLED_STARTUP_RECOVERY_ERROR "
            f"exception={type(exc).__name__} retryable=true secretOutput=NONE"
        )
    if startup_recovery is not None:
        if startup_recovery.ok:
            emit(
                f"P10.2 STARTUP RECOVERY PASS requeued={startup_recovery.safe_requeued} "
                f"protected={startup_recovery.protected_jobs} control={startup_recovery.control_requeued} "
                f"releasedSlots={startup_recovery.released_slots} active={startup_recovery.active_jobs} "
                f"elapsed={startup_recovery.elapsed_ms/1000:.2f}s secretOutput=NONE"
            )
        else:
            emit(
                f"P10.2 STARTUP RECOVERY FAIL code={startup_recovery.code} "
                f"retryable={str(startup_recovery.retryable).lower()} secretOutput=NONE"
            )

    initial_interval = int(initial_heartbeat.heartbeat_interval_seconds or heartbeat_seconds)
    threading.Thread(
        target=heartbeat_thread,
        args=(initial_interval,),
        name="mwoif-heartbeat",
        daemon=True,
    ).start()
    threading.Thread(
        target=memory_guard_thread,
        name="mwoif-memory-guard",
        daemon=True,
    ).start()
    if provider_auto_recovery_enabled():
        threading.Thread(
            target=provider_auto_recovery_thread,
            name="mwoif-provider-auto-recovery",
            daemon=True,
        ).start()
        emit("P6.2 AUTO ROUTER RECOVERY armed=true mode=on-demand secretOutput=NONE")

    for control_no in range(1, control_runners + 1):
        thread = threading.Thread(
            target=control_runner,
            args=(control_no,),
            name=f"mwoif-control-runtime-{control_no:02d}",
            daemon=False,
        )
        control_threads.append(thread)
        thread.start()

    for runner_no in range(1, concurrent_jobs + 1):
        thread = threading.Thread(
            target=job_runner,
            args=(runner_no,),
            name=f"mwoif-job-runtime-{runner_no:02d}",
            daemon=False,
        )
        runner_threads.append(thread)
        thread.start()

    try:
        while not drain_event.wait(0.5):
            if runner_threads and not any(thread.is_alive() for thread in runner_threads):
                emit("WORKER SERVICE STOP code=NO_JOB_RUNTIMES_ALIVE secretOutput=NONE")
                drain_event.set()
                break
    finally:
        OBSERVABILITY.set_draining(True)
        drain_event.set()
        drain_started = time.monotonic()
        warned = False
        all_threads = runner_threads + control_threads
        while any(thread.is_alive() for thread in all_threads):
            for thread in all_threads:
                if thread.is_alive():
                    thread.join(timeout=0.5)
            if not warned and time.monotonic() - drain_started >= drain_warn_seconds:
                warned = True
                emit(
                    f"P9 WORKER DRAIN WAIT elapsed={int(time.monotonic()-drain_started)}s "
                    "policy=never-force-kill-active-batch secretOutput=NONE"
                )
        shutdown_event.set()
        emit("P9 WORKER DRAIN COMPLETE activeRuntimes=0 activeControlRuntimes=0 secretOutput=NONE")
        for sig_num, handler in old_handlers.items():
            try:
                signal.signal(sig_num, handler)  # type: ignore[arg-type]
            except Exception:
                pass
        process_lock.release()

    with safety_lock:
        held_count = len(safety_holds)
    if memory_recycle_event.is_set():
        return 75
    return 2 if held_count >= concurrent_jobs and concurrent_jobs > 0 else 0
