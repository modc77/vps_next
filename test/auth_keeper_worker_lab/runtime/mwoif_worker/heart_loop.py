from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Callable

from mwoif_worker.claim import claim_once, _clear_state as _clear_claim_state, _state_path as _claim_state_path
from mwoif_worker.sender_lease import sender_lease_once
from mwoif_worker.heart_one import heart_one_once

Event = Callable[[str], None]


@dataclass(slots=True)
class HeartLoopResult:
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
    attempts: int = 0
    failed_attempts: int = 0
    last_sga_id: int | None = None

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
            "attempts": self.attempts,
            "failed_attempts": self.failed_attempts,
            "last_sga_id": self.last_sga_id,
            "secretOutput": "NONE",
        }


def _event(cb: Event | None, text: str) -> None:
    if cb:
        cb(text)


def _env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = str(os.getenv(name) or default).strip()
    try:
        value = float(raw)
    except ValueError:
        value = default
    return min(maximum, max(minimum, value))


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = str(os.getenv(name) or default).strip()
    try:
        value = int(raw)
    except ValueError:
        value = default
    return min(maximum, max(minimum, value))


def heart_loop_run(version: str, *, live: bool, max_deliveries: int = 0, event_cb: Event | None = None) -> HeartLoopResult:
    started = time.perf_counter()
    if not live:
        return HeartLoopResult(
            False,
            "P7_1_LIVE_GUARD_REQUIRED",
            "--live-heart-loop is required for automatic Heart delivery",
            False,
            (time.perf_counter() - started) * 1000.0,
        )

    delay = _env_float("MWOIF_P7_LOOP_DELAY_SECONDS", 0.35, 0.0, 10.0)
    max_failures = _env_int("MWOIF_P7_LOOP_MAX_CONSECUTIVE_FAILURES", 12, 1, 100)
    max_attempts = _env_int("MWOIF_P7_LOOP_MAX_TOTAL_ATTEMPTS", 10000, 1, 50000)
    max_deliveries = max(0, min(10000, int(max_deliveries or 0)))

    claim = claim_once(version)
    if not claim.ok or not claim.claimed or not isinstance(claim.job, dict):
        return HeartLoopResult(
            False,
            claim.code,
            claim.message,
            claim.retryable,
            (time.perf_counter() - started) * 1000.0,
        )

    job = claim.job
    sj_id = int(job.get("sj_id") or 0)
    target = int(job.get("target_value") or 0)
    progress = int(job.get("completed_value") or 0)
    if sj_id < 1 or target < 1:
        return HeartLoopResult(False, "P7_1_JOB_INVALID", "Claimed Heart job is invalid", False, (time.perf_counter() - started) * 1000.0, sj_id or None)

    start_progress = progress
    delivered = 0
    attempts = 0
    failed_attempts = 0
    consecutive_failures = 0
    last_sga_id: int | None = None

    if progress >= target:
        try:
            _clear_claim_state(_claim_state_path())
        except Exception:
            pass
        return HeartLoopResult(True, "HEART_LOOP_ALREADY_COMPLETE", "Heart job target is already reached", False, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, progress, target)

    _event(event_cb, f"P7.1 LOOP START sj_id={sj_id} progress={progress}/{target} secretOutput=NONE")

    while progress < target:
        if attempts >= max_attempts:
            return HeartLoopResult(False, "HEART_LOOP_ATTEMPT_LIMIT", "Automatic Heart loop reached its attempt safety limit", True, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, progress, target, delivered, attempts, failed_attempts, last_sga_id)

        # Recover/renew the same Job claim before each sender round.
        claim = claim_once(version)
        if not claim.ok or not claim.claimed or not isinstance(claim.job, dict):
            return HeartLoopResult(False, claim.code, claim.message, claim.retryable, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, progress, target, delivered, attempts, failed_attempts, last_sga_id)
        if int(claim.job.get("sj_id") or 0) != sj_id:
            return HeartLoopResult(False, "HEART_LOOP_JOB_CHANGED", "Worker claim changed while a Heart job was running", False, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, progress, target, delivered, attempts, failed_attempts, last_sga_id)
        progress = max(progress, int(claim.job.get("completed_value") or 0))
        target = int(claim.job.get("target_value") or target)
        if progress >= target:
            break

        lease = sender_lease_once(version)
        if not lease.ok or not lease.leased or not isinstance(lease.sender, dict):
            return HeartLoopResult(False, lease.code, lease.message, lease.retryable, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, progress, target, delivered, attempts, failed_attempts, last_sga_id)

        last_sga_id = int(lease.sender.get("sga_id") or 0) or None
        attempts += 1
        _event(event_cb, f"P7.1 ROUND START attempt={attempts} sj_id={sj_id} sga_id={last_sga_id} progress={progress}/{target} secretOutput=NONE")

        one = heart_one_once(version, live=True, event_cb=event_cb)
        if one.ok and one.code in {"HEART_DELIVERY_RECORDED", "HEART_DELIVERY_RECOVERED"}:
            progress = int(one.progress_value or progress)
            target = int(one.target_value or target)
            delivered += 1
            consecutive_failures = 0
            _event(event_cb, f"P7.1 PROGRESS sj_id={sj_id} progress={progress}/{target} deliveredThisRun={delivered} secretOutput=NONE")
            if progress >= target:
                break
            if max_deliveries > 0 and delivered >= max_deliveries:
                _event(event_cb, f"P7.1 TEST BATCH STOP sj_id={sj_id} progress={progress}/{target} deliveredThisRun={delivered} secretOutput=NONE")
                return HeartLoopResult(True, "HEART_LOOP_BATCH_LIMIT_REACHED", "Heart loop test batch limit reached; job remains active for resume", False, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, progress, target, delivered, attempts, failed_attempts, last_sga_id)
            if delay > 0:
                time.sleep(delay)
            continue

        failed_attempts += 1
        consecutive_failures += 1

        # Unknown/committed send is intentionally not auto-retried. PHP pauses the Job.
        if one.outcome == "recovery_required" or one.code in {"HEART_RECOVERY_RECORDED", "SEND_OUTCOME_UNKNOWN", "LIFE_MAIL_SEQ_NOT_FOUND", "HEART_RECEIVE_FAILED"}:
            return HeartLoopResult(False, "HEART_LOOP_RECOVERY_REQUIRED", "Heart delivery requires manual recovery before the loop can continue", True, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, int(one.progress_value or progress), int(one.target_value or target), delivered, attempts, failed_attempts, last_sga_id)

        # A pre-send failure recorded by PHP releases the sender without pair cooldown,
        # so another random eligible sender may be tried safely.
        if one.code == "HEART_ATTEMPT_RECORDED" and one.retryable and one.sender_released:
            progress = int(one.progress_value or progress)
            if consecutive_failures >= max_failures:
                return HeartLoopResult(False, "HEART_LOOP_CONSECUTIVE_FAILURE_LIMIT", "Too many consecutive sender attempts failed before a confirmed Heart send", True, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, progress, target, delivered, attempts, failed_attempts, last_sga_id)
            _event(event_cb, f"P7.1 ROUND RETRY code={one.code} consecutiveFailures={consecutive_failures}/{max_failures} secretOutput=NONE")
            if delay > 0:
                time.sleep(delay)
            continue

        return HeartLoopResult(False, one.code or "HEART_LOOP_ROUND_FAILED", one.message or "Heart loop round failed", one.retryable, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, int(one.progress_value or progress), int(one.target_value or target), delivered, attempts, failed_attempts, last_sga_id)

    try:
        _clear_claim_state(_claim_state_path())
    except Exception:
        pass
    _event(event_cb, f"P7.1 LOOP COMPLETE sj_id={sj_id} progress={progress}/{target} deliveredThisRun={delivered} secretOutput=NONE")
    return HeartLoopResult(True, "HEART_LOOP_COMPLETED", "Heart job target completed", False, (time.perf_counter() - started) * 1000.0, sj_id, start_progress, progress, target, delivered, attempts, failed_attempts, last_sga_id)
