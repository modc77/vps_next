from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator


@dataclass(frozen=True, slots=True)
class ShardLease:
    job_key: str
    slot_no: int
    allocation: int
    active_jobs: int


class ElasticShardPool:
    """Fair, non-preemptive execution-slot pool shared by active Heart jobs.

    A job may borrow every slot while it is the only active job. When another
    job registers, the desired allocation is recomputed (e.g. 5 -> 3+2). Slots
    already executing are never interrupted; the oversized job simply cannot
    acquire another slot until enough of its current shard work finishes.
    """

    def __init__(self, total_slots: int) -> None:
        self.total_slots = max(1, int(total_slots))
        self._cond = threading.Condition(threading.RLock())
        self._jobs: list[str] = []
        self._in_use: dict[str, set[int]] = {}
        self._free_slots: set[int] = set(range(1, self.total_slots + 1))
        self._peak: dict[str, int] = {}
        self._waiters: dict[str, int] = {}

    def register(self, job_key: str) -> None:
        key = str(job_key)
        with self._cond:
            if key not in self._jobs:
                self._jobs.append(key)
                self._in_use.setdefault(key, set())
                self._peak.setdefault(key, 0)
                self._waiters.setdefault(key, 0)
                self._cond.notify_all()

    def unregister(self, job_key: str) -> None:
        key = str(job_key)
        with self._cond:
            slots = self._in_use.pop(key, set())
            self._free_slots.update(slots)
            if key in self._jobs:
                self._jobs.remove(key)
            self._peak.pop(key, None)
            self._waiters.pop(key, None)
            self._cond.notify_all()

    def allocation(self, job_key: str) -> int:
        key = str(job_key)
        with self._cond:
            return self._allocation_locked(key)

    def _allocation_locked(self, job_key: str) -> int:
        if job_key not in self._jobs:
            return 0
        count = max(1, len(self._jobs))
        base = self.total_slots // count
        extra = self.total_slots % count
        index = self._jobs.index(job_key)
        return base + (1 if index < extra else 0)

    def snapshot(self, job_key: str) -> dict[str, int]:
        key = str(job_key)
        with self._cond:
            return {
                "total_slots": self.total_slots,
                "active_jobs": len(self._jobs),
                "allocation": self._allocation_locked(key),
                "in_use": len(self._in_use.get(key, set())),
                "peak": int(self._peak.get(key, 0)),
                "free": len(self._free_slots),
            }

    def _other_job_needs_fair_share_locked(self, key: str) -> bool:
        for other in self._jobs:
            if other == key:
                continue
            if self._waiters.get(other, 0) <= 0:
                continue
            if len(self._in_use.get(other, set())) < self._allocation_locked(other):
                return True
        return False

    def acquire(self, job_key: str, *, stop_event: threading.Event | None = None) -> ShardLease:
        key = str(job_key)
        with self._cond:
            if key not in self._jobs:
                raise RuntimeError("SHARD_JOB_NOT_REGISTERED")
            self._waiters[key] = self._waiters.get(key, 0) + 1
            try:
                while True:
                    if key not in self._jobs:
                        raise RuntimeError("SHARD_JOB_NOT_REGISTERED")
                    if stop_event is not None and stop_event.is_set():
                        raise RuntimeError("SHARD_STOP_REQUESTED")

                    allocation = self._allocation_locked(key)
                    current = len(self._in_use.get(key, set()))
                    under_fair_share = current < allocation
                    can_borrow = not self._other_job_needs_fair_share_locked(key)
                    if self._free_slots and (under_fair_share or can_borrow):
                        slot_no = min(self._free_slots)
                        self._free_slots.remove(slot_no)
                        self._in_use.setdefault(key, set()).add(slot_no)
                        self._peak[key] = max(self._peak.get(key, 0), current + 1)
                        return ShardLease(
                            job_key=key,
                            slot_no=slot_no,
                            allocation=allocation,
                            active_jobs=len(self._jobs),
                        )
                    self._cond.wait(timeout=0.20)
            finally:
                self._waiters[key] = max(0, self._waiters.get(key, 1) - 1)

    def release(self, lease: ShardLease) -> None:
        with self._cond:
            slots = self._in_use.get(lease.job_key)
            if slots is not None and lease.slot_no in slots:
                slots.remove(lease.slot_no)
                self._free_slots.add(lease.slot_no)
            self._cond.notify_all()

    @contextmanager
    def slot(self, job_key: str, *, stop_event: threading.Event | None = None) -> Iterator[ShardLease]:
        lease = self.acquire(job_key, stop_event=stop_event)
        try:
            yield lease
        finally:
            self.release(lease)

    def wait_for_idle(self, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        with self._cond:
            while len(self._free_slots) != self.total_slots:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cond.wait(timeout=min(0.20, remaining))
            return True
