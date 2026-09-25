from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable

Event = Callable[[str], None]


class JobControlSignal:
    def __init__(self, global_drain: threading.Event) -> None:
        self._global_drain = global_drain
        self._event = threading.Event()
        self._safe = threading.Event()
        self._applied = threading.Event()
        self._lock = threading.RLock()
        self._mode = ""

    @property
    def mode(self) -> str:
        with self._lock:
            if self._event.is_set():
                return self._mode or "pause"
        return "drain" if self._global_drain.is_set() else ""

    def is_set(self) -> bool:
        return self._global_drain.is_set() or self._event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        while True:
            if self.is_set():
                return True
            if deadline is not None and time.monotonic() >= deadline:
                return False
            time.sleep(0.05)

    def request(self, mode: str) -> bool:
        value = str(mode or "").strip().lower()
        if value not in {"pause", "cancel"}:
            return False
        with self._lock:
            if self._event.is_set() and self._mode != value:
                if self._mode == "cancel":
                    return True
                if value == "cancel":
                    self._mode = "cancel"
                    return True
                return False
            self._mode = value
            self._event.set()
            return True

    def mark_safe(self) -> None:
        self._safe.set()

    def wait_safe(self, timeout: float) -> bool:
        return self._safe.wait(max(0.1, float(timeout)))

    def mark_applied(self) -> None:
        self._applied.set()

    def wait_applied(self, timeout: float) -> bool:
        return self._applied.wait(max(0.1, float(timeout)))


@dataclass(slots=True)
class _Entry:
    signal: JobControlSignal
    runner_no: int
    registered_at: float


class JobControlRegistry:
    def __init__(self, global_drain: threading.Event) -> None:
        self._global_drain = global_drain
        self._lock = threading.RLock()
        self._entries: dict[int, _Entry] = {}

    def register(self, sj_id: int, runner_no: int) -> JobControlSignal:
        job_id = int(sj_id)
        with self._lock:
            existing = self._entries.get(job_id)
            if existing is not None:
                existing.runner_no = int(runner_no)
                return existing.signal
            signal = JobControlSignal(self._global_drain)
            self._entries[job_id] = _Entry(signal, int(runner_no), time.monotonic())
            return signal

    def unregister(self, sj_id: int) -> None:
        with self._lock:
            self._entries.pop(int(sj_id), None)

    def request(self, sj_id: int, mode: str) -> tuple[bool, JobControlSignal | None]:
        job_id = int(sj_id)
        with self._lock:
            entry = self._entries.get(job_id)
            if entry is None:
                signal = JobControlSignal(self._global_drain)
                if not signal.request(mode):
                    return False, None
                signal.mark_safe()
                self._entries[job_id] = _Entry(signal, 0, time.monotonic())
                return True, signal
        return entry.signal.request(mode), entry.signal

    def active_job_ids(self) -> list[int]:
        with self._lock:
            return sorted(self._entries)
