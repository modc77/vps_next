from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

_PROCESS_STARTED_MONOTONIC = time.monotonic()
_PROCESS_STARTED_UNIX = int(time.time())


class _RuntimeObservability:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._configured_runners = 0
        self._shard_slots = 0
        self._active_runtimes = 0
        self._safety_holds: set[int] = set()
        self._draining = False
        self._jobs_started = 0
        self._jobs_completed = 0
        self._jobs_stopped = 0
        self._pool_recycles = 0
        self._last_job_started_unix = 0
        self._last_job_finished_unix = 0

    def configure(self, *, runners: int, shard_slots: int) -> None:
        with self._lock:
            self._configured_runners = max(0, int(runners))
            self._shard_slots = max(0, int(shard_slots))

    def set_draining(self, value: bool) -> None:
        with self._lock:
            self._draining = bool(value)

    def job_started(self) -> None:
        with self._lock:
            self._active_runtimes += 1
            self._jobs_started += 1
            self._last_job_started_unix = int(time.time())

    def job_finished(self, *, completed: bool) -> None:
        with self._lock:
            self._active_runtimes = max(0, self._active_runtimes - 1)
            if completed:
                self._jobs_completed += 1
            else:
                self._jobs_stopped += 1
            self._last_job_finished_unix = int(time.time())

    def set_safety_hold(self, runner_no: int, value: bool = True) -> None:
        with self._lock:
            if value:
                self._safety_holds.add(int(runner_no))
            else:
                self._safety_holds.discard(int(runner_no))

    def pool_recycled(self) -> None:
        with self._lock:
            self._pool_recycles += 1

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            runtime = {
                "configured_runners": self._configured_runners,
                "shard_slots": self._shard_slots,
                "active_runtimes": self._active_runtimes,
                "safety_holds": len(self._safety_holds),
                "draining": self._draining,
                "jobs_started": self._jobs_started,
                "jobs_completed": self._jobs_completed,
                "jobs_stopped": self._jobs_stopped,
                "pool_recycles": self._pool_recycles,
                "last_job_started_unix": self._last_job_started_unix,
                "last_job_finished_unix": self._last_job_finished_unix,
            }
        runtime.update(_process_metrics())
        return runtime


OBSERVABILITY = _RuntimeObservability()


def _linux_rss_bytes() -> int | None:
    statm = Path("/proc/self/statm")
    try:
        parts = statm.read_text(encoding="ascii").strip().split()
        if len(parts) < 2:
            return None
        resident_pages = int(parts[1])
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        value = resident_pages * page_size
        return value if value >= 0 else None
    except Exception:
        return None


def _windows_rss_bytes() -> int | None:
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        process = ctypes.windll.kernel32.GetCurrentProcess()
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb)
        if not ok:
            return None
        value = int(counters.WorkingSetSize)
        return value if value > 0 else None
    except Exception:
        return None


def _fallback_rss_bytes() -> int | None:
    windows_value = _windows_rss_bytes()
    if windows_value is not None:
        return windows_value
    try:
        import resource

        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        if value <= 0:
            return None
        if sys.platform == "darwin":
            return value
        return value * 1024
    except Exception:
        return None


def _open_fds() -> int | None:
    fd_dir = Path("/proc/self/fd")
    try:
        return len(list(fd_dir.iterdir()))
    except Exception:
        return None


def _system_load_1m() -> float | None:
    try:
        return round(float(os.getloadavg()[0]), 3)
    except Exception:
        return None


def _process_metrics() -> dict[str, Any]:
    rss = _linux_rss_bytes()
    if rss is None:
        rss = _fallback_rss_bytes()
    return {
        "pid": os.getpid(),
        "process_started_unix": _PROCESS_STARTED_UNIX,
        "uptime_seconds": max(0, int(time.monotonic() - _PROCESS_STARTED_MONOTONIC)),
        "thread_count": max(0, threading.active_count()),
        "rss_bytes": rss,
        "open_fds": _open_fds(),
        "process_cpu_seconds": round(float(time.process_time()), 3),
        "system_load_1m": _system_load_1m(),
    }


def heartbeat_metrics() -> dict[str, Any]:
    return OBSERVABILITY.snapshot()
