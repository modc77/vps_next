from __future__ import annotations

import ctypes
import gc
import os
import platform
from dataclasses import dataclass


@dataclass(slots=True)
class MemorySnapshot:
    rss_mb: float
    total_mb: float
    available_mb: float


@dataclass(slots=True)
class MemoryGuardPolicy:
    soft_rss_mb: int
    hard_rss_mb: int
    min_free_mb: int
    interval_seconds: int


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(str(os.getenv(name) or default).strip())
    except Exception:
        value = default
    return max(lo, min(hi, value))


def _windows_memory() -> MemorySnapshot:
    class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivateUsage", ctypes.c_size_t),
        ]

    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    counters = PROCESS_MEMORY_COUNTERS_EX()
    counters.cb = ctypes.sizeof(counters)
    process = ctypes.windll.kernel32.GetCurrentProcess()
    ok = ctypes.windll.psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb)
    if not ok:
        raise OSError("GetProcessMemoryInfo failed")

    status = MEMORYSTATUSEX()
    status.dwLength = ctypes.sizeof(status)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise OSError("GlobalMemoryStatusEx failed")

    mib = 1024.0 * 1024.0
    return MemorySnapshot(
        rss_mb=float(counters.WorkingSetSize) / mib,
        total_mb=float(status.ullTotalPhys) / mib,
        available_mb=float(status.ullAvailPhys) / mib,
    )


def _linux_memory() -> MemorySnapshot:
    page_size = os.sysconf("SC_PAGE_SIZE")
    with open("/proc/self/statm", "r", encoding="ascii") as fh:
        parts = fh.read().split()
    rss_bytes = int(parts[1]) * int(page_size)

    values: dict[str, int] = {}
    with open("/proc/meminfo", "r", encoding="ascii") as fh:
        for line in fh:
            key, _, raw = line.partition(":")
            if not raw:
                continue
            try:
                values[key] = int(raw.strip().split()[0]) * 1024
            except Exception:
                pass
    mib = 1024.0 * 1024.0
    total = float(values.get("MemTotal", 0)) / mib
    available = float(values.get("MemAvailable", values.get("MemFree", 0))) / mib
    return MemorySnapshot(rss_mb=rss_bytes / mib, total_mb=total, available_mb=available)


def snapshot() -> MemorySnapshot:
    system = platform.system().lower()
    if system == "windows":
        return _windows_memory()
    if system == "linux":
        return _linux_memory()
    return MemorySnapshot(rss_mb=0.0, total_mb=0.0, available_mb=0.0)


def policy_from_env(current: MemorySnapshot | None = None) -> MemoryGuardPolicy:
    snap = current or snapshot()
    total = max(0.0, snap.total_mb)

    auto_soft = int(max(768.0, min(2048.0, total * 0.25))) if total > 0 else 1536
    auto_hard = int(max(1024.0, min(3072.0, total * 0.35))) if total > 0 else 2304
    auto_free = int(max(512.0, min(2048.0, total * 0.12))) if total > 0 else 768

    soft_raw = _env_int("MWOIF_WORKER_RSS_SOFT_MB", 0, 0, 65536)
    hard_raw = _env_int("MWOIF_WORKER_RSS_HARD_MB", 0, 0, 65536)
    free_raw = _env_int("MWOIF_SYSTEM_MIN_FREE_MB", 0, 0, 65536)
    interval = _env_int("MWOIF_MEMORY_GUARD_INTERVAL_SECONDS", 15, 5, 300)

    soft = soft_raw or auto_soft
    hard = hard_raw or auto_hard
    if hard <= soft:
        hard = max(soft + 256, int(soft * 1.35))
    min_free = free_raw or auto_free

    return MemoryGuardPolicy(soft_rss_mb=soft, hard_rss_mb=hard, min_free_mb=min_free, interval_seconds=interval)


def collect() -> None:
    gc.collect()
