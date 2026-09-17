from __future__ import annotations

import os
import threading
import time
from pathlib import Path

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

_ROOT = Path(__file__).resolve().parents[1]
if load_dotenv is not None:
    load_dotenv(_ROOT / '.env', override=False)
from collections import Counter, deque
from dataclasses import dataclass


def _env_bool(name: str, default: bool = True) -> bool:
    raw = str(os.getenv(name) or ("1" if default else "0")).strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(str(os.getenv(name) or default).strip())
    except Exception:
        value = default
    return max(lo, min(hi, value))


_PROVIDER_SUSPECT_CODES = {
    "DEVPLAY_TIMEOUT",
    "DEVPLAY_NETWORK_ERROR",
    "DEVPLAY_LOGIN_HTTP_RETRYABLE",
    "DEVPLAY_LOGIN_REDIRECT_BLOCKED",
    "DEVPLAY_LOGIN_FAILED",
    "DEVPLAY_LOGIN_RESPONSE_INVALID",
    "CHECKEMAIL_HTTP_FAILED",
    "CHECKEMAIL_REDIRECT_BLOCKED",
    "CHECKEMAIL_USER_TOKEN_MISSING",
    "P1_INTERNAL_ERROR",
    "INTERNAL",
}


@dataclass(frozen=True, slots=True)
class ProviderIncidentSnapshot:
    enabled: bool
    state: str
    distinct_accounts: int
    threshold: int
    window_seconds: int
    opened_at_unix: int
    primary_code: str
    code_counts: dict[str, int]

    def safe_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "state": self.state,
            "distinct_accounts": self.distinct_accounts,
            "threshold": self.threshold,
            "window_seconds": self.window_seconds,
            "opened_at_unix": self.opened_at_unix,
            "primary_code": self.primary_code,
            "code_counts": dict(self.code_counts),
            "secretOutput": "NONE",
        }


class ProviderIncidentGuard:
    def __init__(self) -> None:
        self.enabled = _env_bool("MWOIF_PROVIDER_GUARD_ENABLED", True)
        self.threshold = _env_int("MWOIF_PROVIDER_GUARD_FAILURES", 15, 10, 50)
        self.window_seconds = _env_int("MWOIF_PROVIDER_GUARD_WINDOW_SECONDS", 180, 30, 900)
        self._lock = threading.RLock()
        self._recent: deque[tuple[float, int, str]] = deque()
        self._state = "closed"
        self._opened_at_unix = 0
        self._primary_code = ""
        self._alert_sent = False

    def _trim_locked(self, now: float) -> None:
        cutoff = now - float(self.window_seconds)
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

    def _snapshot_locked(self, now: float | None = None) -> ProviderIncidentSnapshot:
        if now is None:
            now = time.monotonic()
        self._trim_locked(now)
        distinct = {account_id for _, account_id, _ in self._recent}
        counts = Counter(code for _, _, code in self._recent)
        primary = self._primary_code or (counts.most_common(1)[0][0] if counts else "")
        return ProviderIncidentSnapshot(
            enabled=self.enabled,
            state=self._state,
            distinct_accounts=len(distinct),
            threshold=self.threshold,
            window_seconds=self.window_seconds,
            opened_at_unix=self._opened_at_unix,
            primary_code=primary,
            code_counts=dict(counts.most_common(8)),
        )

    @staticmethod
    def _suspect(code: str, stage: str, retryable: bool) -> bool:
        value = str(code or "").strip().upper()
        stage_value = str(stage or "").strip().upper()
        if stage_value not in {"LOGIN", "NETWORK", "CHECKEMAIL", "CONTROL"}:
            return False
        if retryable:
            return True
        if value in _PROVIDER_SUSPECT_CODES:
            return True
        return value.endswith("_NETWORK_ERROR") or value.endswith("_TIMEOUT") or value.startswith("HTTP_429")

    def record_failure(self, account_id: int, code: str, *, stage: str = "LOGIN", retryable: bool = False) -> tuple[bool, ProviderIncidentSnapshot]:
        if not self.enabled or account_id < 1 or not self._suspect(code, stage, retryable):
            return False, self.snapshot()
        value = str(code or "UNKNOWN").strip().upper()[:80] or "UNKNOWN"
        now = time.monotonic()
        with self._lock:
            if self._state == "open":
                return False, self._snapshot_locked(now)
            self._trim_locked(now)
            self._recent.append((now, int(account_id), value))
            distinct = {item[1] for item in self._recent}
            if len(distinct) < self.threshold:
                return False, self._snapshot_locked(now)
            counts = Counter(item[2] for item in self._recent)
            self._state = "open"
            self._opened_at_unix = int(time.time())
            self._primary_code = counts.most_common(1)[0][0] if counts else value
            self._alert_sent = False
            return True, self._snapshot_locked(now)

    def record_success(self, account_id: int) -> None:
        if not self.enabled or account_id < 1:
            return
        with self._lock:
            if self._state != "closed":
                return
            if not self._recent:
                return
            self._recent = deque(item for item in self._recent if item[1] != int(account_id))

    def is_open(self) -> bool:
        with self._lock:
            return self.enabled and self._state == "open"

    def mark_alert_sent(self) -> bool:
        with self._lock:
            if self._alert_sent:
                return False
            self._alert_sent = True
            return True

    def snapshot(self) -> ProviderIncidentSnapshot:
        with self._lock:
            return self._snapshot_locked()

    def reset(self) -> None:
        with self._lock:
            self._recent.clear()
            self._state = "closed"
            self._opened_at_unix = 0
            self._primary_code = ""
            self._alert_sent = False


_GUARD = ProviderIncidentGuard()


def get_provider_guard() -> ProviderIncidentGuard:
    return _GUARD
