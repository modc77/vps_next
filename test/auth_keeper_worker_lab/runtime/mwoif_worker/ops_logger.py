from __future__ import annotations

import logging
import os
import re
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Callable

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|token|secret|authorization|cookie|session(?:_?key)?|access(?:_?token)?|refresh(?:_?token)?)\s*[:=]\s*([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+\-/=]{12,}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]{8,})?\b")
_EMAIL_RE = re.compile(r"(?P<local>[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64})@(?P<domain>[A-Za-z0-9.-]{1,255})")


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = str(os.getenv(name) or "").strip()
    try:
        value = int(raw) if raw else int(default)
    except Exception:
        value = int(default)
    return max(minimum, min(maximum, value))


def _mask_email(match: re.Match[str]) -> str:
    local = match.group("local")
    domain = match.group("domain")
    if len(local) <= 2:
        masked = (local[:1] or "*") + "*"
    elif len(local) <= 5:
        masked = local[:1] + "***" + local[-1:]
    else:
        masked = local[:2] + "***" + local[-2:]
    return f"{masked}@{domain}"


def redact_event_text(text: str) -> str:
    value = str(text or "").replace("\r", " ").replace("\n", " ")
    value = _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=REDACTED", value)
    value = _BEARER_RE.sub("Bearer REDACTED", value)
    value = _JWT_RE.sub("JWT_REDACTED", value)
    value = _EMAIL_RE.sub(_mask_email, value)
    if len(value) > 4096:
        value = value[:4096] + "...[truncated]"
    return value


class _UtcFormatter(logging.Formatter):
    converter = time.gmtime


class SafeRotatingEventLogger:
    def __init__(self, project_root: Path, *, console_sink: Callable[[str], None] | None = None) -> None:
        self._console_sink = console_sink
        self._lock = threading.RLock()
        enabled = str(os.getenv("MWOIF_FILE_LOG_ENABLED") or "1").strip().lower() not in {"0", "false", "no", "off"}
        self._logger: logging.Logger | None = None
        if not enabled:
            return

        configured = str(os.getenv("MWOIF_LOG_DIR") or "logs").strip()
        log_dir = Path(configured)
        if not log_dir.is_absolute():
            log_dir = (project_root / log_dir).resolve()
        log_dir.mkdir(parents=True, exist_ok=True)

        max_bytes = _env_int("MWOIF_LOG_MAX_BYTES", 10 * 1024 * 1024, 1024 * 1024, 512 * 1024 * 1024)
        backups = _env_int("MWOIF_LOG_BACKUP_COUNT", 10, 1, 100)
        logger = logging.getLogger(f"mwoif.worker.service.{id(self)}")
        logger.setLevel(logging.INFO)
        logger.propagate = False
        handler = RotatingFileHandler(
            log_dir / "worker-service.log",
            maxBytes=max_bytes,
            backupCount=backups,
            encoding="utf-8",
            delay=True,
        )
        handler.setFormatter(_UtcFormatter("%(asctime)sZ %(message)s", "%Y-%m-%dT%H:%M:%S"))
        logger.addHandler(handler)
        self._logger = logger

    def emit(self, text: str) -> None:
        safe = redact_event_text(text)
        with self._lock:
            if self._console_sink is not None:
                self._console_sink(safe)
            if self._logger is not None:
                self._logger.info(safe)

    def close(self) -> None:
        with self._lock:
            if self._logger is None:
                return
            handlers = list(self._logger.handlers)
            for handler in handlers:
                try:
                    handler.flush()
                    handler.close()
                finally:
                    self._logger.removeHandler(handler)
            self._logger = None
