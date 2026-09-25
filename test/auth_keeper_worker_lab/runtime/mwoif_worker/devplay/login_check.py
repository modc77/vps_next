from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from typing import Any, Callable

from mwoif_worker.config import WorkerConfig

from .context import load_login_web_context
from .exact_template import ExactTemplateReplayer

Event = Callable[[str], None]
_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


@dataclass(slots=True)
class LoginCheckResult:
    ok: bool
    credential_valid: bool
    code: str
    stage: str
    message: str
    retryable: bool
    email: str
    elapsed_ms: float
    detail: dict[str, Any]
    member_id: str = ""

    def safe_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "credential_valid": self.credential_valid,
            "code": self.code,
            "stage": self.stage,
            "message": self.message,
            "retryable": self.retryable,
            "email": self.email,
            "identity_fp": hashlib.sha256(self.email.lower().encode("utf-8", "ignore")).hexdigest()[:12] if self.email else "",
            "elapsed_ms": round(self.elapsed_ms, 1),
            "detail": self.detail,
            "secretOutput": "NONE",
        }


class DevPlayLoginChecker:
    """Headless P1 credential verifier.

    Uses the exact-template direct HTTP login path proven by Local V1.
    It never captures a browser template and never persists returned tokens.
    """

    def __init__(self, config: WorkerConfig | None = None) -> None:
        self.config = config or WorkerConfig.load()

    def check(self, email: str, password: str, event_cb: Event | None = None) -> LoginCheckResult:
        started = time.monotonic()
        email = str(email or "").strip()
        password = str(password or "")
        if not email or not password:
            return LoginCheckResult(False, False, "EMPTY_CREDENTIAL", "PRECHECK", "Email/Password is required", False, email, 0.0, {})
        if not _EMAIL_RE.match(email):
            return LoginCheckResult(False, False, "EMAIL_FORMAT_INVALID", "PRECHECK", "Email format is invalid", False, email, 0.0, {})

        try:
            context = load_login_web_context(self.config.web_context_file, self.config.login_url)
        except FileNotFoundError:
            return LoginCheckResult(False, False, "WEB_CONTEXT_MISSING", "CONFIG", "Private DevPlay web context is missing", False, email, (time.monotonic() - started) * 1000, {})
        except Exception:
            return LoginCheckResult(False, False, "WEB_CONTEXT_INVALID", "CONFIG", "Private DevPlay web context is invalid", False, email, (time.monotonic() - started) * 1000, {})

        if not context.complete:
            return LoginCheckResult(
                False, False, "WEB_CONTEXT_INCOMPLETE", "CONFIG", "Private DevPlay web context is incomplete", False, email,
                (time.monotonic() - started) * 1000,
                {"context": context.safe_summary()},
            )

        replayer = ExactTemplateReplayer(
            template_file=self.config.exact_template_file,
            timeout_seconds=self.config.timeout_seconds,
            verify_ssl=self.config.verify_ssl,
            warmup_get=self.config.warmup_get,
        )
        replay = replayer.replay(context=context, email=email, password=password, event_cb=event_cb)
        safe = replay.safe_dict()
        return LoginCheckResult(
            ok=replay.ok,
            credential_valid=replay.ok,
            code=replay.code,
            stage=replay.stage,
            message=replay.message,
            retryable=replay.retryable,
            email=email,
            elapsed_ms=replay.elapsed_ms,
            detail={
                "provider": safe["provider"],
                "login": safe.get("login"),
                "steps": safe.get("steps", []),
                "context": context.safe_summary(),
            },
            member_id=replay.bundle.mid if replay.bundle is not None else "",
        )
