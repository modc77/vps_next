from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    root: Path
    web_context_file: Path
    exact_template_file: Path
    login_url: str
    timeout_seconds: int
    verify_ssl: bool
    warmup_get: bool

    @classmethod
    def load(cls, root: Path | None = None) -> "WorkerConfig":
        root = (root or Path(__file__).resolve().parents[1]).resolve()
        if load_dotenv is not None:
            load_dotenv(root / ".env", override=False)

        def resolve_file(env_name: str, default: str) -> Path:
            raw = (os.getenv(env_name) or default).strip()
            path = Path(raw)
            if not path.is_absolute():
                path = root / path
            return path.resolve()

        timeout = int((os.getenv("MWOIF_DEVPLAY_HTTP_LOGIN_TIMEOUT_SECONDS") or "35").strip())
        if timeout < 3 or timeout > 180:
            raise ValueError("MWOIF_DEVPLAY_HTTP_LOGIN_TIMEOUT_SECONDS must be 3..180")

        return cls(
            root=root,
            web_context_file=resolve_file(
                "MWOIF_DEVPLAY_WEB_CONTEXT_FILE",
                "state/login_web_context.private.json",
            ),
            exact_template_file=resolve_file(
                "MWOIF_DEVPLAY_HTTP_EXACT_TEMPLATE_FILE",
                "state/http_login_exact_template_receiver.private.json",
            ),
            login_url=(
                os.getenv("MWOIF_DEVPLAY_LOGIN_URL")
                or "https://app.devplay.com/auth/v2/login-try"
            ).strip(),
            timeout_seconds=timeout,
            verify_ssl=_bool("MWOIF_GAME_VERIFY_SSL", True),
            warmup_get=_bool("MWOIF_DEVPLAY_HTTP_WARMUP_GET", True),
        )
