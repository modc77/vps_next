from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mwoif.core.config import AppConfig


@dataclass(slots=True)
class DevPlayRuntimeConfig:
    """Small compatibility adapter for the V2-passed login/session logic.

    The backup V2 code is not imported at runtime. V3 builds the same config
    shape from .env so the proven behavior can be reused behind V3 modules.
    """

    root: Path
    raw: dict[str, Any]

    @property
    def server(self) -> dict[str, Any]:
        return self.raw.setdefault("server", {})

    @property
    def devplay(self) -> dict[str, Any]:
        return self.raw.setdefault("devplay", {})

    @property
    def game(self) -> dict[str, Any]:
        return self.raw.setdefault("game", {})

    @property
    def workflow(self) -> dict[str, Any]:
        return self.raw.setdefault("workflow", {})


def _bool_text(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def build_devplay_runtime_config(config: AppConfig) -> DevPlayRuntimeConfig:
    env = config.extra
    root = config.project_root

    game_base = env.get("MWOIF_GAME_BASE_URL", "https://server.live.prod.devsnova.cloud/")
    timeout = int(env.get("MWOIF_GAME_TIMEOUT_SECONDS", "20") or "20")
    verify_ssl = _bool_text(env.get("MWOIF_GAME_VERIFY_SSL"), True)

    version = env.get("MWOIF_GAME_VERSION", "26.8.02")
    build_version = env.get("MWOIF_GAME_BUILD_VERSION", "651")

    locale = env.get("MWOIF_DEVPLAY_LOCALE", "en-US")
    timezone = env.get("MWOIF_DEVPLAY_TIMEZONE", "Asia/Bangkok")
    country = env.get("MWOIF_DEVPLAY_LOCATION_COUNTRY", "US")

    raw: dict[str, Any] = {
        "server": {
            "game_base_url": game_base,
            "timeout_seconds": timeout,
            "verify_ssl": verify_ssl,
            "friend_grpc_target": env.get("MWOIF_FRIEND_GRPC_TARGET", "gserver.live.prod.devsnova.cloud:443"),
        },
        "devplay": {
            "runtime_metadata_version": "V3_FROM_V2_PASS",
            "timezone": timezone,
            "location_country": country,
            "os_type": env.get("MWOIF_DEVPLAY_OS_TYPE", "A"),
            "os_version": env.get("MWOIF_DEVPLAY_OS_VERSION", "12"),
            "locale": locale,
            "device_name": env.get("MWOIF_DEVPLAY_DEVICE_NAME", "SM-A156E"),
            "device_model": env.get("MWOIF_DEVPLAY_DEVICE_MODEL", "SM-A156E"),
            "device_id": env.get("MWOIF_DEVPLAY_DEVICE_ID", ""),
            "time_zone_distance": env.get("MWOIF_DEVPLAY_TIME_ZONE_DISTANCE", "25200"),
            "market_type": env.get("MWOIF_DEVPLAY_MARKET_TYPE", "GOOGLE_PLAY"),
            "login_platform": "email",
        },
        "game": {
            "version": version,
            "build_version": build_version,
            "package_name": env.get("MWOIF_GAME_PACKAGE_NAME", "com.devsisters.crg"),
            "index_file_hash": env.get("MWOIF_GAME_INDEX_FILE_HASH", "71c2fe2247b746f7570e7e6ae5670c69"),
        },
        "workflow": {
            "receiver_slot": "A",
            "friend_source_type": int(env.get("MWOIF_FRIEND_SOURCE_TYPE", "2") or "2"),
            "grpc_timeout_seconds": int(env.get("MWOIF_GRPC_TIMEOUT_SECONDS", "12") or "12"),
            "ds_timeout_seconds": int(env.get("MWOIF_DS_TIMEOUT_SECONDS", "20") or "20"),
        },
        "v2": {
            "auth_base_url": env.get("MWOIF_DEVPLAY_AUTH_BASE_URL", "https://account.prod.devsisters.cloud"),
            "devplay_login_url": env.get("MWOIF_DEVPLAY_LOGIN_URL", "https://app.devplay.com/auth/v2/login-try"),
            "browser_headless": _bool_text(env.get("MWOIF_DEVPLAY_BROWSER_HEADLESS"), False),
            "browser_channel": env.get("MWOIF_DEVPLAY_BROWSER_CHANNEL", "chrome"),
            "browser_timeout_seconds": int(env.get("MWOIF_DEVPLAY_BROWSER_TIMEOUT_SECONDS", "120") or "120"),
            "browser_auto_submit": _bool_text(env.get("MWOIF_DEVPLAY_BROWSER_AUTO_SUBMIT"), True),
            "http_login_timeout_seconds": int(env.get("MWOIF_DEVPLAY_HTTP_LOGIN_TIMEOUT_SECONDS", "35") or "35"),
            "http_login_max_steps": int(env.get("MWOIF_DEVPLAY_HTTP_LOGIN_MAX_STEPS", "8") or "8"),
            "http_login_auto_submit": _bool_text(env.get("MWOIF_DEVPLAY_HTTP_LOGIN_AUTO_SUBMIT"), True),
            "network_record_save": _bool_text(env.get("MWOIF_DEVPLAY_NETWORK_RECORD_SAVE"), True),
            "network_record_max_events": int(env.get("MWOIF_DEVPLAY_NETWORK_RECORD_MAX_EVENTS", "120") or "120"),
            "network_record_scan_scripts": _bool_text(env.get("MWOIF_DEVPLAY_NETWORK_RECORD_SCAN_SCRIPTS"), True),
            "devplay_account_base_url": env.get("MWOIF_DEVPLAY_ACCOUNT_BASE_URL", "https://account.devplay.com"),
            "http_login_checkemail_path": env.get("MWOIF_DEVPLAY_HTTP_CHECKEMAIL_PATH", "/v4/checkemail"),
            "http_login_devsisters_path": env.get("MWOIF_DEVPLAY_HTTP_DEVSISTERS_PATH", "/v3/login/devsisters"),
            "http_login_lc_mode": env.get("MWOIF_DEVPLAY_HTTP_LC_MODE", "prefixed"),
            "http_login_warmup_get": _bool_text(env.get("MWOIF_DEVPLAY_HTTP_WARMUP_GET"), True),
            "http_matrix_max_attempts": int(env.get("MWOIF_DEVPLAY_HTTP_MATRIX_MAX_ATTEMPTS", "48") or "48"),
            "http_matrix_stop_on_hit": _bool_text(env.get("MWOIF_DEVPLAY_HTTP_MATRIX_STOP_ON_HIT"), True),
            "http_matrix_sleep_ms": int(env.get("MWOIF_DEVPLAY_HTTP_MATRIX_SLEEP_MS", "150") or "150"),
            "http_matrix_save": _bool_text(env.get("MWOIF_DEVPLAY_HTTP_MATRIX_SAVE"), True),
            "http_exact_template_file": env.get("MWOIF_DEVPLAY_HTTP_EXACT_TEMPLATE_FILE", ""),
            "http_exact_template_save": _bool_text(env.get("MWOIF_DEVPLAY_HTTP_EXACT_TEMPLATE_SAVE"), True),
            "persist_runtime_tokens": False,
            "login_web_context": {
                "private_context_file": env.get("MWOIF_DEVPLAY_WEB_CONTEXT_FILE", "state/login_web_context.private.json"),
                "query": {"lc.new_fgs_id": ""},
                "cookies": {},
            },
        },
    }
    return DevPlayRuntimeConfig(root=root, raw=raw)
