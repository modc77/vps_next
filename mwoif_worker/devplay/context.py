from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

LOGIN_QUERY_NAMES: tuple[str, ...] = (
    "agree_ad_day_push", "agree_ad_night_push", "agree_dt", "country_code",
    "device_id", "device_type", "email_address", "fallback_country_code", "lang",
    "lc.anonymous_id", "lc.app_build", "lc.app_installed_id", "lc.app_version",
    "lc.device.manufacturer", "lc.device.model", "lc.device.traits", "lc.device.version",
    "lc.devsisters_id", "lc.fgs_id", "lc.library_name", "lc.library_version",
    "lc.locale_on_game", "lc.location_country", "lc.new_fgs_id", "lc.os_name",
    "lc.os_version", "lc.platform", "lc.semi_device_id", "lc.store", "lc.timezone",
    "push_token", "recall_session_id", "terms_updates_ids", "terms_updates_values",
    "timezone", "use_popup_v2", "use_terms_v2",
)

LOGIN_REQUIRED_COOKIE_NAMES: tuple[str, ...] = (
    "api_key", "bundle_id", "lang", "platform", "sdk", "sdk_version",
)
LOGIN_OPTIONAL_COOKIE_NAMES: tuple[str, ...] = ("oven_access_token",)
LOGIN_COOKIE_NAMES = LOGIN_REQUIRED_COOKIE_NAMES + LOGIN_OPTIONAL_COOKIE_NAMES

# LAB confirmed these can be absent/blank in a valid pre-login context.
OPTIONAL_QUERY_NAMES = frozenset({
    "email_address", "lc.device.traits", "recall_session_id", "lc.new_fgs_id",
})


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value).strip()


def _parse_cookie_header(value: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in _text(value).split(";"):
        item = part.strip()
        if not item or "=" not in item:
            continue
        name, raw = item.split("=", 1)
        name = name.strip()
        if name in LOGIN_COOKIE_NAMES:
            out[name] = raw.strip()
    return out


@dataclass(frozen=True, slots=True)
class LoginWebContext:
    login_url: str
    query: dict[str, str]
    cookies: dict[str, str]
    missing_query: tuple[str, ...]
    missing_cookies: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return not self.missing_query and not self.missing_cookies

    def safe_summary(self) -> dict[str, Any]:
        return {
            "query_schema": f"{len(LOGIN_QUERY_NAMES)}/{len(LOGIN_QUERY_NAMES)}",
            "query_present": f"{sum(1 for k in LOGIN_QUERY_NAMES if self.query.get(k))}/{len(LOGIN_QUERY_NAMES)}",
            "cookie_present": f"{sum(1 for k in LOGIN_COOKIE_NAMES if self.cookies.get(k))}/{len(LOGIN_COOKIE_NAMES)}",
            "missing_query_names": list(self.missing_query),
            "missing_cookie_names": list(self.missing_cookies),
            "secretOutput": "NONE",
        }


def load_login_web_context(path: Path, login_url_base: str) -> LoginWebContext:
    # Keep the P1 security boundary strict: context replay is allowed only against
    # the exact DevPlay login entry point that was proven by Local V1.
    base = urlsplit(str(login_url_base or ""))
    if base.scheme.lower() != "https" or (base.hostname or "").lower() != "app.devplay.com":
        raise ValueError("login_url_base must be https://app.devplay.com/...")
    if base.path != "/auth/v2/login-try":
        raise ValueError("login_url_base path must be /auth/v2/login-try")

    if not path.is_file():
        raise FileNotFoundError(f"private web context file not found: {path.name}")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("private web context root must be a JSON object")

    query: dict[str, str] = {}
    cookies: dict[str, str] = {}

    for key in ("url", "login_url", "raw_url"):
        raw_url = _text(obj.get(key))
        if not raw_url:
            continue
        parsed = urlsplit(raw_url)
        # Ignore embedded URLs unless they are from the proven origin/path.
        if parsed.scheme.lower() != "https":
            continue
        if (parsed.hostname or "").lower() != "app.devplay.com":
            continue
        if parsed.path != "/auth/v2/login-try":
            continue
        values = parse_qs(parsed.query, keep_blank_values=True)
        for name in LOGIN_QUERY_NAMES:
            if name in values and values[name]:
                query[name] = _text(values[name][0])

    raw_query = obj.get("query") if isinstance(obj.get("query"), dict) else {}
    for name in LOGIN_QUERY_NAMES:
        if name in raw_query:
            query[name] = _text(raw_query.get(name))

    headers = obj.get("headers") if isinstance(obj.get("headers"), dict) else {}
    if not headers and isinstance(obj.get("customHeader"), dict):
        headers = obj.get("customHeader")
    if not headers and isinstance(obj.get("custom_header"), dict):
        headers = obj.get("custom_header")
    cookie_header = (
        obj.get("cookie_header")
        or obj.get("Cookie")
        or headers.get("Cookie")
        or headers.get("cookie")
        or ""
    )
    cookies.update(_parse_cookie_header(cookie_header))
    raw_cookies = obj.get("cookies") if isinstance(obj.get("cookies"), dict) else {}
    for name in LOGIN_COOKIE_NAMES:
        if name in raw_cookies:
            cookies[name] = _text(raw_cookies.get(name))

    # Local V1 proven deterministic adapters. These are not invented runtime
    # values; both come from context that must already be present.
    if not query.get("fallback_country_code"):
        query["fallback_country_code"] = _text(
            query.get("country_code") or query.get("lc.location_country")
        )
    if not query.get("lc.platform"):
        query["lc.platform"] = _text(cookies.get("platform"))

    # Preserve the proven 37-name query schema. Do not synthesize any other
    # missing runtime value.
    query = {name: query.get(name, "") for name in LOGIN_QUERY_NAMES}
    full_url = urlunsplit((base.scheme, base.netloc, base.path, urlencode(list(query.items())), ""))

    missing_query = tuple(
        name for name in LOGIN_QUERY_NAMES
        if name not in OPTIONAL_QUERY_NAMES and not query.get(name)
    )
    missing_cookies = tuple(name for name in LOGIN_REQUIRED_COOKIE_NAMES if not cookies.get(name))
    return LoginWebContext(full_url, query, cookies, missing_query, missing_cookies)
