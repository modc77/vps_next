from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

import requests

from .context import LOGIN_COOKIE_NAMES, LoginWebContext
from .models import LoginBundle, find_login_payload

Event = Callable[[str], None]
_EXPECTED_ENDPOINTS = {
    "checkemail": ("account.devplay.com", "/v4/checkemail"),
    "login": ("account.devplay.com", "/v3/login/devsisters"),
}


def _emit(cb: Event | None, text: str) -> None:
    if cb:
        cb(text)


def _origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


def _safe_url(url: str) -> str:
    try:
        p = urlsplit(str(url or ""))
        return urlunsplit((p.scheme, p.netloc, p.path, "", ""))
    except Exception:
        return "<invalid-url>"


def _endpoint_allowed(url: str, endpoint_name: str) -> bool:
    expected = _EXPECTED_ENDPOINTS.get(endpoint_name)
    if expected is None:
        return False
    p = urlsplit(str(url or ""))
    host = (p.hostname or "").lower()
    expected_host, expected_path = expected
    return (
        p.scheme.lower() == "https"
        and host == expected_host
        and p.path == expected_path
        and not p.username
        and not p.password
    )


def _public_json(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {
            "type": "dict",
            "keys": sorted(str(k) for k in value.keys())[:40],
            "key_count": len(value),
            "code": value.get("code") if isinstance(value.get("code"), (str, int, float, bool)) else None,
        }
    if isinstance(value, list):
        return {"type": "list", "len": len(value)}
    return {"type": type(value).__name__}


def _extract_user_token(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("user_token", "userToken", "token"):
            text = str(value.get(key) or "").strip()
            if text:
                return text
        result = value.get("result")
        if isinstance(result, (str, int, float)) and not isinstance(result, bool):
            text = str(result).strip()
            if len(text) >= 8:
                return text
        for child in value.values():
            got = _extract_user_token(child)
            if got:
                return got
    elif isinstance(value, list):
        for child in value:
            got = _extract_user_token(child)
            if got:
                return got
    return ""


def _apply_value(value: Any, *, email: str, password: str, user_token: str, context: LoginWebContext) -> Any:
    if isinstance(value, dict):
        return {k: _apply_value(v, email=email, password=password, user_token=user_token, context=context) for k, v in value.items()}
    if isinstance(value, list):
        return [_apply_value(v, email=email, password=password, user_token=user_token, context=context) for v in value]
    if isinstance(value, str):
        text = value
        replacements = {
            "{{EMAIL}}": email,
            "{{PASSWORD}}": password,
            "{{USER_TOKEN}}": user_token,
            "{{QUERY:push_token}}": context.query.get("push_token", ""),
            "{{QUERY:recall_session_id}}": context.query.get("recall_session_id", ""),
            "{{COOKIE:oven_access_token}}": context.cookies.get("oven_access_token", ""),
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text
    return value


def _apply_headers(headers: dict[str, str], *, context: LoginWebContext, locale: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in (headers or {}).items():
        text = str(value or "")
        text = text.replace("{{LOGIN_URL}}", context.login_url)
        text = text.replace("{{LOGIN_ORIGIN}}", _origin(context.login_url))
        text = text.replace("{{CONTEXT:x-api-key}}", context.cookies.get("api_key", ""))
        text = text.replace("{{CONTEXT:x-bundle-id}}", context.cookies.get("bundle_id", ""))
        if text:
            out[str(key)] = text
    out.setdefault("accept", "application/json, text/plain, */*")
    out.setdefault("accept-language", locale.replace("_", "-") + ",en;q=0.8")
    out.setdefault("content-type", "application/json")
    out.setdefault("origin", _origin(context.login_url))
    out.setdefault("referer", context.login_url)
    if context.cookies.get("api_key"):
        out.setdefault("x-api-key", context.cookies["api_key"])
    if context.cookies.get("bundle_id"):
        out.setdefault("x-bundle-id", context.cookies["bundle_id"])
    return out


@dataclass(slots=True)
class ReplayResult:
    ok: bool
    stage: str
    code: str
    message: str
    retryable: bool = False
    bundle: LoginBundle | None = None
    elapsed_ms: float = 0.0
    steps: list[dict[str, Any]] = field(default_factory=list)

    def safe_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "stage": self.stage,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "provider": "direct-http-exact-template-replay-v1",
            "elapsed_ms": round(self.elapsed_ms, 1),
            "steps": self.steps[-8:],
            "login": self.bundle.safe_summary() if self.bundle else None,
            "secretOutput": "NONE",
        }


class ExactTemplateReplayer:
    def __init__(
        self,
        *,
        template_file: Path,
        timeout_seconds: int,
        verify_ssl: bool,
        warmup_get: bool,
        session_factory: Callable[[], requests.Session] = requests.Session,
    ) -> None:
        self.template_file = template_file
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl
        self.warmup_get = warmup_get
        self.session_factory = session_factory

    def _load_template(self) -> dict[str, Any]:
        if not self.template_file.is_file():
            raise FileNotFoundError(f"exact template file not found: {self.template_file.name}")
        obj = json.loads(self.template_file.read_text(encoding="utf-8"))
        if not isinstance(obj, dict) or obj.get("schema") != "MWOIF_HTTP_LOGIN_EXACT_TEMPLATE_V1":
            raise ValueError("exact template schema mismatch")
        return obj

    def replay(self, *, context: LoginWebContext, email: str, password: str, event_cb: Event | None = None) -> ReplayResult:
        started = time.monotonic()
        if not email.strip() or not password:
            return ReplayResult(False, "PRECHECK", "EMPTY_CREDENTIAL", "email/password is empty")
        if not context.complete:
            return ReplayResult(False, "CONTEXT", "WEB_CONTEXT_INCOMPLETE", "private login context is incomplete")
        try:
            template = self._load_template()
        except FileNotFoundError:
            return ReplayResult(False, "TEMPLATE", "EXACT_TEMPLATE_MISSING", "known-good exact login template is missing")
        except Exception:
            return ReplayResult(False, "TEMPLATE", "EXACT_TEMPLATE_INVALID", "known-good exact login template is invalid")

        check_req = template.get("checkemail") if isinstance(template.get("checkemail"), dict) else {}
        login_req = template.get("login") if isinstance(template.get("login"), dict) else {}
        check_url = str(check_req.get("url") or "https://account.devplay.com/v4/checkemail")
        login_url = str(login_req.get("url") or "https://account.devplay.com/v3/login/devsisters")
        if not _endpoint_allowed(check_url, "checkemail") or not _endpoint_allowed(login_url, "login"):
            return ReplayResult(False, "TEMPLATE", "EXACT_TEMPLATE_ENDPOINT_BLOCKED", "template endpoint scheme/host/path is not allowed")

        locale = context.query.get("lc.locale_on_game") or "en-US"
        steps: list[dict[str, Any]] = []
        session = self.session_factory()
        for host in ("app.devplay.com", "account.devplay.com"):
            for name in LOGIN_COOKIE_NAMES:
                value = context.cookies.get(name)
                if value:
                    session.cookies.set(name, value, domain=host, path="/")

        try:
            if self.warmup_get:
                resp = session.get(
                    context.login_url,
                    headers={"referer": context.login_url},
                    timeout=self.timeout_seconds,
                    verify=self.verify_ssl,
                    allow_redirects=True,
                )
                steps.append({
                    "step": "warmup-login-try",
                    "method": "GET",
                    "url": _safe_url(getattr(resp, "url", context.login_url)),
                    "http_status": int(resp.status_code),
                })
                _emit(event_cb, f"P1 DEVPLAY warmup status={resp.status_code} secretOutput=NONE")

            check_headers = _apply_headers(check_req.get("headers_template") or {}, context=context, locale=locale)
            check_body_template = check_req.get("body_template")
            if check_body_template is None:
                check_body_template = {
                    "email": "{{EMAIL}}",
                    "lc": {name: context.query.get(name, "") for name in context.query if name.startswith("lc.")},
                }
            check_body = _apply_value(check_body_template, email=email, password=password, user_token="", context=context)
            _emit(event_cb, "P1 DEVPLAY checkemail start secretOutput=NONE")
            check_resp = session.post(
                check_url,
                data=json.dumps(check_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                headers=check_headers,
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
                allow_redirects=False,
            )
            if 300 <= check_resp.status_code < 400:
                steps.append({
                    "step": "checkemail",
                    "method": "POST",
                    "url": _safe_url(check_url),
                    "http_status": int(check_resp.status_code),
                    "redirect_blocked": True,
                })
                return ReplayResult(
                    False, "CHECKEMAIL", "CHECKEMAIL_REDIRECT_BLOCKED", "Unexpected redirect from DevPlay checkemail endpoint",
                    retryable=False, elapsed_ms=(time.monotonic() - started) * 1000, steps=steps,
                )
            try:
                check_json = check_resp.json()
            except Exception:
                check_json = None
            user_token = _extract_user_token(check_json)
            steps.append({
                "step": "checkemail",
                "method": "POST",
                "url": _safe_url(check_url),
                "http_status": int(check_resp.status_code),
                "json": _public_json(check_json),
                "user_token_present": bool(user_token),
            })
            if check_resp.status_code >= 400:
                return ReplayResult(
                    False, "CHECKEMAIL", "CHECKEMAIL_HTTP_FAILED", "DevPlay checkemail request failed",
                    retryable=check_resp.status_code >= 500 or check_resp.status_code == 429,
                    elapsed_ms=(time.monotonic() - started) * 1000, steps=steps,
                )
            if not user_token:
                return ReplayResult(
                    False, "CHECKEMAIL", "CHECKEMAIL_USER_TOKEN_MISSING", "DevPlay checkemail did not return the required login token",
                    retryable=False, elapsed_ms=(time.monotonic() - started) * 1000, steps=steps,
                )

            login_headers = _apply_headers(login_req.get("headers_template") or {}, context=context, locale=locale)
            login_body_template = login_req.get("body_template")
            raw_template = str(login_req.get("raw_body_template") or "")
            if isinstance(login_body_template, dict):
                login_body = _apply_value(login_body_template, email=email, password=password, user_token=user_token, context=context)
                login_raw = json.dumps(login_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            elif raw_template:
                login_raw = str(_apply_value(raw_template, email=email, password=password, user_token=user_token, context=context)).encode("utf-8")
            else:
                return ReplayResult(False, "TEMPLATE", "EXACT_TEMPLATE_BODY_MISSING", "template has no login request body")

            _emit(event_cb, "P1 DEVPLAY login start secretOutput=NONE")
            login_resp = session.post(
                login_url,
                data=login_raw,
                headers=login_headers,
                timeout=self.timeout_seconds,
                verify=self.verify_ssl,
                allow_redirects=False,
            )
            if 300 <= login_resp.status_code < 400:
                steps.append({
                    "step": "login-devsisters",
                    "method": "POST",
                    "url": _safe_url(login_url),
                    "http_status": int(login_resp.status_code),
                    "redirect_blocked": True,
                })
                return ReplayResult(
                    False, "LOGIN", "DEVPLAY_LOGIN_REDIRECT_BLOCKED", "Unexpected redirect from DevPlay login endpoint",
                    retryable=False, elapsed_ms=(time.monotonic() - started) * 1000, steps=steps,
                )
            try:
                login_json = login_resp.json()
            except Exception:
                login_json = None
            hit = find_login_payload(login_json)
            steps.append({
                "step": "login-devsisters",
                "method": "POST",
                "url": _safe_url(login_url),
                "http_status": int(login_resp.status_code),
                "json": _public_json(login_json),
                "contains_login_payload": hit is not None,
            })

            if login_resp.status_code >= 500 or login_resp.status_code == 429:
                return ReplayResult(
                    False, "LOGIN", "DEVPLAY_LOGIN_HTTP_RETRYABLE", "DevPlay login service is temporarily unavailable",
                    retryable=True, elapsed_ms=(time.monotonic() - started) * 1000, steps=steps,
                )
            if hit is None:
                return ReplayResult(
                    False, "LOGIN", "DEVPLAY_LOGIN_FAILED", "DevPlay login did not return a valid login session",
                    retryable=False, elapsed_ms=(time.monotonic() - started) * 1000, steps=steps,
                )
            try:
                bundle = LoginBundle.from_payload(hit)
            except Exception:
                return ReplayResult(
                    False, "LOGIN", "DEVPLAY_LOGIN_RESPONSE_INVALID", "DevPlay returned an incomplete login session",
                    retryable=False, elapsed_ms=(time.monotonic() - started) * 1000, steps=steps,
                )

            _emit(event_cb, "P1 DEVPLAY LOGIN PASS session captured secrets=REDACTED")
            return ReplayResult(
                True, "LOGIN", "DEVPLAY_LOGIN_OK", "DevPlay credential check passed",
                retryable=False, bundle=bundle,
                elapsed_ms=(time.monotonic() - started) * 1000, steps=steps,
            )
        except requests.Timeout:
            return ReplayResult(
                False, "NETWORK", "DEVPLAY_TIMEOUT", "DevPlay login timed out",
                retryable=True, elapsed_ms=(time.monotonic() - started) * 1000, steps=steps,
            )
        except requests.RequestException:
            return ReplayResult(
                False, "NETWORK", "DEVPLAY_NETWORK_ERROR", "DevPlay login network request failed",
                retryable=True, elapsed_ms=(time.monotonic() - started) * 1000, steps=steps,
            )
        finally:
            try:
                session.close()
            except Exception:
                pass
