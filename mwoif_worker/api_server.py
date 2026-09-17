from __future__ import annotations

import hmac
import json
import os
from pathlib import Path
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .devplay.login_check import DevPlayLoginChecker

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)

API_PATH = "/api/p1/devplay/check"
MAX_BODY_BYTES = 8192


def _api_key() -> str:
    key = str(os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
    if len(key) < 32:
        raise RuntimeError("MWOIF_WORKER_API_KEY must contain at least 32 characters")
    return key


def _safe_result(result: Any) -> dict[str, Any]:
    safe = result.safe_dict()
    return {
        "ok": bool(safe.get("ok")),
        "credential_valid": bool(safe.get("credential_valid")),
        "code": str(safe.get("code") or ""),
        "stage": str(safe.get("stage") or ""),
        "message": str(safe.get("message") or ""),
        "retryable": bool(safe.get("retryable")),
        "identity_fp": str(safe.get("identity_fp") or ""),
        "elapsed_ms": float(safe.get("elapsed_ms") or 0.0),
        "secretOutput": "NONE",
    }


class P1ApiHandler(BaseHTTPRequestHandler):
    server_version = "MWOIF-P1"
    sys_version = ""

    def log_message(self, fmt: str, *args: object) -> None:
        # Never log request headers or bodies. The default line contains only
        # source address, method/path/status and is safe for this fixed endpoint.
        super().log_message(fmt, *args)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"ok": False, "code": "METHOD_NOT_ALLOWED", "secretOutput": "NONE"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path != API_PATH or parsed.query:
            self._json(HTTPStatus.NOT_FOUND, {"ok": False, "code": "NOT_FOUND", "secretOutput": "NONE"})
            return

        try:
            expected = _api_key()
        except RuntimeError:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"ok": False, "code": "API_KEY_NOT_CONFIGURED", "secretOutput": "NONE"})
            return

        supplied = str(self.headers.get("X-MWOIF-Worker-Key") or "")
        if not supplied or not hmac.compare_digest(supplied, expected):
            self._json(HTTPStatus.UNAUTHORIZED, {"ok": False, "code": "UNAUTHORIZED", "secretOutput": "NONE"})
            return

        content_type = str(self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"ok": False, "code": "JSON_REQUIRED", "secretOutput": "NONE"})
            return

        try:
            length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            length = 0
        if length < 2 or length > MAX_BODY_BYTES:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"ok": False, "code": "BODY_SIZE_INVALID", "secretOutput": "NONE"})
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "code": "INPUT_JSON_INVALID", "secretOutput": "NONE"})
            return

        if not isinstance(payload, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False, "code": "INPUT_JSON_INVALID", "secretOutput": "NONE"})
            return

        email = str(payload.get("email") or "").strip()
        password = str(payload.get("password") or "")
        if len(email) < 3 or len(email) > 190 or len(password) < 1 or len(password) > 255:
            self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {
                "ok": False,
                "credential_valid": False,
                "code": "INPUT_INVALID",
                "retryable": False,
                "secretOutput": "NONE",
            })
            return

        try:
            result = DevPlayLoginChecker().check(email, password, event_cb=None)
            body = _safe_result(result)
            self._json(HTTPStatus.OK if result.ok else HTTPStatus.UNPROCESSABLE_ENTITY, body)
        except Exception:
            # No exception text is returned because it may contain environment/path details.
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {
                "ok": False,
                "credential_valid": False,
                "code": "P1_INTERNAL_ERROR",
                "retryable": True,
                "secretOutput": "NONE",
            })


def run_api(host: str | None = None, port: int | None = None) -> None:
    bind_host = str(host or os.getenv("MWOIF_WORKER_API_HOST") or "127.0.0.1").strip()
    bind_port = int(port or os.getenv("MWOIF_WORKER_API_PORT") or "8789")
    if bind_host not in {"127.0.0.1", "::1"}:
        raise RuntimeError("MWOIF_WORKER_API_LOOPBACK_REQUIRED")
    if bind_port < 1024 or bind_port > 65535:
        raise RuntimeError("MWOIF_WORKER_API_PORT_INVALID")
    _api_key()
    server = ThreadingHTTPServer((bind_host, bind_port), P1ApiHandler)
    print(f"P1 API listening on {bind_host}:{bind_port} path={API_PATH} secretOutput=NONE", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
