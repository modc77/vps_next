from __future__ import annotations

import json
import os
import platform
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from mwoif.net.http_pool import pooled_post_bytes
from mwoif_worker.observability import heartbeat_metrics
from mwoif_worker.work_security import signed_headers

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)


class HeartbeatConfigError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass(slots=True)
class HeartbeatResult:
    ok: bool
    code: str
    message: str
    retryable: bool
    http_status: int
    elapsed_ms: float
    worker: dict[str, Any] | None = None
    slots: list[dict[str, Any]] | None = None
    heartbeat_interval_seconds: int | None = None
    offline_after_seconds: int | None = None

    def safe_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "http_status": self.http_status,
            "elapsed_ms": self.elapsed_ms,
            "secretOutput": "NONE",
        }
        if self.worker is not None:
            payload["worker"] = self.worker
        if self.slots is not None:
            payload["slots"] = self.slots
        if self.heartbeat_interval_seconds is not None:
            payload["heartbeat_interval_seconds"] = self.heartbeat_interval_seconds
        if self.offline_after_seconds is not None:
            payload["offline_after_seconds"] = self.offline_after_seconds
        return payload


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = str(os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise HeartbeatConfigError(f"{name}_INVALID") from exc
    if value < minimum or value > maximum:
        raise HeartbeatConfigError(f"{name}_INVALID")
    return value


def _api_key() -> str:
    value = str(os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
    if len(value) < 32:
        raise HeartbeatConfigError("MWOIF_WORKER_API_KEY_NOT_CONFIGURED")
    if len(value) > 512:
        raise HeartbeatConfigError("MWOIF_WORKER_API_KEY_INVALID")
    return value


def _worker_code() -> str:
    value = str(os.getenv("MWOIF_WORKER_CODE") or "LOCAL-01").strip().upper()
    if not value or len(value) > 64:
        raise HeartbeatConfigError("MWOIF_WORKER_CODE_INVALID")
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
    if any(ch not in allowed for ch in value):
        raise HeartbeatConfigError("MWOIF_WORKER_CODE_INVALID")
    return value


def _host_label() -> str:
    configured = str(os.getenv("MWOIF_WORKER_HOST_LABEL") or "").strip()
    value = configured or platform.node() or socket.gethostname() or "worker"
    value = "".join(ch for ch in value if ch >= " " and ch != "\x7f").strip()
    return value[:120] or "worker"


def _heartbeat_url() -> str:
    url = str(
        os.getenv("MWOIF_WEB_HEARTBEAT_URL")
        or "http://127.0.0.1/M_woif/work/worker/heartbeat.php"
    ).strip()
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    loopback = host in {"127.0.0.1", "localhost", "::1"}

    if scheme not in {"http", "https"}:
        raise HeartbeatConfigError("MWOIF_WEB_HEARTBEAT_URL_INVALID")
    if not host:
        raise HeartbeatConfigError("MWOIF_WEB_HEARTBEAT_URL_INVALID")
    if not path.endswith("/work/worker/heartbeat.php"):
        raise HeartbeatConfigError("MWOIF_WEB_HEARTBEAT_URL_INVALID")
    if parts.username is not None or parts.password is not None:
        raise HeartbeatConfigError("MWOIF_WEB_HEARTBEAT_URL_INVALID")
    if parts.query or parts.fragment:
        raise HeartbeatConfigError("MWOIF_WEB_HEARTBEAT_URL_INVALID")
    if not loopback and scheme != "https":
        raise HeartbeatConfigError("MWOIF_WEB_HEARTBEAT_HTTPS_REQUIRED")
    return url


def _safe_json_object(raw: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("HEARTBEAT_RESPONSE_INVALID") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError("HEARTBEAT_RESPONSE_INVALID")
    return decoded


def send_heartbeat(version: str) -> HeartbeatResult:
    started = time.perf_counter()
    try:
        api_key = _api_key()
        worker_code = _worker_code()
        url = _heartbeat_url()
        timeout = _env_int("MWOIF_WORKER_HEARTBEAT_TIMEOUT_SECONDS", 10, 3, 30)
    except HeartbeatConfigError as exc:
        return HeartbeatResult(
            ok=False,
            code=str(exc),
            message="Worker heartbeat configuration is incomplete",
            retryable=False,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    body = json.dumps(
        {
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "host_label": _host_label(),
            "metrics": heartbeat_metrics(),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    headers = signed_headers(
        url,
        body,
        api_key=api_key,
        extra={"User-Agent": "MWOIF-Services-Worker/heartbeat-r7"},
    )

    try:
        status, raw, _response_headers = pooled_post_bytes(
            url=url,
            body=body,
            headers=headers,
            timeout=float(timeout),
            verify=True,
        )
    except Exception:
        return HeartbeatResult(
            ok=False,
            code="HEARTBEAT_NETWORK_ERROR",
            message="Worker link is temporarily unavailable",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    try:
        if len(raw) > 65536:
            raise RuntimeError("HEARTBEAT_RESPONSE_TOO_LARGE")
        payload = _safe_json_object(raw)
    except Exception:
        return HeartbeatResult(
            ok=False,
            code="HEARTBEAT_ACCESS_DENIED" if status == 403 else "HEARTBEAT_RESPONSE_INVALID",
            message="Worker heartbeat endpoint returned an unexpected response",
            retryable=status >= 500 or status in {403, 408, 425, 429},
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    if status >= 400:
        code = str(payload.get("code") or ("HEARTBEAT_ACCESS_DENIED" if status == 403 else "HEARTBEAT_HTTP_ERROR"))
        return HeartbeatResult(
            ok=False,
            code=code,
            message=str(payload.get("message") or "Worker heartbeat request was not accepted"),
            retryable=bool(payload.get("retryable", status >= 500 or status in {403, 408, 425, 429})),
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    ok = bool(payload.get("ok")) and str(payload.get("code") or "") == "WORKER_HEARTBEAT_OK"
    worker = payload.get("worker") if isinstance(payload.get("worker"), dict) else None
    slots = payload.get("slots") if isinstance(payload.get("slots"), list) else None

    return HeartbeatResult(
        ok=ok,
        code=str(payload.get("code") or ("WORKER_HEARTBEAT_OK" if ok else "HEARTBEAT_REJECTED")),
        message=str(payload.get("message") or ("Worker heartbeat accepted" if ok else "Worker heartbeat rejected")),
        retryable=bool(payload.get("retryable", not ok)),
        http_status=status,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
        worker=worker,
        slots=slots,
        heartbeat_interval_seconds=int(payload.get("heartbeat_interval_seconds")) if str(payload.get("heartbeat_interval_seconds") or "").isdigit() else None,
        offline_after_seconds=int(payload.get("offline_after_seconds")) if str(payload.get("offline_after_seconds") or "").isdigit() else None,
    )


def heartbeat_loop(version: str, *, once: bool = False, event_cb=None) -> int:
    configured_interval = _env_int("MWOIF_HEARTBEAT_INTERVAL_SECONDS", 30, 10, 300)
    failures = 0

    while True:
        result = send_heartbeat(version)
        if event_cb is not None:
            if result.ok:
                status = str((result.worker or {}).get("status") or "")
                active = int((result.worker or {}).get("active_jobs") or 0)
                capacity = int((result.worker or {}).get("capacity") or 0)
                event_cb(
                    f"P2 HEARTBEAT PASS status={status} active={active}/{capacity} "
                    f"elapsed_ms={result.elapsed_ms:.0f} secretOutput=NONE"
                )
            else:
                event_cb(
                    f"P2 HEARTBEAT FAIL code={result.code} retryable={str(result.retryable).lower()} "
                    "secretOutput=NONE"
                )

        if once:
            print(json.dumps(result.safe_dict(), ensure_ascii=False, separators=(",", ":")))
            return 0 if result.ok else 2

        if result.ok:
            failures = 0
            interval = result.heartbeat_interval_seconds or configured_interval
            interval = max(10, min(300, interval))
        else:
            failures = min(failures + 1, 5)
            interval = min(configured_interval * (2 ** failures), 120)

        time.sleep(interval)
