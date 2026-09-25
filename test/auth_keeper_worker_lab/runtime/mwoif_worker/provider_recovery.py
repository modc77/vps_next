from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from mwoif_worker.provider_guard import ProviderIncidentSnapshot
from mwoif_worker.work_security import signed_headers

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

_ROOT = Path(__file__).resolve().parents[1]
if load_dotenv is not None:
    load_dotenv(_ROOT / ".env", override=False)

Event = Callable[[str], None]


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


@dataclass(slots=True)
class ProviderRecoveryResult:
    ok: bool
    code: str
    resumed_jobs: int
    elapsed_ms: float


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name) or ("1" if default else "0")).strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(str(os.getenv(name) or default).strip())
    except Exception:
        value = default
    return max(lo, min(hi, value))


def provider_auto_recovery_enabled() -> bool:
    return _env_bool("MWOIF_PROVIDER_AUTO_ROUTER_RECOVERY", False)


def provider_recovery_min_interval_seconds() -> int:
    return _env_int("MWOIF_PROVIDER_RECOVERY_MIN_INTERVAL_SECONDS", 600, 60, 86400)


def _script_path() -> Path:
    raw = str(os.getenv("MWOIF_PROVIDER_ROUTER_REBOOT_SCRIPT") or "tools/ZTE_F616_Reboot_Worker.bat").strip()
    path = Path(raw)
    if not path.is_absolute():
        path = (_ROOT / path).resolve()
    return path


def _credentials_ready() -> bool:
    return bool(str(os.getenv("MWOIF_ROUTER_USERNAME") or "").strip()) and bool(str(os.getenv("MWOIF_ROUTER_PASSWORD") or ""))


def _endpoint() -> str:
    value = str(os.getenv("MWOIF_WEB_PROVIDER_RECOVERY_URL") or "").strip()
    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not host
        or parts.path != "/work/worker/provider-recovery.php"
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or (not loopback and parts.scheme.lower() != "https")
    ):
        raise RuntimeError("MWOIF_WEB_PROVIDER_RECOVERY_URL_INVALID")
    return value


def _api_key() -> str:
    value = str(os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
    if len(value) < 32 or len(value) > 512:
        raise RuntimeError("MWOIF_WORKER_API_KEY_INVALID")
    return value


def _worker_code() -> str:
    value = str(os.getenv("MWOIF_WORKER_CODE") or "LOCAL-01").strip().upper()
    if not value or len(value) > 64 or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for ch in value):
        raise RuntimeError("MWOIF_WORKER_CODE_INVALID")
    return value


def _recovery_hosts() -> list[tuple[str, int]]:
    hosts: list[tuple[str, int]] = []
    for env_name in ("MWOIF_WEB_HEARTBEAT_URL", "MWOIF_DEVPLAY_LOGIN_URL"):
        value = str(os.getenv(env_name) or "").strip()
        parts = urlsplit(value)
        host = (parts.hostname or "").strip()
        if not host:
            continue
        port = int(parts.port or (443 if parts.scheme.lower() == "https" else 80))
        item = (host, port)
        if item not in hosts:
            hosts.append(item)
    return hosts


def _tcp_ready(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _wait_internet(event_cb: Event | None) -> bool:
    timeout_seconds = _env_int("MWOIF_PROVIDER_INTERNET_WAIT_SECONDS", 900, 60, 1800)
    stable_passes_required = _env_int("MWOIF_PROVIDER_INTERNET_STABLE_PASSES", 3, 1, 12)
    check_interval = _env_int("MWOIF_PROVIDER_INTERNET_CHECK_INTERVAL_SECONDS", 5, 2, 30)
    hosts = _recovery_hosts()
    if not hosts:
        return False
    deadline = time.monotonic() + timeout_seconds
    next_log = 0.0
    stable_passes = 0
    while time.monotonic() < deadline:
        ready = all(_tcp_ready(host, port) for host, port in hosts)
        if ready:
            stable_passes += 1
            if event_cb is not None:
                event_cb(
                    f"P6.2 AUTO ROUTER WAIT internet=true stable={stable_passes}/{stable_passes_required} "
                    "secretOutput=NONE"
                )
            if stable_passes >= stable_passes_required:
                return True
        else:
            stable_passes = 0
            now = time.monotonic()
            if event_cb is not None and now >= next_log:
                remaining = max(0, int(deadline - now))
                event_cb(
                    f"P6.2 AUTO ROUTER WAIT internet=false stable=0/{stable_passes_required} "
                    f"remaining={remaining}s secretOutput=NONE"
                )
                next_log = now + 30.0
        time.sleep(float(check_interval))
    return False


def _safe_json(raw: bytes) -> dict[str, object]:
    if len(raw) > 32768:
        raise RuntimeError("PROVIDER_RECOVERY_RESPONSE_TOO_LARGE")
    decoded = json.loads(raw.decode("utf-8")) if raw else {}
    if not isinstance(decoded, dict):
        raise RuntimeError("PROVIDER_RECOVERY_RESPONSE_INVALID")
    return decoded


def _resume_provider_jobs(version: str, snapshot: ProviderIncidentSnapshot) -> tuple[bool, int, str]:
    url = _endpoint()
    api_key = _api_key()
    body = json.dumps(
        {
            "worker_code": _worker_code(),
            "version": str(version or "")[:64],
            "incident_code": "PROVIDER_ROUTER_RECOVERED",
            "opened_at_unix": int(snapshot.opened_at_unix),
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        url,
        data=body,
        method="POST",
        headers=signed_headers(
            url,
            body,
            api_key=api_key,
            extra={"User-Agent": "MWOIF-Services-Worker/provider-recovery-r7"},
        ),
    )
    try:
        with build_opener(_NoRedirect()).open(request, timeout=15) as response:
            payload = _safe_json(response.read(32769))
            ok = int(getattr(response, "status", 200)) == 200 and bool(payload.get("ok"))
            count = max(0, int(payload.get("resumed_count") or 0)) if ok else 0
            return ok, count, str(payload.get("code") or "PROVIDER_RECOVERY_REJECTED")[:80]
    except HTTPError as exc:
        try:
            payload = _safe_json(exc.read(32769))
            return False, 0, str(payload.get("code") or "PROVIDER_RECOVERY_HTTP_ERROR")[:80]
        except Exception:
            return False, 0, "PROVIDER_RECOVERY_HTTP_ERROR"
    except (URLError, TimeoutError, OSError, ValueError, RuntimeError):
        return False, 0, "PROVIDER_RECOVERY_NETWORK_ERROR"
    except Exception:
        return False, 0, "PROVIDER_RECOVERY_INTERNAL_ERROR"


def run_provider_router_recovery(
    version: str,
    snapshot: ProviderIncidentSnapshot,
    *,
    event_cb: Event | None = None,
) -> ProviderRecoveryResult:
    started = time.perf_counter()
    if not provider_auto_recovery_enabled():
        return ProviderRecoveryResult(False, "AUTO_ROUTER_RECOVERY_DISABLED", 0, 0.0)
    if os.name != "nt":
        return ProviderRecoveryResult(False, "AUTO_ROUTER_RECOVERY_WINDOWS_REQUIRED", 0, (time.perf_counter() - started) * 1000.0)
    if not _credentials_ready():
        return ProviderRecoveryResult(False, "ROUTER_CREDENTIALS_MISSING", 0, (time.perf_counter() - started) * 1000.0)

    script = _script_path()
    if not script.is_file():
        return ProviderRecoveryResult(False, "ROUTER_REBOOT_SCRIPT_MISSING", 0, (time.perf_counter() - started) * 1000.0)

    if event_cb is not None:
        event_cb("P6.2 AUTO ROUTER REBOOT launch=once secretOutput=NONE")

    command_timeout = _env_int("MWOIF_PROVIDER_ROUTER_COMMAND_TIMEOUT_SECONDS", 720, 60, 1800)
    try:
        completed = subprocess.run(
            ["cmd.exe", "/d", "/c", str(script)],
            cwd=str(_ROOT),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=command_timeout,
            check=False,
            env=os.environ.copy(),
        )
    except subprocess.TimeoutExpired:
        return ProviderRecoveryResult(False, "ROUTER_REBOOT_TIMEOUT", 0, (time.perf_counter() - started) * 1000.0)
    except OSError:
        return ProviderRecoveryResult(False, "ROUTER_REBOOT_START_FAILED", 0, (time.perf_counter() - started) * 1000.0)

    if int(completed.returncode) != 0:
        return ProviderRecoveryResult(False, f"ROUTER_REBOOT_EXIT_{int(completed.returncode)}", 0, (time.perf_counter() - started) * 1000.0)

    if event_cb is not None:
        event_cb("P6.2 AUTO ROUTER REBOOT routerOnline=true waitingInternet=true secretOutput=NONE")

    if not _wait_internet(event_cb):
        return ProviderRecoveryResult(False, "INTERNET_RECOVERY_TIMEOUT", 0, (time.perf_counter() - started) * 1000.0)

    if event_cb is not None:
        event_cb("P6.2 AUTO ROUTER INTERNET ready=true providerResume=pending secretOutput=NONE")

    last_code = "PROVIDER_RECOVERY_NETWORK_ERROR"
    for attempt in range(1, 4):
        ok, resumed_jobs, code = _resume_provider_jobs(version, snapshot)
        if ok:
            return ProviderRecoveryResult(True, "PROVIDER_AUTO_RECOVERY_OK", resumed_jobs, (time.perf_counter() - started) * 1000.0)
        last_code = code
        if attempt < 3:
            time.sleep(2.0 * attempt)

    return ProviderRecoveryResult(False, last_code, 0, (time.perf_counter() - started) * 1000.0)
