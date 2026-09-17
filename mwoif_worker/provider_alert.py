from __future__ import annotations

import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from mwoif_worker.provider_guard import ProviderIncidentSnapshot
from mwoif_worker.work_security import signed_headers


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _endpoint() -> str:
    value = str(os.getenv("MWOIF_WEB_PROVIDER_ALERT_URL") or "").strip()
    parts = urlsplit(value)
    host = (parts.hostname or "").lower()
    loopback = host in {"127.0.0.1", "localhost", "::1"}
    if (
        parts.scheme.lower() not in {"http", "https"}
        or not host
        or parts.path != "/work/worker/provider-alert.php"
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or (not loopback and parts.scheme.lower() != "https")
    ):
        raise RuntimeError("MWOIF_WEB_PROVIDER_ALERT_URL_INVALID")
    return value


def _api_key() -> str:
    value = str(os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
    if len(value) < 32 or len(value) > 512:
        raise RuntimeError("MWOIF_WORKER_API_KEY_INVALID")
    return value


def _worker_code() -> str:
    value = str(os.getenv("MWOIF_WORKER_CODE") or "LOCAL-01").strip().upper()
    if not value or len(value) > 64:
        raise RuntimeError("MWOIF_WORKER_CODE_INVALID")
    return value


def send_provider_incident_alert(version: str, snapshot: ProviderIncidentSnapshot) -> bool:
    try:
        url = _endpoint()
        api_key = _api_key()
        payload = {
            "worker_code": _worker_code(),
            "version": str(version or "")[:64],
            "incident_code": "PROVIDER_IP_LIMIT_SUSPECTED",
            "distinct_accounts": int(snapshot.distinct_accounts),
            "threshold": int(snapshot.threshold),
            "window_seconds": int(snapshot.window_seconds),
            "primary_code": str(snapshot.primary_code or "")[:80],
            "opened_at_unix": int(snapshot.opened_at_unix),
            "code_counts": {str(k)[:80]: int(v) for k, v in list(snapshot.code_counts.items())[:8]},
        }
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        request = Request(
            url,
            data=body,
            method="POST",
            headers=signed_headers(
                url,
                body,
                api_key=api_key,
                extra={"User-Agent": "MWOIF-Services-Worker/provider-guard-r7"},
            ),
        )
        with build_opener(_NoRedirect()).open(request, timeout=10) as response:
            raw = response.read(32769)
            if len(raw) > 32768:
                return False
            data = json.loads(raw.decode("utf-8")) if raw else {}
            return int(getattr(response, "status", 200)) == 200 and isinstance(data, dict) and bool(data.get("ok"))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, RuntimeError):
        return False
    except Exception:
        return False
