from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from mwoif_worker.work_security import signed_headers

try:
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None

_ROOT = Path(__file__).resolve().parents[1]
if load_dotenv is not None:
    load_dotenv(_ROOT / ".env", override=False)


class SenderLeaseConfigError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass(slots=True)
class SenderLeaseResult:
    ok: bool
    leased: bool
    code: str
    message: str
    retryable: bool
    http_status: int
    elapsed_ms: float
    sj_id: int = 0
    sender: dict[str, Any] | None = None
    sender_lease_token_present: bool = False

    def safe_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.ok,
            "leased": self.leased,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "http_status": self.http_status,
            "elapsed_ms": round(float(self.elapsed_ms), 3),
            "sj_id": self.sj_id,
            "sender_lease_token_present": self.sender_lease_token_present,
            "secretOutput": "NONE",
        }
        if self.sender is not None:
            payload["sender"] = self.sender
        return payload


def _api_key() -> str:
    value = str(os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
    if len(value) < 32:
        raise SenderLeaseConfigError("MWOIF_WORKER_API_KEY_NOT_CONFIGURED")
    if len(value) > 512:
        raise SenderLeaseConfigError("MWOIF_WORKER_API_KEY_INVALID")
    return value


def _worker_code() -> str:
    value = str(os.getenv("MWOIF_WORKER_CODE") or "LOCAL-01").strip().upper()
    if not value or len(value) > 64:
        raise SenderLeaseConfigError("MWOIF_WORKER_CODE_INVALID")
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
    if any(ch not in allowed for ch in value):
        raise SenderLeaseConfigError("MWOIF_WORKER_CODE_INVALID")
    return value


def _claim_state_path() -> Path:
    raw = str(os.getenv("MWOIF_P3_CLAIM_STATE_FILE") or "state/p3_claim.private.json").strip()
    if not raw:
        raise SenderLeaseConfigError("MWOIF_P3_CLAIM_STATE_FILE_INVALID")
    path = Path(raw)
    if not path.is_absolute():
        path = _ROOT / path
    return path.resolve()


def _sender_state_path() -> Path:
    raw = str(os.getenv("MWOIF_P5_SENDER_LEASE_STATE_FILE") or "state/p5_sender_lease.private.json").strip()
    if not raw:
        raise SenderLeaseConfigError("MWOIF_P5_SENDER_LEASE_STATE_FILE_INVALID")
    path = Path(raw)
    if not path.is_absolute():
        path = _ROOT / path
    return path.resolve()


def _lease_url() -> str:
    url = str(
        os.getenv("MWOIF_WEB_SENDER_LEASE_URL")
        or "http://127.0.0.1/M_woif/work/jobs/sender-lease.php"
    ).strip()
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    path = parts.path or ""
    loopback = host in {"127.0.0.1", "localhost", "::1"}

    if scheme not in {"http", "https"} or not host:
        raise SenderLeaseConfigError("MWOIF_WEB_SENDER_LEASE_URL_INVALID")
    if not path.endswith("/work/jobs/sender-lease.php"):
        raise SenderLeaseConfigError("MWOIF_WEB_SENDER_LEASE_URL_INVALID")
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment:
        raise SenderLeaseConfigError("MWOIF_WEB_SENDER_LEASE_URL_INVALID")
    if not loopback and scheme != "https":
        raise SenderLeaseConfigError("MWOIF_WEB_SENDER_LEASE_HTTPS_REQUIRED")
    return url


def _timeout_seconds() -> int:
    raw = str(os.getenv("MWOIF_WORKER_SENDER_LEASE_TIMEOUT_SECONDS") or "10").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise SenderLeaseConfigError("MWOIF_WORKER_SENDER_LEASE_TIMEOUT_SECONDS_INVALID") from exc
    if value < 3 or value > 30:
        raise SenderLeaseConfigError("MWOIF_WORKER_SENDER_LEASE_TIMEOUT_SECONDS_INVALID")
    return value


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _clear(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def _active_claim(worker_code: str) -> tuple[int, str]:
    state = _read_json(_claim_state_path())
    if not isinstance(state, dict) or state.get("worker_code") != worker_code:
        raise SenderLeaseConfigError("P3_ACTIVE_CLAIM_MISSING")
    claim_token = state.get("claim_token")
    claim_hash = state.get("claim_token_hash")
    job = state.get("job")
    if not isinstance(claim_token, str) or len(claim_token) < 32:
        raise SenderLeaseConfigError("P3_ACTIVE_CLAIM_INVALID")
    if not isinstance(claim_hash, str) or len(claim_hash) != 64:
        raise SenderLeaseConfigError("P3_ACTIVE_CLAIM_INVALID")
    if hashlib.sha256(claim_token.encode("utf-8")).hexdigest() != claim_hash:
        raise SenderLeaseConfigError("P3_ACTIVE_CLAIM_INVALID")
    if not isinstance(job, dict) or str(job.get("service_code") or "") != "HEART_PUMP":
        raise SenderLeaseConfigError("P3_ACTIVE_CLAIM_INVALID")
    try:
        sj_id = int(job.get("sj_id") or 0)
    except Exception as exc:
        raise SenderLeaseConfigError("P3_ACTIVE_CLAIM_INVALID") from exc
    if sj_id < 1:
        raise SenderLeaseConfigError("P3_ACTIVE_CLAIM_INVALID")
    return sj_id, claim_token


def _remote_lease_expired(current: dict[str, Any]) -> bool:
    if str(current.get("phase") or "") != "leased":
        return False
    sender = current.get("sender")
    if not isinstance(sender, dict):
        return False
    raw = sender.get("lease_expires_at")
    if not isinstance(raw, str) or not raw.strip():
        return False
    try:
        expiry = datetime.strptime(raw.strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return expiry <= datetime.now(timezone.utc)


def _pending_sender_state(path: Path, worker_code: str, sj_id: int) -> dict[str, Any]:
    current = _read_json(path)
    if isinstance(current, dict):
        token = current.get("sender_lease_token")
        token_hash = current.get("sender_lease_token_hash")
        valid = (
            current.get("worker_code") == worker_code
            and int(current.get("sj_id") or 0) == sj_id
            and isinstance(token, str)
            and len(token) >= 32
            and isinstance(token_hash, str)
            and len(token_hash) == 64
            and hashlib.sha256(token.encode("utf-8")).hexdigest() == token_hash
        )
        if valid and not _remote_lease_expired(current):
            return current
        if valid and _remote_lease_expired(current):
            _clear(path)

    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    state = {
        "schema": "mwoif-p5-sender-lease-v1",
        "worker_code": worker_code,
        "sj_id": sj_id,
        "phase": "pending",
        "sender_lease_token": token,
        "sender_lease_token_hash": token_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_json(path, state)
    return state


def _safe_json(raw: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("SENDER_LEASE_RESPONSE_INVALID") from exc
    if not isinstance(decoded, dict):
        raise RuntimeError("SENDER_LEASE_RESPONSE_INVALID")
    return decoded


def _safe_sender(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    allowed = {
        "sga_id",
        "game_id",
        "capability",
        "lease_expires_at",
        "lease_seconds",
        "lease_token_fp",
        "selection_strategy",
        "credential_payload_included",
    }
    return {str(k): v for k, v in value.items() if k in allowed}


def sender_lease_once(version: str) -> SenderLeaseResult:
    started = time.perf_counter()
    state_path: Path | None = None
    try:
        api_key = _api_key()
        worker_code = _worker_code()
        sj_id, claim_token = _active_claim(worker_code)
        state_path = _sender_state_path()
        url = _lease_url()
        timeout = _timeout_seconds()
    except SenderLeaseConfigError as exc:
        return SenderLeaseResult(
            ok=False,
            leased=False,
            code=str(exc),
            message="P5 sender lease configuration/claim is incomplete",
            retryable=False,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )

    state = _pending_sender_state(state_path, worker_code, sj_id)
    sender_token = str(state["sender_lease_token"])
    sender_token_hash = str(state["sender_lease_token_hash"])

    body = json.dumps(
        {
            "worker_code": worker_code,
            "version": str(version or "")[:64],
            "sj_id": sj_id,
            "sender_lease_token_hash": sender_token_hash,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    request = Request(
        url,
        data=body,
        method="POST",
        headers=signed_headers(url, body, api_key=api_key, extra={"X-MWOIF-Claim-Token": claim_token, "User-Agent": "MWOIF-Services-Worker/sender-lease-r7"}),
    )
    opener = build_opener(_NoRedirect())

    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(getattr(response, "status", 200))
            raw = response.read(65537)
            if len(raw) > 65536:
                raise RuntimeError("SENDER_LEASE_RESPONSE_TOO_LARGE")
            payload = _safe_json(raw)
    except HTTPError as exc:
        status = int(exc.code or 0)
        try:
            raw = exc.read(65537)
            payload = _safe_json(raw) if raw and len(raw) <= 65536 else {}
        except Exception:
            payload = {}
        code = str(payload.get("code") or "SENDER_LEASE_HTTP_ERROR")
        if status in {400, 401, 403, 405, 413, 415, 422} or code in {
            "SENDER_LEASE_TOKEN_MISMATCH",
            "SENDER_LEASE_TOKEN_STALE",
            "HEART_SENDER_GAME_SCOPE_REQUIRED",
            "HEART_SENDER_GAME_SCOPE_INVALID",
        }:
            _clear(state_path)
        return SenderLeaseResult(
            ok=False,
            leased=False,
            code=code,
            message=str(payload.get("message") or "Sender lease request failed"),
            retryable=bool(payload.get("retryable", status >= 500 or status in {408, 409, 425, 429})),
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
        )
    except (URLError, TimeoutError, OSError):
        # Keep the pending raw token locally. If PHP committed before the network failed,
        # retrying with the same hash will recover the same sender lease.
        return SenderLeaseResult(
            ok=False,
            leased=False,
            code="SENDER_LEASE_NETWORK_ERROR",
            message="Sender lease endpoint is unreachable",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
        )
    except Exception:
        return SenderLeaseResult(
            ok=False,
            leased=False,
            code="SENDER_LEASE_RESPONSE_INVALID",
            message="Sender lease response is invalid",
            retryable=True,
            http_status=0,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
        )

    ok = bool(payload.get("ok"))
    leased = bool(payload.get("leased"))
    code = str(payload.get("code") or "SENDER_LEASE_REJECTED")
    sender = _safe_sender(payload.get("sender"))

    if ok and leased and sender is not None:
        try:
            remote_sga_id = int(sender.get("sga_id") or 0)
        except Exception:
            remote_sga_id = 0
        if remote_sga_id < 1:
            return SenderLeaseResult(
                ok=False,
                leased=False,
                code="SENDER_LEASE_RESPONSE_INVALID",
                message="Sender lease response is incomplete",
                retryable=True,
                http_status=status,
                elapsed_ms=(time.perf_counter() - started) * 1000.0,
                sj_id=sj_id,
            )
        state.update(
            {
                "phase": "leased",
                "sga_id": remote_sga_id,
                "sender": sender,
                "leased_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        _write_json(state_path, state)
        return SenderLeaseResult(
            ok=True,
            leased=True,
            code=code,
            message=str(payload.get("message") or "HEART_SENDER leased"),
            retryable=False,
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
            sender=sender,
            sender_lease_token_present=bool(sender_token),
        )

    if ok and not leased and code == "NO_READY_HEART_SENDER":
        _clear(state_path)
        return SenderLeaseResult(
            ok=True,
            leased=False,
            code=code,
            message=str(payload.get("message") or "No HEART_SENDER is currently available"),
            retryable=True,
            http_status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            sj_id=sj_id,
        )

    _clear(state_path)
    return SenderLeaseResult(
        ok=False,
        leased=False,
        code=code,
        message=str(payload.get("message") or "Sender lease rejected"),
        retryable=bool(payload.get("retryable", True)),
        http_status=status,
        elapsed_ms=(time.perf_counter() - started) * 1000.0,
        sj_id=sj_id,
    )
