from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable

import requests

from mwoif.auth.models import jwt_exp
from mwoif.session.models import AuthRecord
from mwoif_worker.config import WorkerConfig
from mwoif_worker.devplay.context import LoginWebContext, load_login_web_context
from mwoif_worker.devplay.exact_template import _apply_headers
from mwoif_worker.devplay.models import find_login_payload
from mwoif_worker.sender_session_pool import get_sender_session_pool

Event = Callable[[str], None]
REFRESH_URL = "https://account.devplay.com/v3/refresh"


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(str(os.getenv(name) or default).strip())
    except Exception:
        value = default
    return max(lo, min(hi, value))


def _env_bool(name: str, default: bool = False) -> bool:
    raw = str(os.getenv(name) or ("1" if default else "0")).strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _remaining(auth: AuthRecord) -> int | None:
    now = int(time.time())
    values = [jwt_exp(auth.game_access_token), jwt_exp(auth.oven_access_token)]
    known = [int(value) for value in values if value is not None and int(value) > 0]
    if not known:
        return None
    return min(known) - now


@dataclass(slots=True)
class RefreshOutcome:
    sga_id: int
    ok: bool
    code: str
    http_status: int
    elapsed_ms: float
    old_remaining: int | None
    new_remaining: int | None
    auth: AuthRecord | None
    retryable: bool


class AuthKeeperLab:
    def __init__(self, *, stop_event: threading.Event, event_cb: Event | None = None) -> None:
        self.stop_event = stop_event
        self.event_cb = event_cb
        self.enabled = _env_bool("MWOIF_AUTH_KEEPER_LAB_ENABLED", True)
        self.workers = _env_int("MWOIF_AUTH_KEEPER_LAB_WORKERS", 4, 1, 16)
        self.refresh_before = _env_int("MWOIF_AUTH_KEEPER_LAB_REFRESH_BEFORE_SECONDS", 180, 90, 600)
        self.retry_seconds = _env_int("MWOIF_AUTH_KEEPER_LAB_RETRY_SECONDS", 20, 5, 300)
        self.status_seconds = _env_int("MWOIF_AUTH_KEEPER_LAB_STATUS_SECONDS", 30, 10, 300)
        self.max_submit_per_tick = _env_int("MWOIF_AUTH_KEEPER_LAB_MAX_SUBMIT_PER_TICK", 8, 1, 64)
        self.pool = get_sender_session_pool()
        self.cfg = WorkerConfig.load()
        self.context = load_login_web_context(self.cfg.web_context_file, self.cfg.login_url)
        if not self.context.complete:
            raise RuntimeError("AUTH_KEEPER_LAB_WEB_CONTEXT_INCOMPLETE")
        self.headers = self._refresh_headers(self.context)
        self._lock = threading.RLock()
        self._inflight: dict[int, Future[RefreshOutcome]] = {}
        self._retry_at: dict[int, float] = {}
        self._login_required: set[int] = set()
        self._pass = 0
        self._fail = 0
        self._total_ms = 0.0
        self._started = time.monotonic()

    def _emit(self, message: str) -> None:
        if self.event_cb is not None:
            self.event_cb(message)

    def _refresh_headers(self, context: LoginWebContext) -> dict[str, str]:
        template = json.loads(self.cfg.exact_template_file.read_text(encoding="utf-8"))
        login_req = template.get("login") if isinstance(template.get("login"), dict) else {}
        locale = context.query.get("lc.locale_on_game") or "en-US"
        headers = _apply_headers(login_req.get("headers_template") or {}, context=context, locale=locale)
        headers["content-type"] = "application/json"
        headers["accept"] = "application/json, text/plain, */*"
        headers.pop("authorization", None)
        return headers

    def _refresh_one(self, sga_id: int, auth: AuthRecord) -> RefreshOutcome:
        started = time.monotonic()
        old_remaining = _remaining(auth)
        if not auth.refresh_token or not auth.mid or not auth.device_id:
            return RefreshOutcome(sga_id, False, "REFRESH_INPUT_MISSING", 0, 0.0, old_remaining, None, None, False)
        body = {
            "device_id": auth.device_id,
            "mid": auth.mid,
            "refresh_token": auth.refresh_token,
        }
        try:
            response = requests.post(
                REFRESH_URL,
                data=json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
                headers=dict(self.headers),
                timeout=self.cfg.timeout_seconds,
                verify=self.cfg.verify_ssl,
                allow_redirects=False,
            )
            elapsed_ms = (time.monotonic() - started) * 1000.0
            try:
                parsed = response.json()
            except Exception:
                parsed = None
            if not (200 <= response.status_code < 300):
                retryable = response.status_code in {408, 409, 425, 429} or response.status_code >= 500
                return RefreshOutcome(sga_id, False, "REFRESH_HTTP_FAILED", int(response.status_code), elapsed_ms, old_remaining, None, None, retryable)
            hit = find_login_payload(parsed)
            if hit is None:
                return RefreshOutcome(sga_id, False, "REFRESH_RESPONSE_NO_LOGIN_PAYLOAD", int(response.status_code), elapsed_ms, old_remaining, None, None, True)
            game_token = str(hit.get("game_access_token") or hit.get("gameAccessToken") or "").strip()
            oven_token = str(hit.get("oven_access_token") or hit.get("ovenAccessToken") or "").strip()
            refresh_token = str(hit.get("refresh_token") or hit.get("refreshToken") or auth.refresh_token).strip()
            member = hit.get("member") if isinstance(hit.get("member"), dict) else {}
            response_mid = str(member.get("mid") or hit.get("mid") or hit.get("player_id") or hit.get("playerId") or auth.mid).strip()
            if not game_token or not oven_token:
                return RefreshOutcome(sga_id, False, "REFRESH_RESPONSE_INVALID", int(response.status_code), elapsed_ms, old_remaining, None, None, True)
            if response_mid != auth.mid:
                return RefreshOutcome(sga_id, False, "REFRESH_MID_MISMATCH", int(response.status_code), elapsed_ms, old_remaining, None, None, False)
            new_auth = AuthRecord(
                schema=auth.schema,
                account_kind=auth.account_kind,
                account_id=auth.account_id,
                mid=auth.mid,
                refresh_token=refresh_token,
                game_access_token=game_token,
                oven_access_token=oven_token,
                device_secret=str(hit.get("device_secret") or hit.get("deviceSecret") or auth.device_secret).strip(),
                fgs_id=auth.fgs_id,
                device_id=auth.device_id,
                login_type=auth.login_type,
                metadata=dict(auth.metadata),
                imported_at=auth.imported_at,
            )
            return RefreshOutcome(sga_id, True, "REFRESH_OK", int(response.status_code), elapsed_ms, old_remaining, _remaining(new_auth), new_auth, False)
        except requests.Timeout:
            return RefreshOutcome(sga_id, False, "REFRESH_TIMEOUT", 0, (time.monotonic() - started) * 1000.0, old_remaining, None, None, True)
        except requests.RequestException:
            return RefreshOutcome(sga_id, False, "REFRESH_NETWORK_ERROR", 0, (time.monotonic() - started) * 1000.0, old_remaining, None, None, True)
        except Exception as exc:
            return RefreshOutcome(sga_id, False, f"REFRESH_INTERNAL_{type(exc).__name__}"[:80], 0, (time.monotonic() - started) * 1000.0, old_remaining, None, None, True)

    def _collect_finished(self) -> None:
        now = time.monotonic()
        finished: list[tuple[int, Future[RefreshOutcome]]] = []
        with self._lock:
            for sga_id, future in list(self._inflight.items()):
                if future.done():
                    finished.append((sga_id, future))
                    self._inflight.pop(sga_id, None)
        for sga_id, future in finished:
            try:
                outcome = future.result()
            except Exception as exc:
                outcome = RefreshOutcome(sga_id, False, f"REFRESH_FUTURE_{type(exc).__name__}"[:80], 0, 0.0, None, None, None, True)
            if outcome.ok and outcome.auth is not None and self.pool.lab_replace_auth(sga_id, outcome.auth, source="lab-refresh"):
                with self._lock:
                    self._pass += 1
                    self._total_ms += outcome.elapsed_ms
                    self._retry_at.pop(sga_id, None)
                    self._login_required.discard(sga_id)
                self._emit(
                    f"LAB AUTH REFRESH PASS sga_id={sga_id} oldRemaining={outcome.old_remaining} "
                    f"newRemaining={outcome.new_remaining} http={outcome.http_status} elapsedMs={outcome.elapsed_ms:.0f} "
                    "fullLogin=false secretOutput=NONE"
                )
            else:
                with self._lock:
                    self._fail += 1
                    if outcome.retryable:
                        self._retry_at[sga_id] = now + float(self.retry_seconds)
                    else:
                        self._login_required.add(sga_id)
                state = "RETRY" if outcome.retryable else "LOGIN_REQUIRED"
                self._emit(
                    f"LAB AUTH REFRESH FAIL sga_id={sga_id} code={outcome.code} http={outcome.http_status} "
                    f"state={state} elapsedMs={outcome.elapsed_ms:.0f} fullLoginFallback=false secretOutput=NONE"
                )

    def _submit_due(self, executor: ThreadPoolExecutor) -> None:
        now = time.monotonic()
        snapshots = self.pool.lab_refresh_snapshot()
        candidates: list[tuple[int, int | None, AuthRecord]] = []
        with self._lock:
            inflight = set(self._inflight)
            login_required = set(self._login_required)
            retry_at = dict(self._retry_at)
        for sga_id, auth, _session, _email_fp in snapshots:
            if sga_id in inflight or sga_id in login_required:
                continue
            retry_deadline = retry_at.get(sga_id)
            if retry_deadline is not None and now < retry_deadline:
                continue
            remaining = _remaining(auth)
            if remaining is None or remaining <= self.refresh_before:
                candidates.append((sga_id, remaining, auth))
        candidates.sort(key=lambda item: -999999 if item[1] is None else int(item[1]))
        submitted = 0
        for sga_id, remaining, auth in candidates:
            if submitted >= self.max_submit_per_tick:
                break
            with self._lock:
                if sga_id in self._inflight:
                    continue
                future = executor.submit(self._refresh_one, sga_id, auth)
                self._inflight[sga_id] = future
            submitted += 1
            self._emit(
                f"LAB AUTH REFRESH START sga_id={sga_id} remaining={remaining} "
                f"threshold={self.refresh_before}s secretOutput=NONE"
            )

    def _status(self) -> None:
        snapshots = self.pool.lab_refresh_snapshot()
        ready = 0
        due = 0
        stale = 0
        for _sga_id, auth, _session, _email_fp in snapshots:
            remaining = _remaining(auth)
            if remaining is None or remaining <= 0:
                stale += 1
            elif remaining <= self.refresh_before:
                due += 1
            else:
                ready += 1
        with self._lock:
            inflight = len(self._inflight)
            login_required = len(self._login_required)
            passed = self._pass
            failed = self._fail
            avg = (self._total_ms / passed) if passed else 0.0
        stats = self.pool.stats()
        self._emit(
            f"LAB AUTH KEEPER STATUS cached={len(snapshots)} ready={ready} due={due} stale={stale} "
            f"refreshing={inflight} loginRequired={login_required} pass={passed} fail={failed} "
            f"avgRefreshMs={avg:.0f} poolHits={stats.get('hits',0)} poolMisses={stats.get('misses',0)} "
            f"uptime={int(time.monotonic()-self._started)}s secretOutput=NONE"
        )

    def run(self) -> None:
        if not self.enabled:
            self._emit("LAB AUTH KEEPER disabled=true secretOutput=NONE")
            return
        self._emit(
            f"LAB AUTH KEEPER READY workers={self.workers} refreshBefore={self.refresh_before}s "
            f"fullLoginFallback=false cacheMode=LAB_ONLY secretOutput=NONE"
        )
        next_status = 0.0
        with ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="lab-auth-refresh") as executor:
            while not self.stop_event.is_set():
                self._collect_finished()
                self._submit_due(executor)
                now = time.monotonic()
                if now >= next_status:
                    self._status()
                    next_status = now + float(self.status_seconds)
                self.stop_event.wait(0.5)
            self._collect_finished()
        self._status()
        self._emit("LAB AUTH KEEPER STOP secretOutput=NONE")
