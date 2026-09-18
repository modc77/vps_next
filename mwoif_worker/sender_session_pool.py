from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

from mwoif.auth.models import jwt_exp
from mwoif.session.models import AuthRecord, SessionRecord
from mwoif_worker.account_fault_policy import classify

Event = Callable[[str], None]
_ROOT = Path(__file__).resolve().parents[1]
if load_dotenv is not None:
    load_dotenv(_ROOT / ".env", override=False)


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(str(os.getenv(name) or default).strip())
    except Exception:
        value = default
    return max(lo, min(hi, value))


def _env_bool(name: str, default: bool = True) -> bool:
    raw = str(os.getenv(name) or ("1" if default else "0")).strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _email_fp(email: str) -> str:
    value = str(email or "").strip().lower()
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


@dataclass(slots=True)
class SenderSessionEntry:
    sga_id: int
    auth: AuthRecord
    session: SessionRecord
    email_fp: str
    created_mono: float
    last_used_mono: float
    created_wall: int
    last_used_wall: int
    source: str = "memory"


class SenderSessionPool:
    _SCHEMA = "mwoif-sender-session-cache-v2"

    def __init__(self) -> None:
        self.enabled = _env_bool("MWOIF_SENDER_SESSION_CACHE_ENABLED", True)
        self.idle_ttl_seconds = _env_int("MWOIF_SENDER_SESSION_TTL_SECONDS", 604800, 300, 2592000)
        self.ttl_seconds = _env_int("MWOIF_SENDER_SESSION_ABSOLUTE_TTL_SECONDS", 1800, 300, 2592000)
        self.max_entries = _env_int("MWOIF_SENDER_SESSION_POOL_MAX", 1000, 10, 5000)
        self.preferred_limit = _env_int("MWOIF_SENDER_SESSION_PREFERRED_LIMIT", 500, 10, 1000)
        self.persistent_enabled = _env_bool("MWOIF_SENDER_SESSION_PERSIST_ENABLED", True)
        self.persistent_max_age_seconds = _env_int(
            "MWOIF_SENDER_SESSION_PERSIST_MAX_AGE_SECONDS",
            2592000,
            3600,
            7776000,
        )
        raw_dir = str(os.getenv("MWOIF_SENDER_SESSION_STORE_DIR") or "state/sender-session-cache").strip()
        store_dir = Path(raw_dir)
        if not store_dir.is_absolute():
            store_dir = _ROOT / store_dir
        self.store_dir = store_dir.resolve()
        self._lock = threading.RLock()
        self._entries: OrderedDict[int, SenderSessionEntry] = OrderedDict()
        self._hits = 0
        self._persistent_hits = 0
        self._misses = 0
        self._puts = 0
        self._evictions = 0
        self._persist_writes = 0
        self._persist_errors = 0
        self._load_persistent_index()

    def _store_key(self) -> bytes | None:
        if not self.persistent_enabled:
            return None
        api_key = str(os.getenv("MWOIF_WORKER_API_KEY") or "").strip()
        if len(api_key) < 32:
            return None
        return hashlib.sha256(b"MWOIF-SENDER-SESSION-STORE-V2\x00" + api_key.encode("utf-8")).digest()

    def _record_path(self, sga_id: int) -> Path:
        return self.store_dir / f"{int(sga_id)}.bin"

    @staticmethod
    def _aad(sga_id: int) -> bytes:
        return f"MWOIF-SENDER-SESSION-V2:{int(sga_id)}".encode("ascii")

    @staticmethod
    def _auth_from_dict(value: object) -> AuthRecord | None:
        if not isinstance(value, dict):
            return None
        try:
            metadata_raw = value.get("metadata")
            metadata = {str(k): str(v) for k, v in metadata_raw.items()} if isinstance(metadata_raw, dict) else {}
            record = AuthRecord(
                schema=str(value.get("schema") or "mwoif-heart-v3-auth-runtime"),
                account_kind=str(value.get("account_kind") or "sender"),
                account_id=_safe_int(value.get("account_id")),
                mid=str(value.get("mid") or ""),
                refresh_token=str(value.get("refresh_token") or ""),
                game_access_token=str(value.get("game_access_token") or ""),
                oven_access_token=str(value.get("oven_access_token") or ""),
                device_secret=str(value.get("device_secret") or ""),
                fgs_id=str(value.get("fgs_id") or ""),
                device_id=str(value.get("device_id") or ""),
                login_type=str(value.get("login_type") or "email"),
                metadata=metadata,
                imported_at=str(value.get("imported_at") or ""),
            )
            return record if record.ready else None
        except Exception:
            return None

    @staticmethod
    def _session_from_dict(value: object) -> SessionRecord | None:
        if not isinstance(value, dict):
            return None
        try:
            record = SessionRecord(
                schema=str(value.get("schema") or "mwoif-heart-v3-session-runtime"),
                account_kind=str(value.get("account_kind") or "sender"),
                account_id=_safe_int(value.get("account_id")),
                member_seq=_safe_int(value.get("member_seq")),
                current_lv=_safe_int(value.get("current_lv")),
                session_key=str(value.get("session_key") or ""),
                source=str(value.get("source") or "persistent_cache"),
                imported_at=str(value.get("imported_at") or ""),
            )
            return record if record.established else None
        except Exception:
            return None

    @staticmethod
    def _token_expired(auth: AuthRecord, margin_seconds: int = 60) -> bool:
        now = int(time.time()) + max(0, int(margin_seconds))
        expiries = [jwt_exp(auth.game_access_token), jwt_exp(auth.oven_access_token)]
        known = [int(exp) for exp in expiries if exp is not None and int(exp) > 0]
        return bool(known) and min(known) <= now

    def _decode_file(self, path: Path, sga_id: int) -> SenderSessionEntry | None:
        key = self._store_key()
        if key is None:
            return None
        try:
            raw = path.read_bytes()
            if len(raw) < 13 or len(raw) > 131072:
                return None
            nonce, ciphertext = raw[:12], raw[12:]
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, self._aad(sga_id))
            data = json.loads(plaintext.decode("utf-8"))
            if not isinstance(data, dict) or data.get("schema") != self._SCHEMA:
                return None
            if _safe_int(data.get("sga_id")) != int(sga_id):
                return None
            created_wall = _safe_int(data.get("created_wall"))
            last_used_wall = _safe_int(data.get("last_used_wall"), created_wall)
            now_wall = int(time.time())
            age_seconds = now_wall - created_wall
            if (
                created_wall <= 0
                or age_seconds < 0
                or age_seconds >= self.ttl_seconds
                or age_seconds > self.persistent_max_age_seconds
            ):
                return None
            auth = self._auth_from_dict(data.get("auth"))
            session = self._session_from_dict(data.get("session"))
            if auth is None or session is None or self._token_expired(auth):
                return None
            now_mono = time.monotonic()
            return SenderSessionEntry(
                sga_id=int(sga_id),
                auth=auth,
                session=session,
                email_fp=str(data.get("email_fp") or "")[:32],
                created_mono=now_mono,
                last_used_mono=now_mono,
                created_wall=created_wall,
                last_used_wall=last_used_wall,
                source="persistent",
            )
        except Exception:
            return None

    def _persist_entry_locked(self, entry: SenderSessionEntry) -> None:
        key = self._store_key()
        if key is None:
            return
        try:
            self.store_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema": self._SCHEMA,
                "sga_id": int(entry.sga_id),
                "email_fp": entry.email_fp,
                "created_wall": int(entry.created_wall),
                "last_used_wall": int(entry.last_used_wall),
                "auth": asdict(entry.auth),
                "session": asdict(entry.session),
            }
            plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            nonce = os.urandom(12)
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, self._aad(entry.sga_id))
            path = self._record_path(entry.sga_id)
            tmp = path.with_suffix(".tmp")
            tmp.write_bytes(nonce + ciphertext)
            try:
                os.chmod(tmp, 0o600)
            except Exception:
                pass
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except Exception:
                pass
            self._persist_writes += 1
        except Exception:
            self._persist_errors += 1

    def _delete_persistent_locked(self, sga_id: int) -> None:
        if not self.persistent_enabled:
            return
        try:
            self._record_path(sga_id).unlink(missing_ok=True)
        except Exception:
            self._persist_errors += 1

    def _load_persistent_index(self) -> None:
        if not self.enabled or not self.persistent_enabled or self._store_key() is None:
            return
        try:
            self.store_dir.mkdir(parents=True, exist_ok=True)
            files = sorted(self.store_dir.glob("*.bin"), key=lambda p: p.stat().st_mtime, reverse=True)[: self.max_entries]
        except Exception:
            self._persist_errors += 1
            return
        loaded: list[SenderSessionEntry] = []
        for path in files:
            try:
                sga_id = int(path.stem)
            except Exception:
                continue
            if sga_id < 1:
                continue
            entry = self._decode_file(path, sga_id)
            if entry is None:
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass
                continue
            loaded.append(entry)
        loaded.sort(key=lambda item: item.last_used_wall)
        with self._lock:
            for entry in loaded:
                self._entries[entry.sga_id] = entry

    def _purge_locked(self, now: float) -> None:
        expired: list[int] = []
        now_wall = int(time.time())
        for sga_id, entry in self._entries.items():
            age_seconds = now_wall - entry.created_wall
            if (
                now - entry.last_used_mono >= self.idle_ttl_seconds
                or entry.created_wall <= 0
                or age_seconds < 0
                or age_seconds >= self.ttl_seconds
                or not entry.auth.ready
                or not entry.session.established
                or self._token_expired(entry.auth)
                or age_seconds > self.persistent_max_age_seconds
            ):
                expired.append(sga_id)
        for sga_id in expired:
            self._entries.pop(sga_id, None)
            self._delete_persistent_locked(sga_id)
            self._evictions += 1
        while len(self._entries) > self.max_entries:
            sga_id, _entry = self._entries.popitem(last=False)
            self._delete_persistent_locked(sga_id)
            self._evictions += 1

    def get(self, sga_id: int, email: str = "") -> tuple[AuthRecord, SessionRecord] | None:
        if not self.enabled or sga_id < 1:
            return None
        now = time.monotonic()
        with self._lock:
            self._purge_locked(now)
            entry = self._entries.get(int(sga_id))
            if entry is None and self.persistent_enabled:
                entry = self._decode_file(self._record_path(int(sga_id)), int(sga_id))
                if entry is not None:
                    self._entries[int(sga_id)] = entry
                    self._persistent_hits += 1
            if entry is None:
                self._misses += 1
                return None
            fp = _email_fp(email)
            if fp and entry.email_fp and not hmac.compare_digest(fp, entry.email_fp):
                self._entries.pop(int(sga_id), None)
                self._delete_persistent_locked(int(sga_id))
                self._evictions += 1
                self._misses += 1
                return None
            if self._token_expired(entry.auth):
                self._entries.pop(int(sga_id), None)
                self._delete_persistent_locked(int(sga_id))
                self._evictions += 1
                self._misses += 1
                return None
            entry.last_used_mono = now
            entry.last_used_wall = int(time.time())
            self._entries.move_to_end(int(sga_id), last=True)
            self._hits += 1
            return entry.auth, entry.session

    def put(self, sga_id: int, email: str, auth: AuthRecord, session: SessionRecord) -> None:
        if not self.enabled or sga_id < 1 or not auth.ready or not session.established or self._token_expired(auth):
            return
        now_mono = time.monotonic()
        now_wall = int(time.time())
        with self._lock:
            entry = SenderSessionEntry(
                sga_id=int(sga_id),
                auth=auth,
                session=session,
                email_fp=_email_fp(email),
                created_mono=now_mono,
                last_used_mono=now_mono,
                created_wall=now_wall,
                last_used_wall=now_wall,
                source="fresh",
            )
            self._entries[int(sga_id)] = entry
            self._entries.move_to_end(int(sga_id), last=True)
            self._puts += 1
            self._persist_entry_locked(entry)
            self._purge_locked(now_mono)

    def invalidate(self, sga_id: int) -> bool:
        with self._lock:
            removed = self._entries.pop(int(sga_id), None)
            existed = removed is not None or self._record_path(int(sga_id)).exists()
            self._delete_persistent_locked(int(sga_id))
            if existed:
                self._evictions += 1
            return existed

    def preferred_ids(self, limit: int | None = None) -> list[int]:
        if not self.enabled:
            return []
        now = time.monotonic()
        with self._lock:
            self._purge_locked(now)
            cap = self.preferred_limit if limit is None else max(1, min(self.preferred_limit, int(limit)))
            keys = list(self._entries.keys())
            keys.reverse()
            return keys[:cap]

    def stats(self) -> dict[str, int | bool]:
        now = time.monotonic()
        with self._lock:
            self._purge_locked(now)
            return {
                "enabled": self.enabled,
                "size": len(self._entries),
                "ttl_seconds": self.ttl_seconds,
                "idle_ttl_seconds": self.idle_ttl_seconds,
                "max_entries": self.max_entries,
                "hits": self._hits,
                "persistent_hits": self._persistent_hits,
                "misses": self._misses,
                "puts": self._puts,
                "evictions": self._evictions,
                "persistent_enabled": self.persistent_enabled,
                "persistent_max_age_seconds": self.persistent_max_age_seconds,
                "persistent_writes": self._persist_writes,
                "persistent_errors": self._persist_errors,
            }


def is_ip_suspect_code(code: str) -> bool:
    return classify(code).error_class == "network_fault"


class LoginCircuitBreaker:
    def __init__(self) -> None:
        self.enabled = _env_bool("MWOIF_LOGIN_CIRCUIT_ENABLED", True)
        provider_threshold = _env_int("MWOIF_PROVIDER_GUARD_FAILURES", 15, 10, 50)
        configured = _env_int("MWOIF_LOGIN_CIRCUIT_FAILURES", 15, 2, 50)
        self.threshold = max(provider_threshold, configured)
        self.window_seconds = max(
            _env_int("MWOIF_LOGIN_CIRCUIT_WINDOW_SECONDS", 180, 3, 900),
            _env_int("MWOIF_PROVIDER_GUARD_WINDOW_SECONDS", 180, 30, 900),
        )
        self.cooldown_seconds = _env_int("MWOIF_LOGIN_CIRCUIT_COOLDOWN_SECONDS", 60, 10, 1800)
        self.max_cooldown_seconds = _env_int("MWOIF_LOGIN_CIRCUIT_MAX_COOLDOWN_SECONDS", 300, 30, 3600)
        self._cond = threading.Condition(threading.RLock())
        self._recent: deque[tuple[float, int]] = deque()
        self._state = "closed"
        self._open_until = 0.0
        self._open_count = 0
        self._probe_owner = 0

    def _trim_locked(self, now: float) -> None:
        cutoff = now - float(self.window_seconds)
        while self._recent and self._recent[0][0] < cutoff:
            self._recent.popleft()

    def _open_locked(self, now: float) -> int:
        self._open_count = max(1, self._open_count + 1)
        delay = min(self.max_cooldown_seconds, self.cooldown_seconds * (2 ** max(0, self._open_count - 1)))
        self._state = "open"
        self._open_until = now + float(delay)
        self._probe_owner = 0
        self._cond.notify_all()
        return int(delay)

    def before_login(self, account_id: int, event_cb: Event | None = None) -> str:
        if not self.enabled:
            return "normal"
        with self._cond:
            now = time.monotonic()
            if self._state == "closed":
                return "normal"
            if self._state == "open":
                if self._open_until > now:
                    return "blocked"
                self._state = "half_open"
                self._probe_owner = int(account_id)
                return "probe"
            return "blocked"

    def record_success(self, account_id: int, probe: bool, event_cb: Event | None = None) -> None:
        if not self.enabled:
            return
        with self._cond:
            if self._state == "half_open" and (probe or self._probe_owner == int(account_id)):
                self._state = "closed"
                self._open_until = 0.0
                self._open_count = 0
                self._probe_owner = 0
                self._recent.clear()
                self._cond.notify_all()
                if event_cb is not None:
                    event_cb("P10.1 LOGIN CIRCUIT CLOSED probe=pass secretOutput=NONE")

    def record_failure(self, account_id: int, code: str, probe: bool, event_cb: Event | None = None) -> bool:
        if not self.enabled:
            return False
        code = str(code or "").strip().upper()
        with self._cond:
            now = time.monotonic()
            if not is_ip_suspect_code(code):
                if self._state == "half_open" and (probe or self._probe_owner == int(account_id)):
                    self._state = "closed"
                    self._open_until = 0.0
                    self._open_count = 0
                    self._probe_owner = 0
                    self._recent.clear()
                    self._cond.notify_all()
                return False
            if self._state == "half_open" and (probe or self._probe_owner == int(account_id)):
                delay = self._open_locked(now)
                if event_cb is not None:
                    event_cb(f"P10.1 LOGIN CIRCUIT REOPEN cooldown={delay}s code={code} secretOutput=NONE")
                return True
            self._trim_locked(now)
            self._recent.append((now, int(account_id)))
            distinct = {account for _, account in self._recent}
            if self._state == "closed" and len(distinct) >= self.threshold:
                self._open_count = 0
                delay = self._open_locked(now)
                if event_cb is not None:
                    event_cb(
                        f"P10.1 LOGIN CIRCUIT OPEN distinct={len(distinct)} window={self.window_seconds}s "
                        f"cooldown={delay}s code={code} secretOutput=NONE"
                    )
                return True
            return self._state in {"open", "half_open"}

    def reset(self) -> None:
        with self._cond:
            self._recent.clear()
            self._state = "closed"
            self._open_until = 0.0
            self._open_count = 0
            self._probe_owner = 0
            self._cond.notify_all()

    def snapshot(self) -> dict[str, int | str | bool]:
        with self._cond:
            now = time.monotonic()
            remaining = max(0, int(self._open_until - now + 0.999)) if self._state == "open" else 0
            self._trim_locked(now)
            return {
                "enabled": self.enabled,
                "state": self._state,
                "remaining_seconds": remaining,
                "recent_distinct_failures": len({account for _, account in self._recent}),
                "threshold": self.threshold,
            }


_POOL = SenderSessionPool()
_CIRCUIT = LoginCircuitBreaker()


def get_sender_session_pool() -> SenderSessionPool:
    return _POOL


def get_login_circuit() -> LoginCircuitBreaker:
    return _CIRCUIT
