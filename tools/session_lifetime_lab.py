from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def load_env(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip()


load_env(ROOT / ".env")
load_env(ROOT / "SESSION_LIFETIME_LAB.env")

from mwoif.friend.service import list_friends
from mwoif.heart.mailbox import mailbox_read
from mwoif_worker.heart_one import _login_and_session


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = str(os.getenv(name) or default).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"[CONFIG_ERROR] {name} invalid") from exc
    if value < minimum or value > maximum:
        raise SystemExit(f"[CONFIG_ERROR] {name} out of range")
    return value


def env_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw = str(os.getenv(name) or default).strip()
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(f"[CONFIG_ERROR] {name} invalid") from exc
    if value < minimum or value > maximum:
        raise SystemExit(f"[CONFIG_ERROR] {name} out of range")
    return value


def iso_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def fmt_elapsed(seconds: float) -> str:
    total = max(0, int(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def exp_text(epoch_seconds: int | None) -> str:
    if not epoch_seconds:
        return "unknown"
    try:
        return datetime.fromtimestamp(int(epoch_seconds), tz=timezone.utc).astimezone().isoformat(timespec="seconds")
    except Exception:
        return "unknown"


def safe_code(result: dict) -> str:
    return str(
        result.get("grpc_code")
        or result.get("error")
        or result.get("response_code")
        or result.get("http_status")
        or ("OK" if result.get("ok") else "FAILED")
    )[:80]


def auth_failure(result: dict) -> bool:
    code = str(result.get("grpc_code") or result.get("error") or "").upper()
    return code in {"UNAUTHENTICATED", "PERMISSION_DENIED"} or "AUTH" in code and "NETWORK" not in code


def main() -> int:
    email = str(os.getenv("MWOIF_SESSION_LAB_EMAIL") or "demo102@gmail.com").strip()
    password = str(os.getenv("MWOIF_SESSION_LAB_PASSWORD") or "")
    interval = env_int("MWOIF_SESSION_LAB_INTERVAL_SECONDS", 60, 30, 3600)
    duration_hours = env_float("MWOIF_SESSION_LAB_DURATION_HOURS", 24.0, 0.25, 168.0)
    failure_threshold = env_int("MWOIF_SESSION_LAB_FAILURE_THRESHOLD", 3, 1, 10)
    ds_check = str(os.getenv("MWOIF_SESSION_LAB_DS_CHECK") or "1").strip().lower() in {"1", "true", "yes", "on"}

    if not email or not password:
        print("[CONFIG_ERROR] set MWOIF_SESSION_LAB_EMAIL and MWOIF_SESSION_LAB_PASSWORD in SESSION_LIFETIME_LAB.env")
        return 2

    log_dir = ROOT / "state" / "session-lifetime-lab"
    log_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = log_dir / f"session_lifetime_{stamp}.log"

    def emit(text: str) -> None:
        line = f"[{iso_now()}] {text}"
        print(line, flush=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    emit(f"START interval={interval}s duration={duration_hours:g}h threshold={failure_threshold} dsCheck={1 if ds_check else 0} secretOutput=NONE")
    emit("LOGIN_ONCE starting")
    try:
        cfg, auth, session = _login_and_session(
            email=email,
            password=password,
            account_kind="session-lifetime-lab",
            account_id=0,
            slot="R",
            event_cb=None,
        )
    except Exception as exc:
        code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
        stage = str(getattr(exc, "stage", None) or "LOGIN")[:40]
        emit(f"LOGIN_FAILED code={code} stage={stage} secretOutput=NONE")
        return 3

    summary = auth.public_summary()
    emit(
        "LOGIN_OK "
        f"midPresent={1 if summary.get('mid_present') else 0} "
        f"memberSeqPresent={1 if session.member_seq > 0 else 0} "
        f"gameExp={exp_text(summary.get('game_exp'))} "
        f"ovenExp={exp_text(summary.get('oven_exp'))} "
        "secretOutput=NONE"
    )
    emit(f"LOG_FILE={log_path}")

    started = time.monotonic()
    deadline = started + duration_hours * 3600.0
    check_no = 0
    friend_failures = 0
    ds_failures = 0
    friend_first_failure: float | None = None
    ds_first_failure: float | None = None
    friend_expired = False
    ds_expired = False

    while True:
        now = time.monotonic()
        if now >= deadline:
            break
        check_no += 1
        elapsed = now - started

        friend = list_friends(
            cfg=cfg,
            slot="R",
            auth=auth,
            timeout=float(cfg.workflow.get("grpc_timeout_seconds") or 12),
            live=True,
            capacity=300,
            include_player_ids=False,
        )
        friend_ok = bool(friend.get("ok"))
        if friend_ok:
            friend_failures = 0
        else:
            friend_failures += 1
            if friend_first_failure is None:
                friend_first_failure = elapsed
            if auth_failure(friend) and friend_failures >= failure_threshold:
                friend_expired = True

        ds_ok = True
        ds_code = "SKIP"
        if ds_check:
            ds = mailbox_read(
                cfg=cfg,
                slot="R",
                session=session,
                auth=auth,
                from_member_seq=None,
                live=True,
                timeout=float(cfg.workflow.get("ds_timeout_seconds") or 20),
            )
            ds_ok = bool(ds.get("ok"))
            ds_code = safe_code(ds)
            if ds_ok:
                ds_failures = 0
            else:
                ds_failures += 1
                if ds_first_failure is None:
                    ds_first_failure = elapsed
                if ds_failures >= failure_threshold:
                    ds_expired = True

        emit(
            f"CHECK #{check_no} elapsed={fmt_elapsed(elapsed)} "
            f"friend={'OK' if friend_ok else 'FAIL'} friendCode={safe_code(friend)} friendFails={friend_failures} "
            f"ds={'OK' if ds_ok else 'FAIL'} dsCode={ds_code} dsFails={ds_failures} "
            "relogin=0 refresh=0 secretOutput=NONE"
        )

        if friend_expired or (ds_check and ds_expired):
            emit(
                f"SESSION_INVALID_CONFIRMED elapsed={fmt_elapsed(elapsed)} "
                f"friendExpired={1 if friend_expired else 0} dsExpired={1 if ds_expired else 0} "
                f"threshold={failure_threshold} secretOutput=NONE"
            )
            emit("RESULT=EXPIRED_OR_UNUSABLE")
            return 10

        sleep_for = min(float(interval), max(0.0, deadline - time.monotonic()))
        if sleep_for > 0:
            time.sleep(sleep_for)

    elapsed = time.monotonic() - started
    emit(
        f"RESULT=VALID_AT_END elapsed={fmt_elapsed(elapsed)} "
        f"friendFirstFailure={fmt_elapsed(friend_first_failure) if friend_first_failure is not None else 'none'} "
        f"dsFirstFailure={fmt_elapsed(ds_first_failure) if ds_first_failure is not None else 'none'} secretOutput=NONE"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[STOPPED] user interrupted; no relogin or refresh was performed", flush=True)
        raise SystemExit(130)
