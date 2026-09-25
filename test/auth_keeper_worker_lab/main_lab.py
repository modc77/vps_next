from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RUNTIME = HERE / "runtime"
LAB_STATE = ROOT / "state" / "auth-keeper-worker-lab"


def _abs_env(name: str, default_rel: str) -> None:
    raw = str(os.getenv(name) or default_rel).strip()
    path = Path(raw)
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    os.environ[name] = str(path)


def configure_environment() -> None:
    if load_dotenv is not None:
        load_dotenv(ROOT / ".env", override=False)

    LAB_STATE.mkdir(parents=True, exist_ok=True)
    _abs_env("MWOIF_DEVPLAY_WEB_CONTEXT_FILE", "state/login_web_context.private.json")
    _abs_env("MWOIF_DEVPLAY_HTTP_EXACT_TEMPLATE_FILE", "state/http_login_exact_template_receiver.private.json")
    _abs_env("MWOIF_PROVIDER_ROUTER_REBOOT_SCRIPT", "tools/ZTE_F616_Reboot_Worker.bat")

    os.environ["MWOIF_WORKER_PROCESS_LOCK_FILE"] = str((ROOT / "state" / "worker-service.lock").resolve())
    os.environ["MWOIF_SENDER_SESSION_STORE_DIR"] = str((LAB_STATE / "sender-session-cache").resolve())
    os.environ["MWOIF_P3_CLAIM_STATE_FILE"] = str((LAB_STATE / "p3_claim.private.json").resolve())
    os.environ["MWOIF_P5_SENDER_LEASE_STATE_FILE"] = str((LAB_STATE / "p5_sender_lease.private.json").resolve())
    os.environ["MWOIF_P7_HEART_ONE_STATE_FILE"] = str((LAB_STATE / "p7_heart_one.private.json").resolve())
    os.environ["MWOIF_HEART_RELATIONSHIP_JOURNAL_DIR"] = str((LAB_STATE / "heart_relationship_journal").resolve())
    os.environ["MWOIF_LOG_DIR"] = str((LAB_STATE / "logs").resolve())

    os.environ["MWOIF_SENDER_SESSION_CACHE_ENABLED"] = "1"
    os.environ["MWOIF_SENDER_SESSION_PERSIST_ENABLED"] = "1"
    os.environ["MWOIF_SENDER_SESSION_TTL_SECONDS"] = "604800"
    os.environ["MWOIF_SENDER_SESSION_ABSOLUTE_TTL_SECONDS"] = "604800"
    os.environ["MWOIF_SENDER_SESSION_PERSIST_MAX_AGE_SECONDS"] = "2592000"
    os.environ["MWOIF_SENDER_SESSION_POOL_MAX"] = "5000"
    os.environ["MWOIF_SENDER_SESSION_PREFERRED_LIMIT"] = "5000"

    os.environ["MWOIF_AUTH_KEEPER_LAB_ENABLED"] = "1"
    os.environ["MWOIF_AUTH_KEEPER_LAB_CAPTURE_CONTROL_LOGIN"] = "1"
    os.environ.setdefault("MWOIF_AUTH_KEEPER_LAB_WORKERS", "4")
    os.environ.setdefault("MWOIF_AUTH_KEEPER_LAB_REFRESH_BEFORE_SECONDS", "180")
    os.environ.setdefault("MWOIF_AUTH_KEEPER_LAB_RETRY_SECONDS", "20")
    os.environ.setdefault("MWOIF_AUTH_KEEPER_LAB_STATUS_SECONDS", "30")
    os.environ.setdefault("MWOIF_AUTH_KEEPER_LAB_MAX_SUBMIT_PER_TICK", "8")

    sys.path.insert(0, str(RUNTIME))
    sys.path.insert(1, str(ROOT))
    os.chdir(ROOT)


def _emit(text: str) -> None:
    print(text, flush=True)


def cmd_preflight() -> int:
    from mwoif_worker.preflight import run_preflight

    result = run_preflight()
    result["lab"] = "AUTH_KEEPER_WORKER_LAB_V1"
    result["productionWorker"] = "MUST_BE_STOPPED"
    result["cache"] = str(LAB_STATE / "sender-session-cache")
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0 if result.get("ok") else 2


def cmd_worker() -> int:
    from mwoif_worker import __version__
    from mwoif_worker.ops_logger import SafeRotatingEventLogger
    from mwoif_worker.worker_service import worker_service_run

    print("=" * 64)
    print(" M WOIF AUTH KEEPER WORKER LAB V1")
    print(" productionCode=UNTOUCHED webDatabase=LIVE labCache=ISOLATED")
    print(" fullLoginCapture=ADMIN_BULK_LOGIN refreshKeeper=ENABLED")
    print(" IMPORTANT=start_worker.bat must be stopped")
    print("=" * 64)
    logger = SafeRotatingEventLogger(LAB_STATE, console_sink=_emit)
    try:
        return worker_service_run(__version__, event_cb=logger.emit)
    finally:
        logger.close()


def main() -> int:
    configure_environment()
    parser = argparse.ArgumentParser(prog="mwoif-auth-keeper-worker-lab-v1")
    parser.add_argument("command", choices=["preflight", "worker-service"])
    args = parser.parse_args()
    return cmd_preflight() if args.command == "preflight" else cmd_worker()


if __name__ == "__main__":
    raise SystemExit(main())
