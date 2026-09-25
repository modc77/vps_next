from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import datetime
from pathlib import Path


def find_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in (here.parents[1], here.parents[2], Path.cwd()):
        if (candidate / "mwoif").is_dir() and (candidate / "mwoif_worker").is_dir():
            return candidate.resolve()
    raise SystemExit("VPS_ROOT_NOT_FOUND")


ROOT = find_root()
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from mwoif.auth.config_adapter import build_devplay_runtime_config
from mwoif.core.config import load_config
from mwoif.powder import config_check, fetch_powder_snapshot
from mwoif_worker.config import WorkerConfig
from mwoif_worker.devplay.context import load_login_web_context
from mwoif_worker.devplay.exact_template import ExactTemplateReplayer
from mwoif_worker.heart_one import _legacy_auth


def emit(message: str) -> None:
    print(message, flush=True)


def args_parse() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="M WOIF Powder config/CDN API-only read probe")
    p.add_argument("--email", default=os.getenv("MWOIF_POWDER_EMAIL", ""))
    p.add_argument("--password", default=os.getenv("MWOIF_POWDER_PASSWORD", ""))
    p.add_argument("--timeout", type=float, default=20.0)
    return p.parse_args()


def report_write(data: dict) -> Path:
    out_dir = ROOT / "state" / "powder-config-probe"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def main() -> int:
    args = args_parse()
    email = str(args.email or "").strip()
    password = str(args.password or "")
    if not email:
        email = input("DevPlay email: ").strip()
    if not password:
        password = getpass.getpass("DevPlay password: ")
    if not email or not password:
        emit("INPUT_REQUIRED")
        return 2

    worker_cfg = WorkerConfig.load(ROOT)
    context = load_login_web_context(worker_cfg.web_context_file, worker_cfg.login_url)
    if not context.complete:
        emit("LOGIN CONFIG FAIL code=WEB_CONTEXT_INCOMPLETE")
        return 3

    replayer = ExactTemplateReplayer(
        template_file=worker_cfg.exact_template_file,
        timeout_seconds=worker_cfg.timeout_seconds,
        verify_ssl=worker_cfg.verify_ssl,
        warmup_get=worker_cfg.warmup_get,
    )
    emit("DIRECT LOGIN START target=DevPlay webBackend=DISABLED secretOutput=NONE")
    replay = replayer.replay(context=context, email=email, password=password, event_cb=emit)
    password = ""
    if not replay.ok or replay.bundle is None:
        emit(f"DIRECT LOGIN FAIL stage={replay.stage} code={replay.code}")
        return 4

    cfg = build_devplay_runtime_config(load_config(ROOT / ".env"))
    auth = _legacy_auth(context=context, bundle=replay.bundle, account_kind="powder_config_probe", account_id=0)
    replay = None

    try:
        before = fetch_powder_snapshot(cfg, slot="POWDER_CONFIG", auth=auth, event_cb=emit)
    except Exception as exc:
        emit(f"POWDER SNAPSHOT FAIL code={type(exc).__name__}")
        return 5

    emit("CONFIG CHECK START endpoint=check/configCheck.ds mode=READ_ONLY_API")
    result = config_check(cfg, auth=auth, session=before.session, live=True, timeout=args.timeout)

    safe = {
        "ok": bool(result.get("ok")),
        "endpoint": result.get("endpoint"),
        "http_status": result.get("http_status"),
        "response_code": result.get("response_code"),
        "response_message": result.get("response_message"),
        "response_data_decoded": result.get("response_data_decoded"),
        "config_response_decoded": result.get("config_response_decoded"),
        "config_root_keys": result.get("config_root_keys", []),
        "config_candidates": result.get("config_candidates", []),
        "config_discovery_error": result.get("config_discovery_error"),
        "secretOutput": "NONE",
    }
    out = report_write(safe)

    emit(
        f"CONFIG CHECK RESULT ok={safe['ok']} http={safe.get('http_status')} "
        f"responseCode={safe.get('response_code')} message={safe.get('response_message')}"
    )
    candidates = safe.get("config_candidates") or []
    emit(f"CONFIG META candidates={len(candidates)}")
    for item in candidates[:80]:
        emit(f"  {item.get('path')}={item.get('value')}")
    emit("NETWORK ACTION=READ_ONLY no purchase request was sent")
    emit(f"REPORT={out}")
    return 0 if safe["ok"] else 6


if __name__ == "__main__":
    raise SystemExit(main())
