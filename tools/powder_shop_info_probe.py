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
from mwoif.powder import SHOP_GET_INFO_METHOD, get_shop_info
from mwoif_worker.config import WorkerConfig
from mwoif_worker.devplay.context import load_login_web_context
from mwoif_worker.devplay.exact_template import ExactTemplateReplayer
from mwoif_worker.heart_one import _legacy_auth


def emit(message: str) -> None:
    print(message, flush=True)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="M WOIF Powder ShopInfo API-only read probe")
    p.add_argument("--email", default=os.getenv("MWOIF_POWDER_EMAIL", ""))
    p.add_argument("--password", default=os.getenv("MWOIF_POWDER_PASSWORD", ""))
    p.add_argument("--timeout", type=float, default=15.0)
    return p.parse_args()


def write_report(data: dict) -> Path:
    out_dir = ROOT / "state" / "powder-shop-info"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def main() -> int:
    args = parse_args()
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
    auth = _legacy_auth(context=context, bundle=replay.bundle, account_kind="powder_shop_probe", account_id=0)
    replay = None

    emit(f"SHOP INFO START method={SHOP_GET_INFO_METHOD} mode=READ_ONLY_API")
    result = get_shop_info(cfg, auth=auth, timeout=args.timeout, execute=True)

    safe = {
        "ok": bool(result.get("ok")),
        "transport": result.get("transport"),
        "method": result.get("method"),
        "read_only": result.get("read_only"),
        "network_action_enabled": result.get("network_action_enabled"),
        "elapsed_ms": result.get("elapsed_ms"),
        "response_bytes": result.get("response_bytes"),
        "grpc_code": result.get("grpc_code"),
        "grpc_details": result.get("grpc_details"),
        "failure_class": result.get("failure_class"),
        "shop_info_scan_ok": result.get("shop_info_scan_ok"),
        "shop_info_scalar_count": result.get("shop_info_scalar_count"),
        "shop_info_price5000_hits": result.get("shop_info_price5000_hits"),
        "shop_info_price5000_candidates": result.get("shop_info_price5000_candidates", []),
        "shop_info_strings": result.get("shop_info_strings", []),
        "shop_info_varints": result.get("shop_info_varints", []),
        "secretOutput": "NONE",
    }
    out = write_report(safe)

    if not result.get("ok"):
        emit(
            f"SHOP INFO FAIL grpc={result.get('grpc_code') or 'UNKNOWN'} "
            f"class={result.get('failure_class') or 'UNKNOWN'}"
        )
        if result.get("grpc_details"):
            emit(f"DETAIL={str(result.get('grpc_details'))[:240]}")
        emit(f"REPORT={out}")
        return 5

    emit(
        f"SHOP INFO PASS responseBytes={result.get('response_bytes')} "
        f"scalarCount={result.get('shop_info_scalar_count')} "
        f"price5000Hits={result.get('shop_info_price5000_hits')}"
    )

    candidates = result.get("shop_info_price5000_candidates") or []
    for index, candidate in enumerate(candidates[:10], 1):
        emit(f"PRICE5000 CANDIDATE #{index} parent={candidate.get('parent')}")
        for field in candidate.get("fields") or []:
            value = field.get("value", field.get("hex", ""))
            emit(f"  path={field.get('path')} kind={field.get('kind')} value={value}")

    strings = result.get("shop_info_strings") or []
    if strings:
        emit("SHOP STRINGS")
        for item in strings[:60]:
            emit(f"  path={item.get('path')} value={item.get('value')}")

    emit("NETWORK ACTION=READ_ONLY no purchase request was sent")
    emit(f"REPORT={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
