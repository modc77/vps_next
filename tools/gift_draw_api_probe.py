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
from mwoif.gift_draw import GiftDrawError, fetch_gift_snapshot, gift_draw
from mwoif_worker.config import WorkerConfig
from mwoif_worker.devplay.context import load_login_web_context
from mwoif_worker.devplay.exact_template import ExactTemplateReplayer
from mwoif_worker.heart_one import _legacy_auth


def emit(message: str) -> None:
    print(message, flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="M WOIF isolated Gift Draw API probe")
    parser.add_argument("--email", default=os.getenv("MWOIF_GIFT_DRAW_EMAIL", ""))
    parser.add_argument("--password", default=os.getenv("MWOIF_GIFT_DRAW_PASSWORD", ""))
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--count", type=int, choices=(1, 2), default=1)
    return parser.parse_args()


def safe_result(result: dict) -> dict:
    keys = (
        "ok",
        "read_only",
        "network_action_enabled",
        "action",
        "endpoint",
        "request_mode",
        "native_contract",
        "http_status",
        "response_code",
        "response_message",
        "response_bytes",
        "elapsed_ms",
        "response_data_present",
        "response_data_decoded",
        "response_root_keys",
        "response_interesting",
        "response_safe",
        "error",
        "response_decode_error",
        "missing_live_fields",
        "crypto_self_check",
        "secretOutput",
    )
    return {key: result.get(key) for key in keys if key in result}


def confirm_live(email: str, gift_count: int, count: int, args: argparse.Namespace) -> bool:
    if not args.live:
        return False
    if args.yes:
        return True
    print()
    print("LIVE WARNING")
    print(f"This run will attempt to open exactly {count} stored Gift Draw gift(s).")
    print(f"account={email}")
    print(f"giftCount_before={gift_count}")
    answer = input(f"Type YES to call shop/buyStuff.ds Gift Draw {count} time(s): ").strip()
    return answer == "YES"


def write_report(data: dict) -> Path:
    out_dir = ROOT / "state" / "gift-draw-phase1"
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
        print("INPUT_REQUIRED")
        return 2

    emit("M WOIF GIFT DRAW API PHASE1")
    emit("mode=ISOLATED webBackend=DISABLED existingWorkerFiles=READ_ONLY secretOutput=NONE")

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
        emit(f"DIRECT LOGIN FAIL stage={replay.stage} code={replay.code} retryable={replay.retryable}")
        return 4

    runtime_cfg = build_devplay_runtime_config(load_config(ROOT / ".env"))
    auth = _legacy_auth(
        context=context,
        bundle=replay.bundle,
        account_kind="gift_draw_probe",
        account_id=0,
    )
    replay = None

    try:
        before = fetch_gift_snapshot(runtime_cfg, slot="GIFT", auth=auth, event_cb=emit)
    except GiftDrawError as exc:
        emit(f"GIFT SNAPSHOT FAIL code={str(exc)[:180]}")
        return 5

    emit(
        f"GIFT STATUS before currentPoint={before.current_point}/100 "
        f"giftCount={before.gift_count} todayPoint={before.today_point}"
    )

    preview = gift_draw(
        cfg=runtime_cfg,
        slot="GIFT",
        session=before.session,
        auth=auth,
        live=False,
        timeout=max(3.0, float(args.timeout)),
    )
    emit(
        f"REQUEST READY endpoint={preview.get('endpoint')} mode={preview.get('request_mode')} "
        f"cryptoSelfCheck={'PASS' if preview.get('crypto_self_check') else 'FAIL'}"
    )
    if not preview.get("ok"):
        print(json.dumps(safe_result(preview), ensure_ascii=False, indent=2))
        return 6

    if not args.live:
        report = {
            "phase": "PREVIEW",
            "before": before.public_summary(),
            "request": safe_result(preview),
            "secretOutput": "NONE",
        }
        out = write_report(report)
        emit("PREVIEW PASS networkWrite=NO")
        emit("NEXT=Run again with --live --count 1 or --live --count 2.")
        emit(f"REPORT={out}")
        return 0

    count = int(args.count)
    if before.gift_count < count:
        emit(f"LIVE REJECT code=NOT_ENOUGH_STORED_GIFT giftCount={before.gift_count} requested={count}")
        return 7
    if not confirm_live(email, before.gift_count, count, args):
        emit("LIVE CANCELLED networkWrite=NO")
        return 8

    current = before
    draws = []
    for index in range(1, count + 1):
        emit(
            f"GIFT DRAW START draw={index}/{count} endpoint=shop/buyStuff.ds "
            f"networkWrite=YES giftCountBefore={current.gift_count}"
        )
        result = gift_draw(
            cfg=runtime_cfg,
            slot=f"GIFT_{index}",
            session=current.session,
            auth=auth,
            live=True,
            timeout=max(3.0, float(args.timeout)),
        )
        public = safe_result(result)
        print(json.dumps(public, ensure_ascii=False, indent=2))
        if not result.get("ok"):
            report = {
                "phase": "LIVE_FAIL",
                "requestedCount": count,
                "completedCount": len(draws),
                "before": before.public_summary(),
                "draws": draws,
                "failedDraw": {"index": index, "result": public},
                "secretOutput": "NONE",
            }
            out = write_report(report)
            emit(f"GIFT DRAW FAIL draw={index}/{count} report={out}")
            return 9

        try:
            after = fetch_gift_snapshot(
                runtime_cfg,
                slot=f"GIFT_VERIFY_{index}",
                auth=auth,
                event_cb=emit,
            )
        except GiftDrawError as exc:
            report = {
                "phase": "LIVE_VERIFY_FAILED",
                "requestedCount": count,
                "completedCount": len(draws),
                "before": before.public_summary(),
                "draws": draws,
                "failedDraw": {
                    "index": index,
                    "result": public,
                    "verify_error": str(exc)[:180],
                },
                "secretOutput": "NONE",
            }
            out = write_report(report)
            emit(f"DRAW RESPONSE COMPLETE but verify failed draw={index}/{count} code={str(exc)[:180]}")
            emit(f"REPORT={out}")
            return 10

        gift_delta = after.gift_count - current.gift_count
        point_delta = after.current_point - current.current_point
        verified = gift_delta == -1
        draw_row = {
            "index": index,
            "before": current.public_summary(),
            "draw": public,
            "after": after.public_summary(),
            "giftCountDelta": gift_delta,
            "currentPointDelta": point_delta,
            "verifiedOneGiftConsumed": verified,
        }
        draws.append(draw_row)
        emit(
            f"VERIFY draw={index}/{count} beforeGift={current.gift_count} afterGift={after.gift_count} "
            f"giftDelta={gift_delta} currentPointDelta={point_delta}"
        )
        if not verified:
            report = {
                "phase": "LIVE_VERIFY_MISMATCH",
                "requestedCount": count,
                "completedCount": len(draws),
                "before": before.public_summary(),
                "draws": draws,
                "secretOutput": "NONE",
            }
            out = write_report(report)
            emit(f"GIFT DRAW RESPONSE COMPLETE but exact giftCount -1 verification did not pass draw={index}/{count}")
            emit(f"REPORT={out}")
            return 11
        emit(f"GIFT DRAW PASS draw={index}/{count} exactStoredGiftDelta=-1")
        current = after

    report = {
        "phase": "LIVE",
        "requestedCount": count,
        "completedCount": len(draws),
        "before": before.public_summary(),
        "draws": draws,
        "after": current.public_summary(),
        "totalGiftCountDelta": current.gift_count - before.gift_count,
        "secretOutput": "NONE",
    }
    out = write_report(report)
    emit(
        f"GIFT DRAW TEST PASS completed={len(draws)}/{count} "
        f"giftCount={before.gift_count}->{current.gift_count}"
    )
    emit(f"REPORT={out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
