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
from mwoif.powder import NORMAL_BOX_PRICE, PowderError, buy_normal_box, consume_treasure, fetch_powder_snapshot
from mwoif_worker.config import WorkerConfig
from mwoif_worker.devplay.context import load_login_web_context
from mwoif_worker.devplay.exact_template import ExactTemplateReplayer
from mwoif_worker.heart_one import _legacy_auth


def emit(message: str) -> None:
    print(message, flush=True)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="M WOIF isolated Powder API one-box probe")
    p.add_argument("--email", default=os.getenv("MWOIF_POWDER_EMAIL", ""))
    p.add_argument("--password", default=os.getenv("MWOIF_POWDER_PASSWORD", ""))
    p.add_argument("--stuff-seq", type=int, default=int(os.getenv("MWOIF_POWDER_BOX1_STUFF_SEQ", "0") or 0))
    p.add_argument("--powder-qty", type=int)
    p.add_argument("--shard-qty", type=int)
    p.add_argument("--timeout", type=float, default=20.0)
    p.add_argument("--live", action="store_true")
    p.add_argument("--yes", action="store_true")
    return p.parse_args()


def write_report(data: dict) -> Path:
    out_dir = ROOT / "state" / "powder-api-phase1"
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
    if args.stuff_seq <= 0:
        emit("BOX1_CONTRACT_REQUIRED code=STUFF_SEQ_MISSING")
        emit(r"Run: python tools\powder_shop_info_probe.py")
        emit("LAB/ADB are not used by the Powder API flow.")
        return 3

    worker_cfg = WorkerConfig.load(ROOT)
    context = load_login_web_context(worker_cfg.web_context_file, worker_cfg.login_url)
    if not context.complete:
        emit("LOGIN CONFIG FAIL code=WEB_CONTEXT_INCOMPLETE")
        return 4

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
        return 5

    cfg = build_devplay_runtime_config(load_config(ROOT / ".env"))
    auth = _legacy_auth(context=context, bundle=replay.bundle, account_kind="powder_probe", account_id=0)
    replay = None

    try:
        before = fetch_powder_snapshot(cfg, slot="POWDER_BEFORE", auth=auth, event_cb=emit)
    except PowderError as exc:
        emit(f"SNAPSHOT FAIL code={str(exc)[:180]}")
        return 6

    emit(
        f"PRECHECK coin={before.coin} powder={before.powder} shard={before.shard} "
        f"treasureCount={len(before.treasures)} affordable={before.coin // NORMAL_BOX_PRICE}"
    )
    if before.coin < NORMAL_BOX_PRICE:
        emit("PRECHECK REJECT code=COIN_BELOW_5000")
        return 7

    preview = buy_normal_box(cfg, auth=auth, session=before.session, stuff_seq=args.stuff_seq, live=False, timeout=args.timeout)
    emit(
        f"BUY REQUEST READY endpoint={preview.get('endpoint')} stuffSeq={args.stuff_seq} "
        f"price={NORMAL_BOX_PRICE} buyType=0 cryptoSelfCheck={'PASS' if preview.get('crypto_self_check') else 'FAIL'}"
    )
    if not preview.get("ok"):
        print(json.dumps(preview, ensure_ascii=False, indent=2))
        return 8
    if not args.live:
        out = write_report({"phase":"PREVIEW","before":before.public_summary(),"buy":preview,"secretOutput":"NONE"})
        emit("PREVIEW PASS networkWrite=NO")
        emit(f"REPORT={out}")
        return 0

    if not args.yes:
        answer = input("Type YES to buy exactly 1 Normal 5000-Coin Treasure Box: ").strip()
        if answer != "YES":
            emit("LIVE CANCELLED networkWrite=NO")
            return 9

    emit("BUY START count=1 networkWrite=YES")
    buy = buy_normal_box(cfg, auth=auth, session=before.session, stuff_seq=args.stuff_seq, live=True, timeout=args.timeout)
    if not buy.get("ok"):
        print(json.dumps(buy, ensure_ascii=False, indent=2))
        return 10

    try:
        after_buy = fetch_powder_snapshot(cfg, slot="POWDER_AFTER_BUY", auth=auth, event_cb=emit)
    except PowderError as exc:
        emit(f"BUY VERIFY FAIL code={str(exc)[:180]}")
        return 11

    before_ids = {t.raw_id for t in before.treasures}
    new_items = [t for t in after_buy.treasures if t.raw_id not in before_ids]
    coin_delta = after_buy.coin - before.coin
    emit(f"BUY VERIFY coin={before.coin}->{after_buy.coin} delta={coin_delta} newTreasureCount={len(new_items)}")
    if coin_delta != -NORMAL_BOX_PRICE or len(new_items) != 1:
        out = write_report({
            "phase":"BUY_VERIFY_MISMATCH",
            "before":before.public_summary(),
            "afterBuy":after_buy.public_summary(),
            "coinDelta":coin_delta,
            "newTreasureIds":[t.raw_id for t in new_items],
            "secretOutput":"NONE",
        })
        emit(f"SAFE STOP report={out}")
        return 12

    new_item = new_items[0]
    emit(f"NEW TREASURE groupSeq={new_item.group_seq} tag={new_item.tag} uuid=present")

    if args.powder_qty is None or args.shard_qty is None:
        out = write_report({
            "phase":"BUY_ONE_VERIFIED_BREAK_NOT_SENT",
            "before":before.public_summary(),
            "afterBuy":after_buy.public_summary(),
            "coinDelta":coin_delta,
            "newTreasure":{"rawId":new_item.raw_id,"groupSeq":new_item.group_seq,"tag":new_item.tag,"uuid":"present"},
            "buy":buy,
            "secretOutput":"NONE",
        })
        emit("BUY ONE PASS")
        emit("BREAK SAFE STOP code=CONSUME_REWARD_VALUES_REQUIRED")
        emit("No old Treasure was touched. New Treasure remains in inventory.")
        emit(f"REPORT={out}")
        return 0

    emit(
        f"BREAK START count=1 endpoint=shop/consumeTreasure.ds powderQty={args.powder_qty} "
        f"shardQty={args.shard_qty} networkWrite=YES"
    )
    br = consume_treasure(
        cfg,
        auth=auth,
        session=after_buy.session,
        treasure=new_item,
        powder_qty=args.powder_qty,
        shard_qty=args.shard_qty,
        live=True,
        timeout=args.timeout,
    )
    if not br.get("ok"):
        print(json.dumps(br, ensure_ascii=False, indent=2))
        return 13

    try:
        final = fetch_powder_snapshot(cfg, slot="POWDER_AFTER_BREAK", auth=auth, event_cb=emit)
    except PowderError as exc:
        emit(f"BREAK VERIFY FAIL code={str(exc)[:180]}")
        return 14

    final_ids = {t.raw_id for t in final.treasures}
    removed = new_item.raw_id not in final_ids
    powder_delta = final.powder - after_buy.powder
    shard_delta = final.shard - after_buy.shard
    ok = removed and powder_delta == args.powder_qty and shard_delta == args.shard_qty
    report = {
        "phase":"BUY_BREAK_ONE",
        "ok":ok,
        "before":before.public_summary(),
        "afterBuy":after_buy.public_summary(),
        "final":final.public_summary(),
        "coinDelta":coin_delta,
        "newTreasureRemoved":removed,
        "powderDelta":powder_delta,
        "shardDelta":shard_delta,
        "secretOutput":"NONE",
    }
    out = write_report(report)
    emit(
        f"FINAL VERIFY removed={removed} powder={after_buy.powder}->{final.powder} delta={powder_delta} "
        f"shard={after_buy.shard}->{final.shard} delta={shard_delta}"
    )
    emit(f"RESULT={'PASS' if ok else 'VERIFY_MISMATCH'}")
    emit(f"REPORT={out}")
    return 0 if ok else 15


if __name__ == "__main__":
    raise SystemExit(main())
