from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
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
from mwoif.friend.proto import encode_string
from mwoif.friend.service import _grpc_call
from mwoif.session.game_session import SessionBootstrapError, bootstrap_session
from mwoif_worker.config import WorkerConfig
from mwoif_worker.devplay.context import load_login_web_context
from mwoif_worker.devplay.exact_template import ExactTemplateReplayer
from mwoif_worker.heart_one import _legacy_auth
from tools.onelink_resolver import normalize_onelink_url, resolve_http, validate_invite_uri


INVITE_METHOD = "/service.api.InvitationAPI/SetReferrer"


def emit(message: str) -> None:
    print(message, flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="M WOIF isolated InvitationAPI SetReferrer probe")
    parser.add_argument("--email", default=os.getenv("MWOIF_INVITE_PROBE_EMAIL", ""))
    parser.add_argument("--password", default=os.getenv("MWOIF_INVITE_PROBE_PASSWORD", ""))
    parser.add_argument("--url", default=os.getenv("MWOIF_INVITE_PROBE_URL", ""))
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--resolve-timeout", type=float, default=12.0)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--yes", action="store_true")
    return parser.parse_args()


def short_fp(value: str) -> str:
    raw = str(value or "").encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:12] if raw else ""


def safe_grpc_summary(result: dict) -> dict:
    return {
        "ok": bool(result.get("ok")),
        "network_action_enabled": bool(result.get("network_action_enabled")),
        "method": result.get("method"),
        "host": result.get("host"),
        "elapsed_ms": result.get("elapsed_ms"),
        "response_bytes": result.get("response_bytes"),
        "grpc_code": result.get("grpc_code"),
        "failure_class": result.get("failure_class"),
        "error": result.get("error"),
        "secretOutput": "NONE",
    }


def resolve_invite(url: str, timeout: float) -> tuple[str, dict[str, str]]:
    normalized = normalize_onelink_url(url)
    uri, _trace = resolve_http(normalized, timeout=max(3.0, timeout), max_hops=8, force_probe=True)
    if not uri:
        raise RuntimeError("ONELINK_DIRECT_URI_NOT_FOUND")
    params, warnings = validate_invite_uri(uri)
    if warnings:
        severe = [w for w in warnings if w.startswith("MISSING_PARAMS=") or w == "DEEP_LINK_VALUE_NOT_INVITE"]
        if severe:
            raise RuntimeError("ONELINK_INVITE_PARAMS_INVALID:" + ",".join(severe))
    referrer_player_id = str(params.get("deep_link_sub1") or "").strip()
    if not referrer_player_id:
        raise RuntimeError("REFERRER_PLAYER_ID_MISSING")
    return referrer_player_id, params


def confirm_live(email: str, referrer_player_id: str, args: argparse.Namespace) -> bool:
    if not args.live:
        return False
    if args.yes:
        return True
    print()
    print("LIVE WARNING")
    print("This call may permanently consume this Lv.5 receiver for invitation use.")
    print(f"receiver={email}")
    print(f"referrer_player_id_fp={short_fp(referrer_player_id)}")
    answer = input("Type YES to call InvitationAPI/SetReferrer: ").strip()
    return answer == "YES"


def main() -> int:
    args = parse_args()
    email = str(args.email or "").strip()
    password = str(args.password or "")
    onelink = str(args.url or "").strip()

    if not email:
        email = input("Receiver DevPlay email (Lv.5+ unused): ").strip()
    if not password:
        password = getpass.getpass("Receiver DevPlay password: ")
    if not onelink:
        onelink = input("Inviter OneLink URL: ").strip()
    if not email or not password or not onelink:
        print("INPUT_REQUIRED")
        return 2

    emit("M WOIF INVITE API PROBE V1")
    emit("mode=ISOLATED existingWorkerFiles=READ_ONLY secretOutput=NONE")

    try:
        referrer_player_id, invite_params = resolve_invite(onelink, args.resolve_timeout)
    except Exception as exc:
        emit(f"ONELINK RESOLVE FAIL code={type(exc).__name__} detail={str(exc)[:180]}")
        return 3

    emit("ONELINK RESOLVE PASS")
    emit(f"deep_link_value={invite_params.get('deep_link_value', '')}")
    emit(f"referrer_player_id=present fp={short_fp(referrer_player_id)}")
    emit(f"referrer_customer_id=present:{bool(invite_params.get('af_referrer_customer_id'))}")

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

    emit("DIRECT LOGIN START target=DevPlay webBackend=DISABLED")
    replay = replayer.replay(context=context, email=email, password=password, event_cb=emit)
    password = ""
    if not replay.ok or replay.bundle is None:
        emit(
            "DIRECT LOGIN FAIL "
            f"stage={replay.stage} code={replay.code} retryable={replay.retryable}"
        )
        return 5

    runtime_cfg = build_devplay_runtime_config(load_config(ROOT / ".env"))
    auth = _legacy_auth(
        context=context,
        bundle=replay.bundle,
        account_kind="invite_probe_receiver",
        account_id=0,
    )
    replay = None

    try:
        session = bootstrap_session(runtime_cfg, "INVITE", auth, event_cb=emit)
    except SessionBootstrapError as exc:
        emit(f"SESSION FAIL code=INITMEMBER3_FAILED detail={str(exc)[:180]}")
        return 6

    emit(f"RECEIVER CHECK lv={session.current_lv} memberSeq=present session=present")
    if session.current_lv < 5:
        emit("RECEIVER REJECT code=LEVEL_TOO_LOW required=5")
        return 7

    body = encode_string(2, referrer_player_id)
    emit(f"REQUEST READY method={INVITE_METHOD} protobufField=2 requestBytes={len(body)}")

    if not args.live:
        emit("PREVIEW PASS networkWrite=NO")
        emit("NEXT=Run again with --live after confirming this receiver has never consumed an invite.")
        return 0

    if not confirm_live(email, referrer_player_id, args):
        emit("LIVE CANCELLED networkWrite=NO")
        return 8

    emit("SET_REFERRER START networkWrite=YES")
    result = _grpc_call(
        cfg=runtime_cfg,
        slot="INVITE",
        auth=auth,
        action="invite-set-referrer",
        method_path=INVITE_METHOD,
        request_body=body,
        timeout=max(3.0, float(args.timeout)),
        live=True,
        schema={
            "request": "service.api.SetReferrerRequest",
            "field_2": "referrer_player_id:string",
        },
    )

    summary = safe_grpc_summary(result)
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    if not result.get("ok"):
        emit("SET_REFERRER FAIL")
        return 9

    emit("SET_REFERRER PASS grpc=OK")
    emit("VERIFY=Run direct_login_inspect.py on the inviter and confirm friendInviteCount increased by exactly 1.")
    emit("IMPORTANT=Do not reuse this receiver for another invite proof until verification is complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
