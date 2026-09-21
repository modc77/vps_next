from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


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
from mwoif.invite.service import INVITE_METHOD, set_referrer
from mwoif.invite.snapshot import InviteMemberSnapshot, InviteSnapshotError, fetch_invite_member_snapshot
from mwoif_worker.config import WorkerConfig
from mwoif_worker.devplay.context import load_login_web_context
from mwoif_worker.devplay.exact_template import ExactTemplateReplayer
from mwoif_worker.heart_one import _legacy_auth
from tools.onelink_resolver import normalize_onelink_url, resolve_http, validate_invite_uri


TARGET_INVITES = 29
MIN_RECEIVER_LEVEL = 5


def emit(message: str) -> None:
    print(message, flush=True)


def fp(value: str) -> str:
    raw = str(value or "").strip().lower().encode("utf-8", "ignore")
    return hashlib.sha256(raw).hexdigest()[:12] if raw else ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="M WOIF INVITE_PUMP standalone Phase 1")
    parser.add_argument("--inviter-email", default=os.getenv("MWOIF_INVITE_TARGET_EMAIL", ""))
    parser.add_argument("--inviter-password", default=os.getenv("MWOIF_INVITE_TARGET_PASSWORD", ""))
    parser.add_argument("--url", default=os.getenv("MWOIF_INVITE_TARGET_URL", ""))
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--max-receivers", type=int, default=0)
    parser.add_argument("--grpc-timeout", type=float, default=15.0)
    parser.add_argument("--resolve-timeout", type=float, default=12.0)
    parser.add_argument("--verify-attempts", type=int, default=5)
    parser.add_argument("--verify-delay", type=float, default=1.5)
    return parser.parse_args()


@dataclass(slots=True)
class LoginRuntime:
    worker_cfg: WorkerConfig
    runtime_cfg: Any
    context: Any
    replayer: ExactTemplateReplayer


@dataclass(slots=True)
class LoginResult:
    ok: bool
    auth: Any = None
    snapshot: InviteMemberSnapshot | None = None
    code: str = ""
    retryable: bool = False


def build_login_runtime() -> LoginRuntime:
    worker_cfg = WorkerConfig.load(ROOT)
    context = load_login_web_context(worker_cfg.web_context_file, worker_cfg.login_url)
    if not context.complete:
        raise RuntimeError("WEB_CONTEXT_INCOMPLETE")
    replayer = ExactTemplateReplayer(
        template_file=worker_cfg.exact_template_file,
        timeout_seconds=worker_cfg.timeout_seconds,
        verify_ssl=worker_cfg.verify_ssl,
        warmup_get=worker_cfg.warmup_get,
    )
    runtime_cfg = build_devplay_runtime_config(load_config(ROOT / ".env"))
    return LoginRuntime(
        worker_cfg=worker_cfg,
        runtime_cfg=runtime_cfg,
        context=context,
        replayer=replayer,
    )


def login_account(
    runtime: LoginRuntime,
    *,
    email: str,
    password: str,
    account_kind: str,
    slot: str,
) -> LoginResult:
    identity = fp(email)
    emit(f"LOGIN START slot={slot} accountFp={identity} secretOutput=NONE")
    replay = runtime.replayer.replay(
        context=runtime.context,
        email=email,
        password=password,
        event_cb=emit,
    )
    password = ""
    if not replay.ok or replay.bundle is None:
        emit(
            "LOGIN ERROR "
            f"slot={slot} accountFp={identity} code={replay.code or 'DEVPLAY_LOGIN_FAILED'} "
            f"retryable={bool(replay.retryable)} switch=NEXT"
        )
        return LoginResult(
            ok=False,
            code=str(replay.code or "DEVPLAY_LOGIN_FAILED"),
            retryable=bool(replay.retryable),
        )

    auth = _legacy_auth(
        context=runtime.context,
        bundle=replay.bundle,
        account_kind=account_kind,
        account_id=0,
    )
    replay = None
    try:
        snapshot = fetch_invite_member_snapshot(
            runtime.runtime_cfg,
            slot=slot,
            auth=auth,
            event_cb=emit,
        )
    except InviteSnapshotError as exc:
        emit(
            f"SESSION ERROR slot={slot} accountFp={identity} code={str(exc)[:120]} switch=NEXT"
        )
        return LoginResult(ok=False, code=str(exc), retryable=True)

    return LoginResult(ok=True, auth=auth, snapshot=snapshot)


def resolve_invite(url: str, timeout: float) -> tuple[str, dict[str, str]]:
    normalized = normalize_onelink_url(url)
    uri, _trace = resolve_http(
        normalized,
        timeout=max(3.0, float(timeout)),
        max_hops=8,
        force_probe=True,
    )
    if not uri:
        raise RuntimeError("ONELINK_DIRECT_URI_NOT_FOUND")
    params, warnings = validate_invite_uri(uri)
    severe = [
        item for item in warnings
        if item.startswith("MISSING_PARAMS=") or item == "DEEP_LINK_VALUE_NOT_INVITE"
    ]
    if severe:
        raise RuntimeError("ONELINK_INVITE_PARAMS_INVALID:" + ",".join(severe))
    referrer_player_id = str(params.get("deep_link_sub1") or "").strip()
    if not referrer_player_id:
        raise RuntimeError("REFERRER_PLAYER_ID_MISSING")
    return referrer_player_id, params


def owner_matches(
    referrer_player_id: str,
    params: dict[str, str],
    auth: Any,
    snapshot: InviteMemberSnapshot,
) -> tuple[bool, str]:
    identities = {
        str(snapshot.session.member_seq),
        str(getattr(auth, "mid", "") or "").strip(),
    }
    candidates = {
        str(referrer_player_id or "").strip(),
        str(params.get("af_referrer_customer_id") or "").strip(),
    }
    identities.discard("")
    candidates.discard("")
    if identities.intersection(candidates):
        if str(referrer_player_id or "").strip() in identities:
            return True, "deep_link_sub1"
        return True, "af_referrer_customer_id"
    return False, "unverified"


def state_writer() -> tuple[Path, Any]:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = ROOT / "state" / "invite-phase1" / stamp
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "run.jsonl"

    def write(event: str, **fields: Any) -> None:
        row = {
            "time": datetime.now().isoformat(timespec="seconds"),
            "event": event,
            **fields,
            "secretOutput": "NONE",
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")

    return path, write


def refresh_target(
    runtime: LoginRuntime,
    *,
    auth: Any,
    attempts: int,
    delay: float,
    expected_min: int | None = None,
) -> InviteMemberSnapshot | None:
    attempts = max(1, min(int(attempts), 10))
    delay = max(0.2, min(float(delay), 10.0))
    last: InviteMemberSnapshot | None = None
    for attempt in range(1, attempts + 1):
        try:
            last = fetch_invite_member_snapshot(
                runtime.runtime_cfg,
                slot="INVITER_VERIFY",
                auth=auth,
                event_cb=None,
            )
            emit(
                f"VERIFY TARGET attempt={attempt}/{attempts} "
                f"friendInviteCount={last.friend_invite_count}"
            )
            if expected_min is None or last.friend_invite_count >= expected_min:
                return last
        except InviteSnapshotError as exc:
            emit(f"VERIFY TARGET ERROR attempt={attempt}/{attempts} code={str(exc)[:100]}")
        if attempt < attempts:
            time.sleep(delay)
    return last


def ask_max_receivers(args: argparse.Namespace, remaining: int) -> int:
    if args.max_receivers > 0:
        return max(1, min(args.max_receivers, remaining))
    raw = input(f"Max test receiver accounts [1-{min(3, remaining)}] (default 1): ").strip()
    if not raw:
        return 1
    try:
        value = int(raw)
    except ValueError:
        return 1
    return max(1, min(value, remaining, 10))


def main() -> int:
    args = parse_args()
    inviter_email = str(args.inviter_email or "").strip()
    inviter_password = str(args.inviter_password or "")
    onelink = str(args.url or "").strip()

    if not inviter_email:
        inviter_email = input("Inviter DevPlay email (target account): ").strip()
    if not inviter_password:
        inviter_password = getpass.getpass("Inviter DevPlay password: ")
    if not onelink:
        onelink = input("Inviter OneLink URL: ").strip()
    if not inviter_email or not inviter_password or not onelink:
        emit("INPUT REQUIRED")
        return 2

    emit("M WOIF INVITE_PUMP • VPS PHASE 1")
    emit("mode=STANDALONE workerService=UNTOUCHED webDatabase=UNTOUCHED secretOutput=NONE")
    state_path, write_state = state_writer()

    try:
        referrer_player_id, params = resolve_invite(onelink, args.resolve_timeout)
    except Exception as exc:
        emit(f"ONELINK ERROR code={type(exc).__name__} detail={str(exc)[:160]}")
        return 3

    emit(
        "ONELINK PASS "
        f"deep_link_value={params.get('deep_link_value', '')} "
        f"referrerPlayerId=present fp={fp(referrer_player_id)}"
    )

    try:
        runtime = build_login_runtime()
    except Exception as exc:
        emit(f"RUNTIME ERROR code={str(exc)[:120]}")
        return 4

    target = login_account(
        runtime,
        email=inviter_email,
        password=inviter_password,
        account_kind="invite_phase1_target",
        slot="INVITER",
    )
    inviter_password = ""
    if not target.ok or target.auth is None or target.snapshot is None:
        emit(f"TARGET ERROR code={target.code} stop=YES")
        return 5

    match, match_by = owner_matches(referrer_player_id, params, target.auth, target.snapshot)
    emit(f"ONELINK OWNER CHECK match={'YES' if match else 'UNVERIFIED'} via={match_by}")
    if not match:
        emit("ONELINK OWNER NOTE link/account identity cannot be proven from available public fields; Phase 1 will use the supplied link.")

    current = int(target.snapshot.friend_invite_count)
    remaining = max(0, TARGET_INVITES - current)
    emit(
        f"TARGET CHECK lv={target.snapshot.session.current_lv} "
        f"friendInviteCount={current} target={TARGET_INVITES} remaining={remaining}"
    )
    write_state(
        "TARGET_READY",
        targetFp=fp(inviter_email),
        current=current,
        target=TARGET_INVITES,
        remaining=remaining,
        linkFp=fp(onelink),
    )

    if current >= TARGET_INVITES:
        emit("TARGET COMPLETE friendInviteCount=29 action=NONE")
        emit(f"STATE={state_path}")
        return 0

    if not args.live:
        emit("PHASE1 PREVIEW PASS networkWrite=NO")
        emit(f"NEXT=Live test needs up to {remaining} eligible Lv.5 receiver account(s).")
        emit(f"STATE={state_path}")
        return 0

    max_receivers = ask_max_receivers(args, remaining)
    if not args.yes:
        emit("")
        emit(
            f"LIVE PLAN current={current} target={TARGET_INVITES} "
            f"remaining={remaining} maxTestReceivers={max_receivers}"
        )
        answer = input("Type RUN to start Phase 1 live test: ").strip()
        if answer != "RUN":
            emit("LIVE CANCELLED networkWrite=NO")
            return 7

    successful = 0
    errors = 0
    consumed: list[str] = []

    for index in range(1, max_receivers + 1):
        if current >= TARGET_INVITES:
            break
        emit("")
        emit(
            f"RECEIVER {index}/{max_receivers} START "
            f"current={current} remaining={max(0, TARGET_INVITES - current)}"
        )
        receiver_email = input("Receiver DevPlay email (Lv.5+ unused): ").strip()
        receiver_password = getpass.getpass("Receiver DevPlay password: ")
        if not receiver_email or not receiver_password:
            receiver_password = ""
            errors += 1
            emit("RECEIVER ERROR code=EMPTY_CREDENTIAL switch=NEXT")
            continue

        receiver_fp = fp(receiver_email)
        receiver = login_account(
            runtime,
            email=receiver_email,
            password=receiver_password,
            account_kind="invite_phase1_receiver",
            slot=f"INVITE_{index}",
        )
        receiver_password = ""

        if not receiver.ok or receiver.auth is None or receiver.snapshot is None:
            errors += 1
            write_state(
                "RECEIVER_ERROR",
                receiverFp=receiver_fp,
                code=receiver.code,
                stage="LOGIN_OR_SESSION",
                action="SWITCH_NEXT",
            )
            continue

        level = int(receiver.snapshot.session.current_lv)
        eligible = level >= MIN_RECEIVER_LEVEL
        emit(
            f"INVITE ACCOUNT CHECK accountFp={receiver_fp} lv={level} "
            f"requiredLv={MIN_RECEIVER_LEVEL} eligible={'YES' if eligible else 'NO'}"
        )
        if not eligible:
            errors += 1
            emit(f"RECEIVER ERROR accountFp={receiver_fp} code=LEVEL_TOO_LOW switch=NEXT")
            write_state(
                "RECEIVER_ERROR",
                receiverFp=receiver_fp,
                code="LEVEL_TOO_LOW",
                lv=level,
                action="SWITCH_NEXT",
            )
            continue

        before = current
        emit(
            f"SET_REFERRER START accountFp={receiver_fp} method={INVITE_METHOD} "
            f"before={before} networkWrite=YES"
        )
        result = set_referrer(
            cfg=runtime.runtime_cfg,
            auth=receiver.auth,
            referrer_player_id=referrer_player_id,
            slot="INVITE",
            timeout=args.grpc_timeout,
            live=True,
        )
        if not bool(result.get("ok")):
            errors += 1
            code = str(result.get("grpc_code") or result.get("error") or "SET_REFERRER_FAILED")
            emit(
                f"SET_REFERRER ERROR accountFp={receiver_fp} code={code} "
                f"switch=NEXT"
            )
            write_state(
                "RECEIVER_ERROR",
                receiverFp=receiver_fp,
                code=code,
                stage="SET_REFERRER",
                lv=level,
                action="SWITCH_NEXT",
            )
            continue

        emit(
            f"SET_REFERRER PASS accountFp={receiver_fp} "
            f"elapsedMs={result.get('elapsed_ms')} responseBytes={result.get('response_bytes')}"
        )
        write_state(
            "SET_REFERRER_ACCEPTED",
            receiverFp=receiver_fp,
            lv=level,
            before=before,
        )

        verified = refresh_target(
            runtime,
            auth=target.auth,
            attempts=args.verify_attempts,
            delay=args.verify_delay,
            expected_min=before + 1,
        )
        if verified is None or verified.friend_invite_count < before + 1:
            emit(
                f"VERIFY PENDING accountFp={receiver_fp} before={before} "
                "action=STOP_TO_AVOID_DOUBLE_CONSUME"
            )
            write_state(
                "VERIFY_PENDING",
                receiverFp=receiver_fp,
                before=before,
                action="STOP_TO_AVOID_DOUBLE_CONSUME",
            )
            emit(f"STATE={state_path}")
            return 8

        current = int(verified.friend_invite_count)
        delta = current - before
        successful += 1
        consumed.append(receiver_fp)
        emit(
            f"VERIFY PASS accountFp={receiver_fp} before={before} after={current} delta={delta}"
        )
        emit(
            f"ACCOUNT CONSUMED accountFp={receiver_fp} inviteUse=USED "
            "nextRoleCandidate=HEART_SENDER"
        )
        write_state(
            "RECEIVER_CONSUMED",
            receiverFp=receiver_fp,
            lv=level,
            before=before,
            after=current,
            delta=delta,
            nextRoleCandidate="HEART_SENDER",
        )

        if current >= TARGET_INVITES:
            break

    remaining = max(0, TARGET_INVITES - current)
    emit("")
    if current >= TARGET_INVITES:
        emit(
            f"PHASE1 COMPLETE friendInviteCount={current} target={TARGET_INVITES} "
            f"successful={successful} errors={errors}"
        )
    else:
        emit(
            f"PHASE1 PARTIAL friendInviteCount={current} target={TARGET_INVITES} "
            f"remaining={remaining} successful={successful} errors={errors}"
        )
        emit("NEXT=Add more unused Lv.5 receiver accounts and run again; current count will be re-read first.")

    if consumed:
        emit(f"MIGRATION CANDIDATES count={len(consumed)} nextRole=HEART_SENDER")
    emit(f"STATE={state_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
