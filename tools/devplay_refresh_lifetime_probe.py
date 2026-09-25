from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests


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
from mwoif.auth.models import jwt_exp
from mwoif.core.config import load_config
from mwoif.friend.service import list_friends
from mwoif.session.game_session import SessionBootstrapError, bootstrap_session
from mwoif.session.models import AuthRecord, SessionRecord
from mwoif_worker.config import WorkerConfig
from mwoif_worker.devplay.context import LoginWebContext, load_login_web_context
from mwoif_worker.devplay.exact_template import ExactTemplateReplayer, _apply_headers
from mwoif_worker.devplay.models import LoginBundle, find_login_payload
from mwoif_worker.heart_one import _legacy_auth


REFRESH_URL = "https://account.devplay.com/v3/refresh"
SECRET_OUTPUT = "NONE"


@dataclass(slots=True)
class RefreshResult:
    ok: bool
    code: str
    http_status: int
    bundle: LoginBundle | None
    header_mode: str
    elapsed_ms: float
    response_keys: list[str]
    message: str


def mask_email(email: str) -> str:
    text = str(email or "").strip()
    if "@" not in text:
        return "<masked>"
    left, right = text.split("@", 1)
    if len(left) <= 2:
        shown = left[:1] + "***"
    else:
        shown = left[:2] + "***" + left[-1:]
    return f"{shown}@{right}"


def fp(value: str) -> str:
    text = str(value or "")
    if not text:
        return "NONE"
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:12]


def token_exp(token: str) -> int:
    value = jwt_exp(str(token or ""))
    return int(value or 0)


def token_remaining(bundle: LoginBundle) -> int | None:
    now = int(time.time())
    expiries = [token_exp(bundle.game_access_token), token_exp(bundle.oven_access_token)]
    known = [x for x in expiries if x > 0]
    if not known:
        return None
    return min(known) - now


def safe_token_state(bundle: LoginBundle) -> dict[str, Any]:
    now = int(time.time())
    game_exp = token_exp(bundle.game_access_token)
    oven_exp = token_exp(bundle.oven_access_token)
    return {
        "mid_present": bool(bundle.mid),
        "refresh_present": bool(bundle.refresh_token),
        "refresh_fp": fp(bundle.refresh_token),
        "game_present": bool(bundle.game_access_token),
        "game_fp": fp(bundle.game_access_token),
        "game_exp": game_exp or None,
        "game_remaining_s": (game_exp - now) if game_exp else None,
        "oven_present": bool(bundle.oven_access_token),
        "oven_fp": fp(bundle.oven_access_token),
        "oven_exp": oven_exp or None,
        "oven_remaining_s": (oven_exp - now) if oven_exp else None,
        "expired_date_ms": int(bundle.expired_date_ms or 0) or None,
        "device_secret_present": bool(bundle.device_secret),
        "secretOutput": SECRET_OUTPUT,
    }


def public_json_keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        return sorted(str(k) for k in value.keys())[:50]
    return []


def load_refresh_headers(
    *,
    worker_cfg: WorkerConfig,
    context: LoginWebContext,
    authorization_token: str = "",
) -> dict[str, str]:
    template = json.loads(worker_cfg.exact_template_file.read_text(encoding="utf-8"))
    login_req = template.get("login") if isinstance(template.get("login"), dict) else {}
    locale = context.query.get("lc.locale_on_game") or "en-US"
    headers = _apply_headers(login_req.get("headers_template") or {}, context=context, locale=locale)
    headers["content-type"] = "application/json"
    headers["accept"] = "application/json, text/plain, */*"
    if authorization_token:
        headers["authorization"] = "Bearer " + authorization_token
    else:
        headers.pop("authorization", None)
    return headers


def refresh_request(
    *,
    worker_cfg: WorkerConfig,
    context: LoginWebContext,
    old_bundle: LoginBundle,
    header_mode: str,
) -> RefreshResult:
    started = time.monotonic()
    device_id = str(context.query.get("device_id") or "").strip()
    if not device_id or not old_bundle.mid or not old_bundle.refresh_token:
        return RefreshResult(
            False,
            "REFRESH_INPUT_MISSING",
            0,
            None,
            header_mode,
            0.0,
            [],
            "device_id/mid/refresh_token is missing",
        )

    body = {
        "device_id": device_id,
        "mid": old_bundle.mid,
        "refresh_token": old_bundle.refresh_token,
    }
    auth_token = old_bundle.game_access_token if header_mode == "game_bearer" else ""
    headers = load_refresh_headers(
        worker_cfg=worker_cfg,
        context=context,
        authorization_token=auth_token,
    )

    session = requests.Session()
    try:
        response = session.post(
            REFRESH_URL,
            data=json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            timeout=worker_cfg.timeout_seconds,
            verify=worker_cfg.verify_ssl,
            allow_redirects=False,
        )
        elapsed_ms = (time.monotonic() - started) * 1000
        try:
            parsed = response.json()
        except Exception:
            parsed = None
        hit = find_login_payload(parsed)
        keys = public_json_keys(parsed)

        if not (200 <= response.status_code < 300):
            return RefreshResult(
                False,
                "REFRESH_HTTP_FAILED",
                int(response.status_code),
                None,
                header_mode,
                elapsed_ms,
                keys,
                "DevPlay refresh returned non-2xx",
            )
        if hit is None:
            return RefreshResult(
                False,
                "REFRESH_RESPONSE_NO_LOGIN_PAYLOAD",
                int(response.status_code),
                None,
                header_mode,
                elapsed_ms,
                keys,
                "Refresh response did not contain access-token fields",
            )
        refresh_token = str(hit.get("refresh_token") or hit.get("refreshToken") or old_bundle.refresh_token).strip()
        game_access_token = str(hit.get("game_access_token") or hit.get("gameAccessToken") or "").strip()
        oven_access_token = str(hit.get("oven_access_token") or hit.get("ovenAccessToken") or "").strip()
        member = hit.get("member") if isinstance(hit.get("member"), dict) else {}
        response_mid = str(
            member.get("mid")
            or hit.get("mid")
            or hit.get("player_id")
            or hit.get("playerId")
            or old_bundle.mid
        ).strip()
        device_secret = str(hit.get("device_secret") or hit.get("deviceSecret") or old_bundle.device_secret).strip()

        if not game_access_token or not oven_access_token:
            return RefreshResult(
                False,
                "REFRESH_RESPONSE_INVALID",
                int(response.status_code),
                None,
                header_mode,
                elapsed_ms,
                keys,
                "Refresh response did not contain both access tokens",
            )
        if response_mid != old_bundle.mid:
            return RefreshResult(
                False,
                "REFRESH_MID_MISMATCH",
                int(response.status_code),
                None,
                header_mode,
                elapsed_ms,
                keys,
                "Refresh response MID did not match the logged-in account",
            )

        game_exp = jwt_exp(game_access_token) or 0
        oven_exp = jwt_exp(oven_access_token) or 0
        exp_candidates = [x for x in (game_exp, oven_exp) if x > 0]
        expired_date_ms = min(exp_candidates) * 1000 if exp_candidates else 0
        bundle = LoginBundle(
            mid=old_bundle.mid,
            refresh_token=refresh_token,
            game_access_token=game_access_token,
            oven_access_token=oven_access_token,
            device_secret=device_secret,
            expired_date_ms=expired_date_ms,
        )
        return RefreshResult(
            True,
            "REFRESH_OK",
            int(response.status_code),
            bundle,
            header_mode,
            elapsed_ms,
            keys,
            "DevPlay access-token refresh passed",
        )
    except requests.Timeout:
        return RefreshResult(False, "REFRESH_TIMEOUT", 0, None, header_mode, (time.monotonic() - started) * 1000, [], "DevPlay refresh timed out")
    except requests.RequestException as exc:
        return RefreshResult(False, "REFRESH_NETWORK_ERROR", 0, None, header_mode, (time.monotonic() - started) * 1000, [], f"network:{type(exc).__name__}")
    finally:
        try:
            session.close()
        except Exception:
            pass


def refresh_with_header_discovery(
    *,
    worker_cfg: WorkerConfig,
    context: LoginWebContext,
    old_bundle: LoginBundle,
    preferred_mode: str | None,
) -> RefreshResult:
    if preferred_mode in {"base", "game_bearer"}:
        return refresh_request(
            worker_cfg=worker_cfg,
            context=context,
            old_bundle=old_bundle,
            header_mode=preferred_mode,
        )

    first = refresh_request(
        worker_cfg=worker_cfg,
        context=context,
        old_bundle=old_bundle,
        header_mode="base",
    )
    if first.ok:
        return first
    if first.http_status not in {401, 403}:
        return first
    return refresh_request(
        worker_cfg=worker_cfg,
        context=context,
        old_bundle=old_bundle,
        header_mode="game_bearer",
    )


def as_auth(*, context: LoginWebContext, bundle: LoginBundle) -> AuthRecord:
    return _legacy_auth(
        context=context,
        bundle=bundle,
        account_kind="refresh_lifetime_probe",
        account_id=0,
    )


def session_fp(session: SessionRecord | None) -> str:
    if session is None:
        return "NONE"
    return fp(session.session_key)


def append_jsonl(path: Path, event: dict[str, Any]) -> None:
    row = {
        "at": datetime.now(timezone.utc).isoformat(),
        **event,
        "secretOutput": SECRET_OUTPUT,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def emit_json(path: Path, event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    append_jsonl(path, payload)


def emit(text: str) -> None:
    print(text, flush=True)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Standalone DevPlay refresh-token lifetime probe")
    p.add_argument("--email", default=os.getenv("MWOIF_REFRESH_PROBE_EMAIL", ""))
    p.add_argument("--password", default=os.getenv("MWOIF_REFRESH_PROBE_PASSWORD", ""))
    p.add_argument("--hours", type=float, default=0.0, help="Run duration. 0 = until Ctrl+C")
    p.add_argument("--interval", type=int, default=60, help="Read-only verification interval in seconds")
    p.add_argument("--refresh-before", type=int, default=120, help="Refresh when minimum access-token TTL is <= this many seconds")
    p.add_argument("--skip-immediate-refresh", action="store_true", help="Do not prove the refresh contract immediately after login")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    email = str(args.email or "").strip()
    password = str(args.password or "")
    if not email:
        email = input("DevPlay email: ").strip()
    if not password:
        password = getpass.getpass("DevPlay password: ")
    if not email or not password:
        print("EMPTY_CREDENTIAL")
        return 2

    interval = max(15, int(args.interval))
    refresh_before = max(30, int(args.refresh_before))
    max_seconds = 0 if float(args.hours) <= 0 else int(float(args.hours) * 3600)

    worker_cfg = WorkerConfig.load(ROOT)
    context = load_login_web_context(worker_cfg.web_context_file, worker_cfg.login_url)
    if not context.complete:
        print("WEB_CONTEXT_INCOMPLETE")
        return 3

    runtime_cfg = build_devplay_runtime_config(load_config(ROOT / ".env"))
    replayer = ExactTemplateReplayer(
        template_file=worker_cfg.exact_template_file,
        timeout_seconds=worker_cfg.timeout_seconds,
        verify_ssl=worker_cfg.verify_ssl,
        warmup_get=worker_cfg.warmup_get,
    )

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    state_dir = ROOT / "state" / "devplay-refresh-lifetime" / stamp
    state_dir.mkdir(parents=True, exist_ok=True)
    log_path = state_dir / "run.jsonl"

    emit("M WOIF DEVPLAY REFRESH LIFETIME PROBE V1.3")
    emit("mode=STANDALONE workerService=UNTOUCHED webDatabase=UNTOUCHED secretOutput=NONE")
    duration_label = "UNTIL_CTRL_C" if max_seconds == 0 else f"{args.hours}h"
    emit(f"account={mask_email(email)} duration={duration_label} interval={interval}s refreshBefore={refresh_before}s")
    emit("STOP_POLICY=refresh or refreshed-access-token auth failure stops; initMember3 rebootstrap failure is diagnostic only")
    emit("FULL LOGIN START count=1")
    replay = replayer.replay(context=context, email=email, password=password, event_cb=emit)
    password = ""
    if not replay.ok or replay.bundle is None:
        emit(f"FULL LOGIN FAIL stage={replay.stage} code={replay.code} retryable={str(replay.retryable).lower()}")
        emit_json(log_path, "full_login_fail", stage=replay.stage, code=replay.code, retryable=replay.retryable)
        return 4

    bundle = replay.bundle
    replay = None
    login_pass_mono = time.monotonic()
    full_login_count = 1
    refresh_count = 0
    verify_pass = 0
    verify_fail = 0
    session_rebootstrap_count = 0
    session_rebootstrap_fail = 0
    refreshed_auth_verify_pass = 0
    refreshed_auth_verify_fail = 0
    header_mode: str | None = None

    initial_state = safe_token_state(bundle)
    emit(
        "TOKEN BASELINE "
        f"gameRemaining={initial_state['game_remaining_s']}s "
        f"ovenRemaining={initial_state['oven_remaining_s']}s "
        f"refresh=present:{initial_state['refresh_present']}"
    )
    emit_json(log_path, "login_pass", password_login_count=1, token=initial_state)

    auth = as_auth(context=context, bundle=bundle)
    try:
        game_session = bootstrap_session(runtime_cfg, "REFRESH_PROBE_INITIAL", auth, event_cb=emit)
    except Exception as exc:
        emit(f"INITIAL SESSION FAIL type={type(exc).__name__}")
        emit_json(log_path, "initial_session_fail", error_type=type(exc).__name__)
        return 5
    emit(f"INITIAL SESSION PASS sessionFp={session_fp(game_session)} lv={game_session.current_lv}")
    emit_json(log_path, "initial_session_pass", session_fp=session_fp(game_session), lv=game_session.current_lv)

    def apply_refresh(reason: str) -> bool:
        nonlocal bundle, auth, game_session, refresh_count, header_mode, session_rebootstrap_count, session_rebootstrap_fail, refreshed_auth_verify_pass, refreshed_auth_verify_fail
        before = safe_token_state(bundle)
        emit(
            f"REFRESH START reason={reason} count={refresh_count + 1} "
            f"gameRemaining={before['game_remaining_s']}s ovenRemaining={before['oven_remaining_s']}s"
        )
        result = refresh_with_header_discovery(
            worker_cfg=worker_cfg,
            context=context,
            old_bundle=bundle,
            preferred_mode=header_mode,
        )
        if not result.ok or result.bundle is None:
            lived_s = int(time.monotonic() - login_pass_mono)
            emit(
                f"REFRESH FAIL code={result.code} http={result.http_status} "
                f"headerMode={result.header_mode} elapsedMs={round(result.elapsed_ms)} responseKeys={','.join(result.response_keys)} "
                f"lifetimeSinceLogin={lived_s}s"
            )
            emit_json(
                log_path,
                "refresh_fail",
                reason=reason,
                code=result.code,
                http_status=result.http_status,
                header_mode=result.header_mode,
                elapsed_ms=round(result.elapsed_ms, 1),
                response_keys=result.response_keys,
            )
            return False

        after_bundle = result.bundle
        after = safe_token_state(after_bundle)
        game_changed = before["game_fp"] != after["game_fp"]
        oven_changed = before["oven_fp"] != after["oven_fp"]
        refresh_changed = before["refresh_fp"] != after["refresh_fp"]
        header_mode = result.header_mode
        refresh_count += 1
        bundle = after_bundle
        auth = as_auth(context=context, bundle=bundle)

        emit(
            "REFRESH PASS "
            f"count={refresh_count} headerMode={header_mode} http={result.http_status} "
            f"gameChanged={str(game_changed).lower()} ovenChanged={str(oven_changed).lower()} "
            f"refreshRotated={str(refresh_changed).lower()} "
            f"newGameRemaining={after['game_remaining_s']}s newOvenRemaining={after['oven_remaining_s']}s "
            f"elapsedMs={round(result.elapsed_ms)}"
        )
        emit_json(
            log_path,
            "refresh_pass",
            reason=reason,
            refresh_count=refresh_count,
            header_mode=header_mode,
            http_status=result.http_status,
            elapsed_ms=round(result.elapsed_ms, 1),
            game_changed=game_changed,
            oven_changed=oven_changed,
            refresh_rotated=refresh_changed,
            before=before,
            after=after,
        )

        auth_probe_ok = False
        auth_probe_last: dict[str, Any] = {}
        for auth_attempt in range(1, 4):
            probe_started = time.monotonic()
            try:
                auth_probe = list_friends(
                    cfg=runtime_cfg,
                    slot="REFRESH_AUTH_VERIFY",
                    auth=auth,
                    timeout=float(runtime_cfg.server.get("timeout_seconds") or 20),
                    live=True,
                    include_player_ids=False,
                )
            except Exception as exc:
                auth_probe = {"ok": False, "failure_class": type(exc).__name__, "grpc_code": "EXCEPTION"}
            probe_ms = round((time.monotonic() - probe_started) * 1000, 1)
            auth_probe_last = auth_probe if isinstance(auth_probe, dict) else {"ok": False}
            if auth_probe_last.get("ok"):
                refreshed_auth_verify_pass += 1
                auth_probe_ok = True
                emit(
                    f"REFRESHED AUTH VERIFY PASS refresh={refresh_count} attempt={auth_attempt}/3 "
                    f"friendCount={auth_probe_last.get('count', auth_probe_last.get('friend_count', 'n/a'))} elapsedMs={probe_ms}"
                )
                emit_json(
                    log_path,
                    "refreshed_auth_verify_pass",
                    refresh_count=refresh_count,
                    attempt=auth_attempt,
                    elapsed_ms=probe_ms,
                )
                break
            refreshed_auth_verify_fail += 1
            grpc_code = str(auth_probe_last.get("grpc_code") or "")
            failure_class = str(auth_probe_last.get("failure_class") or auth_probe_last.get("error") or "UNKNOWN")
            emit(
                f"REFRESHED AUTH VERIFY FAIL refresh={refresh_count} attempt={auth_attempt}/3 "
                f"grpc={grpc_code or 'NONE'} class={failure_class} elapsedMs={probe_ms}"
            )
            emit_json(
                log_path,
                "refreshed_auth_verify_fail",
                refresh_count=refresh_count,
                attempt=auth_attempt,
                grpc_code=grpc_code,
                failure_class=failure_class,
                elapsed_ms=probe_ms,
            )
            if auth_attempt < 3:
                time.sleep(2.0)

        if not auth_probe_ok:
            emit(
                f"REFRESH AUTH INVALID refresh={refresh_count} "
                f"grpc={str(auth_probe_last.get('grpc_code') or 'NONE')} "
                f"class={str(auth_probe_last.get('failure_class') or auth_probe_last.get('error') or 'UNKNOWN')}"
            )
            return False

        old_session_fp = session_fp(game_session)
        try:
            new_session = bootstrap_session(
                runtime_cfg,
                f"REFRESH_PROBE_AFTER_{refresh_count}",
                auth,
                event_cb=None,
            )
            session_rebootstrap_count += 1
            game_session = new_session
            emit(
                f"POST-REFRESH INIT PASS count={session_rebootstrap_count} "
                f"sessionChanged={str(old_session_fp != session_fp(new_session)).lower()} lv={new_session.current_lv}"
            )
            emit_json(
                log_path,
                "post_refresh_init_pass",
                refresh_count=refresh_count,
                session_rebootstrap_count=session_rebootstrap_count,
                session_changed=old_session_fp != session_fp(new_session),
                session_fp=session_fp(new_session),
                lv=new_session.current_lv,
            )
        except Exception as exc:
            session_rebootstrap_fail += 1
            detail = str(exc).replace("\r", " ").replace("\n", " ")[:240]
            emit(
                f"POST-REFRESH INIT WARN refresh={refresh_count} type={type(exc).__name__} "
                f"detail={detail} action=CONTINUE_AUTH_LIFETIME_TEST"
            )
            emit_json(
                log_path,
                "post_refresh_init_warn",
                refresh_count=refresh_count,
                error_type=type(exc).__name__,
                detail=detail,
                action="CONTINUE_AUTH_LIFETIME_TEST",
            )
        return True

    if not args.skip_immediate_refresh:
        if not apply_refresh("CONTRACT_PROBE"):
            lived_s = int(time.monotonic() - login_pass_mono)
            emit(f"STOPPED lifetimeSinceLogin={lived_s}s reason=REFRESH_CONTRACT_FAILED")
            emit("RESULT=REFRESH_CONTRACT_FAILED")
            emit_json(log_path, "summary", elapsed_s=lived_s, password_login_count=1, refresh_count=refresh_count, verify_pass=0, verify_fail=0, exit_code=6)
            emit(f"STATE={log_path}")
            return 6

    started = time.monotonic()
    next_probe = time.monotonic()
    crossed_30m = False
    crossed_60m = False
    next_hour_milestone = 2
    exit_code = 0

    try:
        while True:
            now_mono = time.monotonic()
            elapsed = int(now_mono - started)
            if max_seconds and elapsed >= max_seconds:
                break

            if elapsed >= 1800 and not crossed_30m:
                crossed_30m = True
                emit("MILESTONE 30M REACHED fullLoginCount=1")
                emit_json(log_path, "milestone", minutes=30, password_login_count=full_login_count, refresh_count=refresh_count)
            if elapsed >= 3600 and not crossed_60m:
                crossed_60m = True
                emit("MILESTONE 60M REACHED fullLoginCount=1")
                emit_json(log_path, "milestone", minutes=60, password_login_count=full_login_count, refresh_count=refresh_count)
            while elapsed >= next_hour_milestone * 3600:
                emit(f"MILESTONE {next_hour_milestone}H REACHED fullLoginCount={full_login_count} refreshCount={refresh_count} verifyPass={verify_pass}")
                emit_json(log_path, "milestone", hours=next_hour_milestone, password_login_count=full_login_count, refresh_count=refresh_count, verify_pass=verify_pass)
                next_hour_milestone += 1

            remaining = token_remaining(bundle)
            if remaining is not None and remaining <= refresh_before:
                if not apply_refresh("TTL_THRESHOLD"):
                    exit_code = 7
                    break
                remaining = token_remaining(bundle)

            if now_mono >= next_probe:
                probe_started = time.monotonic()
                try:
                    result = list_friends(
                        cfg=runtime_cfg,
                        slot="REFRESH_LIFETIME",
                        auth=auth,
                        timeout=float(runtime_cfg.server.get("timeout_seconds") or 20),
                        live=True,
                        include_player_ids=False,
                    )
                except Exception as exc:
                    result = {"ok": False, "failure_class": type(exc).__name__, "grpc_code": "EXCEPTION"}
                probe_ms = round((time.monotonic() - probe_started) * 1000, 1)
                if result.get("ok"):
                    verify_pass += 1
                    emit(
                        f"VERIFY PASS t=+{elapsed}s count={verify_pass} tokenRemaining={remaining}s "
                        f"friendCount={result.get('count', result.get('friend_count', 'n/a'))} elapsedMs={probe_ms}"
                    )
                    emit_json(
                        log_path,
                        "verify_pass",
                        elapsed_s=elapsed,
                        verify_pass=verify_pass,
                        token_remaining_s=remaining,
                        elapsed_ms=probe_ms,
                    )
                else:
                    verify_fail += 1
                    grpc_code = str(result.get("grpc_code") or "")
                    failure_class = str(result.get("failure_class") or result.get("error") or "UNKNOWN")
                    emit(
                        f"VERIFY FAIL t=+{elapsed}s count={verify_fail} grpc={grpc_code or 'NONE'} "
                        f"class={failure_class} tokenRemaining={remaining}s"
                    )
                    emit_json(
                        log_path,
                        "verify_fail",
                        elapsed_s=elapsed,
                        verify_fail=verify_fail,
                        grpc_code=grpc_code,
                        failure_class=failure_class,
                        token_remaining_s=remaining,
                    )
                    if grpc_code in {"UNAUTHENTICATED", "PERMISSION_DENIED"}:
                        if not apply_refresh("AUTH_FAILURE"):
                            exit_code = 8
                            break
                next_probe = now_mono + interval

            time.sleep(min(1.0, max(0.1, next_probe - time.monotonic())))
    except KeyboardInterrupt:
        emit("STOP requested=CTRL_C")

    elapsed_total = int(time.monotonic() - login_pass_mono)
    final_state = safe_token_state(bundle)
    emit(
        "SUMMARY "
        f"elapsed={elapsed_total}s fullLoginCount={full_login_count} refreshCount={refresh_count} "
        f"sessionRebootstrapCount={session_rebootstrap_count} sessionRebootstrapFail={session_rebootstrap_fail} "
        f"refreshedAuthVerifyPass={refreshed_auth_verify_pass} refreshedAuthVerifyFail={refreshed_auth_verify_fail} "
        f"verifyPass={verify_pass} verifyFail={verify_fail} "
        f"gameRemaining={final_state['game_remaining_s']}s ovenRemaining={final_state['oven_remaining_s']}s"
    )
    if elapsed_total >= 2100 and full_login_count == 1 and refresh_count >= 1 and verify_pass >= 1 and exit_code == 0:
        emit("RESULT=PASS_BEYOND_30_MIN_WITHOUT_PASSWORD_RELOGIN")
    elif exit_code == 0:
        emit("RESULT=RUN_COMPLETE")
    else:
        emit(f"STOPPED lifetimeSinceLogin={elapsed_total}s reason=REFRESH_OR_AUTH_FAILURE")
        emit("RESULT=STOPPED_ON_REFRESH_OR_AUTH_FAILURE")
    emit_json(
        log_path,
        "summary",
        elapsed_s=elapsed_total,
        password_login_count=full_login_count,
        refresh_count=refresh_count,
        session_rebootstrap_count=session_rebootstrap_count,
        session_rebootstrap_fail=session_rebootstrap_fail,
        refreshed_auth_verify_pass=refreshed_auth_verify_pass,
        refreshed_auth_verify_fail=refreshed_auth_verify_fail,
        verify_pass=verify_pass,
        verify_fail=verify_fail,
        crossed_30m=crossed_30m,
        crossed_60m=crossed_60m,
        final_token=final_state,
        exit_code=exit_code,
    )
    emit(f"STATE={log_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
