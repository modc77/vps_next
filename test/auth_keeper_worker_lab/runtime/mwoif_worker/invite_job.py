from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from mwoif.friend.service import remove_friend
from mwoif.invite.service import set_referrer
from mwoif.invite.snapshot import InviteSnapshotError, fetch_invite_member_snapshot
from mwoif_worker.claim import _api_key, _read_state, _state_path, _worker_code, clear_claim_state
from mwoif_worker.heart_one import HeartOneRuntimeError, _login_and_session
from mwoif_worker.provider_guard import get_provider_guard
from mwoif_worker.receiver_login import _credential_url as _receiver_credential_url
from mwoif_worker.work_security import signed_headers

Event = Callable[[str], None]


class InviteJobError(RuntimeError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


@dataclass(slots=True)
class InviteJobResult:
    ok: bool
    code: str
    message: str
    retryable: bool
    elapsed_ms: float
    sj_id: int | None = None
    progress_value: int | None = None
    target_value: int | None = 29
    recovery_required: bool = False


@dataclass(slots=True)
class PreparedSender:
    sender: dict[str, Any]
    lease_token: str
    email: str = ""
    password: str = ""
    cfg: Any = None
    auth: Any = None
    session: Any = None
    error_code: str = ""
    level: int = 0


def _event(cb: Event | None, text: str) -> None:
    if cb:
        cb(text)


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(str(os.getenv(name) or default).strip())
    except Exception:
        value = default
    return max(lo, min(hi, value))


def _endpoint_from_receiver(filename: str) -> str:
    base = _receiver_credential_url()
    parts = urlsplit(base)
    path = parts.path.rsplit('/', 1)[0] + '/' + filename
    return urlunsplit((parts.scheme, parts.netloc, path, '', ''))


def _safe_json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode('utf-8'))
    except Exception as exc:
        raise InviteJobError('WORK_RESPONSE_INVALID') from exc
    if not isinstance(value, dict):
        raise InviteJobError('WORK_RESPONSE_INVALID')
    return value


def _post(
    url: str,
    *,
    api_key: str,
    claim_token: str,
    payload: dict[str, Any],
    sender_lease_token: str | None = None,
    timeout: int = 20,
) -> tuple[int, dict[str, Any]]:
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    extra = {
        'X-MWOIF-Claim-Token': claim_token,
        'User-Agent': 'MWOIF-Services-Worker/invite-pump-r8',
    }
    if sender_lease_token:
        extra['X-MWOIF-Sender-Lease-Token'] = sender_lease_token
    req = Request(url, data=body, method='POST', headers=signed_headers(url, body, api_key=api_key, extra=extra))
    try:
        with build_opener(_NoRedirect()).open(req, timeout=timeout) as response:
            status = int(getattr(response, 'status', 200))
            raw = response.read(65537)
            if len(raw) > 65536:
                raise InviteJobError('WORK_RESPONSE_TOO_LARGE')
            return status, _safe_json(raw)
    except HTTPError as exc:
        status = int(exc.code or 0)
        try:
            raw = exc.read(65537)
            data = _safe_json(raw) if raw and len(raw) <= 65536 else {}
        except Exception:
            data = {}
        return status, {
            'ok': bool(data.get('ok', False)),
            'code': str(data.get('code') or 'WORK_HTTP_ERROR'),
            'message': str(data.get('message') or 'Worker endpoint request failed'),
            'retryable': bool(data.get('retryable', status >= 500 or status in {408, 409, 425, 429})),
        }


def _active_claim() -> tuple[str, int, str, dict[str, Any]]:
    worker_code = _worker_code()
    state = _read_state(_state_path(), worker_code)
    if not isinstance(state, dict):
        raise InviteJobError('INVITE_ACTIVE_CLAIM_MISSING')
    token = state.get('claim_token')
    job = state.get('job')
    if not isinstance(token, str) or len(token) < 32 or not isinstance(job, dict):
        raise InviteJobError('INVITE_ACTIVE_CLAIM_INVALID')
    sj_id = int(job.get('sj_id') or 0)
    if sj_id < 1 or str(job.get('service_code') or '').upper() != 'INVITE_PUMP':
        raise InviteJobError('INVITE_ACTIVE_CLAIM_INVALID')
    if int(job.get('target_value') or 0) != 29:
        raise InviteJobError('INVITE_TARGET_INVALID')
    return worker_code, sj_id, token, job


def _receiver_credential(version: str, api_key: str, worker_code: str, sj_id: int, claim_token: str) -> tuple[str, str]:
    status, data = _post(
        _receiver_credential_url(),
        api_key=api_key,
        claim_token=claim_token,
        payload={'worker_code': worker_code, 'version': str(version or '')[:64], 'sj_id': sj_id},
    )
    cred = data.get('credential') if isinstance(data.get('credential'), dict) else {}
    email = str(cred.get('email') or '').strip()
    password = str(cred.get('password') or '')
    if status != 200 or not bool(data.get('ok')) or not email or not password:
        raise InviteJobError(str(data.get('code') or 'RECEIVER_CREDENTIAL_FAILED'))
    return email, password


def _sync_progress(version: str, api_key: str, worker_code: str, sj_id: int, claim_token: str, count: int) -> dict[str, Any]:
    status, data = _post(
        _endpoint_from_receiver('invite-progress-sync.php'),
        api_key=api_key,
        claim_token=claim_token,
        payload={'worker_code': worker_code, 'version': str(version or '')[:64], 'sj_id': sj_id, 'current_count': count},
    )
    if status != 200 or not bool(data.get('ok')):
        raise InviteJobError(str(data.get('code') or 'INVITE_PROGRESS_SYNC_FAILED'))
    return data


def _lease_sender(version: str, api_key: str, worker_code: str, sj_id: int, claim_token: str) -> tuple[dict[str, Any], str]:
    lease_token = secrets.token_urlsafe(32)
    lease_hash = hashlib.sha256(lease_token.encode('utf-8')).hexdigest()
    status, data = _post(
        _endpoint_from_receiver('invite-sender-lease.php'),
        api_key=api_key,
        claim_token=claim_token,
        payload={
            'worker_code': worker_code,
            'version': str(version or '')[:64],
            'sj_id': sj_id,
            'lease_token_hash': lease_hash,
        },
    )
    if status != 200 or not bool(data.get('ok')):
        raise InviteJobError(str(data.get('code') or 'INVITE_SENDER_LEASE_FAILED'))
    if not bool(data.get('leased')):
        raise InviteJobError(str(data.get('code') or 'NO_READY_INVITE_SENDER'))
    sender = data.get('sender') if isinstance(data.get('sender'), dict) else None
    if not isinstance(sender, dict) or int(sender.get('sga_id') or 0) < 1:
        raise InviteJobError('INVITE_SENDER_LEASE_INVALID')
    return sender, lease_token


def _sender_credential(version: str, api_key: str, worker_code: str, sj_id: int, claim_token: str, sender: dict[str, Any], lease_token: str) -> tuple[str, str]:
    status, data = _post(
        _endpoint_from_receiver('invite-sender-credential.php'),
        api_key=api_key,
        claim_token=claim_token,
        payload={
            'worker_code': worker_code,
            'version': str(version or '')[:64],
            'sj_id': sj_id,
            'sga_id': int(sender['sga_id']),
            'lease_token': lease_token,
        },
    )
    item = data.get('sender') if isinstance(data.get('sender'), dict) else {}
    email = str(item.get('email') or '').strip()
    password = str(item.get('password') or '')
    if status != 200 or not bool(data.get('ok')) or not email or not password:
        raise InviteJobError(str(data.get('code') or 'INVITE_SENDER_CREDENTIAL_FAILED'))
    return email, password


def _report_step(
    version: str,
    api_key: str,
    worker_code: str,
    sj_id: int,
    claim_token: str,
    sender: dict[str, Any],
    lease_token: str,
    *,
    outcome: str,
    before: int,
    after: int,
    actual_level: int,
    error_code: str = '',
    cleanup_ok: bool = True,
    cleanup_error_code: str = '',
) -> dict[str, Any]:
    status, data = _post(
        _endpoint_from_receiver('invite-step-result.php'),
        api_key=api_key,
        claim_token=claim_token,
        sender_lease_token=lease_token,
        payload={
            'worker_code': worker_code,
            'version': str(version or '')[:64],
            'sj_id': sj_id,
            'sga_id': int(sender['sga_id']),
            'outcome': outcome,
            'before_count': before,
            'after_count': after,
            'actual_level': actual_level,
            'error_code': str(error_code or '')[:80],
            'cleanup_ok': bool(cleanup_ok),
            'cleanup_error_code': str(cleanup_error_code or '')[:80],
        },
    )
    if status != 200 or not bool(data.get('ok')):
        raise InviteJobError(str(data.get('code') or 'INVITE_STEP_RESULT_FAILED'))
    return data


def _prepare_sender_batch(
    *,
    version: str,
    api_key: str,
    worker_code: str,
    sj_id: int,
    claim_token: str,
    wanted: int,
    login_workers: int,
    event_cb: Event | None,
) -> list[PreparedSender]:
    prepared: list[PreparedSender] = []
    for _ in range(max(0, wanted)):
        try:
            sender, lease_token = _lease_sender(version, api_key, worker_code, sj_id, claim_token)
        except InviteJobError as exc:
            if str(exc) == 'NO_READY_INVITE_SENDER':
                break
            raise
        item = PreparedSender(sender=sender, lease_token=lease_token)
        try:
            item.email, item.password = _sender_credential(version, api_key, worker_code, sj_id, claim_token, sender, lease_token)
        except Exception as exc:
            item.error_code = str(getattr(exc, 'code', '') or str(exc) or 'INVITE_SENDER_CREDENTIAL_FAILED').upper()[:80]
        prepared.append(item)

    login_items = [item for item in prepared if not item.error_code]
    if login_items:
        _event(event_cb, f'INVITE LOGIN BATCH START count={len(login_items)} workers={min(login_workers,len(login_items))} secretOutput=NONE')

        def login_one(item: PreparedSender) -> PreparedSender:
            sga_id = int(item.sender['sga_id'])
            try:
                cfg, auth, session = _login_and_session(
                    email=item.email,
                    password=item.password,
                    account_kind='sender',
                    account_id=sga_id,
                    slot=f'INVITE_{sga_id}',
                    event_cb=None,
                )
                item.cfg = cfg
                item.auth = auth
                item.session = session
                item.level = int(session.current_lv or 0)
            except HeartOneRuntimeError as exc:
                item.error_code = str(exc.code or 'INVITE_SENDER_LOGIN_FAILED')[:80]
            except Exception as exc:
                item.error_code = str(getattr(exc, 'code', '') or type(exc).__name__).upper()[:80]
            finally:
                item.password = ''
            return item

        with ThreadPoolExecutor(max_workers=max(1, min(login_workers, len(login_items)))) as pool:
            futures = [pool.submit(login_one, item) for item in login_items]
            for future in as_completed(futures):
                future.result()

        ok_count = sum(1 for item in login_items if not item.error_code)
        _event(event_cb, f'INVITE LOGIN BATCH DONE pass={ok_count} fail={len(login_items)-ok_count} secretOutput=NONE')

    return prepared


def _cleanup_exact_invited_friend(
    *,
    cfg,
    target_auth,
    invited_mid: str,
    timeout: float,
    attempts: int,
    event_cb: Event | None,
) -> tuple[bool, str]:
    mid = str(invited_mid or '').strip()
    if not mid:
        return False, 'INVITE_CLEANUP_SENDER_MID_MISSING'
    last_code = 'INVITE_FRIEND_CLEANUP_FAILED'
    for attempt in range(1, max(1, attempts) + 1):
        try:
            result = remove_friend(
                cfg=cfg,
                slot='INVITER_CLEANUP',
                auth=target_auth,
                target_mids=[mid],
                timeout=timeout,
                live=True,
            )
            if bool(result.get('ok')):
                _event(event_cb, f'INVITE FRIEND CLEANUP PASS attempt={attempt}/{attempts} target=EXACT_INVITED_SENDER secretOutput=NONE')
                return True, ''
            last_code = str(result.get('grpc_code') or result.get('error') or 'INVITE_FRIEND_CLEANUP_FAILED').upper()[:80]
        except Exception as exc:
            last_code = str(getattr(exc, 'code', '') or type(exc).__name__).upper()[:80]
        if attempt < attempts:
            time.sleep(0.20 * attempt)
    _event(event_cb, f'INVITE FRIEND CLEANUP FAIL code={last_code} target=EXACT_INVITED_SENDER secretOutput=NONE')
    return False, last_code


def invite_job_run(version: str, *, live: bool, event_cb: Event | None = None, stop_event=None) -> InviteJobResult:
    started = time.perf_counter()
    sj_id: int | None = None
    progress = 0
    failures = 0
    try:
        if not live:
            raise InviteJobError('INVITE_LIVE_REQUIRED')

        batch_size = _env_int('MWOIF_INVITE_LOGIN_BATCH_SIZE', 10, 1, 10)
        login_workers = _env_int('MWOIF_INVITE_LOGIN_WORKERS', 10, 1, 10)
        max_failures = _env_int('MWOIF_INVITE_MAX_FAILED_SENDERS', 20, 3, 60)
        cleanup_attempts = _env_int('MWOIF_INVITE_CLEANUP_ATTEMPTS', 3, 1, 5)
        cleanup_timeout = float(_env_int('MWOIF_INVITE_CLEANUP_TIMEOUT_SECONDS', 8, 3, 20))

        api_key = _api_key()
        worker_code, sj_id, claim_token, job = _active_claim()
        referrer_player_id = str(job.get('invite_referrer_player_id') or '').strip()
        if not referrer_player_id or len(referrer_player_id) > 128:
            raise InviteJobError('INVITE_REFERRER_ID_MISSING')
        invite_mode = 'link_only' if str(job.get('invite_mode') or '').strip().lower() == 'link_only' else 'full'
        cleanup_required = bool(job.get('invite_cleanup_required', invite_mode != 'link_only')) and invite_mode != 'link_only'
        target_cfg = None
        target_auth = None

        if invite_mode == 'link_only':
            progress = max(0, min(29, int(job.get('completed_value') or 0)))
            _event(event_cb, f'INVITE LINK ONLY START current={progress} target=29 remaining={max(0,29-progress)} batch={batch_size} loginWorkers={login_workers} cleanup=false secretOutput=NONE')
            if progress >= 29:
                clear_claim_state()
                return InviteJobResult(True, 'INVITE_ALREADY_COMPLETED', 'Link-only invite job is already 29/29', False, (time.perf_counter()-started)*1000.0, sj_id, 29, 29)
        else:
            target_email, target_password = _receiver_credential(version, api_key, worker_code, sj_id, claim_token)
            _event(event_cb, f'INVITE TARGET LOGIN START sj_id={sj_id} secretOutput=NONE')
            try:
                target_cfg, target_auth, _target_session = _login_and_session(
                    email=target_email,
                    password=target_password,
                    account_kind='receiver',
                    account_id=sj_id,
                    slot='INVITER',
                    event_cb=event_cb,
                )
            except HeartOneRuntimeError as exc:
                opened, provider_snapshot = get_provider_guard().record_failure(
                    sj_id,
                    str(exc.code or 'INVITE_TARGET_LOGIN_FAILED'),
                    stage='GAME_SESSION' if str(exc.code or '').upper() == 'INITMEMBER3_FAILED' else 'LOGIN',
                    retryable=bool(exc.retryable),
                )
                if opened or get_provider_guard().is_open():
                    _event(event_cb, f'INVITE PROVIDER GUARD OPEN source=TARGET distinct={provider_snapshot.distinct_accounts}/{provider_snapshot.threshold} primary={provider_snapshot.primary_code or exc.code} secretOutput=NONE')
                    return InviteJobResult(False, 'PROVIDER_IP_LIMIT_SUSPECTED', 'Provider login circuit opened; router recovery will handle the incident', True, (time.perf_counter()-started)*1000.0, sj_id, progress, 29)
                raise
            target_password = ''
            get_provider_guard().record_success(sj_id)
            snapshot = fetch_invite_member_snapshot(target_cfg, slot='INVITER_VERIFY', auth=target_auth, event_cb=event_cb)
            progress = int(snapshot.friend_invite_count)
            owners = {str(snapshot.session.member_seq), str(target_auth.mid or '').strip()}
            if referrer_player_id not in owners:
                raise InviteJobError('INVITE_ONELINK_OWNER_MISMATCH')

            sync = _sync_progress(version, api_key, worker_code, sj_id, claim_token, progress)
            sync_job = sync.get('job') if isinstance(sync.get('job'), dict) else {}
            progress = int(sync_job.get('completed_value') or progress)
            _event(event_cb, f'INVITE TARGET CHECK current={progress} target=29 remaining={max(0,29-progress)} batch={batch_size} loginWorkers={login_workers} secretOutput=NONE')
            if progress >= 29 or str(sync_job.get('status') or '') == 'completed':
                clear_claim_state()
                return InviteJobResult(True, 'INVITE_ALREADY_COMPLETED', 'Invite target is already 29/29', False, (time.perf_counter()-started)*1000.0, sj_id, 29, 29)

        while progress < 29:
            if stop_event is not None and getattr(stop_event, 'is_set', lambda: False)():
                return InviteJobResult(False, 'INVITE_CONTROL_STOP', 'Invite job stopped before a new Sender batch was leased', True, (time.perf_counter()-started)*1000.0, sj_id, progress, 29)
            if failures >= max_failures:
                return InviteJobResult(False, 'INVITE_TOO_MANY_SENDER_FAILURES', 'Too many Invite Sender accounts failed validation/login', True, (time.perf_counter()-started)*1000.0, sj_id, progress, 29)

            wanted = min(batch_size, 29 - progress)
            batch = _prepare_sender_batch(
                version=version,
                api_key=api_key,
                worker_code=worker_code,
                sj_id=sj_id,
                claim_token=claim_token,
                wanted=wanted,
                login_workers=login_workers,
                event_cb=event_cb,
            )
            if not batch:
                return InviteJobResult(False, 'NO_READY_INVITE_SENDER', 'No ready Invite Sender account is available', True, (time.perf_counter()-started)*1000.0, sj_id, progress, 29)

            for item in batch:
                sender = item.sender
                lease_token = item.lease_token
                sga_id = int(sender['sga_id'])

                if item.error_code:
                    _event(event_cb, f'INVITE SENDER ERROR sga_id={sga_id} stage=LOGIN code={item.error_code} switch=NEXT secretOutput=NONE')
                    _report_step(version, api_key, worker_code, sj_id, claim_token, sender, lease_token, outcome='login_error', before=progress, after=progress, actual_level=0, error_code=item.error_code)
                    failures += 1
                    opened, provider_snapshot = get_provider_guard().record_failure(
                        sga_id,
                        item.error_code,
                        stage='GAME_SESSION' if item.error_code == 'INITMEMBER3_FAILED' else 'LOGIN',
                        retryable=True,
                    )
                    if opened or get_provider_guard().is_open():
                        _event(event_cb, f'INVITE PROVIDER GUARD OPEN distinct={provider_snapshot.distinct_accounts}/{provider_snapshot.threshold} primary={provider_snapshot.primary_code or item.error_code} secretOutput=NONE')
                        return InviteJobResult(False, 'PROVIDER_IP_LIMIT_SUSPECTED', 'Provider login circuit opened; router recovery will handle the incident', True, (time.perf_counter()-started)*1000.0, sj_id, progress, 29)
                    continue

                level = int(item.level or 0)
                eligible = level >= 5
                _event(event_cb, f'INVITE ACCOUNT CHECK sga_id={sga_id} lv={level} requiredLv=5 eligible={"YES" if eligible else "NO"} secretOutput=NONE')
                if not eligible:
                    _report_step(version, api_key, worker_code, sj_id, claim_token, sender, lease_token, outcome='level_too_low', before=progress, after=progress, actual_level=level, error_code='INVITE_SENDER_LEVEL_TOO_LOW')
                    failures += 1
                    continue
                get_provider_guard().record_success(sga_id)

                _event(event_cb, f'SET_REFERRER START sga_id={sga_id} before={progress} networkWrite=YES mode={invite_mode} secretOutput=NONE')
                grpc = set_referrer(cfg=item.cfg, auth=item.auth, referrer_player_id=referrer_player_id, slot=f'INVITE_{sga_id}', timeout=20.0, live=True)
                if not bool(grpc.get('ok')):
                    code = str(grpc.get('error') or grpc.get('failure_class') or grpc.get('grpc_code') or 'INVITE_SET_REFERRER_UNCERTAIN').upper()[:80]
                    _report_step(version, api_key, worker_code, sj_id, claim_token, sender, lease_token, outcome='ambiguous', before=progress, after=progress, actual_level=level, error_code=code)
                    clear_claim_state()
                    return InviteJobResult(False, 'INVITE_SET_REFERRER_UNCERTAIN', 'SetReferrer result is not safe to retry automatically', False, (time.perf_counter()-started)*1000.0, sj_id, progress, 29, True)

                if invite_mode == 'link_only':
                    after = min(29, progress + 1)
                    cleanup_ok, cleanup_error = True, ''
                    _event(event_cb, f'INVITE LINK ONLY ACCEPTED sga_id={sga_id} progress={after}/29 cleanup=SKIP secretOutput=NONE')
                else:
                    after = progress
                    for attempt in range(1, 6):
                        verified = fetch_invite_member_snapshot(target_cfg, slot='INVITER_VERIFY', auth=target_auth, event_cb=None)
                        after = int(verified.friend_invite_count)
                        _event(event_cb, f'INVITE VERIFY attempt={attempt}/5 before={progress} after={after} secretOutput=NONE')
                        if after == progress + 1:
                            break
                        if after > progress + 1:
                            break
                        if attempt < 5:
                            time.sleep(0.35)

                    if after != progress + 1:
                        _report_step(version, api_key, worker_code, sj_id, claim_token, sender, lease_token, outcome='ambiguous', before=progress, after=min(29, max(0, after)), actual_level=level, error_code='INVITE_VERIFY_DELTA_INVALID')
                        clear_claim_state()
                        return InviteJobResult(False, 'INVITE_VERIFY_AMBIGUOUS', 'SetReferrer was sent but exact +1 verification did not pass', False, (time.perf_counter()-started)*1000.0, sj_id, progress, 29, True)

                    cleanup_ok, cleanup_error = _cleanup_exact_invited_friend(
                        cfg=target_cfg,
                        target_auth=target_auth,
                        invited_mid=str(item.auth.mid or ''),
                        timeout=cleanup_timeout,
                        attempts=cleanup_attempts,
                        event_cb=event_cb,
                    ) if cleanup_required else (True, '')

                result = _report_step(
                    version,
                    api_key,
                    worker_code,
                    sj_id,
                    claim_token,
                    sender,
                    lease_token,
                    outcome='success',
                    before=progress,
                    after=after,
                    actual_level=level,
                    cleanup_ok=cleanup_ok,
                    cleanup_error_code=cleanup_error,
                )
                result_job = result.get('job') if isinstance(result.get('job'), dict) else {}
                progress = int(result_job.get('completed_value') or after)
                job_status = str(result_job.get('status') or '')
                _event(event_cb, f'INVITE STEP PASS sga_id={sga_id} progress={progress}/29 mode={invite_mode} cleanup={"OK" if cleanup_ok and cleanup_required else ("SKIP" if not cleanup_required else "FAILED")} promoted=HEART_SENDER secretOutput=NONE')

                if (cleanup_required and not cleanup_ok) or job_status == 'paused':
                    clear_claim_state()
                    return InviteJobResult(False, str(result.get('code') or 'INVITE_FRIEND_CLEANUP_FAILED'), 'Invite step completed but required cleanup did not complete', False, (time.perf_counter()-started)*1000.0, sj_id, progress, 29, True)

                if progress >= 29 or job_status == 'completed':
                    clear_claim_state()
                    elapsed = (time.perf_counter() - started) * 1000.0
                    _event(event_cb, f'INVITE PUMP COMPLETE progress=29/29 elapsed={elapsed/1000.0:.2f}s secretOutput=NONE')
                    return InviteJobResult(True, 'INVITE_PUMP_COMPLETED', 'Invite target reached 29/29' + (' with exact invited-friend cleanup' if cleanup_required else ' in Link-only mode'), False, elapsed, sj_id, 29, 29)

        clear_claim_state()
        return InviteJobResult(True, 'INVITE_PUMP_COMPLETED', 'Invite target reached 29/29', False, (time.perf_counter()-started)*1000.0, sj_id, 29, 29)

    except (InviteJobError, InviteSnapshotError, HeartOneRuntimeError) as exc:
        code = str(getattr(exc, 'code', '') or str(exc) or type(exc).__name__)[:80]
        return InviteJobResult(False, code, 'Invite job stopped before completion', code in {'NO_READY_INVITE_SENDER','INVITE_PROGRESS_SYNC_FAILED'}, (time.perf_counter()-started)*1000.0, sj_id, progress, 29)
    except (URLError, TimeoutError, OSError):
        return InviteJobResult(False, 'INVITE_WORK_NETWORK_ERROR', 'Invite Work endpoint is temporarily unreachable', True, (time.perf_counter()-started)*1000.0, sj_id, progress, 29)
    except Exception as exc:
        code = str(getattr(exc, 'code', '') or type(exc).__name__)[:80]
        return InviteJobResult(False, f'INVITE_UNHANDLED_{code}', 'Invite job failed unexpectedly', True, (time.perf_counter()-started)*1000.0, sj_id, progress, 29)
