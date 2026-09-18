from __future__ import annotations

import os
import time
from dataclasses import dataclass
from secrets import SystemRandom
from typing import Any, Callable

from mwoif.friend.service import handle_friend_request, list_friends, remove_friend

Event = Callable[[str], None]
_PENDING_PATH = (3, 1, 1)
_IGNORED_PATHS = {(4,)}
_RNG = SystemRandom()


class ReceiverRelationshipError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    try:
        value = int(str(os.getenv(name) or default).strip())
    except Exception:
        value = default
    return max(lo, min(hi, value))


def _decode_path(value: Any) -> tuple[int, ...] | None:
    if not isinstance(value, list) or not value:
        return None
    out: list[int] = []
    for item in value:
        try:
            n = int(item)
        except Exception:
            return None
        if n < 1:
            return None
        out.append(n)
    return tuple(out)


@dataclass(frozen=True, slots=True)
class RelationshipSnapshot:
    friend_count: int
    friend_ids: tuple[str, ...]
    friend_path: tuple[int, ...] | None
    friend_upper_bound: int
    pending_count: int
    pending_ids: tuple[str, ...]
    groups: tuple[tuple[tuple[int, ...], tuple[str, ...]], ...]


@dataclass(frozen=True, slots=True)
class ReceiverReadinessResult:
    friends_bound: int
    pending_count: int
    capacity: int
    available_at_least: int
    required_free_slots: int
    relationship_ready: bool


@dataclass(frozen=True, slots=True)
class ReceiverPreflightResult:
    friends_before: int
    pending_before: int
    rejected_pending: int
    trimmed_friends: int
    friends_after: int
    pending_after: int
    available_slots: int
    calibrated: bool


@dataclass(frozen=True, slots=True)
class BatchRelationshipReconcileResult:
    requested: int
    pending_before: int
    friends_before: int
    pending_rejected: int
    friends_removed: int
    resolved_mids: tuple[str, ...]
    unresolved_mids: tuple[str, ...]


def _groups_from_result(result: dict[str, Any]) -> tuple[tuple[tuple[int, ...], tuple[str, ...]], ...]:
    groups: dict[tuple[int, ...], tuple[str, ...]] = {}
    rows = result.get("candidate_group_player_ids")
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            path = _decode_path(row.get("path"))
            values = row.get("player_ids")
            if path is None or not isinstance(values, list):
                continue
            ids = tuple(dict.fromkeys(str(v).strip() for v in values if str(v).strip()))[:300]
            if ids:
                groups[path] = ids
    return tuple(sorted(groups.items(), key=lambda item: (len(item[1]), len(item[0])), reverse=True))


def _friend_candidates(groups: tuple[tuple[tuple[int, ...], tuple[str, ...]], ...]) -> list[tuple[tuple[int, ...], tuple[str, ...]]]:
    return [
        (path, ids)
        for path, ids in groups
        if path != _PENDING_PATH and path not in _IGNORED_PATHS and ids
    ]


def _read_snapshot(cfg, receiver_auth, *, timeout: float, friend_path: tuple[int, ...] | None = None) -> RelationshipSnapshot:
    result = list_friends(
        cfg=cfg,
        slot="R",
        auth=receiver_auth,
        timeout=timeout,
        live=True,
        capacity=300,
        include_player_ids=True,
    )
    if not bool(result.get("ok")):
        code = str(result.get("grpc_code") or result.get("error") or "FRIEND_LIST_FAILED")[:80]
        raise ReceiverRelationshipError(code, "Receiver friend list request failed", retryable=True)
    groups = _groups_from_result(result)
    confidence = str(result.get("parser_confidence") or "none").lower()
    if int(result.get("response_bytes") or 0) > 0 and not groups and confidence == "none":
        raise ReceiverRelationshipError("FRIEND_LIST_PARSE_FAILED", "Receiver friend list could not be parsed", retryable=True)

    mapping = dict(groups)
    pending_ids = mapping.get(_PENDING_PATH, ())
    candidates = _friend_candidates(groups)
    friend_upper_bound = max((len(ids) for _path, ids in candidates), default=0)
    friend_ids = mapping.get(friend_path, ()) if friend_path is not None else ()

    return RelationshipSnapshot(
        friend_count=len(friend_ids),
        friend_ids=friend_ids,
        friend_path=friend_path if friend_ids else None,
        friend_upper_bound=max(len(friend_ids), friend_upper_bound),
        pending_count=len(pending_ids),
        pending_ids=pending_ids,
        groups=groups,
    )


def receiver_relationship_readiness(
    cfg,
    receiver_auth,
    *,
    required_free_slots: int = 100,
    capacity: int = 300,
) -> ReceiverReadinessResult:
    capacity = max(1, int(capacity))
    required_free_slots = max(1, min(capacity, int(required_free_slots)))
    timeout = float(max(3, min(20, _env_int("MWOIF_RECEIVER_RELATIONSHIP_TIMEOUT_SECONDS", 12, 3, 20))))
    snapshot = _read_snapshot(cfg, receiver_auth, timeout=timeout)
    friend_bound = max(0, min(capacity, int(snapshot.friend_upper_bound)))
    available = max(0, capacity - friend_bound)
    return ReceiverReadinessResult(
        friends_bound=friend_bound,
        pending_count=max(0, int(snapshot.pending_count)),
        capacity=capacity,
        available_at_least=available,
        required_free_slots=required_free_slots,
        relationship_ready=available >= required_free_slots,
    )


def _failure_code(result: dict[str, Any] | None) -> str:
    if not isinstance(result, dict):
        return "UNKNOWN"
    return str(result.get("grpc_code") or result.get("error") or "UNKNOWN")[:80]


def _format_failures(failures: dict[str, int]) -> str:
    if not failures:
        return "none"
    return ",".join(f"{code}:{count}" for code, count in sorted(failures.items()))[:240]


def _reject_pending(cfg, receiver_auth, mids: tuple[str, ...], *, timeout: float) -> tuple[int, dict[str, int]]:
    ok_count = 0
    failures: dict[str, int] = {}
    for mid in mids:
        try:
            result = handle_friend_request(
                cfg=cfg,
                slot="R",
                auth=receiver_auth,
                target_mid=mid,
                accept=False,
                timeout=timeout,
                live=True,
            )
        except Exception as exc:
            code = str(getattr(exc, "code", None) or type(exc).__name__)[:80]
            failures[code] = failures.get(code, 0) + 1
            continue
        if bool(result.get("ok")):
            ok_count += 1
        else:
            code = _failure_code(result)
            failures[code] = failures.get(code, 0) + 1
    return ok_count, failures


def _verify_after_mutation(
    cfg,
    receiver_auth,
    *,
    timeout: float,
    settle: float,
    friend_path: tuple[int, ...] | None = None,
) -> RelationshipSnapshot:
    if settle > 0:
        time.sleep(settle)
    return _read_snapshot(cfg, receiver_auth, timeout=timeout, friend_path=friend_path)


def _remove_bulk(cfg, receiver_auth, mids: list[str], *, timeout: float) -> tuple[bool, str]:
    try:
        result = remove_friend(
            cfg=cfg,
            slot="R",
            auth=receiver_auth,
            target_mids=mids,
            timeout=timeout,
            live=True,
        )
    except Exception as exc:
        return False, str(getattr(exc, "code", None) or type(exc).__name__)[:80]
    return bool(result.get("ok")), _failure_code(result)


def _friend_ids_for_targets(snapshot: RelationshipSnapshot, targets: set[str]) -> set[str]:
    found: set[str] = set()
    for _path, ids in _friend_candidates(snapshot.groups):
        found.update(targets.intersection(ids))
    return found


def receiver_reconcile_batch_relationships(
    cfg,
    receiver_auth,
    target_mids: list[str] | tuple[str, ...],
    *,
    event_cb: Event | None = None,
    scope: str = "batch",
) -> BatchRelationshipReconcileResult:
    mids = tuple(dict.fromkeys(str(mid).strip() for mid in target_mids if str(mid).strip()))[:100]
    if not mids:
        return BatchRelationshipReconcileResult(0, 0, 0, 0, 0, (), ())

    timeout = float(max(3, min(20, _env_int("MWOIF_RECEIVER_RELATIONSHIP_TIMEOUT_SECONDS", 12, 3, 20))))
    settle = max(0.10, _env_int("MWOIF_RECEIVER_RELATIONSHIP_SETTLE_MS", 250, 100, 1500) / 1000.0)
    targets = set(mids)
    before = _read_snapshot(cfg, receiver_auth, timeout=timeout)
    pending_before_ids = targets.intersection(before.pending_ids)
    friend_before_ids = _friend_ids_for_targets(before, targets)

    if pending_before_ids:
        _reject_pending(cfg, receiver_auth, tuple(sorted(pending_before_ids)), timeout=timeout)
        current = _verify_after_mutation(cfg, receiver_auth, timeout=timeout, settle=settle)
    else:
        current = before

    friend_targets = _friend_ids_for_targets(current, targets)
    if friend_targets:
        _remove_bulk(cfg, receiver_auth, sorted(friend_targets), timeout=timeout)
        current = _verify_after_mutation(cfg, receiver_auth, timeout=timeout, settle=settle)
        still_friend = _friend_ids_for_targets(current, targets)
        if still_friend:
            time.sleep(max(0.50, settle * 2.0))
            current = _read_snapshot(cfg, receiver_auth, timeout=timeout)

    final_pending = targets.intersection(current.pending_ids)
    final_friends = _friend_ids_for_targets(current, targets)
    unresolved = final_pending.union(final_friends)
    resolved = targets.difference(unresolved)
    pending_rejected = len(pending_before_ids.difference(final_pending))
    friends_removed = len(friend_before_ids.difference(final_friends))

    if event_cb:
        event_cb(
            f"P7D RELATIONSHIP RECONCILE scope={str(scope or 'batch')[:24]} requested={len(targets)} "
            f"pendingBefore={len(pending_before_ids)} friendsBefore={len(friend_before_ids)} "
            f"pendingRejected={pending_rejected} friendsRemoved={friends_removed} "
            f"resolved={len(resolved)} unresolved={len(unresolved)} secretOutput=NONE"
        )

    return BatchRelationshipReconcileResult(
        requested=len(targets),
        pending_before=len(pending_before_ids),
        friends_before=len(friend_before_ids),
        pending_rejected=pending_rejected,
        friends_removed=friends_removed,
        resolved_mids=tuple(sorted(resolved)),
        unresolved_mids=tuple(sorted(unresolved)),
    )


def _confirm_friend_path(
    cfg,
    receiver_auth,
    snapshot: RelationshipSnapshot,
    *,
    timeout: float,
    settle: float,
    target_friends: int,
    event_cb: Event | None,
) -> tuple[RelationshipSnapshot, int]:
    candidates = [
        (path, ids)
        for path, ids in _friend_candidates(snapshot.groups)
        if len(ids) > target_friends
    ]
    if not candidates:
        return snapshot, 0

    for path, ids in candidates:
        target = _RNG.choice(ids)
        before_count = len(ids)
        rpc_ok, rpc_code = _remove_bulk(cfg, receiver_auth, [target], timeout=timeout)
        after = _verify_after_mutation(
            cfg,
            receiver_auth,
            timeout=timeout,
            settle=settle,
            friend_path=path,
        )
        after_ids = dict(after.groups).get(path, ())
        changed = len(after_ids) < before_count or target not in after_ids
        if event_cb:
            event_cb(
                f"P6.2 RECEIVER FRIEND PROBE path={'/'.join(map(str, path))} before={before_count} "
                f"rpcOk={str(rpc_ok).lower()} code={rpc_code} changed={str(changed).lower()} "
                f"after={len(after_ids)} secretOutput=NONE"
            )
        if changed:
            return _read_snapshot(cfg, receiver_auth, timeout=timeout, friend_path=path), max(0, before_count - len(after_ids))

    raise ReceiverRelationshipError(
        "RECEIVER_FRIEND_GROUP_UNRESOLVED",
        "A relationship group above the safe friend threshold could not be verified as Friends",
        retryable=False,
    )


def receiver_relationship_preflight(
    cfg,
    receiver_auth,
    *,
    event_cb: Event | None = None,
    target_friends: int = 200,
    capacity: int = 300,
) -> ReceiverPreflightResult:
    target_friends = max(0, min(capacity, int(target_friends)))
    pending_target = 0
    timeout = float(max(3, min(20, _env_int("MWOIF_RECEIVER_RELATIONSHIP_TIMEOUT_SECONDS", 12, 3, 20))))
    settle = max(0.10, _env_int("MWOIF_RECEIVER_RELATIONSHIP_SETTLE_MS", 250, 100, 1500) / 1000.0)
    pending_chunk = _env_int("MWOIF_RECEIVER_PENDING_REJECT_CHUNK", 20, 1, 50)
    pending_max_rounds = _env_int("MWOIF_RECEIVER_PENDING_CLEAR_MAX_ROUNDS", 30, 1, 60)
    trim_max_rounds = _env_int("MWOIF_RECEIVER_FRIEND_TRIM_MAX_ROUNDS", 3, 1, 5)

    snapshot = _read_snapshot(cfg, receiver_auth, timeout=timeout)
    pending_before = snapshot.pending_count
    friends_before = snapshot.friend_upper_bound
    rejected_total = 0
    trimmed_total = 0

    if event_cb:
        event_cb(
            f"P6.2 RECEIVER RELATIONSHIP MODE runtime-verified pendingPath=3/1/1 "
            f"pendingTarget={pending_target} friendTarget={target_friends}/{capacity} "
            f"friendPath=dynamic-if-needed secretOutput=NONE"
        )

    pending_round = 0
    pending_stall = 0
    while snapshot.pending_count > pending_target:
        pending_round += 1
        if pending_round > pending_max_rounds:
            raise ReceiverRelationshipError(
                "RECEIVER_PENDING_CLEAR_TIMEOUT",
                "Receiver pending request cleanup exceeded bounded rounds",
                retryable=True,
            )
        need_remove = snapshot.pending_count - pending_target
        before_ids = snapshot.pending_ids
        targets = before_ids[: min(pending_chunk, need_remove)]
        if not targets:
            raise ReceiverRelationshipError("RECEIVER_PENDING_IDS_INCOMPLETE", "Pending request ids are incomplete", retryable=True)
        ack, failures = _reject_pending(cfg, receiver_auth, targets, timeout=timeout)
        after = _verify_after_mutation(cfg, receiver_auth, timeout=timeout, settle=settle)
        removed = len(set(before_ids) - set(after.pending_ids))
        if removed == 0 and ack > 0:
            time.sleep(max(0.50, settle * 2.0))
            after = _read_snapshot(cfg, receiver_auth, timeout=timeout)
            removed = len(set(before_ids) - set(after.pending_ids))
        rejected_total += removed
        if event_cb:
            event_cb(
                f"P6.2 RECEIVER PENDING CLEAR round={pending_round} target={pending_target} "
                f"before={len(before_ids)} attempted={len(targets)} ack={ack} removed={removed} "
                f"after={after.pending_count} failCodes={_format_failures(failures)} secretOutput=NONE"
            )
        pending_stall = 0 if removed > 0 else pending_stall + 1
        snapshot = after
        if pending_stall >= 2:
            raise ReceiverRelationshipError(
                "RECEIVER_PENDING_CLEAR_STALLED",
                "Receiver pending request cleanup made no observable progress",
                retryable=True,
            )

    snapshot, probe_trimmed = _confirm_friend_path(
        cfg,
        receiver_auth,
        snapshot,
        timeout=timeout,
        settle=settle,
        target_friends=target_friends,
        event_cb=event_cb,
    )
    trimmed_total += probe_trimmed

    trim_round = 0
    trim_stall = 0
    while snapshot.friend_path is not None and snapshot.friend_count > target_friends:
        trim_round += 1
        if trim_round > trim_max_rounds:
            raise ReceiverRelationshipError(
                "RECEIVER_FRIEND_TRIM_TIMEOUT",
                "Receiver friend trim exceeded bounded rounds",
                retryable=False,
            )
        excess = snapshot.friend_count - target_friends
        targets = _RNG.sample(list(snapshot.friend_ids), excess)
        before_count = snapshot.friend_count
        bulk_ok, bulk_code = _remove_bulk(cfg, receiver_auth, targets, timeout=timeout)
        after = _verify_after_mutation(
            cfg,
            receiver_auth,
            timeout=timeout,
            settle=settle,
            friend_path=snapshot.friend_path,
        )
        removed = max(0, before_count - after.friend_count)
        if removed == 0 and bulk_ok:
            time.sleep(max(0.50, settle * 2.0))
            after = _read_snapshot(cfg, receiver_auth, timeout=timeout, friend_path=snapshot.friend_path)
            removed = max(0, before_count - after.friend_count)
        trimmed_total += removed
        if event_cb:
            event_cb(
                f"P6.2 RECEIVER FRIEND TRIM round={trim_round} before={before_count}/{capacity} "
                f"requested={excess} rpcOk={str(bulk_ok).lower()} code={bulk_code} removed={removed} "
                f"after={after.friend_count}/{capacity} selection=random secretOutput=NONE"
            )
        snapshot = after
        trim_stall = 0 if removed > 0 else trim_stall + 1
        if trim_stall >= 1:
            raise ReceiverRelationshipError(
                "RECEIVER_FRIEND_TRIM_STALLED",
                "Verified RemoveFriend flow made no observable progress",
                retryable=False,
            )

    snapshot = _read_snapshot(cfg, receiver_auth, timeout=timeout, friend_path=snapshot.friend_path)
    if snapshot.pending_count > pending_target:
        raise ReceiverRelationshipError("RECEIVER_PENDING_CLEAR_INCOMPLETE", "Pending requests remain after cleanup", retryable=True)
    if snapshot.friend_path is not None and snapshot.friend_count > target_friends:
        raise ReceiverRelationshipError("RECEIVER_FRIEND_TRIM_INCOMPLETE", "Receiver still has too many friends", retryable=False)

    friend_bound = snapshot.friend_count if snapshot.friend_path is not None else snapshot.friend_upper_bound
    available = max(0, capacity - friend_bound)
    if friend_bound > target_friends:
        raise ReceiverRelationshipError(
            "RECEIVER_FRIEND_BOUND_UNSAFE",
            "Receiver relationship state cannot prove at least 100 friend slots are available",
            retryable=False,
        )

    if event_cb:
        friend_path_text = "/".join(map(str, snapshot.friend_path)) if snapshot.friend_path else "NONE"
        event_cb(
            f"P6.2 RECEIVER PREFLIGHT mode=production friendsBoundBefore={friends_before}/{capacity} "
            f"pendingBefore={pending_before} pendingRejected={rejected_total} trimmedFriends={trimmed_total} "
            f"friendsBoundAfter={friend_bound}/{capacity} friendPath={friend_path_text} "
            f"pendingAfter={snapshot.pending_count} availableAtLeast={available} "
            f"pendingSource=runtime-verified friendSafety=bounded secretOutput=NONE"
        )

    return ReceiverPreflightResult(
        friends_before=friends_before,
        pending_before=pending_before,
        rejected_pending=rejected_total,
        trimmed_friends=trimmed_total,
        friends_after=friend_bound,
        pending_after=snapshot.pending_count,
        available_slots=available,
        calibrated=True,
    )

def receiver_relationship_prepare_capacity(
    cfg,
    receiver_auth,
    *,
    event_cb: Event | None = None,
    target_friends: int = 200,
    capacity: int = 300,
) -> ReceiverPreflightResult:
    target_friends = max(0, min(capacity, int(target_friends)))
    timeout = float(max(3, min(20, _env_int("MWOIF_RECEIVER_RELATIONSHIP_TIMEOUT_SECONDS", 12, 3, 20))))
    settle = max(0.10, _env_int("MWOIF_RECEIVER_RELATIONSHIP_SETTLE_MS", 250, 100, 1500) / 1000.0)
    snapshot = _read_snapshot(cfg, receiver_auth, timeout=timeout)
    friends_before = snapshot.friend_upper_bound
    pending_before = snapshot.pending_count
    trimmed_total = 0

    if friends_before > target_friends:
        snapshot, probe_trimmed = _confirm_friend_path(
            cfg,
            receiver_auth,
            snapshot,
            timeout=timeout,
            settle=settle,
            target_friends=target_friends,
            event_cb=event_cb,
        )
        trimmed_total += probe_trimmed

        if snapshot.friend_path is None and snapshot.friend_upper_bound > target_friends:
            raise ReceiverRelationshipError(
                "RECEIVER_FRIEND_GROUP_UNRESOLVED",
                "Receiver friend group could not be verified safely",
                retryable=False,
            )

        if snapshot.friend_path is not None and snapshot.friend_count > target_friends:
            excess = snapshot.friend_count - target_friends
            targets = _RNG.sample(list(snapshot.friend_ids), excess)
            before_count = snapshot.friend_count
            bulk_ok, bulk_code = _remove_bulk(cfg, receiver_auth, targets, timeout=timeout)
            after = _verify_after_mutation(
                cfg,
                receiver_auth,
                timeout=timeout,
                settle=settle,
                friend_path=snapshot.friend_path,
            )
            removed = max(0, before_count - after.friend_count)
            if removed == 0 and bulk_ok:
                time.sleep(max(0.50, settle * 2.0))
                after = _read_snapshot(cfg, receiver_auth, timeout=timeout, friend_path=snapshot.friend_path)
                removed = max(0, before_count - after.friend_count)
            trimmed_total += removed
            if event_cb:
                event_cb(
                    f"P7C RECEIVER CAPACITY TRIM before={before_count}/{capacity} requested={excess} "
                    f"rpcOk={str(bulk_ok).lower()} code={bulk_code} removed={removed} "
                    f"after={after.friend_count}/{capacity} selection=random explicitConsent=true secretOutput=NONE"
                )
            if removed < excess:
                raise ReceiverRelationshipError(
                    "RECEIVER_FRIEND_TRIM_INCOMPLETE",
                    "Receiver friend trim did not remove the exact required excess",
                    retryable=False,
                )
            snapshot = after

    snapshot = _read_snapshot(cfg, receiver_auth, timeout=timeout, friend_path=snapshot.friend_path)
    friend_bound = snapshot.friend_count if snapshot.friend_path is not None else snapshot.friend_upper_bound
    available = max(0, capacity - friend_bound)
    if friend_bound > target_friends:
        raise ReceiverRelationshipError(
            "RECEIVER_CAPACITY_NOT_READY",
            "Receiver still does not have enough free friend slots",
            retryable=False,
        )
    if event_cb:
        event_cb(
            f"P7C RECEIVER CAPACITY READY friendsBefore={friends_before}/{capacity} "
            f"removed={trimmed_total} friendsAfter={friend_bound}/{capacity} "
            f"pendingUntouched={snapshot.pending_count} available={available} explicitConsent=true secretOutput=NONE"
        )
    return ReceiverPreflightResult(
        friends_before=friends_before,
        pending_before=pending_before,
        rejected_pending=0,
        trimmed_friends=trimmed_total,
        friends_after=friend_bound,
        pending_after=snapshot.pending_count,
        available_slots=available,
        calibrated=True,
    )


def _clear_receiver_pending_before_job(
    cfg,
    receiver_auth,
    *,
    event_cb: Event | None = None,
) -> tuple[RelationshipSnapshot, int, int]:
    timeout = float(max(3, min(20, _env_int("MWOIF_RECEIVER_RELATIONSHIP_TIMEOUT_SECONDS", 12, 3, 20))))
    settle = max(0.10, _env_int("MWOIF_RECEIVER_RELATIONSHIP_SETTLE_MS", 250, 100, 1500) / 1000.0)
    chunk = _env_int("MWOIF_RECEIVER_PENDING_REJECT_CHUNK", 20, 1, 50)
    max_rounds = _env_int("MWOIF_RECEIVER_PENDING_CLEAR_MAX_ROUNDS", 30, 1, 60)
    snapshot = _read_snapshot(cfg, receiver_auth, timeout=timeout)
    pending_before = snapshot.pending_count
    rejected_total = 0
    stall = 0
    round_no = 0

    while snapshot.pending_count > 0:
        round_no += 1
        if round_no > max_rounds:
            raise ReceiverRelationshipError(
                "RECEIVER_PENDING_CLEAR_TIMEOUT",
                "Receiver pending request cleanup exceeded bounded rounds",
                retryable=True,
            )
        before_ids = snapshot.pending_ids
        targets = before_ids[: min(chunk, snapshot.pending_count)]
        if not targets:
            raise ReceiverRelationshipError(
                "RECEIVER_PENDING_IDS_INCOMPLETE",
                "Pending request ids are incomplete",
                retryable=True,
            )
        ack, failures = _reject_pending(cfg, receiver_auth, targets, timeout=timeout)
        after = _verify_after_mutation(cfg, receiver_auth, timeout=timeout, settle=settle)
        removed = len(set(before_ids) - set(after.pending_ids))
        if removed == 0 and ack > 0:
            time.sleep(max(0.50, settle * 2.0))
            after = _read_snapshot(cfg, receiver_auth, timeout=timeout)
            removed = len(set(before_ids) - set(after.pending_ids))
        rejected_total += removed
        if event_cb:
            event_cb(
                f"P8 RECEIVER PENDING CLEAR round={round_no} before={len(before_ids)} "
                f"attempted={len(targets)} ack={ack} removed={removed} after={after.pending_count} "
                f"failCodes={_format_failures(failures)} secretOutput=NONE"
            )
        stall = 0 if removed > 0 else stall + 1
        snapshot = after
        if stall >= 2:
            raise ReceiverRelationshipError(
                "RECEIVER_PENDING_CLEAR_STALLED",
                "Receiver pending request cleanup made no observable progress",
                retryable=True,
            )

    if snapshot.pending_count != 0:
        raise ReceiverRelationshipError(
            "RECEIVER_PENDING_CLEAR_INCOMPLETE",
            "Pending requests remain before job start",
            retryable=True,
        )
    return snapshot, pending_before, rejected_total


def receiver_relationship_job_guard(
    cfg,
    receiver_auth,
    *,
    event_cb: Event | None = None,
    target_friends: int = 200,
    capacity: int = 300,
) -> ReceiverPreflightResult:
    target_friends = max(0, min(capacity, int(target_friends)))
    snapshot, pending_before, rejected_pending = _clear_receiver_pending_before_job(
        cfg, receiver_auth, event_cb=event_cb,
    )
    friend_bound = max(0, min(capacity, int(snapshot.friend_upper_bound)))
    available = max(0, capacity - friend_bound)
    required_free = max(1, capacity - target_friends)
    if available < required_free:
        raise ReceiverRelationshipError(
            "RECEIVER_CAPACITY_NOT_READY",
            "Receiver capacity changed before job start",
            retryable=False,
        )
    if event_cb:
        event_cb(
            f"P8 RECEIVER JOB GUARD pendingBefore={pending_before} pendingRejected={rejected_pending} "
            f"pendingAfter=0 friendsBound={friend_bound}/{capacity} availableAtLeast={available} "
            f"requiredFree={required_free} friendMutation=false secretOutput=NONE"
        )
    return ReceiverPreflightResult(
        friends_before=friend_bound,
        pending_before=pending_before,
        rejected_pending=rejected_pending,
        trimmed_friends=0,
        friends_after=friend_bound,
        pending_after=0,
        available_slots=available,
        calibrated=False,
    )

