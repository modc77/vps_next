from __future__ import annotations

import argparse
import os
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mwoif.friend.capacity import parse_friend_list_response
from mwoif.friend.service import LIST_FRIENDS_METHOD, _grpc_call, handle_friend_request, remove_friend
from mwoif_worker.heart_one import _login_and_session

CONFIG_FILE = _ROOT / "FRIEND_RELATIONSHIP_LAB.env"
DEFAULT_EMAIL = "demo102@gmail.com"
MAX_GROUPS = 8


@dataclass(slots=True)
class Group:
    path: tuple[int, ...]
    ids: tuple[str, ...]

    @property
    def count(self) -> int:
        return len(self.ids)

    @property
    def path_text(self) -> str:
        return "/".join(str(x) for x in self.path) or "root"


def _load_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip():
            out[k.strip()] = v.strip()
    return out


def _setting(values: dict[str, str], key: str, default: str = "") -> str:
    return str(os.getenv(key) or values.get(key) or default).strip()


def _enabled(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _list_groups(*, cfg, auth, timeout: float = 12.0) -> tuple[dict[str, Any], list[Group]]:
    def enrich(raw: bytes) -> dict[str, Any]:
        parsed = parse_friend_list_response(raw, capacity=300)
        relationship_groups = getattr(parsed, "relationship_groups", None)
        if callable(relationship_groups):
            source_groups = relationship_groups()
        else:
            selected = tuple(getattr(parsed, "selected_path", None) or ())
            ids = tuple(getattr(parsed, "friend_player_ids", ()) or ())
            source_groups = ((selected, ids),) if selected and ids else ()
        return {
            "groups": [
                {"path": list(path), "ids": list(ids), "count": len(ids)}
                for path, ids in source_groups
                if path and ids
            ],
            "response_bytes": len(raw),
        }

    result = _grpc_call(
        cfg=cfg,
        slot="R",
        auth=auth,
        action="friend-relationship-lab-list",
        method_path=LIST_FRIENDS_METHOD,
        request_body=b"",
        timeout=timeout,
        live=True,
        read_only_action=True,
        schema={"request": "empty"},
        response_enricher=enrich,
    )
    if not bool(result.get("ok")):
        return result, []
    groups: list[Group] = []
    for item in result.get("groups") or []:
        if not isinstance(item, dict):
            continue
        try:
            path = tuple(int(x) for x in (item.get("path") or []))
        except Exception:
            continue
        ids = tuple(dict.fromkeys(str(x).strip() for x in (item.get("ids") or []) if str(x).strip()))
        if path and ids:
            groups.append(Group(path=path, ids=ids))
    groups.sort(key=lambda g: (g.count, len(g.path)), reverse=True)
    return result, groups[:MAX_GROUPS]


def _group_at(groups: list[Group], path: tuple[int, ...]) -> Group | None:
    return next((g for g in groups if g.path == path), None)


def _print_groups(groups: list[Group], title: str) -> None:
    print(f"\n=== {title} ===")
    if not groups:
        print("NO PLAYER-ID GROUPS FOUND")
        return
    for i, group in enumerate(groups, 1):
        print(f"[{i}] path={group.path_text} count={group.count} sample={', '.join(group.ids[:5])}")


def _verify(before: Group, after_groups: list[Group], target: str) -> tuple[bool, int, bool]:
    after = _group_at(after_groups, before.path)
    if after is None:
        return True, 0, True
    gone = target not in after.ids
    reduced = after.count < before.count
    return bool(gone or reduced), after.count, gone


def _probe_reject(*, cfg, auth, group: Group, timeout: float) -> tuple[bool, list[Group]]:
    target = random.choice(group.ids)
    print(f"\n[REJECT PROBE] path={group.path_text} count={group.count} target={target}")
    result = handle_friend_request(
        cfg=cfg,
        slot="R",
        auth=auth,
        target_mid=target,
        accept=False,
        timeout=timeout,
        live=True,
    )
    code = str(result.get("grpc_code") or result.get("response_code") or result.get("error") or "OK")
    print(f"[RPC] action=reject ok={bool(result.get('ok'))} code={code} elapsed_ms={result.get('elapsed_ms')}")
    time.sleep(0.4)
    verify_result, after_groups = _list_groups(cfg=cfg, auth=auth, timeout=timeout)
    if not bool(verify_result.get("ok")):
        print("[VERIFY] ListFriends failed")
        return False, after_groups
    changed, after_count, gone = _verify(group, after_groups, target)
    print(f"[VERIFY] before={group.count} after={after_count} target_gone={str(gone).lower()} changed={str(changed).lower()}")
    return changed, after_groups


def _probe_remove(*, cfg, auth, group: Group, timeout: float) -> tuple[bool, list[Group]]:
    target = random.choice(group.ids)
    print(f"\n[REMOVE PROBE] path={group.path_text} count={group.count} target={target} wire=field2_repeated_string")
    result = remove_friend(
        cfg=cfg,
        slot="R",
        auth=auth,
        target_mids=[target],
        timeout=timeout,
        live=True,
    )
    code = str(result.get("grpc_code") or result.get("response_code") or result.get("error") or "OK")
    print(f"[RPC] action=remove ok={bool(result.get('ok'))} code={code} elapsed_ms={result.get('elapsed_ms')}")
    time.sleep(0.4)
    verify_result, after_groups = _list_groups(cfg=cfg, auth=auth, timeout=timeout)
    if not bool(verify_result.get("ok")):
        print("[VERIFY] ListFriends failed")
        return False, after_groups
    changed, after_count, gone = _verify(group, after_groups, target)
    print(f"[VERIFY] before={group.count} after={after_count} target_gone={str(gone).lower()} changed={str(changed).lower()}")
    return changed, after_groups


def _clear_pending(*, cfg, auth, path: tuple[int, ...], timeout: float) -> bool:
    round_no = 0
    while True:
        result, groups = _list_groups(cfg=cfg, auth=auth, timeout=timeout)
        if not bool(result.get("ok")):
            print("CLEAR_PENDING_FAIL ListFriends")
            return False
        group = _group_at(groups, path)
        if group is None or group.count == 0:
            print(f"CLEAR_PENDING_DONE path={'/'.join(map(str, path))} count=0")
            return True
        round_no += 1
        targets = list(group.ids[:20])
        ack = 0
        for target in targets:
            reply = handle_friend_request(
                cfg=cfg,
                slot="R",
                auth=auth,
                target_mid=target,
                accept=False,
                timeout=timeout,
                live=True,
            )
            if bool(reply.get("ok")):
                ack += 1
            time.sleep(0.05)
        time.sleep(0.35)
        _, after_groups = _list_groups(cfg=cfg, auth=auth, timeout=timeout)
        after = _group_at(after_groups, path)
        after_count = after.count if after else 0
        removed = group.count - after_count
        print(f"[CLEAR PENDING] round={round_no} before={group.count} attempted={len(targets)} ack={ack} removed={removed} after={after_count}")
        if removed <= 0:
            print("CLEAR_PENDING_FAIL no progress")
            return False


def _self_test() -> int:
    assert _ROOT.is_dir()
    assert callable(_login_and_session)
    assert callable(handle_friend_request)
    assert callable(remove_friend)
    print(f"SELF_TEST_OK root={_ROOT} secretOutput=NONE")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="friend-relationship-lab-v3")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()

    values = _load_env(CONFIG_FILE)
    email = _setting(values, "FRIEND_RELATIONSHIP_LAB_EMAIL", DEFAULT_EMAIL)
    password = _setting(values, "FRIEND_RELATIONSHIP_LAB_PASSWORD")
    allow_mutation = _enabled(_setting(values, "FRIEND_RELATIONSHIP_LAB_ALLOW_MUTATION", "0"))
    clear_pending = _enabled(_setting(values, "FRIEND_RELATIONSHIP_LAB_CLEAR_PENDING", "0"))
    timeout = float(_setting(values, "FRIEND_RELATIONSHIP_LAB_TIMEOUT_SECONDS", "12") or 12)

    if not password or password in {"...", "PUT_PASSWORD_HERE", "CHANGE_ME"}:
        print(f"PASSWORD_MISSING edit={CONFIG_FILE}")
        return 10
    if not allow_mutation:
        print("MUTATION_NOT_ALLOWED set FRIEND_RELATIONSHIP_LAB_ALLOW_MUTATION=1")
        return 11

    print(f"[CONFIG] email={email} mutation=1 clearPending={1 if clear_pending else 0} secretOutput=NONE")
    print("[LOGIN] starting")
    try:
        cfg, auth, _session = _login_and_session(
            email=email,
            password=password,
            account_kind="receiver-probe",
            account_id=0,
            slot="R",
            event_cb=None,
        )
    except Exception as exc:
        password = ""
        print(f"LOGIN_FAIL code={str(getattr(exc, 'code', None) or type(exc).__name__)}")
        return 2
    password = ""
    print(f"LOGIN_OK receiver_mid={auth.mid} secretOutput=NONE")

    list_result, groups = _list_groups(cfg=cfg, auth=auth, timeout=timeout)
    if not bool(list_result.get("ok")):
        print(f"LIST_FRIENDS_FAIL code={str(list_result.get('grpc_code') or list_result.get('error') or 'UNKNOWN')}")
        return 2
    _print_groups(groups, "LIST FRIENDS PLAYER-ID GROUPS")

    pending_path: tuple[int, ...] | None = None
    friend_path: tuple[int, ...] | None = None
    current_groups = groups

    for group in list(groups):
        current = _group_at(current_groups, group.path)
        if current is None or current.count == 0:
            continue
        changed, after_groups = _probe_reject(cfg=cfg, auth=auth, group=current, timeout=timeout)
        current_groups = after_groups
        if changed:
            pending_path = group.path
            print(f"CLASSIFIED_PENDING path={group.path_text}")
            break

    if pending_path and clear_pending:
        if not _clear_pending(cfg=cfg, auth=auth, path=pending_path, timeout=timeout):
            return 4
        _, current_groups = _list_groups(cfg=cfg, auth=auth, timeout=timeout)
        _print_groups(current_groups, "GROUPS AFTER PENDING CLEAR")

    for group in list(current_groups):
        if pending_path is not None and group.path == pending_path:
            continue
        if group.count == 0:
            continue
        changed, after_groups = _probe_remove(cfg=cfg, auth=auth, group=group, timeout=timeout)
        current_groups = after_groups
        if changed:
            friend_path = group.path
            print(f"CLASSIFIED_FRIEND path={group.path_text}")
            break

    pending_text = "/".join(map(str, pending_path)) if pending_path else "NONE"
    friend_text = "/".join(map(str, friend_path)) if friend_path else "NONE"
    print(f"\nRELATIONSHIP_RESULT pendingPath={pending_text} friendPath={friend_text}")
    if pending_path and friend_path:
        print("NEXT=PRODUCTION_PATCH_READY")
        return 0
    if pending_path and not friend_path:
        print("NOTE=pending_confirmed_friend_not_present_or_not_identified")
        print("NEXT=IF_FRIENDS_EXPECTED_THEN_GHIDRA_OR_NATIVE_CAPTURE")
        return 3
    print("NEXT=GHIDRA_OR_NATIVE_CAPTURE")
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
