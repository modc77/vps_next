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
from mwoif.friend.proto import encode_string, encode_varint
from mwoif.friend.service import LIST_FRIENDS_METHOD, REMOVE_FRIEND_METHOD, _grpc_call
from mwoif_worker.heart_one import _login_and_session

CONFIG_FILE = _ROOT / "FRIEND_REMOVE_LAB.env"
DEFAULT_EMAIL = "demo102@gmail.com"
MAX_CANDIDATE_GROUPS = 8
REMOVE_VARIANTS = (
    "field2_string",
    "field1_string",
    "field1_nested_field2",
    "field2_nested_field2",
)


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


def _load_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            values[key] = value
    return values


def _setting(values: dict[str, str], key: str, default: str = "") -> str:
    return str(os.getenv(key) or values.get(key) or default).strip()


def _enabled(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _embedded(field_number: int, payload: bytes) -> bytes:
    return encode_varint((field_number << 3) | 2) + encode_varint(len(payload)) + payload


def _remove_body(variant: str, mids: list[str]) -> bytes:
    if variant == "field2_string":
        return b"".join(encode_string(2, mid) for mid in mids)
    if variant == "field1_string":
        return b"".join(encode_string(1, mid) for mid in mids)
    if variant == "field1_nested_field2":
        return b"".join(_embedded(1, encode_string(2, mid)) for mid in mids)
    if variant == "field2_nested_field2":
        return b"".join(_embedded(2, encode_string(2, mid)) for mid in mids)
    raise ValueError(f"unknown variant: {variant}")


def _list_groups(*, cfg, auth, timeout: float = 12.0) -> tuple[dict[str, Any], list[Group]]:
    def enrich(raw: bytes) -> dict[str, Any]:
        parsed = parse_friend_list_response(raw, capacity=300)
        groups = []
        relationship_groups = getattr(parsed, "relationship_groups", None)
        if callable(relationship_groups):
            source_groups = relationship_groups()
        else:
            selected = tuple(getattr(parsed, "selected_path", None) or ())
            ids = tuple(getattr(parsed, "friend_player_ids", ()) or ())
            source_groups = ((selected, ids),) if selected and ids else ()
        for path, ids in source_groups:
            groups.append({"path": list(path), "ids": list(ids), "count": len(ids)})
        return {
            "probe_groups": groups,
            "probe_response_bytes": len(raw),
            "probe_parser_confidence": getattr(parsed, "parser_confidence", "unknown"),
            "probe_selected_path": list(getattr(parsed, "selected_path", None) or ()),
        }

    result = _grpc_call(
        cfg=cfg,
        slot="R",
        auth=auth,
        action="friend-remove-lab-list",
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
    out: list[Group] = []
    for item in result.get("probe_groups") or []:
        if not isinstance(item, dict):
            continue
        try:
            path = tuple(int(x) for x in (item.get("path") or []))
        except Exception:
            continue
        ids = tuple(dict.fromkeys(str(x).strip() for x in (item.get("ids") or []) if str(x).strip()))
        if path and ids:
            out.append(Group(path=path, ids=ids))
    out.sort(key=lambda g: (g.count, len(g.path)), reverse=True)
    return result, out[:MAX_CANDIDATE_GROUPS]


def _group_at(groups: list[Group], path: tuple[int, ...]) -> Group | None:
    for group in groups:
        if group.path == path:
            return group
    return None


def _print_groups(groups: list[Group], *, title: str) -> None:
    print(f"\n=== {title} ===")
    if not groups:
        print("NO PLAYER-ID GROUPS FOUND")
        return
    for index, group in enumerate(groups, 1):
        samples = ", ".join(group.ids[:5])
        print(f"[{index}] path={group.path_text} count={group.count} sample={samples}")


def _remove_call(*, cfg, auth, variant: str, mids: list[str], timeout: float = 12.0) -> dict[str, Any]:
    body = _remove_body(variant, mids)
    return _grpc_call(
        cfg=cfg,
        slot="R",
        auth=auth,
        action=f"friend-remove-lab-{variant}",
        method_path=REMOVE_FRIEND_METHOD,
        request_body=body,
        timeout=timeout,
        live=True,
        schema={"variant": variant, "count": len(mids)},
    )


def _verify_path_change(*, before: Group, after_groups: list[Group], target_mid: str) -> tuple[bool, int, bool]:
    after = _group_at(after_groups, before.path)
    if after is None:
        return True, 0, True
    target_gone = target_mid not in after.ids
    count_reduced = after.count < before.count
    return bool(target_gone or count_reduced), after.count, target_gone


def _probe_remove_one(*, cfg, auth, groups: list[Group]) -> tuple[Group | None, str | None, list[Group]]:
    if not groups:
        print("No candidate player-id group to probe.")
        return None, None, groups

    for group in groups:
        target = random.choice(group.ids)
        print(f"\n[PROBE] candidate path={group.path_text} count={group.count} target={target}")
        for variant in REMOVE_VARIANTS:
            print(f"[TRY] variant={variant}")
            result = _remove_call(cfg=cfg, auth=auth, variant=variant, mids=[target])
            code = str(result.get("grpc_code") or result.get("response_code") or result.get("error") or "OK")
            print(f"[RPC] ok={bool(result.get('ok'))} code={code} elapsed_ms={result.get('elapsed_ms')}")
            time.sleep(0.35)
            list_result, after_groups = _list_groups(cfg=cfg, auth=auth)
            if not bool(list_result.get("ok")):
                print("[VERIFY] ListFriends failed after remove attempt")
                continue
            changed, after_count, target_gone = _verify_path_change(before=group, after_groups=after_groups, target_mid=target)
            print(
                f"[VERIFY] path={group.path_text} before={group.count} after={after_count} "
                f"target_gone={str(target_gone).lower()} changed={str(changed).lower()}"
            )
            if changed:
                print(f"\nVERIFIED_REMOVE variant={variant} path={group.path_text} before={group.count} after={after_count} target={target}")
                verified = _group_at(after_groups, group.path)
                if verified is None:
                    verified = Group(path=group.path, ids=())
                return verified, variant, after_groups
        print(f"[MISS] path={group.path_text} did not change with any tested request shape")
    return None, None, groups


def _trim_to(*, cfg, auth, path: tuple[int, ...], variant: str, target_count: int) -> bool:
    round_no = 0
    while True:
        list_result, groups = _list_groups(cfg=cfg, auth=auth)
        if not bool(list_result.get("ok")):
            print("TRIM_FAIL ListFriends failed")
            return False
        group = _group_at(groups, path)
        if group is None:
            print("TRIM_FAIL verified path disappeared")
            return False
        if group.count <= target_count:
            print(f"TRIM_DONE path={group.path_text} count={group.count}")
            return True
        round_no += 1
        need = group.count - target_count
        take = min(25, need)
        mids = random.sample(list(group.ids), take)
        print(f"[TRIM] round={round_no} path={group.path_text} before={group.count} remove={take} variant={variant}")
        result = _remove_call(cfg=cfg, auth=auth, variant=variant, mids=mids)
        code = str(result.get("grpc_code") or result.get("response_code") or result.get("error") or "OK")
        print(f"[TRIM RPC] ok={bool(result.get('ok'))} code={code}")
        time.sleep(0.45)
        verify_result, verify_groups = _list_groups(cfg=cfg, auth=auth)
        if not bool(verify_result.get("ok")):
            print("TRIM_FAIL verify ListFriends failed")
            return False
        after = _group_at(verify_groups, path)
        after_count = after.count if after is not None else 0
        removed = group.count - after_count
        print(f"[TRIM VERIFY] before={group.count} after={after_count} removed={removed}")
        if removed <= 0:
            print("TRIM_FAIL no progress")
            return False


def _self_test() -> int:
    assert _ROOT.is_dir()
    assert callable(parse_friend_list_response)
    assert callable(_login_and_session)
    for variant in REMOVE_VARIANTS:
        body = _remove_body(variant, ["KMSLM6355"])
        assert isinstance(body, bytes) and body
    print(f"SELF_TEST_OK root={_ROOT} secretOutput=NONE")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="friend-remove-lab")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()

    values = _load_env_file(CONFIG_FILE)
    email = _setting(values, "FRIEND_REMOVE_LAB_EMAIL", DEFAULT_EMAIL)
    password = _setting(values, "FRIEND_REMOVE_LAB_PASSWORD")
    mode = _setting(values, "FRIEND_REMOVE_LAB_MODE", "inspect").lower()
    allow_delete = _enabled(_setting(values, "FRIEND_REMOVE_LAB_ALLOW_DELETE", "0"))
    allow_trim = _enabled(_setting(values, "FRIEND_REMOVE_LAB_ALLOW_TRIM_TO_200", "0"))

    if not password or password in {"...", "PUT_PASSWORD_HERE", "CHANGE_ME"}:
        print(f"PASSWORD_MISSING edit={CONFIG_FILE}")
        print("Set FRIEND_REMOVE_LAB_PASSWORD=your_devplay_password")
        return 10
    if mode not in {"inspect", "probe", "trim200"}:
        print(f"CONFIG_INVALID FRIEND_REMOVE_LAB_MODE={mode}")
        return 11
    if mode in {"probe", "trim200"} and not allow_delete:
        print("DELETE_NOT_ALLOWED set FRIEND_REMOVE_LAB_ALLOW_DELETE=1")
        return 12
    if mode == "trim200" and not allow_trim:
        print("TRIM_NOT_ALLOWED set FRIEND_REMOVE_LAB_ALLOW_TRIM_TO_200=1")
        return 13

    print(f"[CONFIG] email={email} mode={mode} secretOutput=NONE")
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
        code = str(getattr(exc, "code", None) or type(exc).__name__)
        print(f"LOGIN_FAIL code={code}")
        return 2
    password = ""
    print(f"LOGIN_OK receiver_mid={auth.mid} secretOutput=NONE")

    list_result, groups = _list_groups(cfg=cfg, auth=auth)
    if not bool(list_result.get("ok")):
        code = str(list_result.get("grpc_code") or list_result.get("error") or "LIST_FRIENDS_FAILED")
        print(f"LIST_FRIENDS_FAIL code={code}")
        return 2
    _print_groups(groups, title="LIST FRIENDS RAW PLAYER-ID GROUPS")

    if mode == "inspect":
        print("\nINSPECT_DONE no mutation performed")
        return 0

    verified_group, variant, after_groups = _probe_remove_one(cfg=cfg, auth=auth, groups=groups)
    if verified_group is None or variant is None:
        print("\nREMOVE_PROBE_FAILED no tested candidate/path/shape produced a verified state change")
        print("NEXT=GHIDRA_OR_CAPTURE_REQUIRED")
        return 3

    _print_groups(after_groups, title="GROUPS AFTER VERIFIED REMOVE")
    if mode == "trim200":
        print(f"\nVERIFIED path={verified_group.path_text} variant={variant}")
        ok = _trim_to(cfg=cfg, auth=auth, path=verified_group.path, variant=variant, target_count=200)
        return 0 if ok else 4

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
