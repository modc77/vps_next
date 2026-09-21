from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin


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
from mwoif.net.http_pool import pooled_post_bytes
from mwoif.session.ds_v4 import compact_json_bytes, encode_v4
from mwoif.session.game_session import (
    INIT_MEMBER_ENDPOINT,
    _decode_init_member_response_data,
    build_init_member_payload,
)
from mwoif_worker.config import WorkerConfig
from mwoif_worker.devplay.context import load_login_web_context
from mwoif_worker.devplay.exact_template import ExactTemplateReplayer
from mwoif_worker.heart_one import _legacy_auth


SENSITIVE_PARTS = (
    "token",
    "session",
    "secret",
    "password",
    "passwd",
    "cookie",
    "authorization",
    "credential",
    "accesskey",
    "apikey",
    "masterkey",
)
INTERESTING_PARTS = (
    "invite",
    "invitation",
    "referr",
    "recommend",
    "friend",
    "event",
    "level",
    "lv",
    "exp",
    "reward",
    "campaign",
    "share",
    "link",
    "member",
    "nickname",
    "tutorial",
    "stage",
)


def normalized_key(value: str) -> str:
    return value.lower().replace("-", "").replace("_", "")


def is_sensitive_key(key: str) -> bool:
    normalized = normalized_key(key)
    return any(normalized_key(part) in normalized for part in SENSITIVE_PARTS)


def redact(value, key: str = ""):
    if is_sensitive_key(key):
        return value if value in (None, "", [], {}) else "<REDACTED>"
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, key) for v in value]
    return value


def walk(value, path: str = "$") -> list[dict]:
    rows: list[dict] = []
    if isinstance(value, dict):
        rows.append({"path": path, "type": "object", "size": len(value)})
        for key, child in value.items():
            rows.extend(walk(child, f"{path}.{key}"))
    elif isinstance(value, list):
        rows.append({"path": path, "type": "array", "size": len(value)})
        for index, child in enumerate(value):
            rows.extend(walk(child, f"{path}[{index}]"))
    else:
        leaf = path.rsplit(".", 1)[-1].split("[", 1)[0]
        if is_sensitive_key(leaf):
            shown = "<REDACTED>" if value not in (None, "") else value
        elif isinstance(value, str) and len(value) > 500:
            shown = value[:500] + "…"
        else:
            shown = value
        rows.append({"path": path, "type": type(value).__name__, "value": shown})
    return rows


def emit(message: str) -> None:
    print(message, flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--email", default=os.getenv("MWOIF_INSPECT_EMAIL", ""))
    parser.add_argument("--password", default=os.getenv("MWOIF_INSPECT_PASSWORD", ""))
    return parser.parse_args()


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

    worker_cfg = WorkerConfig.load(ROOT)
    context = load_login_web_context(worker_cfg.web_context_file, worker_cfg.login_url)
    if not context.complete:
        print("WEB_CONTEXT_INCOMPLETE")
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
        print(
            json.dumps(
                {
                    "ok": False,
                    "stage": replay.stage,
                    "code": replay.code,
                    "message": replay.message,
                    "retryable": replay.retryable,
                },
                ensure_ascii=False,
            )
        )
        return 4

    runtime_cfg = build_devplay_runtime_config(load_config(ROOT / ".env"))
    auth = _legacy_auth(
        context=context,
        bundle=replay.bundle,
        account_kind="direct_inspect",
        account_id=0,
    )
    replay = None

    payload, missing = build_init_member_payload(runtime_cfg, auth)
    if missing:
        print("INITMEMBER3_MISSING=" + ",".join(missing))
        return 5

    encoded = encode_v4(compact_json_bytes(payload))
    url = urljoin(str(runtime_cfg.server.get("game_base_url") or "").rstrip("/") + "/", INIT_MEMBER_ENDPOINT)

    emit("DIRECT INIT START endpoint=member/initMember3.ds webBackend=DISABLED secretOutput=NONE")
    started = time.monotonic()
    try:
        status_code, response_body, _ = pooled_post_bytes(
            url=url,
            body=encoded.form_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=float(runtime_cfg.server.get("timeout_seconds") or 20),
            verify=bool(runtime_cfg.server.get("verify_ssl", True)),
        )
    except Exception as exc:
        print(f"INITMEMBER3_NETWORK_ERROR type={type(exc).__name__}")
        return 6

    try:
        wrapper = json.loads(response_body.decode("utf-8-sig"))
    except Exception:
        print(f"INITMEMBER3_WRAPPER_INVALID http={status_code}")
        return 7

    response_code = wrapper.get("responseCode") if isinstance(wrapper, dict) else None
    response_message = wrapper.get("responseMessage") if isinstance(wrapper, dict) else None
    emit(
        f"DIRECT INIT HTTP={status_code} responseCode={response_code} "
        f"elapsedMs={round((time.monotonic() - started) * 1000)} secretOutput=NONE"
    )
    if not (200 <= status_code < 300) or response_code != 200:
        print(
            json.dumps(
                {
                    "ok": False,
                    "http_status": status_code,
                    "response_code": response_code,
                    "response_message": str(response_message or "")[:200],
                },
                ensure_ascii=False,
            )
        )
        return 8

    try:
        obj, decode_mode, decode_profile = _decode_init_member_response_data(wrapper.get("responseData") or "")
    except Exception as exc:
        print(f"INITMEMBER3_DECODE_ERROR type={type(exc).__name__}")
        return 9

    safe = redact(obj)
    paths = walk(obj)
    interesting = [
        row for row in paths
        if any(part in str(row.get("path", "")).lower() for part in INTERESTING_PARTS)
    ]

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = ROOT / "state" / "direct-login-inspect" / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)

    safe_file = out_dir / "initMember3.safe.json"
    paths_file = out_dir / "initMember3.paths.json"
    interesting_file = out_dir / "initMember3.interesting.json"
    summary_file = out_dir / "summary.json"

    safe_file.write_text(json.dumps(safe, ensure_ascii=False, indent=2), encoding="utf-8")
    paths_file.write_text(json.dumps(paths, ensure_ascii=False, indent=2), encoding="utf-8")
    interesting_file.write_text(json.dumps(interesting, ensure_ascii=False, indent=2), encoding="utf-8")

    root_keys = sorted(obj.keys()) if isinstance(obj, dict) else []
    level = None
    member_seq_present = False
    if isinstance(obj, dict):
        def deep_find(value, key):
            if isinstance(value, dict):
                if key in value:
                    return value[key]
                for child in value.values():
                    hit = deep_find(child, key)
                    if hit not in (None, ""):
                        return hit
            elif isinstance(value, list):
                for child in value:
                    hit = deep_find(child, key)
                    if hit not in (None, ""):
                        return hit
            return None
        level = deep_find(obj, "lv") or deep_find(obj, "currentLv")
        member_seq_present = deep_find(obj, "memberSeq") not in (None, "", 0)

    summary = {
        "ok": True,
        "web_backend_connected": False,
        "devplay_login": True,
        "initMember3": True,
        "memberSeq_present": member_seq_present,
        "lv": level,
        "decode_mode": decode_mode,
        "decode_profile": decode_profile,
        "root_type": type(obj).__name__,
        "root_key_count": len(root_keys),
        "root_keys": root_keys,
        "recursive_path_count": len(paths),
        "interesting_path_count": len(interesting),
        "output_dir": str(out_dir),
        "secretOutput": "REDACTED",
    }
    summary_file.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    emit(f"DIRECT INSPECT PASS lv={level} memberSeq={'present' if member_seq_present else 'missing'}")
    emit(f"ROOT KEYS count={len(root_keys)}")
    for key in root_keys:
        emit(f"  {key}")
    emit(f"INTERESTING PATHS count={len(interesting)}")
    for row in interesting[:120]:
        value = row.get("value", "")
        if value == "":
            emit(f"  {row.get('path')} type={row.get('type')} size={row.get('size', '')}")
        else:
            emit(f"  {row.get('path')} type={row.get('type')} value={value}")
    if len(interesting) > 120:
        emit(f"  ... {len(interesting) - 120} more in initMember3.interesting.json")
    emit(f"OUTPUT={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
