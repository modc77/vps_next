from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_LOCK = threading.RLock()
_ALLOWED_STAGES = {"LEASED", "ADD_ATTEMPT", "SEND_INTENT", "DELIVERED"}


def _journal_dir() -> Path:
    raw = str(os.getenv("MWOIF_HEART_RELATIONSHIP_JOURNAL_DIR") or "state/heart_relationship_journal").strip()
    path = Path(raw)
    if not path.is_absolute():
        path = _ROOT / path
    return path


def _path(sj_id: int) -> Path:
    return _journal_dir() / f"job-{max(1, int(sj_id))}.jsonl"


def record_relationship_stage(*, sj_id: int, batch_no: int, sga_id: int, stage: str) -> None:
    stage = str(stage or "").strip().upper()
    if stage not in _ALLOWED_STAGES:
        raise ValueError("RELATIONSHIP_JOURNAL_STAGE_INVALID")
    row = {
        "sj_id": max(1, int(sj_id)),
        "batch_no": max(1, int(batch_no)),
        "sga_id": max(1, int(sga_id)),
        "stage": stage,
        "ts": round(time.time(), 3),
    }
    path = _path(sj_id)
    with _LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
            handle.flush()




def record_batch_leased(*, sj_id: int, batch_no: int, sga_ids: list[int] | tuple[int, ...] | set[int]) -> None:
    ids = sorted({max(1, int(value)) for value in sga_ids if int(value) > 0})
    if not ids:
        return
    row = {
        "sj_id": max(1, int(sj_id)),
        "batch_no": max(1, int(batch_no)),
        "sga_ids": ids,
        "stage": "LEASED",
        "ts": round(time.time(), 3),
    }
    path = _path(sj_id)
    with _LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
            handle.flush()


def load_relationship_stages(sj_id: int) -> dict[int, dict[str, Any]]:
    path = _path(sj_id)
    if not path.exists():
        return {}
    state: dict[int, dict[str, Any]] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return {}
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except Exception:
            continue
        if not isinstance(row, dict):
            continue
        try:
            row_sj = int(row.get("sj_id") or 0)
            batch_no = int(row.get("batch_no") or 0)
        except Exception:
            continue
        stage = str(row.get("stage") or "").strip().upper()
        if row_sj != int(sj_id) or batch_no < 1 or stage not in _ALLOWED_STAGES:
            continue
        batch_ids = row.get("sga_ids")
        if stage == "LEASED" and isinstance(batch_ids, list):
            for value in batch_ids:
                try:
                    sga_id = int(value)
                except Exception:
                    continue
                if sga_id > 0:
                    state[sga_id] = {"batch_no": batch_no, "stage": stage}
            continue
        try:
            sga_id = int(row.get("sga_id") or 0)
        except Exception:
            continue
        if sga_id < 1:
            continue
        state[sga_id] = {"batch_no": batch_no, "stage": stage}
    return state


def clear_relationship_journal(sj_id: int) -> None:
    path = _path(sj_id)
    with _LOCK:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
