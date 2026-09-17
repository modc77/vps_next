from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar, Token
from pathlib import Path
from typing import Iterator

_RUNTIME_ID: ContextVar[str] = ContextVar("mwoif_runtime_id", default="")
_SAFE_RUNTIME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def current_runtime_id() -> str:
    return str(_RUNTIME_ID.get() or "")


def _validated_runtime_id(runtime_id: str) -> str:
    value = str(runtime_id or "").strip()
    if not _SAFE_RUNTIME.fullmatch(value):
        raise ValueError("MWOIF_RUNTIME_ID_INVALID")
    return value


@contextmanager
def runtime_scope(runtime_id: str) -> Iterator[None]:
    value = _validated_runtime_id(runtime_id)
    token: Token[str] = _RUNTIME_ID.set(value)
    try:
        yield
    finally:
        _RUNTIME_ID.reset(token)


def scoped_state_path(base_path: Path) -> Path:
    """Return a runtime-local state path when P8 has bound a JobRuntime.

    Manual milestone commands keep the legacy path because they do not bind a
    runtime. Worker Service runners bind stable runtime-XX ids, so their claim
    state survives restart without colliding with another active JobRuntime.
    """
    base = base_path.resolve()
    runtime_id = current_runtime_id()
    if not runtime_id:
        return base
    runtime_id = _validated_runtime_id(runtime_id)
    return (base.parent / "runtimes" / runtime_id / base.name).resolve()
