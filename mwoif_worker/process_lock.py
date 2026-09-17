from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO


class WorkerProcessLockError(RuntimeError):
    pass


class WorkerProcessLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._fh: BinaryIO | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+b", buffering=0)
        try:
            fh.seek(0)
            if fh.read(1) == b"":
                fh.write(b"0")
                fh.flush()
            fh.seek(0)
            if os.name == "nt":
                import msvcrt

                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise WorkerProcessLockError("WORKER_PROCESS_ALREADY_RUNNING") from exc
            else:
                import fcntl

                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as exc:
                    raise WorkerProcessLockError("WORKER_PROCESS_ALREADY_RUNNING") from exc

            fh.seek(0)
            payload = f"{os.getpid()}\n".encode("ascii", errors="ignore")
            fh.truncate(0)
            fh.write(payload)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
            self._fh = fh
        except Exception:
            fh.close()
            raise

    def release(self) -> None:
        fh = self._fh
        self._fh = None
        if fh is None:
            return
        try:
            fh.seek(0)
            if os.name == "nt":
                import msvcrt

                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError:
                    pass
            else:
                import fcntl

                try:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
        finally:
            fh.close()

    def __enter__(self) -> "WorkerProcessLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.release()


def worker_process_lock_path(root: Path) -> Path:
    raw = str(os.getenv("MWOIF_WORKER_PROCESS_LOCK_FILE") or "state/worker-service.lock").strip()
    path = Path(raw)
    return path if path.is_absolute() else root / path
