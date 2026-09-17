from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mwoif_worker import __app_name__, __version__


def _emit(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def cmd_version(_: argparse.Namespace) -> int:
    print(json.dumps({"app": __app_name__, "version": __version__}, ensure_ascii=False))
    return 0


def cmd_preflight(_: argparse.Namespace) -> int:
    from mwoif_worker.preflight import run_preflight
    result = run_preflight()
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0 if result.get("ok") else 2


def cmd_heartbeat(_: argparse.Namespace) -> int:
    from mwoif_worker.heartbeat import send_heartbeat
    result = send_heartbeat(__version__)
    print(json.dumps(result.safe_dict(), ensure_ascii=False, separators=(",", ":")))
    return 0 if result.ok else 2


def cmd_worker(_: argparse.Namespace) -> int:
    from mwoif_worker.ops_logger import SafeRotatingEventLogger
    from mwoif_worker.worker_service import worker_service_run
    logger = SafeRotatingEventLogger(Path(__file__).resolve().parent, console_sink=_emit)
    try:
        return worker_service_run(__version__, event_cb=logger.emit)
    finally:
        logger.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mwoif-vps-next")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("version")
    p.set_defaults(func=cmd_version)
    p = sub.add_parser("preflight")
    p.set_defaults(func=cmd_preflight)
    p = sub.add_parser("heartbeat")
    p.set_defaults(func=cmd_heartbeat)
    p = sub.add_parser("worker-service")
    p.set_defaults(func=cmd_worker)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
