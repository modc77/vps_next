from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlencode, urljoin, urlsplit, urlunsplit

import requests


DEFAULT_SCHEME = "devsisters-crg"
DEFAULT_COMPONENT = "com.devsisters.crg/com.devsisters.CookieRunForKakao.OvenbreakX"
DEFAULT_DEVICE = os.getenv("MWOIF_ADB_DEVICE", "emulator-5564")
ANDROID_UA = (
    "Mozilla/5.0 (Linux; Android 12; SM-A156E) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/152.0.0.0 Mobile Safari/537.36"
)
REQUIRED_INVITE_PARAMS = (
    "af_deeplink",
    "af_dp",
    "af_referrer_customer_id",
    "af_referrer_uid",
    "af_siteid",
    "deep_link_sub1",
    "deep_link_value",
    "media_source",
    "onelink_id",
    "shortlink",
)


def find_root() -> Path:
    here = Path(__file__).resolve()
    for candidate in (here.parents[1], here.parents[2], Path.cwd()):
        if (candidate / "mwoif").is_dir() and (candidate / "mwoif_worker").is_dir():
            return candidate.resolve()
    if here.parents[1].exists():
        return here.parents[1].resolve()
    return Path.cwd().resolve()


ROOT = find_root()


def emit(message: str) -> None:
    print(message, flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="")
    parser.add_argument("--mode", choices=("http", "adb-capture"), default="http")
    parser.add_argument("--from-log", default="")
    parser.add_argument("--device", default=DEFAULT_DEVICE)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--max-hops", type=int, default=10)
    parser.add_argument("--allow-app-launch", action="store_true")
    parser.add_argument("--force-deeplink-probe", action="store_true")
    return parser.parse_args()


def normalize_onelink_url(value: str) -> str:
    value = value.strip()
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("ONELINK_SCHEME_INVALID")
    host = (parsed.hostname or "").lower()
    if not host.endswith(".onelink.me"):
        raise ValueError("ONELINK_HOST_INVALID")
    return urlunsplit(("https", parsed.netloc, parsed.path, parsed.query, ""))


def decode_text_variants(value: str) -> list[str]:
    variants: list[str] = []
    pending = [value]
    seen: set[str] = set()
    for _ in range(4):
        next_pending: list[str] = []
        for item in pending:
            if item in seen:
                continue
            seen.add(item)
            variants.append(item)
            transformed = html.unescape(item)
            transformed = transformed.replace("\\/", "/")
            transformed = transformed.replace("\\u0026", "&").replace("\\u003d", "=")
            transformed = transformed.replace("\\u003a", ":").replace("\\u002f", "/")
            transformed = transformed.replace("\\x26", "&").replace("\\x3d", "=")
            if transformed != item:
                next_pending.append(transformed)
            try:
                decoded = unquote(item)
            except Exception:
                decoded = item
            if decoded != item:
                next_pending.append(decoded)
        pending = next_pending
        if not pending:
            break
    return variants


def intent_to_uri(value: str) -> str | None:
    if not value.startswith("intent://") or "#Intent;" not in value:
        return None
    prefix, tail = value.split("#Intent;", 1)
    fields = tail.split(";")
    scheme = ""
    for field in fields:
        if field.startswith("scheme="):
            scheme = field.split("=", 1)[1]
            break
    if not scheme:
        return None
    return f"{scheme}://{prefix[len('intent://') :]}"


def clean_uri(value: str) -> str:
    value = html.unescape(value.strip())
    value = value.replace("\\/", "/")
    value = value.rstrip("'\"<>)}],;")
    return value


def extract_direct_uris(text: str, scheme: str = DEFAULT_SCHEME) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    direct_pattern = re.compile(rf"{re.escape(scheme)}://[^\s\"'<>]+", re.IGNORECASE)
    encoded_pattern = re.compile(
        rf"{re.escape(scheme)}%3A%2F%2F[^\s\"'<>]+",
        re.IGNORECASE,
    )
    intent_pattern = re.compile(r"intent://[^\s\"'<>]+#Intent;[^\s\"'<>]+;end", re.IGNORECASE)

    for variant in decode_text_variants(text):
        for match in direct_pattern.finditer(variant):
            uri = clean_uri(match.group(0))
            if uri not in seen:
                seen.add(uri)
                found.append(uri)
        for match in encoded_pattern.finditer(variant):
            uri = clean_uri(unquote(match.group(0)))
            if uri.startswith(f"{scheme}://") and uri not in seen:
                seen.add(uri)
                found.append(uri)
        for match in intent_pattern.finditer(variant):
            uri = intent_to_uri(clean_uri(match.group(0)))
            if uri and uri.startswith(f"{scheme}://") and uri not in seen:
                seen.add(uri)
                found.append(uri)
    return found


def select_uri(candidates: list[str], source_url: str = "") -> str | None:
    if not candidates:
        return None
    shortlink = ""
    template_id = ""
    if source_url:
        parsed = urlsplit(source_url)
        parts = [part for part in parsed.path.split("/") if part]
        if parts:
            template_id = parts[0]
        if len(parts) > 1:
            shortlink = parts[1]
    scored: list[tuple[int, int, str]] = []
    for index, uri in enumerate(candidates):
        params = dict(parse_qsl(urlsplit(uri).query, keep_blank_values=True))
        score = 0
        if params.get("deep_link_value") == "af_app_invites":
            score += 10
        if params.get("media_source") == "af_app_invites":
            score += 5
        if shortlink and params.get("shortlink") == shortlink:
            score += 10
        if template_id and params.get("onelink_id") == template_id:
            score += 5
        score += sum(1 for key in REQUIRED_INVITE_PARAMS if params.get(key))
        scored.append((score, index, uri))
    scored.sort(reverse=True)
    return scored[0][2]


def add_force_deeplink(url: str) -> str:
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if not any(key == "af_force_deeplink" for key, _ in query):
        query.append(("af_force_deeplink", "true"))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment))


def resolve_http(url: str, timeout: float, max_hops: int, force_probe: bool) -> tuple[str | None, list[dict]]:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": ANDROID_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        }
    )
    trace: list[dict] = []
    attempts = [url]
    if force_probe:
        forced = add_force_deeplink(url)
        if forced != url:
            attempts.append(forced)

    for attempt_index, start_url in enumerate(attempts):
        current = start_url
        for hop in range(max_hops):
            started = time.monotonic()
            try:
                response = session.get(current, allow_redirects=False, timeout=timeout)
            except Exception as exc:
                trace.append(
                    {
                        "attempt": attempt_index,
                        "hop": hop,
                        "url": current,
                        "error": type(exc).__name__,
                    }
                )
                break
            elapsed_ms = round((time.monotonic() - started) * 1000)
            location = str(response.headers.get("Location") or "")
            content_type = str(response.headers.get("Content-Type") or "")
            trace.append(
                {
                    "attempt": attempt_index,
                    "hop": hop,
                    "url": current,
                    "status": response.status_code,
                    "location": location[:2000],
                    "content_type": content_type[:200],
                    "elapsed_ms": elapsed_ms,
                    "body_bytes": len(response.content),
                }
            )

            candidates = extract_direct_uris(location)
            if candidates:
                return select_uri(candidates, url), trace

            body = response.text[:2_000_000] if response.content else ""
            candidates = extract_direct_uris(body)
            if candidates:
                return select_uri(candidates, url), trace

            if 300 <= response.status_code < 400 and location:
                next_url = urljoin(current, location)
                parsed = urlsplit(next_url)
                if parsed.scheme in ("http", "https"):
                    current = next_url
                    continue
                break
            break
    return None, trace


def adb_executable() -> str:
    found = shutil.which("adb")
    if not found:
        raise RuntimeError("ADB_NOT_FOUND")
    return found


def adb_capture(url: str, device: str, timeout: float) -> tuple[str | None, list[dict]]:
    adb = adb_executable()
    trace: list[dict] = []
    subprocess.run([adb, "-s", device, "logcat", "-c"], capture_output=True, text=True, timeout=10)
    command = [
        adb,
        "-s",
        device,
        "shell",
        "am",
        "start",
        "-W",
        "-a",
        "android.intent.action.VIEW",
        "-d",
        url,
    ]
    started = time.monotonic()
    launch = subprocess.run(command, capture_output=True, text=True, timeout=max(20.0, timeout))
    trace.append(
        {
            "stage": "launch",
            "returncode": launch.returncode,
            "stdout": launch.stdout[-4000:],
            "stderr": launch.stderr[-2000:],
        }
    )
    deadline = time.monotonic() + max(5.0, timeout)
    while time.monotonic() < deadline:
        dump = subprocess.run(
            [adb, "-s", device, "logcat", "-d", "-v", "brief"],
            capture_output=True,
            text=True,
            timeout=10,
            errors="replace",
        )
        candidates = extract_direct_uris(dump.stdout)
        selected = select_uri(candidates, url)
        if selected:
            trace.append(
                {
                    "stage": "capture",
                    "elapsed_ms": round((time.monotonic() - started) * 1000),
                    "candidate_count": len(candidates),
                }
            )
            return selected, trace
        time.sleep(0.5)
    trace.append({"stage": "capture", "error": "DIRECT_URI_NOT_FOUND"})
    return None, trace


def resolve_from_log(path: Path, source_url: str) -> tuple[str | None, list[dict]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    candidates = extract_direct_uris(text)
    selected = select_uri(candidates, source_url)
    return selected, [{"stage": "log", "file": str(path), "candidate_count": len(candidates)}]


def uri_params(uri: str) -> dict[str, str]:
    return dict(parse_qsl(urlsplit(uri).query, keep_blank_values=True))


def validate_invite_uri(uri: str) -> tuple[dict[str, str], list[str]]:
    params = uri_params(uri)
    warnings: list[str] = []
    missing = [key for key in REQUIRED_INVITE_PARAMS if not params.get(key)]
    if missing:
        warnings.append("MISSING_PARAMS=" + ",".join(missing))
    if params.get("deep_link_value") and params.get("deep_link_value") != "af_app_invites":
        warnings.append("DEEP_LINK_VALUE_NOT_INVITE")
    if params.get("af_deeplink") and params.get("af_deeplink").lower() != "true":
        warnings.append("AF_DEEPLINK_NOT_TRUE")
    return params, warnings


def adb_command(uri: str, device: str) -> str:
    escaped = uri.replace("&", "\\&")
    return (
        f'adb -s {device} shell am start -W -f 0x14000000 '
        f'-a android.intent.action.VIEW -c android.intent.category.BROWSABLE '
        f'-d "{escaped}" -n {DEFAULT_COMPONENT}'
    )


def write_result(
    source_url: str,
    mode: str,
    uri: str | None,
    trace: list[dict],
    device: str,
    warnings: list[str],
) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = ROOT / "state" / "onelink-resolver" / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)
    params = uri_params(uri) if uri else {}
    result = {
        "ok": bool(uri),
        "mode": mode,
        "source_url": source_url,
        "direct_uri": uri,
        "params": params,
        "warnings": warnings,
        "trace": trace,
    }
    (out_dir / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    if uri:
        (out_dir / "direct_uri.txt").write_text(uri + "\n", encoding="utf-8")
        (out_dir / "adb_command.txt").write_text(adb_command(uri, device) + "\n", encoding="utf-8")
    return out_dir


def main() -> int:
    args = parse_args()
    source_url = str(args.url or "").strip()
    if not source_url and not args.from_log:
        source_url = input("OneLink URL: ").strip()
    if source_url:
        try:
            source_url = normalize_onelink_url(source_url)
        except ValueError as exc:
            print(str(exc))
            return 2

    emit(f"ONELINK RESOLVER START mode={'log' if args.from_log else args.mode} secretOutput=NONE")

    if args.from_log:
        path = Path(args.from_log).expanduser().resolve()
        if not path.is_file():
            print("LOG_FILE_NOT_FOUND")
            return 3
        uri, trace = resolve_from_log(path, source_url)
        mode = "log"
    elif args.mode == "http":
        if not source_url:
            print("ONELINK_URL_REQUIRED")
            return 4
        emit("HTTP RESOLVE START appLaunch=NO")
        uri, trace = resolve_http(
            source_url,
            timeout=max(3.0, args.timeout),
            max_hops=max(1, args.max_hops),
            force_probe=bool(args.force_deeplink_probe),
        )
        mode = "http"
    else:
        if not source_url:
            print("ONELINK_URL_REQUIRED")
            return 4
        if not args.allow_app_launch:
            print("ADB_CAPTURE_REQUIRES_--allow-app-launch")
            print("WARNING=This mode opens the OneLink on the device and may consume an eligible invite receiver.")
            return 5
        emit(f"ADB CAPTURE START device={args.device} appLaunch=YES")
        try:
            uri, trace = adb_capture(source_url, args.device, max(5.0, args.timeout))
        except Exception as exc:
            print(f"ADB_CAPTURE_ERROR type={type(exc).__name__} code={exc}")
            return 6
        mode = "adb-capture"

    warnings: list[str] = []
    if uri:
        params, uri_warnings = validate_invite_uri(uri)
        warnings.extend(uri_warnings)
        out_dir = write_result(source_url, mode, uri, trace, args.device, warnings)
        emit("RESOLVE PASS")
        emit(f"directUri={uri}")
        emit("PARAMS")
        for key in sorted(params):
            emit(f"  {key}={params[key]}")
        for warning in warnings:
            emit(f"WARNING={warning}")
        emit("ADB COMMAND")
        emit(adb_command(uri, args.device))
        emit(f"OUTPUT={out_dir}")
        return 0

    warnings.append("DIRECT_URI_NOT_FOUND")
    out_dir = write_result(source_url, mode, None, trace, args.device, warnings)
    emit("RESOLVE FAILED code=DIRECT_URI_NOT_FOUND")
    if mode == "http":
        emit("NEXT=Use a previously captured log with --from-log, or explicit --mode adb-capture --allow-app-launch on a disposable/non-eligible lab account.")
    emit(f"OUTPUT={out_dir}")
    return 7


if __name__ == "__main__":
    raise SystemExit(main())
