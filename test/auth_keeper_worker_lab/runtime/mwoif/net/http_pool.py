from __future__ import annotations

import threading

import requests
from requests.adapters import HTTPAdapter

_TLS = threading.local()
_POOL_LOCK = threading.RLock()


def thread_http_session(*, clear_cookies: bool = False) -> requests.Session:
    session = getattr(_TLS, "session", None)
    if session is None:
        session = requests.Session()
        adapter = HTTPAdapter(
            pool_connections=16,
            pool_maxsize=64,
            max_retries=0,
            pool_block=False,
        )
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        _TLS.session = session
    if clear_cookies:
        session.cookies.clear()
    return session


try:
    import urllib3

    _POOL_VERIFY = urllib3.PoolManager(
        num_pools=32,
        maxsize=128,
        block=False,
        cert_reqs="CERT_REQUIRED",
        retries=False,
    )
    _POOL_INSECURE = urllib3.PoolManager(
        num_pools=32,
        maxsize=128,
        block=False,
        cert_reqs="CERT_NONE",
        retries=False,
    )
except Exception:
    urllib3 = None  # type: ignore
    _POOL_VERIFY = None
    _POOL_INSECURE = None


def reset_http_pools() -> None:
    with _POOL_LOCK:
        for pool in (_POOL_VERIFY, _POOL_INSECURE):
            if pool is None:
                continue
            try:
                pool.clear()
            except Exception:
                pass


def pooled_post_bytes(
    *,
    url: str,
    body: bytes,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
    verify: bool = True,
) -> tuple[int, bytes, dict[str, str]]:
    if urllib3 is None:
        response = thread_http_session().post(
            url,
            data=body,
            headers=headers or {},
            timeout=timeout,
            verify=verify,
        )
        return int(response.status_code), bytes(response.content or b""), dict(response.headers)
    pool = _POOL_VERIFY if verify else _POOL_INSECURE
    assert pool is not None
    response = pool.request(
        "POST",
        url,
        body=body,
        headers=headers or {},
        timeout=urllib3.Timeout(total=float(timeout)),
        preload_content=True,
        redirect=False,
    )
    return int(response.status), bytes(response.data or b""), {str(k): str(v) for k, v in response.headers.items()}
