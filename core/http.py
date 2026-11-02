"""Shared HTTP client: timeouts, a polite per-host rate limit, size caps and
consistent error handling. Every outbound request goes through here."""
from __future__ import annotations

import threading
import time
from urllib.parse import urlparse

import requests

from .configuration import DEFAULT_TIMEOUT, USER_AGENT, get_logger

log = get_logger()

_session = requests.Session()
_session.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.8"})

_MIN_INTERVAL = 0.35  # seconds between requests to the same host
_last: dict[str, float] = {}
_lock = threading.Lock()
MAX_BYTES = 5_000_000


class HttpError(Exception):
    pass


def _throttle(url: str):
    host = urlparse(url).netloc
    with _lock:
        wait = _last.get(host, 0) + _MIN_INTERVAL - time.monotonic()
        _last[host] = max(time.monotonic(), _last.get(host, 0) + _MIN_INTERVAL)
    if wait > 0:
        time.sleep(wait)


def request(method: str, url: str, *, timeout: float = DEFAULT_TIMEOUT, headers: dict | None = None,
            params: dict | None = None, json: dict | list | None = None, data=None,
            allow_redirects: bool = True, max_bytes: int = MAX_BYTES) -> requests.Response:
    _throttle(url)
    try:
        r = _session.request(method, url, timeout=timeout, headers=headers, params=params, json=json,
                             data=data, allow_redirects=allow_redirects, stream=True)
        content = b""
        for chunk in r.iter_content(65536):
            content += chunk
            if len(content) > max_bytes:
                r.close()
                raise HttpError(f"Response from {urlparse(url).netloc} exceeded {max_bytes} bytes")
        r._content = content
        log.info("%s %s -> %s", method, urlparse(url).netloc + urlparse(url).path, r.status_code)
        return r
    except requests.Timeout:
        raise HttpError(f"Timed out contacting {urlparse(url).netloc}")
    except requests.ConnectionError as e:
        raise HttpError(f"Could not connect to {urlparse(url).netloc}: {type(e).__name__}")
    except requests.RequestException as e:
        raise HttpError(f"Request to {urlparse(url).netloc} failed: {type(e).__name__}")


def get(url: str, **kw) -> requests.Response:
    return request("GET", url, **kw)


def get_json(url: str, **kw):
    r = get(url, **kw)
    if r.status_code >= 400:
        raise HttpError(f"{urlparse(url).netloc} returned HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError:
        raise HttpError(f"{urlparse(url).netloc} returned non-JSON content")
