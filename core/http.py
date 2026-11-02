"""Shared HTTP client: timeouts, a polite per-host rate limit, size caps and
consistent error handling. Every outbound request goes through here."""
from __future__ import annotations

import socket
import threading
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urljoin, urlparse

import requests

from .configuration import DEFAULT_TIMEOUT, USER_AGENT, get_logger
from .security import is_public_ip

log = get_logger()

_session = requests.Session()
_session.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.8"})

_MIN_INTERVAL = 0.35  # seconds between requests to the same host
_last: dict[str, float] = {}
_lock = threading.Lock()
MAX_BYTES = 5_000_000
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class HttpError(Exception):
    pass


def _throttle(url: str):
    host = urlparse(url).netloc
    with _lock:
        wait = _last.get(host, 0) + _MIN_INTERVAL - time.monotonic()
        _last[host] = max(time.monotonic(), _last.get(host, 0) + _MIN_INTERVAL)
    if wait > 0:
        time.sleep(wait)


def _retry_delay(response, attempt: int) -> float:
    """Use Retry-After when present, otherwise short bounded exponential backoff."""
    value = response.headers.get("Retry-After", "") if response is not None else ""
    try:
        return min(8.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        if value:
            try:
                retry_at = parsedate_to_datetime(value)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=timezone.utc)
                return min(8.0, max(0.0, (retry_at - datetime.now(timezone.utc)).total_seconds()))
            except (TypeError, ValueError, OverflowError):
                pass
    return min(4.0, 0.5 * (2 ** attempt))


MAX_REDIRECTS = 5


def _assert_public_url(url: str):
    """Refuse non-http(s) URLs and hosts that resolve to loopback/private/link-local addresses."""
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise HttpError("Only http(s) URLs are allowed")
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except OSError:
        raise HttpError(f"Could not resolve {p.hostname}")
    if not infos or not all(is_public_ip(i[4][0].split("%")[0]) for i in infos):
        raise HttpError(f"Refused: {p.hostname} is not a public internet address")


def request(method: str, url: str, *, timeout: float = DEFAULT_TIMEOUT, headers: dict | None = None,
            params: dict | None = None, json: dict | list | None = None, data=None,
            allow_redirects: bool = True, max_bytes: int = MAX_BYTES, retries: int = 0,
            public_only: bool = False) -> requests.Response:
    """Make a bounded request with optional retries for transient network/API failures.

    public_only=True is for user-supplied URLs: every hop (including redirects, followed manually)
    must resolve to a public address, so a URL cannot be used to reach local or internal services.
    """
    if public_only:
        for _ in range(MAX_REDIRECTS + 1):
            _assert_public_url(url)
            resp = request(method, url, timeout=timeout, headers=headers, params=params, json=json, data=data,
                           allow_redirects=False, max_bytes=max_bytes, retries=retries)
            loc = resp.headers.get("Location")
            if not (allow_redirects and resp.status_code in (301, 302, 303, 307, 308) and loc):
                return resp
            url, params = urljoin(url, loc), None
            if resp.status_code in (301, 302, 303):
                method, json, data = "GET", None, None
        raise HttpError("Too many redirects")
    host = urlparse(url).netloc
    attempts = max(0, min(int(retries), 3)) + 1
    for attempt in range(attempts):
        _throttle(url)
        response = None
        try:
            response = _session.request(method, url, timeout=timeout, headers=headers, params=params, json=json,
                                        data=data, allow_redirects=allow_redirects, stream=True)
            if response.status_code in _RETRYABLE_STATUS and attempt + 1 < attempts:
                delay = _retry_delay(response, attempt)
                response.close()
                time.sleep(delay)
                continue
            content = bytearray()
            for chunk in response.iter_content(65536):
                content.extend(chunk)
                if len(content) > max_bytes:
                    response.close()
                    raise HttpError(f"Response from {host} exceeded {max_bytes} bytes")
            response._content = bytes(content)
            # host only: URL paths can contain the usernames/identifiers being investigated
            log.info("%s %s -> %s", method, host, response.status_code)
            return response
        except requests.Timeout:
            if attempt + 1 < attempts:
                time.sleep(_retry_delay(None, attempt))
                continue
            raise HttpError(f"Timed out contacting {host}")
        except requests.ConnectionError as e:
            if attempt + 1 < attempts:
                time.sleep(_retry_delay(None, attempt))
                continue
            raise HttpError(f"Could not connect to {host}: {type(e).__name__}")
        except requests.RequestException as e:
            raise HttpError(f"Request to {host} failed: {type(e).__name__}")
    raise HttpError(f"Request to {host} did not complete")


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
