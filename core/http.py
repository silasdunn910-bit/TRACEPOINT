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


def _split_url(url: str) -> tuple[str, str, int]:
    """-> (scheme, hostname, port) for an http(s) URL; HttpError for anything malformed."""
    try:
        p = urlparse(url)
        port = p.port
        host = p.hostname
    except ValueError:
        raise HttpError("Malformed URL")
    if p.scheme not in ("http", "https") or not host:
        raise HttpError("Only http(s) URLs are allowed")
    return p.scheme, host, port or (443 if p.scheme == "https" else 80)


def _resolve_public(host: str, port: int) -> list[str]:
    """Resolve once and return the addresses, all of which must be public. HttpError otherwise.

    Refusing when *any* answer is non-public stops a name that mixes public and private records."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        raise HttpError(f"Could not resolve {host}")
    addrs = list(dict.fromkeys(i[4][0].split("%")[0] for i in infos))
    if not addrs or not all(is_public_ip(a) for a in addrs):
        raise HttpError(f"Refused: {host} is not a public internet address")
    return addrs


def _assert_public_url(url: str):
    """Early check with a clear message. The guarantee is the connect-time pin below, not this."""
    _, host, port = _split_url(url)
    _resolve_public(host, port)


# --- connect-time pinning (DNS-rebinding protection) ---------------------------------------
# The check above and the later connection could resolve differently. For public_only requests
# the connection itself resolves the name, validates every address, and connects to exactly
# one of those validated IPs. The TLS layer still receives the original hostname, so SNI and
# certificate/hostname verification are unchanged.
from urllib3.connection import HTTPConnection as _U3HTTPConnection, HTTPSConnection as _U3HTTPSConnection  # noqa: E402
from urllib3.connectionpool import HTTPConnectionPool as _U3HTTPPool, HTTPSConnectionPool as _U3HTTPSPool  # noqa: E402
from urllib3.exceptions import NewConnectionError as _NewConnectionError  # noqa: E402
from requests.adapters import HTTPAdapter as _HTTPAdapter  # noqa: E402


def _pinned_new_conn(self):
    try:
        addrs = _resolve_public(self._dns_host, self.port)
    except HttpError as e:
        raise _NewConnectionError(self, str(e))
    last: Exception | None = None
    for addr in addrs:
        try:
            return socket.create_connection((addr, self.port), self.timeout, self.source_address)
        except OSError as e:
            last = e
    raise _NewConnectionError(self, f"Failed to connect to {self._dns_host}: {last}")


class _PinnedHTTPConnection(_U3HTTPConnection):
    _new_conn = _pinned_new_conn


class _PinnedHTTPSConnection(_U3HTTPSConnection):
    _new_conn = _pinned_new_conn


class _PinnedHTTPPool(_U3HTTPPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSPool(_U3HTTPSPool):
    ConnectionCls = _PinnedHTTPSConnection


class _PinnedAdapter(_HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {"http": _PinnedHTTPPool, "https": _PinnedHTTPSPool}


def _make_public_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.8"})
    s.trust_env = False  # no environment proxies/netrc/CA overrides: nothing may redirect the connection
    s.verify = True      # certificate and hostname verification stay on
    for scheme in ("http://", "https://"):
        s.mount(scheme, _PinnedAdapter(max_retries=0))
    return s


_public_session = _make_public_session()


def request(method: str, url: str, *, timeout: float = DEFAULT_TIMEOUT, headers: dict | None = None,
            params: dict | None = None, json: dict | list | None = None, data=None,
            allow_redirects: bool = True, max_bytes: int = MAX_BYTES, retries: int = 0,
            public_only: bool = False, _pinned: bool = False) -> requests.Response:
    """Make a bounded request with optional retries for transient network/API failures.

    public_only=True is for user-supplied URLs: every hop (including redirects, followed manually)
    must resolve to public addresses, and the connection is pinned to the validated address
    (see the pinning section above), so neither a URL, a redirect nor a DNS answer that changes
    between check and connect can reach local or internal services.
    """
    if public_only:
        for _ in range(MAX_REDIRECTS + 1):
            _assert_public_url(url)
            resp = request(method, url, timeout=timeout, headers=headers, params=params, json=json, data=data,
                           allow_redirects=False, max_bytes=max_bytes, retries=retries, _pinned=True)
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
            session = _public_session if _pinned else _session
            response = session.request(method, url, timeout=timeout, headers=headers, params=params, json=json,
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
            if _pinned and "not a public internet address" in str(e):
                raise HttpError(f"Refused: {host} is not a public internet address")
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
