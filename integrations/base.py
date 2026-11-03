"""Adapter contract shared by every provider: credentials, requests, retries, rate limits,
error classification, quota tracking and result normalization.

Secrets are read through the existing credential store (encrypted database, with the provider's
environment variable as a fallback) and are only ever sent to the provider. Error text never
contains request URLs or parameters, and everything stored goes through core.security.redact().
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

from core import http
from core.database import get_db
from core.models import now_iso
from core.security import is_public_ip, redact

# --- statuses ----------------------------------------------------------------------------
CONNECTED = "CONNECTED"
NOT_CONFIGURED = "NOT CONFIGURED"
RATE_LIMITED = "RATE LIMITED"
AUTH_FAILED = "AUTHENTICATION FAILED"
UNAVAILABLE = "PROVIDER UNAVAILABLE"
ERROR = "ERROR"
# Two additional, honest states the required six cannot express:
DISABLED = "DISABLED"        # switched off by the operator
NOT_TESTED = "NOT TESTED"    # credentials present, but no successful live request yet

# --- tiers -------------------------------------------------------------------------------
FREE = "FREE"                # no account, no key
FREE_TIER = "FREE-TIER"      # free account/key with a quota
PAID = "PAID"                # no usable free access

MAX_RAW_BYTES = 8_000_000


class IntegrationError(Exception):
    status = ERROR


class NotConfiguredError(IntegrationError):
    status = NOT_CONFIGURED


class AuthError(IntegrationError):
    status = AUTH_FAILED


class RateLimitError(IntegrationError):
    status = RATE_LIMITED


class UnavailableError(IntegrationError):
    status = UNAVAILABLE


class ResponseError(IntegrationError):
    """Reachable provider, but the answer was malformed or unexpected."""
    status = ERROR


class InputError(IntegrationError):
    """The caller's value is not acceptable for this lookup (nothing was sent)."""
    status = ERROR


@dataclass
class NormalizedResult:
    provider: str
    query: str
    source_url: str
    result_type: str
    data: dict
    timestamp: str = field(default_factory=now_iso)
    confidence: float | None = None   # None = the provider gives no confidence; TRACEPOINT does not invent one
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"provider": self.provider, "query": self.query, "timestamp": self.timestamp,
                "source_url": self.source_url, "result_type": self.result_type, "data": self.data,
                "confidence": self.confidence, "limitations": list(self.limitations)}


@dataclass
class TestOutcome:
    status: str
    detail: str
    quota: dict | None = None
    tested_at: str = field(default_factory=now_iso)


# --- input validation --------------------------------------------------------------------
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def clean_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        raise InputError("Not a valid IP address.") from None
    if not is_public_ip(str(ip)):
        raise InputError("Private, loopback or reserved addresses are never sent to third-party services.")
    return str(ip)


def clean_domain(value: str) -> str:
    v = (value or "").strip().lower().rstrip(".")
    v = re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0]
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        raise InputError("Not a valid domain name.") from None
    if not _DOMAIN.match(v):
        raise InputError("Not a valid domain name.")
    return v


def clean_text(value: str, maxlen: int = 200) -> str:
    v = re.sub(r"[\x00-\x1f\x7f]", " ", (value or "")).strip()
    if not v:
        raise InputError("Empty query.")
    return v[:maxlen]


def clean_url(value: str) -> str:
    v = (value or "").strip()
    p = urlparse(v)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise InputError("Not a valid http(s) URL.")
    return v[:2000]


class Provider:
    """One external service. Subclasses set the metadata and implement _probe() and lookup()."""
    id = ""
    name = ""
    category = ""
    tier = FREE
    free_info = ""
    signup_url = ""
    docs_url = ""
    endpoint = ""
    auth = "none"
    secret_keys: tuple[str, ...] = ()      # credentials that are required (names in core.configuration.ENV_VARS)
    optional_keys: tuple[str, ...] = ()    # credentials that raise limits but are not required
    lookups: dict[str, str] = {}           # kind -> description
    limitations: tuple[str, ...] = ()
    timeout = 15
    retries = 2
    min_interval = 0.0                     # extra spacing (seconds) between requests to this provider
    auth_codes: tuple[int, ...] = (401, 403)

    def __init__(self):
        self._last = 0.0
        self._lock = threading.Lock()
        self.quota: dict | None = None

    # -- credentials ----------------------------------------------------------------
    def secret(self, key: str) -> str:
        return get_db().get_secret(key)

    def missing(self) -> list[str]:
        return [k for k in self.secret_keys if not self.secret(k)]

    def configured(self) -> bool:
        return not self.missing()

    def require(self) -> None:
        miss = self.missing()
        if miss:
            from core.configuration import ENV_VARS
            raise NotConfiguredError("Missing credential: " + ", ".join(ENV_VARS.get(k, k) for k in miss))

    # -- HTTP -----------------------------------------------------------------------
    def _pace(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            start = max(now, self._last + self.min_interval)
            self._last = start
        if start > now:
            time.sleep(start - now)

    def request(self, method: str, url: str, *, params=None, headers=None, json=None, data=None,
                retries: int | None = None, allow: tuple[int, ...] = (), timeout: float | None = None,
                max_bytes: int = MAX_RAW_BYTES) -> requests.Response:
        """One classified request. Returns the response for 2xx (and any code in `allow`)."""
        self._pace()
        try:
            r = http.request(method, url, params=params, headers=headers, json=json, data=data,
                             timeout=timeout or self.timeout, max_bytes=max_bytes,
                             retries=self.retries if retries is None else retries)
        except http.HttpError as e:
            raise UnavailableError(f"{self.name}: {redact(str(e))}") from None
        except Exception as e:  # never let a library bug escape the adapter
            raise UnavailableError(f"{self.name}: {type(e).__name__} during request") from None
        self._note_quota(r)
        code = r.status_code
        if code in allow or 200 <= code < 300:
            return r
        if code in self.auth_codes:
            raise AuthError(f"{self.name} rejected the credentials (HTTP {code}).")
        if code in (429, 402):
            ra = r.headers.get("Retry-After")
            raise RateLimitError(f"{self.name} rate limit or quota reached (HTTP {code})"
                                 + (f"; retry after {ra}s." if ra else "."))
        if code >= 500:
            raise UnavailableError(f"{self.name} server error (HTTP {code}).")
        raise ResponseError(f"{self.name} returned HTTP {code}.")

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def json(self, r: requests.Response, expect=(dict, list)):
        try:
            data = r.json()
        except (ValueError, TypeError):
            raise ResponseError(f"{self.name} returned a non-JSON or malformed response.") from None
        if not isinstance(data, expect):
            raise ResponseError(f"{self.name} returned an unexpected JSON structure.")
        return data

    # -- quota ----------------------------------------------------------------------
    def _note_quota(self, r: requests.Response) -> None:
        try:
            q = self.quota_from(r)
        except Exception:
            q = None
        if q:
            q["as_of"] = now_iso()
            self.quota = q

    def quota_from(self, r: requests.Response) -> dict | None:
        """Generic X-RateLimit-* header parsing; providers with other schemes override this."""
        h = {k.lower(): v for k, v in r.headers.items()}
        out = {}
        for label, names in (("remaining", ("x-ratelimit-remaining", "x-rate-limit-remaining", "ratelimit-remaining")),
                             ("limit", ("x-ratelimit-limit", "x-rate-limit-limit", "ratelimit-limit"))):
            for n in names:
                if n in h and str(h[n]).strip().isdigit():
                    out[label] = int(h[n])
                    break
        return out or None

    # -- contract -------------------------------------------------------------------
    def _probe(self) -> str:
        """One minimal live request; return a short detail string or raise IntegrationError."""
        raise NotImplementedError

    def test(self) -> TestOutcome:
        """Live connection test. CONNECTED only if a real request succeeded."""
        saved_retries = self.retries
        try:
            self.require()
            self.retries = 0  # a test reports the first answer; it must not sit in backoff loops
            detail = self._probe()
            return TestOutcome(CONNECTED, detail or "Test request succeeded.", self.quota)
        except IntegrationError as e:
            return TestOutcome(e.status, redact(str(e)), self.quota)
        except Exception as e:
            return TestOutcome(ERROR, f"Unexpected {type(e).__name__} while testing.", self.quota)
        finally:
            self.retries = saved_retries

    def lookup(self, kind: str, value: str, **kw) -> NormalizedResult:
        raise NotImplementedError

    def _result(self, query: str, source_url: str, result_type: str, data: dict, *,
                limitations: list[str] | None = None, confidence: float | None = None) -> NormalizedResult:
        return NormalizedResult(self.name, query, source_url, result_type, data, confidence=confidence,
                                limitations=list(self.limitations) + list(limitations or []))

    def _check_kind(self, kind: str) -> None:
        if kind not in self.lookups:
            raise InputError(f"{self.name} does not support '{kind}' lookups (supported: "
                             f"{', '.join(self.lookups) or 'none'}).")
