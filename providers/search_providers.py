"""Web search providers behind one interface.

Free, no key:   DuckDuckGo HTML endpoint (best-effort fallback; may rate-limit automated use)
Optional keys:  Brave Search API, Google Programmable Search, self-hosted SearXNG

Every provider failure is raised as ProviderError with a `kind` so callers can tell an
invalid key from a rate limit, an exhausted quota, an access denial, a server error,
a malformed response or a timeout. Provider error messages never contain credentials.

To add a provider: subclass SearchProvider, implement configured() and search(),
and add it to ALL_PROVIDERS.
"""
from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlparse

from core import http
from core.database import get_db
from core.models import now_iso

# --- failure kinds ----------------------------------------------------------
INVALID_KEY = "INVALID_KEY"
INVALID_CONFIG = "INVALID_CONFIG"
RATE_LIMIT = "RATE_LIMIT"
QUOTA = "QUOTA_EXHAUSTED"
ACCESS_DENIED = "ACCESS_DENIED"
SERVER_ERROR = "SERVER_ERROR"
INVALID_RESPONSE = "INVALID_RESPONSE"
TIMEOUT = "TIMEOUT"
UNAVAILABLE = "UNAVAILABLE"  # connection failure or other HTTP error

KIND_LABEL = {
    INVALID_KEY: "invalid API key", INVALID_CONFIG: "invalid configuration", RATE_LIMIT: "rate limited",
    QUOTA: "quota exhausted", ACCESS_DENIED: "access denied", SERVER_ERROR: "server error",
    INVALID_RESPONSE: "invalid response", TIMEOUT: "connection timeout", UNAVAILABLE: "unavailable",
}

# --- connection-test statuses ----------------------------------------------
ST_CONFIGURED = "CONFIGURED"            # stored, NOT yet tested
ST_CONNECTED = "CONNECTED"              # a live test succeeded
ST_INVALID = "INVALID CREDENTIALS"
ST_RATE_LIMITED = "RATE LIMITED"
ST_UNAVAILABLE = "UNAVAILABLE"


@dataclass
class SearchResult:
    title: str
    url: str
    snippet: str
    provider: str
    query: str
    discovered_at: str = field(default_factory=now_iso)
    published_at: str = ""

    @property
    def domain(self) -> str:
        return urlparse(self.url).netloc.lower().removeprefix("www.")


class ProviderUnavailable(Exception):
    kind = UNAVAILABLE


class ProviderError(ProviderUnavailable):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


@dataclass
class ConnectionResult:
    status: str
    detail: str
    kind: str = ""
    tested_at: str = field(default_factory=now_iso)


def validate_searxng_url(value: str) -> tuple[str, str]:
    """Return (normalized_url, error). error is '' when the URL is acceptable."""
    v = (value or "").strip()
    if not v:
        return "", "SearXNG URL is empty."
    if re.search(r"\s", v):
        return "", "SearXNG URL must not contain whitespace."
    if "://" not in v:
        return "", "SearXNG URL needs a scheme, e.g. http://127.0.0.1:8888 or https://search.example.org"
    try:
        p = urlparse(v)
        port = p.port  # raises ValueError on a bad port
    except ValueError:
        return "", "SearXNG URL is malformed (invalid port or host)."
    if p.scheme.lower() not in ("http", "https"):
        return "", f"Unsupported scheme '{p.scheme}'. Only http:// and https:// are allowed."
    if not p.hostname:
        return "", "SearXNG URL has no host name."
    if p.username or p.password:
        return "", "Do not embed credentials in the SearXNG URL."
    if p.query or p.fragment:
        return "", "SearXNG URL must be the instance base address only (no ?query or #fragment)."
    path = p.path.rstrip("/")
    host = p.hostname if ":" not in p.hostname else f"[{p.hostname}]"
    return f"{p.scheme.lower()}://{host}{':' + str(port) if port else ''}{path}", ""


# --- shared helpers -----------------------------------------------------------
def _fetch(name: str, url: str, **kw):
    """HTTP GET that converts transport failures into classified ProviderErrors."""
    try:
        return http.get(url, **kw)
    except http.HttpError as e:
        msg = str(e)
        kind = TIMEOUT if "timed out" in msg.lower() else UNAVAILABLE
        raise ProviderError(kind, f"{name}: {msg}") from None


def _json(name: str, r):
    try:
        data = r.json()
    except (ValueError, TypeError):
        raise ProviderError(INVALID_RESPONSE, f"{name} returned a non-JSON response") from None
    if not isinstance(data, dict):
        raise ProviderError(INVALID_RESPONSE, f"{name} returned an unexpected JSON structure")
    return data


def _safe_json(r) -> dict:
    try:
        d = r.json()
        return d if isinstance(d, dict) else {}
    except (ValueError, TypeError):
        return {}


def _generic_status_error(name: str, code: int) -> ProviderError | None:
    if code >= 500:
        return ProviderError(SERVER_ERROR, f"{name} server error (HTTP {code})")
    if code >= 400:
        return ProviderError(UNAVAILABLE, f"{name} returned HTTP {code}")
    return None


def _strip_tags(s: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", s or "")).strip()


def _text(v) -> str:
    return v if isinstance(v, str) else ""


class SearchProvider:
    name = "base"
    requires_key = False
    secret_keys: tuple[str, ...] = ()
    #: whether HTTP 403 should be reported as a credential problem (true for keyed APIs)
    denied_is_credentials = True

    def configured(self) -> bool:
        return True

    def search(self, query: str, limit: int = 10, retries: int = 2) -> list[SearchResult]:
        raise NotImplementedError

    def test_connection(self) -> ConnectionResult:
        """One minimal live request (no retries). Never reports CONNECTED unless it succeeded."""
        if not self.configured():
            return ConnectionResult(ST_UNAVAILABLE, "Not configured.", "NOT_CONFIGURED")
        try:
            self.search("tracepoint connection test", 1, retries=0)
        except ProviderError as e:
            return ConnectionResult(self._status_for(e.kind), str(e), e.kind)
        except ProviderUnavailable as e:
            return ConnectionResult(ST_UNAVAILABLE, str(e), UNAVAILABLE)
        except Exception as e:  # unexpected parsing bug: still never "connected"
            return ConnectionResult(ST_UNAVAILABLE, f"{type(e).__name__} while testing", INVALID_RESPONSE)
        return ConnectionResult(ST_CONNECTED, "Test query succeeded.")

    def _status_for(self, kind: str) -> str:
        if kind in (INVALID_KEY, INVALID_CONFIG):
            return ST_INVALID
        if kind == ACCESS_DENIED:
            return ST_INVALID if self.denied_is_credentials else ST_UNAVAILABLE
        if kind in (RATE_LIMIT, QUOTA):
            return ST_RATE_LIMITED
        return ST_UNAVAILABLE


class DuckDuckGoHTML(SearchProvider):
    name = "DuckDuckGo (HTML)"
    _a = re.compile(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.S)
    _snip = re.compile(r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', re.S)
    _hint = "Configure Brave/Google/SearXNG for reliable search."

    def search(self, query, limit=10, retries=2):
        try:
            r = http.request("POST", "https://html.duckduckgo.com/html/", data={"q": query, "kl": "us-en"},
                             headers={"Referer": "https://html.duckduckgo.com/"}, retries=retries)
        except http.HttpError as e:
            kind = TIMEOUT if "timed out" in str(e).lower() else UNAVAILABLE
            raise ProviderError(kind, f"DuckDuckGo: {e}") from None
        text = r.text
        if r.status_code == 429:
            raise ProviderError(RATE_LIMIT, f"DuckDuckGo rate limited the request (HTTP 429). {self._hint}")
        if r.status_code >= 500:
            raise ProviderError(SERVER_ERROR, f"DuckDuckGo server error (HTTP {r.status_code}).")
        if r.status_code != 200 or ("anomaly" in text[:5000].lower() and "result__a" not in text):
            raise ProviderError(ACCESS_DENIED, f"DuckDuckGo refused the automated request (HTTP {r.status_code}). "
                                               + self._hint)
        if "result__a" not in text:
            if 'class="no-results"' in text or "No results." in text:
                return []  # a genuine, completed search with zero results
            raise ProviderError(ACCESS_DENIED, "DuckDuckGo returned a page with no results markup "
                                               "(possible block/challenge). " + self._hint)
        links = self._a.findall(text)
        snippets = self._snip.findall(text)
        out = []
        for i, (href, title) in enumerate(links):
            if href.startswith("//"):
                href = "https:" + href
            if "duckduckgo.com/l/" in href:
                href = unquote(parse_qs(urlparse(href).query).get("uddg", [href])[0])
            if "duckduckgo.com/y.js" in href:  # ads
                continue
            out.append(SearchResult(_strip_tags(title), href, _strip_tags(snippets[i]) if i < len(snippets) else "",
                                    self.name, query))
            if len(out) >= limit:
                break
        return out


class BraveSearch(SearchProvider):
    name = "Brave Search API"
    requires_key = True
    secret_keys = ("brave_search_key",)

    def configured(self):
        return bool(get_db().get_secret("brave_search_key"))

    def search(self, query, limit=10, retries=2):
        key = get_db().get_secret("brave_search_key")
        r = _fetch(self.name, "https://api.search.brave.com/res/v1/web/search",
                   params={"q": query, "count": max(1, min(limit, 20))},
                   headers={"X-Subscription-Token": key, "Accept": "application/json"}, retries=retries)
        code = r.status_code
        if code == 401:
            raise ProviderError(INVALID_KEY, "Brave rejected the API key (HTTP 401).")
        if code == 403:
            raise ProviderError(ACCESS_DENIED, "Brave denied access (HTTP 403): key lacks permission for this plan.")
        if code == 429:
            err = _safe_json(r).get("error") or {}
            blob = (str(err.get("code", "")) + str(err.get("detail", ""))).lower() if isinstance(err, dict) else ""
            if "quota" in blob:
                raise ProviderError(QUOTA, "Brave monthly quota exhausted (HTTP 429).")
            raise ProviderError(RATE_LIMIT, "Brave rate limit reached (HTTP 429).")
        generic = _generic_status_error("Brave", code)
        if generic:
            raise generic
        data = _json(self.name, r)
        web = data.get("web", {})
        items = web.get("results", []) if isinstance(web, dict) else None
        if not isinstance(items, list):
            raise ProviderError(INVALID_RESPONSE, "Brave response is missing the web.results list")
        return [SearchResult(_strip_tags(_text(i.get("title"))), _text(i.get("url")),
                             _strip_tags(_text(i.get("description"))), self.name, query)
                for i in items[:limit] if isinstance(i, dict)]


class GoogleCSE(SearchProvider):
    name = "Google Programmable Search"
    requires_key = True
    secret_keys = ("google_cse_key", "google_cse_cx")

    def configured(self):
        db = get_db()
        return bool(db.get_secret("google_cse_key") and db.get_secret("google_cse_cx"))

    @staticmethod
    def _classify(r) -> ProviderError | None:
        code = r.status_code
        if code < 400:
            return None
        err = _safe_json(r).get("error")
        err = err if isinstance(err, dict) else {}
        details = err.get("errors") if isinstance(err.get("errors"), list) else []
        reason = str((details[0] or {}).get("reason", "") if details and isinstance(details[0], dict) else "")
        message = str(err.get("message", "")).lower()
        status = str(err.get("status", ""))
        if reason in ("dailyLimitExceeded", "quotaExceeded") or "quota" in message or status == "RESOURCE_EXHAUSTED":
            return ProviderError(QUOTA, f"Google quota exhausted (HTTP {code}).")
        if reason in ("rateLimitExceeded", "userRateLimitExceeded") or code == 429:
            return ProviderError(RATE_LIMIT, f"Google rate limit reached (HTTP {code}).")
        if reason == "keyInvalid" or "api key not valid" in message or "api key" in message and code in (400, 401):
            return ProviderError(INVALID_KEY, f"Google rejected the API key (HTTP {code}).")
        if code == 400:
            return ProviderError(INVALID_CONFIG, "Google rejected the request (HTTP 400); check the search engine ID (cx).")
        if code in (401, 403):
            return ProviderError(ACCESS_DENIED, f"Google denied access (HTTP {code}); the Custom Search API may not "
                                                "be enabled for this key.")
        return _generic_status_error("Google", code)

    def search(self, query, limit=10, retries=2):
        db = get_db()
        r = _fetch(self.name, "https://www.googleapis.com/customsearch/v1",
                   params={"key": db.get_secret("google_cse_key"), "cx": db.get_secret("google_cse_cx"),
                           "q": query, "num": max(1, min(limit, 10))}, retries=retries)
        err = self._classify(r)
        if err:
            raise err
        data = _json(self.name, r)
        items = data.get("items", [])  # absent when there are zero results
        if not isinstance(items, list):
            raise ProviderError(INVALID_RESPONSE, "Google response has a malformed items list")
        out = []
        for i in items[:limit]:
            if not isinstance(i, dict):
                continue
            tags = (i.get("pagemap") or {}).get("metatags") if isinstance(i.get("pagemap"), dict) else None
            meta = tags[0] if isinstance(tags, list) and tags and isinstance(tags[0], dict) else {}
            published = next((meta.get(k) for k in ("article:published_time", "datePublished", "date") if meta.get(k)), "")
            out.append(SearchResult(_text(i.get("title")), _text(i.get("link")), _text(i.get("snippet")), self.name,
                                    query, published_at=str(published)))
        return out


class SearXNG(SearchProvider):
    name = "SearXNG"
    requires_key = True  # needs explicit configuration (instance URL), never used implicitly
    secret_keys = ("searxng_url",)
    denied_is_credentials = False

    def configured(self):
        return bool(get_db().get_secret("searxng_url"))

    def search(self, query, limit=10, retries=2):
        base, problem = validate_searxng_url(get_db().get_secret("searxng_url"))
        if problem:
            raise ProviderError(INVALID_CONFIG, f"SearXNG: {problem}")
        r = _fetch(self.name, base + "/search", params={"q": query, "format": "json"}, retries=retries)
        code = r.status_code
        if code in (401, 403):
            raise ProviderError(ACCESS_DENIED, f"SearXNG denied access (HTTP {code}): JSON output may be disabled "
                                               "(search.formats) or the bot limiter blocked this client.")
        if code == 429:
            raise ProviderError(RATE_LIMIT, "SearXNG rate limit reached (HTTP 429).")
        generic = _generic_status_error("SearXNG", code)
        if generic:
            raise generic
        data = _json(self.name, r)
        results = data.get("results")
        if not isinstance(results, list):
            raise ProviderError(INVALID_RESPONSE, "SearXNG response is missing the results list")
        return [SearchResult(_text(i.get("title")), _text(i.get("url")), _text(i.get("content")), self.name, query,
                             published_at=str(i.get("publishedDate", "") or ""))
                for i in results[:limit] if isinstance(i, dict)]


ALL_PROVIDERS: list[SearchProvider] = [BraveSearch(), GoogleCSE(), SearXNG(), DuckDuckGoHTML()]
