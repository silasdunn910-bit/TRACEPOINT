"""Search intelligence: SearXNG, Brave and Google (wrapping the existing search providers), GDELT,
Internet Archive and Wikipedia."""
from __future__ import annotations

import time
from urllib.parse import quote

from . import base
from .base import (AUTH_FAILED, ERROR, FREE, FREE_TIER, InputError, Provider, ResponseError, UnavailableError,
                   clean_text)

_QUERY = {"query": "Free-text web search"}


class _LegacySearch(Provider):
    """Adapter over an existing providers.search_providers.SearchProvider so the old (working) code is
    reused, not duplicated, and these engines appear in the same status dashboard."""
    legacy_index = 0
    category = "Search"
    lookups = _QUERY

    @property
    def _legacy(self):
        from providers.search_providers import ALL_PROVIDERS
        return next(p for p in ALL_PROVIDERS if p.__class__.__name__ == self.legacy_class)

    def missing(self):
        return [k for k in self.secret_keys if not self.secret(k)]

    def _probe(self):
        from providers import search_providers as sp
        res = self._legacy.test_connection()
        if res.status == sp.ST_CONNECTED:
            return res.detail
        if res.status == sp.ST_INVALID:
            raise base.AuthError(res.detail)
        if res.status == sp.ST_RATE_LIMITED:
            raise base.RateLimitError(res.detail)
        if res.kind == sp.INVALID_RESPONSE:
            raise ResponseError(res.detail)
        raise UnavailableError(res.detail)

    def lookup(self, kind, value, limit: int = 10, **kw):
        from providers.search_providers import ProviderError, ProviderUnavailable
        self._check_kind(kind)
        q = clean_text(value)
        self.require()
        try:
            rows = self._legacy.search(q, max(1, min(limit, 20)))
        except ProviderError as e:
            from providers import search_providers as sp
            cls = {sp.INVALID_KEY: base.AuthError, sp.INVALID_CONFIG: base.AuthError, sp.ACCESS_DENIED: base.AuthError,
                   sp.RATE_LIMIT: base.RateLimitError, sp.QUOTA: base.RateLimitError,
                   sp.INVALID_RESPONSE: ResponseError}.get(e.kind, UnavailableError)
            raise cls(str(e)) from None
        except ProviderUnavailable as e:
            raise UnavailableError(str(e)) from None
        return self._result(q, rows[0].url if rows else self.endpoint, "search_results",
                            {"results": [{"title": r.title, "url": r.url, "snippet": r.snippet,
                                          "published_at": r.published_at, "retrieved_at": r.discovered_at}
                                         for r in rows]},
                            limitations=["A search hit shows a page was indexed for the query, not that it concerns "
                                         "the person or entity you are researching."])


class Brave(_LegacySearch):
    id = "brave"; name = "Brave Search API"; legacy_class = "BraveSearch"
    tier = FREE_TIER; auth = "X-Subscription-Token header"
    free_info = "Free plan with a small monthly query allowance (check your Brave dashboard for the current figure)."
    signup_url = "https://brave.com/search/api/"; docs_url = "https://api-dashboard.search.brave.com/app/documentation"
    endpoint = "https://api.search.brave.com/res/v1/web/search"
    secret_keys = ("brave_search_key",)


class GoogleCSE(_LegacySearch):
    id = "google_cse"; name = "Google Programmable Search"; legacy_class = "GoogleCSE"
    tier = FREE_TIER; auth = "API key + engine ID (cx) as query parameters"
    free_info = "100 queries/day free; paid above that (do not enable billing to use TRACEPOINT)."
    signup_url = "https://developers.google.com/custom-search/v1/overview"
    docs_url = "https://developers.google.com/custom-search/v1/reference/rest/v1/cse/list"
    endpoint = "https://www.googleapis.com/customsearch/v1"
    secret_keys = ("google_cse_key", "google_cse_cx")
    limitations = ("The engine ID (cx) alone only powers an embedded search box; the JSON API also needs an API key.",)


class SearXNG(_LegacySearch):
    id = "searxng"; name = "SearXNG"; legacy_class = "SearXNG"
    tier = FREE; auth = "none (your own instance URL)"
    free_info = "Free and open source; you host it. No quota except what your instance's upstream engines impose."
    signup_url = "https://docs.searxng.org/admin/installation.html"
    docs_url = "https://docs.searxng.org/dev/search_api.html"
    endpoint = "<your instance>/search?format=json"
    secret_keys = ("searxng_url",)
    limitations = ("Requires a running instance with `json` enabled under search.formats in settings.yml.",)


class GDELT(Provider):
    id = "gdelt"; name = "GDELT"; category = "Search"; tier = FREE
    free_info = "Free, no key. Asks for roughly one request per 5 seconds; TRACEPOINT enforces that."
    signup_url = "https://www.gdeltproject.org/"; docs_url = "https://blog.gdeltproject.org/gdelt-doc-2-0-api-debuts/"
    endpoint = "https://api.gdeltproject.org/api/v2/doc/doc"
    lookups = {"query": "News articles (last 3 months) matching a phrase"}
    limitations = ("News coverage only; an article mentioning a name is not evidence about a specific person.",
                   "Machine-translated and machine-tagged metadata may be wrong.")
    min_interval = 5.0; timeout = 30

    def _fetch(self, q, n):
        r = self.get(self.endpoint, params={"query": q, "mode": "artlist", "format": "json", "maxrecords": n,
                                            "sort": "datedesc"})
        text = r.text.strip()
        if not text:
            return []
        try:
            d = r.json()
        except ValueError:
            # GDELT answers plain text for bad queries ("phrase too short") and some overloads
            raise ResponseError(f"GDELT did not return JSON: {text[:120]!r}") from None
        if not isinstance(d, dict):
            raise ResponseError("GDELT returned an unexpected JSON structure.")
        arts = d.get("articles", [])
        if not isinstance(arts, list):
            raise ResponseError("GDELT response has a malformed articles list.")
        return arts

    def _probe(self):
        try:
            arts = self._fetch("climate", 1)
        except base.RateLimitError:  # GDELT allows ~1 request per 5 s per client: wait once, then report honestly
            time.sleep(self.min_interval + 1)
            arts = self._fetch("climate", 1)
        if not arts:  # GDELT also answers an empty body when overloaded; a common word must have hits
            raise ResponseError("GDELT returned an empty answer to a query that should have results.")
        return f"Test query answered ({len(arts)} article)."

    def lookup(self, kind, value, limit: int = 20, **kw):
        self._check_kind(kind)
        q = clean_text(value)
        arts = self._fetch(q, max(1, min(limit, 75)))
        rows = [{"title": a.get("title"), "url": a.get("url"), "domain": a.get("domain"), "seen": a.get("seendate"),
                 "language": a.get("language"), "country": a.get("sourcecountry")} for a in arts if isinstance(a, dict)]
        return self._result(q, f"{self.endpoint}?query={quote(q)}&mode=artlist", "news_articles",
                            {"articles": rows, "raw": arts})


class InternetArchive(Provider):
    id = "internet_archive"; name = "Internet Archive"; category = "Search"; tier = FREE
    free_info = "Free, no key; no published hard quota, be polite."
    signup_url = "https://archive.org/developers/"; docs_url = "https://archive.org/developers/"
    endpoint = "https://archive.org/advancedsearch.php"
    lookups = {"query": "Search archived items (books, media, web collections)"}
    limitations = ("Searches Archive items, not live pages; use the Wayback Machine adapter for page snapshots.",)

    def _search(self, q, n):
        r = self.get(self.endpoint, params={"q": q, "fl[]": ["identifier", "title", "mediatype", "date", "creator"],
                                            "rows": n, "output": "json"})
        d = self.json(r, dict)
        docs = (d.get("response") or {}).get("docs") if isinstance(d.get("response"), dict) else None
        if not isinstance(docs, list):
            raise ResponseError("Internet Archive response is missing response.docs.")
        return docs

    def _probe(self):
        return f"Test search answered ({len(self._search('tracepoint', 1))} item)."

    def lookup(self, kind, value, limit: int = 20, **kw):
        self._check_kind(kind)
        q = clean_text(value)
        docs = self._search(q, max(1, min(limit, 100)))
        rows = [{"identifier": d.get("identifier"), "title": d.get("title"), "mediatype": d.get("mediatype"),
                 "date": d.get("date"), "creator": d.get("creator"),
                 "url": f"https://archive.org/details/{d.get('identifier')}"} for d in docs if isinstance(d, dict)]
        return self._result(q, f"https://archive.org/search?query={quote(q)}", "archive_items",
                            {"items": rows, "raw": docs})


class Wikipedia(Provider):
    id = "wikipedia"; name = "Wikipedia (MediaWiki API)"; category = "Search"; tier = FREE
    free_info = "Free, no key. Keep to serial requests and send a descriptive User-Agent (TRACEPOINT does)."
    signup_url = "https://www.mediawiki.org/wiki/API:Main_page"; docs_url = "https://www.mediawiki.org/wiki/API:Search"
    endpoint = "https://en.wikipedia.org/w/api.php"
    lookups = {"query": "Search English Wikipedia articles"}
    limitations = ("Wikipedia is a tertiary, user-edited source; treat statements as leads, not verified facts.",)

    def _search(self, q, n):
        r = self.get(self.endpoint, params={"action": "query", "list": "search", "srsearch": q, "srlimit": n,
                                            "format": "json", "formatversion": 2})
        d = self.json(r, dict)
        if "error" in d:
            raise ResponseError(f"Wikipedia API error: {str((d['error'] or {}).get('code', 'unknown'))[:60]}")
        rows = (d.get("query") or {}).get("search") if isinstance(d.get("query"), dict) else None
        if not isinstance(rows, list):
            raise ResponseError("Wikipedia response is missing query.search.")
        return rows

    def _probe(self):
        return f"Test search answered ({len(self._search('Python', 1))} page)."

    def lookup(self, kind, value, limit: int = 10, **kw):
        self._check_kind(kind)
        q = clean_text(value)
        rows = self._search(q, max(1, min(limit, 50)))
        out = [{"title": x.get("title"), "pageid": x.get("pageid"), "snippet": x.get("snippet"),
                "timestamp": x.get("timestamp"),
                "url": "https://en.wikipedia.org/wiki/" + quote(str(x.get("title", "")).replace(" ", "_"))}
               for x in rows if isinstance(x, dict)]
        return self._result(q, f"https://en.wikipedia.org/w/index.php?search={quote(q)}", "encyclopedia_articles",
                            {"pages": out, "raw": rows})


PROVIDERS = [SearXNG, Brave, GoogleCSE, GDELT, InternetArchive, Wikipedia]
