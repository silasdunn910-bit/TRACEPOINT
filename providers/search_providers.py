"""Web search providers behind one interface.

Free, no key:   DuckDuckGo HTML endpoint (best-effort; may rate-limit automated use)
Optional keys:  Brave Search API, Google Programmable Search, self-hosted SearXNG

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
    pass


class SearchProvider:
    name = "base"
    requires_key = False

    def configured(self) -> bool:
        return True

    def search(self, query: str, limit: int = 10) -> list[SearchResult]:
        raise NotImplementedError


def _strip_tags(s: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", s or "")).strip()


class DuckDuckGoHTML(SearchProvider):
    name = "DuckDuckGo (HTML)"
    _a = re.compile(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', re.S)
    _snip = re.compile(r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', re.S)

    def search(self, query, limit=10):
        r = http.request("POST", "https://html.duckduckgo.com/html/", data={"q": query, "kl": "us-en"},
                         headers={"Referer": "https://html.duckduckgo.com/"})
        text = r.text
        if r.status_code != 200 or ("anomaly" in text[:5000].lower() and "result__a" not in text):
            raise ProviderUnavailable(f"DuckDuckGo refused the automated request (HTTP {r.status_code}). "
                                      "Configure Brave/Google/SearXNG for reliable search.")
        if "result__a" not in text:
            raise ProviderUnavailable("DuckDuckGo returned a page with no results (possible block/challenge). "
                                      "Configure Brave/Google/SearXNG for reliable search.")
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

    def configured(self):
        return bool(get_db().get_secret("brave_search_key"))

    def search(self, query, limit=10):
        key = get_db().get_secret("brave_search_key")
        r = http.get("https://api.search.brave.com/res/v1/web/search", params={"q": query, "count": min(limit, 20)},
                     headers={"X-Subscription-Token": key, "Accept": "application/json"})
        if r.status_code in (401, 403):
            raise ProviderUnavailable("Brave rejected the API key.")
        if r.status_code == 429:
            raise ProviderUnavailable("Brave rate limit reached.")
        if r.status_code >= 400:
            raise ProviderUnavailable(f"Brave returned HTTP {r.status_code}")
        items = (r.json().get("web") or {}).get("results", [])
        return [SearchResult(_strip_tags(i.get("title", "")), i.get("url", ""), _strip_tags(i.get("description", "")),
                             self.name, query) for i in items[:limit]]


class GoogleCSE(SearchProvider):
    name = "Google Programmable Search"
    requires_key = True

    def configured(self):
        db = get_db()
        return bool(db.get_secret("google_cse_key") and db.get_secret("google_cse_cx"))

    def search(self, query, limit=10):
        db = get_db()
        r = http.get("https://www.googleapis.com/customsearch/v1",
                     params={"key": db.get_secret("google_cse_key"), "cx": db.get_secret("google_cse_cx"),
                             "q": query, "num": min(limit, 10)})
        if r.status_code >= 400:
            raise ProviderUnavailable(f"Google CSE returned HTTP {r.status_code}")
        out = []
        for i in r.json().get("items", [])[:limit]:
            tags = (i.get("pagemap") or {}).get("metatags") or [{}]
            meta = tags[0] if tags else {}
            published = next((meta.get(k) for k in ("article:published_time", "datePublished", "date") if meta.get(k)), "")
            out.append(SearchResult(i.get("title", ""), i.get("link", ""), i.get("snippet", ""), self.name, query,
                                    published_at=str(published)))
        return out


class SearXNG(SearchProvider):
    name = "SearXNG"
    requires_key = True

    def configured(self):
        return bool(get_db().get_secret("searxng_url"))

    def search(self, query, limit=10):
        base = get_db().get_secret("searxng_url").rstrip("/")
        r = http.get(base + "/search", params={"q": query, "format": "json"})
        if r.status_code >= 400:
            raise ProviderUnavailable(f"SearXNG returned HTTP {r.status_code} (is JSON output enabled?)")
        return [SearchResult(i.get("title", ""), i.get("url", ""), i.get("content", ""), self.name, query,
                             published_at=str(i.get("publishedDate", "") or ""))
                for i in r.json().get("results", [])[:limit]]


ALL_PROVIDERS: list[SearchProvider] = [BraveSearch(), GoogleCSE(), SearXNG(), DuckDuckGoHTML()]
