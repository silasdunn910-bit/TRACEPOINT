"""Central search service reused by every module.

Queries every configured provider, normalizes and de-duplicates results,
preserves original URLs and timestamps, and records provider failures as
source records instead of crashing.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlunparse

from core.http import HttpError
from core.models import LOW, UNVERIFIED, Finding, ModuleResult
from providers.search_providers import ALL_PROVIDERS, ProviderUnavailable, SearchResult

_TRACKING = ("utm_", "fbclid", "gclid", "ref=")


def normalize_url(url: str) -> str:
    p = urlparse(url.strip())
    query = "&".join(q for q in p.query.split("&") if q and not q.lower().startswith(_TRACKING))
    path = p.path.rstrip("/") or "/"
    return urlunparse((p.scheme.lower() or "https", p.netloc.lower().removeprefix("www."), path, "", query, ""))


def active_providers() -> list:
    return [p for p in ALL_PROVIDERS if p.configured()]


def search(query: str, limit: int = 10, result: ModuleResult | None = None) -> list[SearchResult]:
    """Run a query across all configured providers. Provider status is written into `result.sources`."""
    providers = active_providers()
    # DuckDuckGo is the free fallback: only use it when no keyed provider is configured
    keyed = [p for p in providers if p.requires_key]
    if keyed:
        providers = keyed
    merged: dict[str, SearchResult] = {}

    def run(p):
        try:
            return p, p.search(query, limit), None
        except (ProviderUnavailable, HttpError) as e:
            return p, [], str(e)
        except Exception as e:  # provider parsing bug must not kill the investigation
            return p, [], f"{type(e).__name__}: {e}"

    with ThreadPoolExecutor(max_workers=4) as ex:
        for p, rows, err in ex.map(run, providers):
            if result is not None:
                result.source(p.name, "", "error" if err else "ok", err or f'query: {query} ({len(rows)} results)')
                if err:
                    result.errors.append(f"{p.name}: {err}")
            for r in rows:
                if not isinstance(r, SearchResult):
                    if result is not None:
                        result.notes.append(f"Skipped invalid result from {p.name}.")
                    continue
                try:
                    parsed = urlparse(r.url)
                except (TypeError, ValueError):
                    parsed = None
                if not parsed or parsed.scheme not in ("http", "https") or not parsed.hostname:
                    if result is not None:
                        result.notes.append(f"Skipped non-public or invalid URL from {p.name}.")
                    continue
                key = normalize_url(r.url)
                if key in merged:
                    if p.name not in merged[key].provider:
                        merged[key].provider += f", {p.name}"
                else:
                    merged[key] = r
    return list(merged.values())


def results_to_findings(results: list[SearchResult], result: ModuleResult, *, category: str, exact_term: str,
                        what: str) -> int:
    """Turn search hits into findings. A hit is LOW only if the exact term appears in the title/snippet,
    otherwise UNVERIFIED. Search hits are never VERIFIED."""
    n = 0
    term = exact_term.lower()
    for r in results:
        text = f"{r.title} {r.snippet}".lower()
        contains = term in text
        result.add(Finding(
            title=r.title[:160] or r.url,
            description=f"Publicly indexed page returned for {what}.",
            value=r.url, source=r.provider, source_url=r.url, category=category,
            confidence=LOW if contains else UNVERIFIED,
            evidence=(r.snippet[:400] or "(no snippet)") + (f"\n[exact term appears in result text]" if contains else
                                                           "\n[exact term NOT visible in title/snippet]"),
            limitations="A search engine result only shows that a page was indexed for this query. It does not "
                        "establish that the page is about the same person or entity. Open and review the source.",
            discovered_at=r.discovered_at))
        n += 1
    return n
