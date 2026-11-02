"""Central search service reused by every module.

Queries every configured provider, normalizes and de-duplicates results,
preserves original URLs and timestamps, and records provider failures as
source records instead of crashing.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, urlunparse

from core.database import get_db
from core.http import HttpError
from core.models import LOW, UNVERIFIED, Finding, ModuleResult
from providers.search_providers import (ALL_PROVIDERS, ST_CONFIGURED, ConnectionResult, ProviderUnavailable,
                                        SearchResult)

_TRACKING = ("utm_", "fbclid", "gclid", "ref=")


def normalize_url(url: str) -> str:
    p = urlparse(url.strip())
    query = "&".join(q for q in p.query.split("&") if q and not q.lower().startswith(_TRACKING))
    path = p.path.rstrip("/") or "/"
    return urlunparse((p.scheme.lower() or "https", p.netloc.lower().removeprefix("www."), path, "", query, ""))


def active_providers() -> list:
    return [p for p in ALL_PROVIDERS if p.configured()]


class SearchResults(list):
    """List of SearchResult plus how the search actually went.

    completed      True only if at least one provider answered successfully. An empty list with
                   completed=True is a genuine "zero results"; completed=False means the search never ran.
    attempts       one dict per provider tried: name, ok, kind, error, count
    fallback_used  True if DuckDuckGo was used because every configured provider failed
    """
    completed: bool = True
    fallback_used: bool = False

    def __init__(self, rows=(), completed=True, attempts=None, fallback_used=False):
        super().__init__(rows)
        self.completed = completed
        self.attempts = attempts or []
        self.fallback_used = fallback_used


def _run(providers, query, limit):
    def one(p):
        try:
            return p, p.search(query, limit), "", ""
        except ProviderUnavailable as e:
            return p, [], getattr(e, "kind", "UNAVAILABLE"), str(e)
        except HttpError as e:
            return p, [], "UNAVAILABLE", str(e)
        except Exception as e:  # provider parsing bug must not kill the investigation
            return p, [], "INVALID_RESPONSE", f"{p.name}: unexpected {type(e).__name__}"

    with ThreadPoolExecutor(max_workers=4) as ex:
        return list(ex.map(one, providers))


def search(query: str, limit: int = 10, result: ModuleResult | None = None) -> SearchResults:
    """Run a query. Order: configured keyed providers; only if ALL of them fail, DuckDuckGo as an explicit,
    labelled fallback. With no keyed provider configured, DuckDuckGo is the default. Provider status is
    written into `result.sources`; every result keeps the name of the provider that returned it."""
    providers = active_providers()
    keyed = [p for p in providers if p.requires_key]
    free = [p for p in providers if not p.requires_key]
    primary, fallback = (keyed, free) if keyed else (free, [])
    merged: dict[str, SearchResult] = {}
    attempts: list[dict] = []

    def process(outcomes, note=""):
        ok_any = False
        for p, rows, kind, err in outcomes:
            ok = not err
            ok_any = ok_any or ok
            attempts.append({"name": p.name, "ok": ok, "kind": kind, "error": err, "count": len(rows)})
            if result is not None:
                if ok:
                    result.source(p.name, "", "ok", f"query: {query} ({len(rows)} results){note}")
                else:
                    result.source(p.name, "", "error", f"[{kind}] {err}{note}")
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
        return ok_any

    completed = process(_run(primary, query, limit)) if primary else False
    fallback_used = False
    if not completed and fallback:
        fallback_used = True
        completed = process(_run(fallback, query, limit), " [fallback: all configured providers failed]")
    if not completed and result is not None:
        result.errors.append(f"Web search did not run successfully for {query!r}: no provider answered. "
                             "This is not a 'no results' outcome.")
    return SearchResults(merged.values(), completed, attempts, fallback_used)


# --- credential / connection status ------------------------------------------
_CONN_PREFIX = "conn:"


def _slug(p) -> str:
    return _CONN_PREFIX + p.name


def check_provider(p) -> ConnectionResult:
    """Run one live connection test and persist the outcome (never stores credentials)."""
    res = p.test_connection()
    get_db().set_setting(_slug(p), json.dumps({"status": res.status, "detail": res.detail, "kind": res.kind,
                                               "tested_at": res.tested_at}))
    return res


def clear_test_results(secret_key: str) -> None:
    """Forget stored connection results for providers that use this credential (it changed or was removed)."""
    for p in ALL_PROVIDERS:
        if secret_key in getattr(p, "secret_keys", ()):
            get_db().set_setting(_slug(p), "")


def provider_status(p) -> tuple[str, str]:
    """(status, detail). CONNECTED/INVALID/... only if a test ran after the credentials were last saved;
    otherwise CONFIGURED (stored but untested). Unconfigured providers return ('NOT SET', '')."""
    if not p.configured():
        return "NOT SET", ""
    db = get_db()
    raw = db.get_setting(_slug(p), "")
    if not raw:
        return ST_CONFIGURED, "stored, not tested"
    try:
        d = json.loads(raw)
        tested = str(d["tested_at"])
        status = str(d["status"])
    except (ValueError, KeyError, TypeError):
        return ST_CONFIGURED, "stored, not tested"
    names = db.secret_names()
    newest = max((names.get(k, "") for k in p.secret_keys), default="")
    if newest and tested < newest:
        return ST_CONFIGURED, "credentials changed since last test"
    return status, f"{d.get('detail', '')} (tested {tested})"


def note_zero_results(hits, result: ModuleResult, what: str) -> None:
    """Record a successfully completed search that found nothing. A search that never ran is already recorded
    as an error by search(), so no 'no results' note is written for it."""
    if getattr(hits, "completed", True) and not hits:
        result.notes.append(f"Search for {what} completed with zero results; this does not show that no public "
                            "references exist.")


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
