"""Public name-search query planning through TRACEPOINT's configured providers."""
from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import urlparse

from core import search_engine
from providers.search_providers import SearchResult
from modules.name_matching import alternate_spellings


@dataclass(frozen=True)
class NameQuery:
    query: str
    category: str


def build_queries(name: str, context: str = "") -> list[NameQuery]:
    full = " ".join(name.split())
    quoted = f'"{full}"'
    ctx = " ".join(context.split())
    queries = [NameQuery(quoted, "exact_name")]
    if ctx:
        queries.append(NameQuery(f'{quoted} "{ctx}"', "contextual"))
    queries.extend([
        NameQuery(f'{quoted} biography', "professional_biography"),
        NameQuery(f'{quoted} company', "organization"),
        NameQuery(f'{quoted} news', "news"),
        NameQuery(f'{quoted} site:gov', "institutional"),
    ])
    for variant in alternate_spellings(full):
        queries.append(NameQuery(f'"{variant}"', "alternate_spelling"))
    # Search result count is bounded to reduce collection and provider load.
    return queries[:10]


def valid_result(row: object) -> bool:
    if not isinstance(row, SearchResult):
        return False
    try:
        parsed = urlparse(row.url)
        text = f"{row.title} {row.snippet} {row.url}"
        if re.search(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", text):
            return False
        if re.search(r"(?<!\w)\+?\d[\d ().-]{5,}\d(?!\w)", text):
            return False
        if re.search(r"\b\d{1,6}\s+(?:[\w.-]+\s+){0,4}(?:street|st|road|rd|avenue|ave|boulevard|blvd|drive|dr|lane|ln|court|ct)\b", text, re.I):
            return False
        if re.search(r"\b(?:spouse|wife|husband|daughter|son|children|mother|father|sibling|brother|sister)\b", text, re.I):
            return False
        if re.search(r"\b(?:medical diagnosis|health condition|sexual orientation|religious affiliation|political affiliation|disability status)\b", text, re.I):
            return False
        return parsed.scheme in {"http", "https"} and bool(parsed.hostname) and bool(row.title or row.snippet)
    except (TypeError, ValueError):
        return False


def search_name(name: str, context: str = "", *, limit: int = 6, result=None) -> list[tuple[str, SearchResult]]:
    """Search bounded query variants with existing configured providers.

    This sends only search API requests through the shared search engine; it does
    not fetch result pages or bypass site access controls.
    """
    configured = search_engine.active_providers()
    if not any(getattr(p, "requires_key", False) for p in configured):
        if result is not None:
            result.source("Configured public web search", "", "not_configured",
                          "Configure Brave Search, Google Programmable Search, or SearXNG in API Configuration.")
        return []
    found: dict[str, tuple[str, SearchResult]] = {}
    for spec in build_queries(name, context):
        try:
            rows = search_engine.search(spec.query, limit=limit, result=result)
        except Exception as exc:  # one unavailable provider/query does not abort later queries
            if result is not None:
                result.errors.append(f"Name search query failed ({spec.category}): {type(exc).__name__}: {exc}")
            continue
        for row in rows:
            if not valid_result(row):
                if result is not None:
                    result.notes.append("Skipped an invalid result or one whose metadata may contain private/sensitive personal information.")
                continue
            # search_engine normally de-duplicates across providers. A source may
            # recur across planned queries; retain its first query association.
            key = search_engine.normalize_url(row.url)
            found.setdefault(key, (spec.category, row))
    return list(found.values())
