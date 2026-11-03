"""Centralized source registry: one deduplicated record per source of an investigation.

A record is keyed by (provider, normalized URL), so a provider queried several times, or the same page reached by
several findings, is one source. `consulted` is True ONLY when the application recorded a successful retrieval
(status 'ok'). A URL that merely appears in a finding (e.g. a search hit) is 'cited': TRACEPOINT saw a pointer to it,
it did not retrieve it, and it is never reported as consulted.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

_TRACKING = ("utm_", "fbclid", "gclid", "ref=")
_HTTP_RE = re.compile(r"\bHTTP\s*(\d{3})\b", re.I)
_WS = re.compile(r"\s+")
RELIABILITY = {  # by source tier (core.intelligence.evidence_analyzer.SOURCE_TIERS); fixed rules, not per-case accuracy
    "official government / court source": "HIGH", "authoritative registry / primary data": "HIGH",
    "operator-reviewed record": "MODERATE", "third-party intelligence service": "MODERATE",
    "search-engine index": "LOW", "local deterministic check": "NOT APPLICABLE",
    "derived comparison (analysis, not observation)": "NOT APPLICABLE", "unclassified source": "UNASSESSED",
}


def normalize_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return ""
    try:
        p = urlparse(u)
        port = p.port
    except ValueError:
        return u
    if p.scheme.lower() not in ("http", "https") or not p.hostname:
        return u                       # kept verbatim; never "fixed"
    query = "&".join(q for q in p.query.split("&") if q and not q.lower().startswith(_TRACKING))
    host = p.hostname.lower().removeprefix("www.") + (f":{port}" if port else "")
    return urlunparse((p.scheme.lower(), host, p.path.rstrip("/") or "/", "", query, ""))


def source_key(provider: str, url: str) -> str:
    return _WS.sub(" ", (provider or "").strip().lower()) + "|" + normalize_url(url)


def build(sources: list[dict], findings: list[dict]) -> list[dict]:
    """sources: stored source rows; findings: stored finding rows. -> deduplicated registry records."""
    from core.intelligence.evidence_analyzer import classify_source   # late import: package imports core.reports
    recs: dict[str, dict] = {}

    def get(provider: str, url: str, category: str = "") -> dict:
        key = source_key(provider, url)
        if key not in recs:
            tier, _ = classify_source(provider, url, category)
            recs[key] = {"source_key": key, "provider": provider or "(unnamed source)", "url": url or "",
                         "category": tier, "retrieved_at": "", "status": "", "http_status": "", "consulted": False,
                         "reliability": RELIABILITY.get(tier, "UNASSESSED"), "finding_count": 0, "_fids": [],
                         "_statuses": []}
        return recs[key]

    for s in sources:
        r = get(s.get("name") or "", s.get("url") or "")
        r["_statuses"].append(s.get("status") or "")
        if s.get("consulted_at") and s["consulted_at"] > r["retrieved_at"]:
            r["retrieved_at"] = s["consulted_at"]
    for f in findings:
        r = get(f.get("source") or "", f.get("source_url") or "", f.get("category", ""))
        r["_fids"].append(f.get("id"))
        r["finding_count"] += 1
        if not r["_statuses"] and f.get("discovered_at") and f["discovered_at"] > r["retrieved_at"]:
            r["retrieved_at"] = f["discovered_at"]

    out = []
    for r in recs.values():
        sts = [s for s in r.pop("_statuses") if s]
        fids = [str(i) for i in r.pop("_fids") if i is not None]
        if not sts:
            r["status"] = "cited"            # only referenced by findings: pointer seen, nothing retrieved from it
        elif all(s == sts[0] for s in sts):
            r["status"] = sts[0]
        else:
            r["status"] = "partial"          # mixed outcomes across repeated queries; never summarised as ok
        r["consulted"] = any(s == "ok" for s in sts)
        r["finding_ids"] = ",".join(dict.fromkeys(fids))
        out.append(r)
    return out


def attach_http_status(records: list[dict], sources: list[dict]) -> None:
    """Best-effort: the last 'HTTP nnn' a source's detail mentions (modules record failures that way)."""
    by_key = {}
    for s in sources:
        m = _HTTP_RE.search(s.get("detail") or "")
        if m:
            by_key[source_key(s.get("name") or "", s.get("url") or "")] = m.group(1)
    for r in records:
        r["http_status"] = by_key.get(r["source_key"], "")


def refresh(inv_id: int, db=None) -> list[dict]:
    """Rebuild and store the registry for a stored investigation."""
    from core.database import get_db
    db = db or get_db()
    sources = [dict(s) for s in db.sources(inv_id)]
    findings = [dict(f) for f in db.findings(inv_id)]
    recs = build(sources, findings)
    attach_http_status(recs, sources)
    db.replace_source_registry(inv_id, recs)
    return recs
