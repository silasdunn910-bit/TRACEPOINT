"""Turns the stored findings of one investigation into an evidence registry and analyses it.

Input is the dict produced by core.reports.build() (the single collection path for every report format), so
stored data, legacy-grade normalization and core.correlation's contradiction rules are reused, not duplicated.

Rules, in short:
* Every finding becomes one EvidenceItem with its provenance copied verbatim. Missing metadata is listed as a
  gap and never filled in.
* Corroboration requires >= 2 distinct origins (URL host, or source name when there is no URL) AND >= 2 distinct
  source names. The same page reached via two search engines is one origin, not two.
* The engine never raises a stored grade. UNVERIFIED / INCONCLUSIVE findings stay unverified even if repeated:
  the collecting module chose that grade deliberately (e.g. name matches).
* An inference is kept only if it lists the evidence it rests on and passes templates.guard().
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from urllib.parse import urlparse

from core.models import CORROBORATED, INCONCLUSIVE, LOW, MODERATE, UNVERIFIED, VERIFIED, normalize_confidence

from core.source_registry import RELIABILITY, source_key

from . import templates as T
from .models import (ANALYTICAL_INFERENCE, CONTRADICTORY, CORROBORATED_CLAIM, SINGLE_SOURCE_CLAIM, UNVERIFIED_CLAIM,
                     VERIFIED_FACT, ClaimGroup, Discrepancy, EvidenceItem, Inference, SourceRef)

# --- source-type tiers ---------------------------------------------------------------------------------------------
TIER_OPERATOR = "operator-reviewed record"
TIER_PRIMARY = "authoritative registry / primary data"
TIER_GOV = "official government / court source"
TIER_LOCAL = "local deterministic check"
TIER_DERIVED = "derived comparison (analysis, not observation)"
TIER_THIRD = "third-party intelligence service"
TIER_SEARCH = "search-engine index"
TIER_UNKNOWN = "unclassified source"
SOURCE_TIERS = (TIER_OPERATOR, TIER_GOV, TIER_PRIMARY, TIER_LOCAL, TIER_THIRD, TIER_SEARCH, TIER_DERIVED, TIER_UNKNOWN)

_DERIVED_NAMES = ("analyst comparison", "cross-provider comparison")
# AI output is analysis of collected evidence. It is never an observation and never independent corroboration.
_AI_NAMES = ("ai analys", "ai summary", "local model", "ollama", "llm", "language model")
_SEARCH_CAP_GRADES = (VERIFIED, CORROBORATED, MODERATE)   # a search result alone can support at most LOW
_PRIMARY_KEYS = ("rdap", "public dns", "crt.sh", "certificate transparency")
_SEARCH_KEYS = ("brave", "google", "searxng", "duckduckgo", "bing", "web search", "search engine")
_THIRD_KEYS = ("virustotal", "abuseipdb", "ipinfo", "ipdata", "ip-api", "otx", "alienvault", "urlscan", "abuse.ch",
               "threatfox", "urlhaus", "hibp", "have i been pwned", "gravatar", "wayback", "internet archive",
               "courtlistener", "opencorporates", "ip-db", "openipapi", "shodan", "greynoise")
_ANALYTICAL_CATEGORIES = {"comparison", "independently_corroborated"}
_HTTP_RE = re.compile(r"\bHTTP\s*(\d{3})\b", re.I)
_TRIVIAL_VALUES = {"", "none", "n/a", "na", "unknown", "0", "-", "?", "true", "false", "yes", "no"}


def host_of(url: str) -> str:
    try:
        h = (urlparse(url).hostname or "").lower()
    except (TypeError, ValueError):
        return ""
    return h[4:] if h.startswith("www.") else h


def classify_source(name: str, url: str = "", category: str = "") -> tuple[str, str]:
    """-> (tier, basis). Fixed rules over the source name / URL; describes the KIND of source only."""
    n, h = (name or "").lower(), host_of(url)
    if category.endswith("_manual"):
        return TIER_OPERATOR, "entered by the operator from an official portal after manual review"
    if any(k in n for k in _DERIVED_NAMES + _AI_NAMES):
        return TIER_DERIVED, "the source is a comparison performed by TRACEPOINT"
    if n.startswith("local") or "local validation" in n:
        return TIER_LOCAL, "computed locally without a network source"
    if h.endswith((".gov", ".mil")) or ".gov." in h or "uscourts" in h or "nsopw" in n or "nsopw" in h:
        return TIER_GOV, f"official government domain ({h or n})"
    if category.startswith(("court", "registry")):
        return TIER_GOV, "official court / registry source recorded by the records module"
    if any(k in n for k in _PRIMARY_KEYS) or "rdap" in h or h == "crt.sh":
        return TIER_PRIMARY, "registry or protocol-level data (RDAP / DNS / CT logs)"
    if any(k in n for k in _SEARCH_KEYS):
        return TIER_SEARCH, "a search engine's index: shows a page was indexed, not that its content is accurate"
    if any(k in n for k in _THIRD_KEYS) or any(k.replace(" ", "") in h for k in _THIRD_KEYS):
        return TIER_THIRD, "third-party service reporting its own observations or opinions"
    return TIER_UNKNOWN, "no rule matched this source name"


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower()).rstrip(".")


def origin_of(source: str, url: str) -> str:
    return host_of(url) or _norm(source) or "(unnamed source)"


def claim_key(f: dict) -> str:
    v = _norm(f.get("value", ""))
    if v and v not in _TRIVIAL_VALUES:
        return f"{f['category']}|v:{v}"
    return f"{f['category']}|t:{_norm(f['title'])}"


# --- registry ------------------------------------------------------------------------------------------------------
def build_registry(findings: list[dict], consulted: list[dict]) -> tuple[list[EvidenceItem], list[SourceRef]]:
    """One SourceRef per distinct (provider, normalized URL). A source queried several times is ONE record whose
    status is the shared status, or "partial" when the attempts differ - a later failure is never hidden behind an
    earlier success."""
    sources: list[SourceRef] = []
    by_pair: dict[str, SourceRef] = {}
    seen_status: dict[str, list[str]] = {}
    for s in consulted:
        pair = (s.get("name") or "", s.get("url") or "")
        key = source_key(*pair)
        if key in by_pair:
            ref = by_pair[key]
            seen_status[key].append(s.get("status") or "")
            if s.get("detail") and s["detail"] not in ref.detail:
                ref.detail = (ref.detail + " | " + s["detail"])[:600] if ref.detail else s["detail"]
            if (s.get("consulted_at") or "") > ref.consulted_at:
                ref.consulted_at = s["consulted_at"]
            continue
        tier, basis = classify_source(pair[0], pair[1])
        ref = SourceRef(f"S{len(sources) + 1}", pair[0], pair[1], s.get("status") or "", s.get("detail") or "",
                        s.get("consulted_at") or "", tier, basis, reliability=RELIABILITY.get(tier, "UNASSESSED"))
        sources.append(ref)
        by_pair[key] = ref
        seen_status[key] = [s.get("status") or ""]
    for key, ref in by_pair.items():
        sts = seen_status[key]
        ref.status = sts[0] if all(x == sts[0] for x in sts) else "partial"
        ref.consulted = "ok" in sts
        m = _HTTP_RE.search(ref.detail)
        ref.http_status = m.group(1) if m else ""

    items: list[EvidenceItem] = []
    for i, f in enumerate(findings, 1):
        name, url = f.get("source") or "", f.get("source_url") or ""
        sref = by_pair.get(source_key(name, url))
        if sref is None:
            tier, basis = classify_source(name, url, f.get("category", ""))
            sref = SourceRef(f"S{len(sources) + 1}", name, url, "", "", f.get("discovered_at") or "", tier, basis)
            sref.reliability = RELIABILITY.get(tier, "UNASSESSED")
            sources.append(sref)
            by_pair[source_key(name, url)] = sref
        elif not sref.consulted_at and f.get("discovered_at"):
            sref.consulted_at = f["discovered_at"]
        item = EvidenceItem(
            ref=f"E{i}", finding_id=f.get("id"), category=f.get("category") or "general", title=f.get("title") or "",
            value=f.get("value") or "", description=f.get("description") or "", source=name, source_url=url,
            retrieved_at=f.get("discovered_at") or "", published_at=f.get("published_at") or "",
            evidence=f.get("evidence") or "", limitations=f.get("limitations") or "",
            stored_grade=normalize_confidence(f.get("confidence", "")), source_ref=sref.ref,
            origin=origin_of(name, url), query=f.get("query") or "")
        item.grade, item.grade_note = effective_grade(item, sref.tier)
        item.significance = T.category_note(item.category)[0]
        item.metadata_gaps = metadata_gaps(item, sref.tier)
        sref.evidence_refs.append(item.ref)
        items.append(item)
    return items, sources


def effective_grade(e: EvidenceItem, tier: str) -> tuple[str, str]:
    """-> (grade, note). The engine only ever LOWERS a module's grade, never raises it.
    * A search-engine result shows a page was indexed for a query; text in a snippet cannot establish a finding
      above LOW, so VERIFIED / CORROBORATED / MODERATE search findings are capped at LOW.
    * A finding sourced from AI analysis is an analytical statement, not an observation: capped at LOW."""
    g = e.stored_grade
    if tier == TIER_SEARCH and g in _SEARCH_CAP_GRADES:
        return LOW, f"capped from {g}: a search-engine result or snippet alone cannot establish this grade"
    if any(k in e.source.lower() for k in _AI_NAMES) and g in (VERIFIED, CORROBORATED, MODERATE):
        return LOW, f"capped from {g}: AI-generated analysis is not independent evidence"
    return g, ""


def metadata_gaps(e: EvidenceItem, tier: str) -> list[str]:
    gaps = []
    if not e.source.strip():
        gaps.append("source name not recorded")
    if not e.source_url and tier not in (TIER_LOCAL, TIER_DERIVED):
        gaps.append("no source URL recorded")
    if not e.retrieved_at:
        gaps.append("no retrieval timestamp recorded")
    if not e.published_at:
        gaps.append("publication date not provided by the source")
    if not e.evidence.strip():
        gaps.append("no supporting evidence text recorded")
    return gaps


# --- corroboration and duplicates -----------------------------------------------------------------------------------
def group_claims(items: list[EvidenceItem], findings: list[dict]) -> list[ClaimGroup]:
    by_key: dict[str, list[EvidenceItem]] = defaultdict(list)
    for e, f in zip(items, findings):
        if e.category == "contradiction" or _is_analytical(e):
            continue
        by_key[claim_key(f)].append(e)
    groups = []
    for key, members in by_key.items():
        seen_origin: dict[str, str] = {}
        for e in members:
            if e.origin in seen_origin:
                e.duplicate_of = seen_origin[e.origin]
            else:
                seen_origin[e.origin] = e.ref
        origins = list(dict.fromkeys(e.origin for e in members))
        names = list(dict.fromkeys(_norm(e.source) for e in members))
        independent = len(origins) >= 2 and len(names) >= 2
        if independent:
            for e in members:
                e.corroborated_by = [o.ref for o in members if o.origin != e.origin]
        if len(members) >= 2:
            first = members[0]
            label = f"{first.category}: " + (first.value if not key.split("|", 1)[1].startswith("t:") else first.title)
            note = ("independent origins agree" if independent else
                    "repeated by the same origin - counts once, not as corroboration")
            groups.append(ClaimGroup(key, label[:200], [e.ref for e in members], origins, names, independent, note))
    return groups


def _is_analytical(e: EvidenceItem) -> bool:
    return e.category in _ANALYTICAL_CATEGORIES or any(k in e.source.lower() for k in _DERIVED_NAMES + _AI_NAMES)


# --- discrepancies --------------------------------------------------------------------------------------------------
# (absence title, presence title prefix): both present in one investigation is a direct conflict.
ABSENCE_PAIRS = [
    ("No SPF record", "SPF record present"), ("No DMARC record", "DMARC record present"),
    ("No MX record", "MX record"), ("No reverse DNS", "Reverse DNS (PTR)"),
    ("No public Gravatar profile", "Public Gravatar profile"), ("No breaches listed in HIBP", "Breach:"),
    ("No Wayback Machine captures", "Wayback Machine "),
]
SINGLE_VALUED_TITLES = ("Domain registration date", "Registry event", "Domain registrar")


def find_discrepancies(items: list[EvidenceItem], correlation_strings: list[str]) -> list[Discrepancy]:
    out: list[Discrepancy] = []
    covered: set[str] = set()

    # 1. contradictions the collecting module itself recorded
    for e in items:
        if e.category == "contradiction" or (e.category == "comparison" and e.title.startswith("Conflicting")):
            text = f"{e.title}: {e.description}"
            covered.add(text)
            out.append(Discrepancy(text, [e.ref], "collecting module",
                                   "Consult the authoritative primary source for this attribute."))

    # 2. single-valued attributes with different values (same rule family as core.correlation)
    by_title: dict[str, list[EvidenceItem]] = defaultdict(list)
    for e in items:
        if e.title.startswith(SINGLE_VALUED_TITLES) and e.value.strip():
            by_title[e.title].append(e)
    for title, members in by_title.items():
        values = sorted({m.value for m in members})
        if len(values) > 1:
            text = f"{title} has conflicting values: {', '.join(values)}"
            covered.add(text)
            out.append(Discrepancy(text, [m.ref for m in members], "single-valued attribute rule",
                                   "Check the registry (RDAP) record directly; one value may be stale."))

    # 3. presence vs. absence of the same thing
    for absent, present in ABSENCE_PAIRS:
        a = [e for e in items if e.title == absent]
        p = [e for e in items if e.title.startswith(present)]
        if a and p:
            out.append(Discrepancy(f"'{absent}' recorded alongside '{p[0].title}'", [x.ref for x in a + p],
                                   "report engine (presence/absence rule)",
                                   "Re-run the check; the sources may have been queried at different times."))

    # 4. anything else core.correlation flagged that is not already listed
    for text in correlation_strings:
        if text not in covered:
            out.append(Discrepancy(text, [], "core.correlation rules", "Review the underlying findings."))

    involved = defaultdict(set)
    for d in out:
        for r in d.evidence_refs:
            involved[r].update(x for x in d.evidence_refs if x != r)
    for e in items:
        if e.ref in involved:
            e.conflicts_with = sorted(involved[e.ref], key=lambda r: int(r[1:]))
    return out


# --- claim classes --------------------------------------------------------------------------------------------------
def classify_claims(items: list[EvidenceItem], discrepancies: list[Discrepancy]) -> None:
    in_conflict = {r for d in discrepancies for r in d.evidence_refs}
    for e in items:
        g = e.grade or e.stored_grade
        if e.ref in in_conflict:
            e.claim_class = CONTRADICTORY
        elif _is_analytical(e):
            e.claim_class = ANALYTICAL_INFERENCE
        elif g == VERIFIED:
            e.claim_class = VERIFIED_FACT
        elif g == CORROBORATED or (g in (MODERATE, LOW) and e.corroborated_by):
            e.claim_class = CORROBORATED_CLAIM
        elif g in (MODERATE, LOW):
            e.claim_class = SINGLE_SOURCE_CLAIM
        else:  # UNVERIFIED, INCONCLUSIVE, anything unknown
            e.claim_class = UNVERIFIED_CLAIM


# --- patterns / inferences ------------------------------------------------------------------------------------------
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}")


def _keep(inf: Inference, rejected: list[str]) -> Inference | None:
    """An inference must rest on evidence and must not assert identity, location or conduct."""
    if not inf.basis:
        rejected.append(f"Discarded (no supporting evidence): {inf.statement}")
        return None
    try:
        T.guard(inf.statement)
        for alt in inf.alternatives:
            T.guard(alt)
    except T.UnsupportedConclusion as exc:
        rejected.append(f"Discarded ({exc}): {inf.statement}")
        return None
    return inf


def derive_inferences(items: list[EvidenceItem], entities: list[dict], shared: list[dict], profile: T.Profile,
                      generic_check, rejected: list[str]) -> list[Inference]:
    out: list[Inference] = []
    live = [e for e in items if not e.duplicate_of]

    def add(inf: Inference):
        kept = _keep(inf, rejected)
        if kept:
            out.append(kept)

    # why each category matters, with alternative interpretations
    by_cat: dict[str, list[EvidenceItem]] = defaultdict(list)
    for e in live:
        by_cat[e.category].append(e)
    for cat in sorted(by_cat, key=lambda c: -len(by_cat[c])):
        if cat == "contradiction":
            continue
        sig, alts = T.category_note(cat)
        members = by_cat[cat]
        grades = Counter(e.claim_class for e in members)
        mix = ", ".join(f"{c.lower()}: {n}" for c, n in grades.most_common())
        add(Inference(f"{len(members)} finding(s) in '{cat}' ({mix}). {sig}", [e.ref for e in members], list(alts),
                      kind="significance"))

    # concentration on one origin
    if len(live) >= 4:
        origin, n = Counter(e.origin for e in live).most_common(1)[0]
        if n / len(live) > 0.6:
            add(Inference(f"{n} of {len(live)} findings come from a single origin ({origin}); the picture depends "
                          "heavily on that one source.", [e.ref for e in live if e.origin == origin],
                          ["The source may be authoritative for this kind of data, which would make concentration expected."],
                          "Seek a second, independent origin before relying on these findings.", "pattern"))

    # name / handle matches: frequency is about the name, not the subject
    matches = [e for e in live if e.category in ("name_match", "contextual_match", "unresolved_candidate", "profiles")]
    if profile.identity_sensitive and len(matches) >= 2:
        sites = {e.origin for e in matches}
        add(Inference(f"{len(matches)} results matched the searched name or handle across {len(sites)} distinct "
                      "site(s). This measures how often the term appears in indexed sources.",
                      [e.ref for e in matches],
                      ["Several different people or accounts may share the term.",
                       "Some results may be unrelated pages that only contain the words."],
                      T.IDENTITY_STATEMENT, "pattern"))

    # publication-date span (real dates only)
    dated = [e for e in live if _DATE_RE.match(e.published_at)]
    if dated:
        lo = min(e.published_at[:10] for e in dated)
        hi = max(e.published_at[:10] for e in dated)
        add(Inference(f"{len(dated)} of {len(live)} findings carry a source publication date, spanning {lo} to {hi}; "
                      f"{len(live) - len(dated)} carry none.", [e.ref for e in dated],
                      ["Older material may be superseded; publication date is not the date of the underlying event."],
                      kind="pattern"))

    # shared generic infrastructure is not a connection
    for ent in entities:
        if generic_check(ent.get("entity_type", ""), ent.get("value", "")):
            basis = [e.ref for e in live if _norm(e.value) == _norm(ent["value"])] or \
                    [f"ENTITY:{ent['entity_type']}:{ent['value']}"]
            add(Inference(f"{ent['value']} is shared infrastructure used by many unrelated parties.", basis,
                          [], "Using the same mail, DNS, hosting or resolver provider does not connect two subjects.",
                          "correlation"))

    # co-occurrence with other investigations
    mine = {(e.get("entity_type"), _norm(e.get("value", ""))) for e in entities}
    for s in shared:
        if s.get("generic") or (s.get("entity_type"), _norm(s.get("value", ""))) not in mine:
            continue
        add(Inference(f"The {s['entity_type']} {s['value']} also appears in {s['n'] - 1} other investigation(s) "
                      f"({s['refs']}).", [f"ENTITY:{s['entity_type']}:{s['value']}"],
                      ["The other investigations may concern unrelated subjects that share this identifier by coincidence "
                       "or through common services."], T.CORRELATION_CAVEAT, "correlation"))
    return out
