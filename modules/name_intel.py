"""Evidence-limited public Name Intelligence investigation."""
from __future__ import annotations

import re

from core.models import LOW, UNVERIFIED, Finding, ModuleResult
from modules.name_matching import Claim, contradictory_claims, corroborated_claims, name_match_state
from providers.name_search import search_name

LIMITATIONS = (
    "A matching name or search snippet does not establish identity. Candidates remain separate unless multiple "
    "independent supporting identifiers are reviewed. Search results are leads, not proof."
)


def investigate(name: str, *, context: str = "", claims: list[Claim] | None = None, limit: int = 6) -> ModuleResult:
    cleaned = " ".join((name or "").split())
    context = " ".join((context or "").split())
    result = ModuleResult("name", cleaned)
    result.notes.append("Purpose/context supplied by operator: " + (context or "not supplied"))
    result.notes.append("Name search reads indexed public-result metadata only; source pages are not crawled.")
    if len(cleaned.split()) < 2 or len(cleaned) > 160:
        result.errors.append("Enter a full name (at least two words, up to 160 characters).")
        return result
    if any(c in cleaned for c in "@") or sum(c.isdigit() for c in cleaned) >= 7:
        result.errors.append("Name Intelligence accepts names only; do not enter contact details or identifiers.")
        return result
    if ("@" in context or sum(c.isdigit() for c in context) >= 7 or len(context) > 240
            or re.search(r"\b\d{1,6}\s+(?:[\w.-]+\s+){0,4}(?:street|st|road|rd|avenue|ave|boulevard|blvd|drive|dr|lane|ln|court|ct)\b", context, re.I)):
        result.errors.append("Research context must be brief and must not contain contact details or numeric identifiers.")
        return result

    hits = search_name(cleaned, context, limit=max(1, min(int(limit), 6)), result=result)
    for query_category, hit in hits:
        state = name_match_state(cleaned, hit.title, hit.snippet)
        category = {"unresolved": "unresolved_candidate", "name_match": "name_match",
                    "contextual": "contextual_match"}[state]
        has_name = state != "unresolved"
        result.add(Finding(
            title=hit.title[:160] or hit.url,
            description=(f"Public search result ({query_category}); candidate classification: {state}."),
            source=hit.provider, confidence=LOW if has_name else UNVERIFIED,
            category=category, value=hit.url, source_url=hit.url,
            evidence=(hit.snippet or "No snippet provided by provider")[:1000],
            limitations=LIMITATIONS,
            discovered_at=hit.discovered_at, query=hit.query, source_type=query_category,
            published_at=hit.published_at,
        ))

    if not hits:
        result.notes.append("No valid public search results returned. This does not establish absence of public information.")
    if claims:
        for confirmed in corroborated_claims(claims):
            result.add(Finding(
                title=f"Independent sources report: {confirmed['field']}",
                description=f"The analyst-assigned candidate {confirmed['candidate_id']} has the same structured value "
                            "in sources from multiple domains; this is source corroboration, not identity proof.",
                source="Analyst comparison", confidence=UNVERIFIED, category="independently_corroborated",
                value=confirmed["value"], evidence="\n".join(confirmed["source_urls"]),
                limitations="Candidate grouping and source independence require manual verification; source repetition or common ownership may remain."))
        for conflict in contradictory_claims(claims):
            result.add(Finding(
                title=f"Conflicting claims: {conflict['field']}",
                description=f"The explicitly grouped candidate {conflict['candidate_id']} has conflicting values: "
                            + "; ".join(v["value"] for v in conflict["values"]),
                source="Analyst comparison", confidence=UNVERIFIED, category="contradiction",
                value=" | ".join(v["value"] for v in conflict["values"]),
                evidence="\n".join(url for v in conflict["values"] for url in v["sources"]),
                limitations="Contradictory source claims require manual review; the underlying sources may differ in scope or date."))
    if hits and not any(h.published_at for _, h in hits):
        result.notes.append("Search-result publication dates were not supplied by the configured provider; dates are unknown.")
    return result
