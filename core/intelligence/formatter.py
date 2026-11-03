"""Renders an IntelligenceReport as a document.

`blocks()` turns the report into one ordered list of document blocks (the 12 required sections). Markdown and PDF
are both rendered from that list, so the two exports always carry the same content. Source URLs are written
exactly as stored; third-party text is escaped so it cannot inject links or markup.
"""
from __future__ import annotations

import re

from core.reports import safe_href

from core.models import CONFIDENCE_MEANING

from .models import CLAIM_CLASS_MEANING, STATUS_MEANING, IntelligenceReport

SECTION_TITLES = [
    "1. Executive Summary", "2. Investigation Scope", "3. Research Methodology", "4. Sources Consulted",
    "5. Key Findings", "6. Evidence Assessment", "7. Entity Relationships", "8. Contradictory or Unverified Information",
    "9. Intelligence Gaps", "10. Limitations", "11. Overall Assessment", "12. Recommended Next Research Steps",
]
NR = "not recorded"
_NOT_RETRIEVED = ("error", "blocked", "not_configured", "skipped", "manual", "partial")
_WS = re.compile(r"\s+")


def _or(v: str, missing: str = NR) -> str:
    return v if (v or "").strip() else missing


def _dedupe(bl: list[tuple]) -> list[tuple]:
    """Drop repeated paragraphs / bullets (same text anywhere in the document) so a warning is stated once.
    Key/value rows, headings, URLs and evidence text blocks are never dropped."""
    seen: set[str] = set()
    out = []
    for blk in bl:
        if blk[0] in ("p", "li", "ref"):
            key = _WS.sub(" ", blk[1].strip().lower())
            if key in seen:
                continue
            seen.add(key)
        out.append(blk)
    return out


def blocks(r: IntelligenceReport) -> list[tuple]:
    """Document blocks: ("h1", t) ("h2", t, anchor) ("h3", t, anchor) ("p", t) ("li", t) ("kv", k, v)
    ("pre", t) ("url", label, url) ("ref", text, [refs]) - "ref" is a paragraph linking evidence/source refs.
    Markdown, PDF and the terminal view all render this one list, so they always carry the same content."""
    ov, b = r.overview, []
    live = [e for e in r.evidence if not e.duplicate_of]
    b.append(("h1", f"Intelligence Report - {ov['reference']}"))
    b.append(("p", f"Generated {r.generated_at} by {r.generator} (report engine {r.engine_version})."))
    b.append(("kv", "Report status", f"{r.status} - {STATUS_MEANING[r.status]}"))
    b += [("li", x) for x in r.status_reasons]

    # 1 Executive Summary --------------------------------------------------------------------------------------------
    b.append(("h2", SECTION_TITLES[0], "summary"))
    b += [("p", x) for x in r.executive_summary]

    # 2 Investigation Scope ------------------------------------------------------------------------------------------
    b.append(("h2", SECTION_TITLES[1], "scope"))
    for k, v in (("Reference", ov["reference"]), ("Investigation type", f"{ov['type_label']} ({ov['investigation_type']})"),
                 ("Category", ov["family"]), ("Target", ov["target"]), ("Purpose", ov["purpose"]),
                 ("Investigated", ov["investigated_at"]), ("Stored record status", ov["record_status"])):
        b.append(("kv", k, str(v)))
    if ov.get("coverage"):
        b.append(("kv", "Search coverage", ov["coverage"]))
    b.append(("p", "In scope: lawful public-source research and authorized infrastructure checks. Out of scope: private "
                   "accounts, authentication bypass, covert surveillance, and any attempt to profile an individual."))

    # 3 Research Methodology -----------------------------------------------------------------------------------------
    b.append(("h2", SECTION_TITLES[2], "methodology"))
    b.append(("p", "Workflow stages and what each recorded:"))
    for st in r.workflow:
        b.append(("li", f"{st['stage']}: {st['status']}" + (f" - {st['detail']}" if st.get("detail") else "")))
    if not r.workflow:
        b.append(("li", "No stage records exist for this investigation (it was saved before stage recording)."))
    b.append(("li", f"Evidence Assessment (this report): {len(r.evidence)} finding(s) graded, {len(live)} distinct."))
    b.append(("li", f"Entity Resolution (this report): {ov['entities']} entit(ies), {ov['relationships']} relationship(s); "
                    "identities are never merged on a shared name, handle, number or address."))
    b.append(("li", "AI Analysis: " + ("present, kept separate from evidence (see Overall Assessment)."
                                     if r.ai_analysis else "none was run for this investigation.")))
    queries = list(dict.fromkeys(e.query for e in r.evidence if e.query))
    if queries:
        b.append(("p", "Search queries recorded:"))
        b += [("li", q) for q in queries[:15]]
    b.append(("p", r.corroboration["method"]))
    b.append(("p", "Evidence grades: " + "; ".join(f"{k} - {v}" for k, v in CONFIDENCE_MEANING.items())))
    b.append(("p", "Claim classes: " + "; ".join(f"{c} - {m}" for c, m in CLAIM_CLASS_MEANING.items())))

    # 4 Sources Consulted --------------------------------------------------------------------------------------------
    b.append(("h2", SECTION_TITLES[3], "sources"))
    consulted = [s for s in r.sources if s.consulted]
    attempted = [s for s in r.sources if not s.consulted and s.status in _NOT_RETRIEVED]
    cited = [s for s in r.sources if not s.consulted and s.status not in _NOT_RETRIEVED]
    b.append(("p", f"Consulted (a successful retrieval was recorded): {len(consulted)}. Attempted but not retrieved: "
                   f"{len(attempted)}. Cited only (a finding points to it; TRACEPOINT did not retrieve it): {len(cited)}."))
    if not r.sources:
        b.append(("p", "No sources were recorded."))

    def src_block(s, label):
        b.append(("h3", f"{s.ref} - {_or(s.name, 'unnamed source')}", s.ref.lower()))
        b.append(("url", "URL", s.url) if s.url else ("kv", "URL", NR))
        b.append(("kv", "Status", f"{label}: {s.status or 'cited by findings'}"
                  + (f" (HTTP {s.http_status})" if s.http_status else "")))
        b.append(("kv", "Retrieved / recorded", _or(s.consulted_at)))
        b.append(("kv", "Source type", f"{s.tier} ({s.tier_basis})"))
        b.append(("kv", "Reliability", _or(s.reliability, "UNASSESSED") + " (by source type, not for this case)"))
        if s.detail:
            b.append(("kv", "Detail", s.detail))
        if s.evidence_refs:
            b.append(("ref", "Findings: " + ", ".join(s.evidence_refs), s.evidence_refs))
    for group, label in ((consulted, "consulted"), (attempted, "NOT retrieved"), (cited, "cited only")):
        for s in group:
            src_block(s, label)

    # 5 Key Findings -------------------------------------------------------------------------------------------------
    b.append(("h2", SECTION_TITLES[4], "key-findings"))
    if not r.key_findings:
        b.append(("p", "No findings were recorded."))
    for k in r.key_findings:
        b.append(("ref", f"[{k.claim_class}] {k.headline} (module grade {k.stored_grade}; source {k.source_ref}). "
                         f"Why it matters: {k.why_it_matters}", [k.evidence_ref, k.source_ref]))

    # 6 Evidence Assessment ------------------------------------------------------------------------------------------
    b.append(("h2", SECTION_TITLES[5], "evidence"))
    b.append(("p", "Every stored finding with its provenance exactly as recorded. Supporting evidence is what the source "
                   "returned; contradictory evidence is listed where another finding conflicts."))
    if not r.evidence:
        b.append(("p", "The registry is empty: no findings were recorded."))
    src = r.source_by_ref()
    for e in r.evidence:
        b.append(("h3", f"{e.ref} - {e.title}", e.ref.lower()))
        grade = e.grade or e.stored_grade
        b.append(("kv", "Classification", f"{e.claim_class}; evidence grade {grade}"
                  + (f" (module grade {e.stored_grade})" if grade != e.stored_grade else "")))
        if e.grade_note:
            b.append(("kv", "Grade adjustment", e.grade_note))
        b.append(("kv", "Category", e.category))
        if e.value:
            b.append(("kv", "Value", e.value))
        b.append(("kv", "Finding", e.description))
        b.append(("kv", "Source", f"{_or(e.source)} [{e.source_ref}]"
                                  + (f" - {src[e.source_ref].tier}" if e.source_ref in src else "")))
        b.append(("url", "Source URL", e.source_url) if e.source_url else ("kv", "Source URL", NR))
        b.append(("kv", "Retrieved", _or(e.retrieved_at)))
        b.append(("kv", "Published", _or(e.published_at, "not provided by source")))
        if e.query:
            b.append(("kv", "Search query", e.query))
        if e.evidence:
            b.append(("p", "Supporting evidence:"))
            b.append(("pre", e.evidence))
        else:
            b.append(("kv", "Supporting evidence", NR))
        b.append(("kv", "Contradictory evidence", ", ".join(e.conflicts_with) if e.conflicts_with else "none identified"))
        if e.limitations:
            b.append(("kv", "Limitations", e.limitations))
        if e.corroborated_by:
            b.append(("ref", "Independently corroborated by: " + ", ".join(e.corroborated_by), e.corroborated_by))
        if e.duplicate_of:
            b.append(("ref", f"Repeat of {e.duplicate_of} from the same origin (counted once).", [e.duplicate_of]))
        if e.metadata_gaps:
            b.append(("kv", "Metadata gaps", "; ".join(e.metadata_gaps)))
    co = r.corroboration
    b.append(("h3", "Corroboration summary", "corroboration"))
    b.append(("p", f"Independently corroborated claim groups: {len(co['independent_groups'])}"))
    for g in co["independent_groups"]:
        b.append(("ref", f"{g['label']} - origins: {', '.join(g['origins'])} ({', '.join(g['evidence_refs'])})",
                  g["evidence_refs"]))
    if co["same_origin_repeats"]:
        b.append(("p", "Repeated by a single origin (not corroboration):"))
        for g in co["same_origin_repeats"]:
            b.append(("ref", f"{g['label']} - {', '.join(g['evidence_refs'])}", g["evidence_refs"]))
    if co["module_graded_corroborated"]:
        b.append(("ref", "Graded CORROBORATED by the collecting module: " + ", ".join(co["module_graded_corroborated"]),
                  co["module_graded_corroborated"]))
    b.append(("p", f"Single-source claims needing confirmation: {len(co['single_source_refs'])}"
                   + (f" ({', '.join(co['single_source_refs'])})" if co["single_source_refs"] else "")))

    # 7 Entity Relationships -----------------------------------------------------------------------------------------
    b.append(("h2", SECTION_TITLES[6], "entities"))
    if not r.entities and not r.relationships:
        b.append(("p", "No entities or relationships were recorded."))
    for en in r.entities:
        b.append(("li", f"{en.get('entity_type')}: {en.get('value')} ({en.get('verification', 'UNVERIFIED')})"
                        + (" - shared infrastructure, not a connection between subjects" if en.get("generic") else "")))
    for rel in r.relationships:
        b.append(("li", f"{rel.get('src_value')} -[{rel.get('rel_type')}; {rel.get('confidence')}]-> {rel.get('dst_value')}"))
    for inf in [i for i in r.assessment if i.kind == "correlation"]:
        b.append(("ref", f"{inf.statement} (basis: {', '.join(inf.basis[:8])})",
                  [x for x in inf.basis if not x.startswith("ENTITY:")]))
        if inf.caveat:
            b.append(("li", f"Caveat: {inf.caveat}"))
    if r.entities or r.relationships:
        b.append(("p", "A relationship records that identifiers appeared together in public data. It is not an identity match."))

    # 8 Contradictory or Unverified Information -----------------------------------------------------------------------
    b.append(("h2", SECTION_TITLES[7], "discrepancies"))
    if not r.discrepancies:
        b.append(("p", "No contradictions or discrepancies were detected by the module, core.correlation, or the "
                       "report engine's rules. This does not prove the sources agree on everything."))
    for d in r.discrepancies:
        b.append(("ref", f"{d.description} (detected by: {d.detected_by}"
                         + (f"; evidence {', '.join(d.evidence_refs)}" if d.evidence_refs else "; no linked finding")
                         + f"). Next: {d.resolution_hint}", d.evidence_refs))
    unver = [e for e in live if e.claim_class == "UNVERIFIED CLAIM"]
    if unver:
        b.append(("p", f"Unverified information ({len(unver)}): leads that were not confirmed. They are listed, never promoted."))
        for e in unver[:25]:
            b.append(("ref", f"{e.ref}: {e.title} (grade {e.grade or e.stored_grade}; source {e.source_ref})",
                      [e.ref, e.source_ref]))
        if len(unver) > 25:
            b.append(("p", f"{len(unver) - 25} further unverified finding(s) are in the Evidence Assessment."))

    # 9 Intelligence Gaps --------------------------------------------------------------------------------------------
    b.append(("h2", SECTION_TITLES[8], "gaps"))
    gaps = list(r.unresolved_questions)
    gaps += [f"{s.name or 'unnamed source'} was not consulted ({s.status})." for s in r.sources
             if s.status in ("not_configured", "skipped", "manual")]
    nogap = [e for e in live if any(g != "publication date not provided by the source" for g in e.metadata_gaps)]
    if nogap:
        gaps.append(f"{len(nogap)} finding(s) lack provenance metadata (source URL, retrieval time or supporting evidence).")
    b += [("li", g) for g in dict.fromkeys(gaps)] or [("p", "None recorded.")]

    # 10 Limitations -------------------------------------------------------------------------------------------------
    b.append(("h2", SECTION_TITLES[9], "limitations"))
    b += [("li", x) for x in r.limitations]
    b.append(("p", r.confidence.identity_statement))

    # 11 Overall Assessment ------------------------------------------------------------------------------------------
    c = r.confidence
    b.append(("h2", SECTION_TITLES[10], "assessment"))
    b.append(("kv", "Report classification", r.status))
    b.append(("kv", "Overall evidence assessment", c.level))
    b.append(("kv", "What this measures", c.scope))
    b += [("li", f"Factor: {x}") for x in c.factors] + [("li", f"Limit applied: {x}") for x in c.caps]
    infs = [i for i in r.assessment if i.kind != "correlation"]
    b.append(("p", "Analytical inferences drawn from the evidence. Each lists what it rests on; none is an observation by a source."))
    if not infs:
        b.append(("p", "No analytical inference is supported by the recorded evidence."))
    for inf in infs:
        b.append(("ref", f"{inf.statement} (basis: {', '.join(inf.basis[:12])}{' ...' if len(inf.basis) > 12 else ''})",
                  [x for x in inf.basis if not x.startswith("ENTITY:")]))
        for alt in inf.alternatives:
            b.append(("li", f"Alternative interpretation: {alt}"))
        if inf.caveat:
            b.append(("li", f"Caveat: {inf.caveat}"))
    if r.ai_analysis:
        b.append(("h3", "AI analysis (local model; analysis, not evidence)", "ai"))
        b.append(("p", "Generated from the stored findings only. It is not a source, is never counted as corroboration, "
                       "and has not been verified by TRACEPOINT."))
        b.append(("pre", r.ai_analysis))

    # 12 Recommended Next Research Steps -------------------------------------------------------------------------------
    b.append(("h2", SECTION_TITLES[11], "next-steps"))
    b += [("li", s) for s in r.next_steps] or [("p", "None.")]
    return _dedupe(b)


# --- Markdown ------------------------------------------------------------------------------------------------------
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|#!~])")


def md_escape(text: str) -> str:
    return _MD_SPECIAL.sub(r"\\\1", text or "")


def md_url(url: str) -> str:
    """Exact URL. Safe http(s) URLs become autolinks; anything else is shown as inert code."""
    if safe_href(url) and not re.search(r"[\s<>]", url):
        return f"<{url}>"
    fence = "``" if "`" in url else "`"
    return f"{fence} {url} {fence}" if fence == "``" else f"`{url}`"


def _md_ref_text(text: str, refs: list[str]) -> str:
    out = md_escape(text)
    for ref in sorted(set(refs), key=len, reverse=True):
        out = re.sub(rf"(?<![\w#])({re.escape(ref)})(?!\w)", rf"[\1](#{ref.lower()})", out)
    return out


def to_markdown(r: IntelligenceReport) -> str:
    lines: list[str] = []
    for blk in blocks(r):
        kind = blk[0]
        if kind in ("p", "pre", "h3") and lines and lines[-1].startswith("- "):
            lines.append("")            # end the list, or the paragraph becomes part of its last item
        if kind == "h1":
            lines += [f"# {md_escape(blk[1])}", ""]
        elif kind == "h2":
            lines += ["", f'<a id="{blk[2]}"></a>', f"## {md_escape(blk[1])}", ""]
        elif kind == "h3":
            lines += [f'<a id="{blk[2]}"></a>', f"### {md_escape(blk[1])}", ""]
        elif kind == "p":
            lines += [md_escape(blk[1]), ""]
        elif kind == "li":
            lines.append(f"- {md_escape(blk[1])}")
        elif kind == "kv":
            lines.append(f"- **{md_escape(blk[1])}:** {md_escape(blk[2])}")
        elif kind == "url":
            lines.append(f"- **{md_escape(blk[1])}:** {md_url(blk[2])}")
        elif kind == "pre":
            fence = "~~~~" if "```" in blk[1] or "~~~" in blk[1] else "```"
            lines += ["", f"{fence}text", blk[1], fence, ""]
        elif kind == "ref":
            lines += [f"- {_md_ref_text(blk[1], blk[2])}"]
    lines += ["", "---", "", md_escape("Heuristic evidence grades, not legal proof or identity attribution. For "
                                       "auditing identifiers the operator owns or is authorized to investigate."), ""]
    return "\n".join(lines)
