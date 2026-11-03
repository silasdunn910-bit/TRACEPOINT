"""Universal Intelligence Report Engine: one report pipeline for every investigation type.

collect (core.reports.build) -> registry + source tiers -> corroboration / duplicates -> discrepancies ->
claim classes -> inferences -> completeness + assessment -> sections -> stored snapshot.

Investigation types are never special-cased in the pipeline: the type only selects a wording profile in
templates.PROFILES, and unknown (future) types fall back to the cautious generic profile.
"""
from __future__ import annotations

import json

from core import correlation, reports
from core.configuration import APP_NAME, VERSION, get_logger
from core.database import get_db
from core.models import now_iso
from core.security import redact

from . import confidence as C
from . import evidence_analyzer as A
from . import templates as T
from .models import (ANALYTICAL_INFERENCE, CONTRADICTORY, CORROBORATED_CLAIM, ENGINE_VERSION, FAILED, INCOMPLETE,
                     SINGLE_SOURCE_CLAIM, STATUS_MEANING, UNVERIFIED_CLAIM, VERIFIED_FACT, IntelligenceReport,
                     KeyFinding)

KEY_FINDINGS_MAX = 12
_KEY_RANK = {VERIFIED_FACT: 0, CORROBORATED_CLAIM: 1, CONTRADICTORY: 2, SINGLE_SOURCE_CLAIM: 3,
             ANALYTICAL_INFERENCE: 4, UNVERIFIED_CLAIM: 5}
_ROUTINE_CATEGORIES = {"validation", "syntax", "normalization"}   # shown only if nothing else was found


def _type_label(inv_type: str) -> str:
    from core.investigation import SPECS
    spec = SPECS.get(inv_type)
    return spec.label if spec else f"{inv_type.replace('_', ' ').title()} Investigation"


def _headline(e) -> str:
    return e.title + (f": {e.value}" if e.value and e.value not in e.title else "")


def generate(inv_id: int) -> IntelligenceReport:
    """Build the intelligence report for a stored investigation (raises if the investigation does not exist)."""
    built = reports.build(inv_id)
    shared = correlation.shared_entities(2) if built["related_entities"] else []
    return generate_from_built(built, shared)


def generate_from_built(built: dict, shared: list[dict] | None = None) -> IntelligenceReport:
    inv = built["investigation"]
    profile = T.profile_for(inv["type"])
    findings = built["findings"]
    rejected: list[str] = []

    items, sources = A.build_registry(findings, built["sources_consulted"])
    groups = A.group_claims(items, findings)
    discrepancies = A.find_discrepancies(items, built["contradictions"])
    A.classify_claims(items, discrepancies)
    inferences = A.derive_inferences(items, built["related_entities"], shared or [], profile,
                                     correlation.is_generic_infrastructure, rejected)
    status, status_reasons = C.completeness(built)
    conf = C.assess(items, status, len(discrepancies), profile.identity_sensitive)
    live = [e for e in items if not e.duplicate_of]

    # --- key findings -----------------------------------------------------------------------------------------
    pool = [e for e in live if e.category not in _ROUTINE_CATEGORIES] or live
    pool = sorted(pool, key=lambda e: (_KEY_RANK.get(e.claim_class, 9), int(e.ref[1:])))[:KEY_FINDINGS_MAX]
    key_findings = [KeyFinding(e.ref, _headline(e)[:240], e.claim_class, e.stored_grade, e.source_ref, e.significance)
                    for e in pool]

    # --- executive summary --------------------------------------------------------------------------------------
    counts = conf.counts
    by_status = {}
    for s in built["sources_consulted"]:
        by_status[s["status"]] = by_status.get(s["status"], 0) + 1
    summary = [
        f"{_type_label(inv['type'])} of {inv['target']} ({inv['id']}). Report classification: {status}.",
        (f"{counts['total']} distinct finding(s) from {len(built['sources_consulted'])} consulted source(s): "
         f"{counts[VERIFIED_FACT]} verified fact(s), {counts[CORROBORATED_CLAIM]} corroborated, "
         f"{counts[SINGLE_SOURCE_CLAIM]} single-source, {counts[UNVERIFIED_CLAIM]} unverified, "
         f"{counts[ANALYTICAL_INFERENCE]} analytical inference(s), {counts[CONTRADICTORY]} contradictory."
         + (f" {counts['duplicates']} repeated finding(s) were counted once." if counts["duplicates"] else ""))
        if counts["total"] else f"No findings were recorded. {T.ABSENCE_STATEMENT}",
        f"Overall evidence assessment: {conf.level}. {conf.factors[0]}",
    ]
    solid = [k for k in key_findings if k.claim_class in (VERIFIED_FACT, CORROBORATED_CLAIM)][:3]
    if solid:  # only verified / corroborated material is highlighted; leads and allegations are counted, not echoed
        summary.append("Best-supported findings: " + "; ".join(f"{k.headline} [{k.evidence_ref}]" for k in solid) + ".")
    if discrepancies:
        summary.append(f"{len(discrepancies)} discrepancy(ies) need resolution before related findings are relied on.")
    if status == INCOMPLETE:
        summary.append("This investigation is INCOMPLETE and must not be read as a successful or negative result.")
    summary.append(conf.identity_statement)

    # --- unresolved questions / next steps --------------------------------------------------------------------------
    questions = list(profile.standing_questions)
    questions += [f"Which value is correct? {d.description}" for d in discrepancies]
    for s in built["sources_consulted"]:
        if s["status"] in ("error", "blocked"):
            questions.append(f"What would {s['name']} have returned? It {'failed' if s['status'] == 'error' else 'blocked automated checks'}"
                             + (f" ({s['detail']})." if s.get("detail") else "."))
    for e in [e for e in live if e.claim_class == SINGLE_SOURCE_CLAIM][:5]:
        questions.append(f"Can '{_headline(e)[:120]}' [{e.ref}] be confirmed by an independent source?")
    undated = sum(1 for e in live if not e.published_at)
    if live and undated:
        questions.append(f"When was the information first published? {undated} of {len(live)} finding(s) carry no "
                         "publication date from their source.")
    rr = built.get("records_review")
    if rr:
        questions += [f"Missing in the official record: {m}" for m in rr["missing_information"]
                      if not m.startswith(("None of", "No records"))]

    steps = list(profile.next_steps)
    failed = [s["name"] for s in built["sources_consulted"] if s["status"] in ("error", "blocked")]
    if failed:
        steps.append("Re-run the investigation or query these sources directly: " + ", ".join(dict.fromkeys(failed)) + ".")
    not_cfg = [s["name"] for s in built["sources_consulted"] if s["status"] == "not_configured"]
    if not_cfg:
        steps.append("Configure these optional sources (API Configuration) to widen coverage: "
                     + ", ".join(dict.fromkeys(not_cfg)) + ".")
    for d in discrepancies:
        steps.append(f"Resolve: {d.description[:160]} - {d.resolution_hint}")
    if counts[SINGLE_SOURCE_CLAIM]:
        steps.append(f"Seek an independent second origin for the {counts[SINGLE_SOURCE_CLAIM]} single-source claim(s).")
    if rr and rr["inaccessible_sources"]:
        steps.append("Search manually at: " + "; ".join(rr["inaccessible_sources"]) + ".")
    steps = list(dict.fromkeys(steps))

    # --- corroboration section --------------------------------------------------------------------------------------
    corroboration = {
        "method": ("Findings are grouped by category and value. A group is corroborated only when at least two distinct "
                   "origins (URL hosts, or source names when no URL exists) and two distinct source names report it. "
                   "Repeats from one origin count once. UNVERIFIED leads are never upgraded by repetition."),
        "independent_groups": [g.__dict__ for g in groups if g.independent],
        "same_origin_repeats": [g.__dict__ for g in groups if not g.independent],
        "module_graded_corroborated": [e.ref for e in live if e.stored_grade == "CORROBORATED"],
        "single_source_refs": [e.ref for e in live if e.claim_class == SINGLE_SOURCE_CLAIM],
        "duplicates": [{"ref": e.ref, "duplicate_of": e.duplicate_of} for e in items if e.duplicate_of],
        "source_tiers": _tier_summary(sources),
    }

    limitations = list(dict.fromkeys(built["limitations"] + T.ENGINE_LIMITS))
    gap_count = sum(1 for e in live if any(g != "publication date not provided by the source" for g in e.metadata_gaps))
    if gap_count:
        limitations.append(f"{gap_count} finding(s) are missing provenance metadata (source URL, retrieval time, "
                           "or supporting evidence); see each item in the Evidence Registry.")
    if rr:
        limitations.append(rr["statement"])
    limitations += rejected

    overview = {
        "reference": inv["id"], "investigation_type": inv["type"], "type_label": _type_label(inv["type"]),
        "family": profile.family, "subject_kind": profile.subject_noun, "purpose": profile.purpose,
        "target": inv["target"], "investigated_at": inv["timestamp"], "record_status": inv["status"],
        "report_status": status, "notes": inv.get("notes", ""),
        "sources_by_status": by_status, "findings_recorded": len(items),
        "entities": len(built["related_entities"]), "relationships": len(built["relationships"]),
        "coverage": rr["search_coverage"]["summary"] if rr else "",
    }
    report = IntelligenceReport(
        engine_version=ENGINE_VERSION, generated_at=now_iso(), generator=f"{APP_NAME} {VERSION}",
        status=status, status_reasons=status_reasons, overview=overview, executive_summary=summary,
        key_findings=key_findings, evidence=items, sources=sources, corroboration=corroboration,
        discrepancies=discrepancies, assessment=inferences, confidence=conf, limitations=limitations,
        unresolved_questions=list(dict.fromkeys(questions)), next_steps=steps, records_review=rr,
        ai_analysis=built.get("ai_analysis") or "", workflow=built.get("workflow", []),
        entities=[{**en, "generic": correlation.is_generic_infrastructure(en.get("entity_type", ""), en.get("value", ""))}
                  for en in built["related_entities"]],
        relationships=built["relationships"])
    _check_engine_text(report)
    return report


def _tier_summary(sources) -> dict:
    out: dict[str, list[str]] = {}
    for s in sources:
        out.setdefault(s.tier, []).append(s.ref)
    return out


def _check_engine_text(report: IntelligenceReport) -> None:
    """Final safety net: engine-authored conclusions (assessment, confidence factors/caps, next steps) must pass the
    guard, or generation fails and a FAILED report is stored instead of an unsupported conclusion. Executive-summary
    and key-finding lines are not checked because they quote stored finding titles verbatim (attributed to their
    source); the summary only highlights verified / corroborated findings."""
    for inf in report.assessment:
        T.guard(inf.statement)
    for text in report.confidence.factors + report.confidence.caps + [report.confidence.identity_statement]:
        T.guard(text)
    for text in report.next_steps:
        if not text.startswith("Resolve: "):   # quotes the discrepancy text recorded by a module
            T.guard(text)


# --- storage --------------------------------------------------------------------------------------------------------
def _scrub(msg: str) -> str:
    """Error text is stored and shown in the UI, so strip credentials with the same rules the log filter uses
    (key=..., auth headers, bearer tokens) as well as every registered secret value."""
    from core.configuration import _RedactFilter as F
    msg = F._pat.sub(r"\1=***", msg)
    msg = F._hdr.sub(lambda m: m.group(1) + ": ***", msg)
    return redact(F._bearer.sub("Bearer ***", msg))[:2000]


def generate_and_store(inv_id: int) -> tuple[IntelligenceReport | None, int | None]:
    """Generate and persist. Never raises: a failure is stored as a FAILED report with its error, so the
    investigation (already saved) is unaffected and the UI can show what went wrong."""
    db = get_db()
    try:
        report = generate(inv_id)
    except Exception as exc:  # noqa: BLE001 - the whole point is to isolate any failure
        msg = _scrub(f"{type(exc).__name__}: {exc}")
        get_logger().warning("Intelligence report generation failed for investigation %s: %s", inv_id, msg)
        try:
            return None, db.save_intel_report(inv_id, FAILED, ENGINE_VERSION, "", msg)
        except Exception:  # noqa: BLE001 - e.g. the investigation no longer exists
            return None, None
    row = db.save_intel_report(inv_id, report.status, ENGINE_VERSION, json.dumps(report.to_dict(), default=str), "")
    return report, row


def load_latest(inv_id: int) -> tuple[IntelligenceReport | None, dict | None]:
    """-> (report or None, stored row). A FAILED row returns (None, row) so the caller can show the error."""
    row = get_db().latest_intel_report(inv_id)
    if not row:
        return None, None
    row = dict(row)
    if not row["payload"]:
        return None, row
    return IntelligenceReport.from_dict(json.loads(row["payload"])), row


def open_or_generate(inv_id: int) -> tuple[IntelligenceReport | None, dict | None]:
    """Reopen the stored report; generate one for investigations saved before the engine existed."""
    report, row = load_latest(inv_id)
    if row is None:
        generate_and_store(inv_id)
        report, row = load_latest(inv_id)
    return report, row
