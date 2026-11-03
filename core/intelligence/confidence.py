"""Investigation completeness and the overall evidence assessment.

Both are fixed, documented rules over what was recorded. The assessment level describes how well the RECORDED
findings are supported; it is not a probability, says nothing about identity, and is never raised by the engine
beyond what the stored grades and source agreement support.
"""
from __future__ import annotations

from collections import Counter

from . import templates as T
from .models import (ANALYTICAL_INFERENCE, CLAIM_CLASSES, COMPLETE, CONTRADICTORY, CORROBORATED_CLAIM, FAILED, HIGH,
                     INCOMPLETE, INSUFFICIENT, LOW, MODERATE, PARTIAL, SINGLE_SOURCE_CLAIM, UNVERIFIED_CLAIM,
                     VERIFIED_FACT, ConfidenceAssessment, EvidenceItem)

_ORDER = {HIGH: 3, MODERATE: 2, LOW: 1, INSUFFICIENT: 0}


def completeness(built: dict) -> tuple[str, list[str]]:
    """-> (COMPLETE | PARTIAL | INCOMPLETE, reasons). An investigation with failures is never shown as successful."""
    inv, sources = built["investigation"], built["sources_consulted"]
    by = Counter(s["status"] for s in sources)
    incomplete, partial = [], []
    if inv.get("status") == "failed":
        return FAILED, ["The investigation module failed before completing; any partial data was not stored as "
                        "findings. See the recorded workflow stages for the failure."] +             [s["detail"] for s in built.get("workflow", []) if s.get("status") == "FAILED" and s.get("detail")][:3]
    if inv.get("status") == "complete_with_errors":
        incomplete.append("The collecting module reported errors during the investigation.")
    if by.get("error"):
        incomplete.append(f"{by['error']} source(s) failed: " + ", ".join(s["name"] for s in sources if s["status"] == "error"))
    if by.get("blocked"):
        incomplete.append(f"{by['blocked']} source(s) blocked automated checks; their results are inconclusive.")
    if not sources:
        incomplete.append("No source was recorded as consulted.")
    elif not by.get("ok"):
        incomplete.append("No source returned a successful automated response.")
    for status, label in (("not_configured", "not configured"), ("skipped", "skipped"), ("manual", "manual-only")):
        if by.get(status):
            partial.append(f"{by[status]} source(s) {label}: " + ", ".join(s["name"] for s in sources if s["status"] == status))
    rr = built.get("records_review")
    if rr:
        cov = rr["search_coverage"]["status"]
        if cov == "NONE":
            incomplete.append("Records search coverage is NONE: no official source was searched automatically.")
        elif cov == "NOT RECORDED":
            partial.append("Records search coverage was not recorded for this investigation.")
        elif cov != "COMPLETE":
            partial.append(f"Records search coverage is {cov}: " + rr["search_coverage"]["summary"])
    if built.get("findings") == [] and not incomplete:
        # A search that ran and found nothing is a legitimate outcome, but it is not a successful investigation:
        # it never reaches COMPLETE, and absence of results is not evidence of absence.
        partial.insert(0, "The search completed with zero findings. This is not a successful result and does not show "
                          "that no public information exists.")
    if incomplete:
        return INCOMPLETE, incomplete + partial
    if partial:
        return PARTIAL, partial
    return COMPLETE, ["Every consulted source responded and no errors were reported."]


def class_counts(items: list[EvidenceItem]) -> dict:
    live = [e for e in items if not e.duplicate_of]
    c = Counter(e.claim_class for e in live)
    out = {k: c.get(k, 0) for k in CLAIM_CLASSES}
    out["total"] = len(live)
    out["duplicates"] = len(items) - len(live)
    return out


def assess(items: list[EvidenceItem], status: str, n_discrepancies: int, identity_sensitive: bool) -> ConfidenceAssessment:
    counts = class_counts(items)
    total = counts["total"]
    factors, caps = [], []
    strong = counts[VERIFIED_FACT] + counts[CORROBORATED_CLAIM]
    weak = counts[SINGLE_SOURCE_CLAIM] + counts[UNVERIFIED_CLAIM]

    if total == 0:
        level = INSUFFICIENT
        factors.append("No findings were recorded, so there is nothing to assess. " + T.ABSENCE_STATEMENT)
    elif strong == 0:
        level = LOW
        factors.append(f"None of the {total} findings is a verified fact or a corroborated claim.")
    elif strong / total >= 0.5:
        level = HIGH
        factors.append(f"{strong} of {total} findings are verified facts or corroborated claims.")
    else:
        level = MODERATE
        factors.append(f"Only {strong} of {total} findings are verified facts or corroborated claims; "
                       f"{weak} are single-source or unverified.")
    if counts[ANALYTICAL_INFERENCE]:
        factors.append(f"{counts[ANALYTICAL_INFERENCE]} finding(s) are module-derived comparisons, not observations.")
    if counts["duplicates"]:
        factors.append(f"{counts['duplicates']} repeated finding(s) from the same origin were counted once.")

    def cap(limit: str, why: str):
        nonlocal level
        caps.append(why)
        if _ORDER[level] > _ORDER[limit]:
            level = limit

    if n_discrepancies or counts[CONTRADICTORY]:
        cap(MODERATE, f"{max(n_discrepancies, 1)} unresolved discrepancy(ies) limit the assessment to MODERATE at most.")
    if status == FAILED:
        cap(INSUFFICIENT, "The investigation FAILED; nothing can be assessed.")
    elif status == INCOMPLETE:
        cap(MODERATE, "The investigation is INCOMPLETE; the assessment is limited to MODERATE at most.")
    elif status == PARTIAL:
        factors.append("Coverage is partial: some sources were not configured, skipped or manual-only.")
    missing_url = [e for e in items if not e.duplicate_of and "no source URL recorded" in e.metadata_gaps]
    if total and len(missing_url) / total > 0.5:
        cap(MODERATE, f"{len(missing_url)} of {total} findings have no source URL to check them against.")

    scope = ("How well the recorded findings are supported by their sources. It is a qualitative rule-based grade, "
             "not a probability, and it is not an assessment of the subject.")
    identity = T.IDENTITY_STATEMENT + (" " + T.CONDUCT_STATEMENT if identity_sensitive else "")
    return ConfidenceAssessment(level, scope, factors, caps, counts, identity)
