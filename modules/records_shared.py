"""Shared evidence formatting for the Court Records and Registry modules.

Court cases and registry listings stay separate record types with separate finding categories; only the
formatting helpers are shared.
"""
from __future__ import annotations

from core.models import SourceRecord
from providers.coverage import CoverageReport
from providers.jurisdictions import US_NATIONWIDE, Jurisdiction, resolve
from providers.records_common import OfficialSource, SearchOutcome

# Finding categories (kept distinct on purpose).
CAT_COURT_REVIEWED = "court_record_reviewed"      # returned by an automated official source, attached by the operator
CAT_COURT_MANUAL = "court_record_manual"          # entered by the operator from the official portal
CAT_REG_REVIEWED = "registry_listing_reviewed"
CAT_REG_MANUAL = "registry_listing_manual"
COURT_CATEGORIES = (CAT_COURT_REVIEWED, CAT_COURT_MANUAL)
REGISTRY_CATEGORIES = (CAT_REG_REVIEWED, CAT_REG_MANUAL)
NOT_PROVIDED = "not provided by source"

_STATUS_FOR_SOURCE = {"ok": "ok", "error": "error", "manual": "skipped", "skipped": "skipped",
                      "not_configured": "not_configured"}


def source_record(outcome: SearchOutcome, coverage_status: str = "") -> SourceRecord:
    s: OfficialSource = outcome.source
    method = "automated search" if s.automated else "manual search required"
    label = f"[{coverage_status}] " if coverage_status else ""
    detail = (f"{label}{s.agency}; jurisdiction {s.jurisdiction}; {method}; auth: {s.auth} Coverage: PARTIAL - {s.coverage} "
              f"{outcome.detail}").strip()
    return SourceRecord(name=s.name, url=s.search_url, status=_STATUS_FOR_SOURCE.get(outcome.status, "error"),
                        detail=detail[:900], consulted_at=outcome.searched_at)


def evidence_block(pairs: list[tuple[str, str]]) -> str:
    return "\n".join(f"{k}: {v or NOT_PROVIDED}" for k, v in pairs)


def source_description(s: OfficialSource) -> str:
    return (f"{s.name} ({s.agency}); {s.level}/{s.jurisdiction}; "
            f"{'automated' if s.automated else 'manual'} search; coverage partial")


def resolve_jurisdiction(value) -> tuple[Jurisdiction | None, str]:
    """None -> nationwide request; a Jurisdiction passes through; text is resolved (error text if invalid)."""
    if value is None:
        return US_NATIONWIDE, ""
    if isinstance(value, Jurisdiction):
        return value, ""
    return resolve(value)


def coverage_notes(rep: CoverageReport) -> list[str]:
    """Notes saved with the investigation: human-readable scope/coverage lines plus the machine-readable report."""
    c = rep.counts()
    notes = [f"Search scope: {rep.scope}. Requested jurisdiction: {rep.requested}. Resolved jurisdiction: {rep.resolved}.",
             f"Search method: {rep.search_method}. Coverage: {rep.status} - {c['SEARCHED']} searched, {c['MANUAL']} manual, "
             f"{c['UNAVAILABLE']} unavailable, {c['FAILED']} failed, {c['SKIPPED']} skipped, "
             f"{c['NOT IMPLEMENTED']} jurisdiction(s) not implemented."]
    if rep.scope == "nationwide":
        notes.append("This was a NATIONWIDE REQUEST. " + ("Every source in scope was searched." if rep.complete_nationwide else
                     "It is not nationwide coverage: only the sources marked SEARCHED were searched."))
    notes.append(rep.to_marker_line())
    return notes


def scope_evidence(rep: CoverageReport, source_id: str) -> list[tuple[str, str]]:
    e = next((x for x in rep.entries if x.provider_id == source_id), None)
    return [("Search scope", rep.scope), ("Requested jurisdiction", rep.requested), ("Resolved jurisdiction", rep.resolved),
            ("Search method", rep.search_method), ("Provider status in this search", e.status if e else "not part of this search"),
            ("Coverage of this search", rep.status)]
