"""Court Records Intelligence.

Searches official court sources where a documented automated search exists, links the operator to the official
portals otherwise, and stores only records the operator has reviewed and chosen to attach. Candidates that are
not attached are never stored. Nothing in this module decides that a record belongs to the person searched.
"""
from __future__ import annotations

from core.models import E_PERSON, UNVERIFIED, Finding, ModuleResult
from modules.records_shared import (CAT_COURT_MANUAL, CAT_COURT_REVIEWED, coverage_notes, evidence_block,
                                     resolve_jurisdiction, scope_evidence, source_record)
from providers import coverage as cov
from providers.court_sources import COURT_SOURCES, search_source
from providers.records_common import (CIVIL, CONVICTED, CRIMINAL, EMPTY_COURT, IDENTITY_LIMIT, NO_SEARCH_RAN, OPINION,
                                       RECORD_TYPES, REVIEWED, TYPE_UNKNOWN, UNKNOWN, CourtRecord, OfficialSource,
                                       SearchOutcome, check_source_url, classify_court_status, clean_text,
                                       parse_date, reject_address_text, validate_case_number, validate_person_name)

QUERY_KINDS = ("name", "case_number")


def validate_query(term: str, kind: str) -> tuple[str, str]:
    if kind == "name":
        return validate_person_name(term)
    if kind == "case_number":
        return validate_case_number(term)
    return "", f"Unsupported search type '{kind}' (use one of: {', '.join(QUERY_KINDS)})."


def plan(jurisdiction) -> cov.SearchPlan:
    """Providers that apply to a jurisdiction (text, Jurisdiction or None = nationwide). Raises ValueError if invalid."""
    jur, err = resolve_jurisdiction(jurisdiction)
    if err:
        raise ValueError(err)
    return cov.plan(COURT_SOURCES, jur, "court")


def search(term: str, kind: str, jurisdiction=None) -> tuple[list[SearchOutcome], cov.CoverageReport]:
    """Search every compatible provider in the jurisdiction; returns the outcomes and the generated coverage report.
    Manual providers return instructions without any network traffic."""
    jur, err = resolve_jurisdiction(jurisdiction)
    if err:
        raise ValueError(err)
    return cov.execute("court", COURT_SOURCES, jur, term, kind, search_source)


def run_searches(term: str, kind: str, source_ids: list[str] | None = None, jurisdiction=None) -> list[SearchOutcome]:
    """Ask each chosen source (default: every catalogued source in the jurisdiction; nationwide if none given)."""
    if source_ids is None:
        return search(term, kind, jurisdiction)[0]
    sources = []
    for sid in source_ids:
        source = COURT_SOURCES.get(sid)
        if source is None:
            raise ValueError(f"Unknown court source: {sid}")
        sources.append(source)
    return cov.run_sources(sources, term, kind, search_source)


def manual_record(fields: dict) -> tuple[CourtRecord | None, list[str]]:
    """Validate a record the operator read on an official portal. Returns (record, errors)."""
    errors: list[str] = []
    source = COURT_SOURCES.get(clean_text(fields.get("source_id"), 60))
    if source is None:
        return None, ["Choose one of the catalogued official sources."]
    case_number = ""
    if clean_text(fields.get("case_number")):
        case_number, err = validate_case_number(fields.get("case_number", ""))
        if err:
            errors.append(err)
    title = clean_text(fields.get("title"), 300)
    if not (case_number or title):
        errors.append("Enter a case number or a case title.")
    rtype = clean_text(fields.get("record_type"), 30).upper() or TYPE_UNKNOWN
    if rtype not in RECORD_TYPES:
        errors.append(f"Record type must be one of: {', '.join(RECORD_TYPES)}.")
        rtype = TYPE_UNKNOWN
    dates = {}
    for key in ("filing_date", "disposition_date", "source_updated"):
        dates[key], err = parse_date(fields.get(key, ""))
        if err:
            errors.append(f"{key.replace('_', ' ').title()}: {err}")
    original = clean_text(fields.get("original_status"), 200)
    charges = clean_text(fields.get("charges"), 500)
    court = clean_text(fields.get("court"), 200)
    for label, text in (("Case title", title), ("Charges", charges), ("Court", court)):
        msg = reject_address_text(text, label)
        if msg:
            errors.append(msg)
    url, note = check_source_url(fields.get("source_url", ""), source)
    if errors:
        return None, errors
    return CourtRecord(source_id=source.id, jurisdiction=source.jurisdiction, court=court, case_number=case_number,
                       title=title, displayed_name=clean_text(fields.get("displayed_name"), 160), record_type=rtype,
                       original_status=original, status=classify_court_status(original, rtype), charges=charges,
                       filing_date=dates["filing_date"], disposition_date=dates["disposition_date"],
                       source_updated=dates["source_updated"], source_url=url, url_note=note, origin="manual"), []


def _finding(rec: CourtRecord, source: OfficialSource, query: str, report: cov.CoverageReport | None = None) -> Finding:
    manual = rec.origin == "manual"
    evidence = evidence_block((scope_evidence(report, source.id) if report else []) + [
        ("Record type", rec.record_type), ("Court / agency", rec.court or source.agency),
        ("Jurisdiction", f"{source.level}/{rec.jurisdiction}"), ("Case number", rec.case_number),
        ("Record identifier", rec.record_id), ("Case title as published", rec.title),
        ("Name as displayed", rec.displayed_name), ("Original source status", rec.original_status),
        ("TRACEPOINT normalized status", rec.status), ("Charges as published", rec.charges),
        ("Filing date", rec.filing_date), ("Disposition date", rec.disposition_date),
        ("Date shown by source", rec.published_date), ("Source updated", rec.source_updated),
        ("Retrieved/entered", rec.retrieved_at), ("Origin", "entered by operator from the official portal" if manual
                                                    else "returned by the official source's automated search"),
        ("Review status", REVIEWED), ("Official source", source.name)])
    limits = [IDENTITY_LIMIT, source.limitations]
    if rec.status == UNKNOWN:
        limits.append("Status is UNKNOWN: the source text did not state an outcome TRACEPOINT can classify. "
                      "A charge, arrest or filing is not a conviction.")
    else:
        limits.append(f"Normalized status {rec.status} is derived from the source's wording "
                      f"'{rec.original_status}'; confirm it in the official record.")
    if rec.record_type == CIVIL:
        limits.append("Civil case: not a criminal proceeding.")
    if rec.url_note:
        limits.append(rec.url_note)
    if not rec.source_url:
        limits.append("No official source URL was recorded for this record.")
    return Finding(
        title=("Court record: " + (rec.title or rec.case_number))[:160],
        description=("Record entered by the operator from the official portal; it is an UNVERIFIED name/identifier match "
                     "and does not establish that it concerns the person searched." if manual else
                     "Record returned by an official source's search and attached by the operator after manual review; "
                     "it is an UNVERIFIED name match and does not establish that it concerns the person searched."),
        source=source.name, confidence=UNVERIFIED, category=CAT_COURT_MANUAL if manual else CAT_COURT_REVIEWED,
        value=rec.identifier(), source_url=rec.source_url, evidence=evidence, limitations=" ".join(limits),
        query=query, source_type="court", published_at=rec.published_date or rec.filing_date)


def investigate(target: str, *, search_kind: str = "name", outcomes: list[SearchOutcome] | None = None,
                selected: list[CourtRecord] | None = None, manual_records: list[dict] | None = None,
                source_ids: list[str] | None = None, jurisdiction=None,
                coverage: cov.CoverageReport | None = None) -> ModuleResult:
    """`jurisdiction`: None/'US' = nationwide request, 'NC'/'North Carolina' = one state, or a Jurisdiction.
    `outcomes`/`coverage` may be supplied by a caller that already ran the searches (the CLI does)."""
    term, err = validate_query(target, search_kind)
    result = ModuleResult("court", term or clean_text(target, 160))
    if err:
        result.errors.append(err)
        return result
    jur, jerr = resolve_jurisdiction(jurisdiction)
    if jerr:
        result.errors.append(jerr)
        return result
    if outcomes is None:
        if source_ids is None:
            outcomes, coverage = search(term, search_kind, jur)
        else:
            outcomes = run_searches(term, search_kind, source_ids)
    if coverage is None:
        pl = cov.plan(COURT_SOURCES, jur, "court") if source_ids is None else None
        coverage = cov.build_report("court", jur, search_kind, pl, outcomes)
    cstatus = {e.provider_id: e.status for e in coverage.entries}
    result.notes.append(f"Search type: {search_kind}. Purpose: audit of public court records for an authorized subject. "
                        "Records below were attached by the operator after manual review.")
    result.notes.extend(coverage_notes(coverage))
    for o in outcomes:
        result.sources.append(source_record(o, cstatus.get(o.source.id, "")))
        if o.status == "error":
            result.errors.append(f"{o.source.name}: {o.detail}")
        elif o.status == "not_configured":
            result.errors.append(f"{o.source.name}: not configured. {o.detail}")
    if search_kind == "name":
        result.entity(E_PERSON, term, UNVERIFIED, "operator query")

    candidates = {r.key(): (r, o.source) for o in outcomes for r in o.records}
    returned = sum(len(o.records) for o in outcomes)
    ran_ok = [o for o in outcomes if o.status == "ok"]

    chosen: list[tuple[CourtRecord, OfficialSource]] = []
    for rec in selected or []:
        hit = candidates.get(rec.key())
        if hit is None:
            result.errors.append("A selected record was not returned by any searched source and was ignored "
                                 "(use manual entry for records you read on an official portal).")
            continue
        chosen.append(hit)
    for fields in manual_records or []:
        rec, errs = manual_record(fields)
        if errs:
            result.errors.append("Manual record rejected: " + " ".join(errs))
            continue
        chosen.append((rec, COURT_SOURCES[rec.source_id]))

    # Never merge records; collapse exact duplicates and flag conflicting status for the same identifier.
    seen: dict[str, CourtRecord] = {}
    for rec, source in chosen:
        k = rec.key()
        if k in seen:
            if seen[k].status != rec.status:
                result.add(Finding(
                    title=f"Conflicting status for {rec.identifier()}",
                    description=f"Two entries for the same source and identifier disagree: "
                                f"'{seen[k].original_status}' ({seen[k].status}) vs '{rec.original_status}' ({rec.status}).",
                    source=source.name, confidence=UNVERIFIED, category="contradiction", value=rec.identifier(),
                    source_url=rec.source_url, limitations="Check the official record; one entry may be outdated or mistyped."))
            continue
        seen[k] = rec
        result.add(_finding(rec, source, term, coverage))

    unattached = max(0, returned - len([1 for r, _ in chosen if r.origin == "automated"]))
    if unattached:
        result.notes.append(f"{unattached} candidate record(s) were returned but not attached after review; they are "
                            "not stored.")
    if not result.findings:
        if not ran_ok:
            result.notes.append(NO_SEARCH_RAN)
        elif returned == 0:
            result.notes.append(EMPTY_COURT)
        else:
            result.notes.append("Candidate records were returned but none was attached after review.")
    return result
