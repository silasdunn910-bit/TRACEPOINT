"""Sex Offender Registry Intelligence.

No registry is searched automatically (see providers/registry_sources.py for why). The operator searches the
official portal, reviews what it shows, and records the listing here. Registry records have no address or
location fields; a listing is not evidence of current whereabouts or of identity.
"""
from __future__ import annotations

from core.models import E_PERSON, UNVERIFIED, Finding, ModuleResult
from modules.records_shared import (CAT_REG_MANUAL, CAT_REG_REVIEWED, coverage_notes, evidence_block,
                                     resolve_jurisdiction, scope_evidence, source_record)
from providers import coverage as cov
from providers.records_common import (EMPTY_REGISTRY, IDENTITY_LIMIT, NO_SEARCH_RAN, REVIEWED, UNKNOWN,
                                       RegistryRecord, OfficialSource, SearchOutcome, check_source_url,
                                       classify_registry_status, clean_text, parse_date, reject_address_text,
                                       validate_person_name, validate_registry_id)
from providers.registry_sources import QUERY_KINDS, REGISTRY_SOURCES, search_source

REGISTRY_LIMIT = ("A registry listing is not proof of current whereabouts, and TRACEPOINT records no address or "
                  "location. The offense classification and status are the registry's own wording; TRACEPOINT infers "
                  "no additional offenses or statuses.")


def validate_query(term: str, kind: str) -> tuple[str, str]:
    if kind == "name":
        return validate_person_name(term)
    if kind == "registry_id":
        return validate_registry_id(term)
    return "", (f"Unsupported search type '{kind}' (use one of: {', '.join(QUERY_KINDS)}). Location searches "
                "(address, radius, ZIP) are deliberately not supported.")


def plan(jurisdiction) -> cov.SearchPlan:
    """Providers that apply to a jurisdiction (text, Jurisdiction or None = nationwide). Raises ValueError if invalid."""
    jur, err = resolve_jurisdiction(jurisdiction)
    if err:
        raise ValueError(err)
    return cov.plan(REGISTRY_SOURCES, jur, "registry", national_in_state=True)


def search(term: str, kind: str, jurisdiction=None) -> tuple[list[SearchOutcome], cov.CoverageReport]:
    """Search every compatible provider in the jurisdiction; returns the outcomes and the generated coverage report.
    Manual providers return instructions without any network traffic."""
    jur, err = resolve_jurisdiction(jurisdiction)
    if err:
        raise ValueError(err)
    return cov.execute("registry", REGISTRY_SOURCES, jur, term, kind, search_source, national_in_state=True)


def run_searches(term: str, kind: str, source_ids: list[str] | None = None, jurisdiction=None) -> list[SearchOutcome]:
    """Ask each chosen source (default: every catalogued source in the jurisdiction; nationwide if none given)."""
    if source_ids is None:
        return search(term, kind, jurisdiction)[0]
    sources = []
    for sid in source_ids:
        source = REGISTRY_SOURCES.get(sid)
        if source is None:
            raise ValueError(f"Unknown registry source: {sid}")
        sources.append(source)
    return cov.run_sources(sources, term, kind, search_source)


def manual_record(fields: dict) -> tuple[RegistryRecord | None, list[str]]:
    """Validate a listing the operator read on an official registry. Returns (record, errors)."""
    errors: list[str] = []
    source = REGISTRY_SOURCES.get(clean_text(fields.get("source_id"), 60))
    if source is None:
        return None, ["Choose one of the catalogued official registries."]
    name = clean_text(fields.get("displayed_name"), 160)
    reg_id = ""
    if clean_text(fields.get("registry_id")):
        reg_id, err = validate_registry_id(fields.get("registry_id", ""))
        if err:
            errors.append(err)
    if not (name or reg_id):
        errors.append("Enter the displayed name or the registry identification number.")
    dates = {}
    for key in ("registration_date", "source_updated"):
        dates[key], err = parse_date(fields.get(key, ""))
        if err:
            errors.append(f"{key.replace('_', ' ').title()}: {err}")
    offense = clean_text(fields.get("offense_classification"), 300)
    original = clean_text(fields.get("original_status"), 200)
    for label, text in (("Displayed name", name), ("Offense classification", offense), ("Status", original)):
        msg = reject_address_text(text, label)
        if msg:
            errors.append(msg)
    url, note = check_source_url(fields.get("source_url", ""), source)
    if errors:
        return None, errors
    return RegistryRecord(source_id=source.id, jurisdiction=clean_text(fields.get("jurisdiction"), 10).upper() or
                          source.jurisdiction, displayed_name=name, registry_id=reg_id, original_status=original,
                          status=classify_registry_status(original), offense_classification=offense,
                          registration_date=dates["registration_date"], source_updated=dates["source_updated"],
                          source_url=url, url_note=note, agency=source.agency, origin="manual"), []


def _finding(rec: RegistryRecord, source: OfficialSource, query: str, report: cov.CoverageReport | None = None) -> Finding:
    evidence = evidence_block((scope_evidence(report, source.id) if report else []) + [
        ("Registry / agency", rec.agency or source.agency), ("Registry jurisdiction", rec.jurisdiction),
        ("Name as displayed by registry", rec.displayed_name), ("Registry identification number", rec.registry_id),
        ("Registry-displayed status", rec.original_status), ("TRACEPOINT normalized status", rec.status),
        ("Offense classification as published", rec.offense_classification),
        ("Registration date", rec.registration_date), ("Registry updated", rec.source_updated),
        ("Entered", rec.retrieved_at), ("Origin", "entered by operator from the official registry"),
        ("Review status", REVIEWED), ("Official source", source.name)])
    limits = [IDENTITY_LIMIT, REGISTRY_LIMIT, source.limitations]
    if rec.status == UNKNOWN:
        limits.append("Status is UNKNOWN: the displayed status was missing or not one TRACEPOINT classifies.")
    else:
        limits.append(f"Normalized status {rec.status} is TRACEPOINT's reading of the registry's displayed status "
                      f"'{rec.original_status}'; the registry's own wording governs.")
    if rec.url_note:
        limits.append(rec.url_note)
    if not rec.source_url:
        limits.append("No official source URL was recorded for this listing.")
    return Finding(
        title=("Registry listing: " + (rec.displayed_name or rec.registry_id))[:160],
        description=("Listing entered by the operator from the official registry; it is an UNVERIFIED name/identifier "
                     "match and does not establish that it concerns the person searched."),
        source=source.name, confidence=UNVERIFIED, category=CAT_REG_MANUAL if rec.origin == "manual" else CAT_REG_REVIEWED,
        value=rec.identifier(), source_url=rec.source_url, evidence=evidence, limitations=" ".join(limits),
        query=query, source_type="registry", published_at=rec.registration_date)


def investigate(target: str, *, search_kind: str = "name", outcomes: list[SearchOutcome] | None = None,
                selected: list[RegistryRecord] | None = None, manual_records: list[dict] | None = None,
                source_ids: list[str] | None = None, jurisdiction=None,
                coverage: cov.CoverageReport | None = None) -> ModuleResult:
    """`jurisdiction`: None/'US' = nationwide request, 'NC'/'North Carolina' = one state, or a Jurisdiction.
    `outcomes`/`coverage` may be supplied by a caller that already ran the searches (the CLI does)."""
    term, err = validate_query(target, search_kind)
    result = ModuleResult("registry", term or clean_text(target, 160))
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
        pl = cov.plan(REGISTRY_SOURCES, jur, "registry", national_in_state=True) if source_ids is None else None
        coverage = cov.build_report("registry", jur, search_kind, pl, outcomes)
    cstatus = {e.provider_id: e.status for e in coverage.entries}
    result.notes.append(f"Search type: {search_kind}. Purpose: audit of public registry information for an authorized "
                        "subject, for public-safety awareness only. Listings below were entered by the operator "
                        "after manual review.")
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
    chosen: list[tuple[RegistryRecord, OfficialSource]] = []
    for rec in selected or []:
        hit = candidates.get(rec.key())
        if hit is None:
            result.errors.append("A selected listing was not returned by any searched source and was ignored.")
            continue
        chosen.append(hit)
    for fields in manual_records or []:
        rec, errs = manual_record(fields)
        if errs:
            result.errors.append("Manual listing rejected: " + " ".join(errs))
            continue
        chosen.append((rec, REGISTRY_SOURCES[rec.source_id]))

    seen: dict[str, RegistryRecord] = {}
    for rec, source in chosen:
        k = rec.key()
        if k in seen:
            if seen[k].status != rec.status:
                result.add(Finding(
                    title=f"Conflicting status for {rec.identifier()}",
                    description=f"Two entries for the same registry identifier disagree: '{seen[k].original_status}' "
                                f"({seen[k].status}) vs '{rec.original_status}' ({rec.status}).",
                    source=source.name, confidence=UNVERIFIED, category="contradiction", value=rec.identifier(),
                    source_url=rec.source_url, limitations="Check the official registry; one entry may be outdated or mistyped."))
            continue
        seen[k] = rec
        result.add(_finding(rec, source, term, coverage))

    unattached = max(0, returned - len([1 for r, _ in chosen if r.origin == "automated"]))
    if unattached:
        result.notes.append(f"{unattached} candidate listing(s) were returned but not attached after review; they are "
                            "not stored.")
    if not result.findings:
        if not ran_ok:
            result.notes.append(NO_SEARCH_RAN)
        elif returned == 0:
            result.notes.append(EMPTY_REGISTRY)
        else:
            result.notes.append("Candidate listings were returned but none was attached after review.")
    return result
