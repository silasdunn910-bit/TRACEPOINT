"""Maps an investigation type to its module, enforces the authorization gate for
person-oriented identifiers, runs the module, and persists the result."""
from __future__ import annotations

from dataclasses import dataclass

from core.database import get_db
from core.models import ModuleResult, now_iso
from modules import (court_records_intel, domain_intel, email_intel, ip_intel, name_intel, phone_intel, registry_intel,
                     security_intel, social_intel, username_intel)

# Identifier classes that can concern a specific person. These require the caller to
# affirm the identifier is their own or one they are authorized to audit.
PERSON_ORIENTED = {"email", "phone", "username", "social", "name", "court", "registry"}

INFRASTRUCTURE = {"domain", "ip", "security"}

AUTHORIZATION_TEXT = (
    "This identifier can belong to a specific person. TRACEPOINT is for auditing your own\n"
    "digital footprint or subjects you are explicitly authorized to investigate (e.g. your\n"
    "own accounts, your employer's assets in a sanctioned engagement, or a consenting subject).\n"
    "It must not be used to profile, locate, surveil or build a dossier on anyone else."
)


@dataclass
class InvSpec:
    type: str
    label: str
    person_oriented: bool
    description: str


SPECS: dict[str, InvSpec] = {
    "email": InvSpec("email", "Email Intelligence", True, "Validate an address and audit its domain's mail security & public exposure."),
    "phone": InvSpec("phone", "Phone Intelligence", True, "Normalize and classify a number; show public listings."),
    "username": InvSpec("username", "Username Intelligence", True, "Audit where a handle has public profiles; impersonation/duplicate risk."),
    "domain": InvSpec("domain", "Domain Intelligence", False, "RDAP, DNS, email-auth, certificate transparency, history, reputation."),
    "ip": InvSpec("ip", "IP Intelligence", False, "Validation, RDAP network owner, ASN, reverse DNS, geolocation, reputation."),
    "social": InvSpec("social", "Social Intelligence", True, "Analyze a supplied public profile URL and its disclosed links."),
    "security": InvSpec("security", "Security Intelligence", False, "Phishing & suspicious-infrastructure indicators for a domain/URL."),
    "name": InvSpec("name", "Name Intelligence", True, "Search public sources for a stated, authorized research purpose; name hits do not establish identity."),
    "court": InvSpec("court", "Court Records Intelligence", True, "Official court sources: search where permitted, otherwise link to the official portal; attach only records you reviewed. Name matches are not identity."),
    "registry": InvSpec("registry", "Sex Offender Registry Intelligence", True, "Official registries (NSOPW, state): manual lookup guidance and operator-reviewed listings. No addresses stored; a listing is not identity or whereabouts."),
}

_RUNNERS = {
    "email": lambda t, **k: email_intel.investigate(t, **k),
    "phone": lambda t, **k: phone_intel.investigate(t, **k),
    "username": lambda t, **k: username_intel.investigate(t, **k),
    "domain": lambda t, **k: domain_intel.investigate(t, **k),
    "ip": lambda t, **k: ip_intel.investigate(t, **k),
    "social": lambda t, **k: social_intel.investigate(t, **k),
    "security": lambda t, **k: security_intel.investigate(t, **k),
    "name": lambda t, **k: name_intel.investigate(t, **k),
    "court": lambda t, **k: court_records_intel.investigate(t, **k),
    "registry": lambda t, **k: registry_intel.investigate(t, **k),
}


def requires_authorization(inv_type: str) -> bool:
    return inv_type in PERSON_ORIENTED


def _scrub(text: str) -> str:
    from core.security import redact
    return redact(text)[:500]


def run(inv_type: str, target: str, *, authorized: bool = False, persist: bool = True, intel_report: bool = True,
        **kwargs) -> tuple[ModuleResult, int | None]:
    """Run an investigation through the recorded workflow (core.workflow). For person-oriented types,
    `authorized` must be True. Returns (result, investigation_id or None).

    * An unknown type or missing authorization raises before anything is collected or stored.
    * If the module itself raises, the failure is recorded (Search Execution = FAILED), nothing is invented, and a
      record with status 'failed' is stored so the failure is visible and auditable; no half-written data is kept.
    * Every persisted investigation ends with the Intelligence Report stage: a report is generated and stored
      (core.intelligence). That stage never raises; a failure is stored as a FAILED report and the saved
      investigation is unaffected."""
    from core import source_registry, workflow as W
    wf = W.Workflow()
    if inv_type not in _RUNNERS:
        raise ValueError(f"Unknown investigation type: {inv_type}")
    wf.record(W.STAGES[0], W.OK, f"type={inv_type}")
    if requires_authorization(inv_type):
        if not authorized:
            raise PermissionError("Authorization not confirmed for a person-oriented identifier.")
        wf.record("Authorization", W.OK, "operator affirmed authorization at run time")
    else:
        wf.record("Authorization", W.NOT_REQUIRED, "infrastructure identifier")

    started = now_iso()
    final_status = ""
    try:
        result = _RUNNERS[inv_type](target, **kwargs)
    except Exception as exc:  # noqa: BLE001 - a module crash is recorded, never silently lost
        result = ModuleResult(inv_type, target)
        msg = _scrub(f"{type(exc).__name__}: {exc}")
        result.errors.append(f"Investigation module failed: {msg}")
        wf.record("Search Execution", W.FAILED, msg, started)
        wf.record("Source Collection", W.NOT_RUN, "search execution failed")
        final_status = W.ST_FAILED
    else:
        ok_src = sum(1 for s in result.sources if s.status == "ok")
        bad_src = sum(1 for s in result.sources if s.status in ("error", "blocked"))
        if result.errors and not result.findings and not ok_src:
            wf.record("Search Execution", W.FAILED, f"{len(result.errors)} error(s); no source answered", started)
        elif result.errors:
            wf.record("Search Execution", W.PARTIAL, f"{len(result.errors)} error(s) reported", started)
        else:
            wf.record("Search Execution", W.OK,
                      "completed" + ("" if result.findings else " with zero findings (not a negative result)"), started)
        if not result.sources:
            wf.record("Source Collection", W.FAILED, "no source was recorded as consulted")
        elif not ok_src:
            wf.record("Source Collection", W.FAILED, "no source returned a successful response")
        elif bad_src or result.errors:
            wf.record("Source Collection", W.PARTIAL, f"{ok_src} source(s) answered, {bad_src} failed or blocked")
        else:
            wf.record("Source Collection", W.OK, f"{ok_src} source(s) answered")
    # Keep the reported finding count identical to what will be stored: the DB collapses
    # fingerprint-duplicate findings on save, so collapse them here too before display.
    removed = result.dedupe()
    wf.record("Deduplication", W.OK, f"{removed} duplicate finding(s) collapsed")
    wf.record("AI Analysis", W.SKIPPED, "on demand only (local model); not run automatically")
    inv_id = None
    if persist:
        db = get_db()
        inv_id = db.save_result(inv_type, target, result, final_status)
        wf.record("Database Persistence", W.OK, f"saved as investigation id {inv_id}")
        if authorized and requires_authorization(inv_type):
            db.conn.execute("UPDATE investigations SET notes = notes || ? WHERE id=?",
                            ("\n[authorization affirmed by operator at run time]", inv_id))
            db.conn.commit()
        try:
            source_registry.refresh(inv_id)
        except Exception as exc:  # noqa: BLE001 - derived data; never lose the saved investigation over it
            wf.record("Source Collection", W.PARTIAL, f"source registry not stored: {type(exc).__name__}")
        db.save_stages(inv_id, wf.as_list())
        if intel_report:
            from core import intelligence  # late import: the engine imports this module for type labels
            report, row = intelligence.generate_and_store(inv_id)
            if report is None:
                wf.record("Evidence Assessment", W.NOT_RUN, "report generation failed")
                wf.record("Entity Resolution", W.NOT_RUN, "report generation failed")
                wf.record("Intelligence Report", W.FAILED, "report generation failed; see stored error")
                if not final_status:   # the investigation record is valid but its analysis stage did not finish
                    db.conn.execute("UPDATE investigations SET status='complete_with_errors' WHERE id=? AND "
                                    "status='complete'", (inv_id,))
                    db.conn.commit()
            else:
                wf.record("Evidence Assessment", W.OK, f"{len(report.evidence)} finding(s) graded")
                wf.record("Entity Resolution", W.OK,
                          f"{report.overview.get('entities', 0)} entit(ies), "
                          f"{report.overview.get('relationships', 0)} relationship(s) "
                          "(identity is never resolved from names alone)")
                wf.record("Intelligence Report", W.OK, f"report status {report.status}")
        else:
            for st in ("Evidence Assessment", "Entity Resolution", "Intelligence Report"):
                wf.record(st, W.SKIPPED, "report generation disabled by caller")
        db.save_stages(inv_id, wf.as_list())
    result.stages = wf.as_list()
    return result, inv_id
