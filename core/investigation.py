"""Maps an investigation type to its module, enforces the authorization gate for
person-oriented identifiers, runs the module, and persists the result."""
from __future__ import annotations

from dataclasses import dataclass

from core.database import get_db
from core.models import ModuleResult
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


def run(inv_type: str, target: str, *, authorized: bool = False, persist: bool = True, **kwargs) -> tuple[ModuleResult, int | None]:
    """Run an investigation. For person-oriented types, `authorized` must be True.
    Returns (result, investigation_id or None)."""
    if inv_type not in _RUNNERS:
        raise ValueError(f"Unknown investigation type: {inv_type}")
    if requires_authorization(inv_type) and not authorized:
        raise PermissionError("Authorization not confirmed for a person-oriented identifier.")
    result = _RUNNERS[inv_type](target, **kwargs)
    # Keep the reported finding count identical to what will be stored: the DB collapses
    # fingerprint-duplicate findings on save, so collapse them here too before display.
    result.dedupe()
    inv_id = None
    if persist:
        db = get_db()
        inv_id = db.save_result(inv_type, target, result)
        if authorized and requires_authorization(inv_type):
            db.conn.execute("UPDATE investigations SET notes = notes || ? WHERE id=?",
                            ("\n[authorization affirmed by operator at run time]", inv_id))
            db.conn.commit()
    return result, inv_id
