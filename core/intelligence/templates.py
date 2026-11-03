"""Fixed analytical wording used by the report engine.

All narrative text the engine produces comes from here, so it can be reviewed in one place. The text explains
what kinds of evidence mean and how they can mislead; it never asserts anything about the subject beyond the
evidence. `guard()` is a final safety net that rejects engine-written statements implying criminality,
dangerousness, wrongdoing or identity, which no rule-based analysis of public evidence can establish.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

PERSON = "person-oriented"
INFRASTRUCTURE = "infrastructure / network"
CYBER = "cybersecurity"
PUBLIC_RECORD = "government / public record"
GENERIC = "general"


@dataclass
class Profile:
    family: str
    subject_noun: str
    purpose: str
    identity_sensitive: bool
    next_steps: list[str] = field(default_factory=list)
    standing_questions: list[str] = field(default_factory=list)


_PERSON_STEPS = [
    "Confirm the operator's authorization to audit this identifier is documented for the record.",
    "Open each source URL and review the original page; search snippets and metadata are not the record itself.",
    "Treat every name or handle match as a lead only; do not link accounts or people without a shared, verified identifier.",
]
_PERSON_QUESTIONS = [
    "Do any of the recorded matches actually refer to the subject? This report does not establish identity.",
]

PROFILES: dict[str, Profile] = {
    "email": Profile(PERSON, "email address", "audit an address and its domain's public exposure", True,
                     _PERSON_STEPS + ["If breach exposure was found, rotate the affected credentials and enable MFA."],
                     _PERSON_QUESTIONS),
    "phone": Profile(PERSON, "phone number", "classify a number and review public listings", True,
                     _PERSON_STEPS + ["Remember numbering-plan geography and carrier data can change after porting."],
                     _PERSON_QUESTIONS),
    "username": Profile(PERSON, "username", "audit where a handle has public profiles", True,
                        _PERSON_STEPS + ["Check each profile for impersonation or abandoned accounts that could be reclaimed."],
                        _PERSON_QUESTIONS + ["Are profiles with this handle controlled by the same person? Handles are not unique identifiers."]),
    "social": Profile(PERSON, "public profile", "analyze a supplied public profile and its disclosed links", True,
                      _PERSON_STEPS, _PERSON_QUESTIONS),
    "name": Profile(PERSON, "name", "search public sources for a stated research purpose", True,
                    _PERSON_STEPS + ["Narrow the research with a verified, non-name identifier before drawing any conclusion."],
                    _PERSON_QUESTIONS + ["How many different people share this name in the sources searched?"]),
    "domain": Profile(INFRASTRUCTURE, "domain", "assess registration, DNS, mail security and history", False,
                      ["Re-check DNS and RDAP directly against the authoritative registry for any value that matters.",
                       "Review mail-authentication gaps (SPF/DMARC/DKIM) with the domain owner if the audit is authorized."]),
    "ip": Profile(INFRASTRUCTURE, "IP address", "assess network ownership, routing and reputation", False,
                  ["Confirm ownership with the RIR's RDAP record rather than geolocation providers.",
                   "Interpret reputation in context: shared, cloud and VPN addresses accumulate reports from other users."]),
    "security": Profile(CYBER, "domain or URL", "assess phishing and suspicious-infrastructure indicators", False,
                        ["Validate indicators in an isolated environment before acting; do not visit suspected phishing pages directly.",
                         "Report confirmed phishing to the hosting provider or registrar's abuse contact."],
                        ["Which indicators reflect deliberate abuse and which are configuration weaknesses?"]),
    "court": Profile(PUBLIC_RECORD, "court-record search term", "review official court sources", True,
                     ["Search every source marked MANUAL at its official portal; TRACEPOINT did not search them.",
                      "Obtain the official record from the court before relying on any detail; summaries can be incomplete.",
                      "Confirm identity through identifiers in the official record, never through a name match."],
                     ["Do any attached records concern the person searched? A name match is not identity.",
                      "What is the final disposition of each attached case? A charge is not a conviction."]),
    "registry": Profile(PUBLIC_RECORD, "registry search term", "review official registry listings", True,
                        ["Search every source marked MANUAL at its official portal; TRACEPOINT did not search them.",
                         "Use registry information only for lawful public-safety awareness. Never use it to contact, "
                         "locate, threaten or harass anyone."],
                        ["Does any listing concern the person searched? A name match is not identity.",
                         "Is the listing current? A listing is not proof of current whereabouts."]),
}

GENERIC_PROFILE = Profile(GENERIC, "subject", "investigate the supplied identifier", True,
                          ["Open each source URL and review the original material before relying on it.",
                           "Seek an independent second origin for every single-source claim that matters."],
                          ["Does the evidence concern the intended subject? This report does not establish identity."])


def profile_for(inv_type: str) -> Profile:
    """Unknown (future) investigation types get the cautious generic profile: identity-sensitive by default."""
    return PROFILES.get(inv_type, GENERIC_PROFILE)


# --- why a category matters, and how it can mislead ---------------------------------------------------------------
# (significance, alternative interpretations)
CATEGORY_NOTES: dict[str, tuple[str, list[str]]] = {
    "email-auth": ("Mail-authentication records decide whether others can send convincing spoofed mail from this domain.",
                   ["A missing record may be intentional for a domain that sends no mail."]),
    "mail": ("Mail exchangers show where the domain receives mail.", ["Third-party mail hosting is common and shared."]),
    "dns": ("DNS records describe how the name currently resolves.", ["DNS changes frequently; values are a point-in-time view."]),
    "registration": ("Registration data shows who sponsors the domain and when key lifecycle events happened.",
                     ["Registrant data is frequently privacy-redacted; a proxy organization is not the owner."]),
    "network": ("Network ownership shows which organization routes the address.",
                ["The network operator is usually a hosting provider or ISP, not the end user."]),
    "geo": ("Network geolocation estimates where an address block is registered or routed.",
            ["Geolocation describes networks, not people; VPNs, proxies, mobile carriers and cloud hosting move it."]),
    "reputation": ("Reputation verdicts are third-party opinions about observed activity.",
                   ["Shared, cloud, VPN and recycled addresses inherit reports caused by other users.",
                    "A clean verdict means no reports were seen, not that the asset is safe."]),
    "breach": ("Breach listings indicate credentials or data may have been exposed.",
               ["Exposure says nothing about the conduct of the account holder; an address can be entered by anyone."]),
    "subdomains": ("Hostnames in certificate logs reveal attack surface and services.",
                   ["CT logs keep historical names that may no longer exist."]),
    "history": ("Archive captures show how the asset looked in the past.", ["Archives are incomplete samples."]),
    "phishing-indicator": ("Phishing indicators are traits commonly seen in malicious infrastructure.",
                           ["Many indicators also occur on legitimate new or poorly configured sites; an indicator is not a verdict."]),
    "security-weakness": ("Configuration weaknesses can be exploited but are not evidence of compromise.",
                          ["The weakness may be mitigated by controls not visible externally."]),
    "url-analysis": ("URL structure can reveal deceptive patterns.", ["Unusual URLs are common in legitimate tracking links."]),
    "profile": ("A public profile shows what an account discloses about itself.",
                ["Profile content is self-asserted and can be fabricated or impersonated."]),
    "profiles": ("Handle availability across platforms shows where an account with this name exists.",
                 ["The same handle on different platforms is frequently held by different people."]),
    "profiles-inconclusive": ("Some platforms could not be checked automatically.", ["Absence of a result is not absence of an account."]),
    "name_match": ("A page mentioning the searched name is a lead for manual review.",
                   ["Names are shared by many people; a match does not identify the subject."]),
    "contextual_match": ("A page matching the name and research context is a stronger lead, still unverified.",
                         ["Context words are common; the page may concern a different person."]),
    "unresolved_candidate": ("A search result without the name in its visible text is an unresolved lead.",
                             ["It may be entirely unrelated."]),
    "numbering-plan": ("Numbering-plan data describes how a number was allocated.",
                       ["Allocation geography is not a person's location; numbers are ported and reassigned."]),
    "carrier-metadata": ("Carrier data shows the allocating carrier.", ["Numbers are ported between carriers."]),
    "validation": ("Validation shows whether the identifier is well-formed.", []),
    "syntax": ("Syntax checks show whether the identifier is well-formed.", []),
    "classification": ("Classification places the identifier in a known category (e.g. webmail, disposable).",
                       ["Category lists are community-maintained and can be out of date."]),
    "contradiction": ("Contradictions mark where sources disagree and need resolution.", []),
    "comparison": ("Comparisons relate values across sources.", ["Agreement can reflect shared upstream data, not independence."]),
    "independently_corroborated": ("Independent sources reporting the same value strengthen a claim.",
                                   ["Sources may copy one another or share an owner."]),
}

RECORD_CATEGORY_NOTE = ("An official record or listing was attached after operator review.",
                        ["A name match is not identity: the record may concern a different person.",
                         "An arrest or charge is not a conviction; a listing is not proof of current whereabouts."])

DEFAULT_NOTE = ("Recorded by the collecting module as part of this investigation.",
                ["The source may be incomplete or out of date."])


def category_note(category: str) -> tuple[str, list[str]]:
    if category.startswith(("court", "registry")):
        return RECORD_CATEGORY_NOTE
    return CATEGORY_NOTES.get(category, DEFAULT_NOTE)


# --- standing statements -------------------------------------------------------------------------------------------
CORRELATION_CAVEAT = ("Co-occurrence is correlation, not causation: it shows that identifiers appeared together in "
                      "public data, not that one caused, controls or explains the other.")
IDENTITY_STATEMENT = ("No identity attribution is made. Matching names, handles, numbers or metadata do not establish "
                      "that records, accounts or people are the same.")
CONDUCT_STATEMENT = ("No inference of criminality, dangerousness or wrongdoing is drawn from associations, names, "
                     "reputation verdicts or unverified allegations.")
ABSENCE_STATEMENT = "Absence of evidence in the sources searched is not evidence of absence elsewhere."
ENGINE_LIMITS = [
    "Claim classes and the overall assessment are rule-based summaries of stored grades and source agreement; "
    "they are not statistical probabilities and add no new evidence.",
    "Source-type tiers are assigned by fixed rules from the source name and URL; they describe the kind of source, "
    "not its accuracy in this case.",
    "Independence is judged by distinct URL hosts / source names; sources that copy one another can still look independent.",
]

# --- guard against unsupported conclusions ------------------------------------------------------------------------
# Engine-authored text must never assert these about a subject. Third-party text (titles, evidence) is quoted as
# such and is not passed through the guard; the guard applies to what the engine itself concludes.
_PROHIBITED = [
    r"\b(is|are|was|were)\s+(a\s+)?(criminal|guilty|dangerous|fraudster|offender|terrorist|predator|scammer)\b",
    r"\bcommitted\b", r"\bconfirmed\s+(identity|match)\b", r"\bidentity\s+(is\s+)?(confirmed|established|proven)\b",
    r"\bis\s+the\s+same\s+person\b", r"\bproves?\s+(that\s+)?(he|she|they|the\s+subject)\b",
    r"\b(likely|probably)\s+(guilty|criminal|dangerous|involved)\b", r"\bresides\s+at\b", r"\blives\s+at\b",
]
_PROHIBITED_RE = re.compile("|".join(_PROHIBITED), re.I)


class UnsupportedConclusion(ValueError):
    pass


def guard(statement: str) -> str:
    """Return the statement if acceptable; raise UnsupportedConclusion if it asserts identity, location or conduct."""
    m = _PROHIBITED_RE.search(statement or "")
    if m:
        raise UnsupportedConclusion(f"Engine statement rejected (unsupported conclusion: '{m.group(0)}')")
    return statement
