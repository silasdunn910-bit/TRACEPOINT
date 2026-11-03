"""Shared data structures used by every investigation module.

A module never writes to the database directly. It returns a ModuleResult
containing findings, entities and relationships; core.investigation persists it.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# Confidence classifications. These are qualitative evidence grades,
# NOT calibrated probabilities.
VERIFIED = "VERIFIED"      # directly supported by a reliable primary source
CORROBORATED = "CORROBORATED"  # supported by multiple independent sources
STRONG = CORROBORATED      # legacy alias: older records stored "STRONG"
MODERATE = "MODERATE"      # limited but consistent evidence
LOW = "LOW"                # weak association / incomplete evidence
UNVERIFIED = "UNVERIFIED"  # not independently confirmed
INCONCLUSIVE = "INCONCLUSIVE"  # the source could not establish the result
CONFIDENCE_LEVELS = [VERIFIED, CORROBORATED, MODERATE, LOW, UNVERIFIED, INCONCLUSIVE]


def normalize_confidence(value: str) -> str:
    """Map legacy stored grades (STRONG) onto the current taxonomy; unknown -> UNVERIFIED."""
    v = (value or "").upper()
    if v == "STRONG":
        return CORROBORATED
    return v if v in CONFIDENCE_LEVELS else UNVERIFIED

CONFIDENCE_MEANING = {
    VERIFIED: "Directly supported by a reliable primary source.",
    CORROBORATED: "Supported by multiple independent, credible sources.",
    MODERATE: "Supported by limited but consistent evidence.",
    LOW: "Weak association or incomplete evidence.",
    UNVERIFIED: "Not independently confirmed.",
    INCONCLUSIVE: "The source could not establish the result (blocked, unavailable or ambiguous).",
}

# Entity types
E_EMAIL, E_PHONE, E_USERNAME, E_PERSON = "email", "phone", "username", "person"
E_DOMAIN, E_IP, E_ORG, E_SOCIAL = "domain", "ip", "organization", "social_profile"
E_DOCUMENT, E_IMAGE, E_URL = "document", "image", "url"
ENTITY_TYPES = [E_EMAIL, E_PHONE, E_USERNAME, E_PERSON, E_DOMAIN, E_IP, E_ORG,
                E_SOCIAL, E_DOCUMENT, E_IMAGE, E_URL]

# Relationship types
R_ASSOCIATED = "publicly associated with"
R_REFERENCES = "references"
R_LINKS_TO = "links to"
R_REGISTERED_ORG = "registered to organization"
R_SHARES_ID = "shares a public identifier with"
R_POTENTIAL = "potential association"
R_RESOLVES = "resolves to"
R_HOSTED_BY = "hosted by"
R_PART_OF = "part of"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class Finding:
    title: str
    description: str
    source: str
    confidence: str = UNVERIFIED
    category: str = "general"
    value: str = ""
    source_url: str = ""
    evidence: str = ""
    limitations: str = ""
    discovered_at: str = field(default_factory=now_iso)
    query: str = ""
    source_type: str = ""
    published_at: str = ""

    def fingerprint(self) -> str:
        raw = "|".join([self.category, self.title, self.value, self.source_url]).lower()
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class EntityRef:
    type: str
    value: str
    verification: str = UNVERIFIED
    source: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return (self.type, self.value.strip().lower())


@dataclass
class RelationRef:
    src: EntityRef
    dst: EntityRef
    rel_type: str
    confidence: str = UNVERIFIED
    source: str = ""


@dataclass
class SourceRecord:
    name: str
    url: str = ""
    status: str = "ok"  # ok | error | skipped | not_configured
    detail: str = ""
    consulted_at: str = field(default_factory=now_iso)


@dataclass
class ModuleResult:
    module: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    entities: list[EntityRef] = field(default_factory=list)
    relationships: list[RelationRef] = field(default_factory=list)
    sources: list[SourceRecord] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    stages: list[dict] = field(default_factory=list)   # workflow stage records (core.workflow), set by investigation.run

    # helpers -------------------------------------------------------------
    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def dedupe(self) -> int:
        """Collapse findings that share a fingerprint, keeping the first.

        The database enforces UNIQUE(investigation_id, fingerprint) with INSERT OR IGNORE,
        so without this the in-memory list (what the UI counts) could exceed what is stored
        (what the dashboard counts). Deduping here keeps the reported count == the stored count.
        Returns the number of duplicates removed.
        """
        seen: set[str] = set()
        unique: list[Finding] = []
        for f in self.findings:
            fp = f.fingerprint()
            if fp not in seen:
                seen.add(fp)
                unique.append(f)
        removed = len(self.findings) - len(unique)
        self.findings = unique
        return removed

    def entity(self, etype: str, value: str, verification: str = UNVERIFIED, source: str = "") -> EntityRef:
        ref = EntityRef(etype, value, verification, source)
        for e in self.entities:
            if e.key == ref.key:
                return e
        self.entities.append(ref)
        return ref

    def relate(self, src: EntityRef, dst: EntityRef, rel_type: str, confidence: str = UNVERIFIED, source: str = ""):
        self.relationships.append(RelationRef(src, dst, rel_type, confidence, source))

    def source(self, name: str, url: str = "", status: str = "ok", detail: str = ""):
        self.sources.append(SourceRecord(name, url, status, detail))

    def merge(self, other: "ModuleResult"):
        seen = {f.fingerprint() for f in self.findings}
        for f in other.findings:
            if f.fingerprint() not in seen:
                self.findings.append(f)
                seen.add(f.fingerprint())
        for e in other.entities:
            self.entity(e.type, e.value, e.verification, e.source)
        self.relationships.extend(other.relationships)
        self.sources.extend(other.sources)
        self.errors.extend(other.errors)
        self.notes.extend(other.notes)
