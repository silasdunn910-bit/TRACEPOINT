"""Data structures of an Intelligence Report.

Everything here is derived from stored investigation data (core.reports.build). Fields that the source did not
provide stay empty and are rendered as "not recorded"; nothing is filled in or estimated.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

ENGINE_VERSION = "1.1"

# --- report status -----------------------------------------------------------------------------------------------
COMPLETE = "COMPLETE"        # every consulted source answered and the module reported no errors
PARTIAL = "PARTIAL"          # finished, but some sources were not configured / skipped / manual-only
INCOMPLETE = "INCOMPLETE"    # sources failed or were blocked, the module reported errors, or nothing was searched
FAILED = "FAILED"            # the investigation failed to run, or the report itself could not be generated
REPORT_STATUSES = (COMPLETE, PARTIAL, INCOMPLETE, FAILED)

STATUS_MEANING = {
    COMPLETE: "All consulted sources responded and the module reported no errors.",
    PARTIAL: "The investigation finished, but some sources were not configured, skipped, or manual-only, so coverage is limited.",
    INCOMPLETE: "The investigation did NOT complete successfully: sources failed or were blocked, errors were reported, "
                "or nothing was searched. Treat every conclusion as provisional.",
    FAILED: "The investigation did not run to completion (or its report could not be generated). No findings may "
            "be read as a result.",
}

# --- claim classes (how a finding stands evidentially; NOT a new confidence grade) --------------------------------
VERIFIED_FACT = "VERIFIED FACT"
CORROBORATED_CLAIM = "CORROBORATED CLAIM"
SINGLE_SOURCE_CLAIM = "SINGLE-SOURCE CLAIM"
UNVERIFIED_CLAIM = "UNVERIFIED CLAIM"
ANALYTICAL_INFERENCE = "ANALYTICAL INFERENCE"
CONTRADICTORY = "CONTRADICTORY INFORMATION"
CLAIM_CLASSES = (VERIFIED_FACT, CORROBORATED_CLAIM, SINGLE_SOURCE_CLAIM, UNVERIFIED_CLAIM, ANALYTICAL_INFERENCE,
                 CONTRADICTORY)

CLAIM_CLASS_MEANING = {
    VERIFIED_FACT: "The collecting module graded it VERIFIED (direct, reliable primary source) and nothing in this "
                   "investigation contradicts it.",
    CORROBORATED_CLAIM: "The same claim is supported by two or more independent origins, or the module graded it "
                        "CORROBORATED.",
    SINGLE_SOURCE_CLAIM: "Supported by one origin only (graded MODERATE or LOW). Needs independent confirmation.",
    UNVERIFIED_CLAIM: "Graded UNVERIFIED or INCONCLUSIVE by the collecting module: a lead, not a fact.",
    ANALYTICAL_INFERENCE: "A conclusion derived from other evidence (by a module comparison or by this report engine), "
                          "not an observation from a source. Each lists the evidence it rests on.",
    CONTRADICTORY: "Conflicts with other evidence in this investigation. Neither side should be relied on until resolved.",
}

# --- overall assessment levels (qualitative; never a probability) -------------------------------------------------
HIGH, MODERATE, LOW, INSUFFICIENT = "HIGH", "MODERATE", "LOW", "INSUFFICIENT"
ASSESSMENT_LEVELS = (HIGH, MODERATE, LOW, INSUFFICIENT)


@dataclass
class SourceRef:
    """One entry of the Source References section (a unique source name + URL)."""
    ref: str                     # "S1", "S2", ...
    name: str
    url: str = ""                # exact URL as recorded; "" if the source gave none
    status: str = ""             # ok | error | skipped | not_configured | blocked | manual | "" (finding-only source)
    detail: str = ""
    consulted_at: str = ""       # when the source was queried, as recorded; "" if not recorded
    tier: str = ""               # source-type classification (rule-based; see evidence_analyzer.SOURCE_TIERS)
    tier_basis: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    consulted: bool = False      # True ONLY if TRACEPOINT recorded a successful retrieval (status "ok")
    reliability: str = ""        # HIGH | MODERATE | LOW | NOT APPLICABLE | UNASSESSED (fixed rules by source type)
    http_status: str = ""        # last HTTP status the source detail mentions, if any


@dataclass
class EvidenceItem:
    """One stored finding, with full provenance. The registry keeps every finding; nothing is dropped."""
    ref: str                     # "E1", "E2", ...
    finding_id: int | None
    category: str
    title: str
    value: str
    description: str
    source: str                  # source name exactly as stored
    source_url: str              # exact URL as stored
    retrieved_at: str            # finding.discovered_at
    published_at: str            # "" when the source did not provide one
    evidence: str                # supporting evidence text as stored
    limitations: str
    stored_grade: str            # confidence grade assigned by the collecting module (normalized)
    claim_class: str = ""
    source_ref: str = ""         # "S#" this evidence came from
    origin: str = ""             # independence key (URL host or source name)
    query: str = ""
    corroborated_by: list[str] = field(default_factory=list)
    conflicts_with: list[str] = field(default_factory=list)
    duplicate_of: str = ""       # set when the same claim from the same origin was already registered
    metadata_gaps: list[str] = field(default_factory=list)
    significance: str = ""
    grade: str = ""              # effective grade after engine caps (== stored_grade unless capped)
    grade_note: str = ""         # why the engine capped the stored grade, if it did


@dataclass
class ClaimGroup:
    """Findings that assert the same thing (same category + same value, or same category + title)."""
    key: str
    label: str
    evidence_refs: list[str]
    origins: list[str]
    source_names: list[str]
    independent: bool            # >= 2 distinct origins AND >= 2 distinct source names
    note: str = ""


@dataclass
class Discrepancy:
    description: str
    evidence_refs: list[str]
    detected_by: str             # "collecting module" | "core.correlation rules" | "report engine (presence/absence)" ...
    resolution_hint: str = ""


@dataclass
class Inference:
    """An analytical statement. Always lists the evidence it rests on; unsupported ones are discarded."""
    statement: str
    basis: list[str]
    alternatives: list[str] = field(default_factory=list)
    caveat: str = ""
    kind: str = "pattern"        # pattern | significance | gap | correlation


@dataclass
class KeyFinding:
    evidence_ref: str
    headline: str
    claim_class: str
    stored_grade: str
    source_ref: str
    why_it_matters: str


@dataclass
class ConfidenceAssessment:
    level: str
    scope: str                   # what the level is about (reliability of the recorded evidence)
    factors: list[str]
    caps: list[str]
    counts: dict
    identity_statement: str = ""


@dataclass
class IntelligenceReport:
    engine_version: str
    generated_at: str
    generator: str
    status: str
    status_reasons: list[str]
    overview: dict
    executive_summary: list[str]
    key_findings: list[KeyFinding]
    evidence: list[EvidenceItem]
    sources: list[SourceRef]
    corroboration: dict
    discrepancies: list[Discrepancy]
    assessment: list[Inference]
    confidence: ConfidenceAssessment
    limitations: list[str]
    unresolved_questions: list[str]
    next_steps: list[str]
    records_review: dict | None = None
    ai_analysis: str = ""
    error: str = ""
    workflow: list[dict] = field(default_factory=list)   # recorded investigation stages (core.workflow)
    entities: list[dict] = field(default_factory=list)   # stored entities (+ "generic" flag for shared infrastructure)
    relationships: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "IntelligenceReport":
        d = dict(d)
        d["key_findings"] = [KeyFinding(**x) for x in d.get("key_findings", [])]
        d["evidence"] = [EvidenceItem(**x) for x in d.get("evidence", [])]
        d["sources"] = [SourceRef(**x) for x in d.get("sources", [])]
        d["discrepancies"] = [Discrepancy(**x) for x in d.get("discrepancies", [])]
        d["assessment"] = [Inference(**x) for x in d.get("assessment", [])]
        d["confidence"] = ConfidenceAssessment(**d["confidence"])
        return cls(**d)

    def evidence_by_ref(self) -> dict[str, EvidenceItem]:
        return {e.ref: e for e in self.evidence}

    def source_by_ref(self) -> dict[str, SourceRef]:
        return {s.ref: s for s in self.sources}
