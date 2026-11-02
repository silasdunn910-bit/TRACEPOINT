"""Search planning and coverage reporting shared by the Court Records and Sex Offender Registry modules.

Coverage is generated from what actually happened: each provider that was attempted, skipped or missing is
recorded with a status and a reason. Nothing here is hardcoded per jurisdiction, and "nationwide" describes the
request, never the result: COMPLETE is only reported when every provider in scope was searched, each claims complete
coverage, and no jurisdiction is without a provider. Today no catalogued source claims completeness, so a search is
at best PARTIAL.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Callable

from core.models import now_iso
from providers.jurisdictions import FEDERAL, NATIONWIDE, STATE, STATES, Jurisdiction
from providers.records_common import OfficialSource, SearchOutcome

# Per-provider statuses.
SEARCHED, MANUAL, UNAVAILABLE = "SEARCHED", "MANUAL", "UNAVAILABLE"
NOT_IMPLEMENTED, FAILED, SKIPPED = "NOT IMPLEMENTED", "FAILED", "SKIPPED"
PROVIDER_STATUSES = (SEARCHED, MANUAL, UNAVAILABLE, NOT_IMPLEMENTED, FAILED, SKIPPED)
# Overall statuses.
COMPLETE, PARTIAL, NONE = "COMPLETE", "PARTIAL", "NONE"

ZERO_RECORDS_NOTE = ("A source that returned zero records is not proof that no records exist: it only means nothing "
                     "matched in that source's searchable data.")
MARKER = "[coverage-data] "     # prefix of the machine-readable line kept in an investigation's notes


@dataclass
class CoverageEntry:
    provider_id: str
    provider: str
    level: str                  # federal | national | state | county | (blank for NOT IMPLEMENTED)
    jurisdiction: str           # postal code, or "US"
    jurisdiction_name: str
    status: str
    reason: str = ""
    url: str = ""
    method: str = ""            # automated | manual | ""
    auth: str = ""
    records: int = 0
    searched_at: str = ""
    claims_complete: bool = False


@dataclass
class CoverageReport:
    kind: str                   # court | registry
    requested: str              # what the operator typed / chose
    scope: str                  # nationwide | state | federal
    resolved: str               # e.g. "North Carolina (NC)"
    search_method: str          # name | case_number | registry_id
    entries: list[CoverageEntry] = field(default_factory=list)
    generated_at: str = field(default_factory=now_iso)

    # -- derived ---------------------------------------------------------------------
    def by_status(self, status: str) -> list[CoverageEntry]:
        return [e for e in self.entries if e.status == status]

    @property
    def status(self) -> str:
        searched = self.by_status(SEARCHED)
        if not searched:
            return NONE
        if len(searched) == len(self.entries) and all(e.claims_complete for e in searched):
            return COMPLETE
        return PARTIAL

    @property
    def complete_nationwide(self) -> bool:
        """True only if a nationwide request was actually completely covered."""
        return self.scope == NATIONWIDE and self.status == COMPLETE

    def counts(self) -> dict:
        c = {s: len(self.by_status(s)) for s in PROVIDER_STATUSES}
        c["jurisdictions_in_scope"] = len({e.jurisdiction for e in self.entries if e.level != "national"} |
                                          ({"US"} if any(e.level in ("federal", "national") for e in self.entries) else set()))
        c["records_returned"] = sum(e.records for e in self.entries)
        return c

    # -- serialisation ---------------------------------------------------------------
    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CoverageReport":
        entries = [CoverageEntry(**{k: v for k, v in e.items() if k in CoverageEntry.__dataclass_fields__})
                   for e in d.get("entries", [])]
        return cls(d["kind"], d["requested"], d["scope"], d["resolved"], d["search_method"], entries,
                   d.get("generated_at", ""))

    def to_marker_line(self) -> str:
        return MARKER + json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=False)

    # -- text ------------------------------------------------------------------------
    def headline(self) -> str:
        if self.scope == NATIONWIDE:
            return "NATIONWIDE SEARCH COVERAGE"
        return f"SEARCH COVERAGE - {self.resolved.upper()}"

    def lines(self) -> list[str]:
        """Plain-text coverage block (used by the CLI, notes and reports)."""
        out = [self.headline(), f"Requested: {self.requested}   Resolved: {self.resolved}   Search method: {self.search_method}"]
        groups = (("Federal / national:", ("federal", "national")), ("State providers:", ("state",)),
                  ("County providers:", ("county",)))
        for title, levels in groups:
            rows = [e for e in self.entries if e.level in levels]
            if rows:
                out.append(title)
                out += [f"  {e.provider} [{e.jurisdiction}]: {e.status}" + (f" ({e.records} record(s) returned)"
                        if e.status == SEARCHED else "") for e in rows]
        ni = self.by_status(NOT_IMPLEMENTED)
        if ni:
            out.append(f"No official provider catalogued ({len(ni)}): " + ", ".join(e.jurisdiction for e in ni) + "  -> NOT IMPLEMENTED")
        out.append(f"Coverage: {self.status}")
        c = self.counts()
        out.append(f"{c[SEARCHED]} automated source(s) searched; {c[MANUAL]} manual source(s) available; "
                   f"{c[UNAVAILABLE]} unavailable; {c[FAILED]} failed; {c[SKIPPED]} skipped; "
                   f"{c[NOT_IMPLEMENTED]} jurisdiction(s) with no provider implemented.")
        if self.scope == NATIONWIDE:
            out.append("'Nationwide' describes the request. Only the sources marked SEARCHED were searched"
                       + ("." if self.status != COMPLETE else "; every source in scope reports complete coverage."))
        if self.status != COMPLETE:
            out.append("Coverage is PARTIAL or absent: results (including none) do not cover every jurisdiction or record.")
        out.append(ZERO_RECORDS_NOTE)
        return out


@dataclass
class SearchPlan:
    jurisdiction: Jurisdiction
    kind: str
    sources: list[OfficialSource]
    not_implemented: list[str]             # jurisdiction codes in scope with no state/county provider

    @property
    def automated(self) -> list[OfficialSource]:
        return [s for s in self.sources if s.automated]

    @property
    def manual(self) -> list[OfficialSource]:
        return [s for s in self.sources if not s.automated]


_LEVEL_ORDER = {"federal": 0, "national": 1, "state": 2, "county": 3}


def plan(catalog: dict[str, OfficialSource], jur: Jurisdiction, kind: str, *, national_in_state: bool = False) -> SearchPlan:
    """Which catalogued providers apply to `jur`? Never invents a provider.

    nationwide -> every catalogued source; federal -> federal/national-level sources only;
    state -> that state's state- and county-level sources (federal courts are a separate jurisdiction;
    `national_in_state` also lists national-level portals, like NSOPW, that let the operator pick the state)."""
    srcs = list(catalog.values())
    if jur.scope == NATIONWIDE:
        chosen = srcs
    elif jur.scope == FEDERAL:
        chosen = [s for s in srcs if s.level in ("federal", "national")]
    else:
        chosen = [s for s in srcs if s.jurisdiction == jur.code and s.level in ("state", "county")]
        if national_in_state:
            chosen += [s for s in srcs if s.level == "national"]
    chosen.sort(key=lambda s: (_LEVEL_ORDER.get(s.level, 9), s.jurisdiction, s.name))
    if jur.scope == NATIONWIDE:
        covered = {s.jurisdiction for s in srcs if s.level in ("state", "county")}
        missing = [c for c in STATES if c not in covered]
    elif jur.scope == STATE:
        missing = [] if any(s.level in ("state", "county") for s in chosen) else [jur.code]
    else:
        missing = []
    return SearchPlan(jur, kind, chosen, missing)


def supports(source: OfficialSource, search_kind: str) -> bool:
    return not source.kinds or search_kind in source.kinds


def _status_for(o: SearchOutcome) -> str:
    if o.status == "ok":
        return SEARCHED
    if o.status == "manual":
        return MANUAL
    if o.status == "skipped":
        return SKIPPED
    if o.status == "not_configured":
        return UNAVAILABLE
    return UNAVAILABLE if o.error_kind == "unavailable" else FAILED


def _entry(source: OfficialSource, o: SearchOutcome) -> CoverageEntry:
    return CoverageEntry(
        provider_id=source.id, provider=source.name, level=source.level, jurisdiction=source.jurisdiction,
        jurisdiction_name=STATES.get(source.jurisdiction, "United States"), status=_status_for(o), reason=o.detail,
        url=source.search_url, method=source.method, auth=source.auth, records=len(o.records) if o.status == "ok" else 0,
        searched_at=o.searched_at, claims_complete=bool(source.complete))


def build_report(kind: str, jur: Jurisdiction, search_method: str, pl: SearchPlan | None,
                 outcomes: list[SearchOutcome]) -> CoverageReport:
    """Coverage from real outcomes. Planned providers with no outcome are SKIPPED (never silently dropped)."""
    rep = CoverageReport(kind, jur.requested or jur.name, jur.scope, jur.label(), search_method)
    by_id = {o.source.id: o for o in outcomes}
    seen: set[str] = set()
    for s in (pl.sources if pl else []):
        o = by_id.get(s.id)
        if o is None:
            o = SearchOutcome(s, "skipped", detail="Not run in this search.", query_kind=search_method)
        rep.entries.append(_entry(s, o))
        seen.add(s.id)
    for o in outcomes:                      # outcomes outside the plan (explicit provider choice) are still reported
        if o.source.id not in seen:
            rep.entries.append(_entry(o.source, o))
            seen.add(o.source.id)
    for code in (pl.not_implemented if pl else []):
        rep.entries.append(CoverageEntry(
            provider_id="", provider=f"{STATES[code]} - no official {kind} provider catalogued", level="state",
            jurisdiction=code, jurisdiction_name=STATES[code], status=NOT_IMPLEMENTED,
            reason="TRACEPOINT has no verified official source for this jurisdiction; nothing was searched.",
            searched_at=rep.generated_at))
    return rep


def execute(kind: str, catalog: dict[str, OfficialSource], jur: Jurisdiction, term: str, search_kind: str,
            search_fn: Callable[[OfficialSource, str, str], SearchOutcome], *, national_in_state: bool = False,
            ) -> tuple[list[SearchOutcome], CoverageReport]:
    """Run every compatible provider in scope. A provider that raises is recorded as FAILED, not dropped."""
    pl = plan(catalog, jur, kind, national_in_state=national_in_state)
    outcomes = run_sources(pl.sources, term, search_kind, search_fn)
    return outcomes, build_report(kind, jur, search_kind, pl, outcomes)


def run_sources(sources: list[OfficialSource], term: str, search_kind: str,
                search_fn: Callable[[OfficialSource, str, str], SearchOutcome]) -> list[SearchOutcome]:
    outcomes = []
    for s in sources:
        if not supports(s, search_kind):
            outcomes.append(SearchOutcome(s, "skipped", query=term, query_kind=search_kind,
                                          detail=f"{s.name} does not support searching by {search_kind.replace('_', ' ')}."))
            continue
        try:
            outcomes.append(search_fn(s, term, search_kind))
        except Exception as e:                       # one provider's bug must not hide the others
            outcomes.append(SearchOutcome(s, "error", query=term, query_kind=search_kind,
                                          detail=f"Provider error ({type(e).__name__}); no records were obtained from it."))
    return outcomes


def parse_marker(notes: str) -> tuple[CoverageReport | None, str]:
    """Split an investigation's notes into (coverage report or None, notes without the machine-readable line)."""
    keep, rep = [], None
    for ln in (notes or "").splitlines():
        if ln.startswith(MARKER):
            try:
                rep = CoverageReport.from_dict(json.loads(ln[len(MARKER):]))
            except (ValueError, KeyError, TypeError):
                rep = None
        else:
            keep.append(ln)
    return rep, "\n".join(keep)
