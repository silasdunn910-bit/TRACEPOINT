"""Shared building blocks for the Court Records and Sex Offender Registry modules.

Design rules (see PHASE-8-REPORT.md):
* Sources are official government sites only. Every source states, in data, whether TRACEPOINT can
  search it automatically ("automated") or the operator must search it in the official portal and
  review the result ("manual"). Nothing here invents an endpoint or a search capability.
* A name match is never an identity. Records are kept as separate, typed objects and are never merged.
* Registry records deliberately have no address/location fields.
"""
from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlparse

from core.models import now_iso

EMPTY_COURT = ("No records found in the sources searched. This does not establish that the individual has no "
               "criminal or court history.")
EMPTY_REGISTRY = ("No registry records were returned by the sources searched. This does not establish that an "
                  "individual is absent from every registry.")
NO_SEARCH_RAN = ("No source was searched automatically, so no records were obtained. Search the official portal(s) "
                 "listed in this report manually; nothing here indicates whether records exist.")

IDENTITY_LIMIT = ("A name match is not proof of identity. TRACEPOINT does not decide whether this record belongs to "
                  "the person searched; it was attached by the operator after manual review.")

REVIEWED = "REVIEWED_BY_OPERATOR"
UNREVIEWED = "UNREVIEWED"


class ManualSearchRequired(Exception):
    """The source has no verified automated search; the operator must use the official portal."""


@dataclass(frozen=True)
class OfficialSource:
    id: str
    name: str
    agency: str
    kind: str                       # "court" | "registry"
    level: str                      # federal | state | county | national
    jurisdiction: str               # "US", "NC", ...
    official_url: str
    search_url: str
    method: str                     # "automated" | "manual"
    search_fields: tuple[str, ...]  # fields TRACEPOINT can use / the portal documents
    unsupported_fields: tuple[str, ...]
    auth: str                       # authentication / registration requirement, as documented
    coverage: str
    complete: bool                  # False = partial coverage (always, today)
    limitations: str
    official_domains: tuple[str, ...]
    verified_note: str              # what was actually verified, and when
    requires_secret: str = ""       # name of the stored credential, if any
    kinds: tuple[str, ...] = ()     # search kinds the source can take; empty = every kind the module offers

    @property
    def automated(self) -> bool:
        return self.method == "automated"


@dataclass
class SearchOutcome:
    """Result of asking one source. `records` are unreviewed candidates, not findings."""
    source: OfficialSource
    status: str                     # ok | error | manual | not_configured | skipped
    detail: str = ""
    error_kind: str = ""            # "unavailable" when an error is a reachability problem (offline, timeout, 5xx, 429)
    records: list = field(default_factory=list)
    query: str = ""
    query_kind: str = ""
    searched_at: str = field(default_factory=now_iso)
    partial: bool = True

    @property
    def completed(self) -> bool:
        return self.status == "ok"


# --- input validation ---------------------------------------------------------------------------
_ADDRESS = re.compile(r"\b\d{1,6}\s+(?:[\w.'-]+\s+){0,4}(?:street|st|road|rd|avenue|ave|boulevard|blvd|drive|dr|lane|ln|"
                      r"court|ct|way|circle|cir|highway|hwy|apt|apartment|unit|suite)\b", re.I)
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean_text(value, limit: int = 300) -> str:
    """Single-line, control-character-free, length-limited text."""
    text = unicodedata.normalize("NFKC", str(value or ""))
    return " ".join(_CTRL.sub(" ", text).split())[:limit]


def validate_person_name(name: str) -> tuple[str, str]:
    """-> (clean_name, error)."""
    n = clean_text(name, 400)
    if len(n) > 160:
        return "", "Name is too long (160 characters maximum)."
    if len(n.split()) < 2:
        return "", "Enter a full name (at least a first and last name)."
    if "@" in n or "://" in n or any(c.isdigit() for c in n):
        return "", "Enter a person's name only (no digits, e-mail addresses or URLs)."
    if not all(c.isalpha() or c in " '-.,’" for c in n):
        return "", "Names may contain letters, spaces, apostrophes, hyphens, periods and commas only."
    return n, ""


_CASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .:/\-]{2,39}$")


def validate_case_number(value: str) -> tuple[str, str]:
    v = clean_text(value, 100)
    if not _CASE.match(v) or not any(c.isdigit() for c in v):
        return "", ("Case numbers are 3-40 characters of letters, digits, spaces and . : / - and must contain "
                    "a digit (for example 1:24-cr-00123 or 24CR000123-123).")
    return v, ""


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{2,39}$")


def validate_registry_id(value: str) -> tuple[str, str]:
    v = clean_text(value, 100)
    if not _ID.match(v):
        return "", "Registry identification numbers are 3-40 letters, digits or hyphens."
    return v, ""


def reject_address_text(value: str, label: str) -> str:
    """Error text if `value` looks like a street address; TRACEPOINT does not collect residences."""
    if _ADDRESS.search(value or ""):
        return f"{label} looks like a street address; TRACEPOINT does not collect or store residential addresses."
    return ""


def parse_date(value: str) -> tuple[str, str]:
    """-> (iso_date_or_original_text, error). Accepts YYYY-MM-DD or MM/DD/YYYY; blank is allowed."""
    v = clean_text(value, 40)
    if not v:
        return "", ""
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})", v)
    if not m:
        m2 = re.fullmatch(r"(\d{1,2})/(\d{1,2})/(\d{4})", v)
        if not m2:
            return "", "Dates must look like 2024-03-15 or 03/15/2024 (or be left blank)."
        mo, d, y = int(m2.group(1)), int(m2.group(2)), int(m2.group(3))
    else:
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if not (1 <= mo <= 12 and 1 <= d <= 31 and 1800 <= y <= 2200):
        return "", "That is not a valid calendar date."
    return f"{y:04d}-{mo:02d}-{d:02d}", ""


def check_source_url(url: str, source: OfficialSource) -> tuple[str, str]:
    """-> (url, note). Only http(s) URLs are kept. `note` is non-empty when the host is not one of the
    source's official domains (the record is kept, flagged, never silently trusted)."""
    u = clean_text(url, 500)
    if not u:
        return "", ""
    try:
        p = urlparse(u)
        host = (p.hostname or "").lower()
    except ValueError:
        return "", "The URL was malformed and was not kept."
    if p.scheme not in ("http", "https") or not host:
        return "", "Only http(s) URLs are kept."
    ok = any(host == d or host.endswith("." + d) for d in source.official_domains)
    note = "" if ok else (f"URL host {host} is not one of this source's official domains "
                          f"({', '.join(source.official_domains)}); verify it manually.")
    return u, note


def stable_key(*parts: str) -> str:
    raw = "|".join(clean_text(p, 300).lower() for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


# --- classification -----------------------------------------------------------------------------
# Court case statuses. Only the status text published by the source is interpreted, and only when it is
# unambiguous; everything else is UNKNOWN. The original wording is always kept next to the normalized value.
PENDING, DISMISSED, CONVICTED, ACQUITTED = "PENDING", "DISMISSED", "CONVICTED", "ACQUITTED"
DEFERRED, SEALED, UNKNOWN = "DEFERRED", "SEALED / UNAVAILABLE", "UNKNOWN"
COURT_STATUSES = [PENDING, DISMISSED, CONVICTED, ACQUITTED, DEFERRED, SEALED, UNKNOWN]

CRIMINAL, CIVIL, OPINION, TYPE_UNKNOWN = "CRIMINAL", "CIVIL", "PUBLISHED OPINION", "UNKNOWN"
RECORD_TYPES = [CRIMINAL, CIVIL, OPINION, TYPE_UNKNOWN]


def classify_court_status(original: str, record_type: str = TYPE_UNKNOWN) -> str:
    t = clean_text(original, 200).lower()
    if not t:
        return UNKNOWN
    if re.search(r"\b(sealed|expunged|expungement|confidential|restricted|not available online|unavailable|"
                 r"juvenile)\b", t):
        return SEALED
    if re.search(r"\bnot guilty\b|\bacquit", t):
        return ACQUITTED if record_type == CRIMINAL else UNKNOWN          # civil/opinion outcomes are not acquittals
    if re.search(r"\bdismiss|\bnolle pros|\bnol[ .]?pros|\bno true bill\b", t):
        return DISMISSED                                                   # a dismissal is never an acquittal
    if re.search(r"\bdeferred\b|\bdeferral\b|\bpretrial diversion\b", t):
        return DEFERRED
    if re.search(r"\bconvict|\bguilty\b", t):                             # "not guilty" was handled above
        return CONVICTED if record_type == CRIMINAL else UNKNOWN          # only criminal cases can convict
    if re.fullmatch(r"(case )?(is )?(pending|open|active|ongoing|awaiting (trial|disposition))", t):
        return PENDING
    return UNKNOWN                                                         # arrested/charged/filed/etc. are not outcomes


# Registry statuses (as displayed by the registry -> TRACEPOINT's normalized value).
ACTIVE, INACTIVE, DECEASED, ABSCONDED = "ACTIVE", "INACTIVE", "DECEASED", "ABSCONDED"
REGISTRY_STATUSES = [ACTIVE, INACTIVE, DECEASED, ABSCONDED, UNKNOWN]


def classify_registry_status(original: str) -> str:
    t = clean_text(original, 200).lower()
    if not t:
        return UNKNOWN
    if re.search(r"\bdeceased\b|\bdied\b", t):
        return DECEASED
    if re.search(r"\babscond", t):
        return ABSCONDED
    if re.search(r"\binactive\b|\bexpired\b|\bremoved\b|\bterminated\b|\bno longer required\b|\bno longer registered\b", t):
        return INACTIVE
    if re.fullmatch(r"(currently )?(active|registered|current|in compliance|compliant)", t):
        return ACTIVE
    return UNKNOWN


# --- records ------------------------------------------------------------------------------------
@dataclass
class CourtRecord:
    source_id: str
    jurisdiction: str
    court: str = ""
    case_number: str = ""
    title: str = ""                 # case caption / opinion title as published
    displayed_name: str = ""        # party name as displayed, if the source shows one
    record_type: str = TYPE_UNKNOWN
    original_status: str = ""       # the court's own wording, never altered
    status: str = UNKNOWN           # TRACEPOINT's normalized classification
    charges: str = ""               # as published; never summarised or inferred
    filing_date: str = ""
    disposition_date: str = ""
    record_id: str = ""             # source-assigned identifier when there is no case number (e.g. GovInfo packageId)
    published_date: str = ""        # date the source shows for the record (e.g. opinion issue date); not a disposition
    source_url: str = ""
    source_updated: str = ""
    retrieved_at: str = field(default_factory=now_iso)
    origin: str = "automated"       # automated | manual
    url_note: str = ""

    def identifier(self) -> str:
        return self.case_number or self.record_id or self.title

    def key(self) -> str:
        return stable_key("court", self.source_id, self.identifier(),
                          "" if (self.case_number or self.record_id) else self.filing_date)


@dataclass
class RegistryRecord:
    """Deliberately has NO address, location, photo, physical-description or employer fields."""
    source_id: str
    jurisdiction: str
    displayed_name: str = ""
    registry_id: str = ""
    original_status: str = ""
    status: str = UNKNOWN
    offense_classification: str = ""   # as published by the registry
    registration_date: str = ""
    source_updated: str = ""
    source_url: str = ""
    agency: str = ""
    retrieved_at: str = field(default_factory=now_iso)
    origin: str = "manual"
    url_note: str = ""

    def identifier(self) -> str:
        return self.registry_id or self.displayed_name

    def key(self) -> str:
        return stable_key("registry", self.source_id, self.registry_id or self.displayed_name,
                          "" if self.registry_id else self.registration_date)
