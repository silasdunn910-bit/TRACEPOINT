"""Jurisdiction selection for the Court Records and Sex Offender Registry modules.

Selecting a jurisdiction is NOT the same as having a provider for it. This module only turns what the operator typed
(US, NC, "north carolina", " Tx ", "District of Columbia", ...) into one consistent code. Which official sources exist for
that code, and whether any of them can be searched automatically, is decided by the provider catalogs and reported by
providers/coverage.py.
"""
from __future__ import annotations

import difflib
import re
import unicodedata
from dataclasses import dataclass

STATES: dict[str, str] = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California", "CO": "Colorado",
    "CT": "Connecticut", "DE": "Delaware", "FL": "Florida", "GA": "Georgia", "HI": "Hawaii", "ID": "Idaho",
    "IL": "Illinois", "IN": "Indiana", "IA": "Iowa", "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana",
    "ME": "Maine", "MD": "Maryland", "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi",
    "MO": "Missouri", "MT": "Montana", "NE": "Nebraska", "NV": "Nevada", "NH": "New Hampshire", "NJ": "New Jersey",
    "NM": "New Mexico", "NY": "New York", "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma",
    "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina", "SD": "South Dakota",
    "TN": "Tennessee", "TX": "Texas", "UT": "Utah", "VT": "Vermont", "VA": "Virginia", "WA": "Washington",
    "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming", "DC": "District of Columbia",
}

NATIONWIDE, STATE, FEDERAL = "nationwide", "state", "federal"

# Postal codes of territories: recognised only to give a precise error (they are not selectable jurisdictions).
_TERRITORIES = {"PR": "Puerto Rico", "GU": "Guam", "VI": "U.S. Virgin Islands", "AS": "American Samoa",
                "MP": "Northern Mariana Islands"}


def _norm(text: str) -> str:
    t = unicodedata.normalize("NFKC", str(text or "")).casefold()
    t = re.sub(r"[\x00-\x1f\x7f]", " ", t)
    t = re.sub(r"[.,]", "", t)
    t = re.sub(r"[-_]+", " ", t)
    return " ".join(t.split())


_BY_NAME = {_norm(n): c for c, n in STATES.items()}
_ALIASES = {"washington dc": "DC", "washington d c": "DC", "dist of columbia": "DC", "district of columbia": "DC"}
_NATIONWIDE_WORDS = {"us", "usa", "u s", "u s a", "united states", "united states of america", "nationwide", "national"}
_FEDERAL_WORDS = {"federal", "fed", "federal court", "federal courts"}


@dataclass(frozen=True)
class Jurisdiction:
    scope: str          # nationwide | state | federal
    code: str           # "US" for nationwide and federal, otherwise the two-letter postal code
    name: str           # display name
    requested: str = ""  # what the operator asked for, as typed (cleaned)

    @property
    def is_state(self) -> bool:
        return self.scope == STATE

    def label(self) -> str:
        return {NATIONWIDE: "United States (nationwide request)", FEDERAL: "Federal courts / national level"}.get(
            self.scope, f"{self.name} ({self.code})")


US_NATIONWIDE = Jurisdiction(NATIONWIDE, "US", "United States (Nationwide)")
FEDERAL_ONLY = Jurisdiction(FEDERAL, "US", "Federal")


def state(code: str) -> Jurisdiction:
    code = code.upper()
    return Jurisdiction(STATE, code, STATES[code], code)


def resolve(text: str) -> tuple[Jurisdiction | None, str]:
    """-> (jurisdiction, error). Accepts postal codes and full names, any case, surrounding whitespace.
    'US' / 'United States' resolve to the nationwide request, 'Federal' to the federal scope."""
    raw = " ".join(unicodedata.normalize("NFKC", str(text or "")).split())[:80]
    key = _norm(text)
    if not key:
        return None, "Enter a state name or abbreviation (for example NC, SC, NY, CA, TX)."
    if len(key) > 40:
        return None, "That is too long to be a state name. Enter a state name or two-letter abbreviation."
    if key in _NATIONWIDE_WORDS:
        return Jurisdiction(NATIONWIDE, "US", US_NATIONWIDE.name, raw), ""
    if key in _FEDERAL_WORDS:
        return Jurisdiction(FEDERAL, "US", FEDERAL_ONLY.name, raw), ""
    code = _ALIASES.get(key) or _BY_NAME.get(key) or (key.upper() if key.upper() in STATES and len(key) == 2 else None)
    if code:
        return Jurisdiction(STATE, code, STATES[code], raw), ""
    if key.upper() in _TERRITORIES or key in {_norm(n) for n in _TERRITORIES.values()}:
        return None, ("Territories are not selectable jurisdictions. TRACEPOINT supports the 50 states and the "
                      "District of Columbia.")
    near = difflib.get_close_matches(key, list(_BY_NAME), n=2, cutoff=0.7)
    hint = f" Did you mean {' or '.join(STATES[_BY_NAME[n]] + ' (' + _BY_NAME[n] + ')' for n in near)}?" if near else ""
    shown = re.sub(r"[^\w .'-]", "?", raw)[:40]
    return None, (f"'{shown}' is not a recognised jurisdiction. Use a two-letter postal abbreviation (NC) or a full "
                  f"state name (North Carolina); the District of Columbia is DC.{hint}")
