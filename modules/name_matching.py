"""Conservative name matching and explicit claim comparison helpers.

This module never joins people by name. Candidate IDs are source-local unless an
analyst assigns them, and corroboration requires exact claim agreement across
independent registrable domains.
"""
from __future__ import annotations

import re
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urlparse


def normalize_name(value: str) -> str:
    value = unicodedata.normalize("NFKC", value or "").casefold()
    value = "".join(c for c in value if not unicodedata.category(c).startswith("P"))
    return " ".join(value.split())


def alternate_spellings(name: str) -> list[str]:
    """Return conservative orthographic variants, excluding the input itself."""
    name = " ".join((name or "").split())
    variants: set[str] = set()
    # Diacritic-free form is a common search variant, not an identity assertion.
    folded = unicodedata.normalize("NFKD", name)
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    if normalize_name(folded) != normalize_name(name):
        variants.add(folded)
    for a, b in (("’", "'"), ("-", " "), ("'", "")):
        candidate = name.replace(a, b)
        if normalize_name(candidate) != normalize_name(name):
            variants.add(candidate)
    return sorted(variants, key=str.casefold)


def source_domain(url: str) -> str:
    host = (urlparse(url).hostname or "").lower().removeprefix("www.")
    labels = host.split(".")
    if len(labels) < 2:
        return host
    # Conservative handling for common two-level public suffixes without a
    # new dependency. Unknown suffixes remain grouped by their last two labels.
    two_level = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "com.br", "co.in"}
    suffix = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if suffix in two_level and len(labels) >= 3 else suffix


@dataclass(frozen=True)
class Claim:
    candidate_id: str
    field: str
    value: str
    source_url: str
    statement: str = ""


def corroborated_claims(claims: list[Claim]) -> list[dict]:
    """Return exact claims supported by >=2 independent source domains.

    Candidate IDs must be explicitly assigned by the caller; identical names do
    not create candidate membership.
    """
    grouped: dict[tuple[str, str, str], dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for claim in claims:
        if claim.candidate_id and claim.field.strip() and claim.value.strip():
            domain = source_domain(claim.source_url)
            if domain:
                grouped[(claim.candidate_id, normalize_name(claim.field), normalize_name(claim.value))][domain].add(claim.source_url)
    out = []
    for (candidate_id, field, value), domains in grouped.items():
        if len(domains) >= 2:
            out.append({"candidate_id": candidate_id, "field": field, "value": value,
                        "domains": sorted(domains), "source_urls": sorted({u for urls in domains.values() for u in urls})})
    return out


def contradictory_claims(claims: list[Claim]) -> list[dict]:
    grouped: dict[tuple[str, str], dict[str, list[Claim]]] = defaultdict(lambda: defaultdict(list))
    for claim in claims:
        if claim.candidate_id and claim.field.strip() and claim.value.strip():
            grouped[(claim.candidate_id, normalize_name(claim.field))][normalize_name(claim.value)].append(claim)
    return [{"candidate_id": cid, "field": field,
             "values": [{"value": values[0].value, "sources": sorted({c.source_url for c in values})}
                        for values in variants.values()]}
            for (cid, field), variants in grouped.items() if len(variants) > 1]


def name_match_state(name: str, title: str, snippet: str) -> str:
    targets = {normalize_name(name), *(normalize_name(v) for v in alternate_spellings(name))}
    text = normalize_name(f"{title} {snippet}")
    if not any(target and re.search(r"(?<!\w)" + re.escape(target) + r"(?!\w)", text) for target in targets):
        return "unresolved"
    contextual = any(term in text for term in (" biography ", " profile ", " professor ", " director ",
                                                 " author ", " company ", " organization ", " news ", " university "))
    return "contextual" if contextual else "name_match"
