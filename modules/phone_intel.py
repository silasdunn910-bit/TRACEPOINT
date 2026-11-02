"""Phone numbering-plan intelligence using Google's libphonenumber metadata.

This module cannot determine whether a line is active, who subscribes to it, or
where a person is. Web references are separately labeled as public-source leads.
"""
from __future__ import annotations

import re
import unicodedata

import phonenumbers
from phonenumbers import carrier, geocoder, number_type, timezone
from phonenumbers.phonenumberutil import NumberParseException, PhoneNumberType

from core import search_engine
from core.models import E_PHONE, E_URL, LOW, MODERATE, UNVERIFIED, Finding, ModuleResult

TYPE_NAMES = {v: k.replace("_", " ").title() for k, v in vars(PhoneNumberType).items() if isinstance(v, int)}
META = "libphonenumber numbering-plan metadata"
META_LIMIT = ("Metadata describes numbering-plan allocation and formatting. It does not verify that a number is "
              "assigned, active, reachable, or used by a particular person.")
LOC_LIMIT = ("Region, area and time-zone values describe numbering-plan allocation. They do not reveal where a "
             "subscriber lives or where a phone is now.")
_EXT_RE = re.compile(r"\s*(?:ext(?:ension)?\.?|x|#)\s*(\d+)\s*$", re.I)


def normalize_phone_input(value: str) -> str:
    """Normalize common visual formats to a parser-friendly form.

    Separators are removed, Unicode decimal digits become ASCII, extensions are
    retained, and the common ``1+NPA`` spelling is interpreted as ``+1NPA``.
    International/trunk prefix interpretation is then delegated to libphonenumber.
    """
    text = unicodedata.normalize("NFKC", str(value or "")).strip()
    if text.lower().startswith("tel:"):
        text = text[4:].strip()
    if not text or len(text) > 128:
        raise ValueError("Enter a phone number between 1 and 128 characters.")

    ascii_chars = []
    for char in text:
        try:
            ascii_chars.append(str(unicodedata.decimal(char)))
        except (TypeError, ValueError):
            ascii_chars.append(char)
    text = "".join(ascii_chars)
    text = re.sub(r"^1\s*\+\s*", "+1", text)

    extension = ""
    ext_match = _EXT_RE.search(text)
    if ext_match:
        extension = " ext." + ext_match.group(1)
        text = text[:ext_match.start()].strip()
    if not text or text.count("+") > 1 or ("+" in text and not text.lstrip().startswith("+")):
        raise ValueError("Phone number contains an invalid country-code marker.")
    compact = re.sub(r"[\s()./\-]", "", text)
    if not re.fullmatch(r"\+?\d+", compact):
        raise ValueError("Phone number may contain digits, common separators, a leading +, and an extension.")
    # 00 is a widely used international dialing prefix. The country calling code
    # and subsequent national-prefix rules are parsed by libphonenumber.
    if compact.startswith("00") and not compact.startswith("+"):
        compact = "+" + compact[2:]
    return compact + extension


def _configured_web_providers() -> list:
    names = {"Brave Search API", "Google Programmable Search", "SearXNG"}
    return [p for p in search_engine.active_providers() if p.name in names]


def investigate(target: str, *, default_region: str = "US", web_search: bool = True) -> ModuleResult:
    raw = str(target or "").strip()
    res = ModuleResult("phone", raw)
    try:
        normalized = normalize_phone_input(raw)
    except ValueError as exc:
        res.errors.append(str(exc))
        res.add(Finding("Invalid phone input", str(exc), META, UNVERIFIED, "metadata-validation", raw,
                        limitations=META_LIMIT))
        return res
    region = (default_region or "").strip().upper()
    try:
        num = phonenumbers.parse(normalized, None if normalized.startswith("+") else region)
    except NumberParseException as exc:
        res.errors.append(f"Could not parse phone number: {exc}")
        res.add(Finding("Unparseable phone number", str(exc), META, UNVERIFIED, "metadata-validation", normalized,
                        limitations=META_LIMIT))
        return res

    res.source(META, "https://github.com/google/libphonenumber", "ok",
               f"Parser region: {'international' if normalized.startswith('+') else region or 'unspecified'}")
    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    intl = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)
    valid = phonenumbers.is_valid_number(num)
    possible = phonenumbers.is_possible_number(num)
    if not possible:
        message = "Parsed digits are not a possible telephone-number length for the selected numbering region."
        res.errors.append(message)
        res.source(META, "https://github.com/google/libphonenumber", "ok",
                   f"Parser region: {'international' if normalized.startswith('+') else region or 'unspecified'}")
        res.add(Finding("Numbering-plan validation", message, META, MODERATE, "metadata-validation", "false",
                        limitations=META_LIMIT))
        return res
    number_entity = res.entity(E_PHONE, e164, UNVERIFIED, "normalized identifier; subscriber/active status unknown")

    res.add(Finding("Normalized number", f"E.164 {e164} | International {intl} | National {national}", META,
                    MODERATE, "normalization", e164, limitations=META_LIMIT))
    res.add(Finding("Numbering-plan validation",
                    ("Valid" if valid else "Not valid") + " according to current libphonenumber metadata; "
                    + ("possible length." if possible else "impossible length."),
                    META, MODERATE, "metadata-validation", str(valid).lower(), limitations=META_LIMIT))
    if not normalized.startswith("+"):
        res.notes.append(f"No international + country code was supplied; interpreted with region {region or 'unspecified'}.")

    region_code = phonenumbers.region_code_for_number(num)
    if region_code:
        res.add(Finding("Country calling code / numbering region", f"{region_code} (+{num.country_code})", META,
                        MODERATE, "numbering-plan", region_code, limitations=LOC_LIMIT))
    area = geocoder.description_for_number(num, "en")
    if area:
        res.add(Finding("Numbering-plan area", area, META, MODERATE, "numbering-plan", area,
                        limitations=LOC_LIMIT))
    kind = number_type(num)
    type_name = TYPE_NAMES.get(kind, "Unknown")
    res.add(Finding("Number type (metadata)", type_name, META, MODERATE, "classification", type_name,
                    limitations="Number-type metadata is not evidence of present service or subscriber identity. "
                    "Some countries do not distinguish mobile and fixed-line ranges."))
    allocated_carrier = carrier.name_for_number(num, "en")
    if allocated_carrier:
        res.add(Finding("Originally allocated carrier (metadata)", allocated_carrier, META, LOW, "carrier-metadata",
                        allocated_carrier,
                        limitations="This is historical numbering-block allocation. Number portability means it may "
                        "not be the current carrier; no live carrier or subscriber lookup was performed."))
    else:
        res.add(Finding("Carrier not listed in numbering metadata",
                        "No original carrier name is available for this range in the installed metadata.", META,
                        UNVERIFIED, "carrier-metadata", "unknown", limitations=META_LIMIT))
    zones = [zone for zone in timezone.time_zones_for_number(num) if zone != "Etc/Unknown"]
    if zones:
        res.add(Finding("Time zone(s) of numbering region", ", ".join(zones), META, MODERATE, "numbering-plan",
                        ", ".join(zones[:3]), limitations=LOC_LIMIT))

    if web_search and valid:
        providers = _configured_web_providers()
        if not providers:
            res.source("Configured public web search", "", "not_configured",
                       "Configure Brave Search, Google Programmable Search, or SearXNG in API Configuration.")
            res.notes.append("Public web references were skipped because no supported search API is configured.")
        else:
            variants = list(dict.fromkeys((e164, intl, national)))
            seen_urls: set[str] = set()
            searched_ok = 0
            for variant in variants:
                hits = search_engine.search(f'"{variant}"', 8, res)
                searched_ok += bool(getattr(hits, "completed", True))
                for hit in hits:
                    canonical = search_engine.normalize_url(hit.url)
                    if canonical in seen_urls:
                        continue
                    seen_urls.add(canonical)
                    before = len(res.findings)
                    search_engine.results_to_findings([hit], res, category="web-references",
                                                      exact_term=variant.lstrip("+"), what=f'exact query "{variant}"')
                    if len(res.findings) > before:
                        finding = res.findings[-1]
                        finding.description = "Public search index returned this page for an exact formatted-number query."
                        finding.limitations = ("This confirms only that a public search provider returned the page. "
                                               "It does not confirm that the number is active, who uses it, or that "
                                               "the result concerns the person being investigated.")
                        if finding.confidence == LOW:
                            res.relate(res.entity(E_URL, hit.url, UNVERIFIED, hit.provider), number_entity,
                                       "references", LOW, hit.provider)
            if not searched_ok:
                res.notes.append("Public web search did not run successfully for any number format; see provider "
                                 "errors. This is not a 'no results' outcome.")
            elif not seen_urls:
                res.notes.append("No matching indexed pages were returned; this does not show that the number is unused.")
    return res
