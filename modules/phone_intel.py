"""Phone intelligence using Google's libphonenumber metadata (python phonenumbers)."""
from __future__ import annotations

import phonenumbers
from phonenumbers import carrier, geocoder, number_type, timezone
from phonenumbers.phonenumberutil import NumberParseException, PhoneNumberType

from core import search_engine
from core.models import E_PHONE, E_URL, LOW, MODERATE, VERIFIED, Finding, ModuleResult

TYPE_NAMES = {v: k.replace("_", " ").title() for k, v in vars(PhoneNumberType).items() if isinstance(v, int)}
META = "libphonenumber metadata"
LOC_LIMIT = ("This is the region the number was ALLOCATED to under the national numbering plan. "
             "It does not reveal where the user lives or where the phone is right now.")


def investigate(target: str, *, default_region: str = "US", web_search: bool = True) -> ModuleResult:
    raw = target.strip()
    res = ModuleResult("phone", raw)
    try:
        num = phonenumbers.parse(raw, None if raw.startswith("+") else default_region.upper())
    except NumberParseException as e:
        res.errors.append(f"Could not parse phone number: {e}")
        res.add(Finding("Unparseable phone number", str(e), META, VERIFIED, "validation", raw))
        return res
    res.source(META, "https://github.com/google/libphonenumber")
    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    intl = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)
    valid, possible = phonenumbers.is_valid_number(num), phonenumbers.is_possible_number(num)
    region = phonenumbers.region_code_for_number(num)
    p_ent = res.entity(E_PHONE, e164, VERIFIED if valid else "UNVERIFIED")

    res.add(Finding("Normalized number", f"E.164 {e164} | International {intl} | National {national}", META, VERIFIED,
                    "normalization", e164))
    res.add(Finding("Number validity", ("Valid" if valid else "NOT valid") + " for its numbering plan; "
                    + ("possible length." if possible else "impossible length."), META, VERIFIED, "validation",
                    str(valid), limitations="Validity means the number fits an allocated range, not that it is in service."))
    if not raw.startswith("+"):
        res.notes.append(f"Number had no + country code; parsed assuming region {default_region.upper()}.")
    if region:
        res.add(Finding("Country / numbering region", f"{region} (+{num.country_code})", META, VERIFIED, "geo",
                        region, limitations=LOC_LIMIT))
    desc = geocoder.description_for_number(num, "en")
    if desc:
        res.add(Finding("Numbering-plan area", desc, META, MODERATE, "geo", desc, limitations=LOC_LIMIT))
    t = number_type(num)
    res.add(Finding("Number type", TYPE_NAMES.get(t, "Unknown"), META, MODERATE, "classification", TYPE_NAMES.get(t, ""),
                    limitations="Some countries (e.g. US/CA) do not distinguish mobile and fixed-line ranges "
                                "('Fixed Line Or Mobile')."))
    c = carrier.name_for_number(num, "en")
    if c:
        res.add(Finding("Originally allocated carrier", c, META, LOW, "carrier", c,
                        limitations="Shows the carrier the number BLOCK was assigned to. Numbers are frequently ported "
                                    "to other carriers; real-time carrier lookup requires a paid HLR/LNP service."))
    else:
        res.add(Finding("Carrier not in public metadata", "libphonenumber has no carrier data for this range "
                        "(common for US/CA numbers).", META, VERIFIED, "carrier", "unknown"))
    tzs = [z for z in timezone.time_zones_for_number(num) if z != "Etc/Unknown"]
    if tzs:
        res.add(Finding("Time zone(s) of numbering region", ", ".join(tzs), META, MODERATE, "geo", ", ".join(tzs[:3]),
                        limitations=LOC_LIMIT))

    if web_search and valid:
        variants = [e164, intl, national]
        seen = set()
        for v in variants:
            if v in seen:
                continue
            seen.add(v)
            hits = search_engine.search(f'"{v}"', 8, res)
            search_engine.results_to_findings(hits, res, category="web-references", exact_term=v.lstrip("+"),
                                              what=f'exact query "{v}"')
            for h in hits:
                if any(x.lower() in f"{h.title} {h.snippet}".lower() for x in (v, national)):
                    res.relate(res.entity(E_URL, h.url, "UNVERIFIED", h.provider), p_ent, "references", LOW, h.provider)
        res.notes.append("Public business listings appear among web references when the number is published by a "
                         "business. Review each source before drawing conclusions.")
    return res
