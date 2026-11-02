"""Email intelligence: syntax, domain, disposable check, MX/SPF/DMARC/DKIM, RDAP,
public indexed references, Gravatar public profile, optional HIBP breach names."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import quote

from core import http, search_engine
from core.database import get_db
from core.http import HttpError
from core.models import (E_DOMAIN, E_EMAIL, E_SOCIAL, E_URL, LOW, MODERATE, R_ASSOCIATED, R_LINKS_TO, R_PART_OF,
                         UNVERIFIED, VERIFIED, Finding, ModuleResult)
from modules import domain_intel
from providers import domain_providers as dp

EMAIL_RE = re.compile(r"^(?=.{3,254}$)[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$")
_DISPOSABLE_FILE = Path(__file__).parent / "data" / "disposable_domains.txt"
FREE_PROVIDERS = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
                  "icloud.com", "me.com", "mac.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "gmx.de",
                  "mail.com", "yandex.com", "yandex.ru", "zoho.com", "tutanota.com", "fastmail.com", "hey.com"}
_disposable: set[str] | None = None


def disposable_domains() -> set[str]:
    global _disposable
    if _disposable is None:
        try:
            _disposable = {l.strip().lower() for l in _DISPOSABLE_FILE.read_text(encoding="utf-8").splitlines()
                           if l.strip() and not l.startswith("#")}
        except OSError:
            _disposable = set()
    return _disposable


def investigate(target: str, *, dkim_selector: str = "", web_search: bool = True) -> ModuleResult:
    email = target.strip()
    res = ModuleResult("email", email)
    if not EMAIL_RE.match(email):
        res.add(Finding("Invalid email syntax", "Address does not match RFC 5322 practical syntax.", "Local validation",
                        VERIFIED, "syntax", email))
        res.errors.append("Invalid email address; further lookups skipped.")
        return res
    local, domain = email.rsplit("@", 1)
    domain = domain.lower()
    norm = f"{local}@{domain}"
    e_ent = res.entity(E_EMAIL, norm, VERIFIED)
    d_ent = res.entity(E_DOMAIN, domain, VERIFIED)
    res.relate(e_ent, d_ent, R_PART_OF, VERIFIED, "Address syntax")
    res.add(Finding("Valid email syntax", f"Local part '{local}', domain '{domain}'.", "Local validation", VERIFIED,
                    "syntax", norm, limitations="Valid syntax does not mean the mailbox exists."))
    res.source("Local syntax validation")

    if "+" in local:
        res.add(Finding("Sub-address (plus tag) used", f"Base address is likely {local.split('+')[0]}@{domain}.",
                        "Local analysis", MODERATE, "syntax", local.split("+")[0] + "@" + domain,
                        limitations="Plus-addressing behaviour depends on the provider."))

    # disposable / provider type
    disp = disposable_domains()
    if domain in disp:
        res.add(Finding("Disposable email domain", f"{domain} is on the community disposable-domain blocklist.",
                        "disposable-email-domains list", VERIFIED, "classification", domain,
                        "https://github.com/disposable-email-domains/disposable-email-domains",
                        limitations="List membership is community-maintained."))
    elif domain in FREE_PROVIDERS:
        res.add(Finding("Free webmail provider", f"{domain} is a consumer webmail service; the domain says nothing about "
                        "an employer or organization.", "Local classification", VERIFIED, "classification", domain))
    else:
        res.add(Finding("Custom / organizational domain", f"{domain} is not a known free or disposable provider.",
                        "Local classification", MODERATE, "classification", domain,
                        limitations="Could be personal, corporate, or a lesser-known provider."))
    res.source("Disposable domain list", "", "ok", f"{len(disp)} domains")

    # MX
    try:
        mx = dp.dns_query(domain, "MX")
        if mx:
            for rec in mx:
                res.add(Finding("MX record", "Mail exchanger accepting mail for the domain.", "Public DNS", VERIFIED,
                                "mail", rec, evidence=f"{domain} MX {rec}", limitations=domain_intel.DNS_LIMIT))
                res.relate(d_ent, res.entity(E_DOMAIN, rec.split()[-1].lower()), R_LINKS_TO, VERIFIED, "MX")
        else:
            a = dp.dns_query(domain, "A")
            res.add(Finding("No MX record", "Domain has no MX record" + (" (falls back to A record)." if a else
                            " and no A record: it cannot receive email."), "Public DNS", VERIFIED, "mail", "none",
                            limitations=domain_intel.DNS_LIMIT))
        res.source("Public DNS (MX)")
    except Exception as e:
        res.source("Public DNS (MX)", "", "error", type(e).__name__)
        res.errors.append(f"MX lookup failed: {type(e).__name__}")

    domain_intel.email_auth_records(domain, res, dkim_selector, probe_common=bool(dkim_selector) or domain not in FREE_PROVIDERS)

    # RDAP for organizational domains
    if domain not in FREE_PROVIDERS:
        try:
            s = dp.rdap_summary(dp.rdap_domain(domain))
            url = s["self"] or f"https://rdap.org/domain/{domain}"
            if "registration" in s["events"]:
                res.add(Finding("Domain registration date", s["events"]["registration"], "RDAP", VERIFIED,
                                "registration", s["events"]["registration"], url, limitations=domain_intel.RDAP_LIMIT))
            for ent in s["entities"]:
                if "registrar" in ent["roles"] and (ent["org"] or ent["name"]):
                    res.add(Finding("Domain registrar", ent["org"] or ent["name"], "RDAP", VERIFIED, "registration",
                                    ent["org"] or ent["name"], url, limitations=domain_intel.RDAP_LIMIT))
            res.source("RDAP", url)
        except HttpError as e:
            res.source("RDAP", "", "error", str(e))

    # Gravatar public profile (only public data the owner chose to publish)
    sha = hashlib.sha256(norm.lower().encode()).hexdigest()
    try:
        r = http.get(f"https://api.gravatar.com/v3/profiles/{sha}")
        if r.status_code == 200:
            p = r.json()
            res.add(Finding("Public Gravatar profile", f"Display name: {p.get('display_name') or 'n/a'}; "
                            f"location field: {p.get('location') or 'n/a'}", "Gravatar", VERIFIED, "profile",
                            p.get("profile_url", ""), p.get("profile_url", ""),
                            f"Profile linked to the SHA-256 of this address. Job title: {p.get('job_title') or 'n/a'}, "
                            f"company: {p.get('company') or 'n/a'}",
                            "Profile fields are self-reported by whoever controls the address and may be inaccurate."))
            s_ent = res.entity(E_SOCIAL, p.get("profile_url", f"gravatar:{sha[:12]}"), VERIFIED, "Gravatar")
            res.relate(e_ent, s_ent, R_ASSOCIATED, VERIFIED, "Gravatar hash match")
            for acc in p.get("verified_accounts", []) or []:
                if acc.get("url"):
                    res.add(Finding(f"Gravatar-linked account ({acc.get('service_label', acc.get('service_type'))})",
                                    "Account link published on the public Gravatar profile.", "Gravatar", MODERATE,
                                    "profile", acc["url"], acc["url"],
                                    limitations="Self-published link; verification status per Gravatar."))
                    res.relate(s_ent, res.entity(E_URL, acc["url"]), R_LINKS_TO, MODERATE, "Gravatar")
        elif r.status_code == 404:
            res.add(Finding("No public Gravatar profile", "No Gravatar profile is published for this address.",
                            "Gravatar", VERIFIED, "profile", "none"))
        res.source("Gravatar public profile API", "https://gravatar.com", "ok" if r.status_code in (200, 404) else "error",
                   f"HTTP {r.status_code}")
    except HttpError as e:
        res.source("Gravatar public profile API", "", "error", str(e))

    # Breach exposure via HIBP (breach names and data classes only; never credentials)
    key = get_db().get_secret("hibp_key")
    if key:
        try:
            r = http.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(norm)}",
                         params={"truncateResponse": "false"}, headers={"hibp-api-key": key})
            if r.status_code == 404:
                res.add(Finding("No breaches listed in HIBP", "HIBP has no breach records for this address.",
                                "Have I Been Pwned", VERIFIED, "breach", "0", "https://haveibeenpwned.com",
                                limitations="Only covers breaches HIBP has loaded."))
            elif r.status_code == 200:
                for b in r.json():
                    res.add(Finding(f"Breach: {b.get('Title', b.get('Name'))}",
                                    f"Address appears in the {b.get('Name')} breach ({b.get('BreachDate')}).",
                                    "Have I Been Pwned", VERIFIED, "breach", b.get("Name", ""),
                                    f"https://haveibeenpwned.com/PwnedWebsites#{b.get('Name')}",
                                    "Exposed data types: " + ", ".join(b.get("DataClasses", [])),
                                    "TRACEPOINT never retrieves or displays breached data itself."))
            else:
                res.errors.append(f"HIBP returned HTTP {r.status_code}")
            res.source("Have I Been Pwned", "https://haveibeenpwned.com", "ok" if r.status_code in (200, 404) else "error")
        except HttpError as e:
            res.source("Have I Been Pwned", "", "error", str(e))
    else:
        res.source("Have I Been Pwned", "", "not_configured", "Add an HIBP API key to enable breach checks.")

    # Public indexed references
    if web_search:
        hits = search_engine.search(f'"{norm}"', 10, res)
        search_engine.results_to_findings(hits, res, category="web-references", exact_term=norm,
                                          what=f'exact query "{norm}"')
        for h in hits:
            if norm.lower() in f"{h.title} {h.snippet}".lower():
                res.relate(res.entity(E_URL, h.url, UNVERIFIED, h.provider), e_ent, "references", LOW, h.provider)
    return res
