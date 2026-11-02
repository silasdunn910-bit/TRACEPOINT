"""Security intelligence: phishing and suspicious-infrastructure indicators for a domain or URL.

Heuristic, evidence-backed signals only. A high indicator count is a prompt to investigate,
never a verdict that a site is malicious.
"""
from __future__ import annotations

import datetime as dt
import re
from urllib.parse import urlparse

from core.http import HttpError
from core.models import (E_DOMAIN, LOW, MODERATE, STRONG, UNVERIFIED, VERIFIED, Finding, ModuleResult)
from modules import domain_intel
from providers import domain_providers as dp

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "gq", "ml", "cf", "ga", "tk", "work", "click", "link", "country",
                   "kim", "men", "loan", "download", "review", "fit", "rest", "support", "quest", "cfd", "sbs"}
BRAND_KEYWORDS = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook", "instagram", "whatsapp",
                  "bank", "secure", "account", "login", "verify", "update", "wallet", "crypto", "coinbase", "binance",
                  "office365", "outlook", "icloud", "signin", "support", "service", "billing", "invoice", "usps",
                  "fedex", "dhl", "dpd", "hmrc", "irs", "gov"]
HOMOGLYPH = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "rn": "m", "vv": "w"}
LIMIT = ("These are automated heuristic indicators, not a determination that a site is malicious or safe. "
         "Confirm with the registrar, the brand owner, and a sandbox before acting.")


def _shannon(s: str) -> float:
    from math import log2
    s = s or ""
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * log2(s.count(c) / len(s)) for c in set(s))


def investigate(target: str) -> ModuleResult:
    raw = target.strip()
    host = domain_intel.normalize_domain(raw)
    res = ModuleResult("security", raw)
    if not domain_intel.DOMAIN_RE.match(host):
        res.errors.append(f"'{raw}' is not a valid domain or URL.")
        return res
    d_ent = res.entity(E_DOMAIN, host, VERIFIED)
    res.source("Heuristic analysis (local)")
    indicators = 0
    labels = host.split(".")
    sld = labels[-2] if len(labels) >= 2 else host
    tld = labels[-1]

    # 1. TLD
    if tld in SUSPICIOUS_TLDS:
        indicators += 1
        res.add(Finding("Low-reputation TLD", f".{tld} is frequently abused for throwaway/phishing domains.",
                        "Heuristic", MODERATE, "phishing-indicator", tld, limitations=LIMIT))

    # 2. brand keyword in a domain that isn't the brand's own
    for kw in BRAND_KEYWORDS:
        if kw in host.lower():
            indicators += 1
            res.add(Finding(f"Brand/urgency keyword '{kw}' in hostname",
                            "Phishing domains often embed a brand or action word to look legitimate.", "Heuristic",
                            MODERATE, "phishing-indicator", kw, evidence=f"hostname: {host}",
                            limitations=LIMIT + " Legitimate sites also use these words."))
            break

    # 3. structure: many hyphens, very long, many subdomains, digits
    if host.count("-") >= 3:
        indicators += 1
        res.add(Finding("Many hyphens in hostname", f"{host.count('-')} hyphens.", "Heuristic", LOW,
                        "phishing-indicator", str(host.count("-")), limitations=LIMIT))
    if len(host) >= 30:
        indicators += 1
        res.add(Finding("Unusually long hostname", f"{len(host)} characters.", "Heuristic", LOW, "phishing-indicator",
                        str(len(host)), limitations=LIMIT))
    if len(labels) >= 5:
        indicators += 1
        res.add(Finding("Deeply nested subdomains", f"{len(labels)} labels; brand names are sometimes hidden in "
                        "subdomains.", "Heuristic", LOW, "phishing-indicator", str(len(labels)), limitations=LIMIT))
    if _shannon(sld) > 3.5 and len(sld) > 8:
        indicators += 1
        res.add(Finding("High-entropy domain label", f"'{sld}' looks random/algorithmically generated "
                        f"(entropy {_shannon(sld):.2f}).", "Heuristic", LOW, "phishing-indicator", sld, limitations=LIMIT))

    # 4. homoglyph / look-alike
    deglyph = sld.lower()
    for a, b in HOMOGLYPH.items():
        deglyph = deglyph.replace(a, b)
    hit = next((b for b in BRAND_KEYWORDS if b in deglyph and b not in sld.lower()), None)
    if hit:
        indicators += 1
        res.add(Finding("Possible look-alike (homoglyph) domain", f"Normalizing digits/letters turns '{sld}' into "
                        f"something containing '{hit}'.", "Heuristic", MODERATE, "phishing-indicator", deglyph,
                        limitations=LIMIT))

    # 5. domain age via RDAP — brand-new domains are higher risk
    try:
        s = dp.rdap_summary(dp.rdap_domain(host))
        reg = s["events"].get("registration")
        if reg:
            try:
                registered = dt.datetime.fromisoformat(reg.replace("Z", "+00:00"))
                if registered.tzinfo is None:
                    registered = registered.replace(tzinfo=dt.timezone.utc)
                age_days = (dt.datetime.now(dt.timezone.utc) - registered).days
                conf = STRONG if age_days < 30 else MODERATE if age_days < 90 else LOW
                note = "VERY recently registered" if age_days < 30 else "recently registered" if age_days < 90 else "established"
                if age_days < 90:
                    indicators += 1
                res.add(Finding(f"Domain age: {age_days} days ({note})", f"Registered {reg}.", "RDAP",
                                conf if age_days < 90 else VERIFIED, "phishing-indicator" if age_days < 90 else "registration",
                                str(age_days), s["self"] or "", limitations=LIMIT))
            except (ValueError, TypeError):
                res.notes.append(f"RDAP registration date '{reg}' could not be parsed; domain age not scored.")
        res.source("RDAP", s["self"] or f"https://rdap.org/domain/{host}")
    except HttpError as e:
        res.source("RDAP", "", "error", str(e))

    # 6. email-auth weaknesses (reuses domain module)
    auth = ModuleResult("security", host)
    domain_intel.email_auth_records(host, auth, probe_common=True)
    res.merge(auth)
    # Only score "missing" records when the DNS lookup itself succeeded. A resolver
    # failure is not evidence that SPF/DMARC are absent.
    auth_source = next((s for s in auth.sources if s.name == "Public DNS (SPF/DMARC/DKIM)"), None)
    auth_ok = auth_source is not None and auth_source.status == "ok"
    if not auth_ok:
        res.notes.append("Email-auth weakness scoring skipped: the DNS lookup did not complete.")
    else:
        spf = any(f.category == "email-auth" and "SPF record present" in f.title for f in auth.findings)
        dmarc_present = any("DMARC record present" in f.title for f in auth.findings)
        dmarc_strong = any(f.category == "email-auth" and ("p=reject" in f.value or "p=quarantine" in f.value)
                           for f in auth.findings)
        if not spf:
            indicators += 1
            res.add(Finding("Weak email auth: no SPF", "Domain can be more easily spoofed in email.",
                            "Email-auth analysis", MODERATE, "security-weakness", "no SPF", limitations=LIMIT))
        if not dmarc_present:
            indicators += 1
            res.add(Finding("Weak email auth: no DMARC", "No DMARC policy to instruct receivers on spoofed mail.",
                            "Email-auth analysis", MODERATE, "security-weakness", "no DMARC", limitations=LIMIT))
        elif not dmarc_strong:
            res.add(Finding("DMARC present but not enforcing", "DMARC policy is p=none (monitor only).",
                            "Email-auth analysis", LOW, "security-weakness", "p=none", limitations=LIMIT))

    # 7. reputation (optional VT)
    try:
        vt = dp.virustotal("domains", host)
        if vt is None:
            res.source("VirusTotal", "", "not_configured", "Add a VirusTotal key for reputation.")
        else:
            st = vt.get("last_analysis_stats", {})
            mal, susp = st.get("malicious", 0), st.get("suspicious", 0)
            if mal or susp:
                indicators += 2
            res.add(Finding("VirusTotal reputation", f"{mal} malicious / {susp} suspicious vendor verdicts.",
                            "VirusTotal", STRONG if mal >= 3 else MODERATE if (mal or susp) else LOW, "reputation",
                            f"{mal}/{susp}", f"https://www.virustotal.com/gui/domain/{host}", str(st),
                            "Vendor verdicts can be stale or false positives."))
            res.source("VirusTotal", f"https://www.virustotal.com/gui/domain/{host}")
    except HttpError as e:
        res.source("VirusTotal", "", "error", str(e))

    band = "HIGH" if indicators >= 6 else "ELEVATED" if indicators >= 3 else "LOW"
    res.add(Finding(f"Overall phishing-indicator count: {indicators} ({band})",
                    f"{indicators} heuristic indicator(s) were raised for {host}.", "TRACEPOINT heuristic summary",
                    MODERATE if band != "LOW" else LOW, "summary", str(indicators),
                    limitations="A count of heuristics, NOT a verdict. High counts warrant caution and manual review; "
                                "low counts do not certify a site as safe."))
    res.notes.append(f"Security indicator band: {band} ({indicators} indicators).")
    return res
