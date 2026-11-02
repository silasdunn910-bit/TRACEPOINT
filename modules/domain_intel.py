"""Domain intelligence: DNS, RDAP, email auth records, CT logs, archive history, reputation."""
from __future__ import annotations

import re
from urllib.parse import urlparse

import dns.exception

from core.http import HttpError
from core.models import (E_DOMAIN, E_IP, E_ORG, LOW, MODERATE, R_HOSTED_BY, R_LINKS_TO, R_REGISTERED_ORG,
                         R_RESOLVES, UNVERIFIED, VERIFIED, Finding, ModuleResult)
from providers import domain_providers as dp

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$", re.I)
DNS_LIMIT = "DNS answers reflect the current public configuration seen by this resolver; records can change at any time."
RDAP_LIMIT = ("RDAP shows what the registry publishes. Registrant details are frequently redacted for privacy; "
              "a privacy/proxy service is not the actual owner.")


def normalize_domain(value: str) -> str:
    v = value.strip().lower()
    if "://" in v:
        v = urlparse(v).hostname or ""
    v = v.split("/")[0].split(":")[0].rstrip(".")
    return v.removeprefix("www.") if v.count(".") > 1 and v.startswith("www.") else v


def name_in_domain(name: str, domain: str) -> bool:
    """True only when name is the domain or a real subdomain of it (label boundary)."""
    name = str(name).strip().lower().lstrip("*.")
    return name == domain or name.endswith("." + domain)


def email_auth_records(domain: str, res: ModuleResult, dkim_selector: str = "", probe_common: bool = True):
    """SPF, DMARC, DKIM. Shared with the email module."""
    src = "Public DNS"
    try:
        txt = dp.dns_query(domain, "TXT")
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        if spf:
            res.add(Finding("SPF record present", "Domain publishes an SPF policy listing permitted mail senders.",
                            src, VERIFIED, "email-auth", spf[0], evidence=f"TXT {domain}: {spf[0]}",
                            limitations=DNS_LIMIT))
            if len(spf) > 1:
                res.add(Finding("Multiple SPF records", "More than one SPF record exists, which is invalid per RFC 7208.",
                                src, VERIFIED, "email-auth", str(len(spf)), evidence="\n".join(spf), limitations=DNS_LIMIT))
        else:
            res.add(Finding("No SPF record", "No v=spf1 TXT record found.", src, VERIFIED, "email-auth", "none",
                            evidence=f"TXT query for {domain}", limitations=DNS_LIMIT))
        dmarc = [t for t in dp.dns_query(f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
        if dmarc:
            pol = re.search(r"\bp=(\w+)", dmarc[0])
            res.add(Finding("DMARC record present", f"DMARC policy: {pol.group(1) if pol else 'unspecified'}.",
                            src, VERIFIED, "email-auth", dmarc[0], evidence=f"TXT _dmarc.{domain}: {dmarc[0]}",
                            limitations=DNS_LIMIT))
        else:
            res.add(Finding("No DMARC record", "No DMARC policy published.", src, VERIFIED, "email-auth", "none",
                            evidence=f"TXT _dmarc.{domain}", limitations=DNS_LIMIT))
        selectors = [dkim_selector] if dkim_selector else (dp.COMMON_DKIM_SELECTORS if probe_common else [])
        found = []
        for sel in selectors:
            recs = [t for t in dp.dns_query(f"{sel}._domainkey.{domain}", "TXT") if "p=" in t or "k=" in t]
            recs += [c for c in dp.dns_query(f"{sel}._domainkey.{domain}", "CNAME")]
            if recs:
                found.append(sel)
                res.add(Finding(f"DKIM key found (selector '{sel}')", "A DKIM public key or delegation is published.",
                                src, VERIFIED, "email-auth", f"{sel}._domainkey.{domain}", evidence=recs[0][:300],
                                limitations=DNS_LIMIT))
        if not found and selectors:
            res.add(Finding("No DKIM key at checked selectors",
                            f"Checked {len(selectors)} selector(s): {', '.join(selectors)}.", src, LOW, "email-auth",
                            "not found", limitations="DKIM selectors cannot be enumerated. Absence at common selectors "
                            "does not mean DKIM is unused."))
        res.source("Public DNS (SPF/DMARC/DKIM)", "", "ok")
    except dns.exception.DNSException as e:
        res.source("Public DNS (SPF/DMARC/DKIM)", "", "error", type(e).__name__)
        res.errors.append(f"DNS email-auth lookup failed: {type(e).__name__}")


def investigate(target: str, *, dkim_selector: str = "", include_ct: bool = True, include_history: bool = True) -> ModuleResult:
    domain = normalize_domain(target)
    res = ModuleResult("domain", domain)
    if not DOMAIN_RE.match(domain):
        res.errors.append(f"'{target}' is not a valid domain name.")
        return res
    d_ent = res.entity(E_DOMAIN, domain, VERIFIED)

    exists = dp.domain_exists(domain)
    if exists is False:
        res.add(Finding("Domain does not resolve (NXDOMAIN)", "The domain does not exist in public DNS.", "Public DNS",
                        VERIFIED, "dns", domain, limitations=DNS_LIMIT))
    # ---------------- DNS records
    try:
        for rtype in ("A", "AAAA", "NS", "MX", "CNAME", "SOA", "CAA", "TXT"):
            for rec in dp.dns_query(domain, rtype):
                res.add(Finding(f"{rtype} record", f"Public {rtype} record for {domain}.", "Public DNS", VERIFIED,
                                "dns", rec, evidence=f"{domain} {rtype} {rec}", limitations=DNS_LIMIT))
                if rtype in ("A", "AAAA"):
                    res.relate(d_ent, res.entity(E_IP, rec, VERIFIED, "DNS"), R_RESOLVES, VERIFIED, "Public DNS")
                elif rtype == "NS":
                    res.relate(d_ent, res.entity(E_DOMAIN, rec.lower()), R_HOSTED_BY, VERIFIED, "Public DNS (NS)")
                elif rtype == "MX":
                    mx = rec.split()[-1].lower()
                    res.relate(d_ent, res.entity(E_DOMAIN, mx), R_LINKS_TO, VERIFIED, "Public DNS (MX)")
        res.source("Public DNS", "", "ok")
    except dns.exception.DNSException as e:
        res.source("Public DNS", "", "error", type(e).__name__)
        res.errors.append(f"DNS lookup failed: {type(e).__name__}")

    email_auth_records(domain, res, dkim_selector)

    # ---------------- RDAP
    try:
        raw = dp.rdap_domain(domain)
        s = dp.rdap_summary(raw)
        url = s["self"] or f"https://rdap.org/domain/{domain}"
        for action, date in s["events"].items():
            res.add(Finding(f"Registry event: {action}", f"RDAP reports '{action}' on {date}.", "RDAP", VERIFIED,
                            "registration", date, url, f"eventAction={action} eventDate={date}", RDAP_LIMIT))
        if s["status"]:
            res.add(Finding("Registry status", ", ".join(s["status"]), "RDAP", VERIFIED, "registration",
                            ", ".join(s["status"]), url, limitations=RDAP_LIMIT))
        for ent in s["entities"]:
            label = ent["org"] or ent["name"]
            if not label:
                continue
            roles = ", ".join(ent["roles"]) or "unspecified role"
            redacted = bool(re.search(r"redact|privacy|proxy|withheld|not disclosed|data protected", label, re.I))
            res.add(Finding(f"RDAP entity ({roles})", f"{label}" + (" — appears to be a privacy/redaction placeholder"
                                                                  if redacted else ""), "RDAP", VERIFIED,
                            "registration", label, url, f"roles={roles}", RDAP_LIMIT))
            if "registrar" in ent["roles"]:
                res.relate(d_ent, res.entity(E_ORG, label, VERIFIED, "RDAP"), R_REGISTERED_ORG, VERIFIED, "RDAP registrar")
            elif "registrant" in ent["roles"] and not redacted:
                res.relate(d_ent, res.entity(E_ORG, label, MODERATE, "RDAP"), R_REGISTERED_ORG, MODERATE,
                           "RDAP registrant (self-reported to registrar)")
        res.source("RDAP (rdap.org bootstrap)", url, "ok")
    except HttpError as e:
        res.source("RDAP (rdap.org bootstrap)", f"https://rdap.org/domain/{domain}", "error", str(e))
        res.errors.append(f"RDAP: {e}")

    # ---------------- Certificate transparency
    if include_ct:
        try:
            rows = dp.crtsh(domain)
            names: set[str] = set()
            for r in rows:
                for n in str(r.get("name_value", "")).splitlines():
                    n = n.strip().lower().lstrip("*.")
                    # Require a real label boundary so "notexample.com" is not counted
                    # as a hostname inside "example.com".
                    if name_in_domain(n, domain):
                        names.add(n)
            issuers = sorted({str(r.get("issuer_name", "")).split("O=")[-1].split(",")[0] for r in rows})[:8]
            dates = sorted(r.get("not_before", "") for r in rows if r.get("not_before"))
            res.add(Finding("Certificate transparency summary",
                            f"{len(rows)} logged certificates; {len(names)} distinct hostnames.", "crt.sh", VERIFIED,
                            "certificates", str(len(rows)), f"https://crt.sh/?q=%25.{domain}",
                            f"Issuers: {', '.join(issuers)}\nEarliest not_before: {dates[0] if dates else 'n/a'}",
                            "CT logs record issued certificates, not whether a host is live today."))
            for n in sorted(names)[:60]:
                if n != domain:
                    res.add(Finding("Hostname seen in CT logs", n, "crt.sh", VERIFIED, "subdomains", n,
                                    f"https://crt.sh/?q={n}", limitations="Listed in a certificate; may no longer exist."))
                    res.relate(res.entity(E_DOMAIN, n, VERIFIED, "crt.sh"), d_ent, "part of", VERIFIED, "crt.sh")
            if len(names) > 60:
                res.notes.append(f"{len(names) - 60} additional CT hostnames omitted.")
            res.source("crt.sh certificate transparency", f"https://crt.sh/?q=%25.{domain}", "ok")
        except HttpError as e:
            res.source("crt.sh certificate transparency", "https://crt.sh", "error", str(e))
            res.errors.append(f"crt.sh: {e}")

    # ---------------- Archive history
    if include_history:
        try:
            wb = dp.wayback_first_last(domain)
            for label, row in wb.items():
                ts = row[0]
                pretty = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
                res.add(Finding(f"Wayback Machine {label} capture", f"{label.title()} archived capture on {pretty}.",
                                "Internet Archive", VERIFIED, "history", pretty,
                                f"https://web.archive.org/web/{ts}/{row[1]}",
                                limitations="Archive coverage is incomplete; absence of captures proves nothing."))
            if not wb:
                res.add(Finding("No Wayback Machine captures", "The Internet Archive returned no captures.",
                                "Internet Archive", LOW, "history", "none"))
            res.source("Internet Archive CDX", "https://web.archive.org", "ok")
        except HttpError as e:
            res.source("Internet Archive CDX", "https://web.archive.org", "error", str(e))
            res.errors.append(f"Wayback: {e}")

    # ---------------- Reputation (optional)
    try:
        vt = dp.virustotal("domains", domain)
        if vt is None:
            res.source("VirusTotal", "", "not_configured", "Add a VirusTotal key in API Configuration to enable.")
        else:
            stats = vt.get("last_analysis_stats", {})
            mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
            res.add(Finding("VirusTotal reputation", f"{mal} engines flag malicious, {sus} suspicious.", "VirusTotal",
                            MODERATE if (mal or sus) else LOW, "reputation", f"{mal}/{sus}",
                            f"https://www.virustotal.com/gui/domain/{domain}", str(stats),
                            "Vendor verdicts disagree and can be stale or false positives."))
            res.source("VirusTotal", f"https://www.virustotal.com/gui/domain/{domain}", "ok")
    except HttpError as e:
        res.source("VirusTotal", "", "error", str(e))
    return res
