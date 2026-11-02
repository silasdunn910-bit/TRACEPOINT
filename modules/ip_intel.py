"""IP intelligence: validation, RDAP network owner, ASN, reverse DNS, geolocation (network-level),
hosting/proxy classification, optional reputation."""
from __future__ import annotations

import ipaddress

import dns.exception

from core.http import HttpError
from core.models import (E_DOMAIN, E_IP, E_ORG, LOW, MODERATE, R_ASSOCIATED, R_REGISTERED_ORG, R_RESOLVES, STRONG,
                         UNVERIFIED, VERIFIED, Finding, ModuleResult)
from providers import domain_providers as dp
from providers import ip_providers as ipp

GEO_LIMIT = ("IP geolocation estimates where the NETWORK is registered or routed. It is not a physical address or "
             "residence and is often off by hundreds of kilometres; VPNs, mobile carriers and CGNAT make it worse.")


def investigate(target: str) -> ModuleResult:
    raw = target.strip().strip("[]")
    res = ModuleResult("ip", raw)
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        res.errors.append(f"'{raw}' is not a valid IPv4 or IPv6 address.")
        return res
    ip_s = ip.compressed
    i_ent = res.entity(E_IP, ip_s, VERIFIED)
    res.add(Finding("Valid IP address", f"IPv{ip.version} address {ip_s}.", "Local validation", VERIFIED, "validation", ip_s))
    if not ip.is_global:
        kinds = [k for k in ("private", "loopback", "link_local", "multicast", "reserved", "unspecified")
                 if getattr(ip, f"is_{k}")]
        res.add(Finding("Non-public address", f"Address is {', '.join(kinds) or 'not globally routable'}; public "
                        "lookups do not apply.", "Local validation", VERIFIED, "validation", ", ".join(kinds)))
        return res

    # reverse DNS
    try:
        ptr = dp.reverse_dns(ip_s)
        res.source("Reverse DNS (PTR)", "", "ok")
        for p in ptr:
            res.add(Finding("Reverse DNS (PTR)", p, "Public DNS", VERIFIED, "network", p,
                            limitations="PTR records are set by the network operator and may be generic or stale."))
            res.relate(res.entity(E_DOMAIN, p.lower(), VERIFIED, "PTR"), i_ent, R_RESOLVES, VERIFIED, "PTR")
        if not ptr:
            res.add(Finding("No reverse DNS", "No PTR record returned.", "Public DNS", VERIFIED, "network", "none"))
    except dns.exception.DNSException as e:
        res.source("Reverse DNS (PTR)", "", "error", type(e).__name__)
        res.errors.append(f"PTR lookup failed: {type(e).__name__}")

    # RDAP: authoritative network registration
    try:
        s = dp.rdap_summary(dp.rdap_ip(ip_s))
        url = s["self"] or f"https://rdap.org/ip/{ip_s}"
        res.add(Finding("Registered network (RDAP)", f"{s['name']} {s['start']} – {s['end']} ({s['type'] or 'n/a'})",
                        "RDAP (Regional Internet Registry)", VERIFIED, "network", s["name"] or "", url,
                        f"handle={s['handle']} country={s['country']}",
                        "Registration describes the network block holder, not the individual user of the IP."))
        for ent in s["entities"]:
            label = ent["org"] or ent["name"]
            if label and {"registrant", "administrative"} & set(ent["roles"]):
                res.add(Finding("Network registrant", label, "RDAP", VERIFIED, "network", label, url,
                                f"roles={', '.join(ent['roles'])}"))
                res.relate(i_ent, res.entity(E_ORG, label, VERIFIED, "RDAP"), R_REGISTERED_ORG, VERIFIED, "RDAP")
        res.source("RDAP (IP)", url)
    except HttpError as e:
        res.source("RDAP (IP)", "", "error", str(e))
        res.errors.append(f"RDAP: {e}")

    # geolocation / ASN from two independent providers
    geo: dict[str, dict] = {}
    try:
        d = ipp.ip_api(ip_s)
        geo["ip-api.com"] = {"country": d.get("countryCode"), "region": d.get("regionName"), "city": d.get("city")}
        url = f"https://ip-api.com/#{ip_s}"
        res.add(Finding("ASN / network operator", f"{d.get('as')} — ISP: {d.get('isp')}, org: {d.get('org')}",
                        "ip-api.com", MODERATE, "network", d.get("as", ""), url,
                        limitations="Derived from BGP and registry data by a third party."))
        if d.get("as"):
            res.relate(i_ent, res.entity(E_ORG, d.get("asname") or d.get("isp") or d["as"], MODERATE, "ip-api"),
                       R_ASSOCIATED, MODERATE, "ASN operator (ip-api)")
        flags = [k for k in ("hosting", "proxy", "mobile") if d.get(k)]
        res.add(Finding("Network classification", ("Flags: " + ", ".join(flags)) if flags else
                        "Not flagged as hosting, proxy/VPN or mobile.", "ip-api.com", MODERATE, "classification",
                        ", ".join(flags) or "residential/business (unflagged)", url,
                        limitations="Classification lists are heuristic and incomplete."))
        res.source("ip-api.com (free tier)", "http://ip-api.com")
    except HttpError as e:
        res.source("ip-api.com (free tier)", "", "error", str(e))
        res.errors.append(f"ip-api: {e}")
    try:
        d = ipp.ipinfo(ip_s)
        if d.get("bogon"):
            res.notes.append("IPinfo reports this as a bogon address.")
        else:
            geo["ipinfo.io"] = {"country": d.get("country"), "region": d.get("region"), "city": d.get("city")}
            if d.get("org"):
                res.add(Finding("ASN / organization (IPinfo)", d["org"], "IPinfo", MODERATE, "network", d["org"],
                                f"https://ipinfo.io/{ip_s}"))
        res.source("IPinfo", f"https://ipinfo.io/{ip_s}")
    except HttpError as e:
        res.source("IPinfo", "", "error", str(e))

    if geo:
        countries = {g["country"] for g in geo.values() if g.get("country")}
        cities = {(g.get("city") or "").lower() for g in geo.values() if g.get("city")}
        country_agree = len(geo) > 1 and len(countries) == 1
        city_agree = len(cities) <= 1
        for prov, g in geo.items():
            if len(geo) == 1:
                conf = MODERATE
            elif country_agree and city_agree:
                conf = STRONG
            else:
                conf = LOW
            res.add(Finding(f"Network geolocation ({prov})", f"{g.get('city') or '?'}, {g.get('region') or '?'}, "
                            f"{g.get('country') or '?'}", prov, conf,
                            "geo", g.get("country") or "", limitations=GEO_LIMIT))
        if len(countries) > 1:
            res.add(Finding("Geolocation providers disagree on country", ", ".join(sorted(countries)),
                            "Cross-provider comparison", VERIFIED, "contradiction", ", ".join(sorted(countries)),
                            limitations=GEO_LIMIT))
        elif len(cities) > 1:
            res.add(Finding("Geolocation providers disagree on city", ", ".join(sorted(cities)),
                            "Cross-provider comparison", VERIFIED, "contradiction", ", ".join(sorted(cities)),
                            limitations=GEO_LIMIT))

    # reputation (optional)
    try:
        a = ipp.abuseipdb(ip_s)
        if a is None:
            res.source("AbuseIPDB", "", "not_configured", "Add an AbuseIPDB key to enable.")
        else:
            res.add(Finding("AbuseIPDB reputation", f"Abuse confidence {a.get('abuseConfidenceScore')}/100, "
                            f"{a.get('totalReports')} reports in 90 days; usage: {a.get('usageType')}",
                            "AbuseIPDB", MODERATE if a.get("totalReports") else LOW, "reputation",
                            str(a.get("abuseConfidenceScore")), f"https://www.abuseipdb.com/check/{ip_s}",
                            limitations="Crowd-sourced reports; dynamic/shared IPs inherit others' history."))
            res.source("AbuseIPDB", f"https://www.abuseipdb.com/check/{ip_s}")
    except HttpError as e:
        res.source("AbuseIPDB", "", "error", str(e))
    try:
        vt = dp.virustotal("ip_addresses", ip_s)
        if vt is None:
            res.source("VirusTotal", "", "not_configured", "Add a VirusTotal key to enable.")
        else:
            st = vt.get("last_analysis_stats", {})
            res.add(Finding("VirusTotal reputation", f"{st.get('malicious', 0)} malicious / {st.get('suspicious', 0)} "
                            "suspicious verdicts.", "VirusTotal", MODERATE if st.get("malicious") else LOW, "reputation",
                            str(st.get("malicious", 0)), f"https://www.virustotal.com/gui/ip-address/{ip_s}", str(st)))
            res.source("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{ip_s}")
    except HttpError as e:
        res.source("VirusTotal", "", "error", str(e))
    return res
