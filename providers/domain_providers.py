"""DNS, RDAP, certificate transparency, archive and reputation lookups."""
from __future__ import annotations

import dns.exception
import dns.resolver
import dns.reversename

from core import http
from core.database import get_db

_resolver = dns.resolver.Resolver()
_resolver.lifetime = 6
_resolver.timeout = 3


def dns_query(name: str, rtype: str) -> list[str]:
    """Returns record strings; [] when the name/record does not exist.

    A temporary resolver failure (SERVFAIL / all nameservers unreachable / timeout) is
    raised instead of being reported as "no record" — otherwise a network problem would
    be recorded as a VERIFIED absence of SPF/DMARC/MX/etc.
    """
    try:
        ans = _resolver.resolve(name, rtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    out = []
    for r in ans:
        if rtype == "TXT":
            out.append(b"".join(r.strings).decode("utf-8", "replace"))
        elif rtype == "MX":
            out.append(f"{r.preference} {str(r.exchange).rstrip('.')}")
        else:
            out.append(r.to_text().rstrip("."))
    return out


def domain_exists(name: str) -> bool | None:
    try:
        _resolver.resolve(name, "SOA")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        # A zone that answers but has no SOA at the queried apex is unusual; treat as
        # existing rather than guessing absent.
        return True
    except dns.exception.DNSException:
        return None


def reverse_dns(ip: str) -> list[str]:
    """PTR records. [] means "no PTR"; resolver failures are raised so callers can
    distinguish them from a genuinely absent record."""
    try:
        return [r.to_text().rstrip(".") for r in _resolver.resolve(dns.reversename.from_address(ip), "PTR")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []


def rdap_domain(domain: str) -> dict:
    return http.get_json(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json"})


def rdap_ip(ip: str) -> dict:
    return http.get_json(f"https://rdap.org/ip/{ip}", headers={"Accept": "application/rdap+json"})


def rdap_summary(data: dict) -> dict:
    """Extract the publicly published RDAP fields. Many registries redact registrant data; that is expected."""
    out = {"handle": data.get("handle"), "name": data.get("name") or data.get("ldhName"),
           "status": data.get("status", []), "events": {}, "entities": [], "nameservers": [],
           "port43": data.get("port43"), "country": data.get("country"),
           "start": data.get("startAddress"), "end": data.get("endAddress"), "type": data.get("type"),
           "self": next((l.get("href") for l in data.get("links", []) if l.get("rel") == "self"), "")}
    for ev in data.get("events", []):
        out["events"][ev.get("eventAction")] = ev.get("eventDate")
    for ns in data.get("nameservers", []):
        out["nameservers"].append((ns.get("ldhName") or "").lower())

    def walk(ents):
        for e in ents or []:
            name, org = None, None
            for item in (e.get("vcardArray") or [None, []])[1]:
                if item[0] == "fn":
                    name = item[3]
                if item[0] == "org":
                    org = item[3] if isinstance(item[3], str) else " ".join(item[3])
            out["entities"].append({"roles": e.get("roles", []), "name": name, "org": org, "handle": e.get("handle")})
            walk(e.get("entities"))
    walk(data.get("entities"))
    return out


def crtsh(domain: str) -> list[dict]:
    r = http.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=25, max_bytes=15_000_000)
    if r.status_code != 200:
        raise http.HttpError(f"crt.sh returned HTTP {r.status_code}")
    try:
        return r.json()
    except ValueError:
        raise http.HttpError("crt.sh returned an unreadable response (often temporary overload)")


def wayback_first_last(domain: str) -> dict:
    out = {}
    for label, params in (("first", {"limit": "1"}), ("last", {"limit": "-1"})):
        rows = http.get_json("https://web.archive.org/cdx/search/cdx",
                             params={"url": domain, "output": "json", "fl": "timestamp,original", **params}, timeout=20)
        if len(rows) > 1:
            out[label] = rows[1]
    return out


def virustotal(kind: str, value: str) -> dict | None:
    """kind: 'domains' or 'ip_addresses'. Returns None if not configured."""
    key = get_db().get_secret("virustotal_key")
    if not key:
        return None
    r = http.get(f"https://www.virustotal.com/api/v3/{kind}/{value}", headers={"x-apikey": key})
    if r.status_code == 404:
        return {}
    if r.status_code >= 400:
        raise http.HttpError(f"VirusTotal returned HTTP {r.status_code}")
    return r.json().get("data", {}).get("attributes", {})


COMMON_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim",
                         "smtp", "mandrill", "mxvault", "zoho", "protonmail", "fm1", "everlytickey1"]
