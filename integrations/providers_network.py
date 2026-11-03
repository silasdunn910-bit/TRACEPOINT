"""IP and network intelligence: IPinfo, IPdata, IP-DB, OpenIPAPI, BGPView, RIPEstat, RDAP.

An IP address locates a network connection, not a person. Every result carries that limitation."""
from __future__ import annotations

import re

from .base import (FREE, FREE_TIER, InputError, Provider, ResponseError, clean_domain, clean_ip)

_GEO_LIMIT = ("IP geolocation is approximate (often city level or worse) and reflects the network operator, "
              "not the person using the address. An IP address is never proof of identity.",)
_PROBE_IP = "8.8.8.8"  # Google Public DNS: a stable, well-known public address used only for connection tests


def _asn(value: str) -> int:
    m = re.fullmatch(r"(?i)\s*(?:AS)?(\d{1,10})\s*", value or "")
    if not m or not (0 < int(m.group(1)) < 4_294_967_296):
        raise InputError("Not a valid AS number (e.g. AS15169).")
    return int(m.group(1))


class IPinfo(Provider):
    id = "ipinfo"; name = "IPinfo"; category = "IP / Network"; tier = FREE_TIER
    free_info = "Free account token; monthly request allowance (see ipinfo.io/pricing). Works without a token at a much lower limit."
    signup_url = "https://ipinfo.io/signup"; docs_url = "https://ipinfo.io/developers"
    endpoint = "https://ipinfo.io/{ip}/json"; auth = "Authorization: Bearer <token> (optional)"
    optional_keys = ("ipinfo_token",)
    lookups = {"ip": "Geolocation, organisation/ASN and hostname for an IP"}
    limitations = _GEO_LIMIT + ("Free-tier responses omit some fields (e.g. privacy detection, carrier).",)

    def _fetch(self, ip):
        tok = self.secret("ipinfo_token")
        r = self.get(f"https://ipinfo.io/{ip}/json", headers={"Authorization": f"Bearer {tok}"} if tok else None)
        d = self.json(r, dict)
        if "ip" not in d:
            raise ResponseError("IPinfo response has no 'ip' field.")
        return d

    def _probe(self):
        d = self._fetch(_PROBE_IP)
        return "Authenticated request succeeded." if self.secret("ipinfo_token") else \
            "Unauthenticated request succeeded (no token set; lower limits apply)."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        ip = clean_ip(value)
        d = self._fetch(ip)
        return self._result(ip, f"https://ipinfo.io/{ip}", "ip_geolocation",
                            {"summary": {k: d.get(k) for k in ("hostname", "city", "region", "country", "loc", "org",
                                                              "postal", "timezone")}, "raw": d})


class IPdata(Provider):
    id = "ipdata"; name = "IPdata"; category = "IP / Network"; tier = FREE_TIER
    free_info = "Free account key; roughly 1,500 requests/day on the free plan (verify on ipdata.co/pricing)."
    signup_url = "https://ipdata.co/sign-up.html"; docs_url = "https://docs.ipdata.co/"
    endpoint = "https://api.ipdata.co/{ip}"; auth = "api-key query parameter"
    secret_keys = ("ipdata_key",)
    lookups = {"ip": "Geolocation, ASN, threat flags (free-plan fields)"}
    limitations = _GEO_LIMIT + ("Threat/VPN/proxy fields may be restricted on the free plan.",)

    def _fetch(self, ip):
        r = self.get(f"https://api.ipdata.co/{ip}", params={"api-key": self.secret("ipdata_key")})
        d = self.json(r, dict)
        if "ip" not in d:
            raise ResponseError("IPdata response has no 'ip' field.")
        return d

    def _probe(self):
        self._fetch(_PROBE_IP)
        return "Authenticated request succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        ip = clean_ip(value)
        d = self._fetch(ip)
        return self._result(ip, f"https://api.ipdata.co/{ip}", "ip_geolocation",
                            {"summary": {k: d.get(k) for k in ("city", "region", "country_name", "latitude", "longitude",
                                                              "asn", "threat", "time_zone")}, "raw": d})


class IPDB(Provider):
    id = "ipdb"; name = "IP-DB"; category = "IP / Network"; tier = FREE_TIER
    free_info = "Free key: 1,000 checks/day, 10,000/day with a verified email (per ip-db.com/en/api-docs)."
    signup_url = "https://ip-db.com/en/api-docs"; docs_url = "https://ip-db.com/en/api-docs"
    endpoint = "https://ip-db.com/api/v1/check/{ip}"; auth = "Key header"
    secret_keys = ("ipdb_key",)
    lookups = {"ip": "Abuse/blacklist score, network type and location"}
    limitations = _GEO_LIMIT + ("Reputation scores aggregate third-party feeds; an IP listed once may be shared or reassigned.",)

    def _fetch(self, ip):
        r = self.get(f"https://ip-db.com/api/v1/check/{ip}", headers={"Key": self.secret("ipdb_key"),
                                                                       "Accept": "application/json"})
        return self.json(r, dict)

    def _probe(self):
        self._fetch(_PROBE_IP)
        return "Authenticated request succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        ip = clean_ip(value)
        d = self._fetch(ip)
        return self._result(ip, f"https://ip-db.com/ip/{ip}", "ip_reputation", {"raw": d})


class OpenIPAPI(Provider):
    id = "openipapi"; name = "OpenIPAPI"; category = "IP / Network"; tier = FREE_TIER
    free_info = "Free key: 10,000 lookups/month; location and network on the free plan, threat flags on paid plans."
    signup_url = "https://www.openipapi.com/"; docs_url = "https://www.openipapi.com/docs"
    endpoint = "https://api.openipapi.com/v1/lookup/{ip}"; auth = "X-API-Key header"
    secret_keys = ("openipapi_key",)
    lookups = {"ip": "Geolocation and network owner", "asn": "AS information"}
    limitations = _GEO_LIMIT + ("VPN/proxy/Tor flags and risk scores require a paid plan.",)

    def _get(self, path):
        r = self.get("https://api.openipapi.com" + path, headers={"X-API-Key": self.secret("openipapi_key")})
        return self.json(r, dict)

    def _probe(self):
        self._get("/v1/account/usage")  # key check that does not spend a lookup
        return "Authenticated request succeeded (account usage endpoint)."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        if kind == "asn":
            n = _asn(value)
            return self._result(f"AS{n}", f"https://www.openipapi.com/asn/{n}", "asn_info",
                                {"raw": self._get(f"/v1/asn/{n}")})
        ip = clean_ip(value)
        return self._result(ip, f"https://api.openipapi.com/v1/lookup/{ip}", "ip_geolocation",
                            {"raw": self._get(f"/v1/lookup/{ip}")})


class BGPView(Provider):
    id = "bgpview"; name = "BGPView"; category = "IP / Network"; tier = FREE
    free_info = "Documented as free and keyless. NOTE: api.bgpview.io did not resolve in DNS when this adapter was written."
    signup_url = "https://bgpview.io/"; docs_url = "https://bgpview.docs.apiary.io/"
    endpoint = "https://api.bgpview.io"
    lookups = {"ip": "Prefixes and origin ASNs for an IP", "asn": "ASN details"}
    limitations = ("The service appears to be discontinued; use RIPEstat for the same data while it is down.",)

    def _get(self, path):
        d = self.json(self.get(self.endpoint + path), dict)
        if d.get("status") != "ok":
            raise ResponseError("BGPView reported a non-ok status.")
        return d

    def _probe(self):
        self._get("/asn/15169")
        return "ASN query succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        if kind == "asn":
            n = _asn(value)
            return self._result(f"AS{n}", f"https://bgpview.io/asn/{n}", "asn_info", {"raw": self._get(f"/asn/{n}")})
        ip = clean_ip(value)
        return self._result(ip, f"https://bgpview.io/ip/{ip}", "bgp_prefixes", {"raw": self._get(f"/ip/{ip}")})


class RIPEstat(Provider):
    id = "ripestat"; name = "RIPEstat"; category = "IP / Network"; tier = FREE
    free_info = "Free, no key (RIPE NCC Data API; fair-use limits). Added as a working substitute for BGPView."
    signup_url = "https://stat.ripe.net/"; docs_url = "https://stat.ripe.net/docs/02.data-api/"
    endpoint = "https://stat.ripe.net/data/{call}/data.json"
    lookups = {"ip": "Announced prefix and origin ASN", "asn": "AS overview (holder, announced)"}
    limitations = ("Routing data describes networks, not people.",)

    def _call(self, call, resource):
        r = self.get(f"https://stat.ripe.net/data/{call}/data.json",
                     params={"resource": resource, "sourceapp": "tracepoint"})
        d = self.json(r, dict)
        if d.get("status") != "ok" or not isinstance(d.get("data"), dict):
            raise ResponseError("RIPEstat returned a non-ok response.")
        return d

    def _probe(self):
        self._call("as-overview", "AS3333")
        return "AS overview query succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        if kind == "asn":
            n = _asn(value)
            return self._result(f"AS{n}", f"https://stat.ripe.net/AS{n}", "asn_info",
                                {"raw": self._call("as-overview", f"AS{n}")})
        ip = clean_ip(value)
        return self._result(ip, f"https://stat.ripe.net/{ip}", "bgp_prefixes",
                            {"raw": self._call("prefix-overview", ip)})


class RDAP(Provider):
    id = "rdap"; name = "RDAP (rdap.org)"; category = "IP / Network"; tier = FREE
    free_info = "Free, no key. rdap.org is a redirector to the authoritative registry servers, each with its own limits."
    signup_url = "https://rdap.org/"; docs_url = "https://about.rdap.org/"
    endpoint = "https://rdap.org/{domain|ip}/<value>"
    lookups = {"domain": "Registration data for a domain", "ip": "Allocation/holder data for an IP block"}
    limitations = ("Registrant personal data is usually redacted by registries; absence of names is expected.",
                   "Registration data can be stale or privacy-proxied.")
    timeout = 20

    def _fetch(self, path):
        r = self.get("https://rdap.org/" + path, headers={"Accept": "application/rdap+json"}, allow=(404,))
        if r.status_code == 404:
            return None
        return self.json(r, dict)

    def _probe(self):
        if self._fetch("domain/example.com") is None:
            raise ResponseError("RDAP could not find the test domain.")
        return "Domain query succeeded."

    def lookup(self, kind, value, **kw):
        from providers.domain_providers import rdap_summary  # existing parser, reused
        self._check_kind(kind)
        if kind == "domain":
            d = clean_domain(value)
            raw = self._fetch(f"domain/{d}")
            q, url = d, f"https://rdap.org/domain/{d}"
        else:
            ip = clean_ip(value)
            raw = self._fetch(f"ip/{ip}")
            q, url = ip, f"https://rdap.org/ip/{ip}"
        if raw is None:
            return self._result(q, url, "registration", {"found": False, "raw": None},
                                limitations=["No RDAP record was returned; this does not prove the object does not exist."])
        return self._result(q, url, "registration", {"found": True, "summary": rdap_summary(raw), "raw": raw})


PROVIDERS = [IPinfo, IPdata, IPDB, OpenIPAPI, BGPView, RIPEstat, RDAP]
