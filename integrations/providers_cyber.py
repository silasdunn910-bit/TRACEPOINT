"""Cybersecurity intelligence: AbuseIPDB, VirusTotal, AlienVault OTX, urlscan.io, ThreatFox, URLhaus.

These are reputation lookups for defensive analysis. They only send an indicator (IP, domain, URL, hash
the operator typed). TRACEPOINT never uploads files or submits URLs for scanning, because a submission
can publish the target."""
from __future__ import annotations

import base64
import ipaddress
import re

from .base import (FREE_TIER, InputError, Provider, ResponseError, clean_domain, clean_ip, clean_text, clean_url)

_REP_LIMIT = ("Reputation data is a signal for defensive triage, not a verdict. Shared hosting, reassigned "
              "addresses and false positives are common.",)
_HASH = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")


def _host(value: str) -> str:
    """A domain or a public IP."""
    try:
        ipaddress.ip_address(value.strip())
        return clean_ip(value)
    except ValueError:
        return clean_domain(value)


class AbuseIPDB(Provider):
    id = "abuseipdb"; name = "AbuseIPDB"; category = "Cybersecurity"; tier = FREE_TIER
    free_info = "Free account: 1,000 checks/day (verify on abuseipdb.com/pricing)."
    signup_url = "https://www.abuseipdb.com/register"; docs_url = "https://docs.abuseipdb.com/"
    endpoint = "https://api.abuseipdb.com/api/v2/check"; auth = "Key header"
    secret_keys = ("abuseipdb_key",)
    lookups = {"ip": "Community abuse reports and confidence score for an IP"}
    limitations = _REP_LIMIT

    def _fetch(self, ip):
        r = self.get(self.endpoint, params={"ipAddress": ip, "maxAgeInDays": 90},
                     headers={"Key": self.secret("abuseipdb_key"), "Accept": "application/json"})
        d = self.json(r, dict)
        if not isinstance(d.get("data"), dict):
            raise ResponseError("AbuseIPDB response is missing the data object.")
        return d

    def _probe(self):
        self._fetch("8.8.8.8")
        return "Authenticated check succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        ip = clean_ip(value)
        d = self._fetch(ip)
        x = d["data"]
        return self._result(ip, f"https://www.abuseipdb.com/check/{ip}", "ip_reputation",
                            {"summary": {k: x.get(k) for k in ("abuseConfidenceScore", "totalReports", "lastReportedAt",
                                                              "countryCode", "isp", "usageType", "isWhitelisted")},
                             "raw": d})


class VirusTotal(Provider):
    id = "virustotal"; name = "VirusTotal"; category = "Cybersecurity"; tier = FREE_TIER
    free_info = "Public API: 4 requests/minute, 500/day, non-commercial use only."
    signup_url = "https://www.virustotal.com/gui/join-us"; docs_url = "https://docs.virustotal.com/reference/overview"
    endpoint = "https://www.virustotal.com/api/v3/"; auth = "x-apikey header"
    secret_keys = ("virustotal_key",)
    lookups = {"ip": "Multi-engine reputation for an IP", "domain": "Multi-engine reputation for a domain",
               "url": "Reputation for a URL (lookup only, never submitted)", "hash": "Reputation for a file hash (hash only)"}
    limitations = _REP_LIMIT + ("Detections come from third-party engines and include false positives.",
                                "Public API terms prohibit commercial use.")
    min_interval = 15.5  # 4 requests/minute

    def _fetch(self, path):
        r = self.get("https://www.virustotal.com/api/v3/" + path, headers={"x-apikey": self.secret("virustotal_key")},
                     allow=(404,))
        if r.status_code == 404:
            return None
        d = self.json(r, dict)
        if not isinstance(d.get("data"), dict):
            raise ResponseError("VirusTotal response is missing the data object.")
        return d

    def _probe(self):
        self._fetch("ip_addresses/8.8.8.8")
        return "Authenticated lookup succeeded (counts toward the 4/min, 500/day quota)."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        if kind == "ip":
            v = clean_ip(value); path, gui = f"ip_addresses/{v}", f"https://www.virustotal.com/gui/ip-address/{v}"
        elif kind == "domain":
            v = clean_domain(value); path, gui = f"domains/{v}", f"https://www.virustotal.com/gui/domain/{v}"
        elif kind == "url":
            v = clean_url(value)
            uid = base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")
            path, gui = f"urls/{uid}", f"https://www.virustotal.com/gui/url/{uid}"
        else:
            v = clean_text(value, 64)
            if not _HASH.match(v):
                raise InputError("Not an MD5/SHA-1/SHA-256 hash.")
            path, gui = f"files/{v.lower()}", f"https://www.virustotal.com/gui/file/{v.lower()}"
        d = self._fetch(path)
        if d is None:
            return self._result(v, gui, "reputation", {"found": False, "raw": None},
                                limitations=["VirusTotal has no record of this indicator; that is not a clean verdict."])
        a = d["data"].get("attributes") or {}
        return self._result(v, gui, "reputation", {"found": True, "summary": {
            "last_analysis_stats": a.get("last_analysis_stats"), "reputation": a.get("reputation"),
            "last_analysis_date": a.get("last_analysis_date")}, "raw": d})


class OTX(Provider):
    id = "otx"; name = "AlienVault OTX"; category = "Cybersecurity"; tier = FREE_TIER
    free_info = "Free account and API key; no published daily cap (rate limiting applies)."
    signup_url = "https://otx.alienvault.com/accounts/signup/"; docs_url = "https://otx.alienvault.com/api"
    endpoint = "https://otx.alienvault.com/api/v1/indicators/{type}/{value}/general"; auth = "X-OTX-API-KEY header"
    secret_keys = ("otx_key",)
    lookups = {"ip": "Pulses and reputation for an IP", "domain": "Pulses and whois summary for a domain"}
    limitations = _REP_LIMIT + ("Pulses are community-contributed and unvetted; presence in a pulse is an allegation, not proof.",)

    def _get(self, path):
        return self.json(self.get("https://otx.alienvault.com/api/v1/" + path,
                                  headers={"X-OTX-API-KEY": self.secret("otx_key")}), dict)

    def _probe(self):
        self._get("users/me")
        return "Authenticated request succeeded (users/me)."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        if kind == "ip":
            ip = clean_ip(value); t = "IPv6" if ":" in ip else "IPv4"
            d, q, url = self._get(f"indicators/{t}/{ip}/general"), ip, f"https://otx.alienvault.com/indicator/ip/{ip}"
        else:
            q = clean_domain(value)
            d, url = self._get(f"indicators/domain/{q}/general"), f"https://otx.alienvault.com/indicator/domain/{q}"
        pulses = (d.get("pulse_info") or {}) if isinstance(d.get("pulse_info"), dict) else {}
        return self._result(q, url, "threat_intel", {"summary": {"pulse_count": pulses.get("count"),
                                                               "reputation": d.get("reputation")}, "raw": d})


class URLScan(Provider):
    id = "urlscan"; name = "urlscan.io"; category = "Cybersecurity"; tier = FREE_TIER
    free_info = "Free account key raises search/scan quotas; unauthenticated search is allowed at a lower rate."
    signup_url = "https://urlscan.io/user/signup"; docs_url = "https://urlscan.io/docs/api/"
    endpoint = "https://urlscan.io/api/v1/search/"; auth = "API-Key header (optional for search)"
    optional_keys = ("urlscan_key",)
    lookups = {"domain": "Existing public scans involving a domain", "ip": "Existing public scans involving an IP"}
    limitations = _REP_LIMIT + ("Search only: TRACEPOINT never submits scans, because public scans publish the target URL.",
                                "Scan results are snapshots from other users' scans and may be stale.")

    def _search(self, q):
        key = self.secret("urlscan_key")
        r = self.get(self.endpoint, params={"q": q, "size": 20}, headers={"API-Key": key} if key else None)
        d = self.json(r, dict)
        if not isinstance(d.get("results"), list):
            raise ResponseError("urlscan response is missing the results list.")
        return d

    def _probe(self):
        self._search("domain:example.com")
        return ("Authenticated" if self.secret("urlscan_key") else "Unauthenticated (no key set)") + " search succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        if kind == "ip":
            v = clean_ip(value); q = f"ip:\"{v}\""
        else:
            v = clean_domain(value); q = f"domain:{v}"
        d = self._search(q)
        rows = [{"scan_id": x.get("_id"), "url": (x.get("page") or {}).get("url"), "time": (x.get("task") or {}).get("time"),
                 "result": x.get("result"), "country": (x.get("page") or {}).get("country")}
                for x in d["results"] if isinstance(x, dict)]
        return self._result(v, f"https://urlscan.io/search/#{q}", "scan_history",
                            {"total": d.get("total"), "scans": rows, "raw": d})


class _AbuseCh(Provider):
    category = "Cybersecurity"; tier = FREE_TIER
    free_info = "Free abuse.ch Auth-Key (one key covers ThreatFox and URLhaus); fair-use limits."
    signup_url = "https://auth.abuse.ch/"
    auth = "Auth-Key header"
    secret_keys = ("abusech_key",)
    limitations = _REP_LIMIT + ("A listing means the indicator was reported as malicious at some time; infrastructure is reused and cleaned.",)

    def _post(self, url, **kw):
        r = self.request("POST", url, headers={"Auth-Key": self.secret("abusech_key")}, **kw)
        return self.json(r, dict)


class ThreatFox(_AbuseCh):
    id = "threatfox"; name = "ThreatFox"
    docs_url = "https://threatfox.abuse.ch/api/"; endpoint = "https://threatfox-api.abuse.ch/api/v1/"
    lookups = {"ioc": "Search an indicator (IP:port, domain, URL or hash)"}

    def _search(self, term):
        d = self._post(self.endpoint, json={"query": "search_ioc", "search_term": term, "exact_match": True})
        if d.get("query_status") not in ("ok", "no_result"):
            raise ResponseError(f"ThreatFox query_status: {str(d.get('query_status'))[:60]}")
        return d

    def _probe(self):
        self._search("example.com")
        return "Authenticated query succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        v = clean_text(value, 300)
        d = self._search(v)
        rows = d.get("data") if isinstance(d.get("data"), list) else []
        return self._result(v, f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{v}", "threat_intel",
                            {"found": bool(rows), "count": len(rows), "raw": d},
                            limitations=([] if rows else ["No ThreatFox record; this is not a clean verdict."]))


class URLhaus(_AbuseCh):
    id = "urlhaus"; name = "URLhaus"
    docs_url = "https://urlhaus-api.abuse.ch/"; endpoint = "https://urlhaus-api.abuse.ch/v1/"
    lookups = {"host": "Malware URLs seen on a domain or IP", "url": "Whether a URL is listed"}

    def _query(self, path, **form):
        d = self._post(self.endpoint + path, data=form)
        if d.get("query_status") not in ("ok", "no_results", "invalid_host", "invalid_url"):
            raise ResponseError(f"URLhaus query_status: {str(d.get('query_status'))[:60]}")
        return d

    def _probe(self):
        self._query("host/", host="example.com")
        return "Authenticated query succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        if kind == "host":
            v = _host(value); d = self._query("host/", host=v)
            url = f"https://urlhaus.abuse.ch/host/{v}/"
        else:
            v = clean_url(value); d = self._query("url/", url=v)
            url = "https://urlhaus.abuse.ch/browse.php?search=" + v.replace("&", "%26")
        found = d.get("query_status") == "ok"
        return self._result(v, url, "threat_intel", {"found": found, "raw": d},
                            limitations=([] if found else ["No URLhaus record; this is not a clean verdict."]))


PROVIDERS = [AbuseIPDB, VirusTotal, OTX, URLScan, ThreatFox, URLhaus]
