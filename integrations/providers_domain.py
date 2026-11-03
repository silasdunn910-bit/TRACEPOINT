"""Domain and historical intelligence: crt.sh, Wayback Machine, Cloudflare DNS over HTTPS."""
from __future__ import annotations

from urllib.parse import quote

from .base import FREE, Provider, ResponseError, clean_domain

_DNS_TYPES = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16}


class CrtSh(Provider):
    id = "crtsh"; name = "crt.sh"; category = "Domain / History"; tier = FREE
    free_info = "Free, no key. Community service with no SLA; frequently slow or overloaded."
    signup_url = "https://crt.sh/"; docs_url = "https://crt.sh/"
    endpoint = "https://crt.sh/?q=<domain>&output=json"
    lookups = {"domain": "Certificate Transparency entries and subdomain names"}
    limitations = ("Certificates show names that were certificated, not who operates them or whether they are live.",
                   "Responses are capped and the service can time out under load.")
    timeout = 40; retries = 1

    def _fetch(self, q):
        r = self.get("https://crt.sh/", params={"q": q, "output": "json"}, max_bytes=20_000_000)
        try:
            d = r.json()
        except ValueError:
            raise ResponseError("crt.sh returned an unreadable response (often temporary overload).") from None
        if not isinstance(d, list):
            raise ResponseError("crt.sh returned an unexpected JSON structure.")
        return d

    def _probe(self):
        self._fetch("tracepoint-connection-test.invalid")
        return "Test query answered."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        d = clean_domain(value)
        rows = self._fetch(f"%.{d}")
        names = set()
        for c in rows:
            if isinstance(c, dict):
                for n in str(c.get("name_value", "")).splitlines():
                    if n.strip():
                        names.add(n.strip().lower())
        return self._result(d, f"https://crt.sh/?q={quote('%.' + d)}", "certificates",
                            {"certificate_count": len(rows), "names": sorted(names)[:500],
                             "names_truncated": len(names) > 500, "raw": rows[:200]},
                            limitations=["raw is capped at the first 200 certificate records."] if len(rows) > 200 else [])


class Wayback(Provider):
    id = "wayback"; name = "Wayback Machine"; category = "Domain / History"; tier = FREE
    free_info = "Free, no key; polite use (a few requests/second at most)."
    signup_url = "https://web.archive.org/"; docs_url = "https://archive.org/help/wayback_api.php"
    endpoint = "https://archive.org/wayback/available"
    lookups = {"url": "Closest archived snapshot plus first and last capture of a domain or URL"}
    limitations = ("A snapshot shows what the crawler saw at that moment; absence of a snapshot proves nothing.",
                   "Archived content may be incomplete or have been modified by scripts at capture time.")

    def _available(self, target):
        d = self.json(self.get(self.endpoint, params={"url": target}), dict)
        if not isinstance(d.get("archived_snapshots"), dict):
            raise ResponseError("Wayback response is missing archived_snapshots.")
        return d

    def _probe(self):
        self._available("example.com")
        return "Availability query succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        v = (value or "").strip()
        target = clean_domain(v) if "/" not in v.replace("://", "") else v[:2000]
        avail = self._available(target)
        out = {}
        for label, lim in (("first", "1"), ("last", "-1")):
            rows = self.json(self.get("https://web.archive.org/cdx/search/cdx",
                                      params={"url": target, "output": "json", "fl": "timestamp,original,statuscode",
                                              "limit": lim}), list)
            if len(rows) > 1 and isinstance(rows[1], list) and len(rows[1]) >= 2:
                ts = rows[1][0]
                out[label] = {"timestamp": ts, "original": rows[1][1],
                              "snapshot_url": f"https://web.archive.org/web/{ts}/{rows[1][1]}"}
        closest = (avail["archived_snapshots"].get("closest") or {})
        return self._result(target, f"https://web.archive.org/web/*/{target}", "archive_snapshots",
                            {"closest": closest or None, "first_capture": out.get("first"),
                             "last_capture": out.get("last"), "raw": avail})


class CloudflareDoH(Provider):
    id = "cloudflare_doh"; name = "Cloudflare DNS over HTTPS"; category = "Domain / History"; tier = FREE
    free_info = "Free, no key (1.1.1.1 public resolver; fair use)."
    signup_url = "https://developers.cloudflare.com/1.1.1.1/"
    docs_url = "https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/"
    endpoint = "https://cloudflare-dns.com/dns-query"; auth = "Accept: application/dns-json"
    lookups = {"dns": "A, AAAA, MX, NS and TXT records for a domain"}
    limitations = ("Resolver answers reflect Cloudflare's cache and may differ from the authoritative servers.",
                   "NXDOMAIN and empty answers are reported as such; a SERVFAIL is an error, not an absence.")

    def _query(self, name, rtype):
        r = self.get(self.endpoint, params={"name": name, "type": rtype}, headers={"Accept": "application/dns-json"})
        d = self.json(r, dict)
        if not isinstance(d.get("Status"), int):
            raise ResponseError("Cloudflare DoH response is missing Status.")
        return d

    def _probe(self):
        d = self._query("example.com", "A")
        if d["Status"] != 0:
            raise ResponseError(f"Test query returned DNS status {d['Status']}.")
        return "DoH query succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        dom = clean_domain(value)
        recs, raw = {}, {}
        for t in _DNS_TYPES:
            d = self._query(dom, t)
            raw[t] = d
            if d["Status"] not in (0, 3):
                raise ResponseError(f"Cloudflare DoH returned DNS status {d['Status']} for {t}.")
            ans = d.get("Answer") if isinstance(d.get("Answer"), list) else []
            recs[t] = [a.get("data") for a in ans if isinstance(a, dict) and a.get("type") == _DNS_TYPES[t]]
        return self._result(dom, f"{self.endpoint}?name={dom}", "dns_records",
                            {"nxdomain": raw["A"]["Status"] == 3, "records": recs, "raw": raw})


PROVIDERS = [CrtSh, Wayback, CloudflareDoH]
