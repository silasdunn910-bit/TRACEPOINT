"""Government and public-records sources: CourtListener, GovInfo, SEC EDGAR, USAspending, FEC, OpenCorporates.

Records are public but easily mismatched. Every result keeps the original source URL and the retrieval
time (NormalizedResult.timestamp), and carries a same-name warning: a name match is not an identity match."""
from __future__ import annotations

import re
from urllib.parse import quote

from .base import (FREE, FREE_TIER, InputError, Provider, ResponseError, clean_text)

_NAME_WARN = ("Records can be incomplete, outdated, or concern a different person or organisation with the same "
              "or a similar name. Verify identity with the original record before relying on a match.",)


class CourtListener(Provider):
    id = "courtlistener"; name = "CourtListener"; category = "Government / Public records"; tier = FREE_TIER
    free_info = "Free account token (Free Law Project); throttled to a few thousand requests/hour per user."
    signup_url = "https://www.courtlistener.com/sign-up/"; docs_url = "https://www.courtlistener.com/help/api/rest/"
    endpoint = "https://www.courtlistener.com/api/rest/v4/search/"; auth = "Authorization: Token <token>"
    secret_keys = ("courtlistener_key",)
    lookups = {"opinions": "Court opinions matching text", "dockets": "RECAP federal docket entries matching text"}
    limitations = _NAME_WARN + (
        "Coverage is not a complete record of any jurisdiction. Prefer the official court record; CourtListener "
        "is an aggregator (federal PACER/RECAP plus some state courts).",
        "A docket shows that a case exists. It does not by itself distinguish a charge, allegation, conviction or "
        "dismissal; read the underlying filings.")

    def _search(self, q, t):
        r = self.get(self.endpoint, params={"q": q, "type": t},
                     headers={"Authorization": f"Token {self.secret('courtlistener_key')}"})
        d = self.json(r, dict)
        if not isinstance(d.get("results"), list):
            raise ResponseError("CourtListener response is missing the results list.")
        return d

    def _probe(self):
        self._search("test", "o")
        return "Authenticated search succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        q = clean_text(value)
        d = self._search(q, "o" if kind == "opinions" else "r")
        keep = ("caseName", "court", "court_id", "docketNumber", "dateFiled", "docket_id", "absolute_url", "status",
                "citation", "judge")
        rows = [dict({k: x.get(k) for k in keep if k in x},
                     source_url="https://www.courtlistener.com" + str(x.get("absolute_url", "")))
                for x in d["results"] if isinstance(x, dict)]
        return self._result(q, f"https://www.courtlistener.com/?q={quote(q)}", "court_records",
                            {"count": d.get("count"), "records": rows, "raw": d})


class GovInfo(Provider):
    id = "govinfo"; name = "GovInfo"; category = "Government / Public records"; tier = FREE_TIER
    free_info = "Free api.data.gov key; 1,000 requests/hour per key."
    signup_url = "https://api.data.gov/signup/"; docs_url = "https://api.govinfo.gov/docs/"
    endpoint = "https://api.govinfo.gov/"; auth = "X-Api-Key header"
    secret_keys = ("govinfo_key",)
    lookups = {"query": "Search official US government publications (Federal Register, CFR, court opinions, ...)"}
    limitations = _NAME_WARN + ("Official publication text; a mention does not establish wrongdoing.",)

    def _hdr(self):
        return {"X-Api-Key": self.secret("govinfo_key")}

    def _probe(self):
        d = self.json(self.get("https://api.govinfo.gov/collections", headers=self._hdr()), dict)
        if not isinstance(d.get("collections"), list):
            raise ResponseError("GovInfo response is missing the collections list.")
        return "Authenticated collections request succeeded."

    def lookup(self, kind, value, limit: int = 10, **kw):
        self._check_kind(kind)
        q = clean_text(value)
        r = self.request("POST", "https://api.govinfo.gov/search", headers=self._hdr(),
                         json={"query": q, "pageSize": max(1, min(limit, 50)), "offsetMark": "*"})
        d = self.json(r, dict)
        if not isinstance(d.get("results"), list):
            raise ResponseError("GovInfo search response is missing the results list.")
        rows = [{k: x.get(k) for k in ("title", "packageId", "collectionCode", "dateIssued", "lastModified",
                                       "resultLink", "governmentAuthor") if k in x}
                for x in d["results"] if isinstance(x, dict)]
        return self._result(q, f"https://www.govinfo.gov/app/search/{quote(q)}", "publications",
                            {"count": d.get("count"), "records": rows, "raw": d})


class SECEdgar(Provider):
    id = "sec_edgar"; name = "SEC EDGAR"; category = "Government / Public records"; tier = FREE
    free_info = "Free, no key. SEC requires a declared contact in the User-Agent and a maximum of 10 requests/second."
    signup_url = "https://www.sec.gov/search-filings/edgar-application-programming-interfaces"
    docs_url = "https://www.sec.gov/search-filings/edgar-application-programming-interfaces"
    endpoint = "https://data.sec.gov/submissions/CIK##########.json"; auth = "User-Agent with contact details (no key)"
    secret_keys = ("sec_contact",)
    lookups = {"cik": "Company profile and recent filings by CIK", "company": "Find companies by name",
               "filing_text": "Full-text search of filings since 2001"}
    limitations = _NAME_WARN + ("Filings are self-reported by the filer; the SEC does not verify their contents.",)
    min_interval = 0.15

    def _headers(self):
        return {"User-Agent": f"TRACEPOINT research {self.secret('sec_contact')}", "Accept": "application/json"}

    def _submissions(self, cik):
        r = self.get(f"https://data.sec.gov/submissions/CIK{cik:010d}.json", headers=self._headers(), allow=(404,))
        if r.status_code == 404:
            return None
        d = self.json(r, dict)
        if "cik" not in d:
            raise ResponseError("SEC response is missing the cik field.")
        return d

    def _probe(self):
        if self._submissions(320193) is None:
            raise ResponseError("SEC returned 404 for a known CIK.")
        return "Submissions request succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        if kind == "cik":
            m = re.fullmatch(r"\s*(?:CIK)?0*(\d{1,10})\s*", value or "", re.I)
            if not m:
                raise InputError("Not a valid CIK.")
            cik = int(m.group(1))
            d = self._submissions(cik)
            url = f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik:010d}"
            if d is None:
                return self._result(str(cik), url, "company_filings", {"found": False, "raw": None})
            recent = (d.get("filings") or {}).get("recent") or {}
            n = min(20, len(recent.get("accessionNumber", [])))
            filings = [{"form": recent["form"][i], "filed": recent["filingDate"][i], "accession": recent["accessionNumber"][i],
                        "url": f"https://www.sec.gov/Archives/edgar/data/{cik}/{recent['accessionNumber'][i].replace('-', '')}/"
                               f"{recent.get('primaryDocument', [''] * n)[i]}"} for i in range(n)] \
                if all(k in recent for k in ("form", "filingDate", "accessionNumber")) else []
            return self._result(str(cik), url, "company_filings",
                                {"found": True, "summary": {k: d.get(k) for k in ("name", "tickers", "sic",
                                                                                 "sicDescription", "stateOfIncorporation")},
                                 "recent_filings": filings, "raw": {k: v for k, v in d.items() if k != "filings"}})
        q = clean_text(value)
        if kind == "company":
            r = self.get("https://www.sec.gov/files/company_tickers.json", headers=self._headers())
            d = self.json(r, dict)
            needle = q.lower()
            rows = [{"cik": v.get("cik_str"), "ticker": v.get("ticker"), "name": v.get("title")}
                    for v in d.values() if isinstance(v, dict) and needle in str(v.get("title", "")).lower()][:25]
            return self._result(q, "https://www.sec.gov/cgi-bin/browse-edgar?company=" + quote(q), "company_search",
                                {"matches": rows}, limitations=["Only companies with listed tickers appear in this file."])
        r = self.get("https://efts.sec.gov/LATEST/search-index", params={"q": f'"{q}"'}, headers=self._headers())
        d = self.json(r, dict)
        hits = (d.get("hits") or {}).get("hits") if isinstance(d.get("hits"), dict) else None
        if not isinstance(hits, list):
            raise ResponseError("SEC full-text response is missing hits.hits.")
        rows = [{"names": (h.get("_source") or {}).get("display_names"), "form": (h.get("_source") or {}).get("form"),
                 "filed": (h.get("_source") or {}).get("file_date"), "accession": (h.get("_source") or {}).get("adsh")}
                for h in hits[:25] if isinstance(h, dict)]
        return self._result(q, f"https://www.sec.gov/edgar/search/#/q={quote(q)}", "filing_text_search",
                            {"hits": rows, "raw": d})


class USAspending(Provider):
    id = "usaspending"; name = "USAspending"; category = "Government / Public records"; tier = FREE
    free_info = "Free, no key, no published quota (fair use)."
    signup_url = "https://api.usaspending.gov/"; docs_url = "https://api.usaspending.gov/docs/endpoints"
    endpoint = "https://api.usaspending.gov/api/v2/recipient/"
    lookups = {"recipient": "Federal award recipients matching a name"}
    limitations = _NAME_WARN + ("Reflects federal awards as reported by agencies; recipients are often parent/child entity records.",)

    def _probe(self):
        d = self.json(self.get("https://api.usaspending.gov/api/v2/references/toptier_agencies/"), dict)
        if not isinstance(d.get("results"), list):
            raise ResponseError("USAspending response is missing results.")
        return "Reference request succeeded."

    def lookup(self, kind, value, limit: int = 10, **kw):
        self._check_kind(kind)
        q = clean_text(value)
        r = self.request("POST", self.endpoint, json={"keyword": q, "limit": max(1, min(limit, 50)), "page": 1,
                                                       "sort": "amount", "order": "desc", "award_type": "all"})
        d = self.json(r, dict)
        if not isinstance(d.get("results"), list):
            raise ResponseError("USAspending response is missing results.")
        return self._result(q, f"https://www.usaspending.gov/search/?hash=&keyword={quote(q)}", "federal_awards",
                            {"records": d["results"], "page_metadata": d.get("page_metadata"), "raw": d})


class FEC(Provider):
    id = "fec"; name = "FEC (OpenFEC)"; category = "Government / Public records"; tier = FREE_TIER
    free_info = "Free api.data.gov key: 1,000 requests/hour. Without a key TRACEPOINT uses the shared DEMO_KEY (very low limits)."
    signup_url = "https://api.data.gov/signup/"; docs_url = "https://api.open.fec.gov/developers/"
    endpoint = "https://api.open.fec.gov/v1/"; auth = "X-Api-Key header (DEMO_KEY fallback)"
    optional_keys = ("fec_key",)
    lookups = {"candidate": "Candidates by name", "committee": "Committees by name",
               "contributor": "Itemized individual contributions by contributor name"}
    limitations = _NAME_WARN + ("Federal law (52 U.S.C. 30111(a)(4)) forbids using contributor names or addresses "
                                "for solicitation or commercial purposes.",
                                "Donor records are self-reported and not verified; same-name contributors are common.")

    def _key(self):
        return self.secret("fec_key") or "DEMO_KEY"

    def _get(self, path, params):
        r = self.get(self.endpoint + path, params=params, headers={"X-Api-Key": self._key()})
        d = self.json(r, dict)
        if not isinstance(d.get("results"), list):
            raise ResponseError("FEC response is missing the results list.")
        return d

    def _probe(self):
        self._get("names/candidates/", {"q": "smith"})
        return ("Authenticated" if self.secret("fec_key") else "Shared DEMO_KEY (no key set; very low limits)") + \
            " request succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        q = clean_text(value)
        if kind == "candidate":
            d, t = self._get("names/candidates/", {"q": q}), "campaign_candidates"
        elif kind == "committee":
            d, t = self._get("names/committees/", {"q": q}), "campaign_committees"
        else:
            d = self._get("schedules/schedule_a/", {"contributor_name": q, "per_page": 20,
                                                    "sort": "-contribution_receipt_date"})
            t = "campaign_contributions"
        return self._result(q, f"https://www.fec.gov/data/search/?search={quote(q)}", t,
                            {"records": d["results"], "pagination": d.get("pagination"), "raw": d})


class OpenCorporates(Provider):
    id = "opencorporates"; name = "OpenCorporates"; category = "Government / Public records"; tier = FREE_TIER
    free_info = ("API access requires an account token. Free access is granted by application for public-benefit / "
                 "open-data use; otherwise it is a paid service. Confirm your eligibility with OpenCorporates.")
    signup_url = "https://opencorporates.com/users/sign_up"; docs_url = "https://api.opencorporates.com/documentation/API-Reference"
    endpoint = "https://api.opencorporates.com/v0.4/companies/search"; auth = "api_token query parameter"
    secret_keys = ("opencorporates_token",)
    lookups = {"company": "Company registry records by name"}
    limitations = _NAME_WARN + ("Registry data is aggregated from government registers and may lag them; always cite the "
                                "original registry.",)

    def _search(self, q):
        r = self.get(self.endpoint, params={"q": q, "api_token": self.secret("opencorporates_token")})
        d = self.json(r, dict)
        if not isinstance((d.get("results") or {}).get("companies") if isinstance(d.get("results"), dict) else None, list):
            raise ResponseError("OpenCorporates response is missing results.companies.")
        return d

    def _probe(self):
        self._search("tracepoint")
        return "Authenticated search succeeded."

    def lookup(self, kind, value, **kw):
        self._check_kind(kind)
        q = clean_text(value)
        d = self._search(q)
        rows = [(c.get("company") or {}) for c in d["results"]["companies"] if isinstance(c, dict)]
        keep = ("name", "company_number", "jurisdiction_code", "incorporation_date", "dissolution_date",
                "current_status", "opencorporates_url", "registry_url")
        return self._result(q, f"https://opencorporates.com/companies?q={quote(q)}", "company_records",
                            {"records": [{k: c.get(k) for k in keep} for c in rows], "raw": d})


PROVIDERS = [CourtListener, GovInfo, SECEdgar, USAspending, FEC, OpenCorporates]
