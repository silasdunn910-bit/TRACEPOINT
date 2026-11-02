"""Official court-record sources.

What each source can actually do was checked against the government's own pages on 2026-11-02
(see PHASE-8-REPORT.md). Only GovInfo has a documented, key-based, non-interactive search that TRACEPOINT
may use; every other source is manual: TRACEPOINT shows the official search page and the operator reviews
and enters what they find. No endpoint here is guessed.
"""
from __future__ import annotations

from urllib.parse import urlparse, urlunparse

from core import http
from core.database import get_db
from providers.records_common import (CourtRecord, OPINION, OfficialSource, SearchOutcome, UNKNOWN, clean_text,
                                       check_source_url)
from providers.search_providers import (ACCESS_DENIED, INVALID_KEY, INVALID_RESPONSE, KIND_LABEL, RATE_LIMIT,
                                        SERVER_ERROR, TIMEOUT, UNAVAILABLE)

GOVINFO = OfficialSource(
    id="govinfo_uscourts", name="GovInfo - U.S. Courts Opinions (API)",
    agency="U.S. Government Publishing Office (GPO), serving opinions from U.S. courts", kind="court",
    level="federal", jurisdiction="US", official_url="https://www.govinfo.gov/app/collection/uscourts/",
    search_url="https://www.govinfo.gov/app/collection/uscourts/", method="automated",
    search_fields=("name (full-text)", "case_number (full-text)"),
    unsupported_fields=("court filter", "filing date", "case status", "charges", "party role", "docket entries"),
    auth="Free api.data.gov API key (https://www.govinfo.gov/api-signup); stored encrypted in API Configuration.",
    coverage="Published court OPINIONS only, from participating federal courts (PACER states 130+ courts, from April 2004). "
             "Not a docket search: a person with a case but no published opinion will not appear.",
    complete=False,
    limitations="Full-text matching: a name can appear in opinions about other people. Results carry no disposition "
                "or status, so every record is classified UNKNOWN. The service is documented as a 'public preview'.",
    official_domains=("govinfo.gov",),
    verified_note="Request/response format taken from the usgpo/api README and the GovInfo search-service overview "
                  "(read 2026-11-02). The Swagger definitions could not be read; the API-key header name is not "
                  "stated there, so the documented api_key query parameter is used.",
    requires_secret="govinfo_key")

PACER = OfficialSource(
    id="pacer_pcl", name="PACER Case Locator", agency="Administrative Office of the U.S. Courts",
    kind="court", level="federal", jurisdiction="US", official_url="https://pacer.uscourts.gov/",
    search_url="https://pacer.uscourts.gov/find-case/search-national-index", method="manual",
    search_fields=("party name", "case number (court-specific search)"),
    unsupported_fields=("anything automated by TRACEPOINT",),
    auth="PACER account required (free to register). Fees: $0.10/page; waived if $30 or less accrues in a quarter; "
         "a party-name search is charged even when it finds nothing.",
    coverage="Nationwide index of federal case records (updated daily, per PACER).",
    complete=False,
    limitations="A PACER Case Locator API exists but needs your PACER login and its endpoint documentation could not "
                "be read, so TRACEPOINT does not call it. Search manually and enter what you review.",
    official_domains=("uscourts.gov",),
    verified_note="PACER pages read 2026-11-02 (fees, registration, developer resources). Not logged in; nothing was searched.")

NC_COURTS = OfficialSource(
    id="nc_judicial", name="North Carolina Judicial Branch - court records search",
    agency="North Carolina Judicial Branch (Administrative Office of the Courts)", kind="court", level="state",
    jurisdiction="NC", official_url="https://www.nccourts.gov/", search_url="https://www.nccourts.gov/records",
    method="manual", search_fields=("as offered by the official portal (not verified by TRACEPOINT)",),
    unsupported_fields=("anything automated by TRACEPOINT",),
    auth="Not verified: the official pages returned HTTP 403 to TRACEPOINT's research, so login, registration, "
         "CAPTCHA and fee requirements are unknown.",
    coverage="Unknown. Which counties and case types are online (versus courthouse-only) was not verified; county "
             "portals are not catalogued.",
    complete=False,
    limitations="Manual lookup only. Open the official page in your browser; do not assume every county or case type "
                "is available online.",
    official_domains=("nccourts.gov",),
    verified_note="nccourts.gov returned HTTP 403 to an automated fetch on 2026-11-02, so the portal's capabilities "
                  "are UNVERIFIED. The entry URL is the state's published records page and should be checked in a browser.")

COURT_SOURCES: dict[str, OfficialSource] = {s.id: s for s in (GOVINFO, PACER, NC_COURTS)}
# Jurisdictions that have at least one catalogued court source. Every state and DC can be SELECTED (see
# providers/jurisdictions.py); only these have a source, and only GovInfo is searched automatically.
JURISDICTIONS = {"US": "Federal", "NC": "North Carolina (state)"}


def sources_for(jurisdiction: str) -> list[OfficialSource]:
    return [s for s in COURT_SOURCES.values() if s.jurisdiction == jurisdiction]


# --- GovInfo --------------------------------------------------------------------------------------
GOVINFO_SEARCH_URL = "https://api.govinfo.gov/search"


def _strip_query(url: str) -> str:
    """Remove any query string (an API key could be in it) from a URL before keeping it."""
    try:
        p = urlparse(url)
    except ValueError:
        return ""
    return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


def build_govinfo_query(term: str) -> str:
    quoted = clean_text(term, 160).replace("\\", " ").replace('"', " ").strip()
    return f'collection:(USCOURTS) and "{quoted}"'


def _http_error(status: int) -> tuple[str, str]:
    if status in (401, 403):
        return (INVALID_KEY if status == 401 else ACCESS_DENIED), f"GovInfo rejected the API key (HTTP {status})."
    if status == 429:
        return RATE_LIMIT, "GovInfo rate limit reached (HTTP 429); try again later."
    if status >= 500:
        return SERVER_ERROR, f"GovInfo server error (HTTP {status})."
    return UNAVAILABLE, f"GovInfo returned HTTP {status}."


def govinfo_search(term: str, kind: str, *, limit: int = 25) -> SearchOutcome:
    src = GOVINFO
    out = SearchOutcome(src, "error", query=term, query_kind=kind)
    key = get_db().get_secret(src.requires_secret)
    if not key:
        out.status = "not_configured"
        out.detail = ("No GovInfo API key is stored. Add one under API Configuration (free from "
                      "https://www.govinfo.gov/api-signup), or search the official site manually.")
        return out
    body = {"query": build_govinfo_query(term), "pageSize": str(max(1, min(int(limit), 50))),
            "offsetMark": "*", "sorts": [{"field": "score", "sortOrder": "DESC"}]}
    try:
        r = http.request("POST", GOVINFO_SEARCH_URL, params={"api_key": key}, json=body, retries=1, timeout=20)
    except http.HttpError as e:
        out.detail = f"{KIND_LABEL[TIMEOUT] if 'Timed out' in str(e) else KIND_LABEL[UNAVAILABLE]}: {e}"
        out.error_kind = "unavailable"
        return out
    if r.status_code >= 400:
        kind_, msg = _http_error(r.status_code)
        out.detail = f"{KIND_LABEL[kind_]}: {msg}"
        if kind_ in (RATE_LIMIT, SERVER_ERROR, UNAVAILABLE, TIMEOUT):
            out.error_kind = "unavailable"
        return out
    try:
        data = r.json()
    except ValueError:
        data = None
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        out.detail = f"{KIND_LABEL[INVALID_RESPONSE]}: GovInfo reply was not the documented search response."
        return out
    seen: set[str] = set()
    for item in results:
        if not isinstance(item, dict):
            continue
        pkg, gran = clean_text(item.get("packageId"), 120), clean_text(item.get("granuleId"), 160)
        title = clean_text(item.get("title"), 300)
        if not (pkg or gran) or not title:
            continue
        author = item.get("governmentAuthor")
        court = "; ".join(clean_text(a, 120) for a in author if isinstance(a, str)) if isinstance(author, list) else ""
        url, note = check_source_url(_strip_query(clean_text(item.get("resultLink"), 500)), src)
        rec = CourtRecord(source_id=src.id, jurisdiction="US", court=court, title=title, record_type=OPINION,
                          record_id=gran or pkg, published_date=clean_text(item.get("dateIssued"), 40),
                          status=UNKNOWN, source_url=url, url_note=note, origin="automated")
        if rec.key() not in seen:
            seen.add(rec.key())
            out.records.append(rec)
    out.status = "ok"
    out.detail = f"{len(out.records)} candidate opinion(s) returned (partial coverage: published opinions only)."
    return out


def search_source(source: OfficialSource, term: str, kind: str) -> SearchOutcome:
    """Run one source. Manual sources never touch the network."""
    if source.id == GOVINFO.id:
        return govinfo_search(term, kind)
    return SearchOutcome(source, "manual", detail=f"Manual search required. Open {source.search_url} and search for "
                         "the name or case number yourself; then review and enter what you find.",
                         query=term, query_kind=kind)
