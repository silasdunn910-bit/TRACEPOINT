"""Official sex-offender-registry sources.

Checked against the government's own pages on 2026-11-02 (see PHASE-8-REPORT.md):

* NSOPW's FAQ states there is no API ("The browser interface is the only way to search"), its Conditions of
  Use prohibit automated searching and bypassing security mechanisms, and searches sit behind a CAPTCHA.
* The NC SBI registry pages that could be read state an Acceptable Use Policy but no API, bulk download or
  automated-access rule, and its search form could not be read at all.

So TRACEPOINT does not search any registry automatically. It lists the official portals, documents what each
one supports, and lets the operator record what they reviewed. Location/address-radius searches that the portals
offer are deliberately not supported: TRACEPOINT is not a locator and records no residential information.
"""
from __future__ import annotations

from providers.records_common import OfficialSource, SearchOutcome

NSOPW = OfficialSource(
    id="nsopw", name="National Sex Offender Public Website (NSOPW)",
    agency="U.S. Department of Justice, Office of Sex Offender Sentencing, Monitoring, Apprehending, Registering, "
           "and Tracking (SMART Office)",
    kind="registry", level="national", jurisdiction="US", official_url="https://www.nsopw.gov/",
    search_url="https://www.nsopw.gov/search-0", method="manual",
    search_fields=("name", "jurisdiction (state, territory, Indian Country)", "county (if the jurisdiction provides it)",
                   "city/town (if provided)", "ZIP code (up to five)"),
    unsupported_fields=("registry identification number", "registry status filter",
                        "address-radius search (offered by NSOPW, deliberately not supported by TRACEPOINT)",
                        "any automated/API search"),
    auth="No account. You must accept the Conditions of Use and complete a CAPTCHA in the browser.",
    coverage="Searches the participating jurisdictions' own registries in real time (50 states, DC, five territories, "
             "participating tribes). What is searchable depends on each jurisdiction.",
    complete=False,
    limitations="NSOPW states it has no API and prohibits automated searching and bypassing security mechanisms, so "
                "TRACEPOINT never submits searches. It does not guarantee accuracy, completeness or timeliness and tells "
                "users to verify information. Misuse (threats, intimidation, harassment) may be criminally prosecuted.",
    official_domains=("nsopw.gov",),
    verified_note="nsopw.gov home, /search-0, /conditions-use and /faqs read 2026-11-02. Nothing was searched.")

NC_SBI = OfficialSource(
    id="nc_sbi", name="North Carolina Sex Offender Registry",
    agency="North Carolina State Bureau of Investigation (NC SBI)", kind="registry", level="state", jurisdiction="NC",
    official_url="https://sexoffender.ncsbi.gov/", search_url="https://sexoffender.ncsbi.gov/search.aspx",
    method="manual",
    search_fields=("not verified: the search form could not be read by TRACEPOINT's research",),
    unsupported_fields=("any automated/API search (no API or bulk download is stated on the pages read)",),
    auth="Not stated for searching (an Acceptable Use Policy page is shown first). Registration applies only to e-mail alerts.",
    coverage="Registrants reported by sheriffs in all 100 NC counties. Excludes juveniles adjudicated delinquent. "
             "Information is partly offender-reported; the registry says positive identification requires fingerprints.",
    complete=False,
    limitations="Manual lookup only. The Acceptable Use Policy limits use to public protection and warns that using the "
                "information for stalking, harassment, threats or other crimes is subject to prosecution.",
    official_domains=("ncsbi.gov",),
    verified_note="sexoffender.ncsbi.gov home/about/FAQ/search pages read 2026-11-02 (search.aspx returned the policy "
                  "text, not a form). No automated-access rule is stated, but none is documented either, so nothing is automated.")

REGISTRY_SOURCES: dict[str, OfficialSource] = {s.id: s for s in (NSOPW, NC_SBI)}
JURISDICTIONS = {"US": "National (NSOPW)", "NC": "North Carolina"}

# Search kinds TRACEPOINT accepts for its own query. Portal-side narrowing (state, county, city, ZIP) is done in the
# portal; TRACEPOINT never takes a location as a query.
QUERY_KINDS = ("name", "registry_id")

# Hook for a future *documented, permitted* automated provider: source id -> callable(term, kind) -> SearchOutcome.
AUTOMATED_SEARCHERS: dict = {}


def sources_for(jurisdiction: str) -> list[OfficialSource]:
    return [s for s in REGISTRY_SOURCES.values() if s.jurisdiction == jurisdiction]


def search_source(source: OfficialSource, term: str, kind: str) -> SearchOutcome:
    """Manual sources never touch the network."""
    fn = AUTOMATED_SEARCHERS.get(source.id)
    if fn is not None and source.automated:
        return fn(term, kind)
    if kind == "registry_id" and source.id == NSOPW.id:
        return SearchOutcome(source, "manual", query=term, query_kind=kind,
                             detail="NSOPW does not support searching by registry identification number; search by name "
                                    "(optionally narrowed by jurisdiction) or use the state registry's own search.")
    return SearchOutcome(source, "manual", query=term, query_kind=kind,
                         detail=f"Manual search required. Open {source.search_url} and search yourself (accept the "
                                "terms and complete any CAPTCHA); then review and enter what you find.")
