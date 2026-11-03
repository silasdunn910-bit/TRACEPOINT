# API Provider Reference

Generated from the adapter metadata in `integrations/` (so it matches the code). Quotas are the providers' published figures at the time of writing and can change; check each provider's page before relying on them. Nothing here is unlimited.

Tier: **FREE** = no account or key. **FREE-TIER** = free account/key with a quota. Statuses are explained in `INTEGRATION_STATUS.md`.

## Search

### SearXNG  (`searxng`)

| | |
|---|---|
| Tier | FREE |
| Free-tier limits | Free and open source; you host it. No quota except what your instance's upstream engines impose. |
| Get a key / sign up | https://docs.searxng.org/admin/installation.html |
| Documentation | https://docs.searxng.org/dev/search_api.html |
| Endpoint | `<your instance>/search?format=json` |
| Authentication | none (your own instance URL) |
| Required variables | `SEARXNG_URL` |
| Optional variables | none |
| Lookups | `query` - Free-text web search |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('searxng'))"` |

Known limitations:

- Requires a running instance with `json` enabled under search.formats in settings.yml.

### Brave Search API  (`brave`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free plan with a small monthly query allowance (check your Brave dashboard for the current figure). |
| Get a key / sign up | https://brave.com/search/api/ |
| Documentation | https://api-dashboard.search.brave.com/app/documentation |
| Endpoint | `https://api.search.brave.com/res/v1/web/search` |
| Authentication | X-Subscription-Token header |
| Required variables | `BRAVE_SEARCH_API_KEY` |
| Optional variables | none |
| Lookups | `query` - Free-text web search |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('brave'))"` |

Known limitations:

- none recorded

### Google Programmable Search  (`google_cse`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | 100 queries/day free; paid above that (do not enable billing to use TRACEPOINT). |
| Get a key / sign up | https://developers.google.com/custom-search/v1/overview |
| Documentation | https://developers.google.com/custom-search/v1/reference/rest/v1/cse/list |
| Endpoint | `https://www.googleapis.com/customsearch/v1` |
| Authentication | API key + engine ID (cx) as query parameters |
| Required variables | `GOOGLE_SEARCH_API_KEY`, `GOOGLE_SEARCH_CX` |
| Optional variables | none |
| Lookups | `query` - Free-text web search |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('google_cse'))"` |

Known limitations:

- The engine ID (cx) alone only powers an embedded search box; the JSON API also needs an API key.

### GDELT  (`gdelt`)

| | |
|---|---|
| Tier | FREE |
| Free-tier limits | Free, no key. Asks for roughly one request per 5 seconds; TRACEPOINT enforces that. |
| Get a key / sign up | https://www.gdeltproject.org/ |
| Documentation | https://blog.gdeltproject.org/gdelt-doc-2-0-api-debuts/ |
| Endpoint | `https://api.gdeltproject.org/api/v2/doc/doc` |
| Authentication | none |
| Required variables | none |
| Optional variables | none |
| Lookups | `query` - News articles (last 3 months) matching a phrase |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('gdelt'))"` |

Known limitations:

- News coverage only; an article mentioning a name is not evidence about a specific person.
- Machine-translated and machine-tagged metadata may be wrong.

### Internet Archive  (`internet_archive`)

| | |
|---|---|
| Tier | FREE |
| Free-tier limits | Free, no key; no published hard quota, be polite. |
| Get a key / sign up | https://archive.org/developers/ |
| Documentation | https://archive.org/developers/ |
| Endpoint | `https://archive.org/advancedsearch.php` |
| Authentication | none |
| Required variables | none |
| Optional variables | none |
| Lookups | `query` - Search archived items (books, media, web collections) |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('internet_archive'))"` |

Known limitations:

- Searches Archive items, not live pages; use the Wayback Machine adapter for page snapshots.

### Wikipedia (MediaWiki API)  (`wikipedia`)

| | |
|---|---|
| Tier | FREE |
| Free-tier limits | Free, no key. Keep to serial requests and send a descriptive User-Agent (TRACEPOINT does). |
| Get a key / sign up | https://www.mediawiki.org/wiki/API:Main_page |
| Documentation | https://www.mediawiki.org/wiki/API:Search |
| Endpoint | `https://en.wikipedia.org/w/api.php` |
| Authentication | none |
| Required variables | none |
| Optional variables | none |
| Lookups | `query` - Search English Wikipedia articles |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('wikipedia'))"` |

Known limitations:

- Wikipedia is a tertiary, user-edited source; treat statements as leads, not verified facts.

## IP / Network

### IPinfo  (`ipinfo`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free account token; monthly request allowance (see ipinfo.io/pricing). Works without a token at a much lower limit. |
| Get a key / sign up | https://ipinfo.io/signup |
| Documentation | https://ipinfo.io/developers |
| Endpoint | `https://ipinfo.io/{ip}/json` |
| Authentication | Authorization: Bearer <token> (optional) |
| Required variables | none |
| Optional variables | `IPINFO_TOKEN` |
| Lookups | `ip` - Geolocation, organisation/ASN and hostname for an IP |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('ipinfo'))"` |

Known limitations:

- IP geolocation is approximate (often city level or worse) and reflects the network operator, not the person using the address. An IP address is never proof of identity.
- Free-tier responses omit some fields (e.g. privacy detection, carrier).

### IPdata  (`ipdata`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free account key; roughly 1,500 requests/day on the free plan (verify on ipdata.co/pricing). |
| Get a key / sign up | https://ipdata.co/sign-up.html |
| Documentation | https://docs.ipdata.co/ |
| Endpoint | `https://api.ipdata.co/{ip}` |
| Authentication | api-key query parameter |
| Required variables | `IPDATA_API_KEY` |
| Optional variables | none |
| Lookups | `ip` - Geolocation, ASN, threat flags (free-plan fields) |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('ipdata'))"` |

Known limitations:

- IP geolocation is approximate (often city level or worse) and reflects the network operator, not the person using the address. An IP address is never proof of identity.
- Threat/VPN/proxy fields may be restricted on the free plan.

### IP-DB  (`ipdb`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free key: 1,000 checks/day, 10,000/day with a verified email (per ip-db.com/en/api-docs). |
| Get a key / sign up | https://ip-db.com/en/api-docs |
| Documentation | https://ip-db.com/en/api-docs |
| Endpoint | `https://ip-db.com/api/v1/check/{ip}` |
| Authentication | Key header |
| Required variables | `IPDB_API_KEY` |
| Optional variables | none |
| Lookups | `ip` - Abuse/blacklist score, network type and location |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('ipdb'))"` |

Known limitations:

- IP geolocation is approximate (often city level or worse) and reflects the network operator, not the person using the address. An IP address is never proof of identity.
- Reputation scores aggregate third-party feeds; an IP listed once may be shared or reassigned.

### OpenIPAPI  (`openipapi`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free key: 10,000 lookups/month; location and network on the free plan, threat flags on paid plans. |
| Get a key / sign up | https://www.openipapi.com/ |
| Documentation | https://www.openipapi.com/docs |
| Endpoint | `https://api.openipapi.com/v1/lookup/{ip}` |
| Authentication | X-API-Key header |
| Required variables | `OPENIPAPI_API_KEY` |
| Optional variables | none |
| Lookups | `ip` - Geolocation and network owner; `asn` - AS information |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('openipapi'))"` |

Known limitations:

- IP geolocation is approximate (often city level or worse) and reflects the network operator, not the person using the address. An IP address is never proof of identity.
- VPN/proxy/Tor flags and risk scores require a paid plan.

### BGPView  (`bgpview`)

| | |
|---|---|
| Tier | FREE |
| Free-tier limits | Documented as free and keyless. NOTE: api.bgpview.io did not resolve in DNS when this adapter was written. |
| Get a key / sign up | https://bgpview.io/ |
| Documentation | https://bgpview.docs.apiary.io/ |
| Endpoint | `https://api.bgpview.io` |
| Authentication | none |
| Required variables | none |
| Optional variables | none |
| Lookups | `ip` - Prefixes and origin ASNs for an IP; `asn` - ASN details |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('bgpview'))"` |

Known limitations:

- The service appears to be discontinued; use RIPEstat for the same data while it is down.

### RIPEstat  (`ripestat`)

| | |
|---|---|
| Tier | FREE |
| Free-tier limits | Free, no key (RIPE NCC Data API; fair-use limits). Added as a working substitute for BGPView. |
| Get a key / sign up | https://stat.ripe.net/ |
| Documentation | https://stat.ripe.net/docs/02.data-api/ |
| Endpoint | `https://stat.ripe.net/data/{call}/data.json` |
| Authentication | none |
| Required variables | none |
| Optional variables | none |
| Lookups | `ip` - Announced prefix and origin ASN; `asn` - AS overview (holder, announced) |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('ripestat'))"` |

Known limitations:

- Routing data describes networks, not people.

### RDAP (rdap.org)  (`rdap`)

| | |
|---|---|
| Tier | FREE |
| Free-tier limits | Free, no key. rdap.org is a redirector to the authoritative registry servers, each with its own limits. |
| Get a key / sign up | https://rdap.org/ |
| Documentation | https://about.rdap.org/ |
| Endpoint | `https://rdap.org/{domain|ip}/<value>` |
| Authentication | none |
| Required variables | none |
| Optional variables | none |
| Lookups | `domain` - Registration data for a domain; `ip` - Allocation/holder data for an IP block |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('rdap'))"` |

Known limitations:

- Registrant personal data is usually redacted by registries; absence of names is expected.
- Registration data can be stale or privacy-proxied.

## Cybersecurity

### AbuseIPDB  (`abuseipdb`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free account: 1,000 checks/day (verify on abuseipdb.com/pricing). |
| Get a key / sign up | https://www.abuseipdb.com/register |
| Documentation | https://docs.abuseipdb.com/ |
| Endpoint | `https://api.abuseipdb.com/api/v2/check` |
| Authentication | Key header |
| Required variables | `ABUSEIPDB_API_KEY` |
| Optional variables | none |
| Lookups | `ip` - Community abuse reports and confidence score for an IP |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('abuseipdb'))"` |

Known limitations:

- Reputation data is a signal for defensive triage, not a verdict. Shared hosting, reassigned addresses and false positives are common.

### VirusTotal  (`virustotal`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Public API: 4 requests/minute, 500/day, non-commercial use only. |
| Get a key / sign up | https://www.virustotal.com/gui/join-us |
| Documentation | https://docs.virustotal.com/reference/overview |
| Endpoint | `https://www.virustotal.com/api/v3/` |
| Authentication | x-apikey header |
| Required variables | `VIRUSTOTAL_API_KEY` |
| Optional variables | none |
| Lookups | `ip` - Multi-engine reputation for an IP; `domain` - Multi-engine reputation for a domain; `url` - Reputation for a URL (lookup only, never submitted); `hash` - Reputation for a file hash (hash only) |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('virustotal'))"` |

Known limitations:

- Reputation data is a signal for defensive triage, not a verdict. Shared hosting, reassigned addresses and false positives are common.
- Detections come from third-party engines and include false positives.
- Public API terms prohibit commercial use.

### AlienVault OTX  (`otx`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free account and API key; no published daily cap (rate limiting applies). |
| Get a key / sign up | https://otx.alienvault.com/accounts/signup/ |
| Documentation | https://otx.alienvault.com/api |
| Endpoint | `https://otx.alienvault.com/api/v1/indicators/{type}/{value}/general` |
| Authentication | X-OTX-API-KEY header |
| Required variables | `OTX_API_KEY` |
| Optional variables | none |
| Lookups | `ip` - Pulses and reputation for an IP; `domain` - Pulses and whois summary for a domain |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('otx'))"` |

Known limitations:

- Reputation data is a signal for defensive triage, not a verdict. Shared hosting, reassigned addresses and false positives are common.
- Pulses are community-contributed and unvetted; presence in a pulse is an allegation, not proof.

### urlscan.io  (`urlscan`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free account key raises search/scan quotas; unauthenticated search is allowed at a lower rate. |
| Get a key / sign up | https://urlscan.io/user/signup |
| Documentation | https://urlscan.io/docs/api/ |
| Endpoint | `https://urlscan.io/api/v1/search/` |
| Authentication | API-Key header (optional for search) |
| Required variables | none |
| Optional variables | `URLSCAN_API_KEY` |
| Lookups | `domain` - Existing public scans involving a domain; `ip` - Existing public scans involving an IP |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('urlscan'))"` |

Known limitations:

- Reputation data is a signal for defensive triage, not a verdict. Shared hosting, reassigned addresses and false positives are common.
- Search only: TRACEPOINT never submits scans, because public scans publish the target URL.
- Scan results are snapshots from other users' scans and may be stale.

### ThreatFox  (`threatfox`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free abuse.ch Auth-Key (one key covers ThreatFox and URLhaus); fair-use limits. |
| Get a key / sign up | https://auth.abuse.ch/ |
| Documentation | https://threatfox.abuse.ch/api/ |
| Endpoint | `https://threatfox-api.abuse.ch/api/v1/` |
| Authentication | Auth-Key header |
| Required variables | `ABUSECH_AUTH_KEY` |
| Optional variables | none |
| Lookups | `ioc` - Search an indicator (IP:port, domain, URL or hash) |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('threatfox'))"` |

Known limitations:

- Reputation data is a signal for defensive triage, not a verdict. Shared hosting, reassigned addresses and false positives are common.
- A listing means the indicator was reported as malicious at some time; infrastructure is reused and cleaned.

### URLhaus  (`urlhaus`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free abuse.ch Auth-Key (one key covers ThreatFox and URLhaus); fair-use limits. |
| Get a key / sign up | https://auth.abuse.ch/ |
| Documentation | https://urlhaus-api.abuse.ch/ |
| Endpoint | `https://urlhaus-api.abuse.ch/v1/` |
| Authentication | Auth-Key header |
| Required variables | `ABUSECH_AUTH_KEY` |
| Optional variables | none |
| Lookups | `host` - Malware URLs seen on a domain or IP; `url` - Whether a URL is listed |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('urlhaus'))"` |

Known limitations:

- Reputation data is a signal for defensive triage, not a verdict. Shared hosting, reassigned addresses and false positives are common.
- A listing means the indicator was reported as malicious at some time; infrastructure is reused and cleaned.

## Government / Public records

### CourtListener  (`courtlistener`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free account token (Free Law Project); throttled to a few thousand requests/hour per user. |
| Get a key / sign up | https://www.courtlistener.com/sign-up/ |
| Documentation | https://www.courtlistener.com/help/api/rest/ |
| Endpoint | `https://www.courtlistener.com/api/rest/v4/search/` |
| Authentication | Authorization: Token <token> |
| Required variables | `COURTLISTENER_API_KEY` |
| Optional variables | none |
| Lookups | `opinions` - Court opinions matching text; `dockets` - RECAP federal docket entries matching text |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('courtlistener'))"` |

Known limitations:

- Records can be incomplete, outdated, or concern a different person or organisation with the same or a similar name. Verify identity with the original record before relying on a match.
- Coverage is not a complete record of any jurisdiction. Prefer the official court record; CourtListener is an aggregator (federal PACER/RECAP plus some state courts).
- A docket shows that a case exists. It does not by itself distinguish a charge, allegation, conviction or dismissal; read the underlying filings.

### GovInfo  (`govinfo`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free api.data.gov key; 1,000 requests/hour per key. |
| Get a key / sign up | https://api.data.gov/signup/ |
| Documentation | https://api.govinfo.gov/docs/ |
| Endpoint | `https://api.govinfo.gov/` |
| Authentication | X-Api-Key header |
| Required variables | `GOVINFO_API_KEY` |
| Optional variables | none |
| Lookups | `query` - Search official US government publications (Federal Register, CFR, court opinions, ...) |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('govinfo'))"` |

Known limitations:

- Records can be incomplete, outdated, or concern a different person or organisation with the same or a similar name. Verify identity with the original record before relying on a match.
- Official publication text; a mention does not establish wrongdoing.

### SEC EDGAR  (`sec_edgar`)

| | |
|---|---|
| Tier | FREE |
| Free-tier limits | Free, no key. SEC requires a declared contact in the User-Agent and a maximum of 10 requests/second. |
| Get a key / sign up | https://www.sec.gov/search-filings/edgar-application-programming-interfaces |
| Documentation | https://www.sec.gov/search-filings/edgar-application-programming-interfaces |
| Endpoint | `https://data.sec.gov/submissions/CIK##########.json` |
| Authentication | User-Agent with contact details (no key) |
| Required variables | `SEC_EDGAR_CONTACT` |
| Optional variables | none |
| Lookups | `cik` - Company profile and recent filings by CIK; `company` - Find companies by name; `filing_text` - Full-text search of filings since 2001 |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('sec_edgar'))"` |

Known limitations:

- Records can be incomplete, outdated, or concern a different person or organisation with the same or a similar name. Verify identity with the original record before relying on a match.
- Filings are self-reported by the filer; the SEC does not verify their contents.

### USAspending  (`usaspending`)

| | |
|---|---|
| Tier | FREE |
| Free-tier limits | Free, no key, no published quota (fair use). |
| Get a key / sign up | https://api.usaspending.gov/ |
| Documentation | https://api.usaspending.gov/docs/endpoints |
| Endpoint | `https://api.usaspending.gov/api/v2/recipient/` |
| Authentication | none |
| Required variables | none |
| Optional variables | none |
| Lookups | `recipient` - Federal award recipients matching a name |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('usaspending'))"` |

Known limitations:

- Records can be incomplete, outdated, or concern a different person or organisation with the same or a similar name. Verify identity with the original record before relying on a match.
- Reflects federal awards as reported by agencies; recipients are often parent/child entity records.

### FEC (OpenFEC)  (`fec`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | Free api.data.gov key: 1,000 requests/hour. Without a key TRACEPOINT uses the shared DEMO_KEY (very low limits). |
| Get a key / sign up | https://api.data.gov/signup/ |
| Documentation | https://api.open.fec.gov/developers/ |
| Endpoint | `https://api.open.fec.gov/v1/` |
| Authentication | X-Api-Key header (DEMO_KEY fallback) |
| Required variables | none |
| Optional variables | `FEC_API_KEY` |
| Lookups | `candidate` - Candidates by name; `committee` - Committees by name; `contributor` - Itemized individual contributions by contributor name |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('fec'))"` |

Known limitations:

- Records can be incomplete, outdated, or concern a different person or organisation with the same or a similar name. Verify identity with the original record before relying on a match.
- Federal law (52 U.S.C. 30111(a)(4)) forbids using contributor names or addresses for solicitation or commercial purposes.
- Donor records are self-reported and not verified; same-name contributors are common.

### OpenCorporates  (`opencorporates`)

| | |
|---|---|
| Tier | FREE-TIER |
| Free-tier limits | API access requires an account token. Free access is granted by application for public-benefit / open-data use; otherwise it is a paid service. Confirm your eligibility with OpenCorporates. |
| Get a key / sign up | https://opencorporates.com/users/sign_up |
| Documentation | https://api.opencorporates.com/documentation/API-Reference |
| Endpoint | `https://api.opencorporates.com/v0.4/companies/search` |
| Authentication | api_token query parameter |
| Required variables | `OPENCORPORATES_API_KEY` |
| Optional variables | none |
| Lookups | `company` - Company registry records by name |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('opencorporates'))"` |

Known limitations:

- Records can be incomplete, outdated, or concern a different person or organisation with the same or a similar name. Verify identity with the original record before relying on a match.
- Registry data is aggregated from government registers and may lag them; always cite the original registry.

## Domain / History

### crt.sh  (`crtsh`)

| | |
|---|---|
| Tier | FREE |
| Free-tier limits | Free, no key. Community service with no SLA; frequently slow or overloaded. |
| Get a key / sign up | https://crt.sh/ |
| Documentation | https://crt.sh/ |
| Endpoint | `https://crt.sh/?q=<domain>&output=json` |
| Authentication | none |
| Required variables | none |
| Optional variables | none |
| Lookups | `domain` - Certificate Transparency entries and subdomain names |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('crtsh'))"` |

Known limitations:

- Certificates show names that were certificated, not who operates them or whether they are live.
- Responses are capped and the service can time out under load.

### Wayback Machine  (`wayback`)

| | |
|---|---|
| Tier | FREE |
| Free-tier limits | Free, no key; polite use (a few requests/second at most). |
| Get a key / sign up | https://web.archive.org/ |
| Documentation | https://archive.org/help/wayback_api.php |
| Endpoint | `https://archive.org/wayback/available` |
| Authentication | none |
| Required variables | none |
| Optional variables | none |
| Lookups | `url` - Closest archived snapshot plus first and last capture of a domain or URL |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('wayback'))"` |

Known limitations:

- A snapshot shows what the crawler saw at that moment; absence of a snapshot proves nothing.
- Archived content may be incomplete or have been modified by scripts at capture time.

### Cloudflare DNS over HTTPS  (`cloudflare_doh`)

| | |
|---|---|
| Tier | FREE |
| Free-tier limits | Free, no key (1.1.1.1 public resolver; fair use). |
| Get a key / sign up | https://developers.cloudflare.com/1.1.1.1/ |
| Documentation | https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/ |
| Endpoint | `https://cloudflare-dns.com/dns-query` |
| Authentication | Accept: application/dns-json |
| Required variables | none |
| Optional variables | none |
| Lookups | `dns` - A, AAAA, MX, NS and TXT records for a domain |
| Test procedure | Integrations dashboard: `t N`; or `python -c "from integrations import manager; print(manager.test('cloudflare_doh'))"` |

Known limitations:

- Resolver answers reflect Cloudflare's cache and may differ from the authoritative servers.
- NXDOMAIN and empty answers are reported as such; a SERVFAIL is an error, not an absence.
