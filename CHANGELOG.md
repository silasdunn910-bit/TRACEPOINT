# Changelog

## 1.0.2 - 2026-11-03 (Intelligence search and reporting upgrade)
- Report layout is now the 12 required sections (Executive Summary, Investigation Scope, Research Methodology, Sources Consulted, Key Findings, Evidence Assessment, Entity Relationships, Contradictory or Unverified Information, Intelligence Gaps, Limitations, Overall Assessment, Recommended Next Research Steps). Markdown, PDF and the terminal view render one shared block list; repeated paragraphs/warnings are emitted once. Report engine 1.1.
- Classification: a search that ran but returned zero findings is PARTIAL, never COMPLETE (behaviour change; the old test was updated). A module crash stores the investigation as status `failed` with a FAILED report (confidence INSUFFICIENT).
- Evidence rules: search-engine results are capped at LOW (cannot be VERIFIED/CORROBORATED/MODERATE); AI-sourced findings are capped at LOW and never counted as corroboration; each finding shows the effective grade, the reason for any cap, supporting and contradictory evidence.
- Source registry (`core/source_registry.py`, table `source_registry`): one record per provider + normalized URL, with status, parsed HTTP status, retrieval time, reliability by source type and linked findings. `consulted` is true only after a recorded successful retrieval; URLs only cited by findings are "cited only". Mixed outcomes across repeated queries show as `partial`, not as the first attempt's status.
- Workflow (`core/workflow.py`, table `investigation_stages`): ten recorded stages from Initialization to Database Persistence; unreached stages are NOT_RUN. Failures keep their scrubbed detail; a report-stage failure leaves findings intact and marks the investigation `complete_with_errors`.
- AI analyst: evidence payload carries claim class/grade/conflicts; output is verified (invented URLs removed, bad citations neutralised, person-conclusion sentences removed, uncited FACTS marked); new tasks `executive`, `patterns`, `gaps`. Stored separately from findings and labelled as analysis, not evidence.
- Universal search warns up front when no keyed search provider is configured; `Jane Q Public` (middle initial) is now detected as a name.
- Schema v4 (additive; backup taken first; failed step rolls back): `investigation_stages`, `source_registry`, indexes on findings/sources/investigations/search_history/reports.
- Version 1.0.2. Tests: `tests/test_v102.py` (61 tests); `test_phase5` real-database migration test now copies via the SQLite backup API (a plain file copy drops data held in the WAL file).

## Unreleased (Universal Intelligence Report Engine)
- New package `core/intelligence/` (engine, models, evidence_analyzer, confidence, templates, formatter, pdf). It builds on `core.reports.build()`, the existing collection path, so there is one report pipeline for every investigation type; unknown/future types use a cautious generic profile.
- `core.investigation.run()` ends every persisted investigation by generating and storing an Intelligence Report (new keyword `intel_report=True`). The stage never raises: a failure is stored as a `FAILED` report with credential-scrubbed error text, and the saved investigation is unaffected.
- Eleven sections (overview, executive summary, key findings, evidence & source registry, corroboration, contradictions, assessment, confidence & limitations, unresolved questions, next steps, source references). Status `COMPLETE` / `PARTIAL` / `INCOMPLETE` / `FAILED`; investigations with failed or blocked sources, module errors, or nothing searched are shown as INCOMPLETE.
- Evidence registry keeps every finding's source, exact URL, retrieval time, publication date, evidence and module grade; gaps are listed, never filled. Claim classes: verified fact, corroborated, single-source, unverified, analytical inference, contradictory. Corroboration requires distinct origins and source names; same-origin repeats count once; stored grades are never raised.
- Discrepancies: module-reported contradictions, `core.correlation` rules, single-valued attribute conflicts and presence/absence conflicts, each linked to evidence refs.
- Guard against unsupported conclusions (identity, location, criminality, dangerousness, wrongdoing); inferences without evidence are discarded.
- UI: brief report panel after every investigation; `intel` action in the post-investigation menu and History; new menu 19 *Intelligence Reports*; report view with E#/S# evidence links, regenerate, PDF and Markdown export. Menu 12 offers `pdf`/`md` alongside `txt`/`json`/`html` (`core.reports.save()` delegates the new formats).
- PDF export without new dependencies (standard fonts, URI link annotations with exact URLs); Markdown escapes third-party text and links only safe http(s) URLs.
- Schema v3 (additive): table `intel_reports`, cascade-deleted with its investigation. Existing data untouched.
- Tests: `tests/test_intelligence_report.py` (81 tests).

## Unreleased (Free API integration layer)
- New `integrations/` package: one adapter contract (credentials, classified requests, timeouts, retry/backoff, per-provider pacing, quota capture from headers, normalized results with `source_url`/`timestamp`/`limitations`) and a manager (status, test, lookup, enable/disable, persistence). A provider is CONNECTED only after a real request succeeds; a stored key alone shows NOT TESTED. One failing provider never raises into the app.
- 28 adapters: SearXNG, Brave, Google CSE (wrapping the existing search providers), GDELT, Internet Archive, Wikipedia, IPinfo, IPdata, IP-DB, OpenIPAPI, BGPView (service currently offline), RIPEstat (added as the working BGP source), RDAP, AbuseIPDB, VirusTotal, AlienVault OTX, urlscan.io, ThreatFox, URLhaus, CourtListener, GovInfo, SEC EDGAR, USAspending, FEC, OpenCorporates, crt.sh, Wayback Machine, Cloudflare DoH. VirusTotal and urlscan are lookup-only; nothing is uploaded or submitted.
- Menu 18 *Integrations Dashboard* (status, tier, last success, quota, test, lookup, set key, disable). Shows variable names, never values.
- Credentials: environment variables (see `.env.example`) now back the encrypted store; a project-root `.env` is also read. Blank `.env` values are ignored.
- New settings entries (IPdata, IP-DB, OpenIPAPI, OTX, urlscan, abuse.ch, CourtListener, FEC, SEC contact) appear in API Configuration.
- Docs: `API_SETUP.md`, `INTEGRATION_STATUS.md`, `API_PROVIDER_REFERENCE.md`. Tests: `tests/test_integrations.py` (mocked) and opt-in `tests/test_integrations_live.py`.

## Unreleased (Phase 8, part 2: jurisdiction selection and search coverage)
- Court Records and Sex Offender Registry open with a *Jurisdiction Selection* menu: United States (Nationwide), Select a State, Federal Courts (National Registry in the registry module). States accept postal codes or full names, any case, surrounding whitespace; all 50 states and DC; invalid input is explained and can be retried.
- Provider discovery per jurisdiction (federal, state, county where catalogued); automated and manual sources are shown separately. No provider, county source or endpoint was added or guessed: only North Carolina and the federal/national sources exist.
- New search-method screen (name / case number or registry ID) before the search term; names with spaces, hyphens, apostrophes and Unicode are accepted; case numbers are validated separately.
- Every search generates a coverage report from actual provider execution: `SEARCHED`, `MANUAL`, `UNAVAILABLE`, `NOT IMPLEMENTED`, `FAILED`, `SKIPPED`, with overall `NONE` / `PARTIAL` / `COMPLETE`. A nationwide request is never reported as nationwide coverage; zero records is never reported as proof of absence.
- Scope, resolved jurisdiction, provider, search method, coverage status, source URLs and retrieval times are saved with each investigation (notes, sources, finding evidence; no schema change) and shown in reports. Older investigations show coverage as `NOT RECORDED`.
- `modules/*_intel.investigate()` accepts `jurisdiction=`; new `plan()` and `search()` helpers. A provider that raises is recorded as `FAILED` instead of aborting the search.
- Existing CLI scripts for menu 16/17 must use the new prompt order (jurisdiction menu, state, method, term).

## Unreleased (Phase 8)

### Court Records Intelligence and Sex Offender Registry Intelligence (menu 16, 17)
- New modules `court_records_intel` and `registry_intel` with separate record types, categories and report sections.
- Official sources catalogued with agency, URL, method, authentication and coverage: GovInfo U.S. Courts Opinions (automated; needs a free api.data.gov key), PACER, NC Judicial Branch, NSOPW and the NC SBI registry (manual).
- Identity safeguards: every record is `UNVERIFIED`; only records the operator reviews and attaches are stored; no merging by name; mandated empty-result wording; "search never ran" is never reported as "nothing found".
- Normalized court and registry statuses next to the source's original wording; civil and opinion records can never be `CONVICTED`/`ACQUITTED`.
- Registry records carry no address or location data; address-like text is rejected.
- Reports gained a *Records review* section. No schema migration; historical investigations are untouched.
- Rich markup in record text (square brackets) is escaped when shown in History and the new screens.
- New integration key: `govinfo_key` (API Configuration).

## Unreleased (Phases 7 and 7.1)

### Security
- Public-only fetches (Social module) now validate every resolved address and connect to that validated address, so DNS rebinding between check and connect cannot reach local or internal hosts. Redirects are followed manually and re-checked; TLS verification is unchanged; environment proxies are ignored for these requests.
- Address classification also rejects multicast, carrier-grade NAT and IPv4-in-IPv6 forms (mapped, 6to4, NAT64) of non-public IPv4 addresses.
- Credentials: the configuration screen shows nothing of values under 20 characters (and only the last 4 of longer ones); known credential values and header/bearer shapes are redacted from logs and from persisted error text.
- Request logs record host and status only.

### Reliability / tooling
- Atomic investigation saves; menu actions can fail without ending the session; Ctrl-C returns to the menu; the offline Ollama probe is cached for the banner.
- Dependencies pinned (`requirements.txt`, `constraints.txt`); Python 3.11+ required.
- Tests run against a temporary `TRACEPOINT_HOME` and fail if the real installation changes.

## 1.0.1 - 2026-11-02

### Evidence
- Added `CORROBORATED` and `INCONCLUSIVE` grades (six levels). Legacy `STRONG` records are unchanged in the database and displayed as CORROBORATED.
- Summary counts in reports and the terminal use the same normalisation and always add up to the finding count.

### Search infrastructure
- Provider failures are classified: invalid key, invalid configuration, rate limit, quota exhausted, access denied, server error, invalid response, timeout, unavailable.
- Malformed or non-JSON provider replies produce provider-specific errors instead of crashing.
- DuckDuckGo is a labelled fallback only when every configured provider fails (or the default when none is configured).
- `search()` reports whether a search actually completed; "zero results" is distinct from "search never ran" in Name, Email, Phone and Username results.
- Connection tests (`t` in API Configuration) and honest status labels; SearXNG URL validation; confirmed credential deletion; clear messages for empty/invalid input.

### Modules
- Username: 401/403/429/anti-bot pages are `blocked` (source status BLOCKED, finding INCONCLUSIVE), 5xx is `error`; never "not found".
- Email: HIBP 401/429/5xx/unreadable responses are errors ("breach status unknown"), never a clean result.
- Name: exact missing-configuration message; stops after repeated provider failures.
- Relationship Explorer: shared webmail/DNS/CDN/resolver infrastructure is flagged generic and hidden from "shared entities".

### Reports and data
- Report paths resolve against the current reports folder; old `C:\Projects\...` history rows work without being modified. New rows store the file name only.
- No database records were modified or deleted.

### AI
- Hardened Ollama status/analysis against unexpected replies; empty or unreadable output is an error and is not saved.

### Tooling
- Version 1.0.1; `requirements-dev.txt` (pytest); 119 offline tests.
