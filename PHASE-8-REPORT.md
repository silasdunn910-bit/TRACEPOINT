# TRACEPOINT Phase 8 - Court Records & Sex Offender Registry Intelligence

Branch `phase-6-integration`, on top of `643cca0` (Phase 7.1). Not pushed. 2026-11-02, Python 3.11.9 (`.venv`).

## 0. Summary and honest scope

Both modules exist (Part 2 below adds jurisdiction selection and coverage reporting), are wired into the menu (16 and 17), the database, History and the reports, and are covered by 202 new
tests. **Automated coverage is deliberately narrow:** exactly one source is searched automatically (GovInfo's federal
court *opinions*). Every other source (PACER, NC Judicial Branch, NSOPW, NC SBI registry) is *manual*: TRACEPOINT shows the
official page, documents what the source supports, and records what the operator reviews. That is what the official
sources' own documentation allows or what could be verified; nothing was guessed to make it look more capable.
**No nationwide coverage is claimed anywhere.**

## 1. Baseline (Step 1)

| Item | Value |
|---|---|
| Branch / tree | `phase-6-integration`, clean |
| HEAD | `643cca0` (Phase 7.1); `PHASE-7-REPORT.md` and `PHASE-7.1-REPORT.md` present and read |
| Python / dependencies | 3.11.9; `rich 15.0.0`, `requests 2.34.2`, `dnspython 2.9.1`, `phonenumbers 9.0.42` (unchanged; `pip check` clean) |
| Tests before | 251 passed |
| Real database | 14 investigations, 98 findings, 30 entities, 29 relationships, 3 reports; last modified 06:12:55, unchanged at the end |
| Architecture reviewed | `core/models.py` (Finding/ModuleResult/SourceRecord), `core/investigation.py` (specs, runners, authorization), `core/database.py` (`save_result`, UNIQUE fingerprints), `providers/search_providers.py` (error kinds), `core/http.py`, `core/reports.py`, `main.py` menu/`run_and_show`, `modules/name_intel.py` |

## 2. What the official sources actually allow (research, 2026-11-02)

Read from the agencies' own pages via a fetch sub-agent; each fact is attributed, and gaps are stated.

| Source | Finding | Consequence |
|---|---|---|
| NSOPW (nsopw.gov) | FAQ: no API ("The browser interface is the only way to search"); Conditions of Use prohibit "automated searching or attempts to bypass security mechanisms"; searches use a CAPTCHA; name, jurisdiction, county/city/ZIP (if the jurisdiction provides it), radius search | **Manual only.** Not automated, not scraped |
| NC SBI registry (sexoffender.ncsbi.gov) | Home/About/FAQ read; an Acceptable Use Policy (public protection; prosecution for stalking/harassment); no API, bulk download, CAPTCHA or automated-access rule stated; the search form itself could not be read; juveniles excluded; partly offender-reported | **Manual only** (capabilities unverified) |
| NC Judicial Branch (nccourts.gov, portal) | Both fetches returned **HTTP 403** | **Unverified; manual only.** Search fields, fees, CAPTCHA, county coverage are listed as unknown |
| PACER | Account required (free); $0.10/page, waived at $30 or less per quarter; name searches are billed even with no matches; a Case Locator API exists but needs PACER login and its endpoints are in a PDF that could not be read | **Manual only.** API not implemented (would require guessing parameters) |
| GovInfo (GPO) | Documented `POST https://api.govinfo.gov/search`, `collection:(USCOURTS)`, `api.data.gov` key (free), 36,000 requests/hour default, "public preview" | **Automated**, opinions only |

Live verification of the one automated source: a non-personal query (`securities fraud`) with GovInfo's public `DEMO_KEY`
returned HTTP 200 with the documented `count` / `offsetMark` / `results[]` shape and the fields used (`title`, `packageId`,
`granuleId`, `governmentAuthor`, `dateIssued`, `resultLink`). No person was searched live.

## 3. Architecture changes (Step 2)

Court cases and registry listings are separate record types, categories, modules and report treatments; only formatting
helpers are shared.

**New files**
- `providers/records_common.py` - `OfficialSource`, `SearchOutcome`, `CourtRecord`, `RegistryRecord`, validators, status classifiers, mandated messages
- `providers/court_sources.py` - court source catalog and the GovInfo provider
- `providers/registry_sources.py` - registry catalog (all manual) and an empty `AUTOMATED_SEARCHERS` hook for a future *documented, permitted* provider
- `modules/records_shared.py` - source-record and evidence formatting
- `modules/court_records_intel.py`, `modules/registry_intel.py`
- `tests/test_court_records.py`, `tests/test_registry_intel.py`

**Modified files**
- `core/investigation.py` (specs, runners, both types added to the authorization-required set)
- `core/configuration.py` (`govinfo_key` in API Configuration)
- `core/reports.py` (*Records review* section in TXT/HTML/JSON)
- `main.py` (menu 16/17, workflows, `already_authorized`, Rich-markup escaping)
- `README.md`, `CHANGELOG.md`

No schema migration: findings/sources/entities/search history already hold everything (structured fields live in the
`evidence` text, the identifier in `value`, so the existing UNIQUE fingerprint prevents duplicates).

## 4. Court Records Intelligence (Steps 3-5)

| Capability | Status |
|---|---|
| Search by person name or case number | **PASS** (GovInfo full-text, automated). Other sources: manual |
| Jurisdiction selection (Federal, North Carolina) | **PASS** |
| Federal / state / county levels | Federal and state catalogued; **county portals not catalogued** (WARNING) |
| Court, filing date, status, charges, civil/criminal, outcome, URL | Captured **when the operator enters them** from an official portal; GovInfo supplies only title, court/agency, issue date, identifier, URL. Not searchable by court, date, status or charges (documented as unsupported) |
| Provider metadata (agency, jurisdiction, URL, retrieval time, method, coverage, completeness, auth) | **PASS**: stored in the catalog and written into every source record |
| Normalized statuses | **PASS**: PENDING, DISMISSED, CONVICTED, ACQUITTED, DEFERRED, SEALED / UNAVAILABLE, UNKNOWN. Original wording is stored beside the normalized value |
| Never confuse arrest/charge/conviction, dismissal/acquittal, civil/criminal | **PASS** (tests): "Arrested", "Charged", "Filed" stay UNKNOWN; "Dismissed" is never ACQUITTED; civil and opinion records can never be CONVICTED/ACQUITTED |
| CAPTCHA / authentication / paywall bypass | **None attempted.** Manual sources never touch the network (tested) |
| Silent commercial substitution | **None** |

## 5. Sex Offender Registry Intelligence (Steps 6-9)

| Capability | Status |
|---|---|
| NSOPW and NC SBI catalogued with agency, URLs, auth, coverage, limitations | **PASS** |
| Automated search of any registry | **Not implemented, by design** (NSOPW prohibits it; NC SBI undocumented) |
| Search kinds | Name and registry ID are what TRACEPOINT records. State selection is the jurisdiction choice. County/city/ZIP narrowing is done in the portal; address/radius/ZIP-as-query and status filters are **deliberately unsupported** and documented |
| Fields | Displayed name, registry ID, jurisdiction, displayed status, offense classification as published, registration date, update date, source URL, agency, entry time. **No address, location, photo or physical-description field exists**; street-address-like text is rejected; extra location fields in input are ignored (tested) |
| Status | ACTIVE / INACTIVE / DECEASED / ABSCONDED / UNKNOWN, conservative; displayed status and normalized status are shown separately; no inference of whereabouts |

## 6. Identity safeguards and evidence (Steps 10-11)

- Every attached record is `UNVERIFIED`, with the limitation text "A name match is not proof of identity" in the finding.
- Candidates returned by a source are **not stored** unless the operator selects them and confirms each one; a selection that no source returned is rejected.
- Records are never merged by name; exact duplicates collapse; conflicting statuses for the same identifier create a `contradiction` finding.
- Court and registry evidence use different categories (`court_record_*`, `registry_listing_*`).
- Mandated wording is used verbatim for completed empty searches. A search that never ran (manual source, failed provider, missing key) is reported as "no source was searched automatically", never as "nothing found" (tested).
- Reports include a *Records review* section: official source information, unverified name matches, manually reviewed records, missing information, inaccessible/manual-only sources, conflicting records, partial coverage, plus the standing statements.
- Manually typed records are the operator's transcription of an official portal; TRACEPOINT cannot verify them. The URL check only flags hosts outside the source's official domains.

## 7. CLI and database (Steps 12-13)

| Item | Status |
|---|---|
| Two separate menu options added; all existing options keep their numbers (new items are 16 and 17, so numbering is non-contiguous) | **PASS** (WARNING: cosmetic) |
| Court and registry workflows (jurisdiction, source, search, results, official link, review, attach, save, report) | **PASS**: tested with scripted prompts, and a real `main.py` process run with piped keystrokes saved both investigations without errors |
| Authorization gate before any search or save | **PASS** (declining saves nothing) |
| History, reports, graph export | **PASS** |
| Copy of the real database | 14 -> 16 investigations, findings 98 -> 100, relationships unchanged, `integrity_check` ok, foreign keys clean, schema still v2, all 48 historical + new reports regenerated; real file untouched |
| Duplicate prevention | **PASS** |

## 8. Tests (Step 14)

| Run | Result |
|---|---|
| Full suite | **453 passed, 0 failed, 0 skipped** (251 before + 202 new: court 124, registry 78) |
| Isolation | Suite uses a temporary data home; the guard confirmed the real database/log/reports were unchanged |
| Coverage of the requested list | Name/case/ID validation, jurisdiction and provider selection, supported/unsupported fields, provider failures (401/403/429/5xx/timeout/connection), missing configuration, malformed responses, duplicates, status classification, source attribution, unverified-identity handling, empty results, persistence, reports (TXT/JSON/HTML), CLI, offline operation |
| Caveat | **Registry provider failures and malformed responses are tested only through a test double**, because no registry has an automated provider |
| Not done | No live test with a real GovInfo key, no live search of any person, no manual interactive session by a human |

## 9. Security and regression review (Step 16)

| Check | Result |
|---|---|
| SSRF / unsafe redirects / DNS rebinding | **PASS**: the new code fetches only the fixed host `api.govinfo.gov`; user-entered URLs are stored, never fetched; the only browser launch uses catalog URLs. Phase 7.1's pinned fetch is untouched |
| TLS verification | **PASS**: default `requests` verification (asserted) |
| SQL injection / path traversal | **PASS**: no new SQL or file paths; existing parameterised persistence |
| Credential exposure | **PASS**: `govinfo_key` is encrypted, masked, redacted from logs; the key was absent from findings, sources, errors, notes and the log (tested). The key is sent as the documented `api_key` query parameter; the header form is unverified |
| Sensitive data in logs | **PASS**: the searched name does not reach the log (tested); HTTP logs record host and status only |
| Excessive data collection | **PASS**: no addresses/locations; unattached candidates discarded; free-text fields length-limited and control-character stripped |
| Report injection | **PASS**: `<script>` in a case title is escaped in HTML (tested) |
| Rich markup injection | **FAIL -> fixed**: bracketed text (`[/x]`, `[link=...]`) crashed or altered the new candidate table and the existing History viewer. Escaped in the new screens and in `view_investigation`; regression tests added |
| Improper record merging / confidence | **PASS**: no merging by name; all `UNVERIFIED` |
| Migrations | **PASS**: none required; the real-database copy check passed |
| Dependencies | **PASS**: none added |

## 10. Known limitations

- Automated court search is limited to federal published opinions via GovInfo: a full-text match can hit other people, results have no status (always UNKNOWN), a person with a case but no published opinion will not appear, and the service describes itself as a "public preview". The key-in-header form and Swagger schema were not read.
- All registry searching and all state/federal docket searching is manual; the operator-entered record is unverifiable by TRACEPOINT.
- NC Judicial Branch and NC SBI search capabilities are unverified (HTTP 403 / unreadable form). County court portals and other states are not catalogued. Only NC and federal are represented.
- Status classification is an English-keyword heuristic; unrecognised wording becomes UNKNOWN by design.
- PACER Case Locator API is not used (needs credentials; endpoints not verifiable).
- Source terms of other states' registries were not reviewed.

## 11. Remaining work

Verify the NC portals in a browser and, if a documented non-interactive path exists, add a provider with mocked tests; read GovInfo's Swagger to confirm the key header; add other jurisdictions one at a time with the same catalog fields; decide whether to renumber the menu.

## 12. Overall readiness

**WARNING - usable as a guided, manual-first records-review tool; not a nationwide automated search.** The safeguards (no auto-attribution, no unattached storage, no addresses, honest empty/failed-search wording, official-source attribution) are implemented and tested, the existing 251 tests and the real data are intact, and the single automated source works against its documented API. It should not be described as covering every jurisdiction, and the manual/unverified items above should be resolved before relying on it for anything beyond operator-reviewed leads.

Phase 9 has not been started.

---

# Part 2 - Nationwide jurisdiction selection and search-coverage workflow

2026-11-02, same branch, on top of `b4b1ac1`. Not pushed. Phase 9 not started.

## 13. Summary

Court Records (menu 16) and Sex Offender Registry (menu 17) now start with a jurisdiction menu (United States / a state /
Federal Courts) and a search-method menu, and every search produces a coverage report generated from what the providers
actually did. **This changes how a jurisdiction is chosen, not what can be searched.** All 50 states and DC can be
selected, but the catalogue is unchanged: no provider, county source, URL or endpoint was added, because none was
verified. A nationwide request therefore yields `PARTIAL` coverage at best (one automated source, GovInfo, and only when a
key is stored), and a state other than NC yields `NONE` with the jurisdiction reported as `NOT IMPLEMENTED`.

## 14. Supported jurisdiction selections

| Input | Result |
|---|---|
| `US`, `USA`, `United States`, `Nationwide`, menu 1 | Nationwide *request* |
| Two-letter code for any of the 50 states or `DC`, any case, padded with whitespace (menu 2) | That state |
| Full state name in any case, repeated spaces or hyphens (`north carolina`, `West-Virginia`) | That state |
| `District of Columbia`, `Washington DC`, `Washington, D.C.`, `D.C.` | DC (`Washington` alone is the state of WA) |
| `Federal`, `Federal Courts`, menu 3 (registry module: National Registry / NSOPW) | Federal / national level |
| Territories (PR, GU, ...), unknown names, empty / over-long / control-character input | Rejected with a message (near-miss suggestions, e.g. "Nort Carolina" -> North Carolina); the prompt repeats |

Resolution is in `providers/jurisdictions.py`; input is NFKC-normalised and case-folded. Users never see provider ids.

## 15. Actual coverage (what is real today)

| Scope | Court Records | Registry |
|---|---|---|
| Nationwide | GovInfo **SEARCHED** (needs a stored key, otherwise `UNAVAILABLE`); PACER **MANUAL**; NC Judicial Branch **MANUAL**; 50 jurisdictions **NOT IMPLEMENTED**. Overall `PARTIAL` (or `NONE`) | NSOPW **MANUAL**; NC SBI **MANUAL**; 50 jurisdictions **NOT IMPLEMENTED**. Overall `NONE` |
| NC | NC Judicial Branch MANUAL (federal courts excluded as a separate jurisdiction; no county sources catalogued). `NONE` | NSOPW (manual national route) + NC SBI, both MANUAL. `NONE` |
| Any other state or DC | No source: `NOT IMPLEMENTED`, `NONE` | NSOPW MANUAL only (it can be narrowed to that state in the browser); state registry `NOT IMPLEMENTED`. `NONE` |
| Federal / national | GovInfo (automated), PACER (manual) | NSOPW (manual) |

- **Automated:** exactly one provider (GovInfo federal opinions). No registry is searched automatically (NSOPW prohibits it; NC SBI undocumented).
- **Manual-only:** PACER, NC Judicial Branch, NSOPW, NC SBI. The URL, authentication and fees are shown; TRACEPOINT never says it searched them.
- **Unsupported:** every jurisdiction except NC, for both modules (50 of 51 states/DC), and all county portals.
- **COMPLETE** is only reachable if every provider in scope was searched, each claims `complete`, and no jurisdiction lacks a provider. No source claims completeness, so it is unreachable with the current catalogue (the logic is tested with synthetic sources).

## 16. What changed

**New:** `providers/jurisdictions.py` (51-entry table, `resolve`), `providers/coverage.py` (plan, execute, `CoverageReport`, statuses, serialisation), `tests/test_jurisdictions.py` (181 tests).

**Modified:**
- `providers/records_common.py`: `OfficialSource.kinds` (search kinds a source accepts), `SearchOutcome.error_kind`, `skipped` status.
- `providers/court_sources.py`, `registry_sources.py`: NSOPW accepts name only; GovInfo marks reachability errors (offline, timeout, 429, 5xx) as `unavailable`. Source catalogues otherwise unchanged.
- `modules/court_records_intel.py`, `registry_intel.py`: `plan()`, `search()`, `investigate(jurisdiction=, coverage=)`; a crashing provider becomes `FAILED` and the rest still run; providers are never substituted for one another.
- `modules/records_shared.py`: coverage notes, scope evidence lines, source statuses.
- `core/reports.py`: *Search scope and coverage* block (TXT/HTML/JSON); coverage parsed out of the notes.
- `main.py`: jurisdiction menu, state prompt with retry, availability screen (automated vs manual), search-method menu, coverage panel, manual-source screen (URL, auth, fees, record entry); History hides the machine-readable line.
- `README.md`, `CHANGELOG.md`, this report.

**Database:** unchanged schema. The coverage report is stored as one machine-readable line in `investigations.notes` (plus readable summary lines), source statuses in `sources.detail`, and scope / jurisdiction / provider / method / coverage in each finding's `evidence`; URLs and retrieval times use the existing columns. No migration; `schema_version` is asserted unchanged. Historical investigations are untouched and show coverage as `NOT RECORDED`.

## 17. Behaviour guarantees (all tested)

- Coverage is generated from execution. Planned providers without an outcome are `SKIPPED` ("Not run in this search"); unsupported kinds are `SKIPPED` with a reason (NSOPW + registry id); missing key / offline / 429 / 5xx are `UNAVAILABLE`; 401/403/malformed replies/exceptions are `FAILED`.
- "Nationwide" is described as a request in the CLI, notes and reports; the report says "NATIONWIDE REQUEST, not nationwide coverage" unless coverage is genuinely complete. No text claims all 50 states were searched.
- Zero records from a searched source keeps the mandated empty-result wording and adds the "not proof" note; a search where nothing ran says `NO_SEARCH_RAN`.
- Candidates are stored only after per-record operator confirmation; records are never merged by name (same name from two providers = two findings); court and registry findings keep separate categories; registry records still have no address fields.
- The GovInfo key was checked absent from coverage JSON, reports and error text.

## 18. Tests

| Run | Result |
|---|---|
| Before | 453 passed |
| After | **634 passed, 0 failed, 0 skipped** (453 + 181 new) |
| Updated existing | 7 CLI tests in `test_court_records.py` / `test_registry_intel.py` changed to the new prompt order (jurisdiction menu, state, method, term); assertions were not weakened |
| New coverage | all 50 abbreviations + DC (several casings each), all 50 full names (5 forms each), DC aliases, WA vs DC, VA vs WV, NFKC input, invalid/hostile input, near-miss hints, nationwide / state / federal discovery, no-provider states, mixed automated+manual (test doubles), partial/none/complete logic, provider failures (401/403/429/503/bad JSON/offline/exception), missing key, empty results, skipped providers, JSON round trip, court and registry integration, persistence, TXT/HTML/JSON reports, legacy investigations, offline operation, CLI (menu, retry, back, nationwide, federal, case number, no-provider state) |
| Isolation | The suite's guard confirmed the real database, log and reports were unchanged |
| Not done | No live search of any person; GovInfo not re-tested live in this part; registry automated providers exist only as test doubles; no human interactive session (one piped real-process run of menu 17 in a temporary home rendered correctly) |

`pip check`: clean. No dependencies added.

## 19. Known limitations

- Selecting a state does not mean searching it: 50 of 51 jurisdictions have no state provider, and the only automated source is federal opinions via GovInfo (name-matching full text, no statuses, requires a key).
- NC portals remain unverified (HTTP 403 / unreadable form); county sources are not catalogued. I did not research the other states' court or registry sites in this part, so none are listed (a guessed URL would be worse than a stated gap). NSOPW is the only route to other states' registries, and it is manual.
- The coverage report lives in a notes line rather than its own table to honour "preserve the existing database architecture"; if that line is hand-edited away, reports show `NOT RECORDED`.
- In a state scope the registry module also lists NSOPW (a national portal) while the court module does not list federal courts; this follows the "federal is a separate jurisdiction" rule, and NSOPW is how an operator would search that state's registry anyway.
- `Washington` means the state; the District needs `DC` or `Washington DC`.
- Menu numbering (16, 17) is unchanged and non-contiguous.

## 20. Readiness

**WARNING - the jurisdiction workflow is complete and honest; nationwide automated coverage does not exist.** Adding a state is now data entry (an `OfficialSource` with a verified agency URL and method) and appears in selection, discovery and coverage automatically. Phase 9 has not been started.
