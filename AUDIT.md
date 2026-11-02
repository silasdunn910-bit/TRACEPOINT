# TRACEPOINT — Technical Audit

> **Current update:** Name Intelligence implementation and regression results are recorded in the 2026-11-02 addendum at the end of this file. The original audit below is retained as historical context.

> **Follow-up:** the live Windows re-audit, additional fixes and 10 new regression tests are in
> `AUDIT-R2.md`. The project actually lives at `C:\Users\administrators1\Desktop\TRACEPOINT`
> (`C:\Projects\TRACEPOINT` does not exist). This file is kept as the original audit record.

**Date:** 2026-11-02 · **Target:** `C:\Projects\TRACEPOINT` · **Python tested:** 3.13 (container) / 3.11.9 (user's Windows)
**Method:** source inspection of every module + offline reproduction + a new regression test suite (`tests/test_audit.py`, 8 tests).

> **Honesty note on scope of testing.** I executed and verified everything that runs **offline** (DB, models, correlation, reports, graph export, credential round-trip via the non-Windows fallback, type detection, confidence labelling). I **could not execute on Windows from here**, so the following are verified **by code review only** and still need a confirming run on your machine: the **DPAPI** encrypt/decrypt round-trip, all **live-network** modules (DNS/RDAP/HTTP/search/Ollama), and the **PowerShell** scripts. These are called out explicitly in section D.

---

## A. Discovered issues

| # | Severity | Area | File | Issue | Reproduction |
|---|----------|------|------|-------|--------------|
| 1 | **High** | Finding counts / dedup | `core/models.py`, `core/database.py` | Reported finding count (in-memory list) could exceed stored count. The DB enforces `UNIQUE(investigation_id, fingerprint)` with `INSERT OR IGNORE`; two findings sharing `category\|title\|value\|source_url` (e.g. the same RDAP org appearing as both registrant and admin) collapse on save but were both counted live → **"11 reported, 10 on dashboard."** | `tests/test_audit.py::test_finding_count_live_matches_stored` reproduced 11 vs 10 before the fix. |
| 2 | **High** | Relationship Explorer / graph export | `main.py`, `core/correlation.py` | After an entity search, the UI called `show_graph(None)`, rendering and offering to export the **entire-database** graph regardless of the search. Searching "Silas Dunn" therefore showed the existing full graph, not a filtered result. Exports never reflected the selection. | Menu 9 → search any term → whole-DB graph shown/exported. |
| 3 | **Medium** | Relationship Explorer UX | `main.py` | Shared-entity **correlation** (entities in ≥2 investigations) and ordinary **substring entity search** were printed back-to-back with no labelling, so they looked like one feature. | Menu 9 — two unlabelled lists. |
| 4 | **High (latent)** | Credential storage / DPAPI | `core/security.py` | (a) The `create_string_buffer` backing each `DATA_BLOB` was created inside `_blob()` and not kept referenced for the Win32 call — especially the inline `byref(_blob(data))` — a use-after-free / garbage-read risk. (b) `argtypes`/`restype` were undeclared, so on 64-bit Python return/pointer values can be truncated. Could corrupt or fail credential encryption intermittently. | Code review; not reproducible offline (Windows-only path). |
| 5 | **Low** | History accuracy | `main.py`, `core/database.py` | Universal Search wrote a `search_history` row itself **and** `save_result()` wrote another → every universal search double-counted in history. | Menu 8 → run → two rows in `search_history`. |
| 6 | **Medium** | Username false positives | `modules/username_intel.py` | Most sites use JSON APIs that 404 correctly, but `Linktree` and `about.me` are checked by plain HTTP status on hosts that serve **soft-404s with HTTP 200**, yielding a `VERIFIED` "profile exists" that may be false. | Code review (needs live confirmation). |
| 7 | **Low** | Dead code | `core/database.py` | `image_hashes` / `document_meta` tables and their helpers remain after the image/document modules were removed; unused but harmless. | Grep. |

No issues found that fabricate findings, over-state confidence on search hits (verified: search hits are only `LOW`/`UNVERIFIED`), treat network geo as physical location (all geo findings carry the network-geolocation limitation), or merge identities on matching handles (username matches are `SHARES_ID`, never ownership).

---

## B. Prioritized fix list

- **Critical:** none.
- **High:** #1 finding-count dedup · #2 filtered-graph export · #4 DPAPI memory-safety.
- **Medium:** #3 explorer labelling · #6 username soft-404 false positives.
- **Low:** #5 double history logging · #7 dead tables.

---

## C. Incomplete / untested features

- **AI analyst (Ollama)** — code complete; needs a machine with Ollama + a model to confirm end-to-end (offline: status() degrades correctly).
- **Live-network modules** (email/domain/IP DNS·RDAP·CT·search, username platform checks, social fetch, security reputation) — logic verified, each lookup needs a real run on your network. The sandbox blocks outbound DNS/HTTP, so these were not exercised live here.
- **DPAPI round-trip** — verified by review; confirm on Windows by storing then re-reading a key (menu 12).
- **PowerShell scripts** — verified by review and the Python install/verify steps they invoke were run in a clean venv; the `.ps1` control flow itself was not executed here.
- **Username #6** sites (Linktree/about.me) — flagged, not yet changed (see F).
- **Reverse-image / document modules** — intentionally removed earlier; not present.

---

## D. Test report (`tests/test_audit.py`)

Run: `python -m pytest tests/ -v`  or  `python tests/test_audit.py`

| Test | Result | Notes |
|------|--------|-------|
| test_finding_count_live_matches_stored | **PASS** (after fix) | reproduced 11≠10 before fix |
| test_filtered_graph_export_contains_only_selected | **PASS** | other investigations no longer leak into export |
| test_whole_graph_still_available | **PASS** | whole-DB graph still works when asked for |
| test_shared_vs_search_are_distinct | **PASS** | shared-entity vs search are separate queries |
| test_detect_type | **PASS** | email/ip/ipv6/domain/social/phone/name |
| test_search_hits_never_verified | **PASS** | search hits only LOW/UNVERIFIED |
| test_secret_roundtrip_and_masking | **PASS** | **non-Windows fallback only**; DPAPI path needs Windows |
| test_persistence_and_delete | **PASS** | records persist; orphan entities cleaned on delete |

**8 passed, 0 failed.** Could-not-run here: DPAPI round-trip, live-network lookups, PowerShell execution (environment has no Windows/DPAPI and no outbound network).

---

## E. Fixes applied (isolated, no rebuilds)

1. **#1** `core/models.py`: added `ModuleResult.dedupe()`; `core/investigation.py` calls it before display+save so the reported count always equals the stored count.
2. **#2** `core/correlation.py`: added `graph_json_for_entities(entity_ids, include_neighbors)` and extended `export_graph(..., entity_ids=...)` to export exactly the selected subgraph. `main.py` explorer now renders/export the **filtered** graph after a search.
3. **#3** `main.py`: explorer split into labelled **"A · SHARED ENTITIES"** and **"B · ENTITY SEARCH"**; whole-DB graph is now opt-in only.
4. **#4** `core/security.py`: `_mkblob()` returns and the callers retain the backing buffer for the call's lifetime; `argtypes`/`restype` declared; DLLs loaded with `use_last_error=True` and errors report the real code.
5. **#5** `main.py`: Universal Search no longer writes its own `search_history` row for runnable types (`save_result` is the sole writer); it logs only when no investigation runs.

No database schema or stored data was changed; existing investigation records are preserved. No working module was removed or rewritten.

---

## F. Final report — remaining unresolved

- **#6 (username soft-404)** — **documented, not changed.** Switching Linktree/about.me to content-marker checks needs live verification of each site's non-existent-profile response, which I can't do from here without risking new false negatives. Recommendation: verify on your machine, then add a `text_absent` marker per site. Everything else about username checks is sound (JSON-API sites 404 correctly; matches are labelled `SHARES_ID`, never ownership).
- **#7 (dead tables)** — left in place deliberately; removing them is a schema migration with no functional benefit and some risk. Safe to leave.
- **DPAPI / network / PowerShell** — fixes and logic are in; please confirm with one real run (`.\STATUS.ps1`, store a key in menu 12, run a domain/IP investigation, and an Ollama analysis if installed).

All changes are confined to the five files above plus the new `tests/` and this report.

---

## G. Name Intelligence implementation (2026-11-02)

Implemented an authorized, bounded name-search workflow integrated with the existing investigation runner, shared configured search providers, SQLite persistence, Rich terminal UI, and TXT/JSON/HTML reports.

- Added `modules/name_intel.py`, `modules/name_matching.py`, and `providers/name_search.py`.
- Added Name Intelligence to menu 8 and routed names detected by Universal Search into its context and authorization screen. Existing identifier routes continue to use their original modules.
- Name queries include exact phrases, optional context, professional biography, organization, news, institutional, and conservative spelling variants. Searches use configured Brave, Google Programmable Search, or SearXNG only; the name module does not use the legacy HTML fallback and does not fetch result pages.
- Results are normalized and de-duplicated by canonical URL. Snippets remain leads and are labeled `LOW` only when the name is visible; other results remain `UNVERIFIED`. Candidate pages are not merged and no person entity is written to the globally de-duplicated entity table.
- Added an additive database v2 migration for query, source type, and publication date. Existing records and investigation IDs remain intact; source URLs and retrieval times use the existing fields. Provider publication metadata is preserved when available and otherwise remains unknown.
- Analyst-assigned claims can be checked for conflicts and repeated values across distinct source domains. These comparisons do not establish identity and are marked unverified pending manual source review.
- Added metadata screening for contact details, likely street addresses, relatives, and named sensitive attributes. Search results containing these patterns are omitted. No source-page crawling or identity enrichment is performed.
- Updated `README.md` and added 13 offline regression cases covering normalization, URL de-duplication, distinct same-name candidates, corroboration, contradictions, unknown publication dates, unavailable/failed providers, invalid results, migration and persistence, authorization, and report exports.

**Verification executed in the project virtual environment:** existing `test_audit.py` 8 passed; existing `test_fixes.py` 14 passed; new `test_name_intel.py` 13 passed; Python `compileall` completed without errors. The suite was run directly because `pytest` is not installed in that virtual environment. No live provider request was made; configured-key behavior, network availability, provider terms for a particular account, and results from live sources remain unverified.

**Remaining limitations:** search results and snippets vary by provider and may omit publication dates; page text is not fetched or independently verified. The analyst must verify sources and assign claim candidate IDs. The available dependency-free registrable-domain helper handles common two-level suffixes only, so domain independence is a conservative heuristic. The terminal app offers an overall search spinner and result/source views, not per-query live progress. Search providers must be configured before use.
