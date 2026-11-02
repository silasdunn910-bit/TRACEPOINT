# TRACEPOINT v1.0.1 - AUDIT-REPAIR

Status: Phase 1 (audit) complete. Phases 2-5 pending.

## Environment facts
- Real project root: `C:\Users\administrators1\Desktop\VALORIS\TRACEPOINT`.
  `C:\Users\administrators1\Desktop\TRACEPOINT` and `C:\Projects\TRACEPOINT` do not exist.
- Python 3.11.9 in `.venv`. pytest was missing from the venv; installed it (dev only, not yet in requirements).
- Baseline: 47 tests pass (`tests/`: audit, fixes, name_intel, phone_intel).
- DB `data/tracepoint.db`: integrity_check ok, foreign_key_check clean, 14 tables. Not modified.

## Findings (Phase 1)
| # | Sev | Finding | Planned fix |
|---|-----|---------|-------------|
| 1 | High | Report path inconsistency root cause: `reports` table rows 1-3 store stale absolute paths `C:\Projects\TRACEPOINT\reports\...`. Code itself already uses `core.configuration.ROOT` (pathlib), so new reports are written correctly. | Store paths relative to REPORTS_DIR (or resolve by filename) on read; backward-compatible repair of display, no row deletion. Add test that report files exist and reopen. |
| 2 | Med | No `requirements-dev.txt`; pytest absent from venv. | Add dev requirements. |
| 3 | Med | Provider layer exists (`providers/search_providers.py`, `core/search_engine.py`, `providers/name_search.py`): not yet verified for Brave/Google CSE/SearXNG, retry/backoff, rate limit, "no silent fallback". | Phase 2 review. |
| 4 | Med | Evidence taxonomy requested (VERIFIED/CORROBORATED/MODERATE/LOW/UNVERIFIED/INCONCLUSIVE) not yet compared to `core/models.py`; username statuses (BLOCKED/ERROR) not yet verified. | Phase 2 review. |
| 5 | Info | Prior audits (AUDIT.md, AUDIT-R2.md) already fixed: anti-bot false-positive in username, DNS failure treated as absence, launcher PID. Not re-done. | Preserve. |
| 6 | Info | Not yet inspected: email/phone/ip/domain/social/security modules, correlation, ai.py, api_config UI, menus. | Phases 2-4, targeted reads. |

## Not yet verified (no claims made)
API validation, HIBP, AbuseIPDB/VirusTotal/IPinfo/OpenCorporates, Ollama detection, DNSSEC, HTML escaping in reports.

## Phase 2 (done)
- Evidence taxonomy: added CORROBORATED + INCONCLUSIVE; STRONG kept as legacy alias, normalised at read time (core/models.py, reports.py, ui/render.py, ui/theme.py, database.py ordering). Stored rows untouched.
- Username: 401/403/429/challenge -> `blocked`, 5xx -> `error`; both yield INCONCLUSIVE findings, never "not found".
- Report paths: new rows store file name only; `Database.reports()` resolves against REPORTS_DIR and reports `exists`. Stale `C:\Projects\...` rows resolve correctly without modification (verified on a copy of the real DB; all 3 files exist).
- Tests: tests/test_phase2.py (+1 updated test in test_fixes.py). Full suite: 52 passed, 0 failed.
- Deferred to Phase 4: search-provider review (Brave/Google/SearXNG, backoff), SOURCE status `blocked`, other modules.

## Phase 3 (verification + search-infrastructure review; no search changes made)
Verified: 53 tests pass (52 + new blocked-source test). Real DB: 14 user-created investigations (last 06:11 EST), stale report paths and STRONG rows intact, integrity ok.
Fixed: username per-source status `blocked` (was `error`); theme/render/report handle it; `requirements-dev.txt` added (pytest).

### Search infrastructure findings (to fix in Phase 4)
Implemented and reasonable: Brave (header token, count capped), Google CSE (key+cx, num<=10, published date), SearXNG (JSON), DuckDuckGo HTML fallback; shared http client has timeout, per-host 0.35s throttle, retry+exponential backoff honoring Retry-After (max 3); results normalized/deduplicated by tracking-stripped URL, non-http(s) skipped, failures recorded as source errors; secrets DPAPI-encrypted, masked in UI, log redaction filter.
Gaps:
1. Retry only 429/5xx/timeouts, applied with retries=2 for search; but 401/403 and Google 403 (quota/key) are all a generic "HTTP n"; only Brave distinguishes key vs rate limit. Google 429/quota and SearXNG 403 not distinguished.
2. `r.json()` is unguarded in all providers (non-JSON -> ValueError); caught only by the generic catch-all in search_engine, producing a "ValueError" message rather than a provider-specific one.
3. Fallback: DuckDuckGo is silently dropped whenever any keyed provider is configured, and if ALL keyed providers fail there is NO fallback and no explicit "all providers failed" signal; an empty-result list is indistinguishable from "searched, nothing found" except via source records. Name/other modules must check sources (not verified yet).
4. DuckDuckGo 202 (observed) is treated as ProviderUnavailable (good) but retries=2 on a POST that returns 202 is not retried; fine, but message should name the HTTP code (it does).
5. No availability/credential validation: "configured" = stored, not tested. API Config UI shows "● configured" with no connectivity or key check. No per-provider rate limit beyond host throttle; no quota awareness.
6. SearXNG URL is not validated (scheme/host); Google key is passed in the query string (Google API requirement) - redaction filter covers `key=` and `cx=` in logs; HTTP errors never include the URL, good.
7. Search queries run in parallel across providers with a 4-thread pool; same-host throttle is global lock-protected, OK.
8. `ALL_PROVIDERS` instances call get_db() on every `configured()`/search; SearXNG `requires_key=True` is semantically odd (URL, not key).
9. api_config: 'd N' deletion has no confirmation; empty value silently ignored with no message; secrets only masked by first/last 3 chars (fine for long keys, reveals 6 of 9+ chars for short ones).

## Phase 4 (done): search infrastructure + API configuration
- providers/search_providers.py: classified ProviderError kinds (INVALID_KEY, INVALID_CONFIG, RATE_LIMIT, QUOTA_EXHAUSTED, ACCESS_DENIED, SERVER_ERROR, INVALID_RESPONSE, TIMEOUT, UNAVAILABLE); guarded JSON parsing; Google error-body classification; DuckDuckGo genuine "no results" page treated as a completed search; `validate_searxng_url`; `test_connection()` (single request, no retries).
- core/search_engine.py: `search()` returns `SearchResults` (list + `completed`, `attempts`, `fallback_used`). Configured keyed providers first; DuckDuckGo only as a labelled fallback when ALL fail (or as default when none configured). `provider_status()` reports CONFIGURED until a test succeeds after the last credential change; `check_provider()` persists test outcome (no secrets) in settings.
- core/credentials.py (new): validation, save, confirmed delete. main.py API Configuration: status column, `t` to test, delete confirmation, clear rejection messages.
- providers/name_search.py + modules/name_intel.py: exact missing-config message; "search could not be completed" (error) vs "completed with zero results" (note); stops after 2 consecutive failed queries.
- Tests: tests/test_phase4.py (38). Full suite 91 passed.
- Not live-tested: no real Brave/Google/SearXNG calls were made (mocked only). Non-search integrations (IPinfo, AbuseIPDB, VirusTotal, HIBP, OpenCorporates) show "CONFIGURED (no test available)" - Phase 5/remaining.

## Phase 5 (final integration audit)
Verified: 119 offline tests pass (0 fail). pyflakes: no errors; 13 cosmetic warnings (unused imports, 2 f-strings without placeholders, 1 unused local in security_intel) left unchanged on purpose. Real DB unchanged: 14 investigations, 98 findings, integrity ok; migration verified on a copy.
Menus: all 15 options + invalid option exercised in a scratch copy of the app (scripted input, no tracebacks); real DB untouched.
Fixed this phase: Relationship Explorer treated gmail.com / Google MX hosts as "shared entities" (now flagged generic and hidden with an explanation); Email/Username/Phone now distinguish completed zero-result searches from searches that never ran; HIBP 401/429/5xx/unreadable replies are errors ("breach status unknown"), not clean results; Ollama status/analysis tolerate unexpected replies and refuse to save empty output; VERSION set to 1.0.1.
Live testing: none. No search/threat-intel keys are configured, so no provider connection test was possible. Ollama at 127.0.0.1:11434 was offline (offline path verified live; online path mocked only).
Known gaps: Domain/IP/Social/Security modules were not re-audited in depth this phase (DNSSEC, certificate dedupe, AbuseIPDB/VirusTotal quota handling, geolocation conflicts, social link extraction are NOT implemented/verified); phone carrier enrichment and national-format edge cases not re-verified; no connection tests for IPinfo/AbuseIPDB/VirusTotal/HIBP/OpenCorporates; Name Intelligence privacy filters rely on regexes.
