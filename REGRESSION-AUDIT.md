# TRACEPOINT 1.0.1 - Regression Audit (after Phases 1-5)

Date: 2026-11-02. No application file was modified for this audit. The temporary probes live outside the project (session scratchpad, `regress/test_regress.py`, `regress/test_regress2.py`) and ran against mocks or a copy of the database.

## 1. Method and limits (read first)

- **No Git history exists.** The baseline is therefore approximate:
  - `tracepoint-postfix-20261102-022101.zip` (02:21, full source, before the Name/Phone work).
  - `backups/name-intelligence-pre-20261102` and `backups/phone-intelligence-r1.1-pre-20261102` (partial: 8 and 6 files).
  - The code I read in this session before editing (search providers, search engine, name search).
- Files that differ from the 02:21 snapshot include work done by earlier sessions (Name and Phone intelligence, HTTP retry) as well as my Phases 2-5. I attribute changes only where I know I made them; "original behavior" below means the code as it stood when this session started.
- Structural comparison (AST inventory of every function, class and constant): **no function, class or constant present in the 02:21 snapshot was removed.** The only disappearance is an inner helper `run` in `search_engine.search`, replaced by `_run`/`process`, and one renamed test.
- Hash comparison: `modules/domain_intel.py`, `ip_intel.py`, `social_intel.py`, `security_intel.py`, `core/security.py`, `providers/domain_providers.py`, `providers/ip_providers.py` and `tests/test_audit.py` are byte-identical to the 02:21 snapshot. They cannot have regressed from my work. They also received none of the Phase 1 improvements for Domain/IP/Social/Security (DNSSEC, certificate dedupe, etc.); that is a gap, not a regression.
- Test status at audit time: existing suite **119 passed, 0 failed**. Temporary probes: **33 run, 32 passed, 1 failed** (finding R1).
- Real database after all probes: 14 investigations, 98 findings, integrity ok, mtime unchanged (06:12).

## 2. Findings

### R1 - Low - Custom providers with the old `search(query, limit)` signature are mis-reported by the connection test
- **Original:** `SearchProvider.search(self, query, limit=10)`; subclasses implemented exactly that.
- **Current:** base signature is `search(self, query, limit=10, retries=2)`; `test_connection()` calls `self.search(..., retries=0)`.
- **Where:** `providers/search_providers.py`, `SearchProvider.test_connection`.
- **Evidence:** probe `test_old_style_provider_without_retries_kwarg_still_searchable`. The normal `search_engine.search` path works for an old-style provider; `test_connection()` returns `UNAVAILABLE / INVALID_RESPONSE ("TypeError while testing")` for a healthy provider.
- **Impact:** only third-party subclasses (none in the repo; the module docstring invites them). All four built-in providers are updated.
- **Fix:** inspect the signature, or catch `TypeError` and retry without `retries`; keep `ProviderUnavailable` as the documented base.

### R2 - Medium - The CORROBORATED label is now attached to single-source findings (evidence standard)
- **Original:** `STRONG` ("multiple independent, credible sources agree"), emitted by `ip_intel` for provider-agreeing geolocation, by `security_intel` for domain age under 30 days (one RDAP record) and for VirusTotal with 3+ malicious verdicts (one provider).
- **Current:** `models.STRONG` is an alias of `CORROBORATED`, so those findings are stored and displayed as `CORROBORATED` ("supported by multiple independent sources").
- **Where:** `core/models.py` (alias); `modules/security_intel.py:105` and `:156`; `modules/ip_intel.py:113`.
- **Evidence:** code inspection. The two security cases rest on one source each; geolocation agreement may share an upstream data source. The same overclaim existed under the old name, but the rename to the stricter-sounding term (and its definition in the report) makes it more visible and arguably wrong.
- **Fix:** regrade single-source findings (domain age: VERIFIED as a fact with a "risk indicator, not malicious" limitation, or MODERATE; VirusTotal: MODERATE). Keep CORROBORATED only where independent sources are actually compared. Not changed in this audit; the modules are outside the repaired set.

### R3 - Medium - Worst-case search latency roughly doubled by the fallback chain
- **Original:** keyed providers only; at most 3 attempts x 12 s timeout plus 1.5 s backoff, about 37 s per query.
- **Current:** if every keyed provider times out, DuckDuckGo is tried as well: about 75 s per query. Name Intelligence stops after 2 consecutive failed queries (about 150 s). Username, email and phone each run one or more queries.
- **Where:** `core/search_engine.search`; `core/http.request` (`retries`, `DEFAULT_TIMEOUT = 12`).
- **Evidence:** probe `test_worst_case_latency_budget` showed backoff sleeps `[0.5, 1.0, 0.5, 1.0]`, i.e. 3 attempts for the keyed provider and 3 for DuckDuckGo; with a 12 s timeout that is 6 x 12 s + 3 s.
- **Fix:** an overall per-query deadline, and fewer retries (or a shorter timeout) for the fallback.

### R4 - Medium (intended behavior change, needs your confirmation) - Name Intelligence can now send the name to DuckDuckGo
- **Original:** with no keyed provider, Name Intelligence returned "not configured"; it never queried DuckDuckGo. With keyed providers failing, it returned nothing.
- **Current:** if all keyed providers fail, `search_engine.search` falls back to DuckDuckGo and Name Intelligence builds findings from those results.
- **Where:** `core/search_engine.search`; consumer `providers/name_search.search_name`.
- **Evidence:** probe `test_name_intel_uses_ddg_when_keyed_provider_fails`: Brave 401 + DuckDuckGo OK produced findings with source `DuckDuckGo (HTML)` and recorded the Brave error.
- **Mitigations present:** results still pass `valid_result` (private-data filter); the provider is named on every finding; the source record says "fallback". Phase 4 requested the fallback.
- **Residual:** the person's name leaves the machine to a provider the user did not configure for this task; fallback results are less reliable. If that is not wanted, make the fallback opt-in for the `name` module.

### R5 - Low - DuckDuckGo "no results" detection loosens the "blocked is not zero" rule
- **Original:** a page without result markup always raised `ProviderUnavailable`.
- **Current:** such a page counts as a completed zero-result search if it contains `class="no-results"` or the text `No results.`.
- **Where:** `providers/search_providers.py`, `DuckDuckGoHTML.search`.
- **Evidence:** code inspection only (I did not obtain a real DuckDuckGo block page). A challenge page that happens to contain that phrase would be reported as zero results.
- **Fix:** require the specific element only, and keep the existing anomaly/challenge check first.

### R6 - Low - Per-finding confidence labels still show the legacy `STRONG` for 2 historical rows
- **Original:** `STRONG` everywhere.
- **Current:** summary counts and the report's conclusion say CORROBORATED, but the finding rows themselves keep the raw stored value `STRONG`, and the report's definitions list has no `STRONG` entry.
- **Where:** `core/reports.build` (rows copied raw), `ui/render.confidence_text` (used by `main.py:394`).
- **Evidence:** probe `test_legacy_strong_label_in_reports`: investigation TP-20261102-475FC5 has 2 raw `STRONG` findings; definitions keys are `CORROBORATED, INCONCLUSIVE, LOW, MODERATE, UNVERIFIED, VERIFIED`. Nothing crashes (all 14 investigations produced HTML, JSON and TXT).
- **Fix:** apply `normalize_confidence` when presenting rows (not when storing).

### R7 - Low - A generic provider exception no longer records its cause
- **Original:** `f"{type(e).__name__}: {e}"` in the source error and `result.errors`.
- **Current:** `"<provider>: unexpected <ExceptionType>"`; the message is dropped and nothing is logged.
- **Where:** `core/search_engine._run`.
- **Evidence:** code inspection; this made the R1 failure show only "TypeError while testing".
- **Fix:** log the full exception (with the existing redaction filter) to `logs/tracepoint.log`.

### R8 - Low - Credential entry is stricter than before
- **Original:** any non-empty value was stored.
- **Current:** minimum 6 characters, no whitespace, maximum 512, no control characters; the SearXNG URL is validated and normalized; the SearXNG URL is typed visibly (it is not a secret).
- **Where:** `core/credentials.validate_credential`, `main.api_config`.
- **Evidence:** `tests/test_phase4.py`. A legitimate short or space-containing token would now be rejected with a message. Existing stored credentials are untouched.
- **Fix:** none required; relax the 6-character floor if a provider uses shorter tokens.

### R9 - Low - Historical report rows are resolved by file name only
- **Original:** `reports()` returned the stored absolute path as-is.
- **Current:** only the file name is kept and resolved against `REPORTS_DIR`; new rows store only the file name; `reports()` returns dicts instead of `sqlite3.Row`.
- **Where:** `core/database.Database.reports`, `core/reports.save`.
- **Evidence:** the 3 historical rows (`C:\Projects\TRACEPOINT\reports\...`) resolve to existing files and are marked present; the stored rows are unchanged. A report that had been moved to another directory would show `[missing]`. The only consumer is `main.reports_menu`.
- **Fix:** none required.

### R10 - Low - Cosmetic or consistency items
- HIBP: a 200 response with unreadable JSON adds the error "breach status unknown" but the source record is still `ok` (`modules/email_intel.py`, source line).
- Phone: when only some number formats could be searched, a zero-result note can still claim "no matching pages" (`modules/phone_intel.py`, `searched_ok` only distinguishes none vs some).
- Name Intelligence repeats the same provider error once per query in `errors` (seen in the DuckDuckGo-fallback probe).

## 3. Checked and found preserved (evidence in brackets)

1. **SearchResult compatibility.** Fields, order, defaults and the `domain` property are identical; it serializes with `asdict` [probe `test_searchresult_shape_unchanged`]. `search()` still returns a real `list` subclass, so every consumer (email, phone, username, name search, `results_to_findings`) works; JSON-serializable [`test_search_returns_a_real_list_subclass`].
2. **Intelligence modules with the new engine.** Username, email, phone and name were run end to end through the real HTTP layer with mocks: findings from search hits stay LOW/UNVERIFIED, never VERIFIED; failed vs empty searches are distinguished [`test_username_module_with_failed_then_empty_search`, `test_email_module_integration`, `test_phone_module_integration`]. Domain, IP, Social and Security are unchanged files and do not call the search engine.
3. **Fallback.** DuckDuckGo is used after each of: 401, non-JSON 200, JSON list, wrong JSON shape, three timeouts, three connection errors, three 503s [7 parametrized probes]. It is not used when any keyed provider succeeds, even with zero results, and not when a second keyed provider succeeds [`test_two_keyed_providers_one_fails_other_results_kept_no_ddg`]. If DuckDuckGo also fails the search is reported as not completed, not as zero results [`test_fallback_ddg_also_failing_is_not_zero_results`].
4. **Retry, timeouts, rate limits, ordering** through the real `http.request`: 429 x2 then success (3 calls; `Retry-After` honored, then exponential backoff); retries exhausted gives a classified RATE_LIMIT; `Retry-After: 9999` is capped at 8 s; timeouts are retried then classified TIMEOUT; a connection test makes exactly 1 request even on 429; provider order is Brave, Google, SearXNG, DuckDuckGo [probes in `test_regress.py`].
5. **Evidence not more permissive.** For every username site and each of HTTP 401, 403, 429, 500, 502, 503 the result is `blocked` or `error`, never found or not found [parametrized probe]. Search hits are capped at LOW. INCONCLUSIVE ranks below UNVERIFIED. Unknown stored grades normalize to UNVERIFIED. Exception: R2.
6. **Database and reports.** On a copy of the real database all 14 investigations produced HTML, JSON and TXT reports with finding counts equal to the stored findings and summary counts that add up; legacy rows render in the terminal helper without error [`test_all_historical_investigations_report_in_all_formats`, `test_legacy_strong_rows_render_in_terminal_and_html`]. Schema is unchanged; the only new data are optional `settings` keys named `conn:<provider>` (none exist in the real database).
7. **Removed features.** None found (see section 1). `Database.reports()` changed type (R9) and the credential-entry rules changed (R8); both are intentional.

## 4. Not verified

- Behavior against live Brave, Google, SearXNG, DuckDuckGo, Have I Been Pwned or Ollama (no credentials configured; nothing was called live).
- A real DuckDuckGo block or "no results" page (R5).
- Anything in code that existed only between the 02:21 snapshot and the start of this session cannot be attributed with certainty without version control. Initialize Git now so future audits have an exact baseline.

## 5. Suggested order of fixes

1. R2 (evidence grading), 2. R4 (decide on the DuckDuckGo fallback for names), 3. R3 (deadline), 4. R5, R6, R7, R1, then R8-R10.
