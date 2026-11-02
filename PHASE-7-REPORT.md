# TRACEPOINT Phase 7 - Production Hardening & Security Audit

Branch `phase-6-integration` (continued; Phase 7 commit on top of `d0502fa`). Not pushed.
Date: 2026-11-02. Interpreter: project `.venv` (Python 3.11.9). Tests: **133 passed** (122 at Phase 6 + 11 new).

## 0. Method and limits

- All write/destructive/behaviour tests ran in **copies** (`scratchpad\sandbox` with a copy of the real database; `scratchpad\clean` and `scratchpad\clean dir (test)` for clean installs, built from `git archive`). The real database was never opened for writing. Read-only counts before and after Phase 7: 14 investigations, 98 findings, 30 entities, 29 relationships, 3 reports. No investigations were deleted (deletion was exercised only on a copy, in Phase 6).
- No credentials exist in this installation, so keyed providers (Brave, Google, SearXNG, HIBP, VirusTotal) and Ollama analysis were **not** exercised live. Secret handling was tested with a synthetic sentinel value.
- Network tests used only public example/synthetic targets, a local listener I started myself, and public sites for probes of a nonexistent handle. Nothing was tested against systems I am not authorised to touch.
- Phase 6 starting state reviewed: it passed its own checks, but left open R1, R3, R4, R5, R7-R10 from the regression audit and the duplicate-report-rows item. They are carried into section 7; none is a security issue.

## 1. Security findings

| # | Area | Result | Evidence |
|---|---|---|---|
| S1 | Credential encryption (DPAPI) | **PASS** | Stored as `dpapi:...` blobs with per-app entropy; round trip works; sentinel secret absent in plaintext from every file in the tree (DB, reports in all 3 formats, logs) |
| S2 | Secrets in reports/exports | **PASS** | Same sentinel scan after generating HTML/JSON/TXT |
| S3 | SQL injection | **PASS** | All values parameterised. The only f-string SQL builds `?` placeholder lists or a fixed `CASE` clause; `executescript` runs constants only |
| S4 | Command execution | **PASS** | No `subprocess`, `os.system`, `eval`, `exec`, `pickle`, `shell=True` in application code |
| S5 | TLS verification | **PASS** | No `verify=False` anywhere; `requests` defaults apply |
| S6 | Report HTML injection | **PASS** | `<script>`, `<img onerror>` and `javascript:` hrefs in target/finding/URL fields were escaped or neutralised |
| S7 | Path traversal | **PASS** | Report file names derive from generated refs; stored report paths are reduced to a file name before resolving |
| S8 | Input validation | **PASS** | Control characters stripped, 512-character cap, credential and SearXNG URL validation (tests exist) |
| S9 | User-supplied URL fetch (Social module) | **FAIL -> fixed (D2)** | A local listener received `/robots.txt`, the profile path and the redirect target `/internal-secret`: loopback/internal services were reachable, including through redirects |
| S10 | Sensitive data in logs | **FAIL -> fixed (D3)** | Request log included URL paths, which carry the usernames/handles being investigated (e.g. `www.kaggle.com/<handle>`). No keys or query strings were logged |
| S11 | Dependency vulnerabilities | **PASS (point in time)** | `pip-audit -r requirements.txt` in a throwaway venv: no known vulnerabilities |
| S12 | Dependency pinning | **WARNING** | `requirements.txt` uses `>=` only; builds are not reproducible and a future release could break or be compromised. No lock file |
| S13 | File permissions / data exposure | **WARNING** | `data\` inherits `BUILTIN\Users:(M)` on this machine, so other local accounts can read investigation data (credentials stay DPAPI-protected). Not changed on the real tree; a documented `icacls` command is in the README |
| S14 | `mask()` helper | **WARNING** | Shows 3+3 characters of credentials longer than 8 characters (6 of 9); not currently used to display full secrets. Not changed |
| S15 | DNS-rebinding on the public-only fetch | **WARNING** | The address check resolves the host before the request; a hostile resolver could answer differently at connect time. Not mitigated |
| S16 | DPAPI across users/machines | **NOT TESTED** | Only the current user was available |
| S17 | Live TLS interception / certificate failure | **NOT TESTED** | Code review only (defaults) |

## 2. Reliability findings

| # | Area | Result | Evidence |
|---|---|---|---|
| R-1 | Failed save leaves partial data | **FAIL -> fixed (D1)** | Injected mid-save error: the investigation row persisted, and a later unrelated commit would keep it |
| R-2 | A failing screen ends the session | **FAIL -> fixed (D4)** | Any error in a menu action (e.g. report write error) propagated out of `main()` |
| R-3 | Ctrl-C during an investigation | **FAIL -> fixed (D5)** | It exited the whole app; now returns to the menu; nothing is saved (saving happens only after the module finishes) |
| R-4 | Provider failure, timeouts, retries, 429/5xx, malformed or non-JSON replies | **PASS** | Covered by the Phase 4/5 tests and the regression audit probes (fallback chain, `Retry-After` cap, classified errors); suite green |
| R-5 | Missing configuration | **PASS** | Name Intelligence reports "no provider configured"; AI offline degrades cleanly |
| R-6 | Offline operation | **PASS (partial)** | With name resolution disabled for the `requests` path, all 8 modules completed without exceptions (1-9 s each, errors listed). DNS lookups through dnspython still used the network, so this was not a fully air-gapped test |
| R-7 | Database error handling | **PASS** | Integrity and foreign-key checks clean; atomic save now guaranteed (D1) |
| R-8 | Report generation failure | **PASS after D4** | Handled by the new guard; the partial file behaviour of a half-written report was not examined |
| R-9 | Very large graphs | **WARNING** | Graph helpers pass entity ids as SQL parameters; SQLite's variable limit would be hit by tens of thousands of ids. Not reproduced |

## 3. Performance (this machine; synthetic data in a copy)

| Measure | Result |
|---|---|
| `import main` | 0.41-0.57 s, ~159 MB working set after import |
| Start to exit (menu render + Exit), before fix | 2.6 s (2.0 s was the Ollama offline probe) |
| Banner Ollama probe | 2.04 s per redraw when offline (Windows refused-connection delay). **Fixed (D6)**: cached 30 s, so only the first draw pays it |
| Database with 525 investigations / 20,252 findings | list 50: <1 ms; stats 4 ms; shared entities 4 ms; whole-DB graph 9 ms; entity search <1 ms |
| One investigation with 5,000 findings | save 0.03 s; HTML 0.075 s (3.3 MB), JSON 0.089 s, TXT 0.048 s; terminal panel 0.05 s |
| Peak working set after 5,000-finding reports | ~190 MB |
| Search response time | **NOT TESTED** with a real provider; provider-less runs: DuckDuckGo challenge pages return in ~1-2 s, offline module runs 1-9 s |

Only the banner probe was a demonstrated bottleneck; nothing else was optimised.

## 4. Windows deployment

| # | Check | Result |
|---|---|---|
| W1 | Clean install from the committed tree (`INSTALL.ps1`) | **PASS** - 27.6 s, schema v2 created, app starts |
| W2 | `START TRACEPOINT.bat` first run in a path with spaces and parentheses (no `.venv`) | **PASS** - installs, initialises the database, starts, exits |
| W3 | Launchers use the intended interpreter | **PASS** - all use `.venv\Scripts\python.exe` (bare `python` is used only to create the venv) |
| W4 | Launcher with a missing dependency | **FAIL -> fixed (D7)** - under `$ErrorActionPreference = "Stop"` the `2>$null` probe aborted the script instead of reinstalling; after the fix it reinstalls and starts |
| W5 | First-run setup (folders, `config\.env`) | **PASS** |
| W6 | Relative/absolute paths | **PASS** - everything resolves from the app root; moved installs work (history rows resolve by file name) |
| W7 | Python older than 3.10, no network during install, stale lock handling, `STOP.ps1` | **NOT TESTED** (stale lock/STOP only reviewed by reading) |

## 5. Privacy and data protection

| # | Check | Result |
|---|---|---|
| P1 | Credentials never in reports | **PASS** (S2) |
| P2 | Sensitive data in logs | **PASS after D3**; the existing log file still contains older path-bearing lines (not rewritten) |
| P3 | Investigation history preserved | **PASS** - real DB unchanged; no migration run; no deletions |
| P4 | Exports contain only intended data | **PASS (partial)** - reports include investigation data, sources and notes, plus the AI summary if present; no settings or secrets |
| P5 | Backup/recovery documented | **PASS after D8** - README section added (backup, restore, integrity check, key re-entry) |
| P6 | Test hygiene | **WARNING** - the test suite writes to the real `logs\tracepoint.log` (e.g. `search.example` lines) |
| P7 | Name-to-DuckDuckGo fallback (R4) | **WARNING** - unchanged; needs the owner's decision |

## 6. Defects corrected

| ID | Defect | Smallest change | Regression test (`tests/test_phase7.py`) |
|---|---|---|---|
| D1 | `save_result` could leave a partial investigation that a later commit persisted | `save_result` wraps `_save_result` and rolls back on any failure | `test_failed_save_leaves_no_partial_investigation` |
| D2 | Social module could fetch loopback/private/link-local hosts, including via redirects | `http.request(public_only=True)` checks scheme and resolved addresses on every hop (manual redirects, max 5); used for the Social robots.txt and page fetches | `test_public_only_refuses_loopback`, `..._non_http_and_link_local` (3 cases), `..._checks_every_redirect_hop`, `test_social_module_does_not_touch_local_services` |
| D3 | Request log contained URL paths (investigated handles) | Log host and status only | `test_request_log_does_not_contain_url_path` |
| D4 | Any exception in a menu action ended the session | `_run_choice` plus a guard in `main()` that prints the error and returns to the menu | `test_failing_screen_does_not_end_the_session` |
| D5 | Ctrl-C during an investigation exited the app | `run_and_show` catches `KeyboardInterrupt`, nothing saved | `test_keyboard_interrupt_returns_to_menu_without_saving` |
| D6 | Offline Ollama probe added ~2 s to every menu redraw | 30 s cache for the banner only | `test_banner_ai_status_is_cached` |
| D7 | `TRACEPOINT.ps1` aborted instead of reinstalling missing dependencies | Probe runs with `Continue` error preference | Manual (removed `phonenumbers` in a clean install, relaunched, it reinstalled); no automated test |
| D8 | No restore/backup/access-control documentation | README section "Backup, recovery and data protection" | n/a |

The new tests that touch `main.py` were confirmed to fail without the fix (D4/D5 aborted pytest with `KeyboardInterrupt`). I did not run every other new test against the unfixed code. Existing behaviour is otherwise unchanged; D3 is a deliberate reduction in log detail.

## 7. Remaining limitations

- Live provider behaviour (Brave, Google CSE, SearXNG, HIBP, VirusTotal, Ollama analysis) is unverified; web search here depends on an unreliable DuckDuckGo fallback.
- Regression-audit items still open: R1 (old-signature custom providers), R3 (worst-case search latency about 75 s), R5 (DuckDuckGo "no results" detection), R7 (generic exceptions drop their cause), R8-R10 (cosmetic), and repeated report rows in the Reports list.
- Unpinned dependencies (S12), local-user read access to `data\` (S13), DNS rebinding (S15), `mask()` reveal (S14).
- Reverse-DNS lookups time out on this network; Reddit returns 403; some status-only username platforms may still use soft 404s (from AUDIT-R2).

## 8. Unresolved release blockers

For distribution to **external users**, I would treat these as blockers until addressed or explicitly accepted by the owner:

1. **R4 decision**: whether a person's name may be sent to DuckDuckGo when a configured provider fails.
2. **Reproducible installs**: pin or lock dependencies (S12).
3. **Live verification** of at least one keyed search provider and the HIBP path with real credentials (not done).

Not blockers on their own: S13-S15, R3, R5, R7.

## 9. Overall readiness assessment

**Not yet ready to be called production-ready.** The code paths examined are in good shape: no injection or command-execution surface was found, secrets stay encrypted and out of reports and logs, clean install works (including from a path with spaces), performance is comfortable at 20,000+ findings, and eight confirmed defects were fixed with tests. The evidence is limited, though: live provider behaviour, cross-user/machine credential handling, and a fully air-gapped run were not tested, and the three blockers above are open. A reasonable label today is "hardened release candidate for a trusted, single-user Windows setup".

Phase 8 has not been started.
