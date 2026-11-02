# TRACEPOINT Phase 6 - Integration & System Verification Report

Branch `phase-6-integration` (from `main` at `e5e8c9d`). Not pushed.
Date: 2026-11-02. Interpreter: project `.venv` (Python 3.11.9).

## 0. Scope and limits (read first)

- The Phase 6 prompt was truncated: only Step 1 and the general objective/rules were received. Steps 2-9 were **not** seen; this report covers the verification I derived from the stated objective (modules, providers, database, reports, configuration, interfaces). If Steps 2-9 contained other checks, they are not covered here.
- All destructive and write testing ran in a **copy of the project** (`scratchpad\sandbox`, including a copy of `data\tracepoint.db`). The real database was never opened for writing. Read-only count after the work: 14 investigations, 98 findings, 30 entities, 29 relationships, 3 reports - same as the copy at start.
- Live network was used by the sandbox runs (public sites for synthetic targets only). No search provider or HIBP/VirusTotal/Ollama credentials are configured, so keyed providers and AI analysis were **not** exercised live.

## 1. Baseline

| Check | Result |
|---|---|
| Branch / tree | `main`, clean; `e5e8c9d` exists; `phase-6-integration` created |
| Environment | `.venv` Python 3.11.9; `pip check` clean; rich 15.0.0, requests 2.34.2, dnspython 2.9.1, phonenumbers 9.0.42, pytest 9.2.0 |
| Tests at start | 119 passed |
| Database copy | `integrity_check` ok, `foreign_key_check` empty, schema v2; 14 investigations / 98 findings / 30 entities / 29 relationships / 95 sources / 22 search history / 3 reports |

## 2. Integration results (sandbox copy)

| Area | Result |
|---|---|
| All 8 module types end to end via `investigation.run` + persistence | Pass (domain 44 findings, ip 9, email 25, phone 7, username 15, social 23, security 21, name 0 with "no provider configured") |
| Reports: all 22 investigations x HTML/JSON/TXT (66 files) | Pass; JSON finding counts equal stored findings |
| Graph: whole-DB and per-investigation, contradictions, shared entities, neighbours, entity search, graph export, `detect_type` | Pass |
| Database: backup, stats, history, delete investigation (copy), FK check after delete, settings and secret round trips | Pass |
| Menu loop in `main.py` driven by piped input (history, reports, settings, AI, API config, explorer, exit) | No tracebacks; reaches "Goodbye" (menu input was only roughly aligned, so this is a smoke test, not a full UI walkthrough) |
| Launchers | `TRACEPOINT.ps1` uses `.venv\Scripts\python.exe`; not executed here |
| Degraded paths | Search outage reported as "did not run", not as zero results; IP PTR timeout reported as a lookup error; Name Intelligence refuses with a clear message when unconfigured |

## 3. Defects found and corrected

| # | Origin | Defect | Correction | Test |
|---|---|---|---|---|
| D1 | Regression audit R6 | Finding rows in reports and the terminal showed the legacy raw grade `STRONG` while summary counts said CORROBORATED | `reports.build` and `render.confidence_text` normalise for presentation only; stored values untouched | `test_phase6.py` (2 tests) |
| D2 | Regression audit R2 | Single-source findings were graded CORROBORATED (domain age under 30 days: one RDAP record; VirusTotal 3+ malicious: one provider) | Domain age: MODERATE (<30 days) / LOW (<90). VirusTotal: MODERATE if any detections, else LOW. IP geolocation agreement across providers left as CORROBORATED | `test_phase6.py` |

Self-inflicted and fixed in-session: a mid-call comment broke `security_intel.py` (caught immediately by the suite, 8 failures, then fixed).

Tests after corrections: **122 passed** (119 + 3).

## 4. Findings not corrected (open)

Carried over from `REGRESSION-AUDIT.md`, still present in code, deliberately not changed in an integration pass:

- **R1** old-signature custom providers mis-reported by `test_connection` (no in-repo providers affected).
- **R3** worst-case search latency roughly doubled by the fallback chain (needs an overall deadline).
- **R4** Name Intelligence DuckDuckGo fallback: in the sandbox run Name Intelligence stopped with "no provider configured", so it did not send the name out in the unconfigured case; the "keyed provider fails, then DuckDuckGo" case still needs your decision.
- **R5** DuckDuckGo "no results" detection looseness; **R7** generic provider exceptions lose their cause; **R8-R10** minor.
- **New, minor:** each report save appends another row to `reports` (66 saves gave 91 rows), so the Reports list repeats entries on repeated generation.
- **New, environmental:** reverse-DNS (PTR) lookups time out on this network (`LifetimeTimeout`), and DuckDuckGo returns a challenge page here; reliable web search needs a configured provider.
- Not verified live: Brave/Google/SearXNG/HIBP/VirusTotal/Ollama; real DuckDuckGo block page; a full interactive UI session.

## 5. Recommendation

Merge candidates: D1 and D2 (small, tested). Decide on R4 and R3 before adding features. Phase 7 has not been started.
