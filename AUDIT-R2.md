# TRACEPOINT - Re-Audit R2 (fixes applied and verified)

**Date:** 2026-11-02
**Actual project path:** `C:\Users\administrators1\Desktop\TRACEPOINT`
**Note:** the previously documented `C:\Projects\TRACEPOINT` does not exist (`C:\Projects` is empty). The project was not moved by this audit; the path mismatch is documented in `README.md` as `<path-to-your-TRACEPOINT-folder>`.
**Runtime:** Windows, Python 3.11.9 (`.venv`), live network available.
**Safety:** no investigation records were deleted or modified; the live database still contains 1 investigation, 10 findings and 5 entities.

---

## 1. Why this second audit

The first audit (`AUDIT.md`) was written in a non-Windows container and could not execute DPAPI, live network calls or the PowerShell scripts. This round ran on the real Windows machine, reproduced several issues live, fixed them, and added regression tests.

Pre-fix backup:
`C:\Users\administrators1\AppData\Local\Temp\opencode\tracepoint-backup-20261102-021150.zip`

Post-fix source/database snapshot (no virtual environment, no caches):
`C:\Users\ADMINI~1\AppData\Local\Temp\opencode\tracepoint-postfix-20261102-022101.zip`

---

## 2. Issues found and fixed

### High

1. **Username false VERIFIED finding on anti-bot pages.**
   Live reproduction: a nonexistent PyPI user returned HTTP 200 with a `Client Challenge` page, which the old status-only check reported as "profile exists". Added challenge detection (title markers + Cloudflare challenge markers) and report `inconclusive` instead. Verified live: the same user is now `UNVERIFIED / Check inconclusive` for PyPI.
2. **Launcher recorded the wrong PID.**
   `TRACEPOINT.ps1` wrote `$PID` (the PowerShell host) to `data\tracepoint.lock`, so the lock did not identify the Python app. It now starts Python via `System.Diagnostics.Process`, writes the child PID, waits for it, reports its real exit code, and always removes the lock. `STOP.ps1` now verifies the recorded PID's command line contains `main.py` before killing it. If verification is impossible it leaves the process and the lock alone (fail-safe, never kills an unrelated Python).
3. **DNS failure was treated as proof of absence.**
   `dns_query()` returned `[]` for both NXDOMAIN/NoAnswer and resolver/network failures. That could produce false "No SPF/DMARC" and false "domain does not exist" findings. Resolver/network failures now propagate; only NXDOMAIN/NoAnswer are empty. `security_intel` only scores missing SPF/DMARC when the DNS email-auth lookup completed successfully.
4. **Report links allowed `javascript:` / `data:` URLs.**
   `core/reports.py` now emits `<a>` only for absolute `http`/`https` URLs via `safe_href()`; everything else is rendered as plain escaped text.

### Medium

5. **Certificate-transparency hostname boundary bug.**
   A hostname such as `notexample.com` could be counted as a hostname of `example.com`. Fixed with a label-boundary helper (`name_in_domain`) and a regression test.
6. **DMARC enforcement check matched unrelated findings.**
   Any finding containing `p=quarantine` could mark DMARC as enforcing. The check is now limited to `email-auth` findings whose value is the DMARC record.
7. **Geolocation confidence could overstate city agreement.**
   `STRONG` now requires both country and city agreement; country-only agreement is not enough.
8. **`STOP.ps1` could kill an unrelated Python if CIM inspection failed.**
   It now treats an unverifiable PID as "leave it alone" and keeps the lock so `STATUS.ps1` still reports the running process.
9. **`config/.env` was documented but never loaded.**
   Added a small dependency-free loader in `core/configuration.py`. Existing environment variables take precedence. `OLLAMA_URL` is now honored.

### Low

10. **`STATUS.ps1` database statistics were blank.**
    A PowerShell/Python quoting interaction broke the f-string. Replaced with explicit `%` formatting; STATUS now reports `1 investigations, 10 findings, 5 entities`.
11. **`STATUS.ps1` could report a reused PID as a running app.**
    It now verifies the command line contains `main.py` when available.
12. **Windows console encoding.**
    PowerShell scripts are now ASCII-clean, and the launcher/installer set `PYTHONUTF8=1` / `PYTHONIOENCODING=utf-8` for Python. This fixes `UnicodeEncodeError` on legacy Windows code pages (reproduced when piping stdin).
13. **The `.venv` had stale absolute paths.**
    It had been created at `C:\Projects\TRACEPOINT`; `activate`, `activate.bat` and `pyvenv.cfg` pointed there, and the venv was 296 MB due to unused scientific/image packages. Rebuilt at the actual Desktop path from the trimmed requirements (82.5 MB). The old venv is retained as `.venv.old-20261102` for rollback (ignored by `.gitignore`).
14. **Unused dependencies.**
    Removed `Pillow`, `imagehash` and `pypdf` from `requirements.txt`; nothing in the current source imports them.
15. **Database parent directory.**
    `Database()` now creates its parent directory, so a custom DB path cannot fail on a missing folder.
16. **DuckDuckGo empty/blocked page could raise an unhelpful parse/index error.**
    It now raises `ProviderUnavailable` with a clear message when no result markup is present.
17. **RDAP date robustness.**
    Handles `TypeError` as well as `ValueError`, and treats naive timestamps as UTC.
18. **Minor correctness cleanups.**
    Reverse-DNS failures mark the source as `error`; RDAP `self` URL handles `None`; `README.md` no longer hardcodes the nonexistent `C:\Projects\TRACEPOINT`.
19. **Search history double-logging** (from the first audit) remains fixed; no regression found.

---

## 3. Test results

Commands run with the rebuilt venv:

```powershell
.\.venv\Scripts\python.exe tests\test_audit.py
.\.venv\Scripts\python.exe tests\test_fixes.py
.\.venv\Scripts\python.exe -m compileall core modules providers ui tests main.py
```

| Suite | Result |
|-------|--------|
| `tests/test_audit.py` | **8 passed, 0 failed** |
| `tests/test_fixes.py` | **10 passed, 0 failed** |
| `compileall` | **OK** |

`tests/test_fixes.py` covers: unsafe report links, DNS NoAnswer vs NoNameservers, reverse-DNS failure, security email-auth gating, scoped DMARC enforcement, username challenge pages, Reddit JSON metadata, CT label boundaries, `.env` loading/precedence, and DB parent-directory creation. No test uses the live database or the network.

### Live verification

| Check | Result |
|-------|--------|
| IP `8.8.8.8` | 10 findings, 0 errors |
| Domain `example.com` | 35 findings, 0 errors |
| Security `example.com` | 21 findings, 0 errors |
| Phone `+14155552671` (authorized) | 7 findings, 0 errors |
| Email `test@gmail.com` (authorized, no web search) | 10 findings, 0 errors |
| Invalid email | 1 finding, 1 explicit validation error (no crash) |
| Username nonexistent | 14 findings, 0 errors; PyPI now inconclusive, not a false VERIFIED profile |
| DPAPI | round-trip works; `encryption_mode()` = `DPAPI`; no plaintext secret in DB |
| Launcher | child PID recorded, exit code `0`, lock removed |
| Single-instance guard | refuses to start when a verified `main.py` process holds the lock |
| `STOP.ps1` | stopped a verified `main.py` probe and cleared the lock |
| `STATUS.ps1` | app/venv/dependencies/DB/Ollama report correct |

---

## 4. Remaining issues and limitations

1. **Web search is unreliable in this environment.** DuckDuckGo returns HTTP 202 / anomaly pages (HTML and lite), and no keyed provider is configured. The app now fails with a clear message instead of parsing garbage, but reliable search requires a Brave, Google CSE or SearXNG key. This is a data-source limitation, not a logic bug.
2. **Reddit returns HTTP 403 from this network.** The module reports `inconclusive` rather than inventing a result. It may work from another network or with a configured provider; no bypass was added.
3. **Other status-only platforms may still use soft-404s.** Linktree and about.me now return real 404s for a nonexistent handle (the old audit reproduction no longer holds); PyPI is fixed. Kaggle returned 404 with the TRACEPOINT user agent. A site-by-site marker review is still advisable before trusting every status-only result.
4. **Ollama/AI is offline here.** The status/degrades path works, but end-to-end AI analysis was not exercised.
5. **Legacy tables `image_hashes` / `document_meta` remain.** They are unused. Removing them would be a schema migration with no functional benefit; deferred deliberately.
6. **Old venv retained.** `.venv.old-20261102` (296 MB) can be deleted after you are satisfied; the active `.venv` was rebuilt at the correct path.
7. **The project has no git repository.** No commits were made. The `.gitignore` was updated to ignore `.venv.old*/`.

---

## 5. Phase 6 proposal (needs approval before implementation)

**Network Intelligence** would fit as a new module plus graph entities/relationships, not a rewrite:

- **Passive:** DNS records, reverse DNS, RDAP/WHOIS, ASN and announced prefix, certificate transparency SANs, HTTP response headers, TLS certificate metadata, technology hints, passive subdomain discovery.
- **Optional active (explicit authorization required):** bounded TCP connect checks on a small, user-specified port list; no exploitation, no brute force, rate-limited and logged.
- **Graph:** domain/IP/ASN/certificate/subdomain nodes with `RESOLVES_TO`, `ANNOUNCED_BY`, `HOSTS`, `CERTIFICATE_FOR` relationships, each carrying source and confidence.
- **UI:** a new "Network Intelligence" menu entry, exportable filtered graph, and clear "passive vs active" labels.

Decision needed: passive-only, or passive plus an authorization-gated active connect check? Also confirm whether to add a keyed search provider at the same time, since search remains the weakest data source.
