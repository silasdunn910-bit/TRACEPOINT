# TRACEPOINT Phase 7.1 - Security Remediation (Steps 1-5)

Branch `phase-6-integration`. Baseline `b410f13` (Phase 7). Not pushed. 2026-11-02, Python 3.11.9 (`.venv`).

**Scope note:** the Phase 7.1 prompt was cut off at "STEP 6 - NAME INT...". Steps 1-5 were received and are completed here. Step 6 (and anything after it) was **not** received and has **not** been done. The Name Intelligence fallback decision (R4) therefore remains open.

## Step 1 - Baseline

| Check | Result |
|---|---|
| Branch / tree | `phase-6-integration`, clean; `b410f13` exists |
| Tests | 133 passed (as reported) |
| Real database (read-only) | 14 investigations, 98 findings, 30 entities, 29 relationships, 3 reports; file last modified 06:12:55, unchanged through this phase |
| Phase 7 claims vs working tree | Confirmed. One new observation: running the old test suite changed the mtime of the real `logs\tracepoint.log` (the isolation problem in Step 4) |

## Step 2 - DNS rebinding protection: PASS (with stated limits)

Change (`core/http.py`, `core/security.py`):
- For `public_only` requests the **connection itself** resolves the host, requires every returned address to be public, and connects to one of exactly those addresses (urllib3 connection subclass; `socket.create_connection((validated_ip, port))`). A name that resolves differently at connect time than at the early check is refused. A name that returns a mix of public and private addresses is refused.
- TLS is untouched: the TLS layer still receives the original hostname (SNI and certificate hostname check); `verify=True`; `connect()` is inherited unchanged. Live check: `example.com` OK; `expired.badssl.com`, `wrong.host.badssl.com`, `self-signed.badssl.com` rejected with SSL errors; `localhost` refused.
- Every redirect hop is followed manually (max 5) and re-validated and re-pinned.
- Environment proxies are ignored for these requests (`trust_env=False`), so a proxy cannot become the connection target.
- `is_public_ip` now also rejects multicast and looks through IPv4-mapped, 6to4 and NAT64 forms; invalid input is non-public.
- Malformed URLs (bad port, missing host, non-http schemes, NUL bytes, unclosed brackets) raise `HttpError` without traffic. Obfuscated loopback forms (`2130706433`, `0x7f.0.0.1`, `127.1`, `[::ffff:127.0.0.1]`, `0.0.0.0`) are refused.
- Tests: `tests/test_phase71_network.py` (about 70 cases including a simulated rebinding and a check that the pinned connection reaches the validated IP with the original `Host` header).

Limits (stated, not hidden): the guarantee covers requests made with `public_only=True` (currently the Social module's robots.txt and page fetches). Other provider calls use fixed, hard-coded API hosts and are not pinned. The pinned path performs two DNS lookups (early check for a clear message, then the authoritative one at connect); only the second is relied on. An attacker controlling a DNS answer can still point a hostname at a *different public* address, which is not an internal-access issue. There is no automated test of a real TLS failure (verified manually against badssl.com).

## Step 3 - Dependency pinning: PASS

- `requirements.txt` pins direct dependencies (`rich 15.0.0`, `requests 2.34.2`, `dnspython 2.9.1`, `phonenumbers 9.0.42`); `requirements-dev.txt` pins `pytest 9.2.0`; new `constraints.txt` locks all 16 packages including transitive ones. Launchers install with `-c constraints.txt`. No version was upgraded; the pins are the versions already tested.
- Supported Python: **3.11+**. Finding: the previously documented "3.10+" was already wrong for the resolved set, because `dnspython 2.9.1` requires 3.11. `INSTALL.ps1` and the README now say 3.11+.
- Clean virtual environments from the lock on **3.11.9 and 3.14.3**: `pip check` clean, `pip freeze` identical to `constraints.txt`, full suite passes on both. A clean run of `INSTALL.ps1` (25 s) also passes.
- `pip-audit` against `constraints.txt` (pinned set): no known vulnerabilities (point in time, 2026-11-02).
- Limitation: the lock has no hashes.

## Step 4 - Test isolation: PASS

- New `TRACEPOINT_HOME` override in `core/configuration.py`. `tests/conftest.py` creates a temporary home **before `core` is imported**, redirects database, reports, logs, config, backups, `tempfile` and pytest's base temp into it, restores the database singleton after every test, and deletes the home at exit (verified: nothing left behind).
- Hard guard: the session aborts if `core` was imported against the real tree; at the end it compares the real database, WAL, log, `.env` and `reports\` against a start-of-run snapshot and **fails the run** if anything changed. Demonstrated: a deliberate probe that wrote into the real `reports\` made pytest exit with code 1 (probe removed).
- Regression tests: `tests/test_isolation.py` (7 tests: paths, singleton, log handler, real log unchanged after logging, backup location, temp/pytest scratch space).
- Two existing tests still **read** the real log and a copy of the real database (read-only; they check credentials in the log and migration of real data). They cannot modify it and the guard verifies that.

## Step 5 - Credential masking: PASS

Findings and changes:
- Old `mask()` showed 3 + 3 characters for anything over 8 characters (6 of 9). New policy: values under 20 characters are **fully masked with a fixed-width mask** (length not revealed); 20+ characters show only the last 4 (at most 20%).
- The configuration screen now uses `credentials.display_value`; the SearXNG address (validated to contain no credentials or query) shows only `scheme://host:port`.
- Logs: redaction extended to header and bearer shapes plus **every credential value known to the process** (registered on store and read), so a value echoed back in a remote error message is scrubbed. Persisted source details and investigation notes get the same scrub, so it cannot reach reports.
- Checked, no change needed: validation, save and remove messages never echo values; password entry is not echoed; HTTP error messages carry host only; keys travel in headers or query parameters, never in stored URLs.
- Tests: `tests/test_phase71_masking.py` (about 45 cases across credential lengths 1-200, the rendered configuration screen with five stored credentials, error messages, eight log shapes, a log-file round trip, and TXT/JSON/HTML reports plus the encrypted-at-rest column).

## Results

- Tests: **251 passed** (133 before; 118 new), `.venv`, about 15 s; also passing in clean 3.11 and 3.14 environments.
- Real database: unchanged (14/98/30/29/3). No investigations deleted. Nothing pushed.

## Still open

- **Step 6 onward** (not received), including the R4 decision on sending a name to DuckDuckGo after provider failure.
- Live verification of keyed providers (Brave, Google CSE, SearXNG, HIBP, VirusTotal) and Ollama analysis: not done (no credentials).
- `data\` ACL (other local accounts can read investigation data) is documented, not applied; lock file has no hashes; DPAPI across users/machines untested.
- Phase 7 blockers: dependency pinning is now resolved; R4 and live provider verification remain.

Phase 8 has not been started.
