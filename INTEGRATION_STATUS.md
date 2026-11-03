# Integration Status

Verified on **2026-11-02** from the development machine (Windows 11, Python 3.11) with **no API keys configured**.
Only requests that actually reached the provider count as "live". Mocked tests (`tests/test_integrations.py`) prove
the adapter's handling of success, bad credentials, rate limits, timeouts, 5xx and malformed replies, but they
**do not** prove a provider works. Re-run live checks with:

```powershell
$env:TRACEPOINT_LIVE_TESTS = "1"; .venv\Scripts\python.exe -m pytest tests/test_integrations_live.py -v -s
```

## Statuses

| Status | Meaning |
|---|---|
| CONNECTED | A real request succeeded. A stored key alone never shows this. |
| NOT CONFIGURED | A required credential is missing. Nothing is sent. |
| NOT TESTED | Credentials present, no successful live request since they were set. |
| RATE LIMITED | Provider answered 429/402 or a quota message. |
| AUTHENTICATION FAILED | Provider rejected the credential (401/403). |
| PROVIDER UNAVAILABLE | Timeout, connection failure, DNS failure or 5xx. |
| ERROR | Reachable, but the reply was malformed or unexpected. |
| DISABLED | Switched off by the operator (`x N` in the dashboard). |

## Live-verified (no key needed)

| Provider | Live connection test | Live lookup verified | Note |
|---|---|---|---|
| Internet Archive | CONNECTED | yes | |
| Wikipedia | CONNECTED | yes | |
| IPinfo | CONNECTED (unauthenticated) | yes | Token optional; unauthenticated limits are low. Token path is mock-only. |
| RIPEstat (added) | CONNECTED | yes (ip, asn) | Working substitute for BGPView. |
| RDAP | CONNECTED | yes (domain, ip) | |
| urlscan.io | CONNECTED (unauthenticated search) | yes | Key optional. Key path is mock-only. |
| USAspending | CONNECTED | yes | |
| FEC | CONNECTED (shared `DEMO_KEY`) | yes (candidate) | `DEMO_KEY` has very low limits; own key path is mock-only. |
| Wayback Machine | CONNECTED | yes | |
| Cloudflare DNS over HTTPS | CONNECTED | yes | |
| GDELT | CONNECTED on some runs, RATE LIMITED on others | yes (once) | Strict per-IP throttling (HTTP 429 observed repeatedly). Not reliable from this machine. |
| crt.sh | CONNECTED on some runs, PROVIDER UNAVAILABLE on others | yes (85 certificates for example.com) | Community service, frequent overload/timeouts. |

## Live: provider down

| Provider | Result |
|---|---|
| BGPView | PROVIDER UNAVAILABLE. `api.bgpview.io` and `bgpview.io` do not resolve in DNS; the service appears discontinued. The adapter is complete (and mock-tested) in case it returns; use RIPEstat meanwhile. |

## Implemented, mock-tested only (credential or instance required)

Endpoints for these were checked as far as possible without a key: ThreatFox, URLhaus, CourtListener, GovInfo and OpenCorporates were confirmed live to answer **401 without credentials** (so the host, path and auth requirement are real). IP-DB and OpenIPAPI endpoints/headers come from their published documentation. Success-path response parsing for all of the below is based on documentation and has **not** been confirmed against a live keyed response.

| Provider | Missing credential | Where to get it |
|---|---|---|
| IPdata | `IPDATA_API_KEY` | https://ipdata.co/sign-up.html |
| IP-DB | `IPDB_API_KEY` | https://ip-db.com/en/api-docs |
| OpenIPAPI | `OPENIPAPI_API_KEY` | https://www.openipapi.com/ |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | https://www.abuseipdb.com/register |
| VirusTotal | `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/join-us |
| AlienVault OTX | `OTX_API_KEY` | https://otx.alienvault.com/accounts/signup/ |
| ThreatFox + URLhaus | `ABUSECH_AUTH_KEY` (one key) | https://auth.abuse.ch/ |
| CourtListener | `COURTLISTENER_API_KEY` | https://www.courtlistener.com/sign-up/ |
| GovInfo | `GOVINFO_API_KEY` | https://api.data.gov/signup/ |
| SEC EDGAR | `SEC_EDGAR_CONTACT` (no key; a real contact string is required by the SEC) | n/a |
| OpenCorporates | `OPENCORPORATES_API_KEY` | https://opencorporates.com/users/sign_up |
| Brave Search | `BRAVE_SEARCH_API_KEY` | https://brave.com/search/api/ |
| Google Programmable Search | `GOOGLE_SEARCH_API_KEY` (+ `GOOGLE_SEARCH_CX`) | https://developers.google.com/custom-search/v1/overview |
| SearXNG | `SEARXNG_URL` (a running instance) | see `API_SETUP.md`; not installable natively on Windows, and Docker/WSL are not installed on this machine |

Brave, Google and SearXNG are wrappers over the pre-existing, already-tested `providers/search_providers.py`; they were not rewritten.

## Needs paid access / approval

- **OpenCorporates**: API access requires an account token. Free access is by application for public-benefit/open-data use; otherwise it is paid. No paid plan was purchased or trial started. Confirm your eligibility with the provider.
- No other listed service requires payment for the functionality TRACEPOINT uses. VirusTotal's free key is licensed for non-commercial use only. Google's free quota is 100 queries/day; billing must not be enabled for TRACEPOINT to stay free.

## Known issues

- BGPView is down (above). GDELT and crt.sh are intermittently unavailable (above).
- The pre-existing test suite printed `ISOLATION FAILURE ... data/tracepoint.db-wal` once before any change was made; it did not recur after the changes. It looks like a stray write from an earlier session and was not investigated further.
- `integrations/` adapters sit beside the existing module code (`providers/ip_providers.py`, `providers/domain_providers.py`, etc.). The existing investigation modules still call their own functions; they do not yet route through the manager's status/quota layer.
