# API Setup

TRACEPOINT works with no keys at all. Each key you add unlocks one more source. Never pay for anything to use
these integrations: every service below has a genuinely free route (see `API_PROVIDER_REFERENCE.md` for limits and
the one caveat, OpenCorporates).

## 1. Where credentials live

Two supported places. The encrypted database value wins if both exist.

1. **In the app (recommended):** run TRACEPOINT, menu **18 Integrations Dashboard**, type `k N` for a provider and paste the key. It is stored encrypted and never displayed in full.
2. **Environment / `.env`:** copy `.env.example` to `.env` (project root) or `config/.env`, fill in only what you use. `.env` is git-ignored. Blank values are ignored.

Never put real keys in `.env.example`, source files or commit messages. Keys are redacted from logs, error
messages and the dashboard; the dashboard shows variable *names*, never values.

## 2. Install and start

```powershell
# from the TRACEPOINT folder
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt -c constraints.txt
.venv\Scripts\python.exe main.py
```

(`START TRACEPOINT.bat` and `INSTALL.ps1` do the same.) Run the tests with
`.venv\Scripts\python.exe -m pip install -r requirements-dev.txt` then `.venv\Scripts\python.exe -m pytest -q`.
No new Python dependencies were added.

## 3. Register for each key

| Service | Link | Variable |
|---|---|---|
| IPinfo (optional) | https://ipinfo.io/signup | `IPINFO_TOKEN` |
| IPdata | https://ipdata.co/sign-up.html | `IPDATA_API_KEY` |
| IP-DB | https://ip-db.com/en/api-docs ("Get API Key") | `IPDB_API_KEY` |
| OpenIPAPI | https://www.openipapi.com/ | `OPENIPAPI_API_KEY` |
| AbuseIPDB | https://www.abuseipdb.com/register | `ABUSEIPDB_API_KEY` |
| VirusTotal | https://www.virustotal.com/gui/join-us | `VIRUSTOTAL_API_KEY` |
| AlienVault OTX | https://otx.alienvault.com/accounts/signup/ | `OTX_API_KEY` |
| urlscan.io (optional) | https://urlscan.io/user/signup | `URLSCAN_API_KEY` |
| ThreatFox + URLhaus | https://auth.abuse.ch/ (one Auth-Key for both) | `ABUSECH_AUTH_KEY` |
| CourtListener | https://www.courtlistener.com/sign-up/ | `COURTLISTENER_API_KEY` |
| GovInfo + FEC | https://api.data.gov/signup/ (one key works for both) | `GOVINFO_API_KEY`, `FEC_API_KEY` |
| OpenCorporates | https://opencorporates.com/users/sign_up (see eligibility note) | `OPENCORPORATES_API_KEY` |
| Brave Search | https://brave.com/search/api/ | `BRAVE_SEARCH_API_KEY` |
| Google Programmable Search | https://developers.google.com/custom-search/v1/overview | `GOOGLE_SEARCH_API_KEY` + `GOOGLE_SEARCH_CX` |
| SEC EDGAR | no key; set a contact such as `Jane Doe jane@example.org` (the SEC requires one in the User-Agent) | `SEC_EDGAR_CONTACT` |

No account needed: GDELT, Internet Archive, Wikipedia, RIPEstat, RDAP, USAspending, crt.sh, Wayback Machine,
Cloudflare DNS over HTTPS (and BGPView, which is currently offline).

The Google `GOOGLE_SEARCH_CX` value in `.env.example` is a public search-engine ID for an embedded search box. The
JSON API that TRACEPOINT uses additionally needs `GOOGLE_SEARCH_API_KEY`; the ID alone does nothing for the API.

## 4. SearXNG

SearXNG is software you host, not a service with a key. It has no supported native Windows install, and this
machine has neither Docker nor WSL, so TRACEPOINT could not install it here. Options:

- Docker (any machine): `docker run -d -p 8888:8080 -v searxng:/etc/searxng searxng/searxng`, then add `json` under `search: formats:` in `settings.yml`, restart the container.
- Linux/WSL: follow https://docs.searxng.org/admin/installation.html.

Then set `SEARXNG_URL=http://127.0.0.1:8888` (or use `k N` in the dashboard) and press `t N` to test. If the test
shows PROVIDER UNAVAILABLE with "JSON output may be disabled", the `json` format is not enabled.

## 5. Test a provider

Dashboard (menu **18**): `t N` tests one provider with a real request, `ta` tests every configured provider,
`l N` runs a lookup, `x N` disables or re-enables a provider. From code:

```powershell
.venv\Scripts\python.exe -c "from integrations import manager; print(manager.test('abuseipdb'))"
.venv\Scripts\python.exe -c "from integrations import manager; print(manager.lookup('rdap','domain','example.com'))"
```

A provider is CONNECTED only after a request succeeds. Tests spend a little of your free quota.

## 6. Research rules the integrations enforce

- Only lawful, public sources. No private accounts, no scraping behind logins, no quota or auth bypass.
- Private/loopback IPs are never sent to third parties. VirusTotal and urlscan are lookup-only: TRACEPOINT never uploads files or submits URLs for scanning (a submission can publish the target).
- Every result records `source_url` and a retrieval `timestamp`, keeps the provider's original response under `data.raw`, and lists limitations. Confidence is left `null` unless a provider supplies one.
- An IP address is not an identity. Name-based record results (courts, FEC, USAspending, OpenCorporates, SEC) can describe a different person with the same name; verify against the original record. Court data is an aggregator view: prefer the official court record and keep its jurisdiction and case number.
