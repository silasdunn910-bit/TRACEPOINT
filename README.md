# TRACEPOINT

**Local-first OSINT, infrastructure intelligence, and digital-footprint auditing — in a PowerShell-launched terminal.**

TRACEPOINT investigates **publicly available** information about infrastructure (domains, IPs) and about identifiers **you own or are explicitly authorized to audit** (your email, phone, usernames, profile URLs, and name-based research). It normalizes findings, grades each one by evidence strength, records them in a local SQLite database, and exports evidence-backed reports. Nothing leaves your machine except the public lookups you trigger.

> ### Intended use & scope
> TRACEPOINT is built for **auditing your own digital footprint** and for **authorized security work** (checking your own domains/mail security, triaging suspicious infrastructure, phishing analysis). Person-oriented modules (email, phone, username, social) require you to **affirm authorization** before each run.
>
> It deliberately does **not** do: private-account discovery, login-wall bypassing, credential/breach-content retrieval, covert location tracking, or automated dossiers on arbitrary individuals. Name Intelligence uses only configured search APIs, preserves leads for review, and never treats a name match as identity proof. It does not crawl result pages and honors source access controls.

---

## Quick start (Windows)

```powershell
cd <path-to-your-TRACEPOINT-folder>
.\INSTALL.ps1      # one-time: checks Python, builds .venv, installs deps, initializes the DB
.\TRACEPOINT.ps1   # launch the app (auto-installs on first run if needed)
```

Other scripts:

```powershell
.\STATUS.ps1   # application / dependency / database / Ollama status
.\STOP.ps1     # stop only the TRACEPOINT process (never other Python/Node)
```

If PowerShell blocks the scripts, allow them for your user once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**Requirements:** Windows 10/11, Python 3.10+ (`python` on PATH). No Docker, no admin rights, no manually opened second terminal. Ollama is optional.

**Run the tests (developers):**

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q      # offline; no live services are contacted
```

---

## The menu

| # | Module | What it does | Needs authorization |
|---|--------|--------------|:---:|
| 1 | **Email** | Syntax, domain, disposable/free classification, MX, SPF, DKIM, DMARC, RDAP, public Gravatar profile, optional breach-name check (HIBP), public references | ✔ |
| 2 | **Phone** | Normalizes common input formats and validates numbering-plan metadata with libphonenumber; optional configured-provider public references | ✔ |
| 3 | **Username** | Checks ~25 platforms (official/public APIs) for a public profile with that exact handle, cross-platform field comparison, impersonation/duplicate notes | ✔ |
| 4 | **Domain** | RDAP, full DNS, SPF/DKIM/DMARC, certificate-transparency hostnames, Wayback history, reputation | — |
| 5 | **IP** | Validation, RDAP network owner, ASN/ISP, reverse DNS, hosting/proxy classification, geolocation (2 providers, cross-checked), reputation | — |
| 6 | **Social** | Analyzes a supplied public profile URL: title/bio/metadata, `rel="me"` and disclosed links, cross-platform handle check | ✔ |
| 7 | **Security** | Phishing & suspicious-infrastructure indicators: look-alike/homoglyph & brand-keyword domains, low-rep TLDs, entropy, domain age, email-auth weaknesses, reputation | — |
| 8 | **Name** | Search configured public web providers for exact names, spelling variants, biographies, organizations, news and institutional pages; preserve sources and separate unresolved candidates | ✔ |
| 9 | **Universal Search** | Auto-detects the identifier type and routes names to Name Intelligence | depends |
| 10 | **Relationship Explorer** | Entities shared across investigations, entity search, Cytoscape graph export | — |
| 11 | **History** | Browse/open/delete past investigations (persisted) | — |
| 12 | **Reports** | Generate TXT / JSON / HTML reports | — |
| 13 | **API Configuration** | Add optional API keys (stored encrypted) | — |
| 14 | **Settings** | Ollama URL/model, DB backup, encryption mode | — |
| 15 | **AI Analyst** | Ollama connection/model status | — |

Name Intelligence requires the operator to affirm authorization before each run. Supply a defined research context
when useful. It searches only through configured Brave Search, Google Programmable Search or SearXNG APIs; without
one configured, it reports that search is unavailable instead of scraping a fallback search page. It does not crawl
result pages, collect private contact details, or infer that same-name results identify one person. Search snippets
are preserved as leads, with their source URLs and retrieval times; publication dates remain unknown when the provider
does not supply them. Structured claims can be compared for conflicts or corroboration only after an analyst assigns
them to a candidate. Matching names alone never create that assignment.

---

Phone metadata does not establish that a number is active, reachable, or owned by a person. Region and time-zone details
describe numbering-plan allocation only. For national-format input, the app asks for the numbering region (default `US`);
international numbers with a leading `+` use their country calling code. Public web-reference searches use configured Brave Search, Google Programmable
Search, or SearXNG APIs; when none is configured, phone search reports that fact and does not fall back to DuckDuckGo
HTML scraping. Search results are leads and retain source URLs and retrieval times.

## Confidence grades

Every finding carries a qualitative grade — **not** a statistical probability:

- **VERIFIED** — directly supported by a reliable primary source (e.g. a DNS record, an RDAP event).
- **CORROBORATED** — supported by multiple independent sources (older records stored as `STRONG` are shown as CORROBORATED).
- **MODERATE** — limited but consistent evidence.
- **LOW** — weak association or incomplete evidence (e.g. a search hit containing the term).
- **UNVERIFIED** — not independently confirmed.
- **INCONCLUSIVE** — the source could not establish the result (blocked, rate-limited, unavailable). An HTTP 403/429 or an anti-bot page is never read as "account not found".

Each finding also records its source, source URL, discovery time, supporting evidence, and **limitations**. Matching handles/names are never treated as proof of common ownership; IP/phone geography is labeled as network/numbering-plan data, never a person's location.

---

## Optional integrations (all free-tier or self-hosted)

Set these in **API Configuration** (menu 13). TRACEPOINT is fully useful **without** any of them, though Name Intelligence needs a configured web-search provider.

| Key | Enables |
|-----|---------|
| Brave Search / Google Programmable Search / SearXNG | Web-reference search; Name Intelligence uses configured providers only |
| IPinfo | Richer IP data |
| AbuseIPDB / VirusTotal | IP & domain reputation |
| Have I Been Pwned | Breach **names** for an email (never credentials) |
| OpenCorporates | Public company-officer records |

**Search provider setup (needed for Name Intelligence):** configure at least one of
- *Brave Search*: API key,
- *Google Programmable Search*: API key **and** search engine ID (`cx`),
- *SearXNG*: instance base URL, `http://` or `https://` only, with JSON output enabled (`search.formats` includes `json`).

**Status labels in API Configuration.** `CONFIGURED` only means a credential is stored. Press `t` to run one live connection test per search provider; only then does the status become `CONNECTED`, `INVALID CREDENTIALS`, `RATE LIMITED` or `UNAVAILABLE`. A changed credential resets the status to `CONFIGURED`. Other integrations (IPinfo, AbuseIPDB, VirusTotal, HIBP, OpenCorporates) have no connection test yet and show `CONFIGURED (no test available)`.

**Search order.** Configured providers are tried first. DuckDuckGo is used only if none is configured, or as a labelled fallback when every configured provider fails. A search that never ran is reported as an error, never as "no results".

Keys are encrypted at rest with **Windows DPAPI** (scoped to your Windows user); they are never printed in full, never written to logs, and `config/.env` / the database are git-ignored. On non-Windows dev machines a clearly-labeled base64 fallback is used and the app says so.

---

## Local AI analyst (optional)

Install [Ollama](https://ollama.com), then e.g.:

```powershell
ollama pull qwen2.5-coder:7b
```

Open any investigation → **ai**. The model receives **only the stored findings** and is instructed to cite finding numbers, separate facts from inferences and unknowns, and never invent sources or locations. It never downloads models itself. If Ollama is offline, everything else still works. AI text is stored separately from findings, is labelled "local model · unverified" in reports, and is never counted as evidence.

---

## Project layout

```
TRACEPOINT/
  TRACEPOINT.ps1  INSTALL.ps1  STOP.ps1  STATUS.ps1
  main.py                     # Rich terminal UI
  requirements.txt  README.md
  core/      models, database (SQLite+migrations), http, search_engine,
             correlation, reports, ai, security (DPAPI), configuration, investigation
  modules/   email, phone, username, domain, ip, social, security  (+ data/ disposable list)
  providers/ search_providers, domain_providers, ip_providers
  ui/        theme, render
  data/  reports/  logs/  config/
```

## Reports & data

- The reports folder is always `<app folder>\reports` (resolved from the app root, never a hard-coded path). Older history entries that recorded another location are resolved by file name; a missing file is marked `[missing]`.
- Reports are written to `reports/` as `TP-<date>-<id>.{txt,json,html}`. The HTML report is self-contained (no external assets).
- All investigations persist in `data/tracepoint.db` and survive restarts; **History** reopens or deletes them.
- **Settings → backup-db** snapshots the database into `data/backups/` (last 10 kept).

## Backup, recovery and data protection

**What is sensitive.** `data/tracepoint.db` holds every investigation (targets, findings) and the DPAPI-encrypted API keys; `reports/` holds exported reports; `logs/tracepoint.log` records request hosts and status codes only (no URL paths, targets or keys). None of these folders is committed to Git. Reports never contain API keys.

**Access control.** Credentials are encrypted for the current Windows user only, but the investigation data itself is as readable as the folder. If other local accounts exist, restrict the app folder to your user, for example:
`icacls "<app folder>" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"`

**Backup.** Close TRACEPOINT, then copy `data\tracepoint.db` (plus `tracepoint.db-wal` and `tracepoint.db-shm` if present) to a safe place; or use **Settings -> backup-db**, which makes a consistent snapshot in `data\backups\` while the app runs (last 10 kept). Also copy `reports\` if you want the exported files. API keys in a backup can only be decrypted by the same Windows user on the same machine; after restoring on another machine/user, re-enter them under **API Configuration**.

**Recovery.** Close TRACEPOINT, keep the damaged file (rename it `tracepoint.db.bad`), delete any leftover `tracepoint.db-wal` / `-shm`, copy the chosen backup to `data\tracepoint.db`, start the app and check the investigation count in the banner. Check integrity with `.venv\Scripts\python.exe -c "import sqlite3;print(sqlite3.connect('data/tracepoint.db').execute('pragma integrity_check').fetchone())"` (expects `('ok',)`).

**User-supplied URLs.** The Social module only fetches public internet addresses (loopback, private and link-local targets are refused, including via redirects).

## Legal & ethical note

You are responsible for how you use TRACEPOINT. Use it only on identifiers and infrastructure you own or are authorized to investigate, and in compliance with applicable laws, site terms, and the access controls of the services queried. It reads only public data and does not bypass authentication.
