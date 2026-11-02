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

**Requirements:** Windows 10/11, Python 3.11+ (`python` on PATH; tested on 3.11.9). No Docker, no admin rights, no manually opened second terminal. Ollama is optional.

**Run the tests (developers):**

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt -c constraints.txt
.\.venv\Scripts\python.exe -m pytest -q      # offline; no live services are contacted
```

The tests run against a temporary `TRACEPOINT_HOME` (database, reports, logs, config, backups), created before the application is imported and deleted afterwards. They never write to your real `data\`, `logs\` or `reports\`; the run fails if the real installation changes. `TRACEPOINT_HOME` can also be set to relocate all data for a portable install.

**Dependencies** are pinned: `requirements.txt` lists the direct packages and `constraints.txt` locks every package (install with `-c constraints.txt`, as the launchers do). Tested on Python 3.11.9 and 3.14.3 (Windows). Python 3.10 is not supported because the pinned `dnspython` needs 3.11+. To update, change the pins deliberately, then run `pip check`, `pip-audit` and the tests.

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
| 16 | **Court Records** | Official court sources: automated search where a documented source allows it (federal opinions via GovInfo), otherwise the official portal; you review and attach records | ✔ |
| 17 | **Sex Offender Registry** | Official registries (NSOPW, NC SBI): manual lookup guidance and operator-reviewed listings; no addresses stored | ✔ |

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

## Court Records and Sex Offender Registry (menu 16 and 17)

Both use official government sources only. **They do not provide nationwide automated coverage**, and nothing in
either module decides that a record belongs to the person searched: every record is an `UNVERIFIED` name match until
you verify it yourself, and only records you review and choose to attach are stored.

| Source | Agency | Jurisdiction | Search in TRACEPOINT | Authentication | Coverage |
|---|---|---|---|---|---|
| GovInfo - U.S. Courts Opinions | U.S. Government Publishing Office | Federal | **Automated** (name / case-number full-text) | Free api.data.gov key in *API Configuration* | Published opinions only, not dockets; partial |
| PACER Case Locator | Administrative Office of the U.S. Courts | Federal | Manual (official page + your review) | PACER account; $0.10/page, waived at $30 or less per quarter; name searches are billed even with no matches | Nationwide index of federal cases |
| NC Judicial Branch records search | NC Administrative Office of the Courts | North Carolina | Manual | **Unverified** (the official pages returned HTTP 403 to automated checks) | Unknown; county portals not catalogued |
| NSOPW | U.S. DOJ SMART Office | National | Manual (no API; automated searching and CAPTCHA bypass are prohibited by its terms) | Accept conditions of use; CAPTCHA | Participating jurisdictions; depends on each |
| NC Sex Offender Registry | NC State Bureau of Investigation | North Carolina | Manual (no API or automated-access rule is stated; search form not verified) | Not stated | 100 counties; excludes juveniles adjudicated delinquent |

Only GovInfo is searched automatically. PACER's Case Locator API needs your PACER login and its endpoint documentation
could not be read, so it is not used. Searches that the portals offer by address, radius, ZIP or registry status are
deliberately **not** supported; TRACEPOINT accepts only a person's name, a case number (courts) or a registry
identification number (registries).

**Workflow.** Pick a jurisdiction and an official source, enter a name or number, confirm authorization, then either
review automated candidates or open the official page (TRACEPOINT shows the URL and can open it in your browser) and
type in what you reviewed. Each record needs your explicit confirmation before it is attached. The search itself is
saved to History even when nothing is attached.

**Classification rules.** The source's own wording is always stored next to TRACEPOINT's normalized value.
Court statuses: `PENDING`, `DISMISSED`, `CONVICTED`, `ACQUITTED`, `DEFERRED`, `SEALED / UNAVAILABLE`, `UNKNOWN`; only
explicit wording is classified. An arrest, charge or filing is never a conviction; a dismissal is never an acquittal;
civil and published-opinion records can never be `CONVICTED` or `ACQUITTED`. Registry statuses: `ACTIVE`,
`INACTIVE`, `DECEASED`, `ABSCONDED`, `UNKNOWN`. A registry listing is not proof of current whereabouts.

**Empty and missing results.** A completed search with no records says: "No records found in the sources searched. This
does not establish that the individual has no criminal or court history." (registries: "No registry records were returned
by the sources searched. This does not establish that an individual is absent from every registry."). A search that never
ran (manual source, failed provider, missing key) is reported as such, never as "nothing found".

**Data handling.** Registry records have no address, location, photo or physical-description fields, and street-address-like
text is rejected. Candidates you do not attach are not stored. Source URLs are kept (http/https only; hosts outside the
source's official domains are flagged). Reports add a *Records review* section that separates official source information,
unverified name matches, reviewed records, missing information, inaccessible sources, conflicts and partial coverage.
Use is limited to authorized subjects and public-safety awareness; threatening, harassing or intimidating anyone is
prohibited by the registries' terms and may be prosecuted.

**Adding a jurisdiction.** Add an `OfficialSource` (agency, URLs, method, supported fields, authentication, coverage,
verification note) to `providers/court_sources.py` or `providers/registry_sources.py`. Mark it `automated` only when the
agency documents a non-interactive search that permits it, and add a searcher with mocked-response tests.

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
