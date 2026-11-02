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

---

## The menu

| # | Module | What it does | Needs authorization |
|---|--------|--------------|:---:|
| 1 | **Email** | Syntax, domain, disposable/free classification, MX, SPF, DKIM, DMARC, RDAP, public Gravatar profile, optional breach-name check (HIBP), public references | ✔ |
| 2 | **Phone** | E.164 normalization, country/region, number type, allocated carrier, numbering-plan area, public listings | ✔ |
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

## Confidence grades

Every finding carries a qualitative grade — **not** a statistical probability:

- **VERIFIED** — directly supported by a reliable primary source (e.g. a DNS record, an RDAP event).
- **STRONG** — multiple independent, credible sources agree.
- **MODERATE** — limited but consistent evidence.
- **LOW** — weak association or incomplete evidence (e.g. a search hit containing the term).
- **UNVERIFIED** — not independently confirmed.

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

Keys are encrypted at rest with **Windows DPAPI** (scoped to your Windows user); they are never printed in full, never written to logs, and `config/.env` / the database are git-ignored. On non-Windows dev machines a clearly-labeled base64 fallback is used and the app says so.

---

## Local AI analyst (optional)

Install [Ollama](https://ollama.com), then e.g.:

```powershell
ollama pull qwen2.5-coder:7b
```

Open any investigation → **ai**. The model receives **only the stored findings** and is instructed to cite finding numbers, separate facts from inferences and unknowns, and never invent sources or locations. It never downloads models itself. If Ollama is offline, everything else still works.

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

- Reports are written to `reports/` as `TP-<date>-<id>.{txt,json,html}`. The HTML report is self-contained (no external assets).
- All investigations persist in `data/tracepoint.db` and survive restarts; **History** reopens or deletes them.
- **Settings → backup-db** snapshots the database into `data/backups/` (last 10 kept).

## Legal & ethical note

You are responsible for how you use TRACEPOINT. Use it only on identifiers and infrastructure you own or are authorized to investigate, and in compliance with applicable laws, site terms, and the access controls of the services queried. It reads only public data and does not bypass authentication.
