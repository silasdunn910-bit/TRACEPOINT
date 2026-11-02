# Changelog

## Unreleased (Phases 7 and 7.1)

### Security
- Public-only fetches (Social module) now validate every resolved address and connect to that validated address, so DNS rebinding between check and connect cannot reach local or internal hosts. Redirects are followed manually and re-checked; TLS verification is unchanged; environment proxies are ignored for these requests.
- Address classification also rejects multicast, carrier-grade NAT and IPv4-in-IPv6 forms (mapped, 6to4, NAT64) of non-public IPv4 addresses.
- Credentials: the configuration screen shows nothing of values under 20 characters (and only the last 4 of longer ones); known credential values and header/bearer shapes are redacted from logs and from persisted error text.
- Request logs record host and status only.

### Reliability / tooling
- Atomic investigation saves; menu actions can fail without ending the session; Ctrl-C returns to the menu; the offline Ollama probe is cached for the banner.
- Dependencies pinned (`requirements.txt`, `constraints.txt`); Python 3.11+ required.
- Tests run against a temporary `TRACEPOINT_HOME` and fail if the real installation changes.

## 1.0.1 - 2026-11-02

### Evidence
- Added `CORROBORATED` and `INCONCLUSIVE` grades (six levels). Legacy `STRONG` records are unchanged in the database and displayed as CORROBORATED.
- Summary counts in reports and the terminal use the same normalisation and always add up to the finding count.

### Search infrastructure
- Provider failures are classified: invalid key, invalid configuration, rate limit, quota exhausted, access denied, server error, invalid response, timeout, unavailable.
- Malformed or non-JSON provider replies produce provider-specific errors instead of crashing.
- DuckDuckGo is a labelled fallback only when every configured provider fails (or the default when none is configured).
- `search()` reports whether a search actually completed; "zero results" is distinct from "search never ran" in Name, Email, Phone and Username results.
- Connection tests (`t` in API Configuration) and honest status labels; SearXNG URL validation; confirmed credential deletion; clear messages for empty/invalid input.

### Modules
- Username: 401/403/429/anti-bot pages are `blocked` (source status BLOCKED, finding INCONCLUSIVE), 5xx is `error`; never "not found".
- Email: HIBP 401/429/5xx/unreadable responses are errors ("breach status unknown"), never a clean result.
- Name: exact missing-configuration message; stops after repeated provider failures.
- Relationship Explorer: shared webmail/DNS/CDN/resolver infrastructure is flagged generic and hidden from "shared entities".

### Reports and data
- Report paths resolve against the current reports folder; old `C:\Projects\...` history rows work without being modified. New rows store the file name only.
- No database records were modified or deleted.

### AI
- Hardened Ollama status/analysis against unexpected replies; empty or unreadable output is an error and is not saved.

### Tooling
- Version 1.0.1; `requirements-dev.txt` (pytest); 119 offline tests.
