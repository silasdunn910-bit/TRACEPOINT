# Changelog

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
