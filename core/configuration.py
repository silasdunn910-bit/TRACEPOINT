"""Paths, constants and non-secret settings."""
from __future__ import annotations

import logging
import os
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

APP_NAME = "TRACEPOINT"
VERSION = "1.0.1"

# TRACEPOINT_HOME relocates all data (database, reports, logs, config, backups). The test suite
# sets it to a temporary directory so tests can never touch the real investigation data.
ROOT = (Path(os.environ["TRACEPOINT_HOME"]).resolve() if os.environ.get("TRACEPOINT_HOME")
        else Path(__file__).resolve().parent.parent)
DATA_DIR = ROOT / "data"
REPORTS_DIR = ROOT / "reports"
LOGS_DIR = ROOT / "logs"
CONFIG_DIR = ROOT / "config"
DB_PATH = DATA_DIR / "tracepoint.db"
LOCK_PATH = DATA_DIR / "tracepoint.lock"
BACKUP_DIR = DATA_DIR / "backups"

for _d in (DATA_DIR, REPORTS_DIR, LOGS_DIR, CONFIG_DIR, BACKUP_DIR):
    _d.mkdir(parents=True, exist_ok=True)


def _load_env_file(path: Path) -> None:
    """Load simple KEY=VALUE lines from config/.env without adding a dependency.

    Only non-secret defaults belong here (API keys live encrypted in the database).
    Real environment variables take precedence, and malformed/unsafe lines are ignored.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip("'\"")
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and key not in os.environ:
            os.environ[key] = value


_load_env_file(CONFIG_DIR / ".env")

DEFAULT_TIMEOUT = 12  # seconds for any outbound request
USER_AGENT = f"TRACEPOINT/{VERSION} (local OSINT research tool)"
OLLAMA_DEFAULT = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")

# Optional integrations. key -> (label, category, help)
API_INTEGRATIONS: dict[str, tuple[str, str, str]] = {
    "brave_search_key": ("Brave Search API", "Search", "https://brave.com/search/api/ (free tier available)"),
    "google_cse_key": ("Google Programmable Search key", "Search", "https://developers.google.com/custom-search/v1/overview"),
    "google_cse_cx": ("Google Programmable Search engine ID (cx)", "Search", "Created at https://programmablesearchengine.google.com/"),
    "searxng_url": ("SearXNG instance URL", "Search", "Your own SearXNG with JSON output enabled, e.g. http://127.0.0.1:8888"),
    "govinfo_key": ("GovInfo API key (api.data.gov)", "Court", "https://www.govinfo.gov/api-signup (free) - federal court opinions search"),
    "ipinfo_token": ("IPinfo token", "IP", "https://ipinfo.io/signup (free tier)"),
    "abuseipdb_key": ("AbuseIPDB key", "IP", "https://www.abuseipdb.com/register (free tier)"),
    "virustotal_key": ("VirusTotal key", "Domain/IP", "https://www.virustotal.com/gui/join-us (free tier)"),
    "hibp_key": ("Have I Been Pwned key", "Breach", "https://haveibeenpwned.com/API/Key (paid)"),
    "opencorporates_token": ("OpenCorporates token", "Business", "https://opencorporates.com/api_accounts/new"),
}


class _RedactFilter(logging.Filter):
    """Removes anything that looks like a credential from log lines."""
    _pat = re.compile(r"(?i)(key|token|apikey|api_key|authorization|hibp-api-key|x-apikey|x-subscription-token|cx)=([^&\s]+)")
    _hdr = re.compile(r"(?i)\b(authorization|x-subscription-token|x-apikey|hibp-api-key|api-key|key)\s*:\s*(?:bearer\s+)?[^\s,;]+")
    _bearer = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{6,}")

    def filter(self, record):
        from .security import redact  # late import: security imports this module
        msg = record.getMessage()
        msg = self._pat.sub(r"\1=***", msg)
        msg = self._hdr.sub(lambda m: m.group(1) + ": ***", msg)
        msg = self._bearer.sub("Bearer ***", msg)
        record.msg = redact(msg)
        record.args = ()
        return True


def get_logger() -> logging.Logger:
    log = logging.getLogger("tracepoint")
    if not log.handlers:
        log.setLevel(logging.INFO)
        h = RotatingFileHandler(LOGS_DIR / "tracepoint.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        h.addFilter(_RedactFilter())
        log.addHandler(h)
        # quiet noisy libraries; never log request URLs with secrets at debug level
        logging.getLogger("urllib3").setLevel(logging.WARNING)
    return log


IS_WINDOWS = os.name == "nt"
