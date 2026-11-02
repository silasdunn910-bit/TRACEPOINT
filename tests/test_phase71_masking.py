"""Phase 7.1: credentials are masked everywhere they could be displayed, logged or exported."""
import io
import json
import logging

import pytest
from rich.console import Console

from core import credentials, reports
from core.database import Database
from core.models import ModuleResult, Finding
from core.security import MASK_DOTS, mask, redact, register_secret

LETTERS = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghijklmnopqrstuvwxyz"


def _secret(n: int) -> str:
    # all distinct leading characters so any leaked fragment is detectable
    return (LETTERS * 3)[:n]


@pytest.mark.parametrize("n", [1, 5, 6, 7, 8, 9, 10, 12, 16, 19])
def test_short_and_medium_credentials_are_fully_masked(n):
    v = _secret(n)
    m = mask(v)
    assert m == MASK_DOTS
    assert not any(v[i:i + 2] in m for i in range(len(v) - 1))


@pytest.mark.parametrize("n", [20, 24, 32, 40, 64, 200])
def test_long_credentials_reveal_at_most_the_last_four_characters(n):
    v = _secret(n)
    m = mask(v)
    assert m.startswith(MASK_DOTS) and m.endswith(v[-4:])
    shown = m[len(MASK_DOTS):]
    assert len(shown) <= 4 and len(shown) <= 0.2 * len(v)
    assert v[:-4] not in m and v[:4] not in m


def test_masking_does_not_reveal_length_for_non_revealing_values():
    assert len({mask(_secret(n)) for n in range(1, 20)}) == 1


def test_empty_value_masks_to_empty():
    assert mask("") == "" and mask(None) == ""


def test_searxng_url_shows_only_scheme_host_port():
    shown = credentials.display_value("searxng_url", "https://search.example.org:8443/secret-path-token")
    assert shown == "https://search.example.org:8443"
    assert "secret-path-token" not in shown


def test_other_credentials_use_mask_in_display_value():
    assert credentials.display_value("brave_search_key", "BRAVE-KEY-123") == MASK_DOTS
    assert credentials.display_value("brave_search_key", "") == ""


# --- terminal output: the API Configuration screen -----------------------------------------------
def test_api_configuration_screen_never_prints_credentials(monkeypatch):
    import main
    from core.database import get_db
    db = get_db()
    secrets = {"brave_search_key": _secret(12), "hibp_key": _secret(24), "virustotal_key": _secret(40),
               "ipinfo_token": _secret(7), "abuseipdb_key": _secret(64)}
    for k, v in secrets.items():
        db.set_secret(k, v)
    buf = io.StringIO()
    from ui.theme import THEME
    monkeypatch.setattr(main, "console", Console(file=buf, width=220, force_terminal=False, color_system=None, theme=THEME))
    monkeypatch.setattr(main, "ask", lambda *a, **k: "")  # leave the screen immediately
    main.api_config()
    out = buf.getvalue()
    for k, v in secrets.items():
        shown_tail = v[-4:] if len(v) >= 20 else ""
        body = out.replace(shown_tail, "") if shown_tail else out
        assert v not in out, k
        assert v[:6] not in body, k          # no leading fragment
        assert v[:-4] not in body, k
    assert MASK_DOTS in out


# --- error / confirmation messages --------------------------------------------------------------
@pytest.mark.parametrize("raw", [_secret(3), "has space inside token", "ctrl\x07char-secretvalue", "x" * 600])
def test_validation_errors_never_echo_the_value(raw):
    _, err = credentials.validate_credential("brave_search_key", raw)
    assert err
    for chunk in (raw.strip(), raw[:8]):
        assert chunk not in err


def test_save_and_remove_messages_do_not_contain_the_value(tmp_path):
    db = Database(tmp_path / "t.db")
    value = "UNIQUE-SECRET-VALUE-9f8e7d"
    ok, msg = credentials.save_credential(db, "hibp_key", value)
    assert ok and value not in msg
    ok, msg = credentials.remove_credential(db, "hibp_key", lambda: True)
    assert ok and value not in msg


# --- logs ---------------------------------------------------------------------------------------
def _filtered(msg: str) -> str:
    from core import configuration
    rec = logging.LogRecord("t", logging.INFO, "", 0, msg, (), None)
    configuration._RedactFilter().filter(rec)
    return rec.getMessage()


@pytest.mark.parametrize("line", [
    "GET https://x/y?key=SUPERSECRETKEY1&q=1",
    "GET https://x/y?token=SUPERSECRETKEY1",
    "GET https://x/y?foo=1&cx=SUPERSECRETKEY1",
    "Authorization: Bearer SUPERSECRETKEY1",
    "headers {'X-Subscription-Token': 'x'} X-Subscription-Token: SUPERSECRETKEY1",
    "hibp-api-key: SUPERSECRETKEY1",
    "x-apikey=SUPERSECRETKEY1",
    "retrying with Bearer SUPERSECRETKEY1 after 429",
])
def test_log_filter_redacts_credential_shapes(line):
    assert "SUPERSECRETKEY1" not in _filtered(line)


def test_log_filter_redacts_known_stored_values_even_without_a_label():
    register_secret("Zq8-unlabelled-stored-secret")
    assert "Zq8-unlabelled-stored-secret" not in _filtered("provider said: invalid key Zq8-unlabelled-stored-secret!")


def test_a_secret_echoed_by_a_remote_error_is_not_written_to_the_log_file():
    from core.http import log
    register_secret("Echoed-Remote-Secret-77")
    log.info("remote error: %s", "bad credential Echoed-Remote-Secret-77")
    for h in logging.getLogger("tracepoint").handlers:
        h.flush()
        path = h.baseFilename
    text = open(path, encoding="utf-8").read()
    assert "Echoed-Remote-Secret-77" not in text and "remote error" in text


def test_redact_helper():
    register_secret("abcdef-secret-1")
    assert redact("a abcdef-secret-1 b abcdef-secret-1") == "a *** b ***"
    assert redact("") == "" and redact("no secrets here") == "no secrets here"
    register_secret("short")  # shorter than the minimum: ignored to avoid mangling ordinary text
    assert redact("short text") == "short text"


# --- reports and persisted text -------------------------------------------------------------------
def test_secrets_never_reach_stored_error_text_or_any_report_format(tmp_path, monkeypatch):
    db = Database(tmp_path / "t.db")
    secret = "Report-Leak-Canary-4242"
    db.set_secret("hibp_key", secret)
    db.set_secret("brave_search_key", secret + "-b")
    res = ModuleResult("email", "someone@example.org")
    res.add(Finding("Plain finding", "value", "src", "LOW", "cat"))
    res.source("HIBP", "https://haveibeenpwned.com", "error", f"HTTP 401 for key {secret}")
    res.notes.append(f"remote said: invalid credential {secret}-b")
    inv_id = db.save_result("email", res.target, res)
    monkeypatch.setattr(reports, "get_db", lambda: db)
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    blobs = [json.dumps(reports.build(inv_id), default=str)]
    for fmt in ("txt", "json", "html"):
        blobs.append(reports.save(inv_id, fmt).read_text(encoding="utf-8"))
    raw_db = db.conn.execute("SELECT group_concat(secret) FROM api_config").fetchone()[0]
    for blob in blobs:
        assert secret not in blob
    assert secret not in raw_db  # encrypted at rest as well
    row = db.q("SELECT detail FROM sources WHERE investigation_id=?", (inv_id,))[0]
    assert secret not in row["detail"] and "***" in row["detail"]
