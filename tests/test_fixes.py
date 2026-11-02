"""Regression tests for the 2026-11-02 re-audit fixes.

Offline only — no network. Run with:  python tests/test_fixes.py
or:  python -m pytest tests/ -v
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("HOME", tempfile.mkdtemp())

import dns.resolver

from core import database
from core.database import Database


def fresh_db() -> Database:
    db = Database(Path(tempfile.mktemp(suffix=".db")))
    database._db = db
    return db


# --- report HTML must never render javascript:/data: links ------------------
def test_report_href_scheme_allowlist():
    from core.reports import safe_href
    assert safe_href("https://example.com/a") == "https://example.com/a"
    assert safe_href("http://example.com/a") == "http://example.com/a"
    for bad in ("javascript:alert(1)", "data:text/html,<script>x</script>", "file:///C:/x", "/relative", ""):
        assert safe_href(bad) == "", f"unsafe href allowed: {bad!r}"


# --- resolver failure is not evidence of an absent record -------------------
class _FakeResolver:
    def __init__(self, exc):
        self.exc = exc

    def resolve(self, *args, **kwargs):
        raise self.exc


def test_dns_no_answer_is_empty_but_failure_raises():
    from providers import domain_providers as dp
    original = dp._resolver
    try:
        dp._resolver = _FakeResolver(dns.resolver.NoAnswer())
        assert dp.dns_query("example.com", "TXT") == []
        dp._resolver = _FakeResolver(dns.resolver.NoNameservers())
        try:
            dp.dns_query("example.com", "TXT")
            assert False, "NoNameservers should propagate"
        except dns.resolver.NoNameservers:
            pass
    finally:
        dp._resolver = original


def test_reverse_dns_failure_raises():
    from providers import domain_providers as dp
    original = dp._resolver
    try:
        dp._resolver = _FakeResolver(dns.resolver.NoAnswer())
        assert dp.reverse_dns("203.0.113.5") == []
        dp._resolver = _FakeResolver(dns.resolver.NoNameservers())
        try:
            dp.reverse_dns("203.0.113.5")
            assert False, "NoNameservers should propagate"
        except dns.resolver.NoNameservers:
            pass
    finally:
        dp._resolver = original


# --- security module must not invent "missing SPF/DMARC" on resolver failure -
def test_security_skips_email_auth_scoring_when_dns_fails():
    fresh_db()
    from core.http import HttpError
    from modules import security_intel

    orig_auth = security_intel.domain_intel.email_auth_records
    orig_rdap = security_intel.dp.rdap_domain

    def fake_auth(domain, res, *a, **k):
        res.source("Public DNS (SPF/DMARC/DKIM)", "", "error", "NoNameservers")
        res.errors.append("DNS email-auth lookup failed: NoNameservers")

    def fake_rdap(domain):
        raise HttpError("rdap unavailable")

    try:
        security_intel.domain_intel.email_auth_records = fake_auth
        security_intel.dp.rdap_domain = fake_rdap
        res = security_intel.investigate("example.com")
        titles = {f.title for f in res.findings}
        assert not any(t.startswith("Weak email auth") for t in titles), titles
        assert any("skipped" in n for n in res.notes), res.notes
    finally:
        security_intel.domain_intel.email_auth_records = orig_auth
        security_intel.dp.rdap_domain = orig_rdap


# --- DMARC enforcement test must not be fooled by an unrelated finding ------
def test_security_dmarc_enforcement_check_is_scoped_correctly():
    fresh_db()
    from core.http import HttpError
    from core.models import Finding, VERIFIED
    from modules import security_intel

    orig_auth = security_intel.domain_intel.email_auth_records
    orig_rdap = security_intel.dp.rdap_domain

    def fake_auth(domain, res, *a, **k):
        res.source("Public DNS (SPF/DMARC/DKIM)", "", "ok")
        res.add(Finding("SPF record present", "spf", "DNS", VERIFIED, "email-auth", "v=spf1 -all"))
        res.add(Finding("DMARC record present", "dmarc", "DNS", VERIFIED, "email-auth", "v=DMARC1; p=none"))
        # An unrelated finding containing the enforcing keyword must NOT count.
        res.add(Finding("Some other note", "other", "DNS", VERIFIED, "other", "p=quarantine"))

    def fake_rdap(domain):
        raise HttpError("rdap unavailable")

    try:
        security_intel.domain_intel.email_auth_records = fake_auth
        security_intel.dp.rdap_domain = fake_rdap
        res = security_intel.investigate("example.com")
        titles = {f.title for f in res.findings}
        assert "DMARC present but not enforcing" in titles, titles
    finally:
        security_intel.domain_intel.email_auth_records = orig_auth
        security_intel.dp.rdap_domain = orig_rdap


# --- username checks: anti-bot challenge is inconclusive, not "found" -------
class _FakeResponse:
    def __init__(self, status_code=200, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


def test_username_challenge_page_is_blocked_not_absent():
    from modules import username_intel

    orig_get = username_intel.http.get
    try:
        username_intel.http.get = lambda *a, **k: _FakeResponse(
            200, "<html><head><title>Client Challenge</title></head><body>cf-chl</body></html>")
        site = next(s for s in username_intel.SITES if s.name == "PyPI")
        out = username_intel.check_site(site, "some_user")
        assert out["state"] == "blocked", out
        assert "challenge" in out["detail"].lower()
    finally:
        username_intel.http.get = orig_get


def test_username_reddit_json_metadata_is_read():
    from modules import username_intel

    orig_get = username_intel.http.get
    try:
        username_intel.http.get = lambda *a, **k: _FakeResponse(
            200, "{}", {"kind": "t2", "data": {"name": "spez", "created_utc": 1, "total_karma": 5}})
        site = next(s for s in username_intel.SITES if s.name == "Reddit")
        out = username_intel.check_site(site, "spez")
        assert out["state"] == "found", out
        assert str(out["meta"].get("karma")) == "5", out["meta"]
    finally:
        username_intel.http.get = orig_get


# --- subdomain attribution needs a label boundary --------------------------
def test_certificate_hostname_requires_label_boundary():
    from modules.domain_intel import name_in_domain
    assert name_in_domain("www.example.com", "example.com")
    assert name_in_domain("example.com", "example.com")
    assert not name_in_domain("notexample.com", "example.com")
    assert not name_in_domain("example.com.evil.test", "example.com")


# --- config/.env is actually loaded (documented behavior) ------------------
def test_env_file_loading_and_precedence():
    import core.configuration as cfg

    p = Path(tempfile.mkdtemp()) / ".env"
    p.write_text("TP_TEST_A=hello\n# comment\nBAD LINE\nTP_TEST_B='quoted value'\n", encoding="utf-8")
    os.environ.pop("TP_TEST_A", None)
    os.environ.pop("TP_TEST_B", None)
    os.environ["TP_TEST_C"] = "already-set"
    try:
        cfg._load_env_file(p)
        assert os.environ["TP_TEST_A"] == "hello"
        assert os.environ["TP_TEST_B"] == "quoted value"
        # Pre-existing environment variables win.
        p2 = Path(tempfile.mkdtemp()) / ".env"
        p2.write_text("TP_TEST_C=from-file\n", encoding="utf-8")
        cfg._load_env_file(p2)
        assert os.environ["TP_TEST_C"] == "already-set"
    finally:
        for k in ("TP_TEST_A", "TP_TEST_B", "TP_TEST_C"):
            os.environ.pop(k, None)


# --- database creates its parent directory ---------------------------------
def test_database_creates_parent_directory():
    p = Path(tempfile.mkdtemp()) / "nested" / "deeper" / "tracepoint.db"
    db = Database(p)
    try:
        assert p.exists()
    finally:
        db.close()


# --- Universal Search: names route to identifier modules, never a dead end --
def test_person_name_detected_exact_input():
    from core.correlation import detect_type
    itype, reason = detect_type("Jameson Ward Wright")
    assert itype == "name", (itype, reason)


class _FakePrompt:
    answers = []

    @classmethod
    def ask(cls, *a, **k):
        return cls.answers.pop(0)


def test_name_routing_screen_has_navigation_and_explains_limits():
    import io
    from rich.console import Console
    import main

    old_console, old_prompt, old_route = main.console, main.Prompt, main._route_name_query
    routed = []
    buf = io.StringIO()
    try:
        main.console = Console(file=buf, theme=main.THEME, force_terminal=False, width=120)
        main.Prompt = _FakePrompt
        main._route_name_query = lambda inv, label, example: routed.append((inv, label))
        _FakePrompt.answers = ["1", "0"]
        result = main._name_routing_screen("Jameson Ward Wright")
        text = buf.getvalue()
        assert result == "menu"
        assert routed == [("email", "Email address")], routed
        for expected in ("NAME DETECTED", "authorized identifier-based", "Email Intelligence",
                         "Phone Intelligence", "Username Intelligence", "Social Intelligence",
                         "Return to Universal Search", "Return to Main Menu"):
            assert expected in text, expected
        assert "NOT SUPPORTED" not in text
    finally:
        main.console, main.Prompt, main._route_name_query = old_console, old_prompt, old_route


def test_name_routing_screen_can_return_to_universal_search():
    import io
    from rich.console import Console
    import main

    old_console, old_prompt = main.console, main.Prompt
    buf = io.StringIO()
    try:
        main.console = Console(file=buf, theme=main.THEME, force_terminal=False, width=120)
        main.Prompt = _FakePrompt
        _FakePrompt.answers = ["8"]
        assert main._name_routing_screen("Jameson Ward Wright") == "universal"
    finally:
        main.console, main.Prompt = old_console, old_prompt


def test_universal_search_exact_name_reaches_routing_not_rejection():
    import io
    from rich.console import Console
    import main
    from core import database

    old_db, old_ask, old_route, old_console = main.db, main.ask, main._name_routing_screen, main.console
    buf = io.StringIO()
    temp_db = Database(Path(tempfile.mktemp(suffix=".db")))
    database._db = temp_db
    main.db = temp_db
    seen = {}
    try:
        main.console = Console(file=buf, theme=main.THEME, force_terminal=False, width=120)
        main.ask = lambda *a, **k: "Jameson Ward Wright"
        main._name_routing_screen = lambda name: (seen.setdefault("name", name), "menu")[1]
        main.universal_search()
        assert seen.get("name") == "Jameson Ward Wright", seen
        assert "NOT SUPPORTED" not in buf.getvalue()
        row = temp_db.q("SELECT query, detected_type FROM search_history ORDER BY id DESC LIMIT 1")[0]
        assert row["query"] == "Jameson Ward Wright"
        assert row["detected_type"] == "name"
    finally:
        main.db, main.ask, main._name_routing_screen, main.console = old_db, old_ask, old_route, old_console
        temp_db.close()


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}"); passed += 1
        except Exception:
            print(f"FAIL {fn.__name__}"); traceback.print_exc(); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
