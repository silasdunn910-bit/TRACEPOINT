"""Phase 5 tests: Ollama, AI labelling, reports end-to-end, generic-infrastructure correlation,
zero-result vs never-ran notes, HIBP failure handling, log redaction, DB migration on a copy of real data.
All offline / mocked."""
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("HOME", tempfile.mkdtemp())

import pytest

from core import ai, configuration, correlation, database, http, models, reports, search_engine
from core.database import Database

ROOT = Path(__file__).resolve().parent.parent


class Resp:
    def __init__(self, code=200, payload=None, text=""):
        self.status_code, self._p, self.text, self.headers = code, payload, text, {}

    def json(self):
        if self._p is None:
            raise ValueError("not json")
        return self._p


@pytest.fixture
def db(monkeypatch):
    d = Database(Path(tempfile.mktemp(suffix=".db")))
    monkeypatch.setattr(database, "_db", d)
    return d


def _investigation(db):
    r = models.ModuleResult("username", "<b>evil</b>")
    r.add(models.Finding("Profile <script>alert(1)</script>", "d", "Site", models.VERIFIED, "profiles",
                         "v", "https://example.org/u", "ev", "lim-text"))
    r.add(models.Finding("Blocked check", "HTTP 403", "Other", models.INCONCLUSIVE, "profiles-inconclusive",
                         limitations="automated check blocked"))
    r.add(models.Finding("legacy", "d", "Src", "STRONG"))
    r.source("Other", "https://other.example/x", "blocked", "blocked or unavailable (HTTP 403)")
    r.source("Site", "https://example.org/u", "ok", "found")
    return db.save_result("username", "<b>evil</b>", r)


# --- Ollama ------------------------------------------------------------------------
def test_ollama_offline_is_graceful(db, monkeypatch):
    monkeypatch.setattr(http, "get_json", lambda *a, **k: (_ for _ in ()).throw(http.HttpError("Could not connect")))
    ok, models_, err = ai.status()
    assert ok is False and models_ == [] and "connect" in err.lower()
    with pytest.raises(RuntimeError, match="not reachable"):
        ai.analyze(_investigation(db))


def test_ollama_model_discovery_and_selection(db, monkeypatch):
    monkeypatch.setattr(http, "get_json", lambda *a, **k: {"models": [{"name": "llama3:8b"}, {"name": "qwen2.5-coder:7b"}, {}]})
    ok, found, _ = ai.status()
    assert ok and found == ["llama3:8b", "qwen2.5-coder:7b"]
    assert ai.selected_model(found) == "qwen2.5-coder:7b"  # preferred model
    db.set_setting("ollama_model", "llama3:8b")
    assert ai.selected_model(found) == "llama3:8b"  # explicit choice wins
    db.set_setting("ollama_model", "not-installed")
    assert ai.selected_model(found) == "qwen2.5-coder:7b"  # stale choice ignored
    assert ai.selected_model([]) == ""


@pytest.mark.parametrize("bad", [[], "x", {"models": "x"}, {"models": None}])
def test_ollama_unexpected_tags_reply_is_offline_not_crash(monkeypatch, db, bad):
    monkeypatch.setattr(http, "get_json", lambda *a, **k: bad)
    ok, found, err = ai.status()
    assert (ok, found) == (False, [])


def test_ollama_online_analysis_is_labelled_and_not_evidence(db, monkeypatch):
    inv = _investigation(db)
    before = [dict(f) for f in db.findings(inv)]
    monkeypatch.setattr(http, "get_json", lambda *a, **k: {"models": [{"name": "m1"}]})
    monkeypatch.setattr(http, "request", lambda *a, **k: Resp(200, {"message": {"content": "FACTS: x [1]"}}))
    text = ai.analyze(inv)
    assert text.startswith("[AI analysis by local model m1") and "verify before relying" in text
    db.set_ai_summary(inv, text)
    after = [dict(f) for f in db.findings(inv)]
    assert after == before  # AI output never becomes a finding
    assert all(f["source"] != "m1" and "AI" not in f["confidence"] for f in after)
    rep = reports.build(inv)
    assert rep["ai_analysis"] == text and "unverified" in reports.to_txt(rep).lower()
    assert "local model" in reports.to_html(rep) and "unverified" in reports.to_html(rep)


def test_ollama_bad_replies_raise_clear_errors(db, monkeypatch):
    inv = _investigation(db)
    monkeypatch.setattr(http, "get_json", lambda *a, **k: {"models": [{"name": "m1"}]})
    for reply, msg in [(Resp(200, None), "unreadable"), (Resp(200, {"message": {"content": "  "}}), "empty"),
                       (Resp(500, {}, "boom"), "HTTP 500")]:
        monkeypatch.setattr(http, "request", lambda *a, _r=reply, **k: _r)
        with pytest.raises(RuntimeError, match=msg):
            ai.analyze(inv)


# --- reports -------------------------------------------------------------------------------
def test_reports_written_to_one_directory_reopen_and_escape(db, monkeypatch, tmp_path):
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    inv = _investigation(db)
    db.set_secret("brave_search_key", "SUPERSECRETVALUE123")
    paths = {f: reports.save(inv, f) for f in ("html", "json", "txt")}
    for f, p in paths.items():
        assert p.parent == tmp_path and p.is_file() and p.stat().st_size > 0
    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data["investigation"]["id"].startswith("TP-")
    confs = {f["confidence"] for f in data["findings"]}
    assert {"VERIFIED", "INCONCLUSIVE"} <= confs
    html_text = paths["html"].read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html_text and "&lt;script&gt;" in html_text
    assert "<b>evil</b>" not in html_text
    assert 'href="https://example.org/u"' in html_text
    assert "lim-text" in html_text and "blocked" in html_text.lower()
    for p in paths.values():
        assert "SUPERSECRETVALUE123" not in p.read_text(encoding="utf-8")
    assert "INCONCLUSIVE" in paths["txt"].read_text(encoding="utf-8")
    # summary counts agree with the findings, legacy STRONG counted as CORROBORATED
    assert data["findings"] and len(data["findings"]) == 3
    assert "1 CORROBORATED" in data["conclusion"] and "1 INCONCLUSIVE" in data["conclusion"]


# --- correlation: generic infrastructure ---------------------------------------------------------
@pytest.mark.parametrize("etype,value,generic", [
    ("domain", "gmail.com", True), ("domain", "alt1.gmail-smtp-in.l.google.com", True),
    ("domain", "ns1.cloudflare.com", True), ("domain", "mycompany-example.org", False),
    ("domain", "notgmail.com", False), ("ip", "1.1.1.1", True), ("ip", "203.0.113.9", False),
    ("email", "a@gmail.com", False), ("phone", "+13365550100", False),
])
def test_generic_infrastructure_flag(etype, value, generic):
    assert correlation.is_generic_infrastructure(etype, value) is generic


def test_shared_entities_flags_generic_but_keeps_specific(db):
    for t in ("a", "b"):
        r = models.ModuleResult("domain", t)
        r.entity(models.E_DOMAIN, "gmail.com", models.VERIFIED)
        r.entity(models.E_DOMAIN, "specific-shared.example", models.VERIFIED)
        db.save_result("domain", t, r)
    rows = {e["value"]: e for e in correlation.shared_entities(2)}
    assert rows["gmail.com"]["generic"] is True and rows["specific-shared.example"]["generic"] is False


# --- search outcome notes -------------------------------------------------------------------------
def test_zero_results_note_only_for_completed_searches():
    done = search_engine.SearchResults([], completed=True)
    never = search_engine.SearchResults([], completed=False)
    r1, r2 = models.ModuleResult("t", "x"), models.ModuleResult("t", "x")
    search_engine.note_zero_results(done, r1, "the thing")
    search_engine.note_zero_results(never, r2, "the thing")
    assert r1.notes and "zero results" in r1.notes[0]
    assert r2.notes == []


# --- HIBP failures never read as "clean" -------------------------------------------------------------
@pytest.mark.parametrize("resp", [Resp(401, {}), Resp(429, {}), Resp(503, {}), Resp(200, None), Resp(200, {"x": 1})])
def test_hibp_failure_is_an_error_not_a_clean_result(db, monkeypatch, resp):
    from modules import email_intel
    db.set_secret("hibp_key", "hibp-key-123456")
    monkeypatch.setattr(email_intel.dp, "dns_query", lambda *a, **k: [])
    monkeypatch.setattr(http, "get", lambda url, **k: resp if "haveibeenpwned" in url else Resp(404, {}))
    out = email_intel.investigate("someone@example.org", web_search=False)
    assert any("HIBP" in e and "unknown" in e for e in out.errors)
    assert not [f for f in out.findings if f.category == "breach"]
    assert not any("No breaches listed" in f.title for f in out.findings)


# --- log redaction ----------------------------------------------------------------------------------
def test_log_filter_redacts_credentials():
    rec = logging.LogRecord("t", logging.INFO, "", 0, "GET https://x/y?key=ABC123SECRET&cx=CXSECRET&q=1 hibp-api-key=ZZTOP", (), None)
    configuration._RedactFilter().filter(rec)
    msg = rec.getMessage()
    assert "ABC123SECRET" not in msg and "CXSECRET" not in msg and "ZZTOP" not in msg and "q=1" in msg


def test_existing_log_contains_no_stored_credential_values():
    log = ROOT / "logs" / "tracepoint.log"
    if not log.exists():
        pytest.skip("no log")
    text = log.read_text(encoding="utf-8", errors="replace")
    import re
    assert not re.search(r"(?i)(?:key|token|apikey|cx)=(?!\*\*\*)[A-Za-z0-9_\-]{8,}", text)


# --- database migration on a copy of real data (read-only source) ---------------------------------------
def test_migration_on_copy_of_real_database_preserves_records(tmp_path):
    src = ROOT / "data" / "tracepoint.db"
    if not src.exists():
        pytest.skip("no real database")
    import sqlite3
    ro = sqlite3.connect(f"file:{src.as_posix()}?mode=ro", uri=True)
    before = {t: ro.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for t in ("investigations", "findings", "entities", "relationships", "sources", "reports")}
    ro.close()
    copy = tmp_path / "copy.db"
    shutil.copy(src, copy)
    d = Database(copy)
    for t, n in before.items():
        assert d.q(f"SELECT COUNT(*) c FROM {t}")[0]["c"] == n, t
    assert d.q("PRAGMA integrity_check")[0][0] == "ok"
    assert d.q("PRAGMA foreign_key_check") == []
    d.close()
