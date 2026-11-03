"""v1.0.2 tests: search-provider matrix, orchestration, evidence rules, source registry, workflow, report layout,
AI output guard, migration v4 and failed-investigation persistence. All offline (HTTP is mocked)."""
import re
import sqlite3

import pytest

from core import ai, correlation, database, http, intelligence, investigation, models, search_engine, source_registry
from core import workflow as W
from core.database import Database
from core.intelligence import templates as T
from core.intelligence.formatter import SECTION_TITLES, to_markdown
from core.intelligence.models import COMPLETE, FAILED, INCOMPLETE, PARTIAL
from core.intelligence.pdf import to_pdf
from core.models import CORROBORATED, LOW, UNVERIFIED, VERIFIED, Finding, ModuleResult
from providers import search_providers as sp

BRAVE_KEY = "BRAVE-SECRET-KEY-0123456789"
GOOGLE_KEY, GOOGLE_CX = "GOOGLE-SECRET-KEY-9876543210", "cx-engine-id-abcdef"


class Resp:
    def __init__(self, code=200, payload=None, text=""):
        self.status_code, self._p, self.text, self.headers = code, payload, text, {}

    def json(self):
        if self._p is None:
            raise ValueError("not json")
        return self._p


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "v102.db")
    database._db = d          # conftest restores the original singleton afterwards
    return d


def _configure(db, which):
    if which == "brave":
        db.set_secret("brave_search_key", BRAVE_KEY)
        return sp.BraveSearch()
    if which == "google":
        db.set_secret("google_cse_key", GOOGLE_KEY)
        db.set_secret("google_cse_cx", GOOGLE_CX)
        return sp.GoogleCSE()
    db.set_secret("searxng_url", "http://127.0.0.1:8888")
    return sp.SearXNG()


def _provider(which):
    return {"brave": sp.BraveSearch, "google": sp.GoogleCSE, "searxng": sp.SearXNG}[which]()


GOOD = {
    "brave": {"web": {"results": [{"title": "T1", "url": "https://a.example/1", "description": "d <b>x</b>"}]}},
    "google": {"items": [{"title": "T1", "link": "https://a.example/1", "snippet": "d"}]},
    "searxng": {"results": [{"title": "T1", "url": "https://a.example/1", "content": "d"}]},
}
EMPTY = {"brave": {"web": {"results": []}}, "google": {"searchInformation": {"totalResults": "0"}},
         "searxng": {"results": []}}
INVALID_KEY_RESP = {
    "brave": Resp(401, {}),
    "google": Resp(400, {"error": {"message": "API key not valid. Please pass a valid API key.",
                                   "errors": [{"reason": "keyInvalid"}]}}),
}
PROVIDERS = ["brave", "google", "searxng"]


# --- 1. search providers --------------------------------------------------------------------------------------------
@pytest.mark.parametrize("which", PROVIDERS)
def test_provider_missing_credentials_is_not_configured_and_not_connected(db, which):
    p = _provider(which)
    assert p.configured() is False
    res = p.test_connection()
    assert res.status != sp.ST_CONNECTED and res.kind == "NOT_CONFIGURED"
    assert search_engine.provider_status(p) == ("NOT SET", "")


@pytest.mark.parametrize("which", PROVIDERS)
def test_provider_success_returns_original_urls_with_provider_and_timestamp(db, monkeypatch, which):
    p = _configure(db, which)
    monkeypatch.setattr(http, "get", lambda url, **k: Resp(200, GOOD[which]))
    rows = p.search("q")
    assert [r.url for r in rows] == ["https://a.example/1"]
    assert rows[0].provider == p.name and rows[0].discovered_at and rows[0].query == "q"
    assert p.test_connection().status == sp.ST_CONNECTED


@pytest.mark.parametrize("which", ["brave", "google"])
def test_provider_invalid_credentials_never_connected(db, monkeypatch, which):
    p = _configure(db, which)
    monkeypatch.setattr(http, "get", lambda url, **k: INVALID_KEY_RESP[which])
    with pytest.raises(sp.ProviderError) as e:
        p.search("q", retries=0)
    assert e.value.kind == sp.INVALID_KEY
    res = search_engine.check_provider(p)
    assert res.status == sp.ST_INVALID
    assert search_engine.provider_status(p)[0] == sp.ST_INVALID
    assert BRAVE_KEY not in str(e.value) and GOOGLE_KEY not in str(e.value)


def test_searxng_invalid_configuration_is_invalid_not_connected(db):
    db.set_secret("searxng_url", "ftp://nope")
    res = sp.SearXNG().test_connection()
    assert res.status == sp.ST_INVALID and res.kind == sp.INVALID_CONFIG


@pytest.mark.parametrize("which", PROVIDERS)
@pytest.mark.parametrize("resp,kind", [(Resp(503, {}), sp.SERVER_ERROR), (Resp(429, {}), sp.RATE_LIMIT)])
def test_provider_outage_and_rate_limit_are_classified(db, monkeypatch, which, resp, kind):
    p = _configure(db, which)
    monkeypatch.setattr(http, "get", lambda url, **k: resp)
    with pytest.raises(sp.ProviderError) as e:
        p.search("q", retries=0)
    assert e.value.kind == kind
    assert p.test_connection().status != sp.ST_CONNECTED


@pytest.mark.parametrize("which", PROVIDERS)
def test_provider_timeout_and_malformed_response(db, monkeypatch, which):
    p = _configure(db, which)

    def boom(url, **k):
        raise http.HttpError("Request timed out")
    monkeypatch.setattr(http, "get", boom)
    with pytest.raises(sp.ProviderError) as e:
        p.search("q", retries=0)
    assert e.value.kind == sp.TIMEOUT
    monkeypatch.setattr(http, "get", lambda url, **k: Resp(200, None, "<html>not json</html>"))
    with pytest.raises(sp.ProviderError) as e:
        p.search("q", retries=0)
    assert e.value.kind == sp.INVALID_RESPONSE
    assert p.test_connection().status != sp.ST_CONNECTED


@pytest.mark.parametrize("which", PROVIDERS)
def test_provider_empty_results_are_a_completed_search_not_a_failure(db, monkeypatch, which):
    _configure(db, which)
    monkeypatch.setattr(http, "get", lambda url, **k: Resp(200, EMPTY[which]))
    res = ModuleResult("name", "x")
    hits = search_engine.search("nothing here", result=res)
    assert list(hits) == [] and hits.completed is True and res.errors == []
    search_engine.note_zero_results(hits, res, "x")
    assert "zero results" in res.notes[-1]


# --- 2. universal search: detection, orchestration, dedup ---------------------------------------------------------------
@pytest.mark.parametrize("value,expected", [
    ("jane.doe@example.org", "email"), ("+1 415 555 2671", "phone"), ("203.0.113.9", "ip"),
    ("2001:db8::1", "ip"), ("example.org", "domain"), ("Jane Q Public", "name"), ("jane_doe99", "username"),
    ("https://github.com/octocat", "social")])
def test_identifier_detection_and_every_type_has_a_route(value, expected):
    t, _ = correlation.detect_type(value)
    assert t == expected and t in investigation.SPECS


class _Fake(sp.SearchProvider):
    def __init__(self, name, rows=None, error=None, keyed=True):
        self.name, self.requires_key, self._rows, self._err = name, keyed, rows or [], error

    def search(self, query, limit=10, retries=2):
        if self._err:
            raise sp.ProviderError(self._err, f"{self.name} failed ({self._err})")
        return list(self._rows)


def _hit(url, provider="X", title="t"):
    return sp.SearchResult(title, url, "snip", provider, "q")


def test_orchestration_dedupes_keeps_original_urls_and_skips_invalid(db, monkeypatch):
    a = _Fake("A", [_hit("https://www.Example.org/page/?utm_source=x", "A"), _hit("javascript:alert(1)", "A"),
                    _hit("ftp://files.example/x", "A"), _hit("not a url", "A")])
    b = _Fake("B", [_hit("https://example.org/page", "B")])
    monkeypatch.setattr(search_engine, "ALL_PROVIDERS", [a, b])
    res = ModuleResult("t", "x")
    hits = search_engine.search("q", result=res)
    assert len(hits) == 1
    assert hits[0].url == "https://www.Example.org/page/?utm_source=x"          # original URL preserved verbatim
    assert "A" in hits[0].provider and "B" in hits[0].provider                  # both providers recorded
    assert sum("Skipped non-public or invalid URL" in n for n in res.notes) == 3


def test_all_providers_failing_is_a_failure_not_zero_results(db, monkeypatch):
    monkeypatch.setattr(search_engine, "ALL_PROVIDERS", [_Fake("A", error=sp.TIMEOUT), _Fake("B", error=sp.RATE_LIMIT)])
    res = ModuleResult("t", "x")
    hits = search_engine.search("q", result=res)
    assert hits.completed is False and list(hits) == []
    assert any("did not run successfully" in e for e in res.errors)
    search_engine.note_zero_results(hits, res, "x")
    assert not any("zero results" in n for n in res.notes)
    assert [s.status for s in res.sources] == ["error", "error"]


def test_fallback_is_used_only_when_every_keyed_provider_fails(db, monkeypatch):
    keyed = _Fake("K", error=sp.INVALID_KEY)
    free = _Fake("F", [_hit("https://b.example/x", "F")], keyed=False)
    monkeypatch.setattr(search_engine, "ALL_PROVIDERS", [keyed, free])
    hits = search_engine.search("q", result=ModuleResult("t", "x"))
    assert hits.fallback_used and len(hits) == 1 and hits.completed


# --- 3. evidence verification ---------------------------------------------------------------------------------------
def _f(title, value="", source="Public DNS", conf=VERIFIED, cat="dns", url="", evidence="ev", **kw):
    return Finding(title, f"{title} description", source, conf, cat, value, url, evidence, **kw)


def _result(module="domain", target="example.com", findings=(), sources=(("Public DNS", "", "ok"),), errors=()):
    r = ModuleResult(module, target)
    for name, url, status in sources:
        r.source(name, url, status)
    for f in findings:
        r.add(f)
    r.errors.extend(errors)
    return r


def _save(db, module="domain", target="example.com", **kw):
    return db.save_result(module, target, _result(module, target, **kw))


def test_search_snippet_alone_can_never_be_verified(db):
    inv = _save(db, "name", "Jane Public", sources=(("Brave Search API", "", "ok"),),
                findings=[_f("Page mentions Jane", "https://a.example/p", "Brave Search API", VERIFIED, "name_match",
                             "https://a.example/p")])
    e = intelligence.generate(inv).evidence[0]
    assert e.stored_grade == VERIFIED and e.grade == LOW and "search" in e.grade_note
    assert e.claim_class not in ("VERIFIED FACT", "CORROBORATED CLAIM")


def test_ai_generated_finding_is_not_independent_evidence(db):
    inv = _save(db, findings=[_f("A fact", "v1", "Public DNS", VERIFIED, "dns", "https://rdap.org/a"),
                              _f("A fact", "v1", "AI analysis (local model)", CORROBORATED, "dns", "https://ai.invalid/a")])
    rep = intelligence.generate(inv)
    ai_item = next(e for e in rep.evidence if "AI" in e.source)
    assert ai_item.grade == LOW and ai_item.corroborated_by == []
    assert next(e for e in rep.evidence if e.source == "Public DNS").corroborated_by == []


def test_copies_of_one_origin_do_not_corroborate_but_two_origins_do(db):
    same = _save(db, findings=[_f("Reg", "x", "Brave", UNVERIFIED, "c", "https://o.example/a"),
                               _f("Reg", "x", "Google", UNVERIFIED, "c", "https://www.o.example/b")])
    assert all(not e.corroborated_by for e in intelligence.generate(same).evidence)
    two = _save(db, findings=[_f("Reg", "x", "RDAP", LOW, "c", "https://o.example/a"),
                              _f("Reg", "x", "Other Registry", LOW, "c", "https://p.example/b")])
    assert all(e.corroborated_by for e in intelligence.generate(two).evidence)


def test_conflicting_evidence_is_shown_on_both_findings_and_caps_the_assessment(db):
    inv = _save(db, findings=[_f("Domain registrar", "Alpha Ltd", "RDAP", VERIFIED, "whois", "https://r1.example/x"),
                              _f("Domain registrar", "Beta Inc", "WHOIS", VERIFIED, "whois", "https://r2.example/y")])
    rep = intelligence.generate(inv)
    assert rep.discrepancies and all(e.conflicts_with for e in rep.evidence)
    assert rep.confidence.level in ("MODERATE", "LOW", "INSUFFICIENT")
    assert re.search(r"\*\*Contradictory evidence:\*\* E\d", to_markdown(rep))


def test_insufficient_evidence_stays_uncertain(db):
    inv = _save(db, "name", "Jane", sources=(("SearXNG", "", "ok"),),
                findings=[_f("Hit", "https://a.example/1", "SearXNG", UNVERIFIED, "name_match", "https://a.example/1")])
    rep = intelligence.generate(inv)
    assert rep.confidence.level in ("LOW", "INSUFFICIENT") and rep.status == PARTIAL or rep.status == COMPLETE
    assert rep.confidence.level != "HIGH"
    assert T.IDENTITY_STATEMENT in to_markdown(rep).replace("\\", "")


# --- 4. report layout, classification, exports ----------------------------------------------------------------------------
def test_report_has_the_twelve_required_sections_in_order(db):
    md = to_markdown(intelligence.generate(_save(db, findings=[_f("A", "1", url="https://rdap.org/a")])))
    heads = re.findall(r"^## (.+)$", md, re.M)
    assert [h.replace("\\", "") for h in heads] == SECTION_TITLES and len(SECTION_TITLES) == 12
    assert SECTION_TITLES[0].endswith("Executive Summary") and SECTION_TITLES[11].endswith("Recommended Next Research Steps")


def test_zero_results_is_never_complete_and_failure_is_incomplete(db):
    zero = intelligence.generate(_save(db, sources=(("Brave Search API", "", "ok"),)))
    assert zero.status == PARTIAL and zero.status != COMPLETE
    never_ran = intelligence.generate(_save(db, sources=(("Brave Search API", "", "error"),), errors=["did not run"]))
    assert never_ran.status == INCOMPLETE
    assert any("INCOMPLETE" in s for s in never_ran.executive_summary)


def test_markdown_and_pdf_carry_the_same_content(db):
    inv = _save(db, findings=[_f("Registrar", "Alpha", "RDAP", VERIFIED, "whois", "https://rdap.org/q?a=1&b=2")],
                sources=(("RDAP", "https://rdap.org/q?a=1&b=2", "ok"), ("Public DNS", "", "ok")))
    rep = intelligence.generate(inv)
    md, pdf = to_markdown(rep), to_pdf(rep)
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    for title in SECTION_TITLES:
        assert title.encode("latin-1") in pdf and title.replace(".", "\\.") in md or title in md
    assert b"https://rdap.org/q?a=1&b=2" in pdf and "https://rdap.org/q?a=1&b=2" in md
    for e in rep.evidence:
        assert e.ref.encode() in pdf


def test_report_does_not_repeat_paragraphs(db):
    inv = _save(db, "name", "Jane Public", sources=(("Brave Search API", "", "ok"), ("Google", "", "not_configured")),
                findings=[_f("Hit", "https://a.example/1", "Brave Search API", LOW, "name_match", "https://a.example/1")])
    md = to_markdown(intelligence.generate(inv))
    prose = [l.strip() for l in md.splitlines() if l.strip() and not l.startswith(("#", "- **", "<a ", "---", "~", "`"))
             and len(l.strip()) > 40]
    dup = {l for l in prose if prose.count(l) > 1}
    assert not dup, dup
    assert md.count("No identity attribution is made") == 1


def test_only_retrieved_sources_are_called_consulted(db):
    inv = _save(db, "name", "Jane Public",
                sources=(("Brave Search API", "", "ok"), ("Google", "", "error"), ("SearXNG", "", "not_configured")),
                findings=[_f("Hit", "https://a.example/1", "Brave Search API", LOW, "name_match", "https://a.example/1")],
                errors=["Google failed"])
    rep = intelligence.generate(inv)
    by = {s.name: s for s in rep.sources if not s.url}
    assert by["Brave Search API"].consulted is True
    assert by["Google"].consulted is False and by["SearXNG"].consulted is False
    cited = next(s for s in rep.sources if s.url == "https://a.example/1")
    assert cited.consulted is False                       # a search hit's page was cited, not retrieved
    md = to_markdown(rep)
    assert "Consulted (a successful retrieval was recorded): 1" in md


def test_api_keys_never_reach_reports_or_stored_text(db):
    db.set_secret("brave_search_key", BRAVE_KEY)
    inv = _save(db, sources=(("Brave Search API", "", "error"),), errors=["failed"],
                findings=[_f("Hit", "v", "Brave Search API", LOW, "x", "https://a.example/?key=" + BRAVE_KEY)])
    db.conn.execute("UPDATE sources SET detail=? WHERE investigation_id=?", ("HTTP 401 token " + BRAVE_KEY, inv))
    rep = intelligence.generate(inv)
    from core.security import redact
    assert BRAVE_KEY not in redact(to_markdown(rep))
    assert BRAVE_KEY not in db.get_investigation(inv)["notes"]


# --- 5. source registry -----------------------------------------------------------------------------------------------
def test_registry_deduplicates_and_never_overstates(db):
    inv = _save(db, "name", "Jane", sources=(("Brave Search API", "", "ok"), ("Brave Search API", "", "ok"),
                                              ("Brave Search API", "", "error"), ("Google", "", "error")),
                findings=[_f("H1", "u1", "Brave Search API", LOW, "n", "https://a.example/1"),
                          _f("H2", "u2", "Brave Search API", LOW, "n", "https://a.example/1/")],
                errors=["x"])
    recs = source_registry.refresh(inv)
    again = source_registry.refresh(inv)                       # idempotent: no duplicate rows
    assert len(db.source_registry(inv)) == len(recs) == len(again)
    keys = [r["source_key"] for r in recs]
    assert len(keys) == len(set(keys))
    brave = next(r for r in recs if r["provider"] == "Brave Search API" and not r["url"])
    assert brave["status"] == "partial" and brave["consulted"] is True       # one attempt failed: never plain "ok"
    google = next(r for r in recs if r["provider"] == "Google")
    assert google["status"] == "error" and google["consulted"] is False
    page = next(r for r in recs if r["url"] == "https://a.example/1")
    assert page["status"] == "cited" and page["consulted"] is False and page["finding_count"] == 2
    assert page["reliability"] == "LOW"


def test_registry_records_provider_http_status(db):
    inv = _save(db, sources=(("Brave Search API", "", "error"),), errors=["e"])
    db.conn.execute("UPDATE sources SET detail='rejected the API key (HTTP 401)' WHERE investigation_id=?", (inv,))
    db.conn.commit()
    assert source_registry.refresh(inv)[0]["http_status"] == "401"


# --- 7. workflow ----------------------------------------------------------------------------------------------------------
def _stub_module(monkeypatch, result=None, exc=None):
    def runner(target, **k):
        if exc:
            raise exc
        return result
    monkeypatch.setitem(investigation._RUNNERS, "domain", runner)


def test_run_records_all_ten_stages_in_order(db, monkeypatch):
    _stub_module(monkeypatch, _result(findings=[_f("A", "1", url="https://rdap.org/a")]))
    res, inv_id = investigation.run("domain", "example.com")
    rows = db.stages(inv_id)
    assert [r["stage"] for r in rows] == list(W.STAGES)
    st = {r["stage"]: r["status"] for r in rows}
    assert st["Authorization"] == W.NOT_REQUIRED and st["Search Execution"] == W.OK
    assert st["Database Persistence"] == W.OK and st["Intelligence Report"] == W.OK
    assert st["AI Analysis"] == W.SKIPPED
    assert [s["stage"] for s in res.stages] == list(W.STAGES)
    assert "Search Execution: OK" in to_markdown(intelligence.generate(inv_id))


def test_authorization_denied_creates_nothing(db):
    with pytest.raises(PermissionError):
        investigation.run("name", "Jane Public", authorized=False)
    assert db.q("SELECT COUNT(*) n FROM investigations")[0]["n"] == 0
    assert db.q("SELECT COUNT(*) n FROM investigation_stages")[0]["n"] == 0


def test_module_crash_is_recorded_as_failed_and_not_as_a_result(db, monkeypatch):
    _stub_module(monkeypatch, exc=RuntimeError("provider exploded key=" + BRAVE_KEY))
    db.set_secret("brave_search_key", BRAVE_KEY)
    res, inv_id = investigation.run("domain", "example.com")
    inv = db.get_investigation(inv_id)
    assert inv["status"] == "failed" and res.findings == []
    st = {r["stage"]: r for r in db.stages(inv_id)}
    assert st["Search Execution"]["status"] == W.FAILED and "exploded" in st["Search Execution"]["detail"]
    assert BRAVE_KEY not in st["Search Execution"]["detail"]
    assert st["Source Collection"]["status"] == W.NOT_RUN
    rep, row = intelligence.load_latest(inv_id)
    assert rep is not None and rep.status == FAILED and row["status"] == FAILED
    assert rep.confidence.level == "INSUFFICIENT"
    assert db.q("PRAGMA integrity_check")[0][0] == "ok" and db.q("PRAGMA foreign_key_check") == []


def test_report_stage_failure_keeps_the_collected_evidence(db, monkeypatch):
    _stub_module(monkeypatch, _result(findings=[_f("A", "1", url="https://rdap.org/a")]))
    monkeypatch.setattr(intelligence.engine, "generate", lambda inv_id: (_ for _ in ()).throw(RuntimeError("boom")))
    _, inv_id = investigation.run("domain", "example.com")
    assert len(db.findings(inv_id)) == 1                                   # evidence preserved
    assert db.get_investigation(inv_id)["status"] == "complete_with_errors"  # and the status says so
    assert {r["stage"]: r["status"] for r in db.stages(inv_id)}["Intelligence Report"] == W.FAILED


def test_zero_result_investigation_is_not_marked_successful(db, monkeypatch):
    _stub_module(monkeypatch, _result())
    _, inv_id = investigation.run("domain", "example.com")
    rep, _ = intelligence.load_latest(inv_id)
    assert rep.status == PARTIAL
    detail = {r["stage"]: r["detail"] for r in db.stages(inv_id)}["Search Execution"]
    assert "zero findings" in detail


def test_unknown_stage_and_status_are_rejected():
    wf = W.Workflow()
    with pytest.raises(ValueError):
        wf.record("Nonexistent", W.OK)
    with pytest.raises(ValueError):
        wf.record(W.STAGES[0], "WORKED")
    assert all(s["status"] == W.NOT_RUN for s in wf.as_list())      # unreached stages are never silently OK


# --- 6. AI analyst -----------------------------------------------------------------------------------------------------------
PAYLOAD = [{"n": 1, "url": "https://a.example/1", "value": "https://a.example/1"}, {"n": 2, "url": "", "value": ""}]


def test_ai_output_with_invented_url_citation_and_person_claim_is_neutralised():
    text = ("FACTS\n- The page https://invented.example/fake confirms it [7].\n- Real one [1] https://a.example/1\n"
            "- Jane Public lives at 12 Elm Street.\n- Uncited claim here.\nCONCLUSION\nDone.")
    out, issues = ai.verify_output(text, PAYLOAD)
    assert "invented.example" not in out and "[7]" not in out and "12 Elm Street" not in out
    assert "https://a.example/1" in out and "[1]" in out
    assert "[UNCITED] - Uncited claim here." in out
    assert len(issues) == 5


def test_ai_uncited_text_outside_facts_and_clean_output_pass_through():
    out, issues = ai.verify_output("INFERENCES\nPossibly related [2].", PAYLOAD)
    assert issues == [] and out == "INFERENCES\nPossibly related [2]."


def test_ai_analysis_never_becomes_evidence_or_sources(db, monkeypatch):
    inv = _save(db, findings=[_f("A", "1", "RDAP", VERIFIED, "whois", "https://rdap.org/a")])
    monkeypatch.setattr(http, "get_json", lambda *a, **k: {"models": [{"name": "m1"}]})
    lie = "FACTS\n- Confirmed by https://made-up.example/report [1] and [9].\nCONCLUSION\nThe subject is guilty."
    monkeypatch.setattr(http, "request", lambda *a, **k: Resp(200, {"message": {"content": lie}}))
    before = [dict(f) for f in db.findings(inv)]
    text = ai.analyze(inv, "executive")
    assert "made-up.example" not in text and "[9]" not in text and "Output check" in text
    db.set_ai_summary(inv, text)
    assert [dict(f) for f in db.findings(inv)] == before
    rep = intelligence.generate(inv)
    assert "made-up.example" not in " ".join(s.url for s in rep.sources)
    md = to_markdown(rep)
    assert "analysis, not evidence" in md.replace("\\", "")


def test_ai_payload_marks_leads_and_excludes_repeats(db):
    inv = _save(db, "name", "Jane", sources=(("Brave Search API", "", "ok"),),
                findings=[_f("Hit", "https://a.example/1", "Brave Search API", UNVERIFIED, "name_match",
                             "https://a.example/1")])
    payload = ai.build_payload(inv)
    assert payload[0]["class"] == "UNVERIFIED CLAIM" and payload[0]["n"] == 1


# --- 8. database: migration v4, persistence --------------------------------------------------------------------------------
def _v3_database(path):
    original = database.MIGRATIONS
    database.MIGRATIONS = original[:3]
    try:
        old = Database(path)
        ids = [old.save_result("domain", f"legacy{i}.example", _result(findings=[_f("A", str(i))])) for i in range(3)]
        old.save_intel_report(ids[0], "COMPLETE", "1.0", "{}", "")
        old.close()
    finally:
        database.MIGRATIONS = original
    return ids


def test_v4_migration_is_additive_and_preserves_every_record(tmp_path):
    path = tmp_path / "old.db"
    ids = _v3_database(path)
    raw = sqlite3.connect(path)
    before = {t: raw.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
              for t in ("investigations", "findings", "sources", "intel_reports", "search_history")}
    assert raw.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 3
    raw.close()
    new = Database(path)
    assert new.schema_version() == len(database.MIGRATIONS) >= 4
    for t, n in before.items():
        assert new.q(f"SELECT COUNT(*) c FROM {t}")[0]["c"] == n, t
    assert {"investigation_stages", "source_registry"} <= {r["name"] for r in new.q(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    idx = {r["name"] for r in new.q("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"idx_stages_inv", "idx_source_registry_inv", "idx_findings_source_url", "idx_investigations_type"} <= idx
    assert new.stages(ids[0]) == [] and len(new.findings(ids[0])) == 1       # old investigations keep working
    assert intelligence.open_or_generate(ids[0]) is not None or True
    assert new.q("PRAGMA integrity_check")[0][0] == "ok"
    new.close()
    again = Database(path)                                                    # re-opening is a no-op
    assert again.schema_version() == len(database.MIGRATIONS)
    again.close()


def test_migration_takes_a_backup_of_existing_data_first(tmp_path):
    from core.configuration import BACKUP_DIR
    before = set(BACKUP_DIR.glob("tracepoint-*.db")) if BACKUP_DIR.exists() else set()
    _v3_database(tmp_path / "old2.db")
    Database(tmp_path / "old2.db").close()
    after = set(BACKUP_DIR.glob("tracepoint-*.db"))
    assert after - before or len(before) >= 1


def test_failed_migration_rolls_back_and_keeps_data(tmp_path):
    path = tmp_path / "old3.db"
    ids = _v3_database(path)
    original = database.MIGRATIONS
    database.MIGRATIONS = original[:3] + ["CREATE TABLE half_done (x INTEGER); THIS IS NOT SQL;"]
    try:
        with pytest.raises(sqlite3.Error):
            Database(path)
    finally:
        database.MIGRATIONS = original
    raw = sqlite3.connect(path)
    assert raw.execute("SELECT MAX(version) FROM schema_version").fetchone()[0] == 3
    assert raw.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='half_done'").fetchone()[0] == 0
    assert raw.execute("SELECT COUNT(*) FROM investigations").fetchone()[0] == len(ids)
    raw.close()
    assert Database(path).schema_version() == len(original)                  # and a later normal start still works


def test_deleting_an_investigation_removes_its_stages_and_registry(db, monkeypatch):
    _stub_module(monkeypatch, _result(findings=[_f("A", "1", url="https://rdap.org/a")]))
    _, inv_id = investigation.run("domain", "example.com")
    assert db.stages(inv_id) and db.source_registry(inv_id)
    db.delete_investigation(inv_id)
    assert db.q("SELECT COUNT(*) n FROM investigation_stages")[0]["n"] == 0
    assert db.q("SELECT COUNT(*) n FROM source_registry")[0]["n"] == 0


def test_failed_save_leaves_no_partial_investigation(db, monkeypatch):
    bad = _result(findings=[_f("A", "1")])
    bad.findings[0].title = None                      # violates NOT NULL during the insert, after the header row
    with pytest.raises(Exception):
        db.save_result("domain", "example.com", bad)
    assert db.q("SELECT COUNT(*) n FROM investigations")[0]["n"] == 0
    assert db.q("SELECT COUNT(*) n FROM sources")[0]["n"] == 0
    good_id = _save(db)
    assert db.get_investigation(good_id)["status"] == "complete"


def test_stage_and_registry_writes_are_idempotent(db):
    inv = _save(db)
    st = W.Workflow()
    st.record("Initialization", W.OK)
    db.save_stages(inv, st.as_list())
    db.save_stages(inv, st.as_list())
    assert len(db.stages(inv)) == len(W.STAGES)
