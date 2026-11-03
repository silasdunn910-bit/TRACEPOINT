"""Universal Intelligence Report Engine (core.intelligence)."""
from __future__ import annotations

import json
import re

import pytest

from core import database, intelligence, investigation, reports
from core.database import Database
from core.intelligence import confidence as C
from core.intelligence import engine
from core.intelligence import evidence_analyzer as A
from core.intelligence import templates as T
from core.intelligence.formatter import SECTION_TITLES, md_url, to_markdown
from core.intelligence.models import (ANALYTICAL_INFERENCE, COMPLETE, CONTRADICTORY, CORROBORATED_CLAIM, FAILED,
                                      INCOMPLETE, PARTIAL, SINGLE_SOURCE_CLAIM, UNVERIFIED_CLAIM, VERIFIED_FACT,
                                      Inference, IntelligenceReport)
from core.intelligence.pdf import to_pdf
from core.models import LOW, MODERATE, UNVERIFIED, VERIFIED, Finding, ModuleResult

ODD_URL = "https://example.org/a_b/c?x=1&y=*z*&q=(paren)#frag"


@pytest.fixture
def db(tmp_path):
    d = Database(tmp_path / "intel.db")
    database._db = d          # conftest restores the original singleton afterwards
    return d


def _result(module="domain", target="example.com", findings=(), sources=(("Public DNS", "", "ok"),), errors=()):
    r = ModuleResult(module, target)
    for name, url, status in sources:
        r.source(name, url, status)
    for f in findings:
        r.add(f)
    r.errors.extend(errors)
    return r


def _save(db, module, target, **kw) -> int:
    return db.save_result(module, target, _result(module, target, **kw))


def _f(title, value="", source="Public DNS", conf=VERIFIED, cat="dns", url="", evidence="ev", **kw):
    return Finding(title, f"{title} description", source, conf, cat, value, url, evidence, **kw)


# --- universal integration: every investigation type, and future ones --------------------------------------------
TYPES = list(investigation.SPECS) + ["organization"]


@pytest.mark.parametrize("inv_type", TYPES)
def test_report_for_every_investigation_type(db, inv_type):
    inv_id = _save(db, inv_type, f"target-{inv_type}", findings=[_f("Observed value", "v1", url="https://rdap.org/x")])
    rep = intelligence.generate(inv_id)
    assert rep.overview["investigation_type"] == inv_type
    assert rep.overview["family"] == T.profile_for(inv_type).family
    md = to_markdown(rep)
    for title in SECTION_TITLES:
        assert title in md, title
    assert to_pdf(rep).startswith(b"%PDF-1.4")


@pytest.mark.parametrize("inv_type", list(investigation.SPECS))
def test_run_generates_and_stores_report_for_every_type(db, monkeypatch, inv_type):
    monkeypatch.setitem(investigation._RUNNERS, inv_type,
                        lambda t, **k: _result(inv_type, t, findings=[_f("Thing", "x")]))
    _, inv_id = investigation.run(inv_type, "subject", authorized=True)
    row = db.latest_intel_report(inv_id)
    # court/registry results without stored coverage data must not claim complete coverage
    assert row is not None and row["status"] == (PARTIAL if inv_type in ("court", "registry") else COMPLETE)
    rep, _ = intelligence.load_latest(inv_id)
    assert rep.overview["reference"] == db.get_investigation(inv_id)["ref"]


def test_future_type_uses_cautious_generic_profile():
    p = T.profile_for("organization")
    assert p is T.GENERIC_PROFILE and p.identity_sensitive


def test_run_can_skip_report_and_persist_false_creates_nothing(db, monkeypatch):
    monkeypatch.setitem(investigation._RUNNERS, "domain", lambda t, **k: _result("domain", t))
    _, inv_id = investigation.run("domain", "example.com", intel_report=False)
    assert db.latest_intel_report(inv_id) is None
    _, none_id = investigation.run("domain", "example.com", persist=False)
    assert none_id is None and db.q("SELECT COUNT(*) n FROM intel_reports")[0]["n"] == 0


# --- empty results / completeness ---------------------------------------------------------------------------------
def test_empty_investigation_with_no_sources_is_incomplete_and_insufficient(db):
    inv_id = _save(db, "domain", "empty.example", sources=())
    rep = intelligence.generate(inv_id)
    assert rep.status == INCOMPLETE and rep.confidence.level == "INSUFFICIENT"
    assert rep.key_findings == [] and rep.evidence == []
    md = to_markdown(rep)
    assert "No findings were recorded" in md and T.ABSENCE_STATEMENT in md


def test_zero_results_from_responding_sources_is_never_complete(db):
    # v1.0.2 rule: a search that ran and found nothing is not a successful investigation (was COMPLETE before).
    rep = intelligence.generate(_save(db, "ip", "203.0.113.9"))
    assert rep.status == PARTIAL and rep.confidence.level == "INSUFFICIENT"
    assert any("zero findings" in r for r in rep.status_reasons)


@pytest.mark.parametrize("status,expected", [("error", INCOMPLETE), ("blocked", INCOMPLETE),
                                             ("not_configured", PARTIAL), ("skipped", PARTIAL), ("manual", PARTIAL)])
def test_source_failures_are_never_shown_as_success(db, status, expected):
    inv_id = _save(db, "ip", "203.0.113.9", sources=(("Public DNS", "", "ok"), ("Other", "", status)),
                   findings=[_f("A", "1")])
    rep = intelligence.generate(inv_id)
    assert rep.status == expected
    if expected == INCOMPLETE:
        assert any("INCOMPLETE" in s for s in rep.executive_summary)


def test_module_errors_make_report_incomplete(db):
    rep = intelligence.generate(_save(db, "email", "a@example.com", errors=["lookup failed"], findings=[_f("A", "1")]))
    assert rep.status == INCOMPLETE and rep.confidence.level != "HIGH"


def test_records_coverage_drives_completeness():
    def built(cov):
        return {"investigation": {"status": "complete"}, "sources_consulted": [{"name": "x", "status": "ok"}],
                "records_review": {"search_coverage": {"status": cov, "summary": "s"}}}
    assert C.completeness(built("NONE"))[0] == INCOMPLETE
    assert C.completeness(built("PARTIAL"))[0] == PARTIAL
    assert C.completeness(built("NOT RECORDED"))[0] == PARTIAL
    assert C.completeness(built("COMPLETE"))[0] == COMPLETE


# --- evidence integrity -------------------------------------------------------------------------------------------
def test_missing_source_metadata_is_reported_not_fabricated(db):
    bare = Finding("Bare claim", "desc", "Some Service", MODERATE, "profile", "val", "", "", discovered_at="")
    rep = intelligence.generate(_save(db, "username", "handle", findings=[bare]))
    e = rep.evidence[0]
    assert (e.source_url, e.retrieved_at, e.published_at, e.evidence) == ("", "", "", "")
    assert {"no source URL recorded", "no retrieval timestamp recorded", "no supporting evidence text recorded",
            "publication date not provided by the source"} <= set(e.metadata_gaps)
    md = to_markdown(rep)
    assert "**Source URL:** not recorded" in md and "**Retrieved:** not recorded" in md
    assert "**Published:** not provided by source" in md


def test_every_finding_keeps_full_provenance(db):
    f = _f("Dated", "v", source="Brave Search", conf=LOW, cat="name_match", url=ODD_URL, evidence="snippet text",
           published_at="2024-05-01", query='"Ada" biography')
    inv_id = _save(db, "name", "Ada", findings=[f])
    e = intelligence.generate(inv_id).evidence[0]
    stored = db.findings(inv_id)[0]
    assert (e.source, e.source_url, e.retrieved_at, e.published_at, e.evidence, e.query) == (
        stored["source"], stored["source_url"], stored["discovered_at"], "2024-05-01", "snippet text", '"Ada" biography')
    assert e.finding_id == stored["id"] and e.stored_grade == LOW


def test_source_urls_preserved_exactly_in_every_output(db):
    inv_id = _save(db, "domain", "example.com", findings=[_f("Odd", "v", url=ODD_URL)])
    rep = intelligence.generate(inv_id)
    assert rep.evidence[0].source_url == ODD_URL
    assert ODD_URL in json.dumps(rep.to_dict())
    assert f"<{ODD_URL}>" in to_markdown(rep)
    assert ODD_URL in _pdf_uris(to_pdf(rep))
    intelligence.generate_and_store(inv_id)          # survives storage + reopen unchanged
    assert intelligence.load_latest(inv_id)[0].evidence[0].source_url == ODD_URL


def test_unsafe_urls_are_kept_but_never_made_clickable(db):
    bad = "javascript:alert(1)"
    rep = intelligence.generate(_save(db, "social", "x", findings=[_f("Bad", "v", url=bad)]))
    md = to_markdown(rep)
    assert f"`{bad}`" in md and f"<{bad}>" not in md and md_url(bad) == f"`{bad}`"
    assert bad not in _pdf_uris(to_pdf(rep))


def test_markdown_escapes_third_party_text(db):
    rep = intelligence.generate(_save(db, "name", "x", findings=[_f("[click](http://evil) <script>", "v")]))
    md = to_markdown(rep)
    assert "[click](http://evil)" not in md and "<script>" not in md


# --- corroboration and duplicates ---------------------------------------------------------------------------------
def test_independent_origins_corroborate():
    items = _analyse([_f("Geo (a)", "FR", "ip-api", LOW, "geo"), _f("Geo (b)", "FR", "ipdata", LOW, "geo")])
    assert [e.claim_class for e in items] == [CORROBORATED_CLAIM, CORROBORATED_CLAIM]
    assert items[0].corroborated_by == ["E2"]


def test_same_origin_repeat_is_a_duplicate_not_corroboration():
    items = _analyse([_f("Reg date", "2020-01-01", "RDAP", MODERATE, "registration", "https://rdap.org/d"),
                      _f("Registry event: registration", "2020-01-01", "RDAP", MODERATE, "registration",
                         "https://rdap.org/d2")])
    assert items[1].duplicate_of == "E1" and not items[0].corroborated_by
    assert items[0].claim_class == SINGLE_SOURCE_CLAIM
    assert C.class_counts(items)["total"] == 1 and C.class_counts(items)["duplicates"] == 1


def test_same_page_via_two_search_engines_is_one_origin():
    items = _analyse([_f("Hit 1", "page", "Brave Search", LOW, "contextual_match", "https://site.example/p"),
                      _f("Hit 2", "page", "Google Programmable Search", LOW, "contextual_match", "https://site.example/p")])
    assert not any(e.corroborated_by for e in items) and items[1].duplicate_of == "E1"


def test_unverified_leads_are_never_upgraded_by_repetition():
    items = _analyse([_f("Name hit", "Ada Lovelace", "Brave Search", UNVERIFIED, "name_match", "https://a.example/1"),
                      _f("Name hit", "Ada Lovelace", "SearXNG", UNVERIFIED, "name_match", "https://b.example/2")])
    assert all(e.claim_class == UNVERIFIED_CLAIM for e in items)


def test_duplicate_findings_across_merge_are_counted_once(db):
    r = _result(findings=[_f("MX record", "mx.example.com", cat="mail")])
    r.merge(_result(findings=[_f("MX record", "mx.example.com", cat="mail")]))
    rep = intelligence.generate(db.save_result("domain", "example.com", r))
    assert rep.confidence.counts["total"] == 1


# --- contradictions -----------------------------------------------------------------------------------------------
def test_conflicting_single_valued_attribute(db):
    rep = intelligence.generate(_save(db, "domain", "example.com", findings=[
        _f("Domain registrar", "Registrar A", "RDAP", cat="registration", url="https://rdap.org/a"),
        _f("Domain registrar", "Registrar B", "Other WHOIS", cat="registration", url="https://w.example/b")]))
    assert len(rep.discrepancies) == 1 and rep.discrepancies[0].evidence_refs == ["E1", "E2"]
    assert all(e.claim_class == CONTRADICTORY for e in rep.evidence)
    assert rep.evidence[0].conflicts_with == ["E2"]
    assert rep.confidence.level in ("MODERATE", "LOW") and rep.confidence.caps
    assert any("Which value is correct?" in q for q in rep.unresolved_questions)


def test_module_reported_contradiction_listed_once(db):
    rep = intelligence.generate(_save(db, "ip", "203.0.113.1", findings=[
        _f("Geolocation providers disagree on country", "FR, US", "Cross-provider comparison", VERIFIED, "contradiction")]))
    assert len(rep.discrepancies) == 1 and rep.discrepancies[0].detected_by == "collecting module"
    assert rep.evidence[0].claim_class == CONTRADICTORY


def test_presence_absence_conflict():
    items = _analyse([_f("No SPF record", "none", cat="email-auth"), _f("SPF record present", "v=spf1 -all", cat="email-auth")])
    assert all(e.claim_class == CONTRADICTORY for e in items)


def test_correlation_strings_not_otherwise_detected_are_kept():
    d = A.find_discrepancies([], ["Something odd: details"])
    assert d[0].description == "Something odd: details" and d[0].evidence_refs == []


# --- unsupported conclusions --------------------------------------------------------------------------------------
@pytest.mark.parametrize("text", ["The subject is a criminal.", "This is the same person.", "Identity confirmed.",
                                  "He is dangerous", "She lives at 1 Main St", "They are likely guilty"])
def test_guard_rejects_unsupported_conclusions(text):
    with pytest.raises(T.UnsupportedConclusion):
        T.guard(text)


def test_standing_statements_pass_the_guard():
    for text in [T.CORRELATION_CAVEAT, T.IDENTITY_STATEMENT, T.CONDUCT_STATEMENT, T.ABSENCE_STATEMENT, *T.ENGINE_LIMITS]:
        T.guard(text)
    for note, alts in list(T.CATEGORY_NOTES.values()) + [T.RECORD_CATEGORY_NOTE, T.DEFAULT_NOTE]:
        for t in [note, *alts]:
            T.guard(t)


def test_inference_without_evidence_or_with_prohibited_claim_is_discarded():
    rejected = []
    assert A._keep(Inference("Unsupported pattern.", []), rejected) is None
    assert A._keep(Inference("The subject is a criminal.", ["E1"]), rejected) is None
    assert len(rejected) == 2 and A._keep(Inference("Fine.", ["E1"]), rejected)


def test_allegation_in_unverified_lead_is_not_promoted(db):
    lead = _f("John Doe convicted of fraud", "https://news.example/x", "Brave Search", UNVERIFIED, "name_match",
              "https://news.example/x")
    rep = intelligence.generate(_save(db, "name", "John Doe", findings=[lead]))
    assert not any("convicted" in s for s in rep.executive_summary)
    assert rep.key_findings[0].claim_class == UNVERIFIED_CLAIM
    assert T.CONDUCT_STATEMENT in rep.confidence.identity_statement
    for inf in rep.assessment:
        T.guard(inf.statement)


def test_engine_refuses_to_publish_a_prohibited_engine_statement(db, monkeypatch):
    monkeypatch.setattr(T.PROFILES["domain"], "next_steps", ["Conclude the owner is a criminal."])
    inv_id = _save(db, "domain", "example.com")
    with pytest.raises(T.UnsupportedConclusion):
        intelligence.generate(inv_id)
    report, row = intelligence.generate_and_store(inv_id)
    assert report is None and db.latest_intel_report(inv_id)["status"] == FAILED


def test_analytical_findings_are_classed_as_inference():
    items = _analyse([_f("Independent sources report: employer", "ACME", "Analyst comparison", UNVERIFIED,
                         "independently_corroborated")])
    assert items[0].claim_class == ANALYTICAL_INFERENCE


def test_shared_entities_are_correlation_with_caveat(db):
    for target in ("a.example", "b.example"):
        r = _result(target=target, findings=[_f("NS", "ns1.uniquehost.example")])
        r.entity("domain", "ns1.uniquehost.example")
        r.entity("domain", "gmail.com")
        db.save_result("domain", target, r)
    rep = intelligence.generate(db.list_investigations()[0]["id"])
    corr = [i for i in rep.assessment if i.kind == "correlation"]
    assert any("also appears in 1 other investigation" in i.statement and i.caveat == T.CORRELATION_CAVEAT for i in corr)
    assert any("gmail.com is shared infrastructure" in i.statement for i in corr)


# --- confidence calculation ---------------------------------------------------------------------------------------
def _items(*classes):
    items = A.build_registry([{"category": "c", "title": f"t{i}", "source": "s", "confidence": "VERIFIED",
                               "source_url": f"https://s.example/{i}"} for i in range(len(classes))], [])[0]
    for e, c in zip(items, classes):
        e.claim_class = c
    return items


@pytest.mark.parametrize("classes,status,disc,level", [
    ((), COMPLETE, 0, "INSUFFICIENT"),
    ((VERIFIED_FACT, VERIFIED_FACT, SINGLE_SOURCE_CLAIM), COMPLETE, 0, "HIGH"),
    ((VERIFIED_FACT, SINGLE_SOURCE_CLAIM, UNVERIFIED_CLAIM), COMPLETE, 0, "MODERATE"),
    ((UNVERIFIED_CLAIM, SINGLE_SOURCE_CLAIM), COMPLETE, 0, "LOW"),
    ((VERIFIED_FACT, VERIFIED_FACT), COMPLETE, 1, "MODERATE"),
    ((VERIFIED_FACT, VERIFIED_FACT), INCOMPLETE, 0, "MODERATE"),
    ((VERIFIED_FACT, VERIFIED_FACT), PARTIAL, 0, "HIGH"),
    ((UNVERIFIED_CLAIM,), INCOMPLETE, 1, "LOW"),
])
def test_confidence_levels(classes, status, disc, level):
    assert C.assess(_items(*classes), status, disc, False).level == level


def test_assessment_never_raises_stored_grades(db):
    inv_id = _save(db, "ip", "203.0.113.2", findings=[_f("Geo", "FR", "ip-api", LOW, "geo"),
                                                      _f("Geo2", "FR", "ipdata", LOW, "geo")])
    rep = intelligence.generate(inv_id)
    assert [e.stored_grade for e in rep.evidence] == [r["confidence"] for r in db.findings(inv_id)] == [LOW, LOW]


# --- generation failures ------------------------------------------------------------------------------------------
def test_generation_failure_is_stored_and_does_not_break_investigation(db, monkeypatch):
    monkeypatch.setitem(investigation._RUNNERS, "domain", lambda t, **k: _result("domain", t, findings=[_f("A", "1")]))
    monkeypatch.setattr(engine, "generate",
                        lambda inv_id: (_ for _ in ()).throw(RuntimeError("boom token=abcdef123456 Bearer sekret-xyz-123")))
    result, inv_id = investigation.run("domain", "example.com")
    assert result.findings and db.get_investigation(inv_id)
    report, row = intelligence.load_latest(inv_id)
    assert report is None and row["status"] == FAILED and "boom" in row["error"]
    assert "abcdef123456" not in row["error"] and "sekret-xyz-123" not in row["error"]
    with pytest.raises(intelligence.ReportUnavailable, match="boom"):
        intelligence.export(inv_id, "md")


def test_generate_for_missing_investigation(db):
    with pytest.raises(ValueError):
        intelligence.generate(999)
    assert intelligence.generate_and_store(999) == (None, None)


def test_unknown_export_format_rejected(db):
    with pytest.raises(ValueError):
        intelligence.export(_save(db, "domain", "example.com"), "docx")


# --- export, storage, reopen --------------------------------------------------------------------------------------
@pytest.mark.parametrize("fmt", ["md", "pdf"])
def test_export_writes_registers_and_leaves_no_temp_file(db, fmt):
    inv_id = _save(db, "domain", "example.com", findings=[_f("A record", "192.0.2.1", url="https://rdap.org/x")])
    intelligence.generate_and_store(inv_id)
    path = reports.save(inv_id, fmt)          # unified entry point delegates md/pdf to the engine
    assert path.is_file() and path.name.endswith(f"-intel.{fmt}")
    assert not list(path.parent.glob("*.tmp"))
    row = next(r for r in db.reports() if r["format"] == f"intel-{fmt}")
    assert row["exists"] and row["path"] == str(path)
    if fmt == "pdf":
        _assert_valid_pdf(path.read_bytes())
    else:
        assert "## 1. Executive Summary" in path.read_text(encoding="utf-8")


def test_legacy_formats_unchanged(db):
    inv_id = _save(db, "domain", "example.com", findings=[_f("A", "1")])
    for fmt in ("txt", "json", "html"):
        assert reports.save(inv_id, fmt).suffix == f".{fmt}"


def test_pdf_is_well_formed_multi_page_and_handles_unicode(db):
    many = [_f(f"Finding {i} — café → ✓ 東京", f"v{i}", url=f"https://h{i}.example/p") for i in range(60)]
    pdf = to_pdf(intelligence.generate(_save(db, "domain", "example.com", findings=many)))
    pages = _assert_valid_pdf(pdf)
    assert pages > 3 and b"caf\\351" in pdf and b"->" in pdf   # cp1252 octal escape; arrow substituted


def test_reopen_returns_stored_snapshot_and_legacy_investigations_get_one(db):
    inv_id = _save(db, "domain", "example.com", findings=[_f("A", "1")])
    assert db.latest_intel_report(inv_id) is None            # saved without the engine (pre-feature data)
    rep, row = intelligence.open_or_generate(inv_id)
    again, row2 = intelligence.open_or_generate(inv_id)
    assert row["id"] == row2["id"] and again.to_dict() == rep.to_dict()
    assert isinstance(IntelligenceReport.from_dict(json.loads(row["payload"])), IntelligenceReport)
    assert [r["investigation_id"] for r in db.list_intel_reports()] == [inv_id]


def test_deleting_investigation_removes_its_reports(db):
    inv_id = _save(db, "domain", "example.com")
    intelligence.generate_and_store(inv_id)
    db.delete_investigation(inv_id)
    assert db.q("SELECT COUNT(*) n FROM intel_reports")[0]["n"] == 0


def test_v3_migration_preserves_existing_data(tmp_path):
    path, original = tmp_path / "old.db", database.MIGRATIONS
    database.MIGRATIONS = original[:2]
    try:
        old = Database(path)
        old_id = old.save_result("domain", "legacy.example", _result(findings=[_f("A", "1")]))
        old.close()
    finally:
        database.MIGRATIONS = original
    new = Database(path)
    assert new.schema_version() == len(original)
    assert len(new.findings(old_id)) == 1 and new.latest_intel_report(old_id) is None
    new.close()


# --- user interface -----------------------------------------------------------------------------------------------
def test_ui_view_links_evidence_exports_and_returns(db, monkeypatch):
    import main
    inv_id = _save(db, "domain", "example.com", findings=[_f("[bold red]injected[/]", "1", url=ODD_URL)])
    answers = iter(["E1", "S1", "E99", "md", "pdf", "regenerate", ""])
    monkeypatch.setattr(main, "ask", lambda *a, **k: next(answers))
    with main.console.capture() as cap:
        main.intel_report_view(inv_id)
    out = cap.get()
    for title in SECTION_TITLES:
        assert title in out
    assert "EVIDENCE E1" in out and "SOURCE S1" in out and "No such evidence" in out
    assert "[bold red]injected[/]" in out                    # stored text is shown literally, not as markup
    assert {r["format"] for r in db.reports()} >= {"intel-md", "intel-pdf"}
    assert len(db.q("SELECT id FROM intel_reports WHERE investigation_id=?", (inv_id,))) == 2   # opened + regenerated


def test_ui_shows_incomplete_and_failed_reports_honestly(db):
    from ui import report_view
    from ui.theme import THEME
    from rich.console import Console
    c = Console(width=120, record=True, theme=THEME)
    rep = intelligence.generate(_save(db, "ip", "203.0.113.3", sources=(("AbuseIPDB", "", "error"),)))
    c.print(report_view.brief_panel(rep, {}))
    c.print(report_view.brief_panel(None, {"error": "RuntimeError: x"}))
    text = c.export_text()
    assert "INCOMPLETE - not a successful investigation" in text and "INTELLIGENCE REPORT FAILED" in text


def test_menu_lists_and_opens_reports(db, monkeypatch):
    import main
    inv_id = _save(db, "domain", "example.com")
    intelligence.generate_and_store(inv_id)
    answers = iter([str(inv_id), ""])
    monkeypatch.setattr(main, "ask", lambda *a, **k: next(answers))
    monkeypatch.setattr(main, "db", db)
    with main.console.capture() as cap:
        main.intel_reports_menu()
    assert "INTELLIGENCE REPORTS" in cap.get() and "1. Executive Summary" in cap.get()
    assert "intel" in main.DISPATCH and any(k == "intel" for _, k, _ in main.ACTIONS)


def test_run_and_show_prints_report_brief(db, monkeypatch):
    import main
    monkeypatch.setitem(investigation._RUNNERS, "domain", lambda t, **k: _result("domain", t, findings=[_f("A", "1")]))
    monkeypatch.setattr(main, "db", db)
    monkeypatch.setattr(main, "post_investigation", lambda inv_id: None)
    with main.console.capture() as cap:
        main.run_and_show("domain", "example.com")
    assert "INTELLIGENCE REPORT" in cap.get() and "Evidence assessment" in cap.get()


# --- helpers ------------------------------------------------------------------------------------------------------
def _analyse(findings: list[Finding]):
    dicts = [f.to_dict() for f in findings]
    items, _ = A.build_registry(dicts, [])
    A.group_claims(items, dicts)
    A.classify_claims(items, A.find_discrepancies(items, []))
    return items


def _pdf_uris(pdf: bytes) -> list[str]:
    out = []
    for m in re.finditer(rb"/URI \(((?:\\.|[^\\)])*)\)", pdf):
        raw = re.sub(rb"\\([0-7]{3})", lambda x: bytes([int(x.group(1), 8)]), m.group(1))
        out.append(re.sub(rb"\\(.)", rb"\1", raw).decode("utf-8"))
    return out


def _assert_valid_pdf(pdf: bytes) -> int:
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    startxref = int(re.search(rb"startxref\n(\d+)\n%%EOF", pdf).group(1))
    assert pdf[startxref:startxref + 4] == b"xref"
    count = int(re.match(rb"xref\n0 (\d+)\n", pdf[startxref:]).group(1))
    entries = re.findall(rb"(\d{10}) 00000 n ", pdf[startxref:])
    assert len(entries) == count - 1
    for i, off in enumerate(entries, 1):
        assert pdf[int(off):].startswith(f"{i} 0 obj".encode()), i
    for m in re.finditer(rb"<< /Length (\d+) >>\nstream\n", pdf):
        end = m.end() + int(m.group(1))
        assert pdf[end:end + 10] == b"\nendstream"
    kids = int(re.search(rb"/Type /Pages /Kids \[[^\]]*\] /Count (\d+)", pdf).group(1))
    assert kids == len(re.findall(rb"/Type /Page /Parent", pdf))
    return kids
