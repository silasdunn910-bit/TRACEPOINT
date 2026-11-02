"""Offline regression coverage for Name Intelligence; no public queries are sent."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core import database
from core.database import Database
from core.models import ModuleResult
from modules import name_intel, name_matching
from modules.name_matching import Claim
from providers import name_search
from providers.search_providers import SearchResult


def _fake_hit(title="Ada Lovelace biography", url="https://example.org/ada", snippet="Ada Lovelace was a mathematician"):
    return SearchResult(title, url, snippet, "Fake Search", '"Ada Lovelace"')


def test_name_normalization_and_variant():
    assert name_matching.normalize_name("  Élodie O’Neil-Smith ") == "élodie oneilsmith"
    assert "Elodie O’Neil-Smith" in name_matching.alternate_spellings("Élodie O’Neil-Smith")


def test_duplicate_sources_across_queries_are_removed():
    original_active = name_search.search_engine.active_providers
    original_search = name_search.search_engine.search
    try:
        name_search.search_engine.active_providers = lambda: [type("P", (), {"requires_key": True})()]
        name_search.search_engine.search = lambda *a, **k: [_fake_hit(url="https://www.example.org/ada?utm_source=x")]
        rows = name_search.search_name("Ada Lovelace")
        assert len(rows) == 1
    finally:
        name_search.search_engine.active_providers = original_active
        name_search.search_engine.search = original_search


def test_identical_names_do_not_merge_candidate_claims():
    claims = [Claim("candidate-A", "employer", "Analytical Engine Co", "https://a.example/x"),
              Claim("candidate-B", "employer", "Different Org", "https://b.example/x")]
    assert name_matching.corroborated_claims(claims) == []
    assert name_matching.contradictory_claims(claims) == []


def test_independent_source_corroboration():
    claims = [Claim("candidate-1", "role", "Professor", "https://university.edu/people/a"),
              Claim("candidate-1", "role", "Professor", "https://news.example.org/a")]
    confirmed = name_matching.corroborated_claims(claims)
    assert len(confirmed) == 1
    assert confirmed[0]["domains"] == ["example.org", "university.edu"]


def test_same_domain_is_not_independent():
    claims = [Claim("candidate-1", "role", "Professor", "https://www.example.org/a"),
              Claim("candidate-1", "role", "Professor", "https://news.example.org/b")]
    assert name_matching.corroborated_claims(claims) == []


def test_contradictory_claims_are_reported_with_sources():
    claims = [Claim("candidate-1", "employer", "Org A", "https://a.example/x"),
              Claim("candidate-1", "employer", "Org B", "https://b.example/x")]
    found = name_matching.contradictory_claims(claims)
    assert len(found) == 1 and found[0]["field"] == "employer"


def test_missing_publication_date_is_unknown_not_fabricated():
    original_active = name_search.search_engine.active_providers
    original_search = name_search.search_engine.search
    try:
        name_search.search_engine.active_providers = lambda: [type("P", (), {"requires_key": True})()]
        name_search.search_engine.search = lambda *a, **k: [_fake_hit()]
        out = name_intel.investigate("Ada Lovelace", context="historical biography")
        assert out.findings[0].published_at == ""
        assert any("dates were not supplied" in n for n in out.notes)
    finally:
        name_search.search_engine.active_providers = original_active
        name_search.search_engine.search = original_search


def test_unavailable_configured_search_provider_is_reported():
    original = name_search.search_engine.active_providers
    try:
        name_search.search_engine.active_providers = lambda: []
        out = name_intel.investigate("Ada Lovelace")
        assert out.findings == []
        assert out.sources[0].status == "not_configured"
    finally:
        name_search.search_engine.active_providers = original


def test_provider_error_is_recorded_without_aborting_investigation():
    original_active = name_search.search_engine.active_providers
    original_search = name_search.search_engine.search
    try:
        name_search.search_engine.active_providers = lambda: [type("P", (), {"requires_key": True})()]
        def unavailable(*args, **kwargs):
            raise RuntimeError("provider unavailable")
        name_search.search_engine.search = unavailable
        out = name_intel.investigate("Ada Lovelace")
        assert out.findings == []
        assert out.errors and "provider unavailable" in out.errors[0]
    finally:
        name_search.search_engine.active_providers = original_active
        name_search.search_engine.search = original_search


def test_invalid_search_results_are_skipped():
    original_active = name_search.search_engine.active_providers
    original_search = name_search.search_engine.search
    try:
        name_search.search_engine.active_providers = lambda: [type("P", (), {"requires_key": True})()]
        name_search.search_engine.search = lambda *a, **k: [
            SearchResult("Bad scheme", "javascript:alert(1)", "Ada Lovelace", "Fake", "q"),
            object(), _fake_hit(),
        ]
        out = name_intel.investigate("Ada Lovelace")
        assert len(out.findings) == 1
        assert any("Skipped an invalid result" in n for n in out.notes)
    finally:
        name_search.search_engine.active_providers = original_active
        name_search.search_engine.search = original_search


def test_existing_database_persists_name_provenance_without_losing_investigation():
    path = Path(__import__("tempfile").mktemp(suffix=".db"))
    original_migrations = database.MIGRATIONS
    database.MIGRATIONS = original_migrations[:1]
    v1 = Database(path)
    old_id = v1.save_result("domain", "legacy.example", ModuleResult("domain", "legacy.example"))
    v1.close()
    database.MIGRATIONS = original_migrations
    db = Database(path)  # apply the additive v2 migration to an existing v1 record
    old = database._db
    database._db = db
    try:
        row = _fake_hit()
        out = ModuleResult("name", "Ada Lovelace")
        out.add(__import__("core.models", fromlist=["Finding"]).Finding(
            title=row.title, description="Public search result", source=row.provider,
            category="contextual_match", value=row.url, source_url=row.url, evidence=row.snippet,
            query=row.query, source_type="professional_biography", published_at=""))
        inv_id = db.save_result("name", "Ada Lovelace", out)
        saved = dict(db.findings(inv_id)[0])
        assert saved["source_url"] == row.url and saved["query"] == row.query
        assert saved["source_type"] == "professional_biography" and saved["published_at"] == ""
        assert db.get_investigation(inv_id)["target"] == "Ada Lovelace"
        assert db.get_investigation(old_id)["target"] == "legacy.example"
    finally:
        database._db = old
        db.close()


def test_unrelated_results_remain_unresolved_and_candidates_are_not_joined():
    original_active = name_search.search_engine.active_providers
    original_search = name_search.search_engine.search
    try:
        name_search.search_engine.active_providers = lambda: [type("P", (), {"requires_key": True})()]
        name_search.search_engine.search = lambda *a, **k: [_fake_hit("Lovelace society history", "https://a.example/x", "Historical archive")]
        out = name_intel.investigate("Ada Lovelace")
        assert out.findings[0].category == "unresolved_candidate"
        assert out.entities == []
    finally:
        name_search.search_engine.active_providers = original_active
        name_search.search_engine.search = original_search


def test_runner_authorization_persistence_and_exportable_reports():
    import json
    import tempfile
    from core import investigation
    from core.models import Finding
    from core import reports

    path = Path(tempfile.mktemp(suffix=".db"))
    db = Database(path)
    previous_db = database._db
    previous_active = name_search.search_engine.active_providers
    previous_search = name_search.search_engine.search
    database._db = db
    name_search.search_engine.active_providers = lambda: [type("P", (), {"requires_key": True})()]
    name_search.search_engine.search = lambda *a, **k: [SearchResult(
        "Ada Lovelace biography", "https://university.edu/ada", "Ada Lovelace biography", "Fake Search",
        '"Ada Lovelace"', published_at="1843-01-01")]
    try:
        try:
            investigation.run("name", "Ada Lovelace", authorized=False, context="historical research")
            assert False, "name research must enforce the authorization gate"
        except PermissionError:
            pass
        result, inv_id = investigation.run("name", "Ada Lovelace", authorized=True,
                                            context="historical research")
        assert inv_id is not None and result.findings
        report = reports.build(inv_id)
        stored = report["findings"][0]
        assert stored["published_at"] == "1843-01-01"
        assert stored["source_url"] == "https://university.edu/ada"
        assert json.loads(reports.to_json(report))["investigation"]["id"]
        assert "1843-01-01" in reports.to_txt(report)
        assert "1843-01-01" in reports.to_html(report)
    finally:
        name_search.search_engine.active_providers = previous_active
        name_search.search_engine.search = previous_search
        database._db = previous_db
        db.close()


if __name__ == "__main__":
    import traceback
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    failed = 0
    for test in tests:
        try:
            test()
            print(f"PASS {test.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {test.__name__}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed} passed, {failed} failed")
    raise SystemExit(bool(failed))
