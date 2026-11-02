"""Sex Offender Registry Intelligence (Phase 8). Fictional data only; no registry is ever contacted."""
import dataclasses
import json

import pytest

from core import http, investigation, reports
from core.database import get_db
from modules import registry_intel as rim
from providers import registry_sources as rs
from providers.records_common import (ABSCONDED, ACTIVE, DECEASED, EMPTY_REGISTRY, INACTIVE, NO_SEARCH_RAN, UNKNOWN,
                                       RegistryRecord, SearchOutcome, classify_registry_status, reject_address_text,
                                       validate_person_name, validate_registry_id)
from tests.test_court_records import _drive, flat

NAME = "Robin Examplesurname"       # fictional
MANUAL = {"source_id": "nc_sbi", "displayed_name": "EXAMPLESURNAME, ROBIN", "registry_id": "NC-0000001",
          "original_status": "Active", "offense_classification": "Sexually Violent Offense (example text)",
          "registration_date": "01/15/2020", "source_updated": "2026-10-30", "source_url": "https://sexoffender.ncsbi.gov/example"}


# ---------------------------------------------------------------- sources / providers
def test_provider_catalog_documents_official_agency_urls_and_methods():
    assert set(rs.REGISTRY_SOURCES) == {"nsopw", "nc_sbi"}
    for s in rs.REGISTRY_SOURCES.values():
        assert s.kind == "registry" and s.agency and s.official_url.startswith("https://") and s.auth and s.coverage
        assert s.verified_note and s.complete is False
        assert any(s.official_url.split("/")[2].endswith(d) for d in s.official_domains)


def test_no_registry_is_searched_automatically():
    assert not any(s.automated for s in rs.REGISTRY_SOURCES.values())
    assert rs.AUTOMATED_SEARCHERS == {}


def test_nsopw_documents_no_api_and_prohibition_of_automation():
    s = rs.NSOPW
    assert "no API" in s.limitations and "prohibits automated searching" in s.limitations
    assert "CAPTCHA" in s.auth and s.official_url == "https://www.nsopw.gov/"


def test_nc_sbi_is_attributed_to_the_state_bureau_of_investigation():
    assert "State Bureau of Investigation" in rs.NC_SBI.agency and rs.NC_SBI.jurisdiction == "NC"
    assert "not verified" in rs.NC_SBI.search_fields[0]


def test_state_jurisdiction_selection():
    assert [s.id for s in rs.sources_for("NC")] == ["nc_sbi"]
    assert [s.id for s in rs.sources_for("US")] == ["nsopw"]
    assert rs.sources_for("ZZ") == []
    assert "NC" in rs.JURISDICTIONS


def test_supported_and_unsupported_search_fields_are_documented():
    assert rs.QUERY_KINDS == ("name", "registry_id")
    assert any("registry identification number" in u for u in rs.NSOPW.unsupported_fields)
    assert any("address-radius" in u for u in rs.NSOPW.unsupported_fields)


def test_manual_sources_never_touch_the_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network used")
    monkeypatch.setattr(http, "request", boom)
    monkeypatch.setattr(http, "get", boom)
    outs = rim.run_searches(NAME, "name")
    assert [o.status for o in outs] == ["manual", "manual"] and all("Manual search required" in o.detail for o in outs)


def test_nsopw_registry_id_search_is_explained_as_unsupported():
    o = rs.search_source(rs.NSOPW, "NC-0000001", "registry_id")
    assert "does not support searching by registry identification number" in o.detail


def test_unknown_source_is_an_error():
    with pytest.raises(ValueError):
        rim.run_searches(NAME, "name", ["nope"])


# ---------------------------------------------------------------- provider failures / malformed responses
# No registry has an automated provider, so these exercise the framework hook with a test double.
def _double(result):
    def fn(term, kind):
        if isinstance(result, Exception):
            raise result
        return result
    return fn


def test_future_automated_provider_failure_is_contained(monkeypatch):
    src = dataclasses.replace(rs.NC_SBI, method="automated")
    monkeypatch.setitem(rs.REGISTRY_SOURCES, "nc_sbi", src)
    bad = SearchOutcome(src, "error", "registry timeout", query=NAME, query_kind="name")
    monkeypatch.setitem(rs.AUTOMATED_SEARCHERS, "nc_sbi", _double(bad))
    r = rim.investigate(NAME, source_ids=["nc_sbi"])
    assert r.sources[0].status == "error" and any("registry timeout" in e for e in r.errors)
    assert EMPTY_REGISTRY not in r.notes and NO_SEARCH_RAN in r.notes


def test_future_provider_returning_candidates_requires_operator_attachment(monkeypatch):
    src = dataclasses.replace(rs.NC_SBI, method="automated")
    monkeypatch.setitem(rs.REGISTRY_SOURCES, "nc_sbi", src)
    rec = RegistryRecord(source_id="nc_sbi", jurisdiction="NC", displayed_name="EXAMPLESURNAME, ROBIN", registry_id="NC-0000001",
                         origin="automated")
    ok = SearchOutcome(src, "ok", "1 listing", records=[rec], query=NAME, query_kind="name")
    monkeypatch.setitem(rs.AUTOMATED_SEARCHERS, "nc_sbi", _double(ok))
    outs = rim.run_searches(NAME, "name", ["nc_sbi"])
    none_attached = rim.investigate(NAME, outcomes=outs)
    assert none_attached.findings == [] and any("not stored" in n for n in none_attached.notes)
    attached = rim.investigate(NAME, outcomes=outs, selected=[rec])
    assert len(attached.findings) == 1 and attached.findings[0].category == "registry_listing_reviewed"


def test_selected_listing_not_returned_by_any_source_is_rejected():
    ghost = RegistryRecord(source_id="nsopw", jurisdiction="US", displayed_name="GHOST", registry_id="X-1")
    r = rim.investigate(NAME, outcomes=rim.run_searches(NAME, "name"), selected=[ghost])
    assert r.findings == [] and any("not returned" in e for e in r.errors)


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize("name", ["Robin Examplesurname", "Ana-Maria O'Neil", "Smith, Robin Q."])
def test_valid_names(name):
    assert validate_person_name(name)[1] == ""


@pytest.mark.parametrize("name", ["", "Robin", "Robin 2nd Example", "robin@example.com", "http://x.test"])
def test_invalid_names(name):
    assert validate_person_name(name)[1] != ""


@pytest.mark.parametrize("rid,ok", [("NC-0000001", True), ("A12345", True), ("ab", False), ("", False),
                                    ("NC 000", False), ("NC;DROP", False), ("x" * 50, False)])
def test_registry_id_validation(rid, ok):
    assert (validate_registry_id(rid)[1] == "") is ok


@pytest.mark.parametrize("kind", ["address", "zip", "radius", "county", "status"])
def test_location_and_status_queries_are_not_supported(kind):
    r = rim.investigate("12345", search_kind=kind, outcomes=[])
    assert r.errors and "not supported" in r.errors[0] and not r.findings


# ---------------------------------------------------------------- status classification
@pytest.mark.parametrize("text,expected", [
    ("Active", ACTIVE), ("ACTIVE", ACTIVE), ("Currently Registered", ACTIVE), ("Compliant", ACTIVE),
    ("Inactive", INACTIVE), ("Expired", INACTIVE), ("Removed from registry", INACTIVE),
    ("No longer required to register", INACTIVE),
    ("Deceased", DECEASED), ("Absconder", ABSCONDED), ("Absconded - whereabouts unknown", ABSCONDED),
    ("", UNKNOWN), ("Pending review", UNKNOWN), ("In custody", UNKNOWN), ("Registered in another state", UNKNOWN),
    ("Active warrant", UNKNOWN),
])
def test_registry_status_classification(text, expected):
    assert classify_registry_status(text) == expected


def test_original_status_and_normalized_status_are_both_kept():
    r = rim.investigate(NAME, outcomes=[], manual_records=[dict(MANUAL, original_status="Currently Registered")])
    ev = r.findings[0].evidence
    assert "Registry-displayed status: Currently Registered" in ev and "TRACEPOINT normalized status: ACTIVE" in ev


def test_unknown_status_is_not_guessed():
    r = rim.investigate(NAME, outcomes=[], manual_records=[dict(MANUAL, original_status="")])
    f = r.findings[0]
    assert "TRACEPOINT normalized status: UNKNOWN" in f.evidence and "Registry-displayed status: not provided by source" in f.evidence
    assert "Status is UNKNOWN" in f.limitations


# ---------------------------------------------------------------- privacy by design
def test_registry_record_type_has_no_location_or_physical_fields():
    names = {f.name for f in dataclasses.fields(RegistryRecord)}
    assert not any(w in n for n in names for w in ("address", "street", "city", "zip", "county", "lat", "lon", "photo",
                                                   "employer", "vehicle", "height", "weight", "birth"))


@pytest.mark.parametrize("text", ["lives at 123 Main Street", "42 Oak Ave apt 3", "7 Elm Road"])
def test_address_text_is_rejected(text):
    assert reject_address_text(text, "Field")
    r = rim.investigate(NAME, outcomes=[], manual_records=[dict(MANUAL, offense_classification=text)])
    assert r.findings == [] and any("street address" in e for e in r.errors)


def test_extra_location_fields_in_manual_input_are_ignored_not_stored():
    r = rim.investigate(NAME, outcomes=[], manual_records=[dict(MANUAL, address="1 Hidden Lane", city="Exampleville", zip="27000")])
    blob = json.dumps(r.findings[0].to_dict()) + r.findings[0].evidence
    assert "Hidden" not in blob and "Exampleville" not in blob and "27000" not in blob


# ---------------------------------------------------------------- identity safeguards and evidence
def test_listing_is_unverified_separate_and_attributed():
    r = rim.investigate(NAME, outcomes=rim.run_searches(NAME, "name", ["nc_sbi"]), manual_records=[dict(MANUAL)])
    f = r.findings[0]
    assert f.confidence == "UNVERIFIED" and f.category == "registry_listing_manual" and f.source_type == "registry"
    assert f.source == rs.NC_SBI.name and f.source_url == "https://sexoffender.ncsbi.gov/example"
    assert "not proof of identity" in f.limitations and "not proof of current whereabouts" in f.limitations
    assert "UNVERIFIED name/identifier match" in f.description
    assert "Registry identification number: NC-0000001" in f.evidence and "Registration date: 2020-01-15" in f.evidence
    assert "Offense classification as published: Sexually Violent Offense (example text)" in f.evidence
    assert "Registry / agency: North Carolina State Bureau of Investigation" in f.evidence


def test_records_are_never_merged_by_name_alone():
    other = dict(MANUAL, registry_id="NC-0000002")
    r = rim.investigate(NAME, outcomes=[], manual_records=[dict(MANUAL), other])
    assert len(r.findings) == 2 and r.relationships == []


def test_exact_duplicates_collapse_and_conflicting_status_is_flagged():
    r = rim.investigate(NAME, outcomes=[], manual_records=[dict(MANUAL), dict(MANUAL)])
    assert len(r.findings) == 1
    r2 = rim.investigate(NAME, outcomes=[], manual_records=[dict(MANUAL), dict(MANUAL, original_status="Inactive")])
    assert sorted(f.category for f in r2.findings) == ["contradiction", "registry_listing_manual"]


def test_url_outside_official_domain_is_flagged():
    r = rim.investigate(NAME, outcomes=[], manual_records=[dict(MANUAL, source_url="https://people-search.example/x")])
    assert "official domains" in r.findings[0].limitations


def test_nsopw_listing_url_on_a_state_site_is_flagged_for_verification():
    r = rim.investigate(NAME, outcomes=[], manual_records=[dict(MANUAL, source_id="nsopw", source_url="https://registry.example.gov/x")])
    assert "official domains" in r.findings[0].limitations


def test_person_entity_is_unverified_and_registry_id_search_adds_none():
    r = rim.investigate(NAME, outcomes=[], manual_records=[dict(MANUAL)])
    assert [(e.type, e.verification) for e in r.entities] == [("person", "UNVERIFIED")]
    r2 = rim.investigate("NC-0000001", search_kind="registry_id", outcomes=[], manual_records=[dict(MANUAL)])
    assert r2.entities == []


# ---------------------------------------------------------------- empty results / sources
def test_manual_only_search_does_not_claim_absence():
    r = rim.investigate(NAME, outcomes=rim.run_searches(NAME, "name"))
    assert NO_SEARCH_RAN in r.notes and EMPTY_REGISTRY not in r.notes
    assert [s.status for s in r.sources] == ["skipped", "skipped"]


def test_completed_empty_search_shows_the_mandated_message_exactly():
    ok = SearchOutcome(rs.NC_SBI, "ok", "0 listings", query=NAME, query_kind="name")
    r = rim.investigate(NAME, outcomes=[ok])
    assert EMPTY_REGISTRY in r.notes
    assert EMPTY_REGISTRY == ("No registry records were returned by the sources searched. This does not establish that "
                              "an individual is absent from every registry.")


def test_source_records_state_agency_coverage_and_manual_status():
    r = rim.investigate(NAME, outcomes=rim.run_searches(NAME, "name"))
    for s in r.sources:
        assert "Coverage: PARTIAL" in s.detail and "manual search required" in s.detail


def test_invalid_input_returns_error_without_searching(monkeypatch):
    monkeypatch.setattr(rim, "run_searches", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no search")))
    r = rim.investigate("Robin")
    assert r.errors and not r.sources


@pytest.mark.parametrize("bad", [dict(MANUAL, source_id="x"), dict(MANUAL, displayed_name="", registry_id=""),
                                  dict(MANUAL, registration_date="January"), dict(MANUAL, registry_id="a;b")])
def test_invalid_manual_listings_are_rejected(bad):
    r = rim.investigate(NAME, outcomes=[], manual_records=[bad])
    assert r.findings == [] and r.errors


def test_javascript_url_is_dropped():
    r = rim.investigate(NAME, outcomes=[], manual_records=[dict(MANUAL, source_url="javascript:alert(1)")])
    assert r.findings[0].source_url == "" and "No official source URL" in r.findings[0].limitations


# ---------------------------------------------------------------- persistence / reports / offline
def test_authorization_is_required():
    with pytest.raises(PermissionError):
        investigation.run("registry", NAME, authorized=False, outcomes=[])


def test_persistence_history_and_duplicate_prevention():
    db = get_db()
    _, inv_id = investigation.run("registry", NAME, authorized=True, search_kind="name",
                                  outcomes=rim.run_searches(NAME, "name", ["nc_sbi"]),
                                  manual_records=[dict(MANUAL), dict(MANUAL)])
    assert db.get_investigation(inv_id)["inv_type"] == "registry"
    assert [f["category"] for f in db.findings(inv_id)] == ["registry_listing_manual"]
    assert inv_id in [r["id"] for r in db.list_investigations(500)]
    assert db.sources(inv_id)[0]["status"] == "skipped"


def test_reports_distinguish_record_classes_and_never_imply_whereabouts(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    _, inv_id = investigation.run("registry", NAME, authorized=True, search_kind="name",
                                  outcomes=rim.run_searches(NAME, "name"),
                                  manual_records=[dict(MANUAL, offense_classification="<script>x</script>")])
    built = reports.build(inv_id)
    rr = built["records_review"]
    assert "registry listing is not proof of current whereabouts" in rr["statement"].lower()
    assert "UNVERIFIED name/identifier matches" in rr["unverified_name_matches"]
    assert len(rr["inaccessible_sources"]) == 2 and len(rr["partial_coverage"]) == 2
    txt = reports.save(inv_id, "txt").read_text(encoding="utf-8")
    html = reports.save(inv_id, "html").read_text(encoding="utf-8")
    js = json.loads(reports.save(inv_id, "json").read_text(encoding="utf-8"))
    assert "RECORDS REVIEW" in txt and "Registry listing:" in txt and js["records_review"]
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html
    assert "no address" in txt.lower() or "records no address" in txt.lower()


def test_offline_operation_needs_no_network(monkeypatch):
    monkeypatch.setattr(http, "request", lambda *a, **k: (_ for _ in ()).throw(http.HttpError("offline")))
    r = rim.investigate(NAME, manual_records=[dict(MANUAL)])
    assert len(r.findings) == 1 and r.errors == []


# ---------------------------------------------------------------- CLI
def test_menu_has_registry_option_without_disturbing_existing_ones():
    import main
    nums = {n: k for n, k, _ in main.MENU} | {n: k for n, k, _ in main.ACTIONS}
    assert nums["17"] == "registry" and nums["16"] == "court" and nums["8"] == "name" and nums["0"] == "exit"
    assert "registry" in main.RECORD_FLOWS


def test_cli_registry_workflow_records_a_reviewed_listing(monkeypatch):
    fields = [MANUAL[k] for k in ("displayed_name", "registry_id", "original_status", "offense_classification",
                                  "registration_date", "source_updated", "source_url")]
    main, buf = _drive(monkeypatch, ["2", "NC", "1", NAME, "2"] + fields + ["", "back"], [True, False, True, False])
    before = len(get_db().list_investigations(500))
    main.registry_flow()
    rows = get_db().list_investigations(500)
    assert len(rows) == before + 1 and rows[0]["inv_type"] == "registry"
    f = get_db().findings(rows[0]["id"])
    assert len(f) == 1 and f[0]["category"] == "registry_listing_manual" and f[0]["confidence"] == "UNVERIFIED"
    out = flat(buf.getvalue())
    assert "MANUAL" in out and "prohibit automated searching" in out and "stores no addresses" in out
    assert "https://sexoffender.ncsbi.gov/search.aspx" in out


def test_cli_registry_declined_authorization_saves_nothing(monkeypatch):
    main, buf = _drive(monkeypatch, ["1", "1", NAME], [False])
    before = len(get_db().list_investigations(500))
    main.registry_flow()
    assert len(get_db().list_investigations(500)) == before


def test_cli_registry_rejects_location_style_input_as_a_name(monkeypatch):
    main, buf = _drive(monkeypatch, ["1", "1", "27601"], [])
    main.registry_flow()
    assert "full name" in flat(buf.getvalue()).lower()
