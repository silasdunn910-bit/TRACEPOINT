"""Nationwide jurisdiction selection and search coverage (Phase 8, part 2).

Mocked providers and fictional names only; no live service is contacted and nobody real is searched.
"""
import dataclasses
import io
import json
import re

import pytest
from rich.console import Console

from core import http, investigation, reports
from core.database import get_db
from modules import court_records_intel as cri
from modules import registry_intel as rim
from providers import court_sources, registry_sources as rs
from providers import coverage as cov
from providers.jurisdictions import (FEDERAL, NATIONWIDE, STATE, STATES, US_NATIONWIDE, resolve)
from providers.records_common import EMPTY_COURT, NO_SEARCH_RAN, RegistryRecord, SearchOutcome

NAME = "Alex Examplename"          # fictional
KEY = "GOVINFO-TEST-KEY-123456"    # fictional

ABBREVIATIONS = ("AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND OH "
                 "OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC").split()


class Resp:
    def __init__(self, status=200, payload=None, bad_json=False):
        self.status_code, self._payload, self._bad = status, payload, bad_json
        self.headers, self.text = {}, ""

    def json(self):
        if self._bad:
            raise ValueError("not json")
        return self._payload


def gov_item(n=1):
    return {"title": f"UNITED STATES v. EXAMPLE {n}", "packageId": f"USCOURTS-xx-1_24-cr-0000{n}",
            "granuleId": f"USCOURTS-xx-1_24-cr-0000{n}-0", "governmentAuthor": ["Example District Court"],
            "dateIssued": "2024-05-01", "resultLink": f"https://api.govinfo.gov/packages/x{n}/summary?api_key=LEAK"}


def fake_http(monkeypatch, response=None, exc=None):
    def fake(method, url, **kw):
        if exc:
            raise exc
        return response
    monkeypatch.setattr(court_sources.http, "request", fake)


@pytest.fixture()
def keyed():
    get_db().set_secret("govinfo_key", KEY)
    yield
    get_db().delete_secret("govinfo_key")


def status_of(report, provider_id):
    return next(e.status for e in report.entries if e.provider_id == provider_id)


# ---------------------------------------------------------------- resolution
def test_the_state_table_has_fifty_states_and_dc():
    assert len(STATES) == 51 and set(STATES) == set(ABBREVIATIONS) and STATES["DC"] == "District of Columbia"


@pytest.mark.parametrize("code", ABBREVIATIONS)
def test_every_abbreviation_resolves_in_any_case_with_whitespace(code):
    for text in (code, code.lower(), code.title(), f"  {code}  ", f"\t{code.lower()}\n"):
        jur, err = resolve(text)
        assert err == "" and jur.scope == STATE and jur.code == code and jur.name == STATES[code]


@pytest.mark.parametrize("code", [c for c in ABBREVIATIONS if c != "DC"])
def test_every_full_state_name_resolves_case_insensitively(code):
    name = STATES[code]
    for text in (name, name.upper(), name.lower(), f"   {name}   ", name.replace(" ", "   ")):
        jur, err = resolve(text)
        assert err == "" and jur.code == code, text


@pytest.mark.parametrize("text", ["DC", "dc", "D.C.", "District of Columbia", "district  of  columbia", "Washington DC",
                                  "washington, d.c.", "Washington D.C."])
def test_washington_dc_resolves(text):
    assert resolve(text)[0].code == "DC"


def test_washington_alone_is_the_state_and_virginia_is_not_west_virginia():
    assert resolve("Washington")[0].code == "WA"
    assert resolve("Virginia")[0].code == "VA" and resolve("West Virginia")[0].code == "WV"
    assert resolve("west-virginia")[0].code == "WV"


def test_unicode_input_is_normalised():
    assert resolve("N​")[1] != ""                         # zero-width junk is not silently accepted
    assert resolve("ＮＣ")[0].code == "NC"                      # full-width letters normalise (NFKC)


@pytest.mark.parametrize("text", ["US", "us", " USA ", "United States", "united states of america", "Nationwide"])
def test_us_is_a_nationwide_request(text):
    jur, err = resolve(text)
    assert err == "" and jur.scope == NATIONWIDE and jur.code == "US"


@pytest.mark.parametrize("text", ["federal", "Federal Courts", "FED"])
def test_federal_scope(text):
    assert resolve(text)[0].scope == FEDERAL


@pytest.mark.parametrize("text", ["", "   ", "XX", "Narnia", "N", "123", "NC; DROP TABLE x", "<script>", "Puerto Rico", "PR",
                                  "x" * 200, "N\x00C", "North Carolinaa and South"])
def test_invalid_jurisdictions_are_rejected_with_a_message(text):
    jur, err = resolve(text)
    assert jur is None and err
    assert "<script>" not in err                                # echoed input is neutralised


def test_a_near_miss_gets_a_suggestion():
    assert "North Carolina" in resolve("Nort Carolina")[1]
    assert "Territories" in resolve("Guam")[1]


# ---------------------------------------------------------------- provider discovery
def test_court_discovery_per_scope():
    ids = lambda p: [s.id for s in p.sources]
    assert ids(cri.plan("NC")) == ["nc_judicial"]                        # federal courts are a separate jurisdiction
    assert ids(cri.plan("US")) == ["govinfo_uscourts", "pacer_pcl", "nc_judicial"]
    assert ids(cri.plan("federal")) == ["govinfo_uscourts", "pacer_pcl"]
    pl = cri.plan("CA")
    assert pl.sources == [] and pl.not_implemented == ["CA"]
    assert cri.plan("US").not_implemented == [c for c in STATES if c != "NC"]
    assert cri.plan("NC").not_implemented == []


def test_registry_discovery_per_scope():
    ids = lambda p: [s.id for s in p.sources]
    assert ids(rim.plan("NC")) == ["nsopw", "nc_sbi"]                    # NSOPW is the manual national route into any state
    assert ids(rim.plan("TX")) == ["nsopw"] and rim.plan("TX").not_implemented == ["TX"]
    assert ids(rim.plan("US")) == ["nsopw", "nc_sbi"]
    assert ids(rim.plan("federal")) == ["nsopw"]


def test_no_county_providers_are_invented():
    for catalog in (court_sources.COURT_SOURCES, rs.REGISTRY_SOURCES):
        assert not [s for s in catalog.values() if s.level == "county"]
    assert cri.plan("NC").automated == [] and [s.id for s in cri.plan("US").automated] == ["govinfo_uscourts"]


def test_plan_rejects_an_invalid_jurisdiction():
    with pytest.raises(ValueError):
        cri.plan("Narnia")


# ---------------------------------------------------------------- nationwide coverage is generated from execution
def test_nationwide_court_search_reports_partial_coverage_truthfully(monkeypatch, keyed):
    fake_http(monkeypatch, Resp(payload={"results": [gov_item(1)]}))
    outcomes, rep = cri.search(NAME, "name", None)
    assert [o.source.id for o in outcomes] == ["govinfo_uscourts", "pacer_pcl", "nc_judicial"]
    assert status_of(rep, "govinfo_uscourts") == cov.SEARCHED and status_of(rep, "pacer_pcl") == cov.MANUAL
    assert status_of(rep, "nc_judicial") == cov.MANUAL
    assert len(rep.by_status(cov.NOT_IMPLEMENTED)) == 50 and rep.status == cov.PARTIAL and not rep.complete_nationwide
    c = rep.counts()
    assert c["SEARCHED"] == 1 and c["MANUAL"] == 2 and c["NOT IMPLEMENTED"] == 50 and c["records_returned"] == 1
    text = "\n".join(rep.lines())
    assert "NATIONWIDE SEARCH COVERAGE" in text and "Coverage: PARTIAL" in text and "NOT IMPLEMENTED" in text
    assert "Only the sources marked SEARCHED were searched" in text
    assert not re.search(r"all 50|every state", text, re.I)


def test_state_search_covers_only_that_state():
    outcomes, rep = cri.search(NAME, "name", "north carolina")
    assert [o.source.id for o in outcomes] == ["nc_judicial"] and rep.scope == STATE
    assert rep.status == cov.NONE and "Coverage: NONE" in "\n".join(rep.lines())      # a manual source is not a search
    assert rep.resolved == "North Carolina (NC)" and rep.requested == "north carolina"


def test_state_without_a_provider_is_reported_not_skipped_silently():
    outcomes, rep = cri.search(NAME, "name", "ca")
    assert outcomes == []
    assert [(e.jurisdiction, e.status) for e in rep.entries] == [("CA", cov.NOT_IMPLEMENTED)]
    assert rep.status == cov.NONE and "nothing was searched" in rep.entries[0].reason


def test_federal_scope_searches_federal_sources_only(monkeypatch, keyed):
    fake_http(monkeypatch, Resp(payload={"results": []}))
    outcomes, rep = cri.search(NAME, "name", "Federal")
    assert {e.provider_id for e in rep.entries} == {"govinfo_uscourts", "pacer_pcl"} and not rep.by_status(cov.NOT_IMPLEMENTED)


# ---------------------------------------------------------------- provider failures, missing providers, empty results
def test_missing_key_is_unavailable_not_searched():
    get_db().delete_secret("govinfo_key")
    _, rep = cri.search(NAME, "name", "US")
    assert status_of(rep, "govinfo_uscourts") == cov.UNAVAILABLE and rep.status == cov.NONE


@pytest.mark.parametrize("response,expected", [
    (Resp(status=401), cov.FAILED), (Resp(status=403), cov.FAILED), (Resp(status=429), cov.UNAVAILABLE),
    (Resp(status=503), cov.UNAVAILABLE), (Resp(bad_json=True), cov.FAILED), (Resp(payload={"nope": 1}), cov.FAILED)])
def test_provider_errors_are_classified(monkeypatch, keyed, response, expected):
    fake_http(monkeypatch, response)
    out, rep = cri.search(NAME, "name", "US")
    assert status_of(rep, "govinfo_uscourts") == expected
    assert [o.source.id for o in out] == ["govinfo_uscourts", "pacer_pcl", "nc_judicial"]   # no substitute provider appears


def test_offline_marks_the_provider_unavailable_and_manual_sources_still_listed(monkeypatch, keyed):
    fake_http(monkeypatch, exc=http.HttpError("Connection failed"))
    out, rep = cri.search(NAME, "name", "US")
    assert status_of(rep, "govinfo_uscourts") == cov.UNAVAILABLE and status_of(rep, "pacer_pcl") == cov.MANUAL
    assert key_not_leaked(rep)


def key_not_leaked(rep):
    return KEY not in json.dumps(rep.to_dict())


def test_a_crashing_provider_is_failed_and_the_others_still_run(monkeypatch):
    def boom(source, term, kind):
        if source.id == "govinfo_uscourts":
            raise RuntimeError("secret internals " + KEY)
        return court_sources.search_source(source, term, kind)
    monkeypatch.setattr(cri, "search_source", boom)
    out, rep = cri.search(NAME, "name", "US")
    assert status_of(rep, "govinfo_uscourts") == cov.FAILED and status_of(rep, "pacer_pcl") == cov.MANUAL
    assert "RuntimeError" in rep.entries[0].reason and KEY not in rep.entries[0].reason


def test_zero_records_is_not_proof_of_absence(monkeypatch, keyed):
    fake_http(monkeypatch, Resp(payload={"results": []}))
    outcomes, rep = cri.search(NAME, "name", "US")
    assert status_of(rep, "govinfo_uscourts") == cov.SEARCHED and rep.counts()["records_returned"] == 0
    assert "not proof that no records exist" in "\n".join(rep.lines())
    r = cri.investigate(NAME, outcomes=outcomes, coverage=rep, jurisdiction="US")
    assert EMPTY_COURT in r.notes and not r.findings


def test_nothing_searched_says_so():
    r = cri.investigate(NAME, jurisdiction="CA")
    assert NO_SEARCH_RAN in r.notes and not r.findings


def test_unsupported_search_kind_is_skipped_with_a_reason():
    out, rep = rim.search("NC-12345", "registry_id", "US")
    assert status_of(rep, "nsopw") == cov.SKIPPED and "does not support" in rep.entries[0].reason
    assert status_of(rep, "nc_sbi") == cov.MANUAL


def test_planned_provider_that_did_not_run_is_skipped():
    pl = cri.plan("US")
    rep = cov.build_report("court", US_NATIONWIDE, "name", pl, [])
    assert {e.status for e in rep.entries if e.provider_id} == {cov.SKIPPED}
    assert all("Not run" in e.reason for e in rep.entries if e.provider_id)


# ---------------------------------------------------------------- mixed providers; complete is hard to earn
@pytest.fixture()
def mixed_registries(monkeypatch):
    base = rs.NC_SBI
    auto = dataclasses.replace(base, id="fake_auto", name="Fake State Registry (automated test double)", jurisdiction="SC",
                               method="automated", official_domains=("example.gov",))
    manual = dataclasses.replace(base, id="fake_manual", name="Fake NY Registry (manual test double)", jurisdiction="NY")
    monkeypatch.setitem(rs.REGISTRY_SOURCES, auto.id, auto)
    monkeypatch.setitem(rs.REGISTRY_SOURCES, manual.id, manual)

    def searcher(term, kind):
        rec = RegistryRecord(source_id=auto.id, jurisdiction="SC", displayed_name="Alex Examplename", registry_id="SC-1111",
                             original_status="Active", origin="automated")
        return SearchOutcome(auto, "ok", detail="1 candidate", records=[rec], query=term, query_kind=kind)
    monkeypatch.setitem(rs.AUTOMATED_SEARCHERS, auto.id, searcher)
    return auto, manual


def test_mixed_automated_and_manual_registry_providers(mixed_registries):
    out, rep = rim.search(NAME, "name", "US")
    assert status_of(rep, "fake_auto") == cov.SEARCHED and status_of(rep, "fake_manual") == cov.MANUAL
    assert status_of(rep, "nsopw") == cov.MANUAL and status_of(rep, "nc_sbi") == cov.MANUAL
    assert rep.status == cov.PARTIAL and len(rep.by_status(cov.NOT_IMPLEMENTED)) == 48       # 51 minus NC, SC, NY
    sc = rim.search(NAME, "name", "sc")[1]
    assert [e.provider_id for e in sc.entries] == ["nsopw", "fake_auto"] and sc.status == cov.PARTIAL


def test_registry_candidates_are_attached_only_when_selected(mixed_registries):
    out, rep = rim.search(NAME, "name", "SC")
    r = rim.investigate(NAME, outcomes=out, coverage=rep, jurisdiction="SC")
    assert not r.findings and any("not stored" in n for n in r.notes)
    r = rim.investigate(NAME, outcomes=out, coverage=rep, jurisdiction="SC", selected=out[1].records)
    assert len(r.findings) == 1 and r.findings[0].confidence == "UNVERIFIED"
    assert "Provider status in this search: SEARCHED" in r.findings[0].evidence


def test_complete_requires_every_source_complete_and_every_jurisdiction_covered(monkeypatch):
    done = dataclasses.replace(rs.NC_SBI, id="done_nc", complete=True, method="automated")
    catalog = {"done_nc": done}
    ok = lambda s, t, k: SearchOutcome(s, "ok", records=[], query=t, query_kind=k)
    _, state_rep = cov.execute("registry", catalog, resolve("NC")[0], NAME, "name", ok)
    assert state_rep.status == cov.COMPLETE and not state_rep.complete_nationwide            # state scope: complete
    _, us_rep = cov.execute("registry", catalog, US_NATIONWIDE, NAME, "name", ok)
    assert us_rep.status == cov.PARTIAL and not us_rep.complete_nationwide                    # 50 states still missing
    assert len(us_rep.by_status(cov.NOT_IMPLEMENTED)) == 50
    # a provider that does not claim completeness keeps the search PARTIAL even when searched
    part = dataclasses.replace(done, complete=False)
    assert cov.execute("registry", {"p": part}, resolve("NC")[0], NAME, "name", ok)[1].status == cov.PARTIAL


def test_coverage_round_trips_through_json():
    _, rep = cri.search(NAME, "name", "US")
    back, rest = cov.parse_marker("note one\n" + rep.to_marker_line() + "\nnote two")
    assert rest == "note one\nnote two" and back.to_dict() == rep.to_dict() and back.status == rep.status
    assert cov.parse_marker("plain notes")[0] is None
    assert cov.parse_marker(cov.MARKER + "{broken")[0] is None


# ---------------------------------------------------------------- module integration, persistence, reports
MANUAL_COURT = {"source_id": "nc_judicial", "title": "STATE v. EXAMPLE", "case_number": "24CR000123-456",
                "court": "Example County Superior Court", "record_type": "CRIMINAL", "original_status": "Dismissed",
                "source_url": "https://www.nccourts.gov/example"}
MANUAL_REG = {"source_id": "nc_sbi", "displayed_name": "Alex Examplename", "registry_id": "NC-9999",
              "original_status": "Active", "offense_classification": "Example classification",
              "source_url": "https://sexoffender.ncsbi.gov/example"}


def test_court_investigation_records_scope_jurisdiction_provider_method_and_coverage(monkeypatch):
    monkeypatch.setattr(court_sources.http, "request", lambda *a, **k: (_ for _ in ()).throw(http.HttpError("offline")))
    result, inv_id = investigation.run("court", NAME, authorized=True, jurisdiction=" nc ", manual_records=[MANUAL_COURT])
    f = get_db().findings(inv_id)
    assert len(f) == 1
    ev = f[0]["evidence"]
    for expected in ("Search scope: state", "Requested jurisdiction: nc", "Resolved jurisdiction: North Carolina (NC)",
                     "Search method: name", "Provider status in this search: MANUAL", "Coverage of this search: NONE",
                     "Jurisdiction: state/NC", "Retrieved/entered:"):
        assert expected in ev, expected
    assert f[0]["source_url"] == "https://www.nccourts.gov/example"
    src = get_db().sources(inv_id)
    assert len(src) == 1 and src[0]["name"].startswith("North Carolina Judicial Branch") and "[MANUAL]" in src[0]["detail"]
    assert src[0]["consulted_at"]
    rep, _ = cov.parse_marker(get_db().get_investigation(inv_id)["notes"])
    assert rep.scope == STATE and rep.status == cov.NONE and rep.search_method == "name"


def test_nationwide_investigation_persists_a_non_complete_coverage_record(monkeypatch, keyed):
    fake_http(monkeypatch, Resp(payload={"results": [gov_item(1)]}))
    result, inv_id = investigation.run("court", NAME, authorized=True, selected=None, manual_records=[MANUAL_COURT])
    notes = get_db().get_investigation(inv_id)["notes"]
    assert "NATIONWIDE REQUEST" in notes and "not nationwide coverage" in notes
    built = reports.build(inv_id)
    sc = built["records_review"]["search_coverage"]
    assert sc["status"] == cov.PARTIAL and sc["scope"] == "nationwide" and sc["counts"]["NOT IMPLEMENTED"] == 50
    assert "NATIONWIDE REQUEST, not nationwide coverage" in sc["summary"]
    assert cov.MARKER not in built["investigation"]["notes"]                 # machine line is not shown as a note
    assert len(get_db().findings(inv_id)) == 1                                # the unattached GovInfo candidate was not stored


def test_reports_distinguish_request_from_coverage(monkeypatch, keyed):
    fake_http(monkeypatch, Resp(payload={"results": []}))
    _, inv_id = investigation.run("court", NAME, authorized=True, manual_records=[MANUAL_COURT])
    txt = reports.save(inv_id, "txt").read_text(encoding="utf-8")
    html = reports.save(inv_id, "html").read_text(encoding="utf-8")
    js = json.loads(reports.save(inv_id, "json").read_text(encoding="utf-8"))
    assert "SEARCH SCOPE AND COVERAGE" in txt and "NATIONWIDE SEARCH COVERAGE" in txt and "Coverage: PARTIAL" in txt
    assert "Search scope and coverage: PARTIAL" in html and "NOT IMPLEMENTED" in html
    assert js["records_review"]["search_coverage"]["providers"] and cov.MARKER not in txt
    assert KEY not in txt + html + json.dumps(js)


def test_registry_investigation_by_state_name(monkeypatch):
    result, inv_id = investigation.run("registry", NAME, authorized=True, jurisdiction="North Carolina",
                                       manual_records=[MANUAL_REG])
    f = get_db().findings(inv_id)
    assert len(f) == 1 and f[0]["category"] == "registry_listing_manual"
    assert "Resolved jurisdiction: North Carolina (NC)" in f[0]["evidence"]
    assert "Registry updated" in f[0]["evidence"] and not re.search(r"\baddress\b", f[0]["evidence"], re.I)
    rr = reports.build(inv_id)["records_review"]
    assert rr["search_coverage"]["scope"] == STATE and rr["search_coverage"]["status"] == cov.NONE
    assert len(rr["inaccessible_sources"]) == 2


def test_court_and_registry_records_stay_separate():
    _, c_id = investigation.run("court", NAME, authorized=True, jurisdiction="NC", manual_records=[MANUAL_COURT])
    _, r_id = investigation.run("registry", NAME, authorized=True, jurisdiction="NC", manual_records=[MANUAL_REG])
    assert {f["category"] for f in get_db().findings(c_id)} == {"court_record_manual"}
    assert {f["category"] for f in get_db().findings(r_id)} == {"registry_listing_manual"}


def test_same_name_records_from_different_providers_are_never_merged():
    other = dict(MANUAL_COURT, source_id="pacer_pcl", source_url="https://pacer.uscourts.gov/x")
    r = cri.investigate(NAME, jurisdiction="US", outcomes=[], manual_records=[MANUAL_COURT, other])
    assert len(r.findings) == 2 and {f.confidence for f in r.findings} == {"UNVERIFIED"}


def test_invalid_jurisdiction_in_a_module_call_is_an_error_not_a_search():
    for mod in (cri, rim):
        r = mod.investigate(NAME, jurisdiction="Narnia")
        assert r.errors and "not a recognised jurisdiction" in r.errors[0] and not r.findings and not r.sources


def test_default_jurisdiction_is_a_nationwide_request():
    r = rim.investigate(NAME)
    assert any("Search scope: nationwide" in n for n in r.notes)


def test_legacy_investigations_without_coverage_say_so():
    from core.models import ModuleResult
    legacy = ModuleResult("court", NAME)
    legacy.notes.append("Search type: name.")
    inv_id = get_db().save_result("court", NAME, legacy)
    rr = reports.build(inv_id)["records_review"]
    assert rr["search_coverage"]["status"] == "NOT RECORDED" and "predates" in rr["search_coverage"]["summary"]


def test_offline_registry_and_court_work_without_network(monkeypatch):
    monkeypatch.setattr(http, "request", lambda *a, **k: (_ for _ in ()).throw(http.HttpError("offline")))
    monkeypatch.setattr(court_sources.http, "request", lambda *a, **k: (_ for _ in ()).throw(http.HttpError("offline")))
    for mod, manual in ((cri, MANUAL_COURT), (rim, MANUAL_REG)):
        r = mod.investigate(NAME, jurisdiction="US", manual_records=[manual])
        assert len(r.findings) == 1 and any("Coverage:" in n for n in r.notes)


# ---------------------------------------------------------------- CLI
def flat(text: str) -> str:
    return " ".join(re.sub(r"[─-╿]", " ", text).split())


def drive(monkeypatch, prompts, confirms):
    import main
    from ui.theme import THEME
    buf = io.StringIO()
    monkeypatch.setattr(main, "console", Console(file=buf, width=200, force_terminal=False, color_system=None, theme=THEME))
    p, c = iter(prompts), iter(confirms)
    monkeypatch.setattr(main.Prompt, "ask", lambda *a, **k: next(p))
    monkeypatch.setattr(main.Confirm, "ask", lambda *a, **k: next(c))
    return main, buf


def test_cli_shows_the_three_option_jurisdiction_menu_and_back_exits(monkeypatch):
    main, buf = drive(monkeypatch, ["0"], [])
    before = len(get_db().list_investigations(500))
    main.court_records_flow()
    out = flat(buf.getvalue())
    assert "JURISDICTION SELECTION" in out and "1. United States (Nationwide)" in out
    assert "2. Select a State" in out and "3. Federal Courts" in out and "0. Back" in out
    assert len(get_db().list_investigations(500)) == before
    main, buf = drive(monkeypatch, ["0"], [])
    main.registry_flow()
    assert "3. National Registry (NSOPW)" in flat(buf.getvalue())


def test_cli_state_prompt_rejects_invalid_input_then_accepts_a_name(monkeypatch):
    main, buf = drive(monkeypatch, ["2", "Narnia", "XX", "  north carolina ", "0", "0"], [])
    main.court_records_flow()
    out = flat(buf.getvalue())
    assert out.count("is not a recognised jurisdiction") == 2 and "Enter state name or abbreviation" in out
    assert "COURT RECORDS - NORTH CAROLINA" in out and "SEARCH METHOD" in out
    assert "1. Search by person name" in out and "2. Search by case number" in out
    assert "Search scope: North Carolina (NC)" in out and "Federal court records are a separate jurisdiction" in out
    assert "County resources: none catalogued" in out and "MANUAL" in out


def test_cli_state_with_no_provider_is_explained(monkeypatch):
    main, buf = drive(monkeypatch, ["2", "ca", "0", "0"], [])
    main.court_records_flow()
    out = flat(buf.getvalue())
    assert "COURT RECORDS - CALIFORNIA" in out and "No official source is catalogued" in out and "NOT IMPLEMENTED" in out


def test_cli_nationwide_court_search_prints_coverage_and_saves_it(monkeypatch, keyed):
    fake_http(monkeypatch, Resp(payload={"results": [gov_item(1), gov_item(2)]}))
    # nationwide -> name -> authorize -> attach none -> manual stage: finish -> save anyway
    main, buf = drive(monkeypatch, ["1", "1", NAME, "", "", "", "back"], [True, True])
    main.court_records_flow()
    out = flat(buf.getvalue())
    assert "NATIONWIDE SEARCH COVERAGE" in out and "SEARCHED" in out and "MANUAL" in out and "Coverage: PARTIAL" in out
    assert "TRACEPOINT did NOT search these sources" in out and "UNVERIFIED name matches" in out
    inv = get_db().list_investigations(500)[0]
    assert "[coverage-data]" in inv["notes"] and inv["inv_type"] == "court"
    assert get_db().findings(inv["id"]) == []


def test_cli_registry_nationwide_lists_manual_portals_and_never_implies_a_search(monkeypatch):
    main, buf = drive(monkeypatch, ["1", "1", NAME, "", "back"], [True, True])
    main.registry_flow()
    out = flat(buf.getvalue())
    assert "NATIONWIDE SEARCH COVERAGE" in out and "National Sex Offender Public Website" in out
    assert "https://www.nsopw.gov/search-0" in out and "cannot do so automatically" in out
    assert "Coverage: NONE" in out and "0 automated source(s) searched" in out


def test_cli_federal_option_and_case_number_method(monkeypatch, keyed):
    fake_http(monkeypatch, Resp(payload={"results": [gov_item(1)]}))
    main, buf = drive(monkeypatch, ["3", "2", "1:24-cr-00123", "", "", "back"], [True, True])
    main.court_records_flow()
    out = flat(buf.getvalue())
    assert "COURT RECORDS - FEDERAL" in out and "SEARCH COVERAGE - FEDERAL COURTS / NATIONAL LEVEL" in out.upper()
    rep, _ = cov.parse_marker(get_db().list_investigations(500)[0]["notes"])
    assert rep.search_method == "case_number" and rep.scope == FEDERAL
    assert {e.provider_id for e in rep.entries} == {"govinfo_uscourts", "pacer_pcl"}


def test_cli_invalid_case_number_is_rejected_before_any_search(monkeypatch):
    main, buf = drive(monkeypatch, ["1", "2", "no digits here"], [])
    before = len(get_db().list_investigations(500))
    main.court_records_flow()
    assert "Case numbers are" in flat(buf.getvalue()) and len(get_db().list_investigations(500)) == before


@pytest.mark.parametrize("name", ["Mary-Jane O'Neil", "José Núñez", "Zoë Müller-Ng"])
def test_names_with_hyphens_apostrophes_and_unicode_are_accepted_by_both_modules(name):
    assert cri.validate_query(name, "name")[1] == "" and rim.validate_query(name, "name")[1] == ""


def test_the_database_was_extended_without_a_schema_change():
    cols = {r["name"] for r in get_db().q("PRAGMA table_info(investigations)")}
    assert cols >= {"ref", "inv_type", "target", "status", "notes"}
    before = get_db().schema_version()
    investigation.run("court", NAME, authorized=True, jurisdiction="NC", manual_records=[MANUAL_COURT])
    assert get_db().schema_version() == before                          # saving scope/coverage needs no migration
