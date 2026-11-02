"""Court Records Intelligence (Phase 8). Mocked HTTP and fictional names only; no live service is contacted."""
import io
import json
import logging

import pytest
from rich.console import Console

from core import http, investigation, reports
from core.database import get_db
from modules import court_records_intel as cri
from providers import court_sources
from providers.records_common import (ACQUITTED, CIVIL, CONVICTED, CRIMINAL, DEFERRED, DISMISSED, EMPTY_COURT,
                                       NO_SEARCH_RAN, OPINION, PENDING, SEALED, UNKNOWN, CourtRecord,
                                       classify_court_status, validate_case_number, validate_person_name)

NAME = "Alex Examplename"            # fictional
KEY = "GOVINFO-TEST-KEY-123456"      # fictional


class Resp:
    def __init__(self, status=200, payload=None, bad_json=False):
        self.status_code, self._payload, self._bad = status, payload, bad_json
        self.headers, self.text = {}, ""

    def json(self):
        if self._bad:
            raise ValueError("not json")
        return self._payload


def item(n=1, **kw):
    d = {"title": f"UNITED STATES v. EXAMPLE {n}", "packageId": f"USCOURTS-xx-1_24-cr-0000{n}",
         "granuleId": f"USCOURTS-xx-1_24-cr-0000{n}-0", "governmentAuthor": ["Example District Court"],
         "dateIssued": "2024-05-01", "collectionCode": "USCOURTS",
         "resultLink": f"https://api.govinfo.gov/packages/USCOURTS-xx-1_24-cr-0000{n}/summary?api_key=LEAK"}
    d.update(kw)
    return d


@pytest.fixture()
def keyed():
    get_db().set_secret("govinfo_key", KEY)
    yield
    get_db().delete_secret("govinfo_key")


def fake_http(monkeypatch, response=None, exc=None, calls=None):
    def fake(method, url, **kw):
        if calls is not None:
            calls.append((method, url, kw))
        if exc:
            raise exc
        return response
    monkeypatch.setattr(court_sources.http, "request", fake)


NC = "nc_judicial"
MANUAL = {"source_id": NC, "title": "STATE v. EXAMPLE", "case_number": "24CR000123-456", "court": "Example County Superior Court",
          "record_type": "CRIMINAL", "original_status": "Dismissed - Voluntary", "charges": "SIMPLE ASSAULT",
          "filing_date": "2024-03-15", "disposition_date": "04/02/2024", "source_url": "https://www.nccourts.gov/example"}


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize("name", ["Alex Examplename", "Mary-Jane O'Neil", "José Núñez", "Smith, Alex Q."])
def test_valid_names(name):
    assert validate_person_name(name)[1] == ""


@pytest.mark.parametrize("name", ["", "Cher", "Alex1 Example", "alex@example.com", "https://x.test/a b", "A" * 170 + " B",
                                  "Alex <script> Example", "Alex\x00 Example;DROP"])
def test_invalid_names(name):
    assert validate_person_name(name)[1] != ""


@pytest.mark.parametrize("case", ["24CR000123-456", "1:24-cr-00123", "2024 CVS 1234", "24-1234"])
def test_valid_case_numbers(case):
    assert validate_case_number(case)[1] == ""


@pytest.mark.parametrize("case", ["", "ab", "NODIGITSHERE", "24CR<script>", "x" * 60 + "1", "24CR'; DROP TABLE x;--"])
def test_invalid_case_numbers(case):
    assert validate_case_number(case)[1] != ""


def test_unsupported_query_kind_is_rejected():
    r = cri.investigate(NAME, search_kind="address", outcomes=[])
    assert r.errors and not r.findings


# ---------------------------------------------------------------- jurisdictions and sources
def test_jurisdiction_selection_lists_only_matching_sources():
    assert {s.id for s in court_sources.sources_for("US")} == {"govinfo_uscourts", "pacer_pcl"}
    assert {s.id for s in court_sources.sources_for("NC")} == {"nc_judicial"}
    assert court_sources.sources_for("ZZ") == []


def test_every_source_documents_agency_url_method_auth_and_partial_coverage():
    for s in court_sources.COURT_SOURCES.values():
        assert s.agency and s.official_url.startswith("https://") and s.search_url.startswith("https://")
        assert s.method in ("automated", "manual") and s.auth and s.coverage and s.verified_note
        assert s.complete is False                      # no source is claimed to be complete
        assert any(s.official_url.split("/")[2].endswith(d) for d in s.official_domains)


def test_only_govinfo_is_automated_and_pacer_and_nc_are_manual():
    assert {s.id for s in court_sources.COURT_SOURCES.values() if s.automated} == {"govinfo_uscourts"}


def test_manual_sources_make_no_network_requests(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network used for a manual source")
    monkeypatch.setattr(court_sources.http, "request", boom)
    outs = cri.run_searches(NAME, "name", ["pacer_pcl", NC])
    assert [o.status for o in outs] == ["manual", "manual"] and all(not o.records for o in outs)


def test_unknown_source_id_is_an_error():
    with pytest.raises(ValueError):
        cri.run_searches(NAME, "name", ["not_a_source"])


# ---------------------------------------------------------------- GovInfo provider
def test_govinfo_request_uses_the_documented_endpoint_and_query(keyed, monkeypatch):
    calls = []
    fake_http(monkeypatch, Resp(payload={"results": [], "count": 0, "offsetMark": "*"}), calls=calls)
    o = court_sources.govinfo_search(NAME, "name")
    method, url, kw = calls[0]
    assert (method, url) == ("POST", "https://api.govinfo.gov/search")
    assert kw["json"]["query"] == f'collection:(USCOURTS) and "{NAME}"'
    assert kw["params"] == {"api_key": KEY} and "public_only" not in kw
    assert o.status == "ok" and o.records == []


def test_govinfo_query_escapes_quotes_and_backslashes():
    q = court_sources.build_govinfo_query('Alex "Q" \\ Example')
    assert q.count('"') == 2 and "\\" not in q


def test_govinfo_results_become_unreviewed_candidates(keyed, monkeypatch):
    fake_http(monkeypatch, Resp(payload={"results": [item(1), item(2)]}))
    o = court_sources.govinfo_search(NAME, "name")
    assert len(o.records) == 2
    r = o.records[0]
    assert r.record_type == OPINION and r.status == UNKNOWN and r.origin == "automated"
    assert r.court == "Example District Court" and r.published_date == "2024-05-01"
    assert "LEAK" not in r.source_url and "api_key" not in r.source_url and r.source_url.startswith("https://api.govinfo.gov/")
    assert r.url_note == ""


@pytest.mark.parametrize("status,needle", [(401, "invalid API key"), (403, "access denied"), (429, "rate limited"),
                                            (500, "server error"), (503, "server error"), (404, "unavailable")])
def test_govinfo_http_failures_are_classified(keyed, monkeypatch, status, needle):
    fake_http(monkeypatch, Resp(status=status, payload={}))
    o = court_sources.govinfo_search(NAME, "name")
    assert o.status == "error" and needle in o.detail and not o.records


@pytest.mark.parametrize("exc,needle", [(http.HttpError("Timed out contacting api.govinfo.gov"), "timeout"),
                                         (http.HttpError("Could not connect to api.govinfo.gov: ConnectionError"), "unavailable")])
def test_govinfo_network_failures(keyed, monkeypatch, exc, needle):
    fake_http(monkeypatch, exc=exc)
    o = court_sources.govinfo_search(NAME, "name")
    assert o.status == "error" and needle in o.detail


@pytest.mark.parametrize("resp", [Resp(bad_json=True), Resp(payload=[1, 2]), Resp(payload={"count": 1}),
                                   Resp(payload={"results": "nope"}), Resp(payload=None)])
def test_govinfo_malformed_responses_are_errors_not_empty_results(keyed, monkeypatch, resp):
    fake_http(monkeypatch, resp)
    o = court_sources.govinfo_search(NAME, "name")
    assert o.status == "error" and "invalid response" in o.detail


def test_govinfo_skips_malformed_items_but_keeps_good_ones(keyed, monkeypatch):
    items = [None, "x", {"title": "no id"}, {"packageId": "P"}, item(1), item(1)]       # last is a duplicate
    fake_http(monkeypatch, Resp(payload={"results": items}))
    o = court_sources.govinfo_search(NAME, "name")
    assert [r.record_id for r in o.records] == ["USCOURTS-xx-1_24-cr-00001-0"]


def test_missing_key_is_not_configured_and_makes_no_request(monkeypatch):
    get_db().delete_secret("govinfo_key")
    fake_http(monkeypatch, exc=AssertionError("no request expected"))
    o = court_sources.govinfo_search(NAME, "name")
    assert o.status == "not_configured" and "API Configuration" in o.detail


# ---------------------------------------------------------------- classification
@pytest.mark.parametrize("text,rtype,expected", [
    ("Dismissed - Voluntary", CRIMINAL, DISMISSED), ("DISMISSED WITH PREJUDICE", CIVIL, DISMISSED),
    ("Nolle Prosequi", CRIMINAL, DISMISSED), ("Convicted", CRIMINAL, CONVICTED),
    ("Guilty plea entered", CRIMINAL, CONVICTED), ("Not Guilty", CRIMINAL, ACQUITTED),
    ("Acquitted by jury", CRIMINAL, ACQUITTED), ("Pending", CRIMINAL, PENDING), ("open", CIVIL, PENDING),
    ("Deferred prosecution", CRIMINAL, DEFERRED), ("Sealed", CRIMINAL, SEALED), ("Expunged", CRIMINAL, SEALED),
    ("Not available online", UNKNOWN, SEALED),
    ("Arrested", CRIMINAL, UNKNOWN), ("Charged with assault", CRIMINAL, UNKNOWN), ("Filed", CIVIL, UNKNOWN),
    ("Judgment for plaintiff", CIVIL, UNKNOWN), ("", CRIMINAL, UNKNOWN), ("some new wording", CRIMINAL, UNKNOWN),
])
def test_status_classification(text, rtype, expected):
    assert classify_court_status(text, rtype) == expected


@pytest.mark.parametrize("text", ["Convicted", "Guilty", "Not Guilty", "Acquitted"])
@pytest.mark.parametrize("rtype", [CIVIL, OPINION, UNKNOWN])
def test_non_criminal_records_are_never_convicted_or_acquitted(text, rtype):
    assert classify_court_status(text, rtype) == UNKNOWN


def test_dismissal_is_never_an_acquittal_and_charge_is_never_a_conviction():
    assert classify_court_status("Dismissed", CRIMINAL) != ACQUITTED
    assert classify_court_status("Charged - Felony", CRIMINAL) != CONVICTED
    assert classify_court_status("Pending trial", CRIMINAL) != CONVICTED


# ---------------------------------------------------------------- investigation / evidence
def run(**kw):
    return cri.investigate(NAME, **kw)


def outcome_with(records, status="ok"):
    from providers.records_common import SearchOutcome
    return SearchOutcome(court_sources.GOVINFO, status, "x", records=records, query=NAME, query_kind="name")


def test_unattached_candidates_are_never_stored(keyed, monkeypatch):
    fake_http(monkeypatch, Resp(payload={"results": [item(1), item(2)]}))
    r = run(outcomes=cri.run_searches(NAME, "name", ["govinfo_uscourts"]))
    assert r.findings == []
    assert any("2 candidate record(s)" in n and "not stored" in n for n in r.notes)
    assert any("none was attached" in n for n in r.notes)
    assert not any(EMPTY_COURT == n for n in r.notes)


def test_selected_candidate_becomes_unverified_reviewed_finding(keyed, monkeypatch):
    fake_http(monkeypatch, Resp(payload={"results": [item(1), item(2)]}))
    outs = cri.run_searches(NAME, "name", ["govinfo_uscourts"])
    r = run(outcomes=outs, selected=[outs[0].records[1]])
    assert len(r.findings) == 1
    f = r.findings[0]
    assert f.confidence == "UNVERIFIED" and f.category == "court_record_reviewed" and f.source_type == "court"
    assert "UNVERIFIED name match" in f.description and "not proof of identity" in f.limitations
    assert "Review status: REVIEWED_BY_OPERATOR" in f.evidence and "Official source: GovInfo" in f.evidence
    assert f.source_url.startswith("https://api.govinfo.gov/") and "api_key" not in f.source_url
    assert "Retrieved/entered:" in f.evidence and "Original source status: not provided by source" in f.evidence


def test_a_selected_record_that_no_source_returned_is_rejected(keyed, monkeypatch):
    fake_http(monkeypatch, Resp(payload={"results": [item(1)]}))
    outs = cri.run_searches(NAME, "name", ["govinfo_uscourts"])
    forged = CourtRecord(source_id="govinfo_uscourts", jurisdiction="US", title="FORGED", record_id="X-1")
    r = run(outcomes=outs, selected=[forged])
    assert r.findings == [] and any("not returned by any searched source" in e for e in r.errors)


def test_manual_record_keeps_original_wording_and_normalizes_separately():
    r = run(outcomes=cri.run_searches(NAME, "name", [NC]), manual_records=[dict(MANUAL)])
    f = r.findings[0]
    assert f.category == "court_record_manual" and f.confidence == "UNVERIFIED"
    assert "Original source status: Dismissed - Voluntary" in f.evidence
    assert "TRACEPOINT normalized status: DISMISSED" in f.evidence
    assert "Disposition date: 2024-04-02" in f.evidence and "Filing date: 2024-03-15" in f.evidence
    assert f.source_url == "https://www.nccourts.gov/example" and f.value == "24CR000123-456"
    assert "Charges as published: SIMPLE ASSAULT" in f.evidence


def test_manual_record_with_unofficial_url_is_kept_but_flagged():
    r = run(outcomes=[], manual_records=[dict(MANUAL, source_url="https://example.org/case/1")])
    assert "not one of this source's official domains" in r.findings[0].limitations


@pytest.mark.parametrize("bad", [dict(MANUAL, source_id="nope"), dict(MANUAL, case_number="", title=""),
                                  dict(MANUAL, record_type="FELONY"), dict(MANUAL, filing_date="15th March"),
                                  dict(MANUAL, charges="lives at 123 Main Street apt 4"),
                                  dict(MANUAL, case_number="<script>1</script>")])
def test_invalid_manual_records_are_rejected_not_stored(bad):
    r = run(outcomes=[], manual_records=[bad])
    assert r.findings == [] and any("rejected" in e or "Choose" in e for e in r.errors)


def test_javascript_url_is_not_kept():
    r = run(outcomes=[], manual_records=[dict(MANUAL, source_url="javascript:alert(1)")])
    assert r.findings[0].source_url == ""
    assert "No official source URL" in r.findings[0].limitations


def test_exact_duplicate_entries_collapse_to_one_finding():
    r = run(outcomes=[], manual_records=[dict(MANUAL), dict(MANUAL)])
    assert len(r.findings) == 1


def test_conflicting_status_for_the_same_case_is_flagged_not_merged():
    r = run(outcomes=[], manual_records=[dict(MANUAL), dict(MANUAL, original_status="Convicted")])
    cats = sorted(f.category for f in r.findings)
    assert cats == ["contradiction", "court_record_manual"]


def test_different_cases_are_never_merged():
    r = run(outcomes=[], manual_records=[dict(MANUAL), dict(MANUAL, case_number="24CR000999-001")])
    assert len([f for f in r.findings if f.category == "court_record_manual"]) == 2


def test_civil_and_criminal_stay_distinct():
    r = run(outcomes=[], manual_records=[dict(MANUAL, record_type="CIVIL", original_status="Convicted")])
    f = r.findings[0]
    assert "TRACEPOINT normalized status: UNKNOWN" in f.evidence and "Civil case" in f.limitations


def test_name_search_adds_only_an_unverified_person_entity_and_no_relationships():
    r = run(outcomes=[], manual_records=[dict(MANUAL)])
    assert [(e.type, e.verification) for e in r.entities] == [("person", "UNVERIFIED")]
    assert r.relationships == []


def test_case_number_search_adds_no_person_entity():
    r = cri.investigate("24CR000123-456", search_kind="case_number", outcomes=[], manual_records=[dict(MANUAL)])
    assert r.entities == []


# ---------------------------------------------------------------- empty / negative / missing
def test_empty_search_shows_the_mandated_message_exactly(keyed, monkeypatch):
    fake_http(monkeypatch, Resp(payload={"results": []}))
    r = run(outcomes=cri.run_searches(NAME, "name", ["govinfo_uscourts"]))
    assert EMPTY_COURT in r.notes
    assert EMPTY_COURT == ("No records found in the sources searched. This does not establish that the individual has "
                           "no criminal or court history.")


def test_manual_only_search_does_not_claim_that_nothing_was_found():
    r = run(outcomes=cri.run_searches(NAME, "name", ["pacer_pcl", NC]))
    assert NO_SEARCH_RAN in r.notes and EMPTY_COURT not in r.notes
    assert [s.status for s in r.sources] == ["skipped", "skipped"]


def test_failed_provider_is_an_error_not_an_empty_result(keyed, monkeypatch):
    fake_http(monkeypatch, Resp(status=500, payload={}))
    r = run(outcomes=cri.run_searches(NAME, "name", ["govinfo_uscourts"]))
    assert EMPTY_COURT not in r.notes and NO_SEARCH_RAN in r.notes
    assert any("server error" in e for e in r.errors) and r.sources[0].status == "error"


def test_missing_configuration_is_reported(monkeypatch):
    get_db().delete_secret("govinfo_key")
    r = run(outcomes=cri.run_searches(NAME, "name", ["govinfo_uscourts"]))
    assert r.sources[0].status == "not_configured" and any("not configured" in e for e in r.errors)


def test_every_source_record_states_agency_method_and_partial_coverage():
    r = run(outcomes=cri.run_searches(NAME, "name", ["pacer_pcl", NC]))
    for s in r.sources:
        assert "Coverage: PARTIAL" in s.detail and "manual search required" in s.detail and s.url.startswith("https://")


def test_invalid_input_returns_an_error_and_no_search(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no search expected")
    monkeypatch.setattr(court_sources, "search_source", boom)
    monkeypatch.setattr(cri, "search_source", boom)
    r = cri.investigate("x", search_kind="name")
    assert r.errors and not r.sources


# ---------------------------------------------------------------- offline
def test_offline_operation_is_graceful(keyed, monkeypatch):
    fake_http(monkeypatch, exc=http.HttpError("Could not connect to api.govinfo.gov: ConnectionError"))
    r = run()                                       # default: every catalogued source
    assert len(r.sources) == 3 and r.findings == []
    assert NO_SEARCH_RAN in r.notes and any("unavailable" in e for e in r.errors)


# ---------------------------------------------------------------- persistence, history, reports
def test_authorization_is_required():
    with pytest.raises(PermissionError):
        investigation.run("court", NAME, authorized=False, search_kind="name", outcomes=[])


def test_investigation_is_persisted_and_visible_in_history():
    db = get_db()
    r, inv_id = investigation.run("court", NAME, authorized=True, search_kind="name",
                                  outcomes=cri.run_searches(NAME, "name", [NC]), manual_records=[dict(MANUAL)])
    row = db.get_investigation(inv_id)
    assert row["inv_type"] == "court" and row["target"] == NAME
    assert [f["category"] for f in db.findings(inv_id)] == ["court_record_manual"]
    assert db.sources(inv_id)[0]["name"].startswith("North Carolina Judicial Branch")
    assert inv_id in [x["id"] for x in db.list_investigations(500)]
    assert "authorization affirmed" in db.get_investigation(inv_id)["notes"]


def test_rerunning_does_not_duplicate_records_inside_an_investigation():
    r, inv_id = investigation.run("court", NAME, authorized=True, search_kind="name", outcomes=[],
                                  manual_records=[dict(MANUAL), dict(MANUAL)])
    assert len(get_db().findings(inv_id)) == 1


def test_court_and_registry_records_use_different_categories():
    from modules.records_shared import COURT_CATEGORIES, REGISTRY_CATEGORIES
    assert set(COURT_CATEGORIES).isdisjoint(REGISTRY_CATEGORIES)


@pytest.fixture()
def saved(tmp_path, monkeypatch):
    monkeypatch.setattr(reports, "REPORTS_DIR", tmp_path)
    _, inv_id = investigation.run("court", NAME, authorized=True, search_kind="name",
                                  outcomes=cri.run_searches(NAME, "name", ["pacer_pcl", NC]),
                                  manual_records=[dict(MANUAL, title="<script>alert(1)</script> v. EXAMPLE")])
    return inv_id


def test_reports_in_all_formats_separate_record_types_and_state_limits(saved):
    built = reports.build(saved)
    rr = built["records_review"]
    assert "UNVERIFIED name/identifier matches" in rr["unverified_name_matches"]
    assert "1 entered from the official portal" in rr["manually_reviewed_records"]
    assert any("PACER" in x or "North Carolina" in x for x in rr["inaccessible_sources"])
    assert "dismissal is not an acquittal" in rr["statement"]
    txt = reports.save(saved, "txt").read_text(encoding="utf-8")
    html = reports.save(saved, "html").read_text(encoding="utf-8")
    js = json.loads(reports.save(saved, "json").read_text(encoding="utf-8"))
    assert "RECORDS REVIEW" in txt and "Inaccessible or manual-only sources" in txt
    assert "Records review" in html and js["records_review"]["partial_coverage"]
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html            # report injection
    assert "Court record:" in txt and "confirmed" not in built["conclusion"].lower().replace("unconfirmed", "")


def test_non_record_reports_have_no_records_review_section():
    assert reports._records_review("domain", [], [], []) is None


# ---------------------------------------------------------------- security
def test_api_key_never_reaches_findings_sources_errors_or_logs(keyed, monkeypatch):
    fake_http(monkeypatch, Resp(payload={"results": [item(1)]}))
    outs = cri.run_searches(NAME, "name", ["govinfo_uscourts"])
    r = run(outcomes=outs, selected=outs[0].records)
    blob = json.dumps([f.to_dict() for f in r.findings]) + json.dumps([vars(s) for s in r.sources]) + " ".join(r.errors + r.notes)
    assert KEY not in blob and "LEAK" not in blob
    log = logging.getLogger("tracepoint")
    for h in log.handlers:
        h.flush()
        assert KEY not in open(h.baseFilename, encoding="utf-8").read()


def test_govinfo_host_is_fixed_and_tls_verification_is_default():
    assert court_sources.GOVINFO_SEARCH_URL == "https://api.govinfo.gov/search"
    assert http._session.verify is True


# ---------------------------------------------------------------- CLI
def flat(text: str) -> str:
    """Console output without box-drawing characters or line wrapping."""
    import re
    return " ".join(re.sub(r"[─-╿]", " ", text).split())


def _drive(monkeypatch, prompts, confirms):
    import main
    from ui.theme import THEME
    buf = io.StringIO()
    monkeypatch.setattr(main, "console", Console(file=buf, width=200, force_terminal=False, color_system=None, theme=THEME))
    p, c = iter(prompts), iter(confirms)
    monkeypatch.setattr(main.Prompt, "ask", lambda *a, **k: next(p))
    monkeypatch.setattr(main.Confirm, "ask", lambda *a, **k: next(c))
    return main, buf


def test_menu_keeps_existing_options_and_adds_court_and_registry():
    import main
    nums = {n: k for n, k, _ in main.MENU} | {n: k for n, k, _ in main.ACTIONS}
    for n, k in {"1": "email", "8": "name", "9": "universal", "13": "api", "15": "ai", "0": "exit"}.items():
        assert nums[n] == k
    assert nums["16"] == "court" and nums["17"] == "registry"


def test_cli_court_workflow_manual_source_saves_reviewed_record(monkeypatch):
    fields = [MANUAL[k] for k in ("title", "case_number", "court", "record_type", "original_status", "charges",
                                  "filing_date", "disposition_date", "source_url")]
    main, buf = _drive(monkeypatch, ["NC", "1", "name", NAME] + fields + ["back"],
                       [True, False, True, False])   # authorize, open browser?, enter record, enter another?
    before = len(get_db().list_investigations(500))
    main.court_records_flow()
    rows = get_db().list_investigations(500)
    assert len(rows) == before + 1
    inv = rows[0]
    assert inv["inv_type"] == "court"
    f = get_db().findings(inv["id"])
    assert len(f) == 1 and f[0]["category"] == "court_record_manual" and f[0]["confidence"] == "UNVERIFIED"
    out = flat(buf.getvalue())
    assert "MANUAL" in out and "name match is NOT proof" in out and "https://www.nccourts.gov/records" in out


def test_cli_court_workflow_declined_authorization_saves_nothing(monkeypatch):
    main, buf = _drive(monkeypatch, ["NC", "1", "name", NAME], [False])
    before = len(get_db().list_investigations(500))
    main.court_records_flow()
    assert len(get_db().list_investigations(500)) == before and "authorization not given" in flat(buf.getvalue())


def test_cli_court_workflow_rejects_an_invalid_name_before_any_search(monkeypatch):
    main, buf = _drive(monkeypatch, ["US", "1", "name", "Cher"], [])
    main.court_records_flow()
    assert "full name" in flat(buf.getvalue()).lower()


def test_cli_court_workflow_attaches_only_confirmed_candidates(monkeypatch, keyed):
    fake_http(monkeypatch, Resp(payload={"results": [item(1), item(2), item(3)]}))
    # US -> source 1 (GovInfo, automated) -> name -> attach #1 and #3, confirm only #3 -> no manual entry -> back
    main, buf = _drive(monkeypatch, ["US", "1", "name", NAME, "1,3", "back"], [True, False, True, False])
    main.court_records_flow()
    inv = get_db().list_investigations(500)[0]
    vals = [f["value"] for f in get_db().findings(inv["id"])]
    assert vals == ["USCOURTS-xx-1_24-cr-00003-0"]
    assert "UNVERIFIED name matches" in flat(buf.getvalue())


def test_searched_name_is_not_written_to_the_log(keyed, monkeypatch):
    # the real HTTP layer logs host+status only; run it against a stub session to prove the name never appears
    class FakeSession:
        def request(self, method, url, **kw):
            import requests
            r = requests.Response()
            r.status_code = 200
            r._content = b'{"results": []}'
            r.raw = None
            r.iter_content = lambda n: iter([b'{"results": []}'])
            return r
    monkeypatch.setattr(http, "_session", FakeSession())
    o = court_sources.govinfo_search("Zelda Uniquelogprobe", "name")
    assert o.status == "ok"
    for h in logging.getLogger("tracepoint").handlers:
        h.flush()
        text = open(h.baseFilename, encoding="utf-8").read()
        assert "Uniquelogprobe" not in text and "api.govinfo.gov" in text and KEY not in text


@pytest.mark.parametrize("title", ["IN RE [SEALED] MATTER", "United States v. [/x] Example", "A [bold]B[/bold] C",
                                   "X [link=http://evil.test]click[/link]"])
def test_markup_in_record_text_is_displayed_literally_and_never_crashes(monkeypatch, title):
    main, buf = _drive(monkeypatch, [""], [])
    monkeypatch.setattr(main, "ask", lambda *a, **k: "")
    rec = CourtRecord("govinfo_uscourts", "US", title=title, record_id="1", source_url="https://api.govinfo.gov/x")
    main._choose_candidates([rec], "record")
    assert title in " ".join(flat(buf.getvalue()).split())


@pytest.mark.parametrize("title", ["IN RE [SEALED] MATTER", "United States v. [/x] Example", "A [bold]B[/bold] C"])
def test_history_view_escapes_markup_in_stored_findings(monkeypatch, title):
    r, inv_id = investigation.run("court", NAME, authorized=True, search_kind="name", outcomes=[],
                                  manual_records=[dict(MANUAL, title=title, case_number="24CR000777-001")])
    main, buf = _drive(monkeypatch, ["back"], [])
    main.view_investigation(inv_id)
    assert title in " ".join(flat(buf.getvalue()).split())
