"""Integration layer tests. ALL responses here are MOCKED at the requests-session level (so the real
core.http code, including retries, logging and redaction, runs). Nothing in this file proves a live
connection; see tests/test_integrations_live.py (opt-in) for that."""
import json
import logging

import pytest
import requests

from core import http
from core.configuration import ENV_VARS, LOGS_DIR
from core.database import get_db
from integrations import base, manager
from integrations.base import (AUTH_FAILED, CONNECTED, DISABLED, ERROR, NOT_CONFIGURED, NOT_TESTED, RATE_LIMITED,
                               UNAVAILABLE)

SECRET = "SuperSecretKey-9f8e7d6c5b4a"

# Minimal valid answer for each provider's connection test.
GOOD = {
    "searxng": {"results": []}, "brave": {"web": {"results": []}}, "google_cse": {"items": []},
    "gdelt": {"articles": [{}]}, "internet_archive": {"response": {"docs": [{}]}},
    "wikipedia": {"query": {"search": [{}]}}, "ipinfo": {"ip": "8.8.8.8"}, "ipdata": {"ip": "8.8.8.8"},
    "ipdb": {"ip": "8.8.8.8"}, "openipapi": {"usage": 1}, "bgpview": {"status": "ok"},
    "ripestat": {"status": "ok", "data": {}}, "rdap": {"objectClassName": "domain"},
    "abuseipdb": {"data": {}}, "virustotal": {"data": {}}, "otx": {"username": "x"}, "urlscan": {"results": []},
    "threatfox": {"query_status": "ok"}, "urlhaus": {"query_status": "no_results"},
    "courtlistener": {"results": []}, "govinfo": {"collections": []}, "sec_edgar": {"cik": "320193"},
    "usaspending": {"results": []}, "fec": {"results": []}, "opencorporates": {"results": {"companies": []}},
    "crtsh": [], "wayback": {"archived_snapshots": {}}, "cloudflare_doh": {"Status": 0},
}
CRED_VALUE = {"searxng_url": "http://127.0.0.1:8888", "sec_contact": "Test Runner test@example.org"}


class Net:
    """Scriptable fake network. `plan` is a list of responses/exceptions consumed in order (last repeats)."""
    def __init__(self):
        self.calls = []
        self.plan = []

    def respond(self, status=200, body=None, headers=None, text=None):
        r = requests.Response()
        r.status_code = status
        r._content = (text if text is not None else json.dumps(body if body is not None else {})).encode()
        r._content_consumed = True
        r.headers.update(headers or {})
        return r

    def __call__(self, method, url, **kw):
        self.calls.append((method, url, kw))
        item = self.plan[min(len(self.calls) - 1, len(self.plan) - 1)]
        if isinstance(item, Exception):
            raise item
        return item


@pytest.fixture(autouse=True)
def env(monkeypatch):
    for var in ENV_VARS.values():
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(http, "_MIN_INTERVAL", 0)
    monkeypatch.setattr("time.sleep", lambda s: None)
    net = Net()
    monkeypatch.setattr(http._session, "request", net)
    db = get_db()
    for p in manager.providers():
        db.set_setting(manager._PREFIX + p.id, "")
        db.set_setting(manager._OFF + p.id, "")
        p.quota = None
        for k in p.secret_keys + p.optional_keys:
            db.delete_secret(k)
    yield net
    for p in manager.providers():
        for k in p.secret_keys + p.optional_keys:
            db.delete_secret(k)


def configure(p, value=SECRET):
    for k in p.secret_keys:
        get_db().set_secret(k, CRED_VALUE.get(k, value))


ALL = [p.id for p in manager.providers()]
KEYED = [p.id for p in manager.providers() if p.secret_keys]


def test_all_25_requested_services_are_registered():
    wanted = {"searxng", "gdelt", "internet_archive", "wikipedia", "ipinfo", "ipdata", "ipdb", "openipapi", "bgpview",
              "rdap", "abuseipdb", "virustotal", "otx", "urlscan", "threatfox", "urlhaus", "courtlistener", "govinfo",
              "sec_edgar", "usaspending", "fec", "crtsh", "wayback", "opencorporates", "cloudflare_doh"}
    assert wanted <= set(ALL)
    assert set(GOOD) == set(ALL), "every registered provider needs a mocked success payload"


def test_metadata_is_complete_and_honest():
    for p in manager.providers():
        assert p.name and p.category and p.endpoint and p.lookups and p.docs_url, p.id
        assert p.tier in (base.FREE, base.FREE_TIER, base.PAID)
        assert "unlimited" not in p.free_info.lower()
        for k in p.secret_keys + p.optional_keys:
            assert k in ENV_VARS


# --- per-provider behaviours ------------------------------------------------------------------
@pytest.mark.parametrize("pid", ALL)
def test_success_is_connected_only_after_a_real_request(env, pid):
    p = manager.get(pid)
    configure(p)
    env.plan = [env.respond(200, GOOD[pid])]
    assert manager.status(pid)["status"] == NOT_TESTED          # key present, nothing sent yet
    assert env.calls == []
    row = manager.test(pid)
    assert env.calls, "a test must make a request"
    assert row["status"] == CONNECTED, row
    assert row["last_success"]


@pytest.mark.parametrize("pid", KEYED)
def test_missing_credentials_is_not_configured_and_sends_nothing(env, pid):
    row = manager.test(pid)
    assert row["status"] == NOT_CONFIGURED
    assert env.calls == []
    assert any(v in row["detail"] for v in ENV_VARS.values())
    assert manager.lookup(pid, list(manager.get(pid).lookups)[0], "example.com")["status"] == NOT_CONFIGURED
    assert env.calls == []


@pytest.mark.parametrize("pid", ALL)
def test_invalid_credentials_401(env, pid):
    configure(manager.get(pid))
    env.plan = [env.respond(401, {"error": "bad key " + SECRET})]
    row = manager.test(pid)
    # SearXNG has no credentials: a 401 there is an access/configuration problem, not a bad key.
    assert row["status"] == (UNAVAILABLE if pid == "searxng" else AUTH_FAILED), row
    assert SECRET not in json.dumps(row)


@pytest.mark.parametrize("pid", ALL)
def test_rate_limit_429(env, pid):
    configure(manager.get(pid))
    env.plan = [env.respond(429, {}, headers={"Retry-After": "30"})]
    assert manager.test(pid)["status"] == RATE_LIMITED


@pytest.mark.parametrize("pid", ALL)
def test_timeout(env, pid):
    configure(manager.get(pid))
    env.plan = [requests.Timeout("slow")]
    row = manager.test(pid)
    assert row["status"] == UNAVAILABLE and "Timed out" in row["detail"]


@pytest.mark.parametrize("pid", ALL)
def test_server_error_and_connection_error(env, pid):
    configure(manager.get(pid))
    env.plan = [env.respond(503, {})]
    assert manager.test(pid)["status"] == UNAVAILABLE
    env.plan = [requests.ConnectionError("dns")]
    assert manager.test(pid)["status"] == UNAVAILABLE


@pytest.mark.parametrize("pid", ALL)
def test_malformed_responses_are_errors_not_crashes(env, pid):
    configure(manager.get(pid))
    for plan in (env.respond(200, text="<html>not json</html>"), env.respond(200, text='"just a string"'),
                 env.respond(200, text="")):
        env.plan = [plan]
        row = manager.test(pid)
        assert row["status"] in (ERROR, UNAVAILABLE), (pid, row)
        assert row["status"] != CONNECTED


def test_unexpected_exception_inside_a_provider_cannot_escape(env, monkeypatch):
    p = manager.get("wikipedia")
    monkeypatch.setattr(p, "_probe", lambda: 1 / 0)
    assert manager.test("wikipedia")["status"] == ERROR
    monkeypatch.setattr(p, "lookup", lambda *a, **k: 1 / 0)
    r = manager.lookup("wikipedia", "query", "x")
    assert not r["ok"] and r["status"] == ERROR


def test_transient_failure_is_retried_with_backoff(env):
    env.plan = [env.respond(503, {}), env.respond(200, GOOD["wikipedia"])]
    r = manager.lookup("wikipedia", "query", "Alan Turing")
    assert r["ok"] and len(env.calls) == 2


# --- lookups & normalized format --------------------------------------------------------------
def test_normalized_result_shape_and_provenance(env):
    env.plan = [env.respond(200, {"query": {"search": [{"title": "Alan Turing", "pageid": 1, "snippet": "s"}]}})]
    r = manager.lookup("wikipedia", "query", "Alan Turing")
    assert r["ok"]
    res = r["result"]
    assert set(res) == {"provider", "query", "timestamp", "source_url", "result_type", "data", "confidence", "limitations"}
    assert res["source_url"].startswith("https://") and res["timestamp"] and res["confidence"] is None
    assert res["data"]["raw"], "original provider response is preserved"
    assert res["limitations"]


def test_ip_lookups_refuse_private_addresses_and_send_nothing(env):
    for pid in ("ipinfo", "ripestat", "rdap"):
        r = manager.lookup(pid, "ip", "192.168.1.5")
        assert not r["ok"] and "never sent" in r["error"]
    assert env.calls == []


def test_ip_results_carry_the_not_proof_of_identity_warning(env):
    env.plan = [env.respond(200, {"ip": "1.1.1.1", "city": "X"})]
    r = manager.lookup("ipinfo", "ip", "1.1.1.1")
    assert any("never proof of identity" in l for l in r["result"]["limitations"])


def test_public_records_carry_the_same_name_warning(env):
    for pid, kind in (("courtlistener", "opinions"), ("fec", "candidate"), ("usaspending", "recipient"),
                      ("opencorporates", "company"), ("govinfo", "query")):
        assert any("different person" in l or "same" in l for l in manager.get(pid).limitations), pid


def test_input_validation_rejects_bad_values_without_network(env):
    assert not manager.lookup("rdap", "domain", "not a domain!")["ok"]
    assert not manager.lookup("cloudflare_doh", "dns", "")["ok"]
    assert not manager.lookup("ripestat", "asn", "ASxyz")["ok"]
    assert not manager.lookup("wikipedia", "bogus", "x")["ok"]
    assert not manager.lookup("nope", "x", "y")["ok"]
    assert env.calls == []


def test_virustotal_only_looks_up_it_never_uploads(env):
    p = manager.get("virustotal")
    configure(p)
    env.plan = [env.respond(404, {})]
    r = manager.lookup("virustotal", "hash", "a" * 64)
    assert r["ok"] and r["result"]["data"]["found"] is False
    assert all(c[0] == "GET" for c in env.calls)
    assert not manager.lookup("virustotal", "hash", "not-a-hash")["ok"]


def test_sec_edgar_declares_contact_user_agent(env):
    configure(manager.get("sec_edgar"))
    env.plan = [env.respond(200, {"cik": "320193", "name": "Apple", "filings": {"recent": {}}})]
    assert manager.lookup("sec_edgar", "cik", "320193")["ok"]
    ua = env.calls[0][2]["headers"]["User-Agent"]
    assert "test@example.org" in ua


def test_quota_is_read_from_headers_and_shown(env):
    configure(manager.get("abuseipdb"))
    env.plan = [env.respond(200, GOOD["abuseipdb"], headers={"X-RateLimit-Remaining": "973", "X-RateLimit-Limit": "1000"})]
    row = manager.test("abuseipdb")
    assert row["quota"]["remaining"] == 973 and row["quota"]["limit"] == 1000


def test_fec_without_key_uses_demo_key_and_says_so(env):
    env.plan = [env.respond(200, GOOD["fec"])]
    row = manager.test("fec")
    assert row["status"] == CONNECTED and "DEMO_KEY" in row["detail"]


# --- manager behaviours -----------------------------------------------------------------------
def test_disabled_provider_sends_nothing(env):
    manager.set_disabled("wikipedia", True)
    assert manager.status("wikipedia")["status"] == DISABLED
    assert manager.test("wikipedia")["status"] == DISABLED
    assert manager.lookup("wikipedia", "query", "x")["status"] == DISABLED
    assert env.calls == []
    manager.set_disabled("wikipedia", False)
    assert manager.status("wikipedia")["status"] == NOT_TESTED


def test_statuses_never_touch_the_network(env):
    env.plan = [AssertionError("network used")]
    rows = manager.statuses()
    assert len(rows) == len(ALL) and env.calls == []


def test_one_failing_provider_does_not_stop_the_others(env, monkeypatch):
    monkeypatch.setattr(manager.get("gdelt"), "test", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    env.plan = [env.respond(200, {})]
    rows = manager.test_all()
    by = {r["id"]: r for r in rows}
    assert by["gdelt"]["status"] == ERROR
    assert len(rows) == len(ALL)
    assert by["abuseipdb"]["status"] == NOT_CONFIGURED


def test_changing_a_credential_invalidates_an_earlier_connected_result(env):
    p = manager.get("abuseipdb")
    configure(p)
    env.plan = [env.respond(200, GOOD["abuseipdb"])]
    assert manager.test("abuseipdb")["status"] == CONNECTED
    from core import credentials
    credentials.save_credential(get_db(), "abuseipdb_key", "another-key-123456")
    assert manager.status("abuseipdb")["status"] == NOT_TESTED


def test_env_var_is_a_credential_fallback_and_db_wins(env, monkeypatch):
    monkeypatch.setenv("OTX_API_KEY", "from-environment-123")
    assert get_db().get_secret("otx_key") == "from-environment-123"
    get_db().set_secret("otx_key", "from-database-123")
    assert get_db().get_secret("otx_key") == "from-database-123"


def test_pacing_enforces_min_interval(env, monkeypatch):
    slept = []
    monkeypatch.setattr("time.sleep", lambda s: slept.append(s))
    p = manager.get("gdelt")
    p._last = 0.0
    p._pace(); p._pace()
    assert slept and slept[-1] > 4


# --- secrets & logs ---------------------------------------------------------------------------
def test_secrets_never_reach_logs_status_or_results(env):
    log = logging.getLogger("tracepoint")
    for h in log.handlers:
        h.flush()
    for pid in KEYED:
        configure(manager.get(pid), SECRET)
    # a hostile provider that echoes the key in headers, body and error text
    echo = {"Echo": SECRET}
    for status in (200, 401, 429, 500):
        env.plan = [env.respond(status, {"error": SECRET, "ip": SECRET, "data": {}}, headers=echo)]
        for pid in KEYED:
            manager.test(pid)
            manager.lookup(pid, list(manager.get(pid).lookups)[0], "1.1.1.1" if "ip" in manager.get(pid).lookups else "example.com")
    dump = json.dumps(manager.statuses())
    assert SECRET not in dump
    for h in log.handlers:
        h.flush()
    text = (LOGS_DIR / "tracepoint.log").read_text(encoding="utf-8", errors="replace")
    assert SECRET not in text
    assert "integration test" in text  # the log is being written, so the absence above is meaningful


def test_status_rows_expose_only_variable_names_never_values(env):
    configure(manager.get("abuseipdb"))
    row = manager.status("abuseipdb")
    assert row["env_vars"] == ["ABUSEIPDB_API_KEY"] and SECRET not in json.dumps(row)


def test_env_example_has_every_variable_and_no_real_values():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / ".env.example").read_text(encoding="utf-8")
    vars_ = dict(l.split("=", 1) for l in text.splitlines() if "=" in l and not l.startswith("#"))
    for v in ENV_VARS.values():
        assert v in vars_, v
    assert {k: v for k, v in vars_.items() if v.strip()} == {"GOOGLE_SEARCH_CX": "b20aada3b04a34865"}


def test_gitignore_covers_env_files():
    from pathlib import Path
    text = (Path(__file__).resolve().parents[1] / ".gitignore").read_text(encoding="utf-8-sig")
    assert ".env" in text.splitlines() and "!.env.example" in text.splitlines()


def test_dashboard_view_renders_without_secrets(env):
    from rich.console import Console
    from ui import integrations_view as iv
    from ui.theme import THEME
    configure(manager.get("abuseipdb"))
    con = Console(record=True, width=160, theme=THEME)
    rows = manager.statuses()
    con.print(iv.table(rows))
    con.print(iv.detail(next(r for r in rows if r['id'] == 'abuseipdb')))
    out = con.export_text()
    assert SECRET not in out and "AbuseIPDB" in out and "NOT TESTED" in out and "ABUSEIPDB_API_KEY" in out


def test_dashboard_menu_flow_runs_end_to_end_with_mocked_network(env, monkeypatch):
    import io
    import main
    from rich.console import Console
    from ui.theme import THEME
    buf = io.StringIO()
    monkeypatch.setattr(main, "console", Console(file=buf, theme=THEME, width=160, highlight=False))
    answers = iter(["t 6", "x 6", "t 6", "x 6", "l 6", "bogus", "99", ""])
    monkeypatch.setattr(main, "ask", lambda *a, **k: next(answers))
    monkeypatch.setattr(main.Prompt, "ask", lambda *a, **k: "Alan Turing")
    monkeypatch.setattr(main.console, "input", lambda *a, **k: "")
    env.plan = [env.respond(200, {"query": {"search": [{"title": "Alan Turing", "pageid": 1, "snippet": "s"}]}})]
    main.integrations_dashboard()
    out = buf.getvalue()
    assert "Wikipedia" in out and "CONNECTED" in out and "DISABLED" in out and "RESULT" in out
    assert "Invalid selection" in out
