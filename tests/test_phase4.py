"""Phase 4 tests: provider error classification, fallback, connection status, SearXNG validation,
credential UX rules, Name Intelligence search failures. Fully mocked; no network."""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("HOME", tempfile.mkdtemp())

import pytest

from core import credentials, database, http, search_engine, security
from core.database import Database
from core.models import ModuleResult
from modules import name_intel
from providers import search_providers as sp

SECRET = "SECRETKEY-1234567890"


class Resp:
    def __init__(self, code=200, payload=None, text=None, headers=None):
        self.status_code, self._p, self.headers = code, payload, headers or {}
        self.text = text if text is not None else ""

    def json(self):
        if self._p is None:
            raise ValueError("not json")
        return self._p


class Env:
    pass


@pytest.fixture
def env(monkeypatch):
    db = Database(Path(tempfile.mktemp(suffix=".db")))
    monkeypatch.setattr(database, "_db", db)
    e = Env()
    e.db = db
    e.calls = {"get": [], "request": []}
    e.get = lambda url, **kw: Resp(500)
    e.request = lambda m, url, **kw: Resp(202, text="<html>anomaly</html>")

    def fake_get(url, **kw):
        e.calls["get"].append(url)
        r = e.get(url, **kw)
        if isinstance(r, Exception):
            raise r
        return r

    def fake_request(m, url, **kw):
        e.calls["request"].append(url)
        r = e.request(m, url, **kw)
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(http, "get", fake_get)
    monkeypatch.setattr(http, "request", fake_request)
    return e


def brave(env):
    env.db.set_secret("brave_search_key", SECRET)
    return sp.BraveSearch()


def google(env):
    env.db.set_secret("google_cse_key", SECRET)
    env.db.set_secret("google_cse_cx", "cx-1234567")
    return sp.GoogleCSE()


def searx(env, url="http://127.0.0.1:8888"):
    env.db.set_secret("searxng_url", url)
    return sp.SearXNG()


def kind_of(fn):
    with pytest.raises(sp.ProviderError) as ei:
        fn()
    assert SECRET not in str(ei.value)
    return ei.value.kind


DDG_OK = ('<a class="result__a" href="https://example.org/a">Ada Lovelace page</a>'
          '<a class="result__snippet">Ada Lovelace snippet</a>')


# --- classification -----------------------------------------------------------
def test_invalid_credentials(env):
    b, g = brave(env), google(env)
    env.get = lambda url, **kw: Resp(401, {"error": {}})
    assert kind_of(lambda: b.search("q")) == sp.INVALID_KEY
    env.get = lambda url, **kw: Resp(400, {"error": {"code": 400, "message": "API key not valid. Please pass a valid API key.",
                                                      "status": "INVALID_ARGUMENT"}})
    assert kind_of(lambda: g.search("q")) == sp.INVALID_KEY
    env.get = lambda url, **kw: Resp(401, {})
    assert b.test_connection().status == sp.ST_INVALID


def test_rate_limits(env):
    b = brave(env)
    env.get = lambda url, **kw: Resp(429, {})
    assert kind_of(lambda: b.search("q")) == sp.RATE_LIMIT
    assert b.test_connection().status == sp.ST_RATE_LIMITED


def test_google_quota_exhaustion(env):
    g = google(env)
    env.get = lambda url, **kw: Resp(403, {"error": {"code": 403, "message": "Daily Limit Exceeded",
                                                      "errors": [{"reason": "dailyLimitExceeded"}]}})
    assert kind_of(lambda: g.search("q")) == sp.QUOTA
    env.get = lambda url, **kw: Resp(429, {"error": {"status": "RESOURCE_EXHAUSTED",
                                                      "message": "Quota exceeded for quota metric"}})
    assert kind_of(lambda: g.search("q")) == sp.QUOTA
    assert g.test_connection().status == sp.ST_RATE_LIMITED
    env.get = lambda url, **kw: Resp(403, {"error": {"message": "API not enabled", "errors": [{"reason": "forbidden"}]}})
    assert kind_of(lambda: g.search("q")) == sp.ACCESS_DENIED


def test_searxng_access_denied(env):
    s = searx(env)
    env.get = lambda url, **kw: Resp(403, text="Forbidden")
    assert kind_of(lambda: s.search("q")) == sp.ACCESS_DENIED
    st = s.test_connection()
    assert st.status == sp.ST_UNAVAILABLE and "JSON" in st.detail


@pytest.mark.parametrize("payload", [None, [1, 2], {"unexpected": 1}, {"web": "x"}])
def test_malformed_responses_are_invalid_response(env, payload):
    for prov in (brave(env), google(env), searx(env)):
        env.get = lambda url, **kw: Resp(200, payload)
        if isinstance(payload, dict) and prov.name == "Google Programmable Search":
            continue  # Google omits 'items' when there are zero results
        if payload == {"unexpected": 1} and prov.name == "Brave Search API":
            continue  # Google omits 'items' and Brave omits 'web' when there are zero results
        assert kind_of(lambda: prov.search("q")) == sp.INVALID_RESPONSE


def test_timeouts_server_errors_and_connection_failures(env):
    b = brave(env)
    env.get = lambda url, **kw: http.HttpError("Timed out contacting api.search.brave.com")
    assert kind_of(lambda: b.search("q")) == sp.TIMEOUT
    env.get = lambda url, **kw: http.HttpError("Could not connect to x: ConnectionError")
    assert kind_of(lambda: b.search("q")) == sp.UNAVAILABLE
    env.get = lambda url, **kw: Resp(503)
    assert kind_of(lambda: b.search("q")) == sp.SERVER_ERROR
    assert b.test_connection().status == sp.ST_UNAVAILABLE


# --- fallback / completion semantics --------------------------------------------
def test_duckduckgo_fallback_only_after_all_configured_fail(env):
    brave(env)
    env.get = lambda url, **kw: Resp(401, {})
    env.request = lambda m, url, **kw: Resp(200, text=DDG_OK)
    res = ModuleResult("t", "x")
    out = search_engine.search("ada", 5, res)
    assert out.completed and out.fallback_used
    assert [r.provider for r in out] == ["DuckDuckGo (HTML)"]
    st = {s.name: s for s in res.sources}
    assert st["Brave Search API"].status == "error" and "INVALID_KEY" in st["Brave Search API"].detail
    assert st["DuckDuckGo (HTML)"].status == "ok" and "fallback" in st["DuckDuckGo (HTML)"].detail


def test_no_fallback_when_configured_provider_succeeds_with_zero_results(env):
    brave(env)
    env.get = lambda url, **kw: Resp(200, {"web": {"results": []}})
    env.request = lambda m, url, **kw: pytest.fail("DuckDuckGo must not be used")
    out = search_engine.search("nobody", 5, ModuleResult("t", "x"))
    assert out == [] and out.completed is True and out.fallback_used is False


def test_all_providers_failing_is_not_zero_results(env):
    brave(env)
    env.get = lambda url, **kw: Resp(401, {})
    env.request = lambda m, url, **kw: Resp(202, text="")
    res = ModuleResult("t", "x")
    out = search_engine.search("ada", 5, res)
    assert out == [] and out.completed is False
    assert any("did not run successfully" in e for e in res.errors)
    assert all(not a["ok"] for a in out.attempts)


def test_unconfigured_uses_duckduckgo_as_default_not_fallback(env):
    env.request = lambda m, url, **kw: Resp(200, text=DDG_OK)
    out = search_engine.search("ada", 5)
    assert out.completed and not out.fallback_used and len(out) == 1


def test_duckduckgo_no_results_page_is_a_completed_search(env):
    env.request = lambda m, url, **kw: Resp(200, text='<div class="no-results">No results.</div>')
    out = search_engine.search("zzzz", 5)
    assert out == [] and out.completed is True


# --- connection status honesty -----------------------------------------------------
def test_status_is_configured_until_a_test_succeeds(env):
    b = brave(env)
    assert search_engine.provider_status(b)[0] == "CONFIGURED"
    env.get = lambda url, **kw: Resp(200, {"web": {"results": []}})
    assert search_engine.check_provider(b).status == "CONNECTED"
    assert search_engine.provider_status(b)[0] == "CONNECTED"
    ok, _ = credentials.save_credential(env.db, "brave_search_key", "another-key-98765")
    assert ok and search_engine.provider_status(b)[0] == "CONFIGURED"  # changed key invalidates old test
    env.get = lambda url, **kw: Resp(401, {})
    search_engine.check_provider(b)
    assert search_engine.provider_status(b)[0] == "INVALID CREDENTIALS"
    assert search_engine.provider_status(sp.SearXNG())[0] == "NOT SET"


def test_connection_test_makes_a_single_request(env):
    b = brave(env)
    env.get = lambda url, **kw: Resp(503)
    b.test_connection()
    assert len(env.calls["get"]) == 1


# --- SearXNG URL validation ----------------------------------------------------------
@pytest.mark.parametrize("value,ok", [
    ("http://127.0.0.1:8888", True), ("https://search.example.org/", True), ("https://example.org/searx", True),
    ("", False), ("example.org", False), ("ftp://example.org", False), ("javascript:alert(1)", False),
    ("http://", False), ("http://host:99999", False), ("http://user:pw@host", False),
    ("http://host/?q=1", False), ("http://ho st", False), ("file:///etc/passwd", False),
])
def test_searxng_url_validation(value, ok):
    url, err = sp.validate_searxng_url(value)
    assert (err == "") is ok
    if ok:
        assert not url.endswith("/") and url.startswith(("http://", "https://"))
    else:
        assert err


def test_invalid_searxng_config_is_reported_not_used(env):
    s = searx(env, "ftp://bad")  # e.g. stored by an older version
    env.get = lambda url, **kw: pytest.fail("must not call out with an invalid URL")
    assert kind_of(lambda: s.search("q")) == sp.INVALID_CONFIG


# --- credential entry UX --------------------------------------------------------------
def test_empty_and_invalid_values_are_rejected_without_changes(env):
    for key, bad in [("brave_search_key", ""), ("brave_search_key", "   "), ("brave_search_key", "abc"),
                     ("brave_search_key", "has space in it"), ("searxng_url", "ftp://x"), ("nope", "value12345")]:
        ok, msg = credentials.save_credential(env.db, key, bad)
        assert not ok and msg
    assert env.db.secret_names() == {}


def test_valid_value_is_stored_and_never_echoed(env):
    ok, msg = credentials.save_credential(env.db, "brave_search_key", SECRET)
    assert ok and SECRET not in msg
    assert env.db.get_secret("brave_search_key") == SECRET
    if security.encryption_mode() == "DPAPI":
        assert SECRET not in env.db.q("SELECT secret FROM api_config")[0]["secret"]


def test_credential_deletion_requires_confirmation(env):
    brave(env)
    ok, msg = credentials.remove_credential(env.db, "brave_search_key", lambda: False)
    assert not ok and "unchanged" in msg and "brave_search_key" in env.db.secret_names()
    ok, msg = credentials.remove_credential(env.db, "brave_search_key", lambda: True)
    assert ok and "brave_search_key" not in env.db.secret_names()
    ok, msg = credentials.remove_credential(env.db, "brave_search_key", lambda: pytest.fail("no prompt when unset"))
    assert not ok and "not set" in msg


def test_secrets_never_appear_in_source_records_or_errors(env):
    brave(env)
    env.get = lambda url, **kw: Resp(401, {})
    env.request = lambda m, url, **kw: Resp(202, text="")
    res = ModuleResult("t", "x")
    search_engine.search("ada", 5, res)
    blob = " ".join(res.errors + [s.detail for s in res.sources])
    assert SECRET not in blob


# --- Name Intelligence ------------------------------------------------------------------
def test_name_not_configured_explains_exactly_what_is_missing(env):
    out = name_intel.investigate("Ada Lovelace")
    assert out.findings == []
    assert any("Brave" in e and "cx" in e and "SearXNG" in e for e in out.errors)
    assert out.sources[0].status == "not_configured"


def test_name_search_all_providers_failed_is_not_reported_as_no_results(env):
    brave(env)
    env.get = lambda url, **kw: Resp(401, {})
    env.request = lambda m, url, **kw: Resp(202, text="")
    out = name_intel.investigate("Ada Lovelace")
    assert out.findings == []
    assert any("could not be completed" in e for e in out.errors)
    assert not any("completed with zero" in n.lower() for n in out.notes)
    assert len(env.calls["get"]) <= 3  # stops hammering a failing provider


def test_name_search_zero_results_is_a_completed_search(env):
    brave(env)
    env.get = lambda url, **kw: Resp(200, {"web": {"results": []}})
    out = name_intel.investigate("Ada Lovelace")
    assert out.findings == []
    assert not [e for e in out.errors if "could not be completed" in e]
    assert any("completed with zero" in n.lower() for n in out.notes)


def test_name_search_success_keeps_source_and_never_claims_identity(env):
    brave(env)
    env.get = lambda url, **kw: Resp(200, {"web": {"results": [
        {"title": "Ada Lovelace - Biography", "url": "https://example.org/ada",
         "description": "Ada Lovelace was a mathematician."}]}})
    out = name_intel.investigate("Ada Lovelace")
    assert out.findings
    for f in out.findings:
        assert f.source_url.startswith("https://") and f.source == "Brave Search API" and f.discovered_at
        assert f.confidence in ("LOW", "UNVERIFIED")
        assert "identity" in f.limitations.lower()
