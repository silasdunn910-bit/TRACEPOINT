"""Offline regressions for phone parsing, metadata scope, and public search handling."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests

from core import http, search_engine
from core.models import UNVERIFIED, ModuleResult
from modules import phone_intel
from providers.search_providers import (DuckDuckGoHTML, ProviderUnavailable, SearchResult)


SUPPORTED = {
    "+13364658507": "+13364658507",
    "+1 336 465 8507": "+13364658507",
    "(336) 465-8507": "3364658507",
    "1+3364658507": "+13364658507",
    "1-336-465-8507": "13364658507",
}


def test_all_requested_input_formats_normalize_and_parse_to_same_e164():
    import phonenumbers
    for raw, expected_normalized in SUPPORTED.items():
        normalized = phone_intel.normalize_phone_input(raw)
        assert normalized == expected_normalized, (raw, normalized)
        parsed = phonenumbers.parse(normalized, None if normalized.startswith("+") else "US")
        assert phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164) == "+13364658507"


def test_unicode_digits_and_common_extensions_are_normalized():
    assert phone_intel.normalize_phone_input("＋１ (３３６) ４６５－８５０７ ext. 12") == "+13364658507 ext.12"


def test_invalid_inputs_are_rejected_without_lookup():
    for raw in ("", "not a number", "+1+3364658507", "336ABC8507", "1-2"):
        result = phone_intel.investigate(raw, web_search=False)
        assert result.errors, raw
        assert not result.entities, raw


def test_country_calling_code_and_national_prefix_are_parsed_by_libphonenumber():
    import phonenumbers
    international = phonenumbers.parse(phone_intel.normalize_phone_input("+44 20 7031 3000"), None)
    uk_national = phonenumbers.parse(phone_intel.normalize_phone_input("020 7031 3000"), "GB")
    international_zero_prefix = phonenumbers.parse(phone_intel.normalize_phone_input("0044 20 7031 3000"), "US")
    for parsed in (international, uk_national, international_zero_prefix):
        assert phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164) == "+442070313000"


def test_metadata_findings_do_not_claim_active_line_or_person_identity():
    result = phone_intel.investigate("+13364658507", web_search=False)
    assert result.findings
    assert all(f.confidence != "VERIFIED" for f in result.findings)
    assert all(f.category != "geo" for f in result.findings)
    assert all("active" in f.limitations.lower() or f.category not in ("normalization", "metadata-validation")
               for f in result.findings)
    assert all("owner" not in f.description.lower() and "subscriber is" not in f.description.lower()
               for f in result.findings)
    assert result.entities[0].verification == UNVERIFIED


def test_phone_search_requires_configured_supported_api_not_duckduckgo_fallback():
    old_active = search_engine.active_providers
    old_search = search_engine.search
    try:
        search_engine.active_providers = lambda: []
        search_engine.search = lambda *a, **k: (_ for _ in ()).throw(AssertionError("search should be skipped"))
        result = phone_intel.investigate("+13364658507")
        provider = next(s for s in result.sources if s.name == "Configured public web search")
        assert provider.status == "not_configured"
        assert any("skipped" in note.lower() for note in result.notes)
    finally:
        search_engine.active_providers = old_active
        search_engine.search = old_search


def test_only_configured_supported_search_apis_are_used_for_phone_lookup():
    old_active = search_engine.active_providers
    try:
        providers = [type("API", (), {"name": "Brave Search API"})(),
                     type("API", (), {"name": "Google Programmable Search"})(),
                     type("API", (), {"name": "SearXNG"})(),
                     type("Fallback", (), {"name": "DuckDuckGo (HTML)"})()]
        search_engine.active_providers = lambda: providers
        assert {p.name for p in phone_intel._configured_web_providers()} == {
            "Brave Search API", "Google Programmable Search", "SearXNG"}
    finally:
        search_engine.active_providers = old_active


def test_source_confirmed_search_result_preserves_url_and_retrieval_time():
    old_active = search_engine.active_providers
    old_search = search_engine.search
    try:
        search_engine.active_providers = lambda: [type("P", (), {"name": "Brave Search API"})()]
        hit = SearchResult("Business listing +13364658507", "https://business.example/phone", "Number listed",
                           "Fake Brave", '"+13364658507"', discovered_at="2026-11-02T12:00:00+00:00")
        search_engine.search = lambda *a, **k: [hit]
        result = phone_intel.investigate("+13364658507")
        web = [f for f in result.findings if f.category == "web-references"]
        assert len(web) == 1  # repeated number formats do not duplicate a source
        assert web[0].source_url == hit.url
        assert web[0].discovered_at == hit.discovered_at
        assert web[0].source == hit.provider
        assert "does not confirm" in web[0].limitations
    finally:
        search_engine.active_providers = old_active
        search_engine.search = old_search


def test_transient_search_api_responses_retry_with_retry_after_and_rate_limit():
    old_request, old_throttle, old_sleep = http._session.request, http._throttle, http.time.sleep
    calls, throttles, sleeps = [], [], []

    class Response:
        def __init__(self, status, headers=None):
            self.status_code, self.headers, self._content = status, headers or {}, b"ok"
        def iter_content(self, size):
            yield b"ok"
        def close(self):
            pass

    outcomes = [Response(429, {"Retry-After": "2"}), Response(200)]
    def fake_request(*args, **kwargs):
        calls.append(1)
        return outcomes.pop(0)
    try:
        http._session.request = fake_request
        http._throttle = lambda url: throttles.append(url)
        http.time.sleep = lambda duration: sleeps.append(duration)
        response = http.get("https://search.example/api", retries=2)
        assert response.status_code == 200
        assert len(calls) == len(throttles) == 2
        assert sleeps == [2.0]
    finally:
        http._session.request, http._throttle, http.time.sleep = old_request, old_throttle, old_sleep


def test_timeout_retries_are_bounded_and_reported():
    old_request, old_throttle, old_sleep = http._session.request, http._throttle, http.time.sleep
    calls, sleeps = [], []
    def fake_request(*args, **kwargs):
        calls.append(1)
        raise requests.Timeout()
    try:
        http._session.request = fake_request
        http._throttle = lambda url: None
        http.time.sleep = lambda duration: sleeps.append(duration)
        try:
            http.get("https://search.example/api", retries=1)
            assert False, "final timeout must be surfaced"
        except http.HttpError as exc:
            assert "Timed out" in str(exc)
        assert len(calls) == 2 and sleeps == [0.5]
    finally:
        http._session.request, http._throttle, http.time.sleep = old_request, old_throttle, old_sleep


def test_duckduckgo_challenge_is_reported_as_provider_unavailable():
    old_request = http.request
    try:
        class Response:
            status_code = 200
            text = "<html>anomaly challenge</html>"
        http.request = lambda *a, **k: Response()
        try:
            DuckDuckGoHTML().search('"+13364658507"')
            assert False, "challenge page must not become an empty successful result"
        except ProviderUnavailable as exc:
            assert "refused" in str(exc).lower()
    finally:
        http.request = old_request


def test_search_engine_records_duckduckgo_failure_and_does_not_make_up_hits():
    old_active = search_engine.active_providers
    try:
        class FailedProvider:
            name = "DuckDuckGo (HTML)"
            requires_key = False
            def search(self, query, limit):
                raise ProviderUnavailable("challenge response")
        search_engine.active_providers = lambda: [FailedProvider()]
        result = ModuleResult("phone", "+13364658507")
        hits = search_engine.search('"+13364658507"', result=result)
        assert hits == []
        assert result.sources[0].status == "error"
        assert "challenge response" in result.sources[0].detail
    finally:
        search_engine.active_providers = old_active


if __name__ == "__main__":
    import traceback
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_") and callable(value)]
    failures = 0
    for test in tests:
        try:
            test()
            print(f"PASS {test.__name__}")
        except Exception:
            failures += 1
            print(f"FAIL {test.__name__}")
            traceback.print_exc()
    print(f"\n{len(tests) - failures} passed, {failures} failed")
    raise SystemExit(bool(failures))
