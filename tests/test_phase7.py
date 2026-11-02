"""Phase 7 hardening regressions: atomic saves, public-only fetches, log privacy, Ctrl-C handling."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import logging
import threading

import pytest

from core import http
from core.database import Database
from core.models import Finding, ModuleResult


@pytest.fixture()
def local_server():
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            if self.path.startswith("/redir"):
                self.send_response(302)
                self.send_header("Location", f"http://redir-target.test:{srv.server_address[1]}/internal")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], seen
    srv.shutdown()


def test_failed_save_leaves_no_partial_investigation(tmp_path):
    db = Database(tmp_path / "t.db")
    res = ModuleResult("domain", "boom.example")
    res.add(Finding("t", "v", "s", "LOW", "c"))

    class Bad:
        def __getattr__(self, k):
            raise RuntimeError("boom")

    res.relationships.append(Bad())
    with pytest.raises(RuntimeError):
        db.save_result("domain", "boom.example", res)
    db.set_setting("later", "write")  # an unrelated commit must not persist the partial rows
    assert db.q("SELECT COUNT(*) c FROM investigations")[0]["c"] == 0
    assert db.q("SELECT COUNT(*) c FROM findings")[0]["c"] == 0


def test_public_only_refuses_loopback(local_server):
    port, seen = local_server
    with pytest.raises(http.HttpError):
        http.get(f"http://127.0.0.1:{port}/x", public_only=True)
    assert seen == []


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com/x", "http://169.254.169.254/latest/meta-data/"])
def test_public_only_refuses_non_http_and_link_local(url):
    with pytest.raises(http.HttpError):
        http.get(url, public_only=True)


def test_public_only_checks_every_redirect_hop(local_server, monkeypatch):
    port, seen = local_server
    # hop1.test is allowed (stands in for a public host); the redirect target resolves to a private address.
    fake = {"hop1.test": "127.0.0.1", "redir-target.test": "10.0.0.1"}
    monkeypatch.setattr(http.socket, "getaddrinfo",
                        lambda host, port, *a, **k: [(2, 1, 6, "", (fake.get(host, host), port))])
    monkeypatch.setattr(http, "is_public_ip", lambda a: a == "127.0.0.1")
    with pytest.raises(http.HttpError):
        http.get(f"http://hop1.test:{port}/redir/a", public_only=True)
    assert seen == ["/redir/a"]  # never reached /internal


def test_social_module_does_not_touch_local_services(local_server):
    from modules import social_intel
    port, seen = local_server
    res = social_intel.investigate(f"http://127.0.0.1:{port}/redir/someone")
    assert seen == []
    assert not any("internal" in f.value for f in res.findings)


def test_request_log_does_not_contain_url_path(local_server):
    port, _ = local_server
    records = []

    class Cap(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    lg = logging.getLogger("tracepoint")
    h = Cap()
    lg.addHandler(h)
    try:
        http.get(f"http://127.0.0.1:{port}/@sensitive-handle-12345")
    finally:
        lg.removeHandler(h)
    assert records and not any("sensitive-handle-12345" in m for m in records)


def test_keyboard_interrupt_returns_to_menu_without_saving(monkeypatch):
    import main
    monkeypatch.setattr(main.investigation, "run", lambda *a, **k: (_ for _ in ()).throw(KeyboardInterrupt()))
    main.run_and_show("domain", "example.com")  # must not propagate


def test_failing_screen_does_not_end_the_session(monkeypatch):
    import main
    answers = iter(["12", "0"])  # Reports screen, then Exit
    monkeypatch.setattr(main.Prompt, "ask", lambda *a, **k: next(answers))
    monkeypatch.setattr(main.console, "input", lambda *a, **k: "")
    monkeypatch.setitem(main.DISPATCH, "reports", lambda: (_ for _ in ()).throw(OSError("disk full")))
    main.main()  # must reach Exit instead of raising


def test_banner_ai_status_is_cached(monkeypatch):
    import main
    calls = []
    monkeypatch.setattr(main, "_ai_cache", None)
    monkeypatch.setattr(main.ai, "status", lambda: calls.append(1) or (False, [], "offline"))
    main._header_ai_status()
    main._header_ai_status()
    assert len(calls) == 1
