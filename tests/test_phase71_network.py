"""Phase 7.1: address classification and DNS-rebinding protection for public_only requests."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from core import http
from core.security import is_public_ip


@pytest.mark.parametrize("addr", [
    "8.8.8.8", "93.184.216.34", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888",
])
def test_public_addresses_accepted(addr):
    assert is_public_ip(addr)


@pytest.mark.parametrize("addr", [
    "127.0.0.1", "127.255.255.254", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254",
    "100.64.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1", "240.0.0.1", "192.0.2.1", "198.51.100.7",
    "203.0.113.9", "198.18.0.1", "::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1",
    "2001:db8::1", "::ffff:127.0.0.1", "::ffff:10.1.2.3", "::ffff:169.254.169.254",
    "64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::1", "2002:0a00:0001::1", "64:ff9b:1::1",
    "fe80::1%12", "not-an-ip", "", "999.1.1.1", "1.2.3", None,
])
def test_non_public_or_invalid_addresses_rejected(addr):
    assert not is_public_ip(addr)


def test_ipv4_mapped_public_address_is_judged_by_its_ipv4():
    assert is_public_ip("::ffff:8.8.8.8")


@pytest.mark.parametrize("url", [
    "http://[::1", "http://", "http:///x", "http://host:99999/", "http://host:abc/", "ftp://example.com/",
    "file:///C:/Windows/win.ini", "javascript:alert(1)", "//example.com/x", "example.com",
    "http://user@:80/", "http://\x00host/",
])
def test_malformed_urls_are_rejected_without_traffic(url):
    with pytest.raises(http.HttpError):
        http.get(url, public_only=True)


@pytest.mark.parametrize("url", [
    "http://localhost/", "http://127.1/", "http://2130706433/", "http://0x7f.0.0.1/", "http://[::1]/",
    "http://[::ffff:127.0.0.1]/", "http://0.0.0.0/", "http://169.254.169.254/latest/",
    "http://[fe80::1]/", "http://10.0.0.1/", "http://192.168.0.1:8080/", "http://user:pw@127.0.0.1/",
])
def test_unusual_loopback_and_private_forms_are_refused(url):
    with pytest.raises(http.HttpError):
        http.get(url, public_only=True)


@pytest.fixture()
def server():
    seen = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Host")))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1], seen
    srv.shutdown()


def _fake_dns(monkeypatch, answers):
    """answers: list of address lists returned by successive getaddrinfo calls (last one repeats)."""
    calls = []

    def fake(host, port, *a, **kw):
        if host.replace(".", "").isdigit():  # IP literal: what socket.create_connection resolves
            return [(2, 1, 6, "", (host, port))]
        calls.append(host)
        addrs = answers[min(len(calls), len(answers)) - 1]
        return [(2, 1, 6, "", (a, port)) for a in addrs]

    monkeypatch.setattr(http.socket, "getaddrinfo", fake)
    return calls


def test_dns_rebinding_between_check_and_connect_is_refused(server, monkeypatch):
    port, seen = server
    # 1st lookup (early check) says public; the connection's own lookup says loopback.
    calls = _fake_dns(monkeypatch, [["93.184.216.34"], ["127.0.0.1"]])
    with pytest.raises(http.HttpError) as e:
        http.get(f"http://rebind.test:{port}/x", public_only=True)
    assert "public" in str(e.value)
    assert seen == []
    assert len(calls) >= 2  # the connection validated its own resolution


def test_mixed_public_and_private_answers_are_refused(server, monkeypatch):
    port, seen = server
    _fake_dns(monkeypatch, [["93.184.216.34", "10.0.0.5"]])
    with pytest.raises(http.HttpError):
        http.get(f"http://mixed.test:{port}/x", public_only=True)
    assert seen == []


def test_connection_goes_to_validated_ip_and_keeps_the_original_host_header(server, monkeypatch):
    port, seen = server
    _fake_dns(monkeypatch, [["127.0.0.1"]])
    monkeypatch.setattr(http, "is_public_ip", lambda a: a == "127.0.0.1")  # stand-in for a public IP
    r = http.get(f"http://pinned.test:{port}/p", public_only=True)
    assert r.status_code == 200
    assert seen == [("/p", f"pinned.test:{port}")]


def test_public_requests_ignore_environment_proxies(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    assert http._public_session.trust_env is False
    assert http._public_session.proxies == {}


def test_tls_verification_is_preserved_on_pinned_connections():
    s = http._public_session
    assert s.verify is True
    adapter = s.get_adapter("https://example.com/")
    pool = adapter.poolmanager.connection_from_url("https://example.com/")
    assert isinstance(pool, http._PinnedHTTPSPool)
    adapter.cert_verify(pool, "https://example.com/", True, None)
    assert pool.cert_reqs == "CERT_REQUIRED"
    # connect()/TLS wrapping is inherited unchanged: only the TCP socket creation is replaced
    assert http._PinnedHTTPSConnection.connect is http._U3HTTPSConnection.connect
    assert "connect" not in vars(http._PinnedHTTPSConnection)


def test_ordinary_requests_are_not_pinned(server):
    port, seen = server
    assert http.get(f"http://127.0.0.1:{port}/plain").status_code == 200  # non-public_only path unchanged
    assert seen[0][0] == "/plain"
