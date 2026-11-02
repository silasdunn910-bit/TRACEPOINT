"""Regression tests created during the 2026-11-02 audit.

Offline only — no network. Run with:  python -m pytest tests/ -v
or without pytest:  python tests/test_audit.py
"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("HOME", tempfile.mkdtemp())

from core import correlation, database, models
from core.database import Database


def fresh_db() -> Database:
    """Create an isolated DB and install it as the process singleton, so the
    correlation helpers (which call get_db()) read the same database."""
    db = Database(Path(tempfile.mktemp(suffix=".db")))
    database._db = db
    return db


# --- ISSUE: finding count reported != stored (11 vs 10) ----------------------
def test_finding_count_live_matches_stored():
    db = fresh_db()
    r = models.ModuleResult("ip", "203.0.113.5")
    # two findings that collide on fingerprint (category|title|value|url) — e.g. duplicate RDAP entities
    r.add(models.Finding("Network registrant", "Example Org", "RDAP", models.VERIFIED, "network", "Example Org", "http://x"))
    r.add(models.Finding("Network registrant", "Example Org (admin role)", "RDAP", models.VERIFIED, "network", "Example Org", "http://x"))
    for i in range(9):
        r.add(models.Finding(f"F{i}", "d", "S", models.LOW, "dns", f"v{i}"))
    r.dedupe()                      # <-- fix under test
    live = len(r.findings)
    inv_id = db.save_result("ip", "203.0.113.5", r)
    stored = len(db.findings(inv_id))
    assert live == stored, f"live {live} != stored {stored}"
    assert live == 10


# --- ISSUE: graph export must reflect the selected/filtered entities ---------
def test_filtered_graph_export_contains_only_selected():
    db = fresh_db()
    r = models.ModuleResult("domain", "a.example")
    d = r.entity(models.E_DOMAIN, "a.example", models.VERIFIED)
    ip = r.entity(models.E_IP, "198.51.100.7", models.VERIFIED)
    r.relate(d, ip, models.R_RESOLVES, models.VERIFIED, "DNS")
    db.save_result("domain", "a.example", r)
    r2 = models.ModuleResult("domain", "b.example")
    r2.entity(models.E_DOMAIN, "b.example", models.VERIFIED)
    db.save_result("domain", "b.example", r2)

    matches = correlation.search_entities("a.example")
    ids = [m["id"] for m in matches]
    g = correlation.graph_json_for_entities(ids)
    labels = {n["data"]["label"] for n in g["elements"]["nodes"]}
    assert "a.example" in labels
    assert "b.example" not in labels          # the other investigation must NOT leak in
    assert g["summary"]["filtered"] is True


def test_whole_graph_still_available():
    db = fresh_db()
    r = models.ModuleResult("domain", "c.example")
    r.entity(models.E_DOMAIN, "c.example", models.VERIFIED)
    db.save_result("domain", "c.example", r)
    g = correlation.graph_json(None)
    assert g["summary"]["nodes"] >= 1


# --- ISSUE: shared-entity detection vs ordinary search are different queries -
def test_shared_vs_search_are_distinct():
    db = fresh_db()
    shared_ip = "192.0.2.50"
    for host in ("one.example", "two.example"):
        r = models.ModuleResult("domain", host)
        dd = r.entity(models.E_DOMAIN, host, models.VERIFIED)
        ii = r.entity(models.E_IP, shared_ip, models.VERIFIED)
        r.relate(dd, ii, models.R_RESOLVES, models.VERIFIED, "DNS")
        db.save_result("domain", host, r)
    shared = correlation.shared_entities(2)
    assert any(s["value"] == shared_ip and s["n"] == 2 for s in shared), "shared IP not detected across 2 investigations"
    # a plain search for a unique domain must NOT be reported as shared
    assert all(s["value"] != "one.example" for s in shared)
    assert any(e["value"] == "one.example" for e in correlation.search_entities("one.example"))


# --- identifier detection sanity ---------------------------------------------
def test_detect_type():
    cases = {"a@b.com": "email", "8.8.8.8": "ip", "2001:4860:4860::8888": "ip",
             "example.com": "domain", "https://github.com/torvalds": "social",
             "+14155552671": "phone", "John Smith": "name"}
    for v, expected in cases.items():
        got = correlation.detect_type(v)[0]
        assert got == expected, f"{v!r}: expected {expected}, got {got}"


# --- confidence labelling: search hits are never VERIFIED --------------------
def test_search_hits_never_verified():
    from core import search_engine
    from providers.search_providers import SearchResult
    r = models.ModuleResult("name", "x")
    hits = [SearchResult("Exact term here", "https://e.com/p", "snippet with term", "P", "term"),
            SearchResult("unrelated", "https://f.com/q", "nothing", "P", "term")]
    search_engine.results_to_findings(hits, r, category="web", exact_term="term", what="q")
    confs = {f.confidence for f in r.findings}
    assert models.VERIFIED not in confs and models.STRONG not in confs
    assert models.LOW in confs and models.UNVERIFIED in confs


# --- plaintext fallback credential round-trip (DPAPI path needs Windows) -----
def test_secret_roundtrip_and_masking():
    db = fresh_db()
    db.set_secret("brave_search_key", "TOKEN-abc123456789")
    assert db.get_secret("brave_search_key") == "TOKEN-abc123456789"
    from core.security import mask
    assert "123456789" not in mask("TOKEN-abc123456789")
    db.delete_secret("brave_search_key")
    assert "brave_search_key" not in db.secret_names()


# --- investigations persist & delete is clean --------------------------------
def test_persistence_and_delete():
    db = fresh_db()
    r = models.ModuleResult("ip", "203.0.113.9")
    r.add(models.Finding("t", "d", "S", models.VERIFIED, "net", "v"))
    inv_id = db.save_result("ip", "203.0.113.9", r)
    assert db.get_investigation(inv_id) is not None
    db.delete_investigation(inv_id)
    assert db.get_investigation(inv_id) is None
    # orphan entities cleaned
    assert db.q("SELECT COUNT(*) c FROM entities")[0]["c"] == 0


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}"); passed += 1
        except Exception:
            print(f"FAIL {fn.__name__}"); traceback.print_exc(); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
