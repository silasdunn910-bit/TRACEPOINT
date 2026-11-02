"""Phase 2 tests: evidence taxonomy, blocked username states, report path resolution. Offline."""
import os, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("HOME", tempfile.mkdtemp())

from core import database, models, reports
from core.database import Database


class _R:
    def __init__(self, code, text=""):
        self.status_code, self.text = code, text
    def json(self):
        raise ValueError


def _check(code, text=""):
    from modules import username_intel as u
    orig = u.http.get
    u.http.get = lambda *a, **k: _R(code, text)
    try:
        site = next(s for s in u.SITES if s.method == "status")
        return u.check_site(site, "someone")
    finally:
        u.http.get = orig


def test_taxonomy_has_all_six_levels_and_legacy_alias():
    assert models.CONFIDENCE_LEVELS == ["VERIFIED", "CORROBORATED", "MODERATE", "LOW", "UNVERIFIED", "INCONCLUSIVE"]
    assert models.normalize_confidence("STRONG") == "CORROBORATED"
    assert models.normalize_confidence("bogus") == "UNVERIFIED"
    assert set(models.CONFIDENCE_MEANING) == set(models.CONFIDENCE_LEVELS)


def test_http_403_and_429_are_blocked_never_not_found():
    assert _check(403)["state"] == "blocked"
    assert _check(429)["state"] == "blocked"
    assert _check(503)["state"] == "error"
    assert _check(404)["state"] == "not_found"


def test_blocked_result_becomes_inconclusive_finding():
    from modules import username_intel as u
    orig = u.check_site
    u.check_site = lambda site, h: {"site": site.name, "url": "https://x/y", "check": "https://x/y",
                                    "state": "blocked", "detail": "HTTP 403", "meta": {}}
    try:
        res = u.investigate("someone", web_search=False)
    finally:
        u.check_site = orig
    assert res.findings and all(f.confidence == models.INCONCLUSIVE for f in res.findings
                                if f.category == "profiles-inconclusive")
    assert not any(f.category == "profiles" for f in res.findings)


def _inv(db):
    r = models.ModuleResult("domain", "example.com")
    r.add(models.Finding("a", "d", "src", models.VERIFIED))
    r.add(models.Finding("b", "d", "src", "STRONG"))  # legacy grade
    r.add(models.Finding("c", "d", "src", models.INCONCLUSIVE))
    return db.save_result("domain", "example.com", r)


def test_report_counts_match_findings_including_legacy_strong():
    db = Database(Path(tempfile.mktemp(suffix=".db"))); database._db = db
    inv_id = _inv(db)
    text = reports.build(inv_id)["conclusion"] if "conclusion" in reports.build(inv_id) else str(reports.build(inv_id))
    assert "1 VERIFIED" in text and "1 CORROBORATED" in text and "1 INCONCLUSIVE" in text
    assert "0 UNVERIFIED" in text


def test_report_paths_resolve_to_current_reports_dir_without_modifying_rows():
    db = Database(Path(tempfile.mktemp(suffix=".db"))); database._db = db
    from core.configuration import REPORTS_DIR
    inv_id = _inv(db)
    db.add_report(inv_id, "txt", r"C:\Projects\TRACEPOINT\reports\stale.txt")
    row = db.reports()[0]
    assert Path(row["path"]) == REPORTS_DIR / "stale.txt"
    assert row["exists"] is False
    raw = db.q("SELECT path FROM reports")[0]["path"]
    assert raw == r"C:\Projects\TRACEPOINT\reports\stale.txt"  # stored row untouched


def test_blocked_source_status_is_blocked_not_error_and_reported():
    from modules import username_intel as u
    orig = u.check_site
    def fake(site, h):
        st = {"GitHub": "blocked", "PyPI": "error"}.get(site.name, "not_found")
        return {"site": site.name, "url": "https://x/" + site.name, "check": "https://x/" + site.name,
                "state": st, "detail": "HTTP 403" if st == "blocked" else "HTTP 503", "meta": {}}
    u.check_site = fake
    try:
        res = u.investigate("someone", web_search=False)
    finally:
        u.check_site = orig
    st = {s.name: s.status for s in res.sources}
    assert st["GitHub"] == "blocked" and st["PyPI"] == "error"
    db = Database(Path(tempfile.mktemp(suffix=".db"))); database._db = db
    inv_id = db.save_result("username", "someone", res)
    rep = reports.build(inv_id)
    assert "blocked automated checks" in rep["conclusion"]
    assert any("blocked automated checks: GitHub" in l for l in rep["limitations"])
    assert "[blocked]" in reports.to_txt(rep)
