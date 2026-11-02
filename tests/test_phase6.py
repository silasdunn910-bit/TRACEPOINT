"""Phase 6 integration regressions (R2 single-source grading, R6 legacy grade presentation)."""
from core import reports
from core.database import Database
from core.models import CORROBORATED, Finding, ModuleResult
from ui import render


def test_confidence_text_normalizes_legacy_strong():
    assert CORROBORATED in render.confidence_text("STRONG").plain


def test_report_rows_present_legacy_strong_as_corroborated(tmp_path, monkeypatch):
    db = Database(tmp_path / "t.db")
    res = ModuleResult("domain", "example.com")
    res.add(Finding("legacy", "v", "src", "VERIFIED", "cat"))
    inv_id = db.save_result("domain", "example.com", res)
    db.conn.execute("UPDATE findings SET confidence='STRONG' WHERE investigation_id=?", (inv_id,))
    db.conn.commit()
    monkeypatch.setattr(reports, "get_db", lambda: db)
    built = reports.build(inv_id)
    assert [f["confidence"] for f in built["findings"]] == [CORROBORATED]
    # stored value is untouched
    assert db.conn.execute("SELECT confidence FROM findings WHERE investigation_id=?", (inv_id,)).fetchone()[0] == "STRONG"


def test_single_source_security_findings_never_corroborated():
    import inspect
    from modules import security_intel
    assert "STRONG" not in inspect.getsource(security_intel)
