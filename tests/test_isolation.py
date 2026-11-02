"""The suite must never touch the real installation (see tests/conftest.py)."""
import logging
from pathlib import Path

from tests.conftest import REAL_BEFORE, REAL_ROOT, TEST_HOME, _snapshot
from core import configuration as cfg
from core.database import get_db
from core.http import log as http_log


def _inside(p: Path, root: Path) -> bool:
    return root.resolve() in p.resolve().parents or p.resolve() == root.resolve()


def test_every_data_path_is_inside_the_temporary_home():
    for p in (cfg.ROOT, cfg.DATA_DIR, cfg.REPORTS_DIR, cfg.LOGS_DIR, cfg.CONFIG_DIR, cfg.DB_PATH, cfg.BACKUP_DIR, cfg.LOCK_PATH):
        assert _inside(p, TEST_HOME), p
        assert not _inside(p, REAL_ROOT) or _inside(TEST_HOME, REAL_ROOT), p


def test_application_database_singleton_is_the_temporary_one():
    db = get_db()
    assert _inside(Path(db.path), TEST_HOME)
    assert Path(db.path).resolve() != (REAL_ROOT / "data" / "tracepoint.db").resolve()


def test_log_handler_writes_into_the_temporary_home():
    files = [Path(h.baseFilename) for h in logging.getLogger("tracepoint").handlers if hasattr(h, "baseFilename")]
    assert files and all(_inside(f, TEST_HOME) for f in files)


def test_logging_does_not_change_the_real_log():
    before = _snapshot()["logs/tracepoint.log"]
    for i in range(20):
        http_log.info("isolation probe %s", i)
    for h in logging.getLogger("tracepoint").handlers:
        h.flush()
    assert _snapshot()["logs/tracepoint.log"] == before == REAL_BEFORE["logs/tracepoint.log"]


def test_real_installation_is_unchanged_so_far():
    assert _snapshot() == REAL_BEFORE


def test_backup_goes_to_the_temporary_home():
    path = get_db().backup()
    assert _inside(path, TEST_HOME)
    assert _snapshot() == REAL_BEFORE


def test_temporary_home_starts_without_real_investigations():
    # A fresh temp database: the suite must not depend on, or read, the developer's history.
    assert Path(get_db().path).resolve().parent == cfg.DATA_DIR.resolve()


def test_tempfile_and_pytest_scratch_space_is_inside_the_temporary_home(tmp_path):
    import tempfile
    assert _inside(Path(tempfile.gettempdir()), TEST_HOME)
    assert _inside(tmp_path, TEST_HOME)
