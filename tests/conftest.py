"""Test isolation.

Every test runs against a temporary TRACEPOINT_HOME (database, reports, logs, config, backups),
set *before* any `core` module is imported. The real installation is never written to; at the end
of the session its database, log and reports folder are compared with a snapshot taken at the
start, and the run fails if anything changed.
"""
import atexit
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

REAL_ROOT = Path(__file__).resolve().parents[1]
TEST_HOME = Path(tempfile.mkdtemp(prefix="tracepoint-tests-")).resolve()
os.environ["TRACEPOINT_HOME"] = str(TEST_HOME)
for _var in ("OLLAMA_URL",):
    os.environ.pop(_var, None)  # config comes from the (empty) temp config dir, not the developer's shell
sys.path.insert(0, str(REAL_ROOT))
# Scratch files made with tempfile.* / tmp_path also live inside the test home, so they are cleaned up with it.
(TEST_HOME / "tmp").mkdir()
tempfile.tempdir = str(TEST_HOME / "tmp")


def _snapshot() -> dict:
    snap = {}
    for rel in ("data/tracepoint.db", "data/tracepoint.db-wal", "logs/tracepoint.log", "config/.env"):
        p = REAL_ROOT / rel
        snap[rel] = (p.stat().st_size, p.stat().st_mtime_ns) if p.exists() else None
    rep = REAL_ROOT / "reports"
    snap["reports/"] = sorted((f.name, f.stat().st_size, f.stat().st_mtime_ns) for f in rep.iterdir()) if rep.exists() else []
    return snap


REAL_BEFORE = _snapshot()


def pytest_configure(config):
    if getattr(config.option, "basetemp", None) is None:
        config.option.basetemp = str(TEST_HOME / "pytest")


def _cleanup():
    import gc
    gc.collect()  # drop unreferenced sqlite connections so their files can be deleted on Windows
    logging.shutdown()
    for name in ("tracepoint",):
        lg = logging.getLogger(name)
        for h in list(lg.handlers):
            h.close()
            lg.removeHandler(h)
    try:
        from core import database
        if database._db is not None:
            database._db.close()
    except Exception:
        pass
    shutil.rmtree(TEST_HOME, ignore_errors=True)
    if TEST_HOME.exists():  # something still holds a file open: say so instead of silently leaking it
        print(f"WARNING: test home was not fully removed: {TEST_HOME}")


atexit.register(_cleanup)


@pytest.fixture(scope="session", autouse=True)
def _refuse_to_run_against_real_data():
    from core import configuration as cfg
    if cfg.ROOT.resolve() != TEST_HOME or cfg.ROOT.resolve() == REAL_ROOT:
        pytest.exit(f"Refusing to run: core.configuration.ROOT is {cfg.ROOT}, not the temporary test home. "
                    "Something imported `core` before tests/conftest.py set TRACEPOINT_HOME.", returncode=2)
    yield


@pytest.fixture(autouse=True)
def _restore_app_singletons():
    """Several tests install their own Database as the process singleton; put the original back."""
    from core import database
    base = database.get_db()
    yield
    current = database._db
    if current is not None and current is not base:
        try:
            current.close()
        except Exception:
            pass
    database._db = base


def pytest_sessionfinish(session, exitstatus):
    after = _snapshot()
    if after != REAL_BEFORE:
        changed = [k for k in after if after[k] != REAL_BEFORE.get(k)]
        print(f"\nISOLATION FAILURE: the real installation was modified during the test run: {changed}")
        session.exitstatus = 1
