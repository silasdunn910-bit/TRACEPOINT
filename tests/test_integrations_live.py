"""LIVE connection tests against the real services. Opt-in: set TRACEPOINT_LIVE_TESTS=1.

    $env:TRACEPOINT_LIVE_TESTS = "1"; .venv\Scripts\python.exe -m pytest tests/test_integrations_live.py -v -s

Keyless providers always run when enabled. Keyed providers run only if their environment variable is set
in the shell (the isolated test home has no stored keys); otherwise they are skipped, never faked.
These tests spend a little of each provider's free quota."""
import os

import pytest

from core.configuration import ENV_VARS
from integrations import manager
from integrations.base import CONNECTED

pytestmark = pytest.mark.skipif(os.environ.get("TRACEPOINT_LIVE_TESTS") != "1",
                                reason="live tests are opt-in (TRACEPOINT_LIVE_TESTS=1)")

FLAKY = {"gdelt", "crtsh"}  # strict per-IP throttling / frequent overload: recorded as xfail, never as connected
KNOWN_DOWN = {"bgpview"}  # api.bgpview.io no longer resolves; RIPEstat covers the same data


@pytest.mark.parametrize("pid", [p.id for p in manager.providers()])
def test_live_connection(pid):
    p = manager.get(pid)
    if p.secret_keys and not p.configured():
        pytest.skip("needs " + ", ".join(ENV_VARS[k] for k in p.secret_keys))
    row = manager.test(pid)
    print(f"{pid}: {row['status']} - {row['detail']}")
    if pid in KNOWN_DOWN:
        return  # reported, not asserted: the service is discontinued
    if pid in FLAKY and row["status"] != CONNECTED:
        pytest.xfail(f"{row['status']}: {row['detail']}")
    assert row["status"] == CONNECTED, row
