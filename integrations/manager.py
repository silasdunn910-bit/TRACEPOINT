"""Integration manager: registry, live status, enable/disable, persistence and safe lookups.

Nothing here raises to the caller for a provider problem: a failing provider yields a status row or an
error dict, so one broken service can never take TRACEPOINT down. A provider is CONNECTED only after a
real request has succeeded; having a key stored is reported as NOT TESTED."""
from __future__ import annotations

import json
import threading

from core.configuration import ENV_VARS, get_logger
from core.database import get_db
from core.models import now_iso
from core.security import redact

from . import base
from .base import (CONNECTED, DISABLED, ERROR, NOT_CONFIGURED, NOT_TESTED, IntegrationError, Provider)

log = get_logger()
_PREFIX, _OFF = "integ:", "integ-off:"
_lock = threading.Lock()
_registry: dict[str, Provider] | None = None


def _load() -> dict[str, Provider]:
    global _registry
    with _lock:
        if _registry is None:
            from . import providers_cyber, providers_domain, providers_gov, providers_network, providers_search
            reg: dict[str, Provider] = {}
            for mod in (providers_search, providers_network, providers_cyber, providers_gov, providers_domain):
                for cls in mod.PROVIDERS:
                    p = cls()
                    reg[p.id] = p
            _registry = reg
        return _registry


def providers() -> list[Provider]:
    return list(_load().values())


def get(provider_id: str) -> Provider | None:
    return _load().get(provider_id)


# --- enable / disable ------------------------------------------------------------------------
def is_disabled(provider_id: str) -> bool:
    return get_db().get_setting(_OFF + provider_id, "") == "1"


def set_disabled(provider_id: str, disabled: bool) -> None:
    if get(provider_id) is None:
        raise KeyError(provider_id)
    get_db().set_setting(_OFF + provider_id, "1" if disabled else "")


# --- persisted state -------------------------------------------------------------------------
def _state(provider_id: str) -> dict:
    try:
        d = json.loads(get_db().get_setting(_PREFIX + provider_id, "") or "{}")
        return d if isinstance(d, dict) else {}
    except ValueError:
        return {}


def _save(p: Provider, **changes) -> dict:
    st = _state(p.id)
    st.update(changes)
    if p.quota:
        st["quota"] = p.quota
    get_db().set_setting(_PREFIX + p.id, json.dumps(st, default=str))
    return st


def _credentials_changed_since(p: Provider, tested_at: str) -> bool:
    names = get_db().secret_names()
    newest = max((names.get(k, "") for k in p.secret_keys + p.optional_keys), default="")
    return bool(newest and tested_at and newest > tested_at)


def forget(secret_key: str) -> None:
    """A credential changed or was removed: older test results no longer apply."""
    for p in providers():
        if secret_key in p.secret_keys + p.optional_keys:
            get_db().set_setting(_PREFIX + p.id, "")


# --- status rows -----------------------------------------------------------------------------
def _env_names(p: Provider) -> list[str]:
    return [ENV_VARS.get(k, k) for k in p.secret_keys + p.optional_keys]


def status(provider_id: str) -> dict:
    """Current state without any network request."""
    p = get(provider_id)
    if p is None:
        raise KeyError(provider_id)
    st = _state(p.id)
    miss = p.missing()
    if is_disabled(p.id):
        s, detail = DISABLED, "Disabled by the operator."
    elif miss:
        s, detail = NOT_CONFIGURED, "Missing: " + ", ".join(ENV_VARS.get(k, k) for k in miss)
    elif not st.get("tested_at") or _credentials_changed_since(p, st["tested_at"]):
        s, detail = NOT_TESTED, "No successful live test since the credentials were set." if p.secret_keys else \
            "Not tested yet."
    else:
        s, detail = st.get("status", NOT_TESTED), st.get("detail", "")
    return {"id": p.id, "name": p.name, "category": p.category, "tier": p.tier, "free_info": p.free_info,
            "signup_url": p.signup_url, "docs_url": p.docs_url, "endpoint": p.endpoint, "auth": p.auth,
            "env_vars": _env_names(p), "requires_credentials": bool(p.secret_keys),
            "status": s, "detail": redact(detail), "last_tested": st.get("tested_at", ""),
            "last_success": st.get("last_success", ""), "quota": st.get("quota") or p.quota,
            "lookups": dict(p.lookups), "limitations": list(p.limitations)}


def statuses() -> list[dict]:
    return [status(p.id) for p in providers()]


# --- live operations (never raise) -----------------------------------------------------------
def test(provider_id: str) -> dict:
    """Run one live connection test and record the outcome."""
    p = get(provider_id)
    if p is None:
        raise KeyError(provider_id)
    if is_disabled(p.id) or p.missing():
        return status(p.id)  # nothing is sent for a disabled or unconfigured provider
    try:
        out = p.test()
    except Exception as e:  # defensive: Provider.test already catches, but this must never raise
        out = base.TestOutcome(ERROR, f"Unexpected {type(e).__name__} while testing.")
    changes = {"status": out.status, "detail": redact(out.detail), "tested_at": out.tested_at}
    if out.status == CONNECTED:
        changes["last_success"] = out.tested_at
    _save(p, **changes)
    log.info("integration test %s -> %s", p.id, out.status)
    return status(p.id)


def test_all(only_configured: bool = True) -> list[dict]:
    rows = []
    for p in providers():
        s = status(p.id)
        if s["status"] in (DISABLED, NOT_CONFIGURED):
            rows.append(s)
        else:
            rows.append(test(p.id))
    return rows


def lookup(provider_id: str, kind: str, value: str, **kw) -> dict:
    """Run a lookup. Returns {'ok', 'result' (NormalizedResult dict), 'status', 'error'}; never raises."""
    p = get(provider_id)
    if p is None:
        return {"ok": False, "result": None, "status": ERROR, "error": f"Unknown integration '{provider_id}'."}
    if is_disabled(p.id):
        return {"ok": False, "result": None, "status": DISABLED, "error": f"{p.name} is disabled."}
    miss = p.missing()
    if miss:
        return {"ok": False, "result": None, "status": NOT_CONFIGURED,
                "error": "Missing credential: " + ", ".join(ENV_VARS.get(k, k) for k in miss)}
    try:
        res = p.lookup(kind, value, **kw)
    except base.InputError as e:  # the caller's input, not the provider's health
        return {"ok": False, "result": None, "status": ERROR, "error": redact(str(e))}
    except IntegrationError as e:
        _save(p, status=e.status, detail=redact(str(e)), tested_at=now_iso())
        return {"ok": False, "result": None, "status": e.status, "error": redact(str(e))}
    except Exception as e:
        log.warning("integration %s lookup crashed: %s", p.id, type(e).__name__)
        _save(p, status=ERROR, detail=f"Unexpected {type(e).__name__}.", tested_at=now_iso())
        return {"ok": False, "result": None, "status": ERROR, "error": f"Unexpected {type(e).__name__}."}
    ts = now_iso()
    _save(p, status=CONNECTED, detail="Last lookup succeeded.", tested_at=ts, last_success=ts)
    return {"ok": True, "result": res.to_dict(), "status": CONNECTED, "error": ""}
