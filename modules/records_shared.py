"""Shared evidence formatting for the Court Records and Registry modules.

Court cases and registry listings stay separate record types with separate finding categories; only the
formatting helpers are shared.
"""
from __future__ import annotations

from core.models import SourceRecord
from providers.records_common import OfficialSource, SearchOutcome

# Finding categories (kept distinct on purpose).
CAT_COURT_REVIEWED = "court_record_reviewed"      # returned by an automated official source, attached by the operator
CAT_COURT_MANUAL = "court_record_manual"          # entered by the operator from the official portal
CAT_REG_REVIEWED = "registry_listing_reviewed"
CAT_REG_MANUAL = "registry_listing_manual"
COURT_CATEGORIES = (CAT_COURT_REVIEWED, CAT_COURT_MANUAL)
REGISTRY_CATEGORIES = (CAT_REG_REVIEWED, CAT_REG_MANUAL)
NOT_PROVIDED = "not provided by source"

_STATUS_FOR_SOURCE = {"ok": "ok", "error": "error", "manual": "skipped", "not_configured": "not_configured"}


def source_record(outcome: SearchOutcome) -> SourceRecord:
    s: OfficialSource = outcome.source
    method = "automated search" if s.automated else "manual search required"
    detail = (f"{s.agency}; jurisdiction {s.jurisdiction}; {method}; auth: {s.auth} Coverage: PARTIAL - {s.coverage} "
              f"{outcome.detail}").strip()
    return SourceRecord(name=s.name, url=s.search_url, status=_STATUS_FOR_SOURCE.get(outcome.status, "error"),
                        detail=detail[:900], consulted_at=outcome.searched_at)


def evidence_block(pairs: list[tuple[str, str]]) -> str:
    return "\n".join(f"{k}: {v or NOT_PROVIDED}" for k, v in pairs)


def source_description(s: OfficialSource) -> str:
    return (f"{s.name} ({s.agency}); {s.level}/{s.jurisdiction}; "
            f"{'automated' if s.automated else 'manual'} search; coverage partial")
