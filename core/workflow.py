"""Investigation workflow: ten named stages, each with a recorded status.

Initialization -> Authorization -> Search Execution -> Source Collection -> Deduplication -> Evidence Assessment
-> Entity Resolution -> AI Analysis -> Intelligence Report -> Database Persistence

A stage is only ever recorded with what actually happened. A stage that did not run is NOT_RUN (never OK), a stage
that does not apply is SKIPPED / NOT_REQUIRED, and a failure keeps its (scrubbed) detail. Stage records are stored in
investigation_stages and shown in the report's Research Methodology section.
"""
from __future__ import annotations

from core.models import now_iso

STAGES = ("Initialization", "Authorization", "Search Execution", "Source Collection", "Deduplication",
          "Evidence Assessment", "Entity Resolution", "AI Analysis", "Intelligence Report", "Database Persistence")

OK, PARTIAL, FAILED = "OK", "PARTIAL", "FAILED"
SKIPPED, NOT_REQUIRED, NOT_RUN = "SKIPPED", "NOT_REQUIRED", "NOT_RUN"
STATUSES = (OK, PARTIAL, FAILED, SKIPPED, NOT_REQUIRED, NOT_RUN)

# investigations.status values written by the workflow
ST_COMPLETE, ST_COMPLETE_ERRORS, ST_FAILED = "complete", "complete_with_errors", "failed"


class Workflow:
    def __init__(self):
        self._rec: dict[str, dict] = {}

    def record(self, stage: str, status: str, detail: str = "", started_at: str = "") -> None:
        if stage not in STAGES:
            raise ValueError(f"Unknown workflow stage: {stage}")
        if status not in STATUSES:
            raise ValueError(f"Unknown stage status: {status}")
        ts = now_iso()
        self._rec[stage] = {"stage": stage, "status": status, "started_at": started_at or ts, "finished_at": ts,
                            "detail": detail}

    def get(self, stage: str) -> dict | None:
        return self._rec.get(stage)

    def failed(self) -> list[str]:
        return [s for s in STAGES if self._rec.get(s, {}).get("status") == FAILED]

    def as_list(self) -> list[dict]:
        """All ten stages in order; stages never reached are NOT_RUN (never silently OK)."""
        ts = now_iso()
        return [self._rec.get(s) or {"stage": s, "status": NOT_RUN, "started_at": ts, "finished_at": "",
                                     "detail": "not reached"} for s in STAGES]
