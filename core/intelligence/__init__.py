"""Universal Intelligence Report Engine.

The standard final stage of every TRACEPOINT investigation: core.investigation.run() calls
generate_and_store() after a result is saved, for every investigation type (including future ones).

    engine.py            pipeline, storage, reopen
    models.py            report data structures, status / claim-class / assessment vocabularies
    evidence_analyzer.py registry, source tiers, corroboration, duplicates, discrepancies, inferences
    confidence.py        completeness status and overall evidence assessment
    templates.py         all analytical wording, per-type profiles, unsupported-conclusion guard
    formatter.py         document blocks + Markdown
    pdf.py               dependency-free PDF writer

Collection is shared with the evidence reports in core.reports (TXT/JSON/HTML) through core.reports.build().
"""
from __future__ import annotations

import os
from pathlib import Path

from .engine import generate, generate_and_store, load_latest, open_or_generate
from .models import FAILED, IntelligenceReport

EXPORT_FORMATS = ("md", "pdf")


class ReportUnavailable(RuntimeError):
    """The intelligence report could not be generated; the message carries the stored error."""


def render(report: IntelligenceReport, fmt: str) -> bytes:
    from .formatter import to_markdown
    from .pdf import to_pdf
    fmt = fmt.lower()
    if fmt == "md":
        return to_markdown(report).encode("utf-8")
    if fmt == "pdf":
        return to_pdf(report)
    raise ValueError(f"Unsupported intelligence report format: {fmt}")


def export(inv_id: int, fmt: str, report: IntelligenceReport | None = None) -> Path:
    """Write the (stored, or freshly generated) intelligence report to REPORTS_DIR and register it."""
    from core.configuration import REPORTS_DIR
    from core.database import get_db
    fmt = fmt.lower()
    if fmt not in EXPORT_FORMATS:
        raise ValueError(f"Unsupported intelligence report format: {fmt}")
    if report is None:
        report, row = open_or_generate(inv_id)
        if report is None:
            raise ReportUnavailable((row or {}).get("error") or "The intelligence report could not be generated.")
    body = render(report, fmt)
    path = REPORTS_DIR / f"{report.overview['reference']}-intel.{fmt}"
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_bytes(body)
    os.replace(tmp, path)            # never leave a half-written report behind
    get_db().add_report(inv_id, f"intel-{fmt}", path.name)
    return path


__all__ = ["EXPORT_FORMATS", "FAILED", "IntelligenceReport", "ReportUnavailable", "export", "generate",
           "generate_and_store", "load_latest", "open_or_generate", "render"]
