"""Intelligence Report view (Rich). Rendered from the same document blocks as the Markdown/PDF exports.

Every piece of stored text is wrapped in rich.text.Text, never interpolated into markup, so third-party content
cannot inject Rich markup. The long Evidence Registry and Source References sections are shown as compact tables;
any E#/S# can be opened in full with evidence_panel().
"""
from __future__ import annotations

from rich.console import Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from core.intelligence.formatter import SECTION_TITLES, blocks
from core.intelligence.models import (COMPLETE, CONTRADICTORY, CORROBORATED_CLAIM, FAILED, INCOMPLETE, PARTIAL,
                                      SINGLE_SOURCE_CLAIM, STATUS_MEANING, VERIFIED_FACT, IntelligenceReport)

STATUS_STYLE = {COMPLETE: "tp.ok", PARTIAL: "tp.warn", INCOMPLETE: "tp.err", FAILED: "tp.err"}
LEVEL_STYLE = {"HIGH": "tp.ok", "MODERATE": "tp.accent2", "LOW": "tp.warn", "INSUFFICIENT": "tp.err"}
CLASS_STYLE = {VERIFIED_FACT: "bold cyan", CORROBORATED_CLAIM: "bold blue", SINGLE_SOURCE_CLAIM: "yellow",
               CONTRADICTORY: "bold red"}
_COMPACT = {SECTION_TITLES[3], SECTION_TITLES[5]}


def status_text(status: str) -> Text:
    label = {INCOMPLETE: "INCOMPLETE - not a successful investigation", FAILED: "FAILED"}.get(status, status)
    return Text(label, style=STATUS_STYLE.get(status, "white"))


def brief_panel(report: IntelligenceReport | None, row: dict | None) -> Panel:
    """Shown automatically when an investigation completes."""
    if report is None:
        err = (row or {}).get("error") or "no report was stored"
        return Panel(Text(f"The intelligence report could not be generated: {err}\nThe investigation itself was saved.",
                          style="tp.err"), title="[tp.err]INTELLIGENCE REPORT FAILED[/tp.err]", border_style="tp.err")
    body = Text()
    body.append("Status: ", style="tp.dim")
    body.append_text(status_text(report.status))
    body.append("    Evidence assessment: ", style="tp.dim")
    body.append(report.confidence.level, style=LEVEL_STYLE.get(report.confidence.level, "white"))
    for line in report.executive_summary[1:4]:
        body.append("\n" + line, style="tp.label")
    body.append("\nOpen with 'intel' for the full report, evidence links and PDF / Markdown export.", style="tp.dim")
    style = STATUS_STYLE.get(report.status, "tp.rule")
    return Panel(body, title=f"[{style}]INTELLIGENCE REPORT · {report.overview['reference']}[/{style}]",
                 border_style=style)


def _evidence_table(r: IntelligenceReport) -> Table:
    t = Table(box=None, expand=True, pad_edge=False)
    t.add_column("Ref", style="tp.key", width=5)
    t.add_column("Class", width=24)
    t.add_column("Finding", ratio=1)
    t.add_column("Src", width=5, style="tp.accent2")
    t.add_column("Retrieved", width=20, style="tp.dim")
    for e in r.evidence:
        cls = Text(e.claim_class, style=CLASS_STYLE.get(e.claim_class, "grey62"))
        title = Text(e.title[:90])
        if e.duplicate_of:
            title.append(f"  (repeat of {e.duplicate_of})", style="tp.dim")
        if e.metadata_gaps and any(g != "publication date not provided by the source" for g in e.metadata_gaps):
            title.append("  ⚠ metadata gaps", style="tp.warn")
        t.add_row(e.ref, cls, title, e.source_ref, Text(e.retrieved_at or "not recorded"))
    return t


def _source_table(r: IntelligenceReport) -> Table:
    t = Table(box=None, expand=True, pad_edge=False)
    t.add_column("Ref", style="tp.key", width=5)
    t.add_column("Source", ratio=1)
    t.add_column("Status", width=14)
    t.add_column("Type", width=30, style="tp.dim")
    for s in r.sources:
        name = Text(s.name or "unnamed source")
        if s.url:
            name.append("\n" + s.url, style="tp.accent2 underline")
        t.add_row(s.ref, name, Text(s.status or "cited"), Text(s.tier))
    return t


def document(r: IntelligenceReport) -> Group:
    parts: list = []
    skip = False
    for blk in blocks(r):
        kind = blk[0]
        if kind == "h2":
            skip = blk[1] in _COMPACT
            parts.append(Rule(Text(blk[1], style="tp.head"), style="tp.rule", align="left"))
            if blk[1] == SECTION_TITLES[5]:
                parts.append(Text("Type an evidence ref (e.g. E1) to see its full provenance and supporting evidence.",
                                  style="tp.dim"))
                parts.append(_evidence_table(r))
            elif blk[1] == SECTION_TITLES[3]:
                parts.append(_source_table(r))
            continue
        if skip:
            continue
        if kind == "h1":
            parts.append(Text(blk[1], style="bold white"))
        elif kind == "h3":
            parts.append(Text(blk[1], style="bold white"))
        elif kind == "p":
            parts.append(Text(blk[1], style="tp.label"))
        elif kind in ("li", "ref"):
            parts.append(Text("  • " + blk[1], style="tp.label"))
        elif kind == "kv":
            t = Text("  ")
            t.append(blk[1] + ": ", style="tp.dim")
            if blk[1] == "Report status":
                t.append_text(status_text(r.status))
                t.append(" - " + STATUS_MEANING[r.status], style="tp.label")
            else:
                t.append(blk[2], style="tp.val")
            parts.append(t)
        elif kind == "url":
            parts.append(Text(f"  {blk[1]}: {blk[2]}", style="tp.accent2"))
        elif kind == "pre":
            parts.append(Panel(Text(blk[1]), border_style="tp.rule"))
    return Group(*parts)


def evidence_panel(r: IntelligenceReport, ref: str) -> Panel | None:
    """Full provenance of one evidence item (E#) or source (S#); None if the ref does not exist."""
    ref = ref.strip().upper()
    e = r.evidence_by_ref().get(ref)
    if e:
        s = r.source_by_ref().get(e.source_ref)
        rows = [("Claim class", f"{e.claim_class} (module grade {e.stored_grade})"), ("Category", e.category),
                ("Title", e.title), ("Value", e.value or "-"), ("Statement", e.description),
                ("Source", f"{e.source or 'not recorded'} [{e.source_ref}]" + (f" - {s.tier}" if s else "")),
                ("Source URL", e.source_url or "not recorded"), ("Retrieved", e.retrieved_at or "not recorded"),
                ("Published", e.published_at or "not provided by source")]
        if e.query:
            rows.append(("Search query", e.query))
        rows += [("Supporting evidence", e.evidence or "not recorded"), ("Limitations", e.limitations or "-"),
                 ("Why it matters", e.significance)]
        if e.corroborated_by:
            rows.append(("Corroborated by", ", ".join(e.corroborated_by)))
        if e.conflicts_with:
            rows.append(("Conflicts with", ", ".join(e.conflicts_with)))
        if e.duplicate_of:
            rows.append(("Repeat of", e.duplicate_of))
        if e.metadata_gaps:
            rows.append(("Metadata gaps", "; ".join(e.metadata_gaps)))
        title = f"EVIDENCE {e.ref}"
    else:
        s = r.source_by_ref().get(ref)
        if not s:
            return None
        rows = [("Name", s.name or "unnamed"), ("URL", s.url or "not recorded"), ("Status", s.status or "cited by findings"),
                ("Consulted / retrieved", s.consulted_at or "not recorded"), ("Source type", f"{s.tier} ({s.tier_basis})"),
                ("Detail", s.detail or "-"), ("Evidence", ", ".join(s.evidence_refs) or "none")]
        title = f"SOURCE {s.ref}"
    t = Table(box=None, show_header=False, expand=True)
    t.add_column(style="tp.dim", width=20)
    t.add_column(ratio=1)
    for k, v in rows:
        t.add_row(k, Text(v, style="tp.accent2 underline" if k in ("Source URL", "URL") and v != "not recorded" else "tp.val"))
    return Panel(t, title=f"[tp.head]{title}[/tp.head]", border_style="tp.accent")


def list_table(rows: list) -> Table:
    t = Table(box=None, expand=True)
    t.add_column("Inv", style="tp.key", width=4)
    t.add_column("Ref", style="tp.accent2")
    t.add_column("Type", width=10)
    t.add_column("Target", ratio=1)
    t.add_column("Report status", width=14)
    t.add_column("Generated", style="tp.dim", width=20)
    for r in rows:
        t.add_row(str(r["investigation_id"]), r["ref"], r["inv_type"], Text(r["target"][:46]), status_text(r["status"]),
                  r["generated_at"].replace("T", " ")[:19])
    return t
