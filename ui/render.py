"""Rendering helpers: turn ModuleResult / DB rows into Rich renderables."""
from __future__ import annotations

from collections import defaultdict

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from core.models import CONFIDENCE_LEVELS, ModuleResult
from ui.theme import CONF_DOT, CONF_STYLE, STATUS_ICON, STATUS_STYLE


def confidence_text(conf: str) -> Text:
    return Text(f"{CONF_DOT.get(conf, '·')} {conf}", style=CONF_STYLE.get(conf, "white"))


def findings_panel(result: ModuleResult) -> Panel:
    groups: dict[str, list] = defaultdict(list)
    for f in result.findings:
        groups[f.category].append(f)
    blocks = []
    for cat in sorted(groups):
        t = Table(box=None, expand=True, pad_edge=False, show_header=False)
        t.add_column(width=12, no_wrap=True)
        t.add_column(ratio=1)
        for f in groups[cat]:
            head = Text()
            head.append(f.title, style="bold white")
            if f.value and f.value not in f.title:
                head.append(f"  {f.value}", style="tp.key")
            body = Text(f.description, style="tp.label")
            if f.source_url:
                body.append(f"\n{f.source_url}", style="tp.accent2 underline")
            if f.limitations:
                body.append(f"\n⚠ {f.limitations}", style="tp.muted")
            t.add_row(confidence_text(f.confidence), Group(head, body))
        blocks.append(Panel(t, title=f"[tp.head]{cat.upper()}[/tp.head]", title_align="left",
                            border_style="tp.rule", padding=(0, 1)))
    if not blocks:
        blocks = [Text("No findings.", style="tp.warn")]
    return Panel(Group(*blocks), title=f"[tp.accent]FINDINGS · {len(result.findings)}[/tp.accent]",
                border_style="tp.accent", padding=(1, 1))


def summary_bar(result: ModuleResult) -> Panel:
    counts = {c: 0 for c in CONFIDENCE_LEVELS}
    for f in result.findings:
        counts[f.confidence] = counts.get(f.confidence, 0) + 1
    line = Text()
    for c in CONFIDENCE_LEVELS:
        line.append(f"  {CONF_DOT[c]} {counts[c]} {c}  ", style=CONF_STYLE[c])
    ok = sum(1 for s in result.sources if s.status == "ok")
    err = sum(1 for s in result.sources if s.status == "error")
    meta = Text(f"\n  sources: {ok} ok", style="tp.ok")
    if err:
        meta.append(f" · {err} failed", style="tp.err")
    meta.append(f" · {len(result.entities)} entities · {len(result.relationships)} relationships", style="tp.dim")
    return Panel(Group(line, meta), title="[tp.accent]EVIDENCE SUMMARY[/tp.accent]", border_style="tp.rule")


def sources_table(result: ModuleResult) -> Table:
    t = Table(title="Sources consulted", box=None, title_style="tp.head", expand=True)
    t.add_column("", width=2)
    t.add_column("Source", style="tp.val")
    t.add_column("Status", width=16)
    t.add_column("Detail", style="tp.dim", ratio=1)
    for s in result.sources:
        t.add_row(Text(STATUS_ICON.get(s.status, "?"), style=STATUS_STYLE.get(s.status, "white")),
                  s.name, Text(s.status, style=STATUS_STYLE.get(s.status, "white")), s.detail[:80])
    return t


def entities_table(result: ModuleResult) -> Table:
    t = Table(title="Entities", box=None, title_style="tp.head", expand=True)
    t.add_column("Type", style="tp.accent2", width=14)
    t.add_column("Value", style="tp.val")
    t.add_column("Verification", width=12, style="tp.dim")
    for e in result.entities:
        t.add_row(e.type, e.value[:70], e.verification)
    return t
