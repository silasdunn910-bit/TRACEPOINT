"""Rendering for the Integrations dashboard. Takes status rows from integrations.manager, which never
contain credential values, so nothing here can reveal a key."""
from __future__ import annotations

from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

STATUS_STYLE = {"CONNECTED": "tp.ok", "NOT TESTED": "tp.warn", "RATE LIMITED": "tp.warn", "DISABLED": "tp.muted",
                "NOT CONFIGURED": "tp.dim", "AUTHENTICATION FAILED": "tp.err", "PROVIDER UNAVAILABLE": "tp.err",
                "ERROR": "tp.err"}


def quota_text(q: dict | None) -> str:
    if not q:
        return "—"
    rem, lim = q.get("remaining"), q.get("limit")
    if rem is not None and lim is not None:
        return f"{rem}/{lim}"
    return str(rem if rem is not None else lim)


def _short(ts: str) -> str:
    return ts[:16].replace("T", " ") if ts else "—"


def table(rows: list[dict]) -> Table:
    t = Table(box=None, expand=True)
    t.add_column("#", style="tp.key", width=3)
    t.add_column("Provider", style="tp.val", no_wrap=True)
    t.add_column("Category", style="tp.accent2", width=14)
    t.add_column("Tier", width=9)
    t.add_column("Status", width=22)
    t.add_column("Last OK", style="tp.dim", width=16)
    t.add_column("Quota left", style="tp.dim", width=10)
    for i, r in enumerate(rows, 1):
        t.add_row(str(i), r["name"], r["category"].split(" / ")[0], r["tier"],
                  Text("● " + r["status"], style=STATUS_STYLE.get(r["status"], "tp.err")),
                  _short(r["last_success"]), quota_text(r["quota"]))
    return t


def detail(r: dict) -> Panel:
    lines = [Text.assemble(("Status      ", "tp.label"), (r["status"], STATUS_STYLE.get(r["status"], "tp.err")))]
    if r["detail"]:
        lines.append(Text.assemble(("Detail      ", "tp.label"), (r["detail"], "tp.val")))
    for label, key in (("Free tier", "free_info"), ("Auth", "auth"), ("Endpoint", "endpoint"),
                       ("Sign up", "signup_url"), ("Docs", "docs_url")):
        if r.get(key):
            lines.append(Text.assemble((f"{label:<12}", "tp.label"), (r[key], "tp.val")))
    lines.append(Text.assemble(("Credentials ", "tp.label"),
                               (", ".join(r["env_vars"]) if r["env_vars"] else "none required", "tp.val")))
    lines.append(Text.assemble(("Lookups     ", "tp.label"), ("; ".join(f"{k}: {v}" for k, v in r["lookups"].items()), "tp.val")))
    lines.append(Text.assemble(("Last tested ", "tp.label"), (_short(r["last_tested"]), "tp.val"),
                               ("   Quota ", "tp.label"), (quota_text(r["quota"]), "tp.val")))
    for lim in r["limitations"]:
        lines.append(Text.assemble(("Limitation  ", "tp.warn"), (lim, "tp.dim")))
    return Panel(Group(*lines), title=f"[tp.head]{r['name']}[/tp.head]", border_style="tp.rule")
