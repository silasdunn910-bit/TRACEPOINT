#!/usr/bin/env python3
"""TRACEPOINT — interactive Rich terminal application."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rich.align import Align
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from core import ai, correlation, intelligence, investigation, reports
from core.configuration import API_INTEGRATIONS, APP_NAME, REPORTS_DIR, VERSION
from core.database import get_db
from core.investigation import SPECS
from core.models import ModuleResult
from core.security import clean_input, encryption_mode, mask
from ui import render, report_view
from ui.theme import BANNER, THEME

console = Console(theme=THEME, highlight=False)
db = get_db()

MENU = [
    ("1", "email", "Email Intelligence"), ("2", "phone", "Phone Intelligence"),
    ("3", "username", "Username Intelligence"), ("4", "domain", "Domain Intelligence"),
    ("5", "ip", "IP Intelligence"), ("6", "social", "Social Intelligence"),
    ("7", "security", "Security Intelligence"), ("8", "name", "Name Intelligence"),
    ("16", "court", "Court Records Intelligence"), ("17", "registry", "Sex Offender Registry Intelligence"),
]
ACTIONS = [
    ("9", "universal", "Universal Search  [tp.dim](auto-detect identifier)[/tp.dim]"),
    ("10", "graph", "Relationship Explorer"), ("11", "history", "Investigation History"),
    ("12", "reports", "Reports"), ("19", "intel", "Intelligence Reports"), ("13", "api", "API Configuration"),
    ("18", "integrations", "Integrations Dashboard"), ("14", "settings", "Settings"), ("15", "ai", "AI Analyst Status"), ("0", "exit", "Exit"),
]


# ------------------------------------------------------------------ helpers
_ai_cache: tuple[float, tuple] | None = None
AI_STATUS_TTL = 30.0


def _header_ai_status() -> tuple[bool, list[str], str]:
    """Ollama status for the banner only, cached: an offline probe costs ~2 s on Windows and
    the banner is redrawn after every action. Other screens still query live."""
    global _ai_cache
    now = time.monotonic()
    if _ai_cache is None or now - _ai_cache[0] > AI_STATUS_TTL:
        _ai_cache = (now, ai.status())
    return _ai_cache[1]


def header():
    console.clear()
    console.print(BANNER)
    ok, models, _ = _header_ai_status()
    s = get_db().stats()
    bar = Text("  ", style="tp.dim")
    bar.append(f"v{VERSION}", style="tp.muted")
    bar.append("   investigations ", style="tp.dim"); bar.append(str(s["investigations"]), style="tp.accent")
    bar.append("   findings ", style="tp.dim"); bar.append(str(s["findings"]), style="tp.accent")
    bar.append("   entities ", style="tp.dim"); bar.append(str(s["entities"]), style="tp.accent")
    bar.append("   AI ", style="tp.dim")
    bar.append("online" if ok else "offline", style="tp.ok" if ok else "tp.muted")
    if ok and models:
        bar.append(f" ({ai.selected_model(models) or 'no model'})", style="tp.dim")
    console.print(bar)
    console.print(Rule(style="tp.rule"))


def main_menu():
    left = Table.grid(padding=(0, 2))
    left.add_column(justify="right", style="tp.key", width=3)
    left.add_column()
    left.add_row("", Text("INVESTIGATION MODULES", style="tp.head"))
    for num, key, label in MENU:
        left.add_row(num, Text(label, style="tp.val"))
    right = Table.grid(padding=(0, 2))
    right.add_column(justify="right", style="tp.key", width=3)
    right.add_column()
    right.add_row("", Text("TOOLS", style="tp.head"))
    for num, key, label in ACTIONS:
        right.add_row(num, label)
    grid = Table.grid(padding=(0, 6), expand=True)
    grid.add_column(); grid.add_column()
    grid.add_row(Panel(left, border_style="tp.rule"), Panel(right, border_style="tp.rule"))
    console.print(grid)


def ask(label: str, example: str = "") -> str:
    hint = f" [tp.dim]({example})[/tp.dim]" if example else ""
    try:
        return clean_input(Prompt.ask(f"[tp.accent]›[/tp.accent] {label}{hint}", console=console))
    except ValueError as e:
        console.print(f"[tp.err]{e}[/tp.err]")
        return ""


def authorize(inv_type: str) -> bool:
    if not investigation.requires_authorization(inv_type):
        return True
    console.print(Panel(investigation.AUTHORIZATION_TEXT, title="[tp.warn]AUTHORIZATION REQUIRED[/tp.warn]",
                        border_style="tp.warn"))
    return Confirm.ask("[tp.warn]I confirm I own this identifier or am authorized to audit it[/tp.warn]",
                       console=console, default=False)


def run_and_show(inv_type: str, target: str, **kwargs):
    if not target:
        return
    already_authorized = kwargs.pop("already_authorized", False)
    if not already_authorized and not authorize(inv_type):
        console.print("[tp.dim]Cancelled — authorization not given.[/tp.dim]")
        return
    if inv_type == "phone" and "default_region" not in kwargs:
        from modules.phone_intel import normalize_phone_input
        try:
            normalized_phone = normalize_phone_input(target)
        except ValueError:
            normalized_phone = ""
        if not normalized_phone.startswith("+"):
            region = ask("Numbering region for this national-format number (ISO country code)", "US")
            kwargs["default_region"] = (region or "US").upper()
    result: ModuleResult | None = None
    inv_id = None
    with console.status(f"[tp.accent]Investigating[/tp.accent] {target} …", spinner="dots"):
        try:
            result, inv_id = investigation.run(inv_type, target, authorized=True, **kwargs)
        except KeyboardInterrupt:
            console.print("[tp.warn]Investigation interrupted - nothing was saved.[/tp.warn]")
            return
        except Exception as e:
            console.print(Panel(f"{type(e).__name__}: {e}", title="[tp.err]ERROR[/tp.err]", border_style="tp.err"))
            return
    console.print()
    console.print(render.summary_bar(result))
    console.print(render.findings_panel(result))
    if result.entities:
        console.print(render.entities_table(result))
    console.print(render.sources_table(result))
    if result.errors:
        console.print(Panel("\n".join(f"• {e}" for e in result.errors),
                            title="[tp.warn]SOURCE / LOOKUP ISSUES[/tp.warn]", border_style="tp.warn"))
    shown_notes = [n for n in result.notes if not n.startswith("[coverage-data]")]
    if shown_notes:
        console.print(Panel("\n".join(f"• {escape(n)}" for n in shown_notes), title="[tp.dim]NOTES[/tp.dim]",
                            border_style="tp.rule"))
    saved = db.get_investigation(inv_id)
    if saved["status"] == "failed":
        console.print(Panel("The investigation module failed before completing. The failure was recorded; nothing here "
                            "is a search result, and no conclusion should be drawn from it.",
                            title="[tp.err]INVESTIGATION FAILED[/tp.err]", border_style="tp.err"))
    console.print(f"[tp.ok]✓ Saved as investigation {saved['ref']} (id {inv_id}) - status: {saved['status']}.[/tp.ok]")
    # investigation.run() has already generated and stored the intelligence report (or a FAILED record)
    console.print(report_view.brief_panel(*intelligence.load_latest(inv_id)))
    post_investigation(inv_id)


def post_investigation(inv_id: int):
    while True:
        choice = Prompt.ask("\n[tp.accent]Action[/tp.accent]", choices=["intel", "report", "ai", "graph", "back"],
                            default="back", console=console)
        if choice == "intel":
            intel_report_view(inv_id)
        elif choice == "report":
            do_report(inv_id)
        elif choice == "ai":
            do_ai(inv_id)
        elif choice == "graph":
            show_graph(inv_id)
        else:
            return


# ------------------------------------------------------------------ actions
def _route_name_query(inv_type: str, label: str, example: str):
    target = ask(label, example)
    if not target:
        return
    if inv_type == "name":
        context = ask("Legitimate research context (optional; avoid sensitive/private details)")
        run_and_show(inv_type, target, context=context)
    else:
        run_and_show(inv_type, target)
    console.input("\n[tp.dim]Press Enter to return to routing…[/tp.dim]")


def _run_name_query(name: str):
    context = ask("Legitimate research context (optional; avoid sensitive/private details)")
    run_and_show("name", name, context=context)


def _name_routing_screen(name_query: str):
    """Route name queries to identifier-based modules without doing free-text people search."""
    console.print(Rule("[tp.head]IDENTIFIER-BASED ROUTING[/tp.head]", style="tp.rule"))
    console.print(Panel(
    "A name query can use Name Intelligence for a stated, legitimate research purpose. Authorization is required. "
        "Search matches are leads only; TRACEPOINT does not assume that matching names describe the same person.\n\n"
        "You can also continue with the existing authorized identifier-based routes.",
        title="[tp.warn]NAME DETECTED[/tp.warn]",
        border_style="tp.warn",
    ))
    table = Table.grid(padding=(0, 2))
    table.add_column(justify="right", style="tp.key", width=3)
    table.add_column()
    table.add_row("", Text("AVAILABLE ROUTES", style="tp.head"))
    table.add_row("1", "Email Intelligence — investigate an email address")
    table.add_row("2", "Phone Intelligence — investigate a phone number")
    table.add_row("3", "Username Intelligence — investigate a handle/username")
    table.add_row("6", "Social Intelligence — investigate a profile URL")
    table.add_row("7", "Name Intelligence — search public sources with context")
    table.add_row("8", "Return to Universal Search")
    table.add_row("0", "Return to Main Menu")
    console.print(Panel(table, border_style="tp.rule"))
    console.print(f"[tp.dim]Query entered:[/tp.dim] [tp.val]{name_query}[/tp.val]")
    while True:
        choice = Prompt.ask("[tp.accent]Route to[/tp.accent]", choices=["1", "2", "3", "6", "7", "8", "0"], console=console)
        if choice == "0":
            return "menu"
        if choice == "8":
            return "universal"
        if choice == "1":
            _route_name_query("email", "Email address", EXAMPLES.get("email", ""))
            continue
        if choice == "2":
            _route_name_query("phone", "Phone number", EXAMPLES.get("phone", ""))
            continue
        if choice == "3":
            _route_name_query("username", "Username/handle", EXAMPLES.get("username", ""))
            continue
        if choice == "6":
            _route_name_query("social", "Profile URL", EXAMPLES.get("social", ""))
            continue
        if choice == "7":
            _run_name_query(name_query)
            continue


def _warn_if_no_search_provider(itype: str) -> None:
    """Identifier types that rely on public web search: say up front when only the best-effort fallback exists."""
    if itype not in ("name", "username", "email", "phone", "court", "registry", "social"):
        return
    from core import search_engine
    if not any(p.requires_key for p in search_engine.active_providers()):
        console.print("[tp.warn]No search provider (Brave / Google / SearXNG) is configured. Web-search results use the "
                      "DuckDuckGo fallback, which may be rate-limited or blocked; if it fails the report will say the "
                      "search did not run. Configure one in API Configuration (item 13), then press 't' to test it.[/tp.warn]")


def universal_search():
    while True:
        target = ask("Enter any identifier", "email / phone / IP / domain / profile URL")
        if not target:
            return
        itype, reason = correlation.detect_type(target)
        if itype == "name":
            before_id = db.q("SELECT COALESCE(MAX(id),0) n FROM search_history")[0]["n"]
            route = _name_routing_screen(target)
            logged = db.q("SELECT 1 FROM search_history WHERE id>? AND query=? AND detected_type='name' LIMIT 1",
                          (before_id, target))
            if not logged:
                db.conn.execute("INSERT INTO search_history(query,detected_type,searched_at) VALUES (?,?,datetime('now'))",
                                (target, itype)); db.conn.commit()
            if route == "menu":
                return
            if route == "universal":
                continue
            return
        if itype in SPECS:
            _warn_if_no_search_provider(itype)
            console.print(f"[tp.ok]Detected:[/tp.ok] [tp.accent]{SPECS[itype].label}[/tp.accent] [tp.dim]({reason})[/tp.dim]")
            if Confirm.ask("Proceed?", default=True, console=console):
                run_and_show(itype, target)  # save_result() records this in search_history
            console.input("\n[tp.dim]Press Enter to return to Universal Search…[/tp.dim]")
            continue
        # Not a runnable module: log the attempt so history still reflects it.
        db.conn.execute("INSERT INTO search_history(query,detected_type,searched_at) VALUES (?,?,datetime('now'))",
                        (target, itype)); db.conn.commit()
        console.print(f"[tp.warn]Could not classify '{target}' ({reason}). Pick a module from the menu or try an identifier.[/tp.warn]")
        console.input("\n[tp.dim]Press Enter to return to Universal Search…[/tp.dim]")
        continue


def show_graph(inv_id: int | None):
    g = correlation.graph_json(inv_id)
    console.print(Panel(f"nodes: [tp.accent]{g['summary']['nodes']}[/tp.accent]   "
                        f"edges: [tp.accent]{g['summary']['edges']}[/tp.accent]\n"
                        f"by type: " + "  ".join(f"{k}={v}" for k, v in g['summary']['by_type'].items()),
                        title="[tp.head]GRAPH[/tp.head]", border_style="tp.rule"))
    if inv_id:
        for r in db.relationships_for(inv_id):
            console.print(f"  [tp.val]{r['src_value'][:34]}[/tp.val] [tp.dim]—{r['rel_type']} "
                          f"({r['confidence']})→[/tp.dim] [tp.val]{r['dst_value'][:34]}[/tp.val]")
    if Confirm.ask("Export Cytoscape JSON?", default=False, console=console):
        name = f"graph-{db.get_investigation(inv_id)['ref'] if inv_id else 'all'}.json"
        p = correlation.export_graph(REPORTS_DIR / name, inv_id)
        console.print(f"[tp.ok]✓ {p}[/tp.ok]  [tp.dim](import into cytoscape.js / the TRACEPOINT web graph)[/tp.dim]")


def _render_graph_summary(g: dict, title: str):
    s = g["summary"]
    by = "  ".join(f"{k}={v}" for k, v in s["by_type"].items()) or "—"
    console.print(Panel(f"nodes: [tp.accent]{s['nodes']}[/tp.accent]   edges: [tp.accent]{s['edges']}[/tp.accent]"
                        + (f"   selected: [tp.accent]{s['selected']}[/tp.accent]" if s.get("selected") else "")
                        + f"\nby type: {by}", title=f"[tp.head]{title}[/tp.head]", border_style="tp.rule"))
    for e in g["elements"]["edges"][:40]:
        src = next((n["data"]["label"] for n in g["elements"]["nodes"] if n["data"]["id"] == e["data"]["source"]), "?")
        dst = next((n["data"]["label"] for n in g["elements"]["nodes"] if n["data"]["id"] == e["data"]["target"]), "?")
        console.print(f"  [tp.val]{src[:32]}[/tp.val] [tp.dim]—{e['data']['label']} "
                      f"({e['data']['confidence']})→[/tp.dim] [tp.val]{dst[:32]}[/tp.val]")


def relationship_explorer():
    console.print(Rule("[tp.head]RELATIONSHIP EXPLORER[/tp.head]", style="tp.rule"))

    # --- Mode A: cross-investigation correlation (entities in 2+ investigations) ---
    console.print("[tp.head]A · SHARED ENTITIES[/tp.head] [tp.dim]— appear in two or more investigations[/tp.dim]")
    all_shared = correlation.shared_entities(2)
    shared = [e for e in all_shared if not e["generic"]]
    generic = [e for e in all_shared if e["generic"]]
    if generic:
        console.print(f"[tp.dim]  {len(generic)} shared generic infrastructure entit{'y' if len(generic) == 1 else 'ies'} "
                      f"hidden (e.g. {generic[0]['value'][:40]}): using the same mail/DNS/hosting provider does not "
                      "connect two subjects.[/tp.dim]")
    if shared:
        t = Table(box=None, title_style="tp.head")
        t.add_column("Type", style="tp.accent2"); t.add_column("Value", style="tp.val")
        t.add_column("# inv", justify="right"); t.add_column("Investigations", style="tp.dim")
        for e in shared[:40]:
            t.add_row(e["entity_type"], e["value"][:50], str(e["n"]), e["refs"])
        console.print(t)
    else:
        console.print("[tp.dim]  No entity appears in more than one investigation yet.[/tp.dim]")

    # --- Mode B: ordinary entity search (substring match, this is NOT correlation) ---
    console.print("\n[tp.head]B · ENTITY SEARCH[/tp.head] [tp.dim]— substring match across all stored entities[/tp.dim]")
    term = ask("Search entities (blank to skip)")
    if not term:
        if Confirm.ask("Show the entire-database graph instead?", default=False, console=console):
            _render_graph_summary(correlation.graph_json(None), "ENTIRE DATABASE GRAPH")
            if Confirm.ask("Export entire-database graph?", default=False, console=console):
                p = correlation.export_graph(REPORTS_DIR / "graph-all.json")
                console.print(f"[tp.ok]✓ {p}[/tp.ok]")
        return
    matches = correlation.search_entities(term)
    if not matches:
        console.print(f"[tp.warn]  No entities match '{term}'.[/tp.warn]")
        return
    t = Table(box=None, title=f"Entity search results for '{term}'", title_style="tp.head")
    t.add_column("Type", style="tp.accent2", width=14); t.add_column("Value", style="tp.val")
    t.add_column("Verification", style="tp.dim", width=12)
    for e in matches:
        t.add_row(e["entity_type"], e["value"][:60], e["verification"])
    console.print(t)
    console.print(f"[tp.dim]  {len(matches)} match(es). The graph below is limited to these entities and their "
                  "direct relationships — not the whole database.[/tp.dim]")
    ids = [m["id"] for m in matches]
    g = correlation.graph_json_for_entities(ids)
    _render_graph_summary(g, f"FILTERED GRAPH · '{term}'")
    if Confirm.ask("Export this filtered graph?", default=False, console=console):
        safe = "".join(c if c.isalnum() else "_" for c in term)[:30]
        p = correlation.export_graph(REPORTS_DIR / f"graph-search-{safe}.json", entity_ids=ids)
        console.print(f"[tp.ok]✓ {p}[/tp.ok]  [tp.dim]({g['summary']['nodes']} nodes, {g['summary']['edges']} edges)[/tp.dim]")


def do_report(inv_id: int):
    console.print("[tp.dim]pdf / md: Intelligence Report.  txt / json / html: evidence report.[/tp.dim]")
    fmt = Prompt.ask("Format", choices=["pdf", "md", "txt", "json", "html", "all"], default="pdf", console=console)
    fmts = ["pdf", "md", "txt", "json", "html"] if fmt == "all" else [fmt]
    for f in fmts:
        try:
            p = reports.save(inv_id, f)
        except intelligence.ReportUnavailable as e:
            console.print(f"[tp.err]Intelligence report unavailable: {escape(str(e))}[/tp.err]")
            continue
        console.print(f"[tp.ok]✓ {p}[/tp.ok]")


def intel_report_view(inv_id: int):
    """Intelligence Report view: reopen the stored report, follow evidence links, export, or regenerate."""
    report, row = intelligence.open_or_generate(inv_id)
    shown = False
    while True:
        if report is None:
            console.print(report_view.brief_panel(None, row))
            if Confirm.ask("Try generating the report again?", default=False, console=console):
                intelligence.generate_and_store(inv_id)
                report, row = intelligence.load_latest(inv_id)
                continue
            return
        if not shown:
            style = report_view.STATUS_STYLE.get(report.status, "tp.rule")
            console.print(Panel(report_view.document(report), border_style=style,
                                title=f"[tp.head]INTELLIGENCE REPORT · {escape(report.overview['reference'])}[/tp.head]",
                                subtitle=f"[tp.dim]generated {escape(row['generated_at'])}[/tp.dim]"))
            shown = True
        sel = ask("E#/S# open evidence | pdf | md | regenerate | blank to return")
        if not sel:
            return
        cmd = sel.strip().lower()
        if cmd in intelligence.EXPORT_FORMATS:
            console.print(f"[tp.ok]✓ {intelligence.export(inv_id, cmd, report)}[/tp.ok]")
        elif cmd == "regenerate":
            intelligence.generate_and_store(inv_id)
            report, row = intelligence.load_latest(inv_id)
            shown = False
        else:
            panel = report_view.evidence_panel(report, sel)
            console.print(panel if panel else "[tp.warn]No such evidence or source reference.[/tp.warn]")


def intel_reports_menu():
    console.print(Rule("[tp.head]INTELLIGENCE REPORTS[/tp.head]", style="tp.rule"))
    console.print("[tp.dim]A report is generated automatically when each investigation completes. Investigations "
                  "saved before this feature get one the first time they are opened.[/tp.dim]")
    rows = db.list_intel_reports(60)
    if rows:
        console.print(report_view.list_table(rows))
    else:
        console.print("[tp.dim]No intelligence reports yet.[/tp.dim]")
    sel = ask("Open investigation id / ref (blank to return)")
    if not sel:
        return
    inv = db.find_investigation(sel)
    if not inv:
        console.print("[tp.warn]Not found.[/tp.warn]")
        return
    intel_report_view(inv["id"])


def do_ai(inv_id: int):
    ok, models, err = ai.status()
    if not ok:
        console.print(Panel(f"Ollama not reachable ({err}).\nStart Ollama, or set its URL in Settings. "
                            "TRACEPOINT works fully without AI.", title="[tp.warn]AI UNAVAILABLE[/tp.warn]",
                            border_style="tp.warn"))
        return
    task = Prompt.ask("Analysis", choices=["summary", "executive", "patterns", "gaps", "relationships", "contradictions"], default="summary",
                      console=console)
    with console.status(f"[tp.accent]Local model {ai.selected_model(models)} analysing…[/tp.accent]", spinner="dots"):
        try:
            text = ai.analyze(inv_id, task)
        except Exception as e:
            console.print(f"[tp.err]{e}[/tp.err]")
            return
    console.print(Panel(text, title="[tp.head]AI ANALYST[/tp.head]", border_style="tp.accent"))
    if task == "summary":
        db.set_ai_summary(inv_id, text)
        console.print("[tp.dim]Saved to the investigation; it will appear in exported reports.[/tp.dim]")


def history():
    console.print(Rule("[tp.head]INVESTIGATION HISTORY[/tp.head]", style="tp.rule"))
    rows = db.list_investigations(60)
    if not rows:
        console.print("[tp.dim]No investigations yet.[/tp.dim]"); return
    t = Table(box=None, expand=True)
    t.add_column("ID", style="tp.key", width=4); t.add_column("Ref", style="tp.accent2")
    t.add_column("Type", width=10); t.add_column("Target", style="tp.val", ratio=1)
    t.add_column("Findings", justify="right", width=8); t.add_column("When", style="tp.dim", width=20)
    for r in rows:
        t.add_row(str(r["id"]), r["ref"], r["inv_type"], r["target"][:46], str(r["n_findings"]),
                  r["created_at"].replace("T", " ")[:19])
    console.print(t)
    sel = ask("Open id / ref (blank to return)")
    if not sel:
        return
    inv = db.find_investigation(sel)
    if not inv:
        console.print("[tp.warn]Not found.[/tp.warn]"); return
    view_investigation(inv["id"])


def view_investigation(inv_id: int):
    from providers.coverage import parse_marker
    inv = db.get_investigation(inv_id)
    _cov, _notes = parse_marker(inv["notes"])
    console.print(Panel(f"[tp.accent]{inv['ref']}[/tp.accent]  type [tp.val]{inv['inv_type']}[/tp.val]  "
                        f"target [tp.val]{escape(inv['target'])}[/tp.val]\n[tp.dim]{inv['created_at']}  ·  {inv['status']}"
                        f"{'  ·  '+escape(_notes.strip()) if _notes.strip() else ''}[/tp.dim]",
                        border_style="tp.rule"))
    fs = db.findings(inv_id)
    cat = None
    for f in fs:
        if f["category"] != cat:
            cat = f["category"]; console.print(f"\n[tp.head]{cat.upper()}[/tp.head]")
        console.print(f"  {render.confidence_text(f['confidence'])}  [tp.val]{escape(f['title'])}[/tp.val] "
                      + (f"[tp.key]{escape(f['value'])}[/tp.key]" if f['value'] and f['value'] not in f['title'] else ""))
        if f["source_url"]:
            console.print(f"      [tp.accent2 underline]{escape(f['source_url'])}[/tp.accent2 underline]")
    if inv["ai_summary"]:
        console.print(Panel(inv["ai_summary"], title="[tp.head]AI ANALYSIS[/tp.head]", border_style="tp.rule"))
    action = Prompt.ask("\n[tp.accent]Action[/tp.accent]", choices=["intel", "report", "ai", "graph", "delete", "back"],
                        default="back", console=console)
    if action == "intel":
        intel_report_view(inv_id)
    elif action == "report":
        do_report(inv_id)
    elif action == "ai":
        do_ai(inv_id)
    elif action == "graph":
        show_graph(inv_id)
    elif action == "delete":
        if Confirm.ask(f"[tp.err]Delete {inv['ref']} permanently?[/tp.err]", default=False, console=console):
            db.delete_investigation(inv_id); console.print("[tp.ok]✓ Deleted.[/tp.ok]")


def reports_menu():
    console.print(Rule("[tp.head]REPORTS[/tp.head]", style="tp.rule"))
    rows = db.reports()
    if rows:
        t = Table(box=None); t.add_column("Ref", style="tp.accent2"); t.add_column("Target", style="tp.val")
        t.add_column("Format", width=9); t.add_column("Path", style="tp.dim")
        for r in rows[:30]:
            t.add_row(r["ref"], r["target"][:34], r["format"], r["path"] + ("" if r["exists"] else " [missing]"))
        console.print(t)
    else:
        console.print("[tp.dim]No reports generated yet.[/tp.dim]")
    console.print(f"[tp.dim]Reports are written to {REPORTS_DIR}[/tp.dim]")
    sel = ask("Generate a report for investigation id/ref (blank to return)")
    if sel:
        inv = db.find_investigation(sel)
        if inv:
            do_report(inv["id"])
        else:
            console.print("[tp.warn]Not found.[/tp.warn]")


def api_config():
    from core import credentials, search_engine
    from providers.search_providers import ALL_PROVIDERS
    search_by_key = {k: pr for pr in ALL_PROVIDERS for k in pr.secret_keys}
    while True:
        console.print(Rule("[tp.head]API CONFIGURATION[/tp.head]", style="tp.rule"))
        console.print(f"[tp.dim]Credentials are stored with {encryption_mode()} and never printed in full. "
                      "All integrations are optional. CONFIGURED means stored, not verified: "
                      "use 't' to run a connection test.[/tp.dim]\n")
        names = db.secret_names()
        t = Table(box=None, expand=True)
        t.add_column("#", style="tp.key", width=3); t.add_column("Integration", style="tp.val")
        t.add_column("Category", width=12, style="tp.accent2"); t.add_column("Status", width=22)
        t.add_column("Value", style="tp.dim")
        keys = list(API_INTEGRATIONS)
        for i, k in enumerate(keys, 1):
            label, cat, _ = API_INTEGRATIONS[k]
            if k not in names:
                status = Text("not set", style="tp.muted")
            elif k in search_by_key:
                st, _d = search_engine.provider_status(search_by_key[k])
                style = {"CONNECTED": "tp.ok", "CONFIGURED": "tp.warn"}.get(st, "tp.err")
                status = Text(f"● {st}", style=style)
            else:
                status = Text("● CONFIGURED (no test available)", style="tp.warn")
            t.add_row(str(i), label, cat, status, credentials.display_value(k, db.get_secret(k)) if k in names else "")
        console.print(t)
        sel = ask("Number to set/update, 'd N' to delete, 't' to test search providers, blank to return")
        if not sel:
            return
        if sel.lower() == "t":
            for pr in ALL_PROVIDERS:
                if pr.requires_key and pr.configured():
                    with console.status(f"Testing {pr.name}…"):
                        res = search_engine.check_provider(pr)
                    style = "tp.ok" if res.status == "CONNECTED" else "tp.err"
                    console.print(f"[{style}]{pr.name}: {res.status}[/{style}] [tp.dim]{res.detail}[/tp.dim]")
            if not any(pr.requires_key and pr.configured() for pr in ALL_PROVIDERS):
                console.print("[tp.warn]No search provider is configured; nothing to test.[/tp.warn]")
            continue
        delete = sel.lower().startswith("d")
        num = sel[1:].strip() if delete else sel
        if not num.isdigit() or not (1 <= int(num) <= len(keys)):
            console.print("[tp.warn]Invalid selection.[/tp.warn]"); continue
        key = keys[int(num) - 1]
        if delete:
            ok, msg = credentials.remove_credential(
                db, key, lambda: Confirm.ask(f"[tp.err]Delete the stored {API_INTEGRATIONS[key][0]}?[/tp.err]",
                                             default=False, console=console))
        else:
            console.print(f"[tp.dim]{API_INTEGRATIONS[key][2]}[/tp.dim]")
            val = Prompt.ask(f"Value for {API_INTEGRATIONS[key][0]}", password=(key != "searxng_url"), console=console)
            ok, msg = credentials.save_credential(db, key, val)
        console.print(f"[{'tp.ok' if ok else 'tp.warn'}]{'✓ ' if ok else ''}{msg}[/{'tp.ok' if ok else 'tp.warn'}]")


def integrations_dashboard():
    """Status of every free-API integration. Shows no credential values; tests are live requests."""
    import json as _json
    from core import credentials
    from integrations import manager
    from ui import integrations_view as iv
    while True:
        console.print(Rule("[tp.head]INTEGRATIONS[/tp.head]", style="tp.rule"))
        console.print("[tp.dim]CONNECTED means a live request succeeded; a stored key alone shows NOT TESTED. "
                      "Keys are set with 'k N' (stored encrypted) or through the environment variables in .env.example.[/tp.dim]\n")
        rows = manager.statuses()
        console.print(iv.table(rows))
        sel = ask("N details | t N test | ta test all | l N lookup | k N set key | x N disable/enable | blank to return")
        if not sel:
            return
        cmd, _, arg = sel.partition(" ")
        cmd, arg = cmd.lower(), arg.strip()
        if cmd == "ta":
            with console.status("Testing every configured integration…"):
                manager.test_all()
            continue
        num = arg if cmd in ("t", "l", "k", "x") else cmd
        if not num.isdigit() or not (1 <= int(num) <= len(rows)):
            console.print("[tp.warn]Invalid selection.[/tp.warn]"); continue
        row = rows[int(num) - 1]
        if cmd == "t":
            with console.status(f"Testing {row['name']}…"):
                row = manager.test(row["id"])
            console.print(iv.detail(row))
        elif cmd == "x":
            manager.set_disabled(row["id"], row["status"] != "DISABLED")
        elif cmd == "k":
            p = manager.get(row["id"])
            keys = p.secret_keys + p.optional_keys
            if not keys:
                console.print("[tp.dim]This provider needs no credentials.[/tp.dim]"); continue
            for k in keys:
                console.print(f"[tp.dim]{API_INTEGRATIONS[k][2]}[/tp.dim]")
                val = Prompt.ask(f"Value for {API_INTEGRATIONS[k][0]} (blank to skip)", password=(k != "searxng_url"),
                                 console=console)
                if val.strip():
                    ok, msg = credentials.save_credential(db, k, val)
                    console.print(f"[{'tp.ok' if ok else 'tp.warn'}]{msg}[/{'tp.ok' if ok else 'tp.warn'}]")
        elif cmd == "l":
            kinds = list(row["lookups"])
            kind = kinds[0] if len(kinds) == 1 else Prompt.ask("Lookup type", choices=kinds, default=kinds[0], console=console)
            val = ask(f"{kind} to look up")
            if not val:
                continue
            with console.status(f"Querying {row['name']}…"):
                res = manager.lookup(row["id"], kind, val)
            if not res["ok"]:
                console.print(f"[tp.err]{res['status']}[/tp.err] {escape(res['error'])}")
            else:
                r = res["result"]
                console.print(Panel(escape(_json.dumps({k: r[k] for k in ("provider", "query", "timestamp", "source_url",
                                                                       "result_type", "limitations")}, indent=2))
                                    + "\n\n" + escape(_json.dumps(r["data"].get("summary", r["data"]), indent=2, default=str)[:3000]),
                                    title="[tp.head]RESULT[/tp.head]", border_style="tp.rule"))
        else:
            console.print(iv.detail(row))
        console.input("[tp.dim]Enter…[/tp.dim]")


def settings():
    console.print(Rule("[tp.head]SETTINGS[/tp.head]", style="tp.rule"))
    ok, models, err = ai.status()
    console.print(f"Credential encryption: [tp.accent]{encryption_mode()}[/tp.accent]")
    console.print(f"Ollama endpoint: [tp.accent]{ai.endpoint()}[/tp.accent]  "
                  + ("[tp.ok]online[/tp.ok]" if ok else f"[tp.muted]offline[/tp.muted]"))
    if models:
        console.print("Installed models: " + ", ".join(f"[tp.val]{m}[/tp.val]" for m in models))
        console.print(f"Selected model: [tp.accent]{ai.selected_model(models)}[/tp.accent]")
    console.print(f"Database: [tp.dim]{db.path}[/tp.dim]  (schema v{db.schema_version()})\n")
    choice = Prompt.ask("Change", choices=["ollama-url", "ollama-model", "backup-db", "back"], default="back",
                        console=console)
    if choice == "ollama-url":
        url = ask("Ollama URL", ai.endpoint())
        if url:
            db.set_setting("ollama_url", url); console.print("[tp.ok]✓ Saved.[/tp.ok]")
    elif choice == "ollama-model":
        if models:
            m = Prompt.ask("Model", choices=models, console=console)
            db.set_setting("ollama_model", m); console.print("[tp.ok]✓ Saved.[/tp.ok]")
        else:
            console.print("[tp.warn]No models available.[/tp.warn]")
    elif choice == "backup-db":
        console.print(f"[tp.ok]✓ Backup: {db.backup()}[/tp.ok]")


def ai_status_panel():
    ok, models, err = ai.status()
    if ok:
        body = (f"Endpoint: {ai.endpoint()}\nStatus: online\n"
                f"Models: {', '.join(models) or '(none installed)'}\nSelected: {ai.selected_model(models) or '(none)'}\n\n"
                "Open any investigation and choose 'ai' to summarise evidence, explain relationships, or find "
                "contradictions. The model only sees stored findings and is instructed to add nothing.")
        console.print(Panel(body, title="[tp.head]AI ANALYST[/tp.head]", border_style="tp.accent"))
    else:
        console.print(Panel(f"Endpoint: {ai.endpoint()}\nStatus: offline ({err})\n\n"
                            "Install Ollama from https://ollama.com and run e.g. `ollama pull qwen2.5-coder:7b`. "
                            "TRACEPOINT is fully functional without it.",
                            title="[tp.warn]AI OFFLINE[/tp.warn]", border_style="tp.warn"))


# ------------------------------------------------------------ court records / registry workflows
RECORDS_NOTICE = {
    "court": ("Official court sources only. TRACEPOINT searches a source automatically only where its own documentation "
              "allows it; otherwise it shows the official portal and you search there. A name match is NOT proof of "
              "identity: you review each record and choose what to attach."),
    "registry": ("Official registries only (NSOPW and state registries). Their terms prohibit automated searching, so "
                 "you search the official portal yourself and record what you reviewed. A listing is not proof of "
                 "identity or of current whereabouts. Use is limited to public-safety awareness; threatening, "
                 "harassing or intimidating anyone is prohibited and may be prosecuted. TRACEPOINT stores no addresses."),
}


def _source_table(sources) -> Table:
    t = Table(box=None, expand=True)
    t.add_column("#", style="tp.key", width=3); t.add_column("Source", style="tp.val")
    t.add_column("Search", width=10); t.add_column("Agency / authentication", style="tp.dim")
    for i, s in enumerate(sources, 1):
        t.add_row(str(i), s.name, Text("AUTOMATED" if s.automated else "MANUAL",
                                         style="tp.ok" if s.automated else "tp.warn"), f"{s.agency}\n{s.auth}")
    return t


def _show_source_details(s):
    body = (f"Agency: {s.agency}\nJurisdiction: {s.level}/{s.jurisdiction}\nOfficial URL: {s.official_url}\n"
            f"Search method: {s.method.upper()}\nSupported fields: {', '.join(s.search_fields)}\n"
            f"Not supported: {', '.join(s.unsupported_fields)}\nAuthentication: {s.auth}\n"
            f"Coverage ({'complete' if s.complete else 'PARTIAL'}): {s.coverage}\nLimitations: {s.limitations}\n"
            f"Verification: {s.verified_note}")
    console.print(Panel(body, title=f"[tp.accent]{escape(s.name)}[/tp.accent]", border_style="tp.rule"))


def _choose_candidates(records, noun: str, names: dict | None = None) -> list:
    if not records:
        return []
    t = Table(box=None, expand=True)
    t.add_column("#", style="tp.key", width=3); t.add_column("Record", style="tp.val")
    t.add_column("Provider / court / agency", style="tp.dim"); t.add_column("Date", width=11); t.add_column("Status", width=10)
    for i, r in enumerate(records, 1):
        provider = (names or {}).get(r.source_id, "")
        t.add_row(str(i), Text(getattr(r, "title", "") or getattr(r, "displayed_name", "")),
                  Text((provider + " - " if provider else "") + (getattr(r, "court", "") or getattr(r, "agency", ""))),
                  Text(getattr(r, "published_date", "") or getattr(r, "registration_date", "")), Text(r.status))
        if r.source_url:
            t.add_row("", Text(r.source_url, style="tp.dim"), "", "", "")
    console.print(t)
    console.print(f"[tp.warn]These are UNVERIFIED name matches. Open each {noun} at the official source and review it "
                  "before attaching.[/tp.warn]")
    while True:
        sel = ask(f"Numbers of the {noun}s to attach (comma-separated; blank = attach none)")
        if not sel:
            return []
        parts = [x.strip() for x in sel.split(",") if x.strip()]
        if all(p.isdigit() and 1 <= int(p) <= len(records) for p in parts):
            chosen = [records[int(p) - 1] for p in dict.fromkeys(parts)]
            break
        console.print("[tp.warn]Enter valid numbers from the list.[/tp.warn]")
    return [r for r in chosen if Confirm.ask(
        f"[tp.warn]I reviewed '{escape((getattr(r, 'title', '') or getattr(r, 'displayed_name', ''))[:60])}' at the official "
        f"source and choose to attach it[/tp.warn]", console=console, default=False)]


def _enter_manual_records(source, prompts: list[tuple[str, str, str]], validator) -> list[dict]:
    out: list[dict] = []
    while Confirm.ask(f"[tp.accent]Enter a record you reviewed on {source.name}?[/tp.accent]", console=console,
                      default=False):
        fields = {"source_id": source.id}
        for key, label, hint in prompts:
            fields[key] = ask(label, hint)
        rec, errs = validator(fields)
        if errs:
            for e in errs:
                console.print(f"[tp.warn]{e}[/tp.warn]")
            continue
        console.print(f"[tp.ok]✓ Recorded for review: {escape(rec.identifier())}  (normalized status: {rec.status})[/tp.ok]")
        out.append(fields)
    return out


def _open_official(source):
    console.print(f"Official search page: [tp.accent]{source.search_url}[/tp.accent]")
    if Confirm.ask("Open it in your browser?", console=console, default=False):
        import webbrowser
        webbrowser.open(source.search_url)


COURT_PROMPTS = [("title", "Case title as shown", ""), ("case_number", "Case number", "24CR000123-456"),
                 ("court", "Court", ""),
                 ("record_type", "Record type (CRIMINAL / CIVIL / PUBLISHED OPINION / UNKNOWN)", "UNKNOWN"),
                 ("original_status", "Status/disposition exactly as the court words it", ""),
                 ("charges", "Charges exactly as published (optional)", ""),
                 ("filing_date", "Filing date (optional)", "2024-03-15"), ("disposition_date", "Disposition date (optional)", ""),
                 ("source_url", "Official URL of the record", "https://")]
REGISTRY_PROMPTS = [("displayed_name", "Name exactly as the registry displays it", ""),
                    ("registry_id", "Registry identification number", ""),
                    ("original_status", "Registration status exactly as displayed", ""),
                    ("offense_classification", "Offense classification exactly as published", ""),
                    ("registration_date", "Registration date (optional)", "2024-03-15"),
                    ("source_updated", "Registry update date (optional)", ""),
                    ("source_url", "Official URL of the listing", "https://")]


def _choose_jurisdiction(kind: str):
    """Step 1. Returns a providers.jurisdictions.Jurisdiction, or None for Back."""
    from providers.jurisdictions import FEDERAL_ONLY, US_NATIONWIDE, resolve
    third = "Federal Courts" if kind == "court" else "National Registry (NSOPW)"
    while True:
        body = Text(f"\n  1. United States (Nationwide)\n  2. Select a State\n  3. {third}\n  0. Back\n")
        console.print(Panel(body, title="[tp.head]JURISDICTION SELECTION[/tp.head]", border_style="tp.accent", width=54))
        sel = ask("Select jurisdiction")
        if sel in ("0", ""):
            return None
        if sel == "1":
            return US_NATIONWIDE
        if sel == "3":
            return FEDERAL_ONLY
        if sel != "2":
            console.print("[tp.warn]Enter 1, 2, 3 or 0.[/tp.warn]")
            continue
        while True:
            console.print("Enter state name or abbreviation:\n[tp.dim]Examples: NC, SC, NY, CA, TX  (blank = back)[/tp.dim]")
            text = ask("State")
            if not text:
                break
            jur, err = resolve(text)
            if err:
                console.print(f"[tp.warn]{escape(err)}[/tp.warn]")
                continue
            return jur


def _availability(kind: str, mod, jur):
    """Step 3. Show what can and cannot be searched in the chosen jurisdiction, automated and manual apart."""
    pl = mod.plan(jur)
    title = "COURT RECORDS" if kind == "court" else "SEX OFFENDER REGISTRY"
    where = ("UNITED STATES (NATIONWIDE REQUEST)" if jur.scope == "nationwide" else
             "FEDERAL" if jur.scope == "federal" else jur.name.upper())
    console.print(f"\n[tp.head]{title} - {escape(where)}[/tp.head]")
    console.print("Available official sources:")
    if pl.automated:
        console.print("[tp.ok]AUTOMATED[/tp.ok] (TRACEPOINT runs the documented search):")
        console.print(_source_table(pl.automated))
    if pl.manual:
        console.print("[tp.warn]MANUAL[/tp.warn] (you search the official site; TRACEPOINT cannot do it automatically):")
        console.print(_source_table(pl.manual))
    if not pl.sources:
        console.print("[tp.warn]No official source is catalogued for this jurisdiction. Nothing can be searched or "
                      "linked here (NOT IMPLEMENTED).[/tp.warn]")
    if jur.scope == "state":
        console.print("County resources: " + ("[tp.dim]none catalogued[/tp.dim]" if not any(
            s.level == "county" for s in pl.sources) else "listed above"))
        if kind == "court":
            console.print("[tp.dim]Federal court records are a separate jurisdiction; choose 'Federal Courts' or "
                          "'United States' to include them.[/tp.dim]")
    if pl.not_implemented and jur.scope == "nationwide":
        console.print(f"[tp.dim]No state source is implemented for {len(pl.not_implemented)} of 51 states/DC "
                      "(they will be reported as NOT IMPLEMENTED, not silently skipped).[/tp.dim]")
    console.print(f"Search scope: [tp.val]{escape(jur.label())}[/tp.val]")
    return pl


def _print_coverage(report):
    from providers.coverage import COMPLETE
    style = "tp.ok" if report.status == COMPLETE else "tp.warn"
    body = "\n".join(escape(ln) for ln in report.lines()[1:])      # line 0 is the panel title
    console.print(Panel(body, title=f"[{style}]{escape(report.headline())}[/{style}]", border_style=style))


def _manual_stage(kind, mod, outcomes) -> list[dict]:
    """MANUAL providers: show the official site and let the operator enter what they reviewed there."""
    court = kind == "court"
    manual = [o.source for o in outcomes if o.status == "manual"]
    if not manual:
        return []
    t = Table(box=None, expand=True)
    t.add_column("#", style="tp.key", width=3); t.add_column("Manual source / official site", style="tp.val")
    t.add_column("Access and fees", style="tp.dim")
    for i, s in enumerate(manual, 1):
        t.add_row(str(i), Text(f"{s.name}\n{s.search_url}"), Text(s.auth))
    console.print(Panel(t, title="[tp.warn]MANUAL SEARCH REQUIRED[/tp.warn]", border_style="tp.warn"))
    console.print("[tp.warn]TRACEPOINT did NOT search these sources and cannot do so automatically. Nothing above "
                  "implies a search was performed.[/tp.warn]")
    records: list[dict] = []
    while True:
        sel = ask("Source number to enter a record you reviewed there (blank = done)")
        if not sel:
            return records
        if not (sel.isdigit() and 1 <= int(sel) <= len(manual)):
            console.print("[tp.warn]Invalid selection.[/tp.warn]")
            continue
        source = manual[int(sel) - 1]
        _show_source_details(source)
        _open_official(source)
        if not court:
            console.print("[tp.dim]Do not enter addresses or other location details; TRACEPOINT does not store them.[/tp.dim]")
        records += _enter_manual_records(source, COURT_PROMPTS if court else REGISTRY_PROMPTS, mod.manual_record)


def _records_flow(kind: str):
    from modules import court_records_intel as court_mod, registry_intel as reg_mod
    court = kind == "court"
    mod = court_mod if court else reg_mod
    console.print(Panel(RECORDS_NOTICE[kind], title=f"[tp.warn]{SPECS[kind].label.upper()}[/tp.warn]", border_style="tp.warn"))
    while True:
        jur = _choose_jurisdiction(kind)
        if jur is None:
            return
        _availability(kind, mod, jur)
        methods = list(mod.QUERY_KINDS)
        second = "case number" if court else "registry identification number"
        console.print(Panel(Text(f"\n  1. Search by person name\n  2. Search by {second}\n  0. Back\n"),
                            title="[tp.head]SEARCH METHOD[/tp.head]", border_style="tp.accent", width=54))
        sel = ask("Search method")
        if sel not in ("1", "2"):
            if sel not in ("0", ""):
                console.print("[tp.warn]Enter 1, 2 or 0.[/tp.warn]")
            continue
        qkind = methods[int(sel) - 1]
        term = ask("Full name" if qkind == "name" else "Case number" if court else "Registry identification number")
        if not term:
            return
        term, err = mod.validate_query(term, qkind)
        if err:
            console.print(f"[tp.warn]{escape(err)}[/tp.warn]")
            return
        if not authorize(kind):
            console.print("[tp.dim]Cancelled — authorization not given.[/tp.dim]")
            return
        break
    with console.status("[tp.accent]Searching the available official sources…[/tp.accent]", spinner="dots"):
        outcomes, report = mod.search(term, qkind, jur)
    _print_coverage(report)
    names = {o.source.id: o.source.name for o in outcomes}
    candidates = []
    for o in outcomes:
        if o.status in ("ok", "error", "not_configured", "skipped"):
            console.print(f"[tp.accent]{escape(o.source.name)}[/tp.accent]: {o.status.upper()} — {escape(o.detail)}")
        candidates += o.records
    records = _choose_candidates(candidates, "record" if court else "listing", names)
    manual = _manual_stage(kind, mod, outcomes)
    if not records and not manual:
        if not Confirm.ask("Nothing was attached. Save this search and its coverage report to history anyway?",
                           console=console, default=True):
            return
    run_and_show(kind, term, already_authorized=True, search_kind=qkind, outcomes=outcomes, coverage=report,
                 jurisdiction=jur, selected=records, manual_records=manual)


def court_records_flow():
    _records_flow("court")


def registry_flow():
    _records_flow("registry")


DISPATCH = {
    "universal": universal_search, "graph": relationship_explorer, "history": history,
    "reports": reports_menu, "intel": intel_reports_menu, "api": api_config, "integrations": integrations_dashboard, "settings": settings, "ai": ai_status_panel,
}
RECORD_FLOWS = {"court": court_records_flow, "registry": registry_flow}
EXAMPLES = {"email": "you@example.com", "phone": "+1 415 555 2671", "username": "your_handle",
            "domain": "example.com", "ip": "8.8.8.8", "social": "https://github.com/you",
            "security": "suspicious-domain.xyz"}


def _run_choice(choice: str):
    module = next((k for n, k, _ in MENU if n == choice), None)
    if module in RECORD_FLOWS:
        return RECORD_FLOWS[module]()
    if module:
        console.print(Rule(f"[tp.head]{SPECS[module].label}[/tp.head]  [tp.dim]{SPECS[module].description}[/tp.dim]",
                           style="tp.rule"))
        prompt = "Full name" if module == "name" else "Phone number" if module == "phone" else "Target"
        target = ask(prompt, EXAMPLES.get(module, ""))
        if module == "name" and target:
            _run_name_query(target)
        else:
            run_and_show(module, target)
    else:
        action = next(k for n, k, _ in ACTIONS if n == choice)
        DISPATCH[action]()


def main():
    valid = {n for n, *_ in MENU} | {n for n, *_ in ACTIONS}
    while True:
        header()
        main_menu()
        choice = Prompt.ask("\n[tp.accent]select[/tp.accent]", console=console).strip()
        if choice not in valid:
            console.print("[tp.warn]Unknown option.[/tp.warn]"); console.input("[tp.dim]Enter…[/tp.dim]"); continue
        if choice == "0":
            console.print("[tp.dim]Goodbye.[/tp.dim]"); break
        try:
            _run_choice(choice)
        except (KeyboardInterrupt, EOFError):
            raise
        except Exception as e:  # a failing screen (e.g. report write error) must not end the session
            console.print(Panel(f"{type(e).__name__}: {e}", title="[tp.err]ERROR[/tp.err]", border_style="tp.err"))
        console.input("\n[tp.dim]Press Enter to return to the menu…[/tp.dim]")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[tp.dim]Interrupted. Goodbye.[/tp.dim]")
    finally:
        try:
            get_db().close()
        except Exception:
            pass
