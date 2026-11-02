#!/usr/bin/env python3
"""TRACEPOINT — interactive Rich terminal application."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from core import ai, correlation, investigation, reports
from core.configuration import API_INTEGRATIONS, APP_NAME, REPORTS_DIR, VERSION
from core.database import get_db
from core.investigation import SPECS
from core.models import ModuleResult
from core.security import clean_input, encryption_mode, mask
from ui import render
from ui.theme import BANNER, THEME

console = Console(theme=THEME, highlight=False)
db = get_db()

MENU = [
    ("1", "email", "Email Intelligence"), ("2", "phone", "Phone Intelligence"),
    ("3", "username", "Username Intelligence"), ("4", "domain", "Domain Intelligence"),
    ("5", "ip", "IP Intelligence"), ("6", "social", "Social Intelligence"),
    ("7", "security", "Security Intelligence"), ("8", "name", "Name Intelligence"),
]
ACTIONS = [
    ("9", "universal", "Universal Search  [tp.dim](auto-detect identifier)[/tp.dim]"),
    ("10", "graph", "Relationship Explorer"), ("11", "history", "Investigation History"),
    ("12", "reports", "Reports"), ("13", "api", "API Configuration"),
    ("14", "settings", "Settings"), ("15", "ai", "AI Analyst Status"), ("0", "exit", "Exit"),
]


# ------------------------------------------------------------------ helpers
def header():
    console.clear()
    console.print(BANNER)
    ok, models, _ = ai.status()
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
    if not authorize(inv_type):
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
    if result.notes:
        console.print(Panel("\n".join(f"• {n}" for n in result.notes), title="[tp.dim]NOTES[/tp.dim]",
                            border_style="tp.rule"))
    console.print(f"[tp.ok]✓ Saved as investigation {db.get_investigation(inv_id)['ref']} (id {inv_id}).[/tp.ok]")
    post_investigation(inv_id)


def post_investigation(inv_id: int):
    while True:
        choice = Prompt.ask("\n[tp.accent]Action[/tp.accent]", choices=["report", "ai", "graph", "back"],
                            default="back", console=console)
        if choice == "report":
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
    fmt = Prompt.ask("Format", choices=["txt", "json", "html", "all"], default="html", console=console)
    fmts = ["txt", "json", "html"] if fmt == "all" else [fmt]
    for f in fmts:
        p = reports.save(inv_id, f)
        console.print(f"[tp.ok]✓ {p}[/tp.ok]")


def do_ai(inv_id: int):
    ok, models, err = ai.status()
    if not ok:
        console.print(Panel(f"Ollama not reachable ({err}).\nStart Ollama, or set its URL in Settings. "
                            "TRACEPOINT works fully without AI.", title="[tp.warn]AI UNAVAILABLE[/tp.warn]",
                            border_style="tp.warn"))
        return
    task = Prompt.ask("Analysis", choices=["summary", "relationships", "contradictions"], default="summary",
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
    inv = db.get_investigation(inv_id)
    console.print(Panel(f"[tp.accent]{inv['ref']}[/tp.accent]  type [tp.val]{inv['inv_type']}[/tp.val]  "
                        f"target [tp.val]{inv['target']}[/tp.val]\n[tp.dim]{inv['created_at']}  ·  {inv['status']}"
                        f"{'  ·  '+inv['notes'].strip() if inv['notes'].strip() else ''}[/tp.dim]",
                        border_style="tp.rule"))
    fs = db.findings(inv_id)
    cat = None
    for f in fs:
        if f["category"] != cat:
            cat = f["category"]; console.print(f"\n[tp.head]{cat.upper()}[/tp.head]")
        console.print(f"  {render.confidence_text(f['confidence'])}  [tp.val]{f['title']}[/tp.val] "
                      + (f"[tp.key]{f['value']}[/tp.key]" if f['value'] and f['value'] not in f['title'] else ""))
        if f["source_url"]:
            console.print(f"      [tp.accent2 underline]{f['source_url']}[/tp.accent2 underline]")
    if inv["ai_summary"]:
        console.print(Panel(inv["ai_summary"], title="[tp.head]AI ANALYSIS[/tp.head]", border_style="tp.rule"))
    action = Prompt.ask("\n[tp.accent]Action[/tp.accent]", choices=["report", "ai", "graph", "delete", "back"],
                        default="back", console=console)
    if action == "report":
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
        t.add_column("Format", width=6); t.add_column("Path", style="tp.dim")
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
            t.add_row(str(i), label, cat, status, mask(db.get_secret(k)) if k in names else "")
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


DISPATCH = {
    "universal": universal_search, "graph": relationship_explorer, "history": history,
    "reports": reports_menu, "api": api_config, "settings": settings, "ai": ai_status_panel,
}
EXAMPLES = {"email": "you@example.com", "phone": "+1 415 555 2671", "username": "your_handle",
            "domain": "example.com", "ip": "8.8.8.8", "social": "https://github.com/you",
            "security": "suspicious-domain.xyz"}


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
        module = next((k for n, k, _ in MENU if n == choice), None)
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
