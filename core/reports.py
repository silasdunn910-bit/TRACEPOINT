"""Report generation: TXT, JSON, HTML (self-contained, no external assets)."""
from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from core import correlation
from core.configuration import APP_NAME, REPORTS_DIR, VERSION
from core.database import get_db
from providers.coverage import parse_marker
from core.models import CONFIDENCE_LEVELS, CONFIDENCE_MEANING, normalize_confidence, now_iso

STANDING_LIMITS = [
    "Findings reflect public sources at collection time and may since have changed.",
    "Confidence classifications are qualitative evidence grades, not statistical probabilities.",
    "Matching usernames, names, or metadata do not by themselves establish that accounts or people are the same.",
    "IP and phone-number geography describe networks and numbering plans, not where a person lives or is located.",
    "Search-engine results show only that a page was indexed for a query; each must be reviewed manually.",
    "TRACEPOINT is intended for auditing identifiers the operator owns or is authorized to investigate.",
]


def _records_review(inv_type: str, findings: list[dict], sources: list[dict], contra: list[str],
                    coverage=None) -> dict | None:
    """Court / registry investigations: separate what the official sources said from what is unverified,
    reviewed, missing, inaccessible, conflicting or only partially covered."""
    if inv_type not in ("court", "registry"):
        return None
    from modules.records_shared import COURT_CATEGORIES, NOT_PROVIDED, REGISTRY_CATEGORIES
    cats = COURT_CATEGORIES if inv_type == "court" else REGISTRY_CATEGORIES
    recs = [f for f in findings if f["category"] in cats]
    manual = [f for f in recs if f["category"].endswith("_manual")]
    missing = []
    for f in recs:
        gaps = [ln.split(":", 1)[0] for ln in (f["evidence"] or "").splitlines() if ln.endswith(NOT_PROVIDED)]
        if gaps:
            missing.append(f"{f['title']}: {', '.join(gaps)}")
    kind = "court records" if inv_type == "court" else "registry listings"
    if coverage is not None:
        scope_note = (f"Requested: {coverage.requested} ({coverage.scope}). Resolved: {coverage.resolved}. "
                      f"Actual coverage: {coverage.status}."
                      + (" This was a NATIONWIDE REQUEST, not nationwide coverage: only the providers marked SEARCHED "
                         "were searched." if coverage.scope == "nationwide" and not coverage.complete_nationwide else ""))
        cov_block = {"requested": coverage.requested, "scope": coverage.scope, "resolved": coverage.resolved,
                     "search_method": coverage.search_method, "status": coverage.status, "summary": scope_note,
                     "counts": coverage.counts(), "lines": coverage.lines(),
                     "providers": [{k: v for k, v in e.__dict__.items()} for e in coverage.entries]}
    else:
        cov_block = {"status": "NOT RECORDED", "summary": "This investigation predates jurisdiction and coverage recording; "
                     "the scope of the search was not stored.", "lines": [], "providers": []}
    return {
        "search_coverage": cov_block,
        "official_source_information": [f"{f['source']}: {f['value']} <{f['source_url'] or 'no URL recorded'}>" for f in recs],
        "unverified_name_matches": f"{sum(1 for f in recs if f['confidence'] == 'UNVERIFIED')} of {len(recs)} {kind} "
                                   "are UNVERIFIED name/identifier matches; none is a confirmed record of the person searched.",
        "manually_reviewed_records": f"{len(recs)} record(s) attached by the operator after manual review "
                                    f"({len(manual)} entered from the official portal, {len(recs) - len(manual)} returned by a source search).",
        "missing_information": missing or ["None of the attached records had empty fields."] if recs else ["No records attached."],
        "inaccessible_sources": [f"{s['name']} [{s['status']}]" for s in sources
                                 if s["status"] in ("error", "not_configured", "skipped", "blocked")],
        "conflicting_records": contra or [],
        "partial_coverage": [s["name"] for s in sources],
        "statement": ("Absence of a record in the sources searched does not establish absence elsewhere. "
                      + ("A registry listing is not proof of current whereabouts." if inv_type == "registry"
                         else "An arrest or charge is not a conviction; a dismissal is not an acquittal.")),
    }


def build(inv_id: int) -> dict:
    db = get_db()
    inv = db.get_investigation(inv_id)
    if not inv:
        raise ValueError("Investigation not found")
    findings = [dict(f) for f in db.findings(inv_id)]
    for f in findings:  # present legacy grades (STRONG) under the current taxonomy; stored data is untouched
        f["confidence"] = normalize_confidence(f["confidence"])
    sources = [dict(s) for s in db.sources(inv_id)]
    coverage, public_notes = parse_marker(inv["notes"])
    ents = [dict(e) for e in db.entities_for(inv_id)]
    rels = [dict(r) for r in db.relationships_for(inv_id)]
    counts = Counter(normalize_confidence(f["confidence"]) for f in findings)
    contra = correlation.contradictions(inv_id)
    errors = [s for s in sources if s["status"] == "error"]
    blocked = [s for s in sources if s["status"] == "blocked"]
    not_cfg = [s for s in sources if s["status"] == "not_configured"]
    ok_sources = {s["name"] for s in sources if s["status"] == "ok"}
    if findings:
        conclusion = (f"{len(findings)} findings recorded from {len(ok_sources)} responding sources ("
                      + ", ".join(f"{counts.get(c, 0)} {c}" for c in CONFIDENCE_LEVELS) + "). ")
    else:
        conclusion = "No evidence was found. "
    if contra:
        conclusion += f"{len(contra)} contradiction(s) need review. "
    if errors:
        conclusion += f"{len(errors)} source(s) failed; coverage is incomplete. "
    if blocked:
        conclusion += f"{len(blocked)} source(s) blocked automated checks; results there are inconclusive. "
    conclusion += "No identity attribution is made by this report."
    return {
        "report_generated": now_iso(), "generator": f"{APP_NAME} {VERSION}",
        "investigation": {"id": inv["ref"], "type": inv["inv_type"], "target": inv["target"],
                          "timestamp": inv["created_at"], "status": inv["status"], "notes": public_notes},
        "sources_consulted": sources, "findings": findings, "confidence_counts": dict(counts),
        "confidence_definitions": CONFIDENCE_MEANING, "related_entities": ents, "relationships": rels,
        "geographic_evidence": [f for f in findings if f["category"] == "geo"], "contradictions": contra,
        "limitations": STANDING_LIMITS + [f"Source failed: {s['name']} — {s['detail']}" for s in errors]
        + [f"Source blocked automated checks: {s['name']} — {s['detail']}" for s in blocked]
                       + [f"Not configured: {s['name']}" for s in not_cfg],
        "conclusion": conclusion, "ai_analysis": inv["ai_summary"] or "",
        "records_review": _records_review(inv["inv_type"], findings, sources, contra, coverage),
    }


def to_txt(r: dict) -> str:
    inv = r["investigation"]
    out = ["=" * 78, f" {APP_NAME} INTELLIGENCE REPORT  |  {inv['id']}", "=" * 78,
           f"Type: {inv['type']}    Target: {inv['target']}",
           f"Investigated: {inv['timestamp']}    Report: {r['report_generated']}",
           "", "CONCLUSION", "-" * 78, r["conclusion"], ""]
    if r["ai_analysis"]:
        out += ["AI ANALYSIS (local model, unverified)", "-" * 78, r["ai_analysis"], ""]
    rr = r.get("records_review")
    if rr:
        out += ["RECORDS REVIEW (official sources vs. unverified matches)", "-" * 78,
                "SEARCH SCOPE AND COVERAGE", rr["search_coverage"]["summary"]]
        out += [f"  {ln}" for ln in rr["search_coverage"]["lines"]] + [""]
        out += [rr["unverified_name_matches"], rr["manually_reviewed_records"], "",
                "Official source information:"] + [f"  - {x}" for x in rr["official_source_information"] or ["none attached"]]
        out += ["Missing information:"] + [f"  - {x}" for x in rr["missing_information"]]
        out += ["Inaccessible or manual-only sources:"] + [f"  - {x}" for x in rr["inaccessible_sources"] or ["none"]]
        out += ["Conflicting records:"] + [f"  - {x}" for x in rr["conflicting_records"] or ["none detected"]]
        out += ["Partial coverage (every source searched is partial): " + "; ".join(rr["partial_coverage"] or ["none"]),
                rr["statement"], ""]
    out += ["FINDINGS", "-" * 78]
    cat = None
    for i, f in enumerate(r["findings"], 1):
        if f["category"] != cat:
            cat = f["category"]
            out += ["", f"[{cat.upper()}]"]
        out += [f"{i:>3}. [{f['confidence']}] {f['title']}", f"     {f['description']}"]
        if f["value"] and f["value"] not in f["description"]:
            out.append(f"     Value: {f['value']}")
        out.append(f"     Source: {f['source']}" + (f"  <{f['source_url']}>" if f["source_url"] else ""))
        if "published_at" in f or "query" in f or "source_type" in f:
            out.append(f"     Published: {f.get('published_at') or 'unknown / not provided by source'}")
            if f.get("query"):
                out.append(f"     Search query: {f['query']}")
        if f["evidence"]:
            out.append("     Evidence: " + f["evidence"].replace("\n", "\n               "))
        if f["limitations"]:
            out.append(f"     Limitations: {f['limitations']}")
    out += ["", "CONTRADICTIONS", "-" * 78] + ([f"- {c}" for c in r["contradictions"]] or ["None detected."])
    out += ["", "RELATED PUBLIC ENTITIES", "-" * 78]
    out += [f"- {e['entity_type']}: {e['value']} ({e['verification']})" for e in r["related_entities"]] or ["None."]
    out += ["", "RELATIONSHIPS", "-" * 78]
    out += [f"- {x['src_value']} --[{x['rel_type']} | {x['confidence']}]--> {x['dst_value']}"
            for x in r["relationships"]] or ["None."]
    out += ["", "SOURCES CONSULTED", "-" * 78]
    out += [f"- {s['name']} [{s['status']}] {s['url']} {s['detail']}".rstrip() for s in r["sources_consulted"]]
    out += ["", "LIMITATIONS", "-" * 78] + [f"- {x}" for x in r["limitations"]]
    out += ["", "CONFIDENCE DEFINITIONS", "-" * 78] + [f"- {k}: {v}" for k, v in r["confidence_definitions"].items()]
    return "\n".join(out) + "\n"


def to_json(r: dict) -> str:
    return json.dumps(r, indent=2, default=str)


def safe_href(url: str) -> str:
    """Only allow absolute http(s) links in report HTML. Data comes from third-party
    sources, so a javascript:/data:/file: URL must never become a clickable link."""
    try:
        p = urlparse(url)
    except (TypeError, ValueError):
        return ""
    return url if p.scheme in ("http", "https") and p.netloc else ""


def to_html(r: dict) -> str:
    esc = html.escape
    inv = r["investigation"]
    color = {"VERIFIED": "#22d3ee", "CORROBORATED": "#60a5fa", "STRONG": "#60a5fa", "MODERATE": "#a78bfa", "LOW": "#fbbf24", "UNVERIFIED": "#94a3b8", "INCONCLUSIVE": "#f97316"}

    def anchor(u):
        href = safe_href(u)
        if not href:
            return esc(u[:80]) if u else ""
        return f'<a href="{esc(href)}" target="_blank" rel="noopener noreferrer">{esc(u[:80])}</a>'

    frows = []
    for i, f in enumerate(r["findings"], 1):
        c = color.get(f["confidence"], "#94a3b8")
        frows.append(
            f'<tr><td class="num">{i}</td>'
            f'<td><span class="badge" style="background:{c}1a;color:{c};border-color:{c}55">{f["confidence"]}</span></td>'
            f'<td><div class="cat">{esc(f["category"])}</div><div class="ttl">{esc(f["title"])}</div>'
            f'<div class="desc">{esc(f["description"])}</div>'
            + (f'<div class="muted">Published: {esc(f.get("published_at") or "unknown / not provided by source")}</div>'
               if "published_at" in f or "query" in f or "source_type" in f else "")
            + (f'<div class="muted">Search query: {esc(f["query"])}</div>' if f.get("query") else "")
            + (f'<div class="ev">{esc(f["evidence"])}</div>' if f["evidence"] else "")
            + (f'<div class="lim">⚠ {esc(f["limitations"])}</div>' if f["limitations"] else "")
            + '</td>'
            f'<td class="src">{esc(f["source"])}<br>{anchor(f["source_url"])}</td></tr>')
    counts = r["confidence_counts"]
    chips = "".join(f'<span class="chip" style="color:{color[c]}">{counts.get(c, 0)} {c}</span>' for c in CONFIDENCE_LEVELS)
    ents = "".join(f'<li><b>{esc(e["entity_type"])}</b>: {esc(e["value"])} '
                   f'<span class="muted">({esc(e["verification"])})</span></li>' for e in r["related_entities"]) or "<li>None.</li>"
    rels = "".join(f'<li>{esc(x["src_value"])} <span class="muted">—[{esc(x["rel_type"])} · {esc(x["confidence"])}]→</span> '
                   f'{esc(x["dst_value"])}</li>' for x in r["relationships"]) or "<li>None.</li>"
    srcs = "".join(f'<li class="st-{s["status"]}">{esc(s["name"])} <span class="muted">[{esc(s["status"])}]</span> '
                   f'{anchor(s["url"])} {esc(s["detail"])}</li>' for s in r["sources_consulted"])
    contra = "".join(f"<li>{esc(c)}</li>" for c in r["contradictions"]) or "<li>None detected.</li>"
    lims = "".join(f"<li>{esc(x)}</li>" for x in r["limitations"])
    rr = r.get("records_review")
    rr_html = ""
    if rr:
        def ul(items):
            return "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in items) + "</ul>"
        sc = rr["search_coverage"]
        rr_html = ("<section><h2>Records review</h2><div class=\"concl\">"
                   f"<b>Search scope and coverage: {esc(sc['status'])}</b><p>{esc(sc['summary'])}</p>"
                   + ul(sc["lines"]) +
                   f"<p>{esc(rr['unverified_name_matches'])}</p><p>{esc(rr['manually_reviewed_records'])}</p>"
                   "<b>Official source information</b>" + ul(rr["official_source_information"] or ["none attached"]) +
                   "<b>Missing information</b>" + ul(rr["missing_information"]) +
                   "<b>Inaccessible or manual-only sources</b>" + ul(rr["inaccessible_sources"] or ["none"]) +
                   "<b>Conflicting records</b>" + ul(rr["conflicting_records"] or ["none detected"]) +
                   "<b>Partial coverage</b>" + ul(rr["partial_coverage"] or ["none"]) +
                   f"<p class=\"muted\">{esc(rr['statement'])}</p></div></section>")
    ai = f'<section><h2>AI analysis <span class="muted">(local model · unverified)</span></h2><pre class="ai">{esc(r["ai_analysis"])}</pre></section>' if r["ai_analysis"] else ""
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(APP_NAME)} report {esc(inv['id'])}</title><style>
:root{{color-scheme:dark}}
*{{box-sizing:border-box}}
body{{margin:0;background:#0b0f14;color:#dbe4ee;font:14px/1.5 ui-sans-serif,system-ui,Segoe UI,Roboto,sans-serif}}
.wrap{{max-width:1100px;margin:0 auto;padding:28px}}
header{{border-bottom:1px solid #1e2a38;padding-bottom:18px;margin-bottom:22px}}
h1{{margin:0 0 4px;font-size:22px;letter-spacing:.14em;color:#22d3ee}}
h2{{font-size:15px;text-transform:uppercase;letter-spacing:.1em;color:#7dd3fc;border-left:3px solid #22d3ee;padding-left:10px;margin:28px 0 12px}}
.meta{{color:#8ba0b6;font-size:13px}}
.chips,.chip{{display:inline-block}} .chip{{margin-right:12px;font-weight:600;font-size:12px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
td{{border-top:1px solid #16212e;padding:10px 8px;vertical-align:top}}
.num{{color:#5b6b7d;width:28px}} .src{{color:#8ba0b6;width:210px;font-size:12px;word-break:break-all}}
.badge{{border:1px solid;border-radius:5px;padding:2px 7px;font-size:11px;font-weight:700;white-space:nowrap}}
.cat{{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#5b6b7d}}
.ttl{{font-weight:600;color:#eaf2fb}} .desc{{color:#c3d0de;margin-top:2px}}
.ev{{white-space:pre-wrap;background:#0f1721;border:1px solid #16212e;border-radius:6px;padding:7px;margin-top:6px;color:#9fb3c8;font:12px ui-monospace,monospace}}
.lim{{color:#d6a94a;margin-top:6px;font-size:12px}}
.muted{{color:#5b6b7d}} ul{{margin:0;padding-left:18px}} li{{margin:3px 0}}
.st-error{{color:#f08a8a}} .st-blocked{{color:#fbbf24}} .st-not_configured{{color:#8ba0b6}}
pre.ai{{white-space:pre-wrap;background:#0f1721;border:1px solid #1e2a38;border-radius:8px;padding:14px;color:#cfe0f0}}
.concl{{background:#0f1721;border:1px solid #1e2a38;border-radius:8px;padding:14px;color:#eaf2fb}}
footer{{margin-top:30px;border-top:1px solid #1e2a38;padding-top:14px;color:#5b6b7d;font-size:12px}}
</style></head><body><div class="wrap">
<header><h1>{esc(APP_NAME)} · INTELLIGENCE REPORT</h1>
<div class="meta">{esc(inv['id'])} &nbsp;·&nbsp; type <b>{esc(inv['type'])}</b> &nbsp;·&nbsp; target <b>{esc(inv['target'])}</b><br>
investigated {esc(inv['timestamp'])} &nbsp;·&nbsp; report {esc(r['report_generated'])} &nbsp;·&nbsp; {esc(r['generator'])}</div></header>
<section><h2>Conclusion</h2><div class="concl">{esc(r['conclusion'])}</div>
<p class="chips" style="margin-top:12px">{chips}</p></section>
{ai}
{rr_html}
<section><h2>Findings ({len(r['findings'])})</h2><table><tbody>{''.join(frows) or '<tr><td>No findings.</td></tr>'}</tbody></table></section>
<section><h2>Contradictions</h2><ul>{contra}</ul></section>
<section><h2>Related public entities</h2><ul>{ents}</ul></section>
<section><h2>Relationships</h2><ul>{rels}</ul></section>
<section><h2>Sources consulted</h2><ul>{srcs}</ul></section>
<section><h2>Limitations</h2><ul>{lims}</ul></section>
<footer>Generated by {esc(r['generator'])}. Heuristic evidence grades, not legal proof or identity attribution.
For auditing identifiers the operator owns or is authorized to investigate.</footer>
</div></body></html>"""


def save(inv_id: int, fmt: str) -> Path:
    r = build(inv_id)
    ref = r["investigation"]["id"]
    fmt = fmt.lower()
    body = {"txt": to_txt, "json": to_json, "html": to_html}[fmt](r)
    path = REPORTS_DIR / f"{ref}.{fmt}"
    path.write_text(body, encoding="utf-8")
    get_db().add_report(inv_id, fmt, path.name)  # relative to REPORTS_DIR so the folder can move
    return path
