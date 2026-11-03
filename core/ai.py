"""Optional local AI analyst via Ollama. Never downloads models. Only sees stored evidence."""
from __future__ import annotations

import json
import re

from core import http
from core.configuration import OLLAMA_DEFAULT
from core.database import get_db
from core.http import HttpError

PREFERRED = ["qwen2.5-coder:14b", "qwen2.5-coder:7b", "deepseek-r1:8b"]

SYSTEM = """You are a careful OSINT analyst. You are given a JSON list of findings collected by software from public sources.
Rules you must follow:
- Use ONLY the supplied findings. Do not add facts, sources, names, places or links that are not in the input.
- Every claim you make must cite the finding number(s) in square brackets, e.g. [3].
- Separate your answer into sections: FACTS (directly supported), INFERENCES (reasoned, label confidence), UNKNOWNS, CONTRADICTIONS, CONCLUSION.
- Matching usernames, names or images are NOT proof that accounts or people are the same. Say so when relevant.
- IP or phone-number geography is network/numbering-plan data, not where a person lives or is. Never state a home address or live location.
- If evidence is missing, say "No evidence was found" for that point.
- Each finding carries a class (e.g. UNVERIFIED CLAIM, SINGLE-SOURCE CLAIM). Describe it with that strength; never
  present a lead or an allegation as fact, and never present speculation as fact (label it INFERENCE).
- Your own conclusions are analysis, not evidence. Never cite yourself or call your conclusion corroboration.
- Never invent sources, URLs, dates, names or findings. Only the URLs in the input exist.
- Be concise."""


def endpoint() -> str:
    return get_db().get_setting("ollama_url", OLLAMA_DEFAULT).rstrip("/")


def status() -> tuple[bool, list[str], str]:
    try:
        data = http.get_json(endpoint() + "/api/tags", timeout=3)
        models = data.get("models", []) if isinstance(data, dict) else None
        if not isinstance(models, list):
            return False, [], "Ollama returned an unexpected response (not an Ollama /api/tags reply)"
        return True, [m["name"] for m in models if isinstance(m, dict) and isinstance(m.get("name"), str)], ""
    except HttpError as e:
        return False, [], str(e)


def selected_model(models: list[str]) -> str:
    chosen = get_db().get_setting("ollama_model", "")
    if chosen in models:
        return chosen
    for p in PREFERRED:
        if p in models:
            return p
    return models[0] if models else ""


_URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"')\]]+", re.I)
_CITE_RE = re.compile(r"\[(\d+(?:\s*,\s*\d+)*)\]")
_SENT_RE = re.compile(r"(?<=[.!?])\s+")
_HEADER_RE = re.compile(r"^\W*(FACTS|INFERENCES|UNKNOWNS|CONTRADICTIONS|CONCLUSION)\b", re.I)
REMOVED_URL = "[URL removed: not in the collected evidence]"


def _norm_url(u: str) -> str:
    return u.strip().rstrip(".,;:").lower().removeprefix("https://").removeprefix("http://").removeprefix("www.").rstrip("/")


def build_payload(inv_id: int) -> list[dict]:
    """Evidence handed to the model: stored findings with the report engine's class, effective grade and conflicts
    (so the model sees which findings are only leads). Repeats from one origin are excluded. If the engine cannot
    run, the raw stored findings are used."""
    db = get_db()
    try:
        from core import intelligence
        rep = intelligence.generate(inv_id)
        live = [e for e in rep.evidence if not e.duplicate_of][:120]
        num = {e.ref: i + 1 for i, e in enumerate(live)}
        return [{"n": num[e.ref], "title": e.title, "description": e.description, "value": e.value,
                 "class": e.claim_class, "grade": e.grade or e.stored_grade, "source": e.source, "url": e.source_url,
                 "conflicts_with": [num[c] for c in e.conflicts_with if c in num], "limitations": e.limitations[:200]}
                for e in live]
    except Exception:  # noqa: BLE001 - fall back to the stored findings
        return [{"n": i + 1, "title": f["title"], "description": f["description"], "value": f["value"],
                 "grade": f["confidence"], "source": f["source"], "url": f["source_url"],
                 "limitations": f["limitations"][:200]} for i, f in enumerate(db.findings(inv_id)[:120])]


def verify_output(text: str, payload: list[dict], extra_urls: tuple[str, ...] = ()) -> tuple[str, list[str]]:
    """Check model output against the evidence it was given. Returns (clean_text, issues).

    * URLs that are not in the evidence are removed (the model may not invent sources).
    * Citations to finding numbers that do not exist are replaced by [?].
    * Sentences asserting identity, location or conduct (templates.guard) are removed.
    * Statements under FACTS that cite no finding are marked [UNCITED].
    The model's text is analysis; it is never evidence and is stored separately from the findings."""
    from core.intelligence import templates as T
    issues: list[str] = []
    valid_n = {p["n"] for p in payload}
    allowed = {_norm_url(p["url"]) for p in payload if p.get("url")} | {_norm_url(u) for u in extra_urls if u}
    allowed |= {_norm_url(p["value"]) for p in payload if str(p.get("value", "")).startswith(("http://", "https://"))}

    def fix_url(m):
        if _norm_url(m.group(0)) in allowed:
            return m.group(0)
        issues.append("removed a URL that is not in the collected evidence")
        return REMOVED_URL

    def fix_cite(m):
        nums = [int(x) for x in re.split(r"\s*,\s*", m.group(1))]
        if all(n in valid_n for n in nums):
            return m.group(0)
        issues.append("a citation referred to a finding that does not exist")
        return "[?]"

    out_lines, section = [], ""
    for line in text.splitlines():
        h = _HEADER_RE.match(line)
        if h:
            section = h.group(1).upper()
        line = _URL_RE.sub(fix_url, line)
        line = _CITE_RE.sub(fix_cite, line)
        kept = []
        for sent in _SENT_RE.split(line):
            try:
                T.guard(sent)
            except T.UnsupportedConclusion:
                issues.append("removed a sentence asserting identity, location or conduct: " + sent[:80])
                sent = "[statement removed: unsupported conclusion about a person]"
            kept.append(sent)
        line = " ".join(kept)
        if section == "FACTS" and not h and line.strip(" -*\t") and not _CITE_RE.search(line) and "[?]" not in line:
            issues.append("an uncited statement appeared under FACTS: " + line.strip()[:80])
            line = "[UNCITED] " + line
        out_lines.append(line)
    return "\n".join(out_lines), issues


def analyze(inv_id: int, task: str = "summary") -> str:
    ok, models, err = status()
    if not ok:
        raise RuntimeError(f"Ollama is not reachable at {endpoint()} ({err}). Start Ollama to use AI analysis.")
    model = selected_model(models)
    if not model:
        raise RuntimeError("Ollama is running but no models are installed. Run e.g. `ollama pull qwen2.5-coder:7b`.")
    db = get_db()
    inv = db.get_investigation(inv_id)
    if not inv:
        raise ValueError("Investigation not found")
    if not db.findings(inv_id):
        return "No evidence was found: this investigation has no findings to analyse."
    payload = build_payload(inv_id)
    prompts = {
        "summary": "Summarize the evidence and produce a conclusion.",
        "executive": "Write a concise executive summary (at most 6 sentences) of what the evidence does and does not "
                     "establish, naming the strongest and weakest points.",
        "patterns": "Identify patterns that appear across independent sources. Do not treat repeats from one origin as a pattern.",
        "gaps": "List the missing information and explain the limits on confidence.",
        "relationships": "Explain the relationships between the entities in this evidence and how strong each is.",
        "contradictions": "Identify contradictory or inconsistent evidence. If none, say so.",
    }
    user = (f"Investigation {inv['ref']} - type: {inv['inv_type']}, target: {inv['target']}.\n"
            f"Task: {prompts.get(task, prompts['summary'])}\n\nFINDINGS JSON:\n{json.dumps(payload)}")
    r = http.request("POST", endpoint() + "/api/chat", timeout=600, json={
        "model": model, "stream": False, "options": {"temperature": 0.1},
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]})
    if r.status_code >= 400:
        raise RuntimeError(f"Ollama returned HTTP {r.status_code}: {r.text[:200]}")
    try:
        text = str((r.json().get("message") or {}).get("content", "")).strip()
    except (ValueError, AttributeError):
        raise RuntimeError("Ollama returned an unreadable response; no analysis was produced.") from None
    if not text:
        raise RuntimeError("Ollama returned an empty analysis; nothing was saved.")
    # strip deepseek-r1 reasoning block
    if "</think>" in text:
        text = text.split("</think>", 1)[1].strip()
    text, issues = verify_output(text, payload, (inv["target"],))
    header = (f"[AI analysis by local model {model} - generated from {len(payload)} stored findings; verify before "
              "relying on it. This is analysis, not evidence: it is not a source and is never counted as corroboration.]\n")
    if issues:
        header += f"[Output check: {len(issues)} problem(s) found and neutralised: " + "; ".join(issues[:5]) + "]\n"
    return header + "\n" + text
