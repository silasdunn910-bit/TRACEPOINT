"""Optional local AI analyst via Ollama. Never downloads models. Only sees stored evidence."""
from __future__ import annotations

import json

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
- Be concise."""


def endpoint() -> str:
    return get_db().get_setting("ollama_url", OLLAMA_DEFAULT).rstrip("/")


def status() -> tuple[bool, list[str], str]:
    try:
        data = http.get_json(endpoint() + "/api/tags", timeout=3)
        return True, [m["name"] for m in data.get("models", [])], ""
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


def analyze(inv_id: int, task: str = "summary") -> str:
    ok, models, err = status()
    if not ok:
        raise RuntimeError(f"Ollama is not reachable at {endpoint()} ({err}). Start Ollama to use AI analysis.")
    model = selected_model(models)
    if not model:
        raise RuntimeError("Ollama is running but no models are installed. Run e.g. `ollama pull qwen2.5-coder:7b`.")
    db = get_db()
    inv = db.get_investigation(inv_id)
    findings = db.findings(inv_id)
    if not findings:
        return "No evidence was found: this investigation has no findings to analyse."
    payload = [{"n": i + 1, "title": f["title"], "description": f["description"], "value": f["value"],
                "confidence": f["confidence"], "source": f["source"], "url": f["source_url"],
                "limitations": f["limitations"][:200]} for i, f in enumerate(findings[:120])]
    prompts = {
        "summary": "Summarize the evidence and produce a conclusion.",
        "relationships": "Explain the relationships between the entities in this evidence and how strong each is.",
        "contradictions": "Identify contradictory or inconsistent evidence. If none, say so.",
    }
    user = (f"Investigation {inv['ref']} — type: {inv['inv_type']}, target: {inv['target']}.\n"
            f"Task: {prompts.get(task, prompts['summary'])}\n\nFINDINGS JSON:\n{json.dumps(payload)}")
    r = http.request("POST", endpoint() + "/api/chat", timeout=600, json={
        "model": model, "stream": False, "options": {"temperature": 0.1},
        "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}]})
    if r.status_code >= 400:
        raise RuntimeError(f"Ollama returned HTTP {r.status_code}: {r.text[:200]}")
    text = r.json().get("message", {}).get("content", "").strip()
    # strip deepseek-r1 reasoning block
    if "</think>" in text:
        text = text.split("</think>", 1)[1].strip()
    header = f"[AI analysis by local model {model} — generated from {len(payload)} stored findings; verify before relying on it]\n\n"
    return header + text
