"""Identifier detection, cross-investigation correlation, contradiction detection and graph export.

Entities are de-duplicated only by (type, exact normalized identifier). Person entities are never
merged with each other on name or username similarity."""
from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import phonenumbers

from core.database import get_db

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
DOMAIN_RE = re.compile(r"^(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)
URL_RE = re.compile(r"^https?://", re.I)
SOCIAL_HOSTS = ("github.com", "gitlab.com", "x.com", "twitter.com", "instagram.com", "facebook.com", "linkedin.com",
                "tiktok.com", "reddit.com", "youtube.com", "twitch.tv", "mastodon.", "bsky.app", "t.me",
                "steamcommunity.com", "medium.com", "dev.to", "keybase.io", "linktr.ee", "roblox.com", "chess.com")


def detect_type(value: str) -> tuple[str, str]:
    """-> (type, reason). Types: email, phone, ip, url_social, url_document, url_image, domain, username, name."""
    v = value.strip()
    if EMAIL_RE.match(v):
        return "email", "contains a single @ and a domain"
    try:
        ipaddress.ip_address(v.strip("[]"))
        return "ip", "parses as an IPv4/IPv6 address"
    except ValueError:
        pass
    if URL_RE.match(v) or (v.lower().startswith("www.") and "/" in v):
        low = v.lower().split("?")[0]
        if low.endswith((".pdf", ".docx", ".xlsx", ".pptx")):
            return "document", "URL ends with a document extension"
        if low.endswith((".jpg", ".jpeg", ".png", ".webp", ".gif", ".tif", ".tiff", ".heic")):
            return "image", "URL ends with an image extension"
        if any(h in low for h in SOCIAL_HOSTS) and len([p for p in low.split("://")[-1].split("/") if p]) >= 2:
            return "social", "URL points at a known social platform profile"
        return "domain", "URL — investigating its domain"
    digits = re.sub(r"\D", "", v)
    if re.fullmatch(r"[+()\d\s.-]{7,20}", v) and 7 <= len(digits) <= 15:
        try:
            n = phonenumbers.parse(v, None if v.startswith("+") else "US")
            if phonenumbers.is_possible_number(n):
                return "phone", "digits form a possible phone number"
        except phonenumbers.NumberParseException:
            pass
    if DOMAIN_RE.match(v):
        return "domain", "looks like a hostname with a TLD"
    if re.fullmatch(r"[A-Za-z][A-Za-z'.-]+(\s+[A-Za-z][A-Za-z'.-]*){1,4}", v):
        return "name", "two or more words of letters"
    if re.fullmatch(r"@?[A-Za-z0-9._-]{2,40}", v):
        return "username", "single token of handle characters"
    return "unknown", "no pattern matched"


# Shared hosting / mail / DNS / resolver infrastructure. Two subjects using the same provider are NOT related
# because of it, so such entities are flagged `generic` and shown separately, never as evidence of a connection.
GENERIC_INFRA_SUFFIXES = (
    "gmail.com", "googlemail.com", "google.com", "googleusercontent.com", "outlook.com", "hotmail.com", "live.com",
    "msn.com", "office365.com", "protection.outlook.com", "yahoo.com", "yahoodns.net", "icloud.com", "me.com",
    "aol.com", "proton.me", "protonmail.com", "protonmail.ch", "gmx.com", "gmx.de", "zoho.com", "fastmail.com",
    "cloudflare.com", "cloudflare.net", "amazonaws.com", "awsdns", "azure-dns", "azurewebsites.net", "akamai.net",
    "fastly.net", "github.io", "github.com", "githubusercontent.com", "godaddy.com", "domaincontrol.com",
    "namecheap.com", "registrar-servers.com", "wixdns.net", "squarespace.com", "mailgun.org", "sendgrid.net",
)
GENERIC_IPS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "2606:4700:4700::1111", "2001:4860:4860::8888"}


def is_generic_infrastructure(entity_type: str, value: str) -> bool:
    v = (value or "").strip().lower().rstrip(".")
    if entity_type == "ip":
        return v in GENERIC_IPS
    if entity_type in ("domain", "organization"):
        return any(v == s or v.endswith("." + s) or v.endswith(s) and "." not in s for s in GENERIC_INFRA_SUFFIXES)
    return False


def shared_entities(min_investigations: int = 2) -> list[dict]:
    """Entities that appear in more than one investigation. Each row has `generic` = True for common shared
    infrastructure (webmail, DNS, CDN, public resolvers); that is not evidence that subjects are connected."""
    rows = get_db().q("""SELECT e.id, e.entity_type, e.value, e.verification, COUNT(DISTINCT ie.investigation_id) n,
                         GROUP_CONCAT(DISTINCT i.ref) refs
                         FROM entities e JOIN investigation_entities ie ON ie.entity_id=e.id
                         JOIN investigations i ON i.id=ie.investigation_id
                         GROUP BY e.id HAVING n >= ? ORDER BY n DESC, e.entity_type""", (min_investigations,))
    out = []
    for r in rows:
        d = dict(r)
        d["generic"] = is_generic_infrastructure(d["entity_type"], d["value"])
        out.append(d)
    return out


def entity_neighbors(entity_id: int) -> list[dict]:
    rows = get_db().q("""SELECT r.rel_type, r.confidence, r.source, i.ref,
                         s.id sid, s.entity_type st, s.value sv, d.id did, d.entity_type dt, d.value dv
                         FROM relationships r JOIN entities s ON s.id=r.src_entity_id JOIN entities d ON d.id=r.dst_entity_id
                         JOIN investigations i ON i.id=r.investigation_id
                         WHERE r.src_entity_id=? OR r.dst_entity_id=?""", (entity_id, entity_id))
    return [dict(r) for r in rows]


def search_entities(term: str) -> list[dict]:
    return [dict(r) for r in get_db().q(
        "SELECT * FROM entities WHERE norm LIKE ? ORDER BY entity_type LIMIT 50", (f"%{term.lower()}%",))]


def contradictions(inv_id: int) -> list[str]:
    """Rule-based contradiction detection over stored findings."""
    db = get_db()
    fs = db.findings(inv_id)
    out = [f"{f['title']}: {f['description']}" for f in fs if f["category"] == "contradiction"]
    by_title = defaultdict(set)
    for f in fs:
        if f["category"] in ("geo", "registration", "network"):
            by_title[f["title"]].add(f["value"])
    for t, vals in by_title.items():
        vals.discard("")
        if len(vals) > 1 and t.startswith(("Domain registration date", "Registry event")):
            out.append(f"{t} has conflicting values: {', '.join(sorted(vals))}")
    for f in fs:
        if f["category"] == "comparison" and f["title"].startswith("Conflicting"):
            out.append(f"{f['title']}: {f['description']}")
    return out


def graph_json(inv_id: int | None = None) -> dict:
    """Cytoscape-compatible node/edge JSON for one investigation or the whole database."""
    db = get_db()
    if inv_id:
        ents, rels = db.entities_for(inv_id), db.relationships_for(inv_id)
    else:
        ents = db.q("SELECT * FROM entities")
        rels = db.q("""SELECT r.*, s.entity_type src_type, s.value src_value, d.entity_type dst_type, d.value dst_value
                       FROM relationships r JOIN entities s ON s.id=r.src_entity_id JOIN entities d ON d.id=r.dst_entity_id""")
    nodes = [{"data": {"id": f"e{e['id']}", "label": e["value"], "type": e["entity_type"],
                       "verification": e["verification"]}} for e in ents]
    known = {n["data"]["id"] for n in nodes}
    edges = []
    for r in rels:
        s, d = f"e{r['src_entity_id']}", f"e{r['dst_entity_id']}"
        for nid, t, v in ((s, r["src_type"], r["src_value"]), (d, r["dst_type"], r["dst_value"])):
            if nid not in known:
                nodes.append({"data": {"id": nid, "label": v, "type": t}})
                known.add(nid)
        edges.append({"data": {"id": f"r{r['id']}", "source": s, "target": d, "label": r["rel_type"],
                               "confidence": r["confidence"], "source_ref": r["source"]}})
    return {"elements": {"nodes": nodes, "edges": edges},
            "summary": {"nodes": len(nodes), "edges": len(edges),
                        "by_type": dict(Counter(n["data"]["type"] for n in nodes))}}


def graph_json_for_entities(entity_ids: list[int], include_neighbors: bool = True) -> dict:
    """Subgraph limited to the given entities (e.g. the result of an entity search).

    With include_neighbors, also pulls in directly-related entities and the edges between
    the selection and its neighbours — so an exported search result is self-contained and
    does not silently include the whole database.
    """
    db = get_db()
    ids = set(entity_ids)
    if not ids:
        return {"elements": {"nodes": [], "edges": []},
                "summary": {"nodes": 0, "edges": 0, "by_type": {}, "filtered": True}}
    placeholders = ",".join("?" * len(ids))
    rels = db.q(f"""SELECT r.*, s.entity_type src_type, s.value src_value, d.entity_type dst_type, d.value dst_value
                    FROM relationships r JOIN entities s ON s.id=r.src_entity_id JOIN entities d ON d.id=r.dst_entity_id
                    WHERE r.src_entity_id IN ({placeholders}) OR r.dst_entity_id IN ({placeholders})""",
                tuple(ids) + tuple(ids))
    keep_edges = []
    node_ids = set(ids)
    for r in rels:
        s, d = r["src_entity_id"], r["dst_entity_id"]
        if include_neighbors or (s in ids and d in ids):
            keep_edges.append(r)
            if include_neighbors:
                node_ids.add(s)
                node_ids.add(d)
    rows = db.q(f"SELECT * FROM entities WHERE id IN ({','.join('?' * len(node_ids))})", tuple(node_ids))
    nodes = [{"data": {"id": f"e{e['id']}", "label": e["value"], "type": e["entity_type"],
                       "verification": e["verification"], "selected": e["id"] in ids}} for e in rows]
    edges = [{"data": {"id": f"r{r['id']}", "source": f"e{r['src_entity_id']}", "target": f"e{r['dst_entity_id']}",
                       "label": r["rel_type"], "confidence": r["confidence"], "source_ref": r["source"]}}
             for r in keep_edges]
    return {"elements": {"nodes": nodes, "edges": edges},
            "summary": {"nodes": len(nodes), "edges": len(edges), "selected": len(ids),
                        "by_type": dict(Counter(n["data"]["type"] for n in nodes)), "filtered": True}}


def export_graph(path: Path, inv_id: int | None = None, entity_ids: list[int] | None = None) -> Path:
    """Export a graph. If entity_ids is given, export exactly that filtered subgraph;
    otherwise export one investigation (inv_id) or the whole database (None)."""
    data = graph_json_for_entities(entity_ids) if entity_ids is not None else graph_json(inv_id)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path
