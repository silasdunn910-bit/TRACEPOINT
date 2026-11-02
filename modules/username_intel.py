"""Username intelligence: checks whether a public profile with this exact handle exists on
platforms that expose that publicly (official APIs where available), collects public profile
metadata, and compares it across platforms.

Matching handles are NEVER treated as proof that accounts share an owner.
Platforms that block unauthenticated checks are listed as manual links, not guessed.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from core import http, search_engine
from core.http import HttpError
from core.models import (E_SOCIAL, E_URL, E_USERNAME, LOW, MODERATE, R_LINKS_TO, R_SHARES_ID, UNVERIFIED, VERIFIED,
                         Finding, ModuleResult)

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
OWNERSHIP_LIMIT = ("A profile using the same handle does not establish common ownership. Different people often use "
                   "identical usernames. Compare profile content before associating accounts.")

# Some sites answer HTTP 200 with a bot-challenge page instead of a profile. Treating
# that as "profile exists" is a false VERIFIED finding, so detect and report it as
# inconclusive instead.
_CHALLENGE_MARKERS = ("client challenge", "checking your browser", "just a moment",
                      "attention required", "robot check", "enable javascript and cookies")


def _looks_like_challenge(text: str) -> bool:
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = re.sub(r"\s+", " ", m.group(1)).strip().lower() if m else ""
    if any(x in title for x in _CHALLENGE_MARKERS):
        return True
    low = text[:5000].lower()
    return "cf-chl-" in low or "__cf_chl" in low


@dataclass
class Site:
    name: str
    profile: str                 # human-facing URL
    check: str = ""              # URL used for the check (defaults to profile)
    method: str = "status"       # status | json_nonempty | json_not_null | text_absent | text_present | wiki | roblox
    marker: str = ""
    meta: dict = field(default_factory=dict)  # json field -> label
    lower: bool = False


SITES: list[Site] = [
    Site("GitHub", "https://github.com/{u}", "https://api.github.com/users/{u}",
         meta={"name": "name", "bio": "bio", "location": "location (self-reported)", "blog": "website",
               "company": "company", "created_at": "created"}),
    Site("GitLab", "https://gitlab.com/{u}", "https://gitlab.com/api/v4/users?username={u}", "json_nonempty",
         meta={"name": "name"}),
    Site("Codeberg", "https://codeberg.org/{u}", "https://codeberg.org/api/v1/users/{u}",
         meta={"full_name": "name", "description": "bio", "website": "website", "location": "location (self-reported)",
               "created": "created"}),
    Site("Reddit", "https://www.reddit.com/user/{u}", "https://www.reddit.com/user/{u}/about.json", "reddit"),
    Site("Hacker News", "https://news.ycombinator.com/user?id={u}", "https://hacker-news.firebaseio.com/v0/user/{u}.json",
         "json_not_null", meta={"about": "bio", "created": "created (unix)"}),
    Site("Keybase", "https://keybase.io/{u}", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", "keybase"),
    Site("DEV Community", "https://dev.to/{u}", "https://dev.to/api/users/by_username?url={u}",
         meta={"name": "name", "summary": "bio", "location": "location (self-reported)", "website_url": "website",
               "joined_at": "joined"}),
    Site("Docker Hub", "https://hub.docker.com/u/{u}", "https://hub.docker.com/v2/users/{u}/",
         meta={"full_name": "name", "location": "location (self-reported)", "company": "company"}),
    Site("PyPI", "https://pypi.org/user/{u}/"),
    Site("npm", "https://www.npmjs.com/~{u}"),
    Site("Chess.com", "https://www.chess.com/member/{u}", "https://api.chess.com/pub/player/{u}", lower=True,
         meta={"name": "name", "location": "location (self-reported)", "joined": "joined (unix)"}),
    Site("Lichess", "https://lichess.org/@/{u}", "https://lichess.org/api/user/{u}", meta={"createdAt": "created (ms)"}),
    Site("Steam", "https://steamcommunity.com/id/{u}", method="text_absent",
         marker="The specified profile could not be found"),
    Site("Roblox", "https://www.roblox.com/search/users?keyword={u}", method="roblox"),
    Site("Minecraft (Mojang)", "https://namemc.com/profile/{u}", "https://api.mojang.com/users/profiles/minecraft/{u}",
         "json_not_null"),
    Site("Mastodon (mastodon.social)", "https://mastodon.social/@{u}",
         "https://mastodon.social/api/v1/accounts/lookup?acct={u}",
         meta={"display_name": "name", "note": "bio (HTML)", "created_at": "created"}),
    Site("Bluesky", "https://bsky.app/profile/{u}.bsky.social",
         "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social", lower=True,
         meta={"displayName": "name", "description": "bio", "createdAt": "created"}),
    Site("Telegram", "https://t.me/{u}", method="text_present", marker="tgme_page_title"),
    Site("YouTube", "https://www.youtube.com/@{u}"),
    Site("Wikipedia (en)", "https://en.wikipedia.org/wiki/User:{u}",
         "https://en.wikipedia.org/w/api.php?action=query&list=users&ususers={u}&usprop=registration|editcount&format=json",
         "wiki"),
    Site("itch.io", "https://{u}.itch.io", lower=True),
    Site("Kaggle", "https://www.kaggle.com/{u}"),
    Site("SoundCloud", "https://soundcloud.com/{u}"),
    Site("Linktree", "https://linktr.ee/{u}"),
    Site("about.me", "https://about.me/{u}"),
    Site("Letterboxd", "https://letterboxd.com/{u}/"),
]

# Platforms that require login or block automated profile checks. We only provide links.
MANUAL_SITES = {
    "Instagram": "https://www.instagram.com/{u}/", "TikTok": "https://www.tiktok.com/@{u}",
    "X / Twitter": "https://x.com/{u}", "Facebook": "https://www.facebook.com/{u}",
    "LinkedIn": "https://www.linkedin.com/in/{u}", "Snapchat": "https://www.snapchat.com/add/{u}",
    "Twitch": "https://www.twitch.tv/{u}", "Pinterest": "https://www.pinterest.com/{u}/",
}


def normalize(username: str) -> str:
    return username.strip().lstrip("@").strip()


def variants(u: str) -> list[str]:
    base = u.lower()
    v = {base, base.replace(".", ""), base.replace("_", ""), base.replace("-", ""), base.replace(".", "_"),
         base.replace("_", ".")}
    v.discard(base)
    return sorted(x for x in v if x)


def check_site(site: Site, u: str) -> dict:
    uu = u.lower() if site.lower else u
    profile = site.profile.format(u=uu)
    url = (site.check or site.profile).format(u=uu)
    out = {"site": site.name, "url": profile, "check": url, "state": "unknown", "detail": "", "meta": {}}
    try:
        if site.method == "roblox":
            r = http.request("POST", "https://users.roblox.com/v1/usernames/users",
                             json={"usernames": [u], "excludeBannedUsers": False})
            data = r.json().get("data", []) if r.status_code == 200 else None
            if data is None:
                out.update(state="inconclusive", detail=f"HTTP {r.status_code}")
            elif data:
                d = data[0]
                out.update(state="found", url=f"https://www.roblox.com/users/{d['id']}/profile",
                           meta={"name": d.get("displayName"), "user id": d.get("id")})
            else:
                out["state"] = "not_found"
            return out
        r = http.get(url, timeout=10, max_bytes=2_000_000)
        code = r.status_code
        if code == 429:
            out.update(state="inconclusive", detail="rate limited (HTTP 429)")
            return out
        if code in (401, 403) or code >= 500:
            out.update(state="inconclusive", detail=f"blocked or unavailable (HTTP {code})")
            return out
        page_text = r.text
        if code == 200 and _looks_like_challenge(page_text):
            out.update(state="inconclusive", detail="anti-bot challenge page (profile cannot be verified)")
            return out
        body = None
        if site.method in ("json_nonempty", "json_not_null", "keybase", "wiki", "reddit") or site.meta:
            try:
                body = r.json()
            except ValueError:
                body = None
        found = None
        if site.method == "status":
            found = code == 200 if code in (200, 404, 410) else None
        elif site.method == "json_nonempty":
            found = bool(body) if code == 200 else (False if code == 404 else None)
            if found and isinstance(body, list):
                body = body[0]
        elif site.method == "json_not_null":
            found = code == 200 and body not in (None, {}, [])
            if code in (204, 404):
                found = False
        elif site.method == "keybase":
            them = (body or {}).get("them") or []
            found = bool(them and them[0])
            if found:
                prof = them[0].get("profile") or {}
                out["meta"] = {k: v for k, v in {"name": prof.get("full_name"), "bio": prof.get("bio"),
                                                 "location (self-reported)": prof.get("location")}.items() if v}
        elif site.method == "wiki":
            users = ((body or {}).get("query") or {}).get("users") or [{}]
            found = "missing" not in users[0] and "invalid" not in users[0] and bool(users[0])
            if found:
                out["meta"] = {"registered": users[0].get("registration"), "edits": users[0].get("editcount")}
        elif site.method == "reddit":
            if code == 404:
                found = False
            elif code == 200 and isinstance(body, dict):
                if (body.get("data") or {}).get("name"):
                    found = True
                elif body.get("error") or body.get("message"):
                    found = False
        elif site.method == "text_absent":
            found = code == 200 and site.marker not in page_text
        elif site.method == "text_present":
            found = code == 200 and site.marker in page_text
        if found is None:
            out.update(state="inconclusive", detail=f"unexpected HTTP {code}")
        else:
            out["state"] = "found" if found else "not_found"
        if found and isinstance(body, dict) and site.meta:
            for k, label in site.meta.items():
                v = body.get(k)
                if v not in (None, "", []):
                    out["meta"][label] = str(v)[:300]
        if found and site.name == "Reddit" and isinstance(body, dict):
            d = body.get("data") or {}
            out["meta"] = {k: v for k, v in {"created (unix)": d.get("created_utc"),
                                             "karma": d.get("total_karma")}.items() if v is not None}
    except HttpError as e:
        out.update(state="error", detail=str(e))
    except Exception as e:  # unexpected payload shape
        out.update(state="error", detail=f"{type(e).__name__}")
    return out


def investigate(target: str, *, web_search: bool = True, check_variants: bool = False) -> ModuleResult:
    u = normalize(target)
    res = ModuleResult("username", u)
    if not USERNAME_RE.match(u):
        res.errors.append("Username may only contain letters, digits, '.', '_' and '-' (max 40).")
        return res
    u_ent = res.entity(E_USERNAME, u.lower(), VERIFIED)
    res.add(Finding("Normalized username", u, "Local normalization", VERIFIED, "normalization", u.lower(),
                    evidence="Leading @ and whitespace removed; comparisons are case-insensitive.",
                    limitations="Some platforms treat dots/underscores as distinct characters."))
    vs = variants(u)
    if vs:
        res.add(Finding("Common handle variants (not checked)" if not check_variants else "Handle variants checked",
                        ", ".join(vs), "Local normalization", UNVERIFIED, "normalization", ", ".join(vs),
                        limitations="Variants are only spelling alternatives, not discovered accounts."))

    handles = [u] + (vs[:3] if check_variants else [])
    jobs = [(s, h) for h in handles for s in SITES]
    with ThreadPoolExecutor(max_workers=10) as ex:
        results = list(ex.map(lambda sh: check_site(*sh), jobs))

    found = [r for r in results if r["state"] == "found"]
    seen_urls = set()
    for r in results:
        res.source(r["site"], r["check"], {"found": "ok", "not_found": "ok"}.get(r["state"], "error"),
                   r["state"] + (f" — {r['detail']}" if r["detail"] else ""))
        if r["state"] == "found":
            if r["url"] in seen_urls:
                res.notes.append(f"Duplicate profile URL skipped: {r['url']}")
                continue
            seen_urls.add(r["url"])
            meta = "\n".join(f"{k}: {v}" for k, v in r["meta"].items()) or "(no public metadata returned)"
            res.add(Finding(f"Public profile exists: {r['site']}",
                            f"A public {r['site']} account uses this handle.", r["site"], VERIFIED, "profiles",
                            r["url"], r["url"], meta, OWNERSHIP_LIMIT))
            s_ent = res.entity(E_SOCIAL, r["url"], VERIFIED, r["site"])
            res.relate(s_ent, u_ent, R_SHARES_ID, VERIFIED, f"{r['site']} handle match")
            site_url = r["meta"].get("website")
            if site_url and site_url.startswith("http"):
                res.relate(s_ent, res.entity(E_URL, site_url, MODERATE, r["site"]), R_LINKS_TO, MODERATE,
                           f"{r['site']} profile website field")
        elif r["state"] in ("inconclusive", "error"):
            res.add(Finding(f"Check inconclusive: {r['site']}", r["detail"] or "No definitive answer.", r["site"],
                            UNVERIFIED, "profiles-inconclusive", r["url"], r["url"],
                            limitations="The platform did not give a definitive answer to an automated check."))

    # cross-platform comparison of self-reported names / locations
    for field_name in ("name", "location (self-reported)"):
        vals: dict[str, list[str]] = {}
        for r in found:
            v = (r["meta"].get(field_name) or "").strip()
            if v:
                vals.setdefault(v.lower(), []).append(r["site"])
        if len(vals) > 1:
            res.add(Finding(f"Conflicting {field_name} across platforms",
                            "; ".join(f"'{k}' on {', '.join(v)}" for k, v in vals.items()), "Cross-platform comparison",
                            MODERATE, "comparison", str(len(vals)),
                            evidence="Different values are expected when accounts belong to different people.",
                            limitations=OWNERSHIP_LIMIT))
        elif len(vals) == 1 and len(next(iter(vals.values()))) > 1:
            k, v = next(iter(vals.items()))
            res.add(Finding(f"Consistent {field_name} across platforms", f"'{k}' on {', '.join(v)}",
                            "Cross-platform comparison", LOW, "comparison", k,
                            limitations="Consistency of self-reported fields is weak evidence; fields can be copied "
                                        "or coincidentally identical."))

    for name, tmpl in MANUAL_SITES.items():
        res.add(Finding(f"Manual check: {name}", "Platform restricts automated profile checks; open the link to check "
                        "manually.", "Not checked", UNVERIFIED, "manual-checks", tmpl.format(u=u), tmpl.format(u=u),
                        limitations="Not checked by TRACEPOINT."))

    if web_search:
        hits = search_engine.search(f'"{u}"', 10, res)
        search_engine.results_to_findings(hits, res, category="web-references", exact_term=u.lower(),
                                          what=f'exact username query "{u}"')
    res.notes.append(f"{len(found)} of {len(results)} automated platform checks found a public profile.")
    return res
