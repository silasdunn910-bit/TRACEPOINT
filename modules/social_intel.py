"""Social profile URL analysis using only what the public page itself exposes
(HTML meta tags, rel="me" links). robots.txt is honoured; login walls are not bypassed."""
from __future__ import annotations

import html
import re
from urllib import robotparser
from urllib.parse import urljoin, urlparse

from core import http
from core.configuration import USER_AGENT
from core.http import HttpError
from core.models import (E_DOMAIN, E_SOCIAL, E_URL, E_USERNAME, LOW, MODERATE, R_LINKS_TO, R_SHARES_ID, UNVERIFIED,
                         VERIFIED, Finding, ModuleResult)
from modules import username_intel

PLATFORMS = {
    "github.com": "GitHub", "gitlab.com": "GitLab", "x.com": "X / Twitter", "twitter.com": "X / Twitter",
    "instagram.com": "Instagram", "facebook.com": "Facebook", "linkedin.com": "LinkedIn", "tiktok.com": "TikTok",
    "reddit.com": "Reddit", "youtube.com": "YouTube", "twitch.tv": "Twitch", "mastodon.social": "Mastodon",
    "bsky.app": "Bluesky", "t.me": "Telegram", "steamcommunity.com": "Steam", "medium.com": "Medium",
    "dev.to": "DEV Community", "keybase.io": "Keybase", "pinterest.com": "Pinterest", "soundcloud.com": "SoundCloud",
    "linktr.ee": "Linktree", "roblox.com": "Roblox", "chess.com": "Chess.com", "lichess.org": "Lichess",
}
LOGIN_WALLED = {"Instagram", "Facebook", "LinkedIn", "TikTok", "X / Twitter"}
_META = re.compile(r'<meta\s+[^>]*?(?:property|name)\s*=\s*["\']([^"\']+)["\'][^>]*?content\s*=\s*["\']([^"\']*)["\']', re.I | re.S)
_META_REV = re.compile(r'<meta\s+[^>]*?content\s*=\s*["\']([^"\']*)["\'][^>]*?(?:property|name)\s*=\s*["\']([^"\']+)["\']', re.I | re.S)
_RELME = re.compile(r'<(?:a|link)\s+[^>]*?rel\s*=\s*["\'][^"\']*\bme\b[^"\']*["\'][^>]*?href\s*=\s*["\']([^"\']+)["\']', re.I)
_RELME2 = re.compile(r'<(?:a|link)\s+[^>]*?href\s*=\s*["\']([^"\']+)["\'][^>]*?rel\s*=\s*["\'][^"\']*\bme\b', re.I)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+")


def parse_profile_url(url: str) -> tuple[str, str, str]:
    """-> (platform, handle, host)"""
    p = urlparse(url if "://" in url else "https://" + url)
    host = (p.hostname or "").lower().removeprefix("www.").removeprefix("m.")
    platform = next((v for k, v in PLATFORMS.items() if host == k or host.endswith("." + k)), host)
    parts = [x for x in p.path.split("/") if x]
    handle = ""
    if parts:
        skip = {"user", "u", "in", "id", "profile", "member", "users", "@", "c", "channel", "add"}
        cand = [x for x in parts if x.lower() not in skip]
        handle = (cand[0] if cand else parts[-1]).lstrip("@")
    if platform == "Bluesky" and len(parts) >= 2:
        handle = parts[1]
    if host.endswith(".itch.io"):
        handle, platform = host.split(".")[0], "itch.io"
    return platform, handle, host


def robots_allows(url: str) -> bool | None:
    p = urlparse(url)
    rp = robotparser.RobotFileParser()
    try:
        r = http.get(f"{p.scheme}://{p.netloc}/robots.txt", timeout=6, public_only=True)
        if r.status_code >= 400:
            return True
        rp.parse(r.text.splitlines())
        return rp.can_fetch(USER_AGENT, url)
    except HttpError:
        return None


def investigate(target: str, *, compare_username: bool = True) -> ModuleResult:
    url = target.strip()
    if "://" not in url:
        url = "https://" + url
    res = ModuleResult("social", url)
    platform, handle, host = parse_profile_url(url)
    s_ent = res.entity(E_SOCIAL, url, UNVERIFIED, "user input")
    res.relate(s_ent, res.entity(E_DOMAIN, host, VERIFIED), "hosted by", VERIFIED, "URL")
    res.add(Finding("Profile URL analysis", f"Platform: {platform}; handle: {handle or 'not detected'}; host: {host}",
                    "Local URL parsing", VERIFIED, "url-analysis", handle, url,
                    limitations="Handle extraction is pattern-based and may be wrong for unusual URL formats."))

    if platform in LOGIN_WALLED:
        res.add(Finding("Platform restricts automated access", f"{platform} requires login or blocks automated "
                        "profile retrieval. TRACEPOINT does not bypass this.", "TRACEPOINT policy", VERIFIED,
                        "access", platform, url, limitations="Open the URL manually in your browser."))
        res.source(platform, url, "skipped", "login-walled platform")
    else:
        allowed = robots_allows(url)
        res.source("robots.txt", f"https://{host}/robots.txt", "ok" if allowed is not None else "error",
                   {True: "allowed", False: "disallowed", None: "unreachable"}[allowed])
        if allowed is False:
            res.add(Finding("robots.txt disallows automated fetch", "Page not fetched out of respect for the site's "
                            "robots.txt.", "robots.txt", VERIFIED, "access", "disallowed", url))
        else:
            try:
                r = http.get(url, timeout=12, max_bytes=3_000_000, public_only=True)
                res.source(platform + " public page", url, "ok" if r.status_code < 400 else "error", f"HTTP {r.status_code}")
                if r.status_code == 404:
                    res.add(Finding("Profile page not found", "The page returned HTTP 404.", platform, VERIFIED,
                                    "profile", "404", url))
                elif r.status_code < 400:
                    text = r.text
                    meta = {k.lower(): html.unescape(v).strip() for k, v in _META.findall(text)}
                    meta.update({k.lower(): html.unescape(v).strip() for v, k in _META_REV.findall(text)
                                 if k.lower() not in meta})
                    title = html.unescape((_TITLE.search(text).group(1) if _TITLE.search(text) else "")).strip()
                    disp = meta.get("og:title") or meta.get("twitter:title") or title
                    bio = meta.get("og:description") or meta.get("description") or meta.get("twitter:description")
                    if disp:
                        res.add(Finding("Public display title", disp[:200], platform, VERIFIED, "profile", disp[:200], url,
                                        limitations="Self-reported by the account holder."))
                    if bio:
                        res.add(Finding("Public biography / description", bio[:500], platform, VERIFIED, "profile",
                                        bio[:200], url, limitations="Self-reported; may be outdated or false."))
                    for k in ("og:type", "og:site_name", "profile:username", "og:image", "article:published_time"):
                        if meta.get(k):
                            res.add(Finding(f"Profile metadata: {k}", meta[k][:300], platform, VERIFIED, "metadata",
                                            meta[k][:300], url))
                    links = {urljoin(url, h) for h in _RELME.findall(text) + _RELME2.findall(text)}
                    links |= set(_URL_IN_TEXT.findall(bio or ""))
                    for l in sorted(links)[:25]:
                        if urlparse(l).hostname and urlparse(l).hostname.removeprefix("www.") != host:
                            res.add(Finding("Publicly disclosed link", l, platform, MODERATE, "links", l, l,
                                            evidence="Found in rel=me link or public bio.",
                                            limitations="A link placed by the account holder; not independently verified."))
                            res.relate(s_ent, res.entity(E_URL, l, MODERATE, platform), R_LINKS_TO, MODERATE, platform)
                    if not (disp or bio or links):
                        res.add(Finding("No public metadata exposed", "Page loaded but exposed no profile metadata "
                                        "(content may be rendered by JavaScript or require login).", platform, LOW,
                                        "profile", "none", url))
            except HttpError as e:
                res.source(platform + " public page", url, "error", str(e))
                res.errors.append(str(e))

    if handle:
        u_ent = res.entity(E_USERNAME, handle.lower(), VERIFIED, "URL")
        res.relate(s_ent, u_ent, R_SHARES_ID, VERIFIED, "handle in URL")
        if compare_username and username_intel.USERNAME_RE.match(handle):
            sub = username_intel.investigate(handle, web_search=False)
            for f in sub.findings:
                if f.category == "profiles":
                    f.category = "cross-platform"
                    f.limitations = username_intel.OWNERSHIP_LIMIT
            sub.findings = [f for f in sub.findings if f.category in ("cross-platform", "comparison")]
            res.merge(sub)
    return res
