"""Shared Rich styling for the intelligence-terminal look."""
from __future__ import annotations

from rich.theme import Theme

CONF_STYLE = {"VERIFIED": "bold cyan", "CORROBORATED": "bold blue", "STRONG": "bold blue", "MODERATE": "magenta",
              "LOW": "yellow", "UNVERIFIED": "grey62", "INCONCLUSIVE": "dark_orange"}
CONF_DOT = {"VERIFIED": "●", "CORROBORATED": "●", "STRONG": "●", "INCONCLUSIVE": "?", "MODERATE": "◐", "LOW": "○", "UNVERIFIED": "·"}

THEME = Theme({
    "tp.accent": "bold cyan", "tp.accent2": "bright_blue", "tp.dim": "grey54", "tp.muted": "grey42",
    "tp.ok": "bold green", "tp.warn": "yellow", "tp.err": "bold red", "tp.head": "bold cyan",
    "tp.rule": "grey30", "tp.key": "bright_cyan", "tp.val": "white", "tp.label": "grey70",
})

STATUS_STYLE = {"ok": "tp.ok", "error": "tp.err", "skipped": "tp.warn", "not_configured": "tp.dim",
                "blocked": "tp.warn"}
STATUS_ICON = {"ok": "✓", "error": "✗", "skipped": "⊘", "not_configured": "—", "blocked": "⊗"}

BANNER = r"""[bold cyan]
 ╔════════════════════════════════════════════════════════════════╗
 ║   ████████╗██████╗  █████╗  ██████╗███████╗██████╗  ██████╗     ║
 ║   ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗    ║
 ║      ██║   ██████╔╝███████║██║     █████╗  ██████╔╝██║   ██║    ║
 ║      ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔═══╝ ██║   ██║    ║
 ║      ██║   ██║  ██║██║  ██║╚██████╗███████╗██║     ╚██████╔╝    ║
 ║      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝      ╚═════╝ ██╗ ║
 ╚════════════════════════════════════════════════════════════════╝[/bold cyan]
       [tp.dim]local-first OSINT · infrastructure & footprint intelligence[/tp.dim]"""
