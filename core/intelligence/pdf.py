"""Minimal PDF writer for intelligence reports (no third-party dependency).

Uses the 14 standard PDF fonts (Helvetica, Helvetica-Bold, Courier) with WinAnsi encoding, so text outside
Windows-1252 is replaced with '?' in the PDF only (Markdown keeps the original). Content streams are uncompressed.
Every safe http(s) source URL gets a clickable URI link annotation carrying the exact, unwrapped URL, so the
URL is preserved even where the visible text has to wrap.
"""
from __future__ import annotations

from core.reports import safe_href

from .formatter import blocks
from .models import IntelligenceReport

PAGE_W, PAGE_H, MARGIN = 612.0, 792.0, 54.0
TEXT_W = PAGE_W - 2 * MARGIN

# Helvetica advance widths (1/1000 em) for ASCII 32..126, from the standard AFM metrics.
_HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556,
         556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667,
         556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556,
         556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722,
         500, 500, 500, 334, 260, 334, 584]
_FONTS = {"F1": "Helvetica", "F2": "Helvetica-Bold", "F3": "Courier"}
_SUBST = {"→": "->", "←": "<-", "✓": "OK", "✔": "OK", "⚠": "!", "≥": ">=", "≤": "<=",
          " ": " ", " ": " ", "​": ""}


def _clean(text: str) -> str:
    text = "".join(_SUBST.get(ch, ch) for ch in (text or "")).replace("\t", "    ")
    return text.encode("cp1252", errors="replace").decode("cp1252")


def text_width(text: str, font: str, size: float) -> float:
    if font == "F3":
        return len(text) * 600 * size / 1000
    w = sum(_HELV[ord(c) - 32] if 32 <= ord(c) <= 126 else 556 for c in text)
    return w * size / 1000 * (1.06 if font == "F2" else 1.0) * 1.02   # small safety margin


def wrap(text: str, font: str, size: float, width: float) -> list[str]:
    out: list[str] = []
    for para in _clean(text).split("\n"):
        line = ""
        for word in para.split(" "):
            cand = f"{line} {word}" if line else word
            if text_width(cand, font, size) <= width:
                line = cand
                continue
            if line:
                out.append(line)
            while text_width(word, font, size) > width:   # hard-break long tokens such as URLs
                cut = len(word)
                while cut > 1 and text_width(word[:cut], font, size) > width:
                    cut -= 1
                out.append(word[:cut])
                word = word[cut:]
            line = word
        out.append(line)
    return out


def _pdf_str(text: str) -> str:
    """PDF literal string; bytes outside printable ASCII become octal escapes so the file stays 7-bit."""
    out = []
    for byte in text.encode("cp1252", errors="replace"):
        ch = chr(byte)
        if ch in "()\\":
            out.append("\\" + ch)
        elif 32 <= byte <= 126:
            out.append(ch)
        else:
            out.append(f"\\{byte:03o}")
    return "(" + "".join(out) + ")"


def _uri_str(url: str) -> str:
    out = []
    for byte in url.encode("utf-8"):
        ch = chr(byte)
        out.append("\\" + ch if ch in "()\\" else ch if 32 <= byte <= 126 else f"\\{byte:03o}")
    return "(" + "".join(out) + ")"


class _Layout:
    def __init__(self):
        self.pages: list[dict] = []
        self._new_page()

    def _new_page(self):
        self.page = {"ops": [], "annots": []}
        self.pages.append(self.page)
        self.y = PAGE_H - MARGIN

    def space(self, pts: float):
        self.y -= pts

    def line(self, text: str, font: str = "F1", size: float = 10, x: float = MARGIN, url: str = ""):
        lead = size * 1.35
        if self.y - lead < MARGIN + 18:
            self._new_page()
        self.y -= lead
        self.page["ops"].append(f"BT /{font} {size:g} Tf {x:.2f} {self.y:.2f} Td {_pdf_str(text)} Tj ET")
        if url:
            w = text_width(text, font, size)
            self.page["annots"].append((x, self.y - 2, x + w, self.y + size, url))

    def para(self, text: str, font="F1", size=10.0, indent=0.0, url="", bullet=""):
        x = MARGIN + indent
        lines = wrap(text, font, size, TEXT_W - indent - (10 if bullet else 0))
        for i, ln in enumerate(lines):
            if bullet and i == 0:
                self.line(bullet, "F1", size, x)
                self.y += size * 1.35          # bullet shares the first line
            self.line(ln, font, size, x + (10 if bullet else 0), url)

    def rule(self):
        self.page["ops"].append(f"0.75 G 0.5 w {MARGIN:.2f} {self.y - 4:.2f} m {PAGE_W - MARGIN:.2f} {self.y - 4:.2f} l S 0 G")
        self.y -= 8


def to_pdf(r: IntelligenceReport) -> bytes:
    lay = _Layout()
    for blk in blocks(r):
        kind = blk[0]
        if kind == "h1":
            lay.para(blk[1], "F2", 17)
            lay.space(4)
        elif kind == "h2":
            lay.space(12)
            lay.para(blk[1], "F2", 13.5)
            lay.rule()
        elif kind == "h3":
            lay.space(6)
            lay.para(blk[1], "F2", 10.5)
        elif kind == "p":
            lay.para(blk[1])
            lay.space(3)
        elif kind in ("li", "ref"):
            lay.para(blk[1], indent=8, bullet="•")
        elif kind == "kv":
            lay.para(f"{blk[1]}: {blk[2]}", indent=8)
        elif kind == "url":
            href = safe_href(blk[2])
            lay.para(f"{blk[1]}:", indent=8)
            lay.para(blk[2], "F3", 8.5, indent=18, url=href)
        elif kind == "pre":
            lay.para(blk[1][:6000], "F3", 8, indent=18)
            lay.space(2)

    ref = r.overview.get("reference", "")
    total = len(lay.pages)
    for n, page in enumerate(lay.pages, 1):
        footer = f"TRACEPOINT Intelligence Report {ref} - status {r.status} - page {n} of {total}"
        page["ops"].append(f"0.4 g BT /F1 8 Tf {MARGIN:.2f} {MARGIN - 20:.2f} Td {_pdf_str(footer)} Tj ET 0 g")

    # --- serialize -------------------------------------------------------------------------------------------------
    objs: list[str] = []

    def add(body: str) -> int:
        objs.append(body)
        return len(objs)

    catalog = add("")                       # filled below
    pages_id = add("")
    font_ids = {k: add(f"<< /Type /Font /Subtype /Type1 /BaseFont /{v} /Encoding /WinAnsiEncoding >>")
                for k, v in _FONTS.items()}
    fonts = " ".join(f"/{k} {i} 0 R" for k, i in font_ids.items())
    page_ids = []
    for page in lay.pages:
        stream = "\n".join(page["ops"])
        content = add(f"<< /Length {len(stream.encode('latin-1'))} >>\nstream\n{stream}\nendstream")
        annots = [add(f"<< /Type /Annot /Subtype /Link /Rect [{x1:.2f} {y1:.2f} {x2:.2f} {y2:.2f}] /Border [0 0 0] "
                      f"/A << /S /URI /URI {_uri_str(u)} >> >>") for x1, y1, x2, y2, u in page["annots"]]
        annot_part = f" /Annots [{' '.join(f'{a} 0 R' for a in annots)}]" if annots else ""
        page_ids.append(add(f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_W:g} {PAGE_H:g}] "
                            f"/Resources << /Font << {fonts} >> >> /Contents {content} 0 R{annot_part} >>"))
    objs[catalog - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>"
    objs[pages_id - 1] = f"<< /Type /Pages /Kids [{' '.join(f'{p} 0 R' for p in page_ids)}] /Count {len(page_ids)} >>"
    info = add(f"<< /Title {_pdf_str('TRACEPOINT Intelligence Report ' + ref)} /Producer (TRACEPOINT) >>")

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, 1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{body}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode("latin-1")
    out += "".join(f"{o:010d} 00000 n \n" for o in offsets).encode("latin-1")
    out += (f"trailer\n<< /Size {len(objs) + 1} /Root {catalog} 0 R /Info {info} 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n").encode("latin-1")
    return bytes(out)
