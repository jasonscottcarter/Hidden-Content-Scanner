"""Detect hidden content in HTML (email bodies, .html files, Word altChunks)."""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlparse

from .core import (HIGH, MEDIUM, LOW, INFO, WHITE, INVISIBLE_CONTRAST, analyze_text, contrast, parse_hex, hexs)

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
        "track", "wbr", "keygen"}
SKIP_TEXT = {"script", "style", "head", "title"}

CSS_NAMED = {
    "white": (255, 255, 255), "black": (0, 0, 0), "red": (255, 0, 0), "blue": (0, 0, 255), "green": (0, 128, 0),
    "yellow": (255, 255, 0), "gray": (128, 128, 128), "grey": (128, 128, 128), "silver": (192, 192, 192),
    "whitesmoke": (245, 245, 245), "snow": (255, 250, 250), "ivory": (255, 255, 240), "ghostwhite": (248, 248, 255),
    "navy": (0, 0, 128), "orange": (255, 165, 0), "purple": (128, 0, 128), "linen": (250, 240, 230),
    "floralwhite": (255, 250, 240), "azure": (240, 255, 255), "mintcream": (245, 255, 250),
}


def css_color(v):
    """Returns (rgb or None, transparent_bool)."""
    if not v:
        return None, False
    v = v.strip().lower().replace("!important", "").strip()
    if v == "transparent":
        return None, True
    if v.startswith("#"):
        return parse_hex(v[1:7] if len(v) in (7, 9) else v[1:4]), (len(v) == 9 and v[7:9] == "00")
    m = re.match(r"rgba?\(\s*([\d.]+)%?\s*[, ]\s*([\d.]+)%?\s*[, ]\s*([\d.]+)%?\s*(?:[,/]\s*([\d.]+)(%?))?\s*\)", v)
    if m:
        rgb = tuple(min(255, int(float(m.group(i)))) for i in (1, 2, 3))
        transparent = False
        if m.group(4) is not None:
            a = float(m.group(4)) / (100 if m.group(5) else 1)
            transparent = a < 0.1
        return rgb, transparent
    return CSS_NAMED.get(v), False


def parse_style(s):
    d = {}
    for part in (s or "").split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            d[k.strip().lower()] = v.strip().lower()
    return d


def _len_px(v):
    m = re.match(r"(-?[\d.]+)\s*(px|pt|em|rem|%|in|cm|mm)?", v or "")
    if not m:
        return None
    n = float(m.group(1))
    unit = m.group(2) or "px"
    return n * {"px": 1, "pt": 1.33, "em": 16, "rem": 16, "%": 0.16, "in": 96, "cm": 37.8, "mm": 3.78}[unit]


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []  # (tag, reasons, color, bg)
        self.css = {}  # selector -> decl dict
        self.visible = []
        self.hidden = {}  # reasons tuple -> [text]
        self.comments = []
        self.hidden_inputs = []
        self.images = []
        self.links = []
        self.meta = []
        self.scripts = 0
        self.forms = 0
        self._in_style = False
        self._style_buf = []
        self._link = None

    # current state
    def _top(self):
        if self.stack:
            return self.stack[-1]
        return ("", (), None, WHITE)

    def _decls(self, tag, attrs):
        d = {}
        d.update(self.css.get(tag, {}))
        for cls in (attrs.get("class") or "").split():
            d.update(self.css.get("." + cls, {}))
            d.update(self.css.get(f"{tag}.{cls}", {}))
        if attrs.get("id"):
            d.update(self.css.get("#" + attrs["id"], {}))
        d.update(parse_style(attrs.get("style")))
        return d

    def handle_starttag(self, tag, attrs_list):
        attrs = {k.lower(): (v or "") for k, v in attrs_list}
        _, preasons, pcolor, pbg = self._top()
        reasons = list(preasons)
        color, bg = pcolor, pbg
        d = self._decls(tag, attrs)

        if "hidden" in attrs:
            reasons.append("hidden attribute")
        if d.get("display", "").startswith("none"):
            reasons.append("display:none")
        if d.get("visibility", "").startswith(("hidden", "collapse")):
            reasons.append("visibility:hidden")
        if d.get("mso-hide", "").startswith("all"):
            reasons.append("mso-hide:all (hidden in Outlook)")
        op = d.get("opacity")
        if op is not None:
            try:
                if float(op.rstrip("%")) / (100 if op.endswith("%") else 1) < 0.1:
                    reasons.append(f"opacity:{op}")
            except ValueError:
                pass
        fs = d.get("font-size")
        if fs is not None:
            px = _len_px(fs)
            if px is not None and px <= 2:
                reasons.append(f"font-size:{fs}")
        for prop in ("max-height", "height", "max-width", "width"):
            if prop in d and (_len_px(d[prop]) or 1) <= 1 and d.get("overflow", "").startswith("hidden"):
                reasons.append(f"{prop}:{d[prop]} with overflow:hidden")
                break
        if d.get("position", "") in ("absolute", "fixed"):
            for prop in ("left", "top", "margin-left", "margin-top"):
                px = _len_px(d.get(prop, ""))
                if px is not None and px <= -500:
                    reasons.append(f"positioned off-screen ({prop}:{d[prop]})")
                    break
        ti = _len_px(d.get("text-indent", ""))
        if ti is not None and ti <= -500:
            reasons.append(f"text-indent:{d['text-indent']}")
        if re.search(r"scale\(\s*0(\.0+)?\s*[,)]", d.get("transform", "")):
            reasons.append("transform:scale(0)")
        if re.search(r"rect\(\s*0(px)?[ ,]+0(px)?[ ,]+0(px)?[ ,]+0", d.get("clip", "")):
            reasons.append("clip:rect(0,0,0,0)")
        if tag == "template":
            reasons.append("<template> (never rendered)")

        for key in ("background-color", "background"):
            if key in d:
                c, transp = css_color(d[key].split()[0] if d[key] else "")
                if c:
                    bg = c
        if attrs.get("bgcolor"):
            c, _ = css_color(attrs["bgcolor"])
            bg = c or bg
        if "color" in d:
            c, transp = css_color(d["color"])
            if transp:
                reasons.append("color:transparent")
            color = c or color
        if tag == "font" and attrs.get("color"):
            c, _ = css_color(attrs["color"])
            color = c or color
        if tag == "font" and attrs.get("size") in ("0", "-7", "-6"):
            reasons.append(f"<font size={attrs['size']}>")

        if tag == "style":
            self._in_style = True
            self._style_buf = []
        elif tag == "script":
            self.scripts += 1
        elif tag == "form":
            self.forms += 1
        elif tag == "input" and attrs.get("type", "").lower() == "hidden" and attrs.get("value"):
            self.hidden_inputs.append(f"{attrs.get('name', '?')}={attrs['value']}")
        elif tag == "img":
            self.images.append((attrs, tuple(reasons)))
        elif tag == "meta" and attrs.get("content"):
            self.meta.append(f"{attrs.get('name') or attrs.get('property') or attrs.get('http-equiv') or '?'}: {attrs['content']}")
        elif tag == "a" and attrs.get("href"):
            self._link = [attrs["href"], []]

        if tag not in VOID:
            self.stack.append((tag, tuple(dict.fromkeys(reasons)), color, bg))

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_endtag(self, tag):
        if tag == "style" and self._in_style:
            self._in_style = False
            self._parse_css("".join(self._style_buf))
        if tag == "a" and self._link:
            self.links.append((self._link[0], "".join(self._link[1]).strip()))
            self._link = None
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        if self._in_style:
            self._style_buf.append(data)
            return
        if any(t in SKIP_TEXT for t, *_ in self.stack):
            return
        if self._link is not None:
            self._link[1].append(data)
        if not data.strip():
            self.visible.append(data)
            return
        _, reasons, color, bg = self._top()
        reasons = list(reasons)
        if color and bg:
            cr = contrast(color, bg)
            if cr < INVISIBLE_CONTRAST:
                reasons.append(f"text color {hexs(color)} on background {hexs(bg)} (contrast {cr:.2f}:1)")
        if reasons:
            self.hidden.setdefault(tuple(reasons), []).append(data)
        else:
            self.visible.append(data)

    def handle_comment(self, data):
        if data.strip() and not data.strip().startswith(("[if", "<![endif]", "[endif]")):
            self.comments.append(data.strip())

    def _parse_css(self, css):
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        css = re.sub(r"@media[^{]*\{", "", css)  # flatten media queries (approximation)
        for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
            decl = parse_style(body)
            for s in sel.split(","):
                s = s.strip().lower()
                if re.fullmatch(r"[a-z0-9]*([.#][\w-]+)?", s):
                    self.css.setdefault(s, {}).update(decl)


def ws(s):
    return re.sub(r"\s+", " ", s).strip()


def scan_html(report, html: str, location: str, is_email=False):
    """Analyze HTML. Returns visible text (for comparisons, e.g. email plain vs HTML parts)."""
    p = _Parser()
    try:
        p.feed(html)
        p.close()
    except Exception as e:  # malformed HTML
        report.error(f"{location}: HTML parse problem: {e}")

    visible = ws("".join(p.visible))
    hidden_all = []
    for reasons, chunks in p.hidden.items():
        txt = ws(" ".join(chunks))
        if not re.search(r"\w{2,}", txt):
            continue
        hidden_all.append(txt)
        preheader = is_email and len(txt) <= 160 and any("display:none" in r or "mso-hide" in r or "max-height" in r
                                                         for r in reasons)
        sev = MEDIUM if preheader or len(txt) < 40 else HIGH
        note = " (short display:none text is often a harmless email 'preheader')" if preheader else ""
        report.add(sev, "Hidden HTML text", location, "Text hidden by: " + "; ".join(reasons) + note, txt)
    if hidden_all:
        analyze_text(report, "\n".join(hidden_all), location, hidden=True, context="hidden HTML")

    if p.comments:
        joined = "\n".join(p.comments)
        if re.search(r"[A-Za-z]{3,}.*\s+[A-Za-z]{3,}", joined):
            report.add(LOW, "HTML comments", location,
                       f"{len(p.comments)} HTML comment(s) - not rendered, but read by AI tools that ingest raw HTML.",
                       joined)
            analyze_text(report, joined, location, hidden=True, context="HTML comment")
    if p.hidden_inputs:
        report.add(MEDIUM, "Hidden form fields", location, f"{len(p.hidden_inputs)} hidden input field(s) with values.",
                   "\n".join(p.hidden_inputs))
        analyze_text(report, "\n".join(p.hidden_inputs), location, hidden=True, context="hidden input")
    if p.meta:
        analyze_text(report, "\n".join(p.meta), location, hidden=True, context="meta tags")
    if p.scripts:
        report.add(HIGH if is_email else MEDIUM, "Script in HTML", location, f"{p.scripts} <script> element(s).")
    if p.forms and is_email:
        report.add(MEDIUM, "Form in email", location, "Email body contains an HTML form (credential-phishing technique).")

    # Images: tracking pixels, remote loads, alt text
    remote = []
    for attrs, reasons in p.images:
        src = attrs.get("src", "")
        alt = attrs.get("alt", "")
        if alt:
            analyze_text(report, alt, location, hidden=True, context="image alt text")
        if src.lower().startswith(("http://", "https://", "//")):
            remote.append(src)
            w, h = attrs.get("width", ""), attrs.get("height", "")
            st = parse_style(attrs.get("style"))
            w = w or st.get("width", "")
            h = h or st.get("height", "")
            tiny = all((_len_px(x) if x else 99) <= 2 for x in (w, h)) and (w or h)
            if tiny or reasons:
                report.add(MEDIUM, "Tracking pixel", location,
                           "Tiny or hidden remote image - typically used to track when the message is opened.", src)
        elif src.lower().startswith("data:") and len(src) > 200_000:
            report.add(LOW, "Large inline image", location, f"Inline data-URI image of {len(src):,} chars.")
    if remote:
        report.add(INFO, "Remote images", location, f"{len(remote)} image(s) load from the internet when opened.",
                   "\n".join(dict.fromkeys(remote[:20])))

    # Links whose visible text shows a different domain than the real target
    for href, text in p.links:
        shown = re.search(r"(?:https?://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)", text.lower())
        real = urlparse(href if "://" in href else "http://" + href).hostname or ""
        if shown and real and href.lower().startswith(("http", "//")):
            sd = shown.group(1)
            if not (real.endswith(sd) or sd.endswith(real)) and "." in sd:
                report.add(MEDIUM, "Deceptive link", location, f"Link text shows '{sd}' but points to '{real}'.",
                           f"text: {text}\nhref: {href}")
        if href.lower().startswith(("javascript:", "vbscript:", "file:", "\\\\")):
            report.add(HIGH, "Dangerous link", location, "Link uses a script/file/UNC scheme.", href)

    analyze_text(report, visible, location, hidden=False)
    return visible
