"""Namespace-agnostic XML helpers and Office theme/DrawingML color resolution."""
from __future__ import annotations

import colorsys
import xml.etree.ElementTree as ET

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException

from .core import parse_hex, apply_tint, WHITE, BLACK


class UnsafeXml(Exception):
    """Raised when XML uses DTD entities / external references (XXE, entity bombs)."""


def local(tag):
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def kid(el, name):
    if el is None:
        return None
    for c in el:
        if local(c.tag) == name:
            return c
    return None


def kids(el, name):
    if el is None:
        return []
    return [c for c in el if local(c.tag) == name]


def descs(el, name):
    if el is None:
        return []
    return [d for d in el.iter() if local(d.tag) == name]


def chain(el, *names):
    for n in names:
        el = kid(el, n)
        if el is None:
            return None
    return el


def att(el, name, default=None):
    """Attribute by local name, ignoring namespaces (relationship ids excluded - use rid())."""
    if el is None:
        return default
    if name in el.attrib:
        return el.attrib[name]
    for k, v in el.attrib.items():
        if local(k) == name and "relationships" not in k:
            return v
    return default


def rid(el, name="id"):
    if el is None:
        return None
    for k, v in el.attrib.items():
        if "relationships" in k and local(k) == name:
            return v
    return None


def onoff(el):
    if el is None:
        return None
    v = att(el, "val")
    return v is None or v.lower() not in ("0", "false", "off")


def to_int(v, default=None):
    try:
        return int(float(str(v).rstrip("%")))
    except (TypeError, ValueError):
        return default


def parse_xml(data):
    """Parse untrusted XML safely. Returns None on malformed XML; raises UnsafeXml on entity tricks."""
    try:
        return SafeET.fromstring(data)
    except DefusedXmlException as e:
        raise UnsafeXml(type(e).__name__) from e
    except ET.ParseError:
        return None


def texts(el, tags=("t",)):
    """Concatenate text of descendant elements with the given local names."""
    if el is None:
        return ""
    return "".join((d.text or "") for d in el.iter() if local(d.tag) in tags)


# --------------------------------------------------------------------------------------
# Theme colors
# --------------------------------------------------------------------------------------

DEFAULT_SCHEME = {
    "dk1": BLACK, "lt1": WHITE, "dk2": (0x44, 0x54, 0x6A), "lt2": (0xE7, 0xE6, 0xE6),
    "accent1": (0x44, 0x72, 0xC4), "accent2": (0xED, 0x7D, 0x31), "accent3": (0xA5, 0xA5, 0xA5),
    "accent4": (0xFF, 0xC0, 0x00), "accent5": (0x5B, 0x9B, 0xD5), "accent6": (0x70, 0xAD, 0x47),
    "hlink": (0x05, 0x63, 0xC1), "folHlink": (0x95, 0x4F, 0x72),
}

WORD_THEME_MAP = {
    "dark1": "dk1", "light1": "lt1", "dark2": "dk2", "light2": "lt2",
    "text1": "dk1", "background1": "lt1", "text2": "dk2", "background2": "lt2",
    "hyperlink": "hlink", "followedHyperlink": "folHlink",
}
SCHEME_ALIAS = {"bg1": "lt1", "tx1": "dk1", "bg2": "lt2", "tx2": "dk2"}
EXCEL_THEME_ORDER = ["lt1", "dk1", "lt2", "dk2", "accent1", "accent2", "accent3", "accent4",
                     "accent5", "accent6", "hlink", "folHlink"]

PRESET = {
    "white": WHITE, "black": BLACK, "red": (255, 0, 0), "green": (0, 128, 0), "blue": (0, 0, 255),
    "yellow": (255, 255, 0), "cyan": (0, 255, 255), "magenta": (255, 0, 255), "gray": (128, 128, 128),
    "grey": (128, 128, 128), "silver": (192, 192, 192), "ltgray": (211, 211, 211), "whitesmoke": (245, 245, 245),
    "snow": (255, 250, 250), "ivory": (255, 255, 240), "ghostwhite": (248, 248, 255), "navy": (0, 0, 128),
}

WORD_HIGHLIGHT = {
    "yellow": (255, 255, 0), "green": (0, 255, 0), "cyan": (0, 255, 255), "magenta": (255, 0, 255),
    "blue": (0, 0, 255), "red": (255, 0, 0), "darkBlue": (0, 0, 128), "darkCyan": (0, 128, 128),
    "darkGreen": (0, 128, 0), "darkMagenta": (128, 0, 128), "darkRed": (128, 0, 0), "darkYellow": (128, 128, 0),
    "darkGray": (128, 128, 128), "lightGray": (192, 192, 192), "black": BLACK, "white": WHITE,
}

_IDX = """000000 FFFFFF FF0000 00FF00 0000FF FFFF00 FF00FF 00FFFF
000000 FFFFFF FF0000 00FF00 0000FF FFFF00 FF00FF 00FFFF
800000 008000 000080 808000 800080 008080 C0C0C0 808080
9999FF 993366 FFFFCC CCFFFF 660066 FF8080 0066CC CCCCFF
000080 FF00FF FFFF00 00FFFF 800080 800000 008080 0000FF
00CCFF CCFFFF CCFFCC FFFF99 99CCFF FF99CC CC99FF FFCC99
3366FF 33CCCC 99CC00 FFCC00 FF9900 FF6600 666699 969696
003366 339966 003300 333300 993300 993366 333399 333333""".split()
EXCEL_INDEXED = [parse_hex(h) for h in _IDX]


class Theme:
    def __init__(self, root=None):
        self.c = dict(DEFAULT_SCHEME)
        if root is None:
            return
        cs = next(iter(descs(root, "clrScheme")), None)
        if cs is None:
            return
        for ch in cs:
            name = local(ch.tag)
            for cc in ch:
                n = local(cc.tag)
                rgb = None
                if n == "srgbClr":
                    rgb = parse_hex(att(cc, "val"))
                elif n == "sysClr":
                    rgb = parse_hex(att(cc, "lastClr")) or (WHITE if att(cc, "val") == "window" else BLACK)
                if rgb:
                    self.c[name] = rgb

    def scheme(self, val):
        if not val:
            return None
        return self.c.get(SCHEME_ALIAS.get(val, val))

    def word(self, theme_color, tint=None, shade=None):
        rgb = self.c.get(WORD_THEME_MAP.get(theme_color, theme_color))
        if rgb is None:
            return None
        try:
            if tint:
                f = int(tint, 16) / 255
                rgb = tuple(int(v + (255 - v) * (1 - f)) for v in rgb)
            if shade:
                f = int(shade, 16) / 255
                rgb = tuple(int(v * f) for v in rgb)
        except ValueError:
            pass
        return rgb

    def excel(self, idx, tint=None):
        try:
            rgb = self.c.get(EXCEL_THEME_ORDER[int(idx)])
        except (ValueError, IndexError):
            return None
        try:
            return apply_tint(rgb, float(tint)) if tint else rgb
        except ValueError:
            return rgb


def dml_color(container, theme):
    """Resolve a DrawingML color inside `container` (e.g. a:solidFill). Returns (rgb, alpha_percent)."""
    if container is None:
        return None, None
    for ch in container:
        n = local(ch.tag)
        rgb = None
        if n == "srgbClr":
            rgb = parse_hex(att(ch, "val"))
        elif n == "schemeClr":
            rgb = theme.scheme(att(ch, "val")) if att(ch, "val") != "phClr" else None
        elif n == "sysClr":
            rgb = parse_hex(att(ch, "lastClr")) or (WHITE if att(ch, "val") == "window" else BLACK)
        elif n == "prstClr":
            rgb = PRESET.get((att(ch, "val") or "").lower())
        elif n == "scrgbClr":
            try:
                rgb = tuple(int(int(att(ch, k)) / 100000 * 255) for k in ("r", "g", "b"))
            except (TypeError, ValueError):
                rgb = None
        else:
            continue
        if rgb is None:
            return None, None
        alpha = 100.0
        lum_mod = lum_off = None
        for m in ch:
            mn = local(m.tag)
            v = to_int(att(m, "val"))
            if v is None:
                continue
            f = v / 100000
            if mn == "alpha":
                alpha = f * 100
            elif mn == "lumMod":
                lum_mod = f
            elif mn == "lumOff":
                lum_off = f
            elif mn == "tint":
                rgb = tuple(int(255 * (1 - f) + c * f) for c in rgb)
            elif mn == "shade":
                rgb = tuple(int(c * f) for c in rgb)
        if lum_mod is not None or lum_off is not None:
            h, l, s = colorsys.rgb_to_hls(*(c / 255 for c in rgb))
            l = min(1.0, max(0.0, l * (lum_mod if lum_mod is not None else 1) + (lum_off or 0)))
            rgb = tuple(int(round(c * 255)) for c in colorsys.hls_to_rgb(h, l, s))
        return rgb, alpha
    return None, None
