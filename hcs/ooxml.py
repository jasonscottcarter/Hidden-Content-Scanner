"""Office Open XML scanner: .docx/.docm/.dotx, .xlsx/.xlsm/.xltx, .pptx/.pptm/.ppsx/.potx (and macro variants)."""
from __future__ import annotations

import io
import posixpath
import re
import struct
import zipfile
from collections import namedtuple
from urllib.parse import unquote

from .core import (HIGH, MEDIUM, LOW, INFO, WHITE, INVISIBLE_CONTRAST, analyze_text, contrast, hexs, parse_hex,
                   check_image_trailer, printable_strings, clip, read_zip_member)
from .xmlutil import (local, kid, kids, descs, chain, att, rid, onoff, to_int, parse_xml, texts, Theme, dml_color,
                      WORD_HIGHLIGHT, EXCEL_INDEXED, UnsafeXml)
from . import htmlscan

IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".emf", ".wmf", ".svg", ".webp")
DANGEROUS_EXT = (".exe", ".dll", ".scr", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta", ".lnk",
                 ".msi", ".jar", ".wsf", ".cpl", ".com", ".pif", ".iso", ".img")


# ======================================================================================
# ZIP container checks (shared with ODF and generic ZIPs)
# ======================================================================================

def check_zip_container(report, raw: bytes, label="ZIP container"):
    """Look for data hidden in the ZIP structure itself: appended/prepended bytes, gaps, comments, duplicates."""
    eocd = raw.rfind(b"PK\x05\x06")
    if eocd < 0 or len(raw) < eocd + 22:
        report.error("ZIP end-of-central-directory record not found")
        return
    cd_size, cd_off, clen = struct.unpack("<IIH", raw[eocd + 12:eocd + 22])
    end = eocd + 22 + clen
    comment = raw[eocd + 22:end]
    if comment.strip(b"\x00 "):
        txt = comment.decode("utf-8", "replace")
        report.add(MEDIUM, "ZIP comment", label, f"Archive carries a {len(comment)}-byte comment (not visible in Office).", txt)
        analyze_text(report, txt, label + " comment", hidden=True)
    if len(raw) > end:
        extra = raw[end:]
        if extra.strip(b"\x00"):
            report.add(HIGH, "Data appended after file end", label,
                       f"{len(extra):,} bytes follow the end of the ZIP structure. Office ignores them; they can hold any hidden payload.",
                       "\n".join(printable_strings(extra, limit=15)))
            analyze_text(report, extra.decode("utf-8", "ignore"), label + " appended data", hidden=True)
    if raw[:4] != b"PK\x03\x04":
        first = raw.find(b"PK\x03\x04")
        report.add(HIGH, "Data prepended before ZIP", label,
                   f"{first if first > 0 else '?'} bytes precede the first ZIP entry (polyglot / hidden payload).",
                   "\n".join(printable_strings(raw[:max(first, 0)][:4096], limit=10)))

    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as e:
        report.error(f"Bad ZIP: {e}")
        return
    infos = z.infolist()
    names = [i.filename for i in infos]
    dups = {n for n in names if names.count(n) > 1}
    if dups:
        report.add(HIGH, "Duplicate ZIP entries", label,
                   "The same part name appears more than once - different tools may read different copies.", ", ".join(dups))
    for i in infos:
        if i.comment:
            report.add(MEDIUM, "ZIP entry comment", f"{label}: {i.filename}", "Hidden comment attached to archive entry.",
                       i.comment.decode("utf-8", "replace"))
        if i.flag_bits & 0x1:
            report.add(MEDIUM, "Encrypted ZIP entry", f"{label}: {i.filename}", "Entry is password-encrypted inside the package.")

    # Gaps between entries ("slack" inside the ZIP that no directory entry points to)
    try:
        spans = []
        for i in infos:
            off = i.header_offset
            if raw[off:off + 4] != b"PK\x03\x04":
                continue
            fnl, exl = struct.unpack("<HH", raw[off + 26:off + 30])
            data_end = off + 30 + fnl + exl + i.compress_size
            if i.flag_bits & 0x08:
                data_end += 16 if raw[data_end:data_end + 4] == b"PK\x07\x08" else 12
            spans.append((off, data_end, i.filename))
        spans.sort()
        boundaries = spans + [(cd_off, cd_off, "<central directory>")]
        hidden_gaps = []
        for (s1, e1, n1), (s2, _, n2) in zip(boundaries, boundaries[1:]):
            if s2 > e1:
                gap = raw[e1:s2]
                if gap.strip(b"\x00"):
                    hidden_gaps.append((n1, n2, gap))
        for n1, n2, gap in hidden_gaps[:10]:
            report.add(HIGH, "Hidden data between ZIP entries", label,
                       f"{len(gap):,} unreferenced bytes between '{n1}' and '{n2}' (invisible to Office and archive tools).",
                       "\n".join(printable_strings(gap, limit=10)))
    except Exception as e:  # zip64 or odd layouts
        report.error(f"ZIP gap analysis skipped: {e}")


# ======================================================================================
# Package model
# ======================================================================================

class Package:
    def __init__(self, raw, report):
        self.report = report
        self.z = zipfile.ZipFile(io.BytesIO(raw))
        self.names = [i.filename for i in self.z.infolist()]
        self.nameset = set(self.names)
        self.lower = {n.lower(): n for n in self.names}
        self._xml = {}
        self._rels = {}
        self._read_once = set()
        self.handled = set()

    def resolve(self, n):
        return n if n in self.nameset else self.lower.get(n.lower(), n)

    def read(self, n):
        n = self.resolve(n)
        if n not in self.nameset:
            return b""
        if n in self._read_once:  # already charged to the budget; parts are re-read by several checks
            info = self.z.getinfo(n)
            with self.z.open(info) as f:
                return f.read(info.file_size)
        try:
            data = read_zip_member(self.z, n)
        except Exception:
            return b""
        self._read_once.add(n)
        return data

    def xml(self, n):
        if not n:
            return None
        n = self.resolve(n)
        if n not in self._xml:
            root = None
            if n in self.nameset:
                try:
                    root = parse_xml(self.read(n))
                except UnsafeXml as e:
                    self.report.add(HIGH, "Malicious XML construct", n,
                                    f"Part uses DTD/entity declarations ({e}) - XXE or entity-expansion attack; part not parsed.")
            self._xml[n] = root
        return self._xml[n]

    def rels(self, part):
        if part in self._rels:
            return self._rels[part]
        d, b = posixpath.split(part)
        rp = posixpath.join(d, "_rels", b + ".rels")
        out = []
        root = self.xml(rp)
        if root is not None:
            for r in root:
                if local(r.tag) != "Relationship":
                    continue
                ext = (r.get("TargetMode") or "").lower() == "external"
                raw_t = r.get("Target") or ""
                if ext:
                    t = raw_t
                else:
                    t = unquote(raw_t.split("#")[0])
                    t = t[1:] if t.startswith("/") else posixpath.normpath(posixpath.join(d, t))
                    t = self.resolve(t)
                out.append(dict(id=r.get("Id"), type=(r.get("Type") or "").rsplit("/", 1)[-1], target=t,
                                raw=raw_t, external=ext, source=part))
        self._rels[part] = out
        return out

    def rel_map(self, part):
        return {r["id"]: r for r in self.rels(part)}

    def rel_targets(self, part, typ):
        return [r["target"] for r in self.rels(part) if r["type"] == typ and not r["external"]]

    def main_part(self):
        for r in self.rels(""):
            if r["type"] == "officeDocument" and not r["external"]:
                return r["target"]
        return None

    def all_rels(self):
        for n in self.names:
            if n.endswith(".rels") and "/_rels/" in "/" + n:
                d = posixpath.dirname(posixpath.dirname(n))
                b = posixpath.basename(n)[:-5]
                src = f"{d}/{b}" if d and b else (b or d)
                yield from self.rels(src)


# ======================================================================================
# Package-level checks
# ======================================================================================

EXTERNAL_TYPES = {
    "attachedTemplate": (HIGH, "Remote template", "Document loads a template from an external location (template-injection technique)."),
    "oleObject": (HIGH, "External OLE object", "Linked OLE object loaded from an external location."),
    "frame": (HIGH, "External frame", "Frame content is loaded from an external location."),
    "subDocument": (HIGH, "External sub-document", "Master document pulls in an external sub-document."),
    "aFChunk": (HIGH, "External content chunk", "altChunk content is loaded from an external location."),
    "image": (MEDIUM, "Remote image", "Image is fetched from the internet when opened (web beacon / tracking, NTLM leak if UNC)."),
    "externalLinkPath": (MEDIUM, "External workbook link", "Workbook links to cells in another file."),
    "xlExternalLinkPath/xlPathMissing": (MEDIUM, "External workbook link", "Workbook links to a missing external file."),
    "audio": (MEDIUM, "Remote media", "Audio loaded from an external location."),
    "video": (MEDIUM, "Remote media", "Video loaded from an external location."),
}


def scan_package_level(pkg: Package, report, nested):
    hyperlinks = []
    for r in pkg.all_rels():
        if r["external"]:
            tgt = r["raw"]
            low = tgt.lower()
            if r["type"] == "hyperlink":
                hyperlinks.append(tgt)
                if low.startswith(("javascript:", "vbscript:", "file:", "\\\\", "mhtml:", "ms-msdt:", "search-ms:",
                                   "ms-officecmd:")):
                    report.add(HIGH, "Dangerous hyperlink", r["source"], "Hyperlink uses a script/file/protocol-handler scheme.", tgt)
                continue
            sev, cat, desc = EXTERNAL_TYPES.get(r["type"], (MEDIUM, "External reference", f"External '{r['type']}' relationship."))
            if low.startswith(("\\\\", "file:")) or re.match(r"^[a-z]:\\", low):
                sev, desc = HIGH, desc + " Points to a file/UNC path (can leak Windows credentials)."
            if "mhtml:" in low or "!x-usc:" in low or "ms-msdt" in low:
                sev, desc = HIGH, desc + " Uses an exploit-associated URL scheme."
            report.add(sev, cat, r["source"], desc, tgt)
        else:
            if r["target"] not in pkg.nameset and r["type"] not in ("hyperlink",):
                pass  # dangling internal reference - harmless
    if hyperlinks:
        report.add(INFO, "Hyperlinks", "package", f"{len(hyperlinks)} external hyperlink(s).",
                   "\n".join(dict.fromkeys(hyperlinks[:40])))

    # Orphaned parts: present in the ZIP but not referenced by any relationship
    referenced = {r["target"] for r in pkg.all_rels() if not r["external"]}
    for n in pkg.names:
        if n.endswith("/") or n == "[Content_Types].xml" or n.endswith(".rels") or n in referenced:
            continue
        low = n.lower()
        if low.startswith("[trash]/"):
            report.add(MEDIUM, "Deleted parts retained ([trash])", n, "Leftover part from an earlier edit is still stored in the file.")
        data = pkg.read(n)
        snippet = ""
        if low.endswith((".xml", ".txt", ".htm", ".html", ".json", ".csv", ".vml")):
            try:
                root = parse_xml(data) if low.endswith((".xml", ".vml")) else None
            except UnsafeXml:
                root = None
            snippet = " ".join(root.itertext()) if root is not None else data.decode("utf-8", "replace")
            analyze_text(report, snippet, n, hidden=True, context="orphaned part")
            pkg.handled.add(n)
        elif not low.endswith(IMAGE_EXT):
            snippet = "\n".join(printable_strings(data, limit=10))
        report.add(MEDIUM if not low.endswith(IMAGE_EXT) else LOW, "Orphaned part", n,
                   f"{len(data):,}-byte part is stored in the package but nothing references it - Office never shows it.", snippet)

    for n in pkg.names:
        low = n.lower()
        data = None
        if low.endswith(DANGEROUS_EXT):
            report.add(HIGH, "Executable content in package", n, "Package contains a file with an executable/script extension.")
        if low.endswith("vbaproject.bin"):
            data = pkg.read(n)
            report.add(HIGH, "VBA macros", n, "Document contains a VBA macro project.")
            from .legacy import analyze_vba
            analyze_vba(report, data, n)
        elif "/embeddings/" in low or "/activex/" in low and low.endswith(".bin"):
            data = pkg.read(n)
            kind = "ActiveX control" if "/activex/" in low else "Embedded object"
            report.add(MEDIUM, kind, n, f"{kind} ({len(data):,} bytes) - scanned recursively below.")
            nested(posixpath.basename(n), data)
        elif "/activex/" in low and low.endswith(".xml"):
            root = pkg.xml(n)
            report.add(MEDIUM, "ActiveX control", n, f"ActiveX control (classid {att(root, 'classid', '?')}).")
            pkg.handled.add(n)
        elif low.startswith("customxml/item") and not low.startswith("customxml/itemprops") and low.endswith(".xml"):
            root = pkg.xml(n)
            txt = " ".join(t.strip() for t in root.itertext() if t.strip()) if root is not None else ""
            if txt:
                report.add(LOW, "Custom XML data", n, "Custom XML data part (not displayed in the document).", txt)
                analyze_text(report, txt, n, hidden=True, context="custom XML")
            pkg.handled.add(n)
        elif low.startswith("customui/"):
            root = pkg.xml(n)
            cb = sorted({v for el in (root.iter() if root is not None else []) for k, v in el.attrib.items()
                         if k in ("onLoad", "onAction", "getVisible", "getEnabled")})
            report.add(LOW if not cb else MEDIUM, "Custom ribbon UI", n,
                       "Custom ribbon definition" + (" with macro callbacks: " + ", ".join(cb) if cb else "."))
            pkg.handled.add(n)
        elif low.endswith(IMAGE_EXT):
            data = pkg.read(n)
            extra = check_image_trailer(report, data, n)
            if extra and extra[:2] == b"PK":
                nested(posixpath.basename(n) + ".appended.zip", extra)

    scan_doc_props(pkg, report)


def scan_doc_props(pkg, report):
    meta = []
    for part, fields in (("docProps/core.xml", ("title", "subject", "creator", "keywords", "description",
                                                "lastModifiedBy", "revision", "created", "modified", "category",
                                                "contentStatus", "identifier")),
                         ("docProps/app.xml", ("Application", "AppVersion", "Company", "Manager", "Template",
                                               "TotalTime", "HyperlinkBase"))):
        root = pkg.xml(part)
        if root is None:
            continue
        pkg.handled.add(pkg.resolve(part))
        for el in root:
            n = local(el.tag)
            if n in fields and (el.text or "").strip():
                meta.append(f"{n}: {el.text.strip()}")
                if n in ("description", "keywords", "subject", "title", "category", "Manager", "Company"):
                    analyze_text(report, el.text, f"{part} [{n}]", hidden=True, context="document property")
    if meta:
        report.add(INFO, "Document metadata", "docProps", "Author / revision metadata stored in the file.", "\n".join(meta))
    root = pkg.xml("docProps/custom.xml")
    if root is not None:
        pkg.handled.add(pkg.resolve("docProps/custom.xml"))
        props = []
        for p in kids(root, "property"):
            val = " ".join(t for t in p.itertext())
            props.append(f"{att(p, 'name')}: {val}")
            analyze_text(report, val, f"custom property '{att(p, 'name')}'", hidden=True)
        if props:
            report.add(LOW, "Custom document properties", "docProps/custom.xml",
                       f"{len(props)} custom propert(ies) - invisible unless you open File > Properties.", "\n".join(props))


# ======================================================================================
# Word
# ======================================================================================

def word_rpr_props(rpr, theme):
    d = {}
    if rpr is None:
        return d
    for ch in rpr:
        n = local(ch.tag)
        if n == "vanish":
            d["vanish"] = onoff(ch)
        elif n == "webHidden":
            d["webHidden"] = onoff(ch)
        elif n == "color":
            tc = att(ch, "themeColor")
            if tc:
                d["color"] = theme.word(tc, att(ch, "themeTint"), att(ch, "themeShade"))
            else:
                v = att(ch, "val")
                d["color"] = None if not v or v.lower() == "auto" else parse_hex(v)
        elif n == "sz":
            d["sz"] = to_int(att(ch, "val"))
        elif n == "w":
            d["w"] = to_int(att(ch, "val"))
        elif n == "spacing":
            d["spacing"] = to_int(att(ch, "val"))
        elif n == "position":
            d["position"] = to_int(att(ch, "val"))
        elif n == "highlight":
            d["highlight"] = att(ch, "val")
        elif n == "shd":
            d["shd"] = word_shd(ch, theme)
    return d


def word_shd(el, theme):
    if el is None:
        return None
    val, fill, color = att(el, "val", ""), att(el, "fill"), att(el, "color")
    if att(el, "themeFill"):
        return theme.word(att(el, "themeFill"), att(el, "themeFillTint"), att(el, "themeFillShade"))
    if val == "solid" and color and color.lower() != "auto":
        return parse_hex(color)
    if fill and fill.lower() != "auto":
        return parse_hex(fill)
    return None


class WordStyles:
    def __init__(self, root, theme):
        self.theme = theme
        self.defaults = {}
        self.styles = {}
        self.default_para = None
        self._cache = {}
        if root is None:
            return
        self.defaults = word_rpr_props(chain(root, "docDefaults", "rPrDefault", "rPr"), theme)
        for s in kids(root, "style"):
            sid = att(s, "styleId")
            self.styles[sid] = (att(kid(s, "basedOn"), "val"), word_rpr_props(kid(s, "rPr"), theme))
            if att(s, "type") == "paragraph" and att(s, "default") in ("1", "true"):
                self.default_para = sid

    def resolve(self, sid, depth=0):
        if not sid or sid not in self.styles or depth > 25:
            return {}
        if sid in self._cache:
            return self._cache[sid]
        base, props = self.styles[sid]
        d = dict(self.resolve(base, depth + 1))
        d.update(props)
        self._cache[sid] = d
        return d

    def effective(self, pstyle, rpr):
        d = dict(self.defaults)
        d.update(self.resolve(pstyle or self.default_para))
        rs = att(kid(rpr, "rStyle"), "val") if rpr is not None else None
        if rs:
            d.update(self.resolve(rs))
        d.update(word_rpr_props(rpr, self.theme))
        return d


Ctx = namedtuple("Ctx", "bg reasons deleted styled_table")


class Para:
    __slots__ = ("pstyle", "segs", "instr", "ctx")

    def __init__(self, pstyle, ctx):
        self.pstyle = pstyle
        self.segs = []
        self.instr = ""
        self.ctx = ctx


FIELD_RULES = [
    (r"\bDDE(AUTO)?\b", HIGH, "DDE field - can launch programs when the document opens."),
    (r"\bINCLUDETEXT\b", HIGH, "INCLUDETEXT field - pulls text from another (possibly remote) file."),
    (r"\bINCLUDEPICTURE\b.*(https?://|\\\\)", MEDIUM, "INCLUDEPICTURE field loads a remote image (tracking / credential leak)."),
    (r"\bLINK\b\s+\S", MEDIUM, "LINK field to an external object."),
    (r"\bIMPORT\b", MEDIUM, "IMPORT field pulls in an external file."),
    (r"\\\\[\w.-]+\\", MEDIUM, "Field references a UNC network path (can leak Windows credentials)."),
]


class WordScanner:
    def __init__(self, pkg, report, main, nested):
        self.pkg, self.report, self.main, self.nested = pkg, report, main, nested
        mr = pkg.rels(main)
        theme_part = next((r["target"] for r in mr if r["type"] == "theme"), None)
        self.theme = Theme(pkg.xml(theme_part))
        self.styles = WordStyles(pkg.xml(next((r["target"] for r in mr if r["type"] == "styles"), None)), self.theme)
        root = pkg.xml(main)
        self.page_bg = WHITE
        self.page_w, self.page_h = 12240 * 635, 15840 * 635
        if root is not None:
            bg = kid(root, "background")
            if bg is not None:
                c = theme_part and att(bg, "themeColor")
                self.page_bg = (self.theme.word(c) if c else parse_hex(att(bg, "color") or "")) or WHITE
            sect = descs(root, "sectPr")
            if sect:
                pg = kid(sect[-1], "pgSz")
                self.page_w = (to_int(att(pg, "w"), 12240) or 12240) * 635
                self.page_h = (to_int(att(pg, "h"), 15840) or 15840) * 635
        self.paras = []
        self.alt = []

    def run(self):
        pkg, mr = self.pkg, self.pkg.rels(self.main)
        self.scan_part(self.main, "Body")
        counters = {}
        for r in mr:
            if r["external"]:
                continue
            label = {"header": "Header", "footer": "Footer", "footnotes": "Footnotes", "endnotes": "Endnotes",
                     "glossaryDocument": "Glossary (building blocks)"}.get(r["type"])
            if label:
                counters[label] = counters.get(label, 0) + 1
                self.scan_part(r["target"], label + (f" {counters[label]}" if label in ("Header", "Footer") else ""))
            elif r["type"] == "comments":
                self.scan_comments(r["target"])
            elif r["type"] == "settings":
                self.scan_settings(r["target"])
            elif r["type"] == "aFChunk":
                self.scan_altchunk(r["target"])
            pkg.handled.add(r["target"])
        for n in pkg.names:  # comments extended / people etc. are metadata; mark handled
            if n.startswith("word/") and re.search(r"(comments\w*|people|fontTable|webSettings|numbering|styles|stylesWithEffects)\.xml$", n):
                pkg.handled.add(n)

    # ----------------------------------------------------------------------------------
    def scan_part(self, part, label):
        root = self.pkg.xml(part)
        if root is None:
            return
        self.pkg.handled.add(part)
        self.paras = []
        self.alt = []
        self.walk(root, Ctx(self.page_bg, (), False, False), None)
        self.report_paras(label)
        for loc, text in self.alt:
            analyze_text(self.report, text, f"{label}: {loc}", hidden=True, context="alt text")

    def walk(self, el, c, para):
        t = local(el.tag)
        if t == "p":
            ppr = kid(el, "pPr")
            bg = word_shd(kid(ppr, "shd"), self.theme) or c.bg
            c2 = c._replace(bg=bg)
            np_ = Para(att(kid(ppr, "pStyle"), "val"), c2)
            for ch in el:
                if local(ch.tag) != "pPr":
                    self.walk(ch, c2, np_)
            self.paras.append(np_)
            return
        if t == "Fallback":  # mc:AlternateContent fallback duplicates the Choice content
            return
        if t == "tbl":
            tp = kid(el, "tblPr")
            style = (att(kid(tp, "tblStyle"), "val") or "").lower()
            styled = bool(style) and style not in ("tablegrid", "tablenormal", "normaltable", "tableheading")
            c = c._replace(bg=word_shd(kid(tp, "shd"), self.theme) or c.bg, styled_table=c.styled_table or styled)
        elif t == "tc":
            c = c._replace(bg=word_shd(chain(el, "tcPr", "shd"), self.theme) or c.bg)
        elif t in ("del", "moveFrom"):
            c = c._replace(deleted=True)
        elif t == "r":
            self.word_run(el, c, para)
            for ch in el:
                if local(ch.tag) in ("drawing", "pict", "object", "AlternateContent"):
                    self.walk(ch, c, para)
            return
        elif t in ("anchor", "inline"):
            reasons = self.drawing_reasons(el)
            if reasons:
                c = c._replace(reasons=c.reasons + tuple(reasons))
            dp = kid(el, "docPr")
            alt = " ".join(x for x in (att(dp, "title"), att(dp, "descr")) if x)
            if alt:
                self.alt.append((f"drawing '{att(dp, 'name', '?')}'", alt))
        elif t == "wsp":
            col, alpha = dml_color(chain(el, "spPr", "solidFill"), self.theme)
            if col and (alpha or 100) > 50:
                c = c._replace(bg=col)
        elif t in ("shape", "rect", "roundrect", "oval", "textbox", "group") and el.get("style"):
            reasons = vml_reasons(el.get("style"))
            if reasons:
                c = c._replace(reasons=c.reasons + tuple(reasons))
            if el.get("alt"):
                self.alt.append(("VML shape", el.get("alt")))
        elif t == "fldSimple" and para is not None:
            para.instr += " " + (att(el, "instr") or "")
        for ch in el:
            self.walk(ch, c, para)

    def word_run(self, el, c, para):
        if para is None:
            para = Para(None, c)
            self.paras.append(para)
        rpr = kid(el, "rPr")
        p = self.styles.effective(para.pstyle, rpr)
        reasons = list(c.reasons)
        bg = c.bg
        hl = p.get("highlight")
        if hl and hl != "none" and hl in WORD_HIGHLIGHT:
            bg = WORD_HIGHLIGHT[hl]
        if p.get("shd"):
            bg = p["shd"]
        if p.get("vanish"):
            reasons.append("hidden-text formatting (w:vanish)")
        if p.get("webHidden"):
            reasons.append("web-hidden formatting")
        color = p.get("color")
        if color is not None and bg is not None:
            cr = contrast(color, bg)
            if cr < INVISIBLE_CONTRAST:
                reasons.append(f"font color {hexs(color)} on background {hexs(bg)} (contrast {cr:.2f}:1)"
                               + (" [table style may supply a darker background]" if c.styled_table else ""))
        sz = p.get("sz")
        if sz is not None and sz <= 4:
            reasons.append(f"tiny font ({sz / 2:g}pt)")
        w = p.get("w")
        if w is not None and w <= 15:
            reasons.append(f"characters squeezed to {w}% width")
        sp = p.get("spacing")
        if sp is not None and sp <= -60:
            reasons.append(f"characters condensed by {-sp / 20:g}pt (overlapping)")
        pos = p.get("position")
        if pos is not None and abs(pos) >= 144:
            reasons.append(f"text shifted {pos / 2:g}pt off the line")
        txt = []
        for ch in el:
            lt = local(ch.tag)
            if lt in ("t", "delText"):
                txt.append(ch.text or "")
            elif lt == "tab":
                txt.append("\t")
            elif lt in ("br", "cr"):
                txt.append("\n")
            elif lt in ("instrText", "delInstrText"):
                para.instr += ch.text or ""
        if txt:
            para.segs.append(("".join(txt), tuple(dict.fromkeys(reasons)), c.deleted))

    def drawing_reasons(self, el):
        r = []
        dp = kid(el, "docPr")
        if att(dp, "hidden") in ("1", "true"):
            r.append("drawing marked hidden")
        ext = kid(el, "extent")
        cx, cy = to_int(att(ext, "cx"), 0), to_int(att(ext, "cy"), 0)
        if ext is not None and (cx <= 25400 or cy <= 25400):
            r.append(f"drawing shrunk to {cx / 12700:.1f}x{cy / 12700:.1f}pt")
        if local(el.tag) == "anchor":
            for axis, size, extent in (("positionH", self.page_w, cx), ("positionV", self.page_h, cy)):
                off = chain(el, axis, "posOffset")
                o = to_int(off.text) if off is not None else None
                if o is not None and (o > size + 914400 or o + extent < -914400):
                    r.append(f"drawing positioned off the page ({axis} {o / 914400:.1f}in)")
        return r

    def report_paras(self, label):
        rep = self.report
        deleted = []
        for i, para in enumerate(self.paras, 1):
            loc = f"{label} ¶{i}"
            visible = "".join(t for t, rs, dl in para.segs if not rs and not dl)
            groups = {}
            for t, rs, dl in para.segs:
                if dl:
                    deleted.append(t)
                elif rs:
                    groups.setdefault(rs, []).append(t)
            hidden_all = []
            for rs, ts in groups.items():
                txt = "".join(ts)
                if not re.search(r"\w", txt):
                    continue
                hidden_all.append(txt)
                strong = [r for r in rs if "vanish" not in r and "table style" not in r]
                sev = HIGH if strong else (LOW if any("table style" in r for r in rs) else MEDIUM)
                rep.add(sev, "Hidden text", loc, "; ".join(rs), txt)
            analyze_text(rep, visible, loc)
            if hidden_all:
                analyze_text(rep, " ".join(hidden_all), loc, hidden=True)
            if para.instr.strip():
                self.check_field(para.instr, loc)
        dtext = "".join(deleted)
        if dtext.strip():
            rep.add(MEDIUM, "Tracked deletions retained", label,
                    f"{len(dtext):,} characters of deleted text are still stored (visible with Track Changes / Show Markup).", dtext)
            analyze_text(rep, dtext, label, hidden=True, context="tracked deletion")

    def check_field(self, instr, loc):
        for rx, sev, desc in FIELD_RULES:
            if re.search(rx, instr, re.I):
                self.report.add(sev, "Field code", loc, desc, instr.strip())
        analyze_text(self.report, instr, loc, hidden=True, context="field code")

    def scan_comments(self, part):
        root = self.pkg.xml(part)
        if root is None:
            return
        self.pkg.handled.add(part)
        items = []
        for cm in kids(root, "comment"):
            t = texts(cm, ("t",))
            items.append(f"[{att(cm, 'author', '?')}] {t}")
            analyze_text(self.report, t, f"Comment by {att(cm, 'author', '?')}", context="comment")
        if items:
            self.report.add(INFO, "Comments", part, f"{len(items)} review comment(s).", "\n".join(items))

    def scan_settings(self, part):
        root = self.pkg.xml(part)
        if root is None:
            return
        self.pkg.handled.add(part)
        dv = descs(root, "docVar")
        if dv:
            vals = [f"{att(v, 'name')} = {att(v, 'val')}" for v in dv]
            self.report.add(MEDIUM, "Document variables", part,
                            f"{len(dv)} document variable(s) - invisible storage only readable by macros/fields.", "\n".join(vals))
            analyze_text(self.report, "\n".join(att(v, "val") or "" for v in dv), part, hidden=True, context="docVars")
        for r in self.pkg.rels(part):
            self.pkg.handled.add(r["target"])

    def scan_altchunk(self, part):
        data = self.pkg.read(part)
        self.pkg.handled.add(part)
        self.report.add(MEDIUM, "Embedded content chunk (altChunk)", part,
                        "Raw HTML/RTF/MHT content merged into the document at open time.")
        low = part.lower()
        text = data.decode("utf-8", "replace")
        if low.endswith((".htm", ".html", ".mht", ".mhtml")) or "<html" in text[:2000].lower():
            htmlscan.scan_html(self.report, text, part)
        else:
            self.nested(posixpath.basename(part), data)


def vml_reasons(style):
    s = style.replace(" ", "").lower()
    r = []
    if "visibility:hidden" in s:
        r.append("VML shape visibility:hidden")
    if "mso-hide:all" in s:
        r.append("VML shape mso-hide:all")
    for prop in ("margin-left", "margin-top", "left", "top"):
        m = re.search(rf"(?:^|;){prop}:(-?[\d.]+)(pt|in|px|mm|cm)?", s)
        if m:
            v = float(m.group(1)) * {"pt": 1, "in": 72, "px": 0.75, "mm": 2.83, "cm": 28.3, None: 0.75}[m.group(2)]
            if v < -500 or v > 2500:
                r.append(f"VML shape positioned off the page ({prop}:{m.group(1)}{m.group(2) or ''})")
                break
    for prop in ("width", "height"):
        m = re.search(rf"(?:^|;){prop}:([\d.]+)(pt|in|px)?", s)
        if m and float(m.group(1)) * {"pt": 1, "in": 72, "px": 0.75, None: 0.75}[m.group(2)] < 2:
            r.append(f"VML shape {prop} shrunk to {m.group(1)}{m.group(2) or ''}")
            break
    return r


# ======================================================================================
# DrawingML shapes (PowerPoint slides, Excel drawings)
# ======================================================================================

SHAPE_TAGS = ("sp", "grpSp", "pic", "graphicFrame", "cxnSp", "contentPart")


class DmlScanner:
    def __init__(self, report, theme):
        self.report = report
        self.theme = theme

    @staticmethod
    def cnv(el):
        for ch in el:
            if local(ch.tag).startswith("nv"):
                c = kid(ch, "cNvPr")
                if c is not None:
                    return c, ch
        return None, None

    @staticmethod
    def xfrm(el):
        sp = kid(el, "spPr")
        if sp is None:
            sp = kid(el, "grpSpPr")
        x = kid(sp, "xfrm") if sp is not None else kid(el, "xfrm")
        if x is None:
            return None
        off, ext = kid(x, "off"), kid(x, "ext")
        if off is None or ext is None:
            return None
        return (to_int(att(off, "x"), 0), to_int(att(off, "y"), 0), to_int(att(ext, "cx"), 0), to_int(att(ext, "cy"), 0))

    def shape_fill(self, el, bg):
        sp = kid(el, "spPr")
        if sp is None:
            return bg, False
        if kid(sp, "solidFill") is not None:
            col, alpha = dml_color(kid(sp, "solidFill"), self.theme)
            if col and (alpha or 100) >= 90:
                return col, True
            return bg, False
        if kid(sp, "gradFill") is not None or kid(sp, "blipFill") is not None or kid(sp, "pattFill") is not None:
            return None, True  # unknown background
        return bg, False

    def scan_tree(self, shapes, label, slide_w=None, slide_h=None, bg=WHITE, skip_placeholders=False):
        """shapes: list of top-level shape elements in z-order."""
        geo = []
        for el in shapes:
            x = self.xfrm(el)
            _, opaque = self.shape_fill(el, bg)
            opaque = opaque or local(el.tag) == "pic"
            c, _ = self.cnv(el)
            geo.append((x, opaque, att(c, "name", local(el.tag))))
        for i, el in enumerate(shapes):
            extra = []
            x = geo[i][0]
            if x and self.has_text(el):
                for j in range(i + 1, len(shapes)):
                    y, opaque, name = geo[j]
                    if opaque and y and y[0] <= x[0] and y[1] <= x[1] and y[0] + y[2] >= x[0] + x[2] and y[1] + y[3] >= x[1] + x[3]:
                        extra.append(f"covered by shape '{name}' drawn on top")
                        break
            self.shape(el, label, tuple(extra), bg, True, slide_w, slide_h, skip_placeholders)

    @staticmethod
    def has_text(el):
        return any((t.text or "").strip() for t in descs(el, "t"))

    def shape(self, el, label, inherited, bg, top, sw, sh, skip_ph):
        t = local(el.tag)
        c, nv = self.cnv(el)
        name = att(c, "name", t)
        loc = f"{label} › {('group' if t == 'grpSp' else 'shape')} '{name}'"
        reasons = list(inherited)
        if att(c, "hidden") in ("1", "true"):
            reasons.append("shape is hidden (Selection Pane)")
        alt = " ".join(x for x in (att(c, "title"), att(c, "descr")) if x)
        if alt:
            analyze_text(self.report, alt, loc, hidden=True, context="alt text")
        x = self.xfrm(el)
        if x and top and sw and sh:
            if x[0] >= sw or x[1] >= sh or x[0] + x[2] <= 0 or x[1] + x[3] <= 0:
                reasons.append(f"positioned entirely off the slide (x={x[0] / 914400:.1f}in, y={x[1] / 914400:.1f}in)")
        if x and t in ("sp", "graphicFrame") and (x[2] <= 25400 or x[3] <= 25400):
            reasons.append(f"shape shrunk to {x[2] / 12700:.1f}x{x[3] / 12700:.1f}pt")
        if skip_ph and nv is not None and descs(nv, "ph"):
            analyze_text(self.report, texts(el), loc, context="layout placeholder")
            return
        if t == "grpSp":
            for ch in el:
                if local(ch.tag) in SHAPE_TAGS:
                    self.shape(ch, loc, tuple(reasons), bg, False, sw, sh, skip_ph)
            return
        fill_bg, _ = self.shape_fill(el, bg)
        tb = kid(el, "txBody")
        if tb is not None:
            self.text_body(tb, loc, reasons, fill_bg)
        if t == "graphicFrame":
            for tc in descs(el, "tc"):
                cbg, _ = dml_color(chain(tc, "tcPr", "solidFill"), self.theme)
                tb2 = kid(tc, "txBody")
                if tb2 is not None:
                    self.text_body(tb2, loc + " table cell", reasons, cbg or fill_bg)
        elif t == "pic" and reasons:
            self.report.add(MEDIUM, "Hidden picture", loc, "; ".join(reasons))

    def text_body(self, tb, loc, shape_reasons, bg):
        visible, hidden = [], {}
        for p in kids(tb, "p"):
            for r in p:
                lt = local(r.tag)
                if lt == "br":
                    visible.append("\n")
                    continue
                if lt not in ("r", "fld"):
                    continue
                txt = texts(r)
                if not txt:
                    continue
                reasons = list(shape_reasons)
                rpr = kid(r, "rPr")
                rbg = bg
                hl, _ = dml_color(kid(rpr, "highlight"), self.theme)
                if hl:
                    rbg = hl
                sz = to_int(att(rpr, "sz"))
                if sz is not None and sz < 200:
                    reasons.append(f"tiny font ({sz / 100:g}pt)")
                if kid(rpr, "noFill") is not None:
                    reasons.append("text has no fill (invisible)")
                col, alpha = dml_color(kid(rpr, "solidFill"), self.theme)
                if alpha is not None and alpha < 15:
                    reasons.append(f"text {alpha:.0f}% opaque")
                if col and rbg:
                    cr = contrast(col, rbg)
                    if cr < INVISIBLE_CONTRAST:
                        reasons.append(f"font color {hexs(col)} on background {hexs(rbg)} (contrast {cr:.2f}:1)")
                if reasons:
                    hidden.setdefault(tuple(dict.fromkeys(reasons)), []).append(txt)
                else:
                    visible.append(txt)
            visible.append("\n")
        for rs, ts in hidden.items():
            txt = "".join(ts)
            if re.search(r"\w", txt):
                self.report.add(HIGH, "Hidden text", loc, "; ".join(rs), txt)
        if hidden:
            analyze_text(self.report, " ".join("".join(v) for v in hidden.values()), loc, hidden=True)
        analyze_text(self.report, "".join(visible), loc)


# ======================================================================================
# PowerPoint
# ======================================================================================

class PptScanner:
    def __init__(self, pkg, report, main, nested):
        self.pkg, self.report, self.main, self.nested = pkg, report, main, nested
        self.root = pkg.xml(main)
        mr = pkg.rels(main)
        self.rmap = pkg.rel_map(main)
        theme_part = next((r["target"] for r in mr if r["type"] == "theme"), None)
        if not theme_part:
            masters = [r["target"] for r in mr if r["type"] == "slideMaster"]
            theme_part = next((t for m in masters for t in pkg.rel_targets(m, "theme")), None)
        self.theme = Theme(pkg.xml(theme_part))
        self.dml = DmlScanner(report, self.theme)
        sz = kid(self.root, "sldSz")
        self.w = to_int(att(sz, "cx"), 12192000)
        self.h = to_int(att(sz, "cy"), 6858000)

    def bg_of(self, part, depth=0):
        root = self.pkg.xml(part)
        bg = chain(root, "cSld", "bg")
        if bg is not None:
            bp = kid(bg, "bgPr")
            if bp is not None:
                if kid(bp, "solidFill") is not None:
                    return dml_color(kid(bp, "solidFill"), self.theme)[0] or WHITE
                return None  # gradient / picture: unknown
            ref = kid(bg, "bgRef")
            if ref is not None:
                return dml_color(ref, self.theme)[0] or WHITE
        if depth < 2:
            for typ in ("slideLayout", "slideMaster"):
                nxt = self.pkg.rel_targets(part, typ)
                if nxt:
                    return self.bg_of(nxt[0], depth + 1)
        return WHITE

    @staticmethod
    def top_shapes(root):
        tree = chain(root, "cSld", "spTree")
        return [c for c in tree if local(c.tag) in SHAPE_TAGS] if tree is not None else []

    def run(self):
        pkg = self.pkg
        pkg.handled.add(self.main)
        slides = []
        for s in descs(self.root, "sldId"):
            r = self.rmap.get(rid(s))
            if r:
                slides.append(r["target"])
        used_layouts = set()
        for n, part in enumerate(slides, 1):
            root = pkg.xml(part)
            if root is None:
                continue
            pkg.handled.add(part)
            label = f"Slide {n}"
            used_layouts.update(pkg.rel_targets(part, "slideLayout"))
            if att(root, "show") in ("0", "false"):
                txt = texts(root)
                self.report.add(MEDIUM, "Hidden slide", label, "Slide is hidden - skipped during the slideshow but still in the file.", txt)
                analyze_text(self.report, txt, label, hidden=True, context="hidden slide")
            self.dml.scan_tree(self.top_shapes(root), label, self.w, self.h, self.bg_of(part))
            for r in pkg.rels(part):
                if r["external"]:
                    continue
                if r["type"] == "notesSlide":
                    self.notes(r["target"], label)
                elif r["type"] in ("comments", "comment"):
                    self.comments(r["target"], label)
        all_slides = [n for n in pkg.names if re.fullmatch(r"ppt/slides/slide\d+\.xml", n)]
        for part in all_slides:
            if part not in slides:
                txt = texts(pkg.xml(part))
                self.report.add(HIGH, "Slide not in presentation", part,
                                "Slide is stored in the file but not listed in the presentation - it is never shown.", txt)
                analyze_text(self.report, txt, part, hidden=True)
                pkg.handled.add(part)
        for part in pkg.names:
            if re.fullmatch(r"ppt/(slideLayouts/slideLayout|slideMasters/slideMaster)\d+\.xml", part):
                pkg.handled.add(part)
                root = pkg.xml(part)
                if root is None:
                    continue
                kind = "Layout" if "Layout" in part else "Master"
                label = f"{kind} {posixpath.basename(part)}"
                shapes = self.top_shapes(root)
                if kind == "Layout" and part not in used_layouts:
                    free_text = " ".join(texts(s) for s in shapes if not descs(s, "ph")).strip()
                    if free_text:
                        self.report.add(LOW, "Text on unused layout", label,
                                        "Layout with its own text is not used by any slide - text never appears.", free_text)
                        analyze_text(self.report, free_text, label, hidden=True)
                self.dml.scan_tree(shapes, label, self.w, self.h, self.bg_of(part), skip_placeholders=True)
        for part in pkg.names:
            if re.search(r"ppt/(comments/|commentAuthors|authors)", part) and part not in pkg.handled:
                self.comments(part, part)
            if re.search(r"ppt/(notesMasters|handoutMasters|presProps|viewProps|tableStyles)", part):
                pkg.handled.add(part)

    def notes(self, part, label):
        root = self.pkg.xml(part)
        self.pkg.handled.add(part)
        if root is None:
            return
        chunks = []
        for sp in descs(root, "sp"):
            ph = next(iter(descs(sp, "ph")), None)
            if ph is not None and att(ph, "type") in ("sldNum", "sldImg", "hdr", "ftr", "dt"):
                continue
            t = "\n".join(texts(p) for p in descs(sp, "p")).strip()
            if t:
                chunks.append(t)
        txt = "\n".join(chunks)
        if txt.strip():
            self.report.add(INFO, "Speaker notes", label, "Speaker notes (not shown to the audience).", txt)
            analyze_text(self.report, txt, label, context="speaker notes")

    def comments(self, part, label):
        root = self.pkg.xml(part)
        self.pkg.handled.add(part)
        if root is None:
            return
        txt = " ".join(t.strip() for t in root.itertext() if t.strip())
        if txt and "authors" not in part.lower():
            self.report.add(INFO, "Comments", label, "Review comments.", txt)
            analyze_text(self.report, txt, label, context="comment")


# ======================================================================================
# Excel
# ======================================================================================

def col_index(letters):
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n


def col_letters(n):
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


class XlStyles:
    def __init__(self, root, theme):
        self.theme = theme
        self.numfmts, self.fonts, self.fills, self.xfs = {}, [], [], []
        if root is None:
            return
        for nf in descs(kid(root, "numFmts"), "numFmt"):
            self.numfmts[to_int(att(nf, "numFmtId"))] = att(nf, "formatCode") or ""
        for f in kids(kid(root, "fonts"), "font"):
            sz = kid(f, "sz")
            self.fonts.append((self.color(kid(f, "color")), float(att(sz, "val")) if sz is not None and att(sz, "val") else None))
        for f in kids(kid(root, "fills"), "fill"):
            pf = kid(f, "patternFill")
            col = self.color(kid(pf, "fgColor")) if pf is not None and att(pf, "patternType") == "solid" else None
            self.fills.append(col)
        for xf in kids(kid(root, "cellXfs"), "xf"):
            prot = kid(xf, "protection")
            self.xfs.append((to_int(att(xf, "numFmtId"), 0), to_int(att(xf, "fontId"), 0), to_int(att(xf, "fillId"), 0),
                             att(prot, "hidden") in ("1", "true")))
        self._cache = {}

    def color(self, el):
        if el is None or att(el, "auto") in ("1", "true"):
            return None
        if att(el, "rgb"):
            return parse_hex(att(el, "rgb"))
        if att(el, "theme") is not None:
            return self.theme.excel(att(el, "theme"), att(el, "tint"))
        if att(el, "indexed") is not None:
            i = to_int(att(el, "indexed"))
            return EXCEL_INDEXED[i] if i is not None and i < len(EXCEL_INDEXED) else None
        return None

    def reasons(self, s):
        """Returns (hide_reasons, mask_reason) for cell style index s."""
        if s in self._cache:
            return self._cache[s]
        r, mask = [], None
        if s is not None and s < len(self.xfs):
            nf, fo, fi, _ = self.xfs[s]
            code = self.numfmts.get(nf, "")
            if code and re.fullmatch(r"\s*;\s*;\s*;?\s*", code):
                r.append('number format ";;;" hides the value')
            elif code and is_masking_format(code):
                mask = f'number format "{code}" displays fixed text instead of the real value'
            color, size = self.fonts[fo] if fo < len(self.fonts) else (None, None)
            bg = (self.fills[fi] if fi < len(self.fills) else None) or WHITE
            if color is not None:
                cr = contrast(color, bg)
                if cr < INVISIBLE_CONTRAST:
                    r.append(f"font color {hexs(color)} on fill {hexs(bg)} (contrast {cr:.2f}:1)")
            if size is not None and size < 2:
                r.append(f"tiny font ({size:g}pt)")
        self._cache[s] = (tuple(r), mask)
        return self._cache[s]


def is_masking_format(code):
    sections = []
    cur, q, esc = "", False, False
    for ch in code:
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            q = not q
            continue
        if ch == ";" and not q:
            sections.append(cur)
            cur = ""
            continue
        if not q:
            cur += ch
    sections.append(cur)
    if not any(s.strip() for s in sections):
        return False
    stripped = [re.sub(r"\[[^\]]*\]|_.|\*.", "", s) for s in sections[:3]]
    has_literal = '"' in code or "\\" in code
    return has_literal and not any(re.search(r"[0#?@yYmMdDhHsSeE]|General", s) for s in stripped)


class ExcelScanner:
    def __init__(self, pkg, report, main, nested):
        self.pkg, self.report, self.main, self.nested = pkg, report, main, nested
        self.wb = pkg.xml(main)
        self.rmap = pkg.rel_map(main)
        mr = pkg.rels(main)
        self.theme = Theme(pkg.xml(next((r["target"] for r in mr if r["type"] == "theme"), None)))
        self.styles = XlStyles(pkg.xml(next((r["target"] for r in mr if r["type"] == "styles"), None)), self.theme)
        self.sst, self.sst_hidden = [], {}
        sst_part = next((r["target"] for r in mr if r["type"] == "sharedStrings"), None)
        root = pkg.xml(sst_part)
        if root is not None:
            pkg.handled.add(sst_part)
            for i, si in enumerate(kids(root, "si")):
                parts, hid = [], []
                for ch in si:
                    n = local(ch.tag)
                    if n == "t":
                        parts.append(ch.text or "")
                    elif n == "r":
                        t = texts(ch)
                        parts.append(t)
                        rpr = kid(ch, "rPr")
                        col = self.styles.color(kid(rpr, "color"))
                        sz = kid(rpr, "sz")
                        szv = float(att(sz, "val")) if sz is not None and att(sz, "val") else None
                        if (col is not None and contrast(col, WHITE) < INVISIBLE_CONTRAST) or (szv is not None and szv < 2):
                            hid.append(t)
                self.sst.append("".join(parts))
                if hid:
                    self.sst_hidden[i] = "".join(hid)
        pkg.handled.update(r["target"] for r in mr if r["type"] in ("styles", "theme", "calcChain"))

    def run(self):
        pkg, rep = self.pkg, self.report
        pkg.handled.add(self.main)
        if self.wb is None:
            return
        for v in descs(self.wb, "workbookView"):
            if att(v, "visibility") in ("hidden", "veryHidden"):
                rep.add(MEDIUM, "Hidden workbook window", "workbook", "The workbook window itself is hidden.")
        names = []
        for dn in descs(self.wb, "definedName"):
            nm, val = att(dn, "name", ""), dn.text or ""
            if nm.lower() in ("_xlnm.auto_open", "auto_open", "_xlnm.auto_activate", "auto_close", "_xlnm.auto_close"):
                rep.add(HIGH, "Auto-run macro name", f"name '{nm}'", "Defined name that triggers a macro automatically.", val)
            if att(dn, "hidden") in ("1", "true") and not nm.startswith(("_xlnm.", "_xlfn.")):
                names.append(f"{nm} = {val}")
            if re.match(r'^\s*=?\s*"', val) and len(val) > 20:
                rep.add(MEDIUM, "Text stored in defined name", f"name '{nm}'",
                        "A defined name holds a text constant - invisible unless you open Name Manager.", val)
            analyze_text(rep, val, f"name '{nm}'", hidden=True, context="defined name")
        if names:
            rep.add(LOW, "Hidden defined names", "workbook", f"{len(names)} hidden defined name(s).", "\n".join(names))

        for sh in descs(self.wb, "sheet"):
            name, state = att(sh, "name", "?"), att(sh, "state", "visible")
            r = self.rmap.get(rid(sh))
            if not r:
                continue
            part = r["target"]
            if state == "veryHidden":
                rep.add(HIGH, "Very hidden sheet", f"Sheet '{name}'",
                        "Sheet is 'very hidden' - it cannot be unhidden from Excel's menus (only via VBA / XML).")
            elif state == "hidden":
                rep.add(MEDIUM, "Hidden sheet", f"Sheet '{name}'", "Sheet is hidden (right-click a tab > Unhide to see it).")
            if r["type"] == "xlMacrosheet" or "macrosheets/" in part:
                rep.add(HIGH, "Excel 4.0 (XLM) macro sheet", f"Sheet '{name}'",
                        "Legacy XLM macro sheet - a common malware technique.", texts(pkg.xml(part), ("f", "v"))[:600])
            if r["type"] in ("worksheet", "xlMacrosheet", "dialogsheet"):
                self.sheet(part, name, state)
        for n in pkg.names:
            low = n.lower()
            if n in pkg.handled:
                continue
            if re.match(r"xl/(comments\d*|threadedcomments/.*)\.xml", low):
                root = pkg.xml(n)
                pkg.handled.add(n)
                items = [" ".join(t for t in c.itertext()).strip() for c in descs(root, "comment") + descs(root, "threadedComment")]
                items = [i for i in items if i]
                if items:
                    rep.add(INFO, "Cell comments / notes", n, f"{len(items)} comment(s).", "\n".join(items))
                    analyze_text(rep, "\n".join(items), n, context="comment")
            elif re.match(r"xl/drawings/drawing\d+\.xml", low):
                pkg.handled.add(n)
                root = pkg.xml(n)
                shapes = []
                for anchor in (root if root is not None else []):
                    shapes.extend(c for c in anchor if local(c.tag) in SHAPE_TAGS)
                DmlScanner(rep, self.theme).scan_tree(shapes, f"Drawing {posixpath.basename(n)}")
            elif "vmldrawing" in low or low.startswith(("xl/printersettings", "xl/persons", "xl/metadata")):
                pkg.handled.add(n)
            elif low.startswith("xl/externallinks/") and low.endswith(".xml"):
                pkg.handled.add(n)
                root = pkg.xml(n)
                cached = descs(root, "cell")
                rep.add(MEDIUM, "External workbook link", n,
                        f"Link to another workbook; {len(cached)} cached value(s) from that file are stored here.",
                        texts(root, ("v",))[:600])
            elif low == "xl/connections.xml":
                pkg.handled.add(n)
                root = pkg.xml(n)
                for c in descs(root, "connection"):
                    detail = " | ".join(f"{k}={v}" for el in c.iter() for k, v in el.attrib.items()
                                        if local(k) in ("name", "connection", "command", "url", "sourceFile"))
                    sev = HIGH if re.search(r"password\s*=", detail, re.I) else MEDIUM
                    rep.add(sev, "Data connection", n, "External data connection" +
                            (" containing an embedded password" if sev == HIGH else "") + ".", detail)
            elif low.startswith("xl/querytables/"):
                pkg.handled.add(n)
                rep.add(MEDIUM, "Query table", n, "Web/database query table that refreshes from an external source.")

    def sheet(self, part, name, state):
        pkg, rep = self.pkg, self.report
        root = pkg.xml(part)
        pkg.handled.add(part)
        if root is None:
            return
        label = f"Sheet '{name}'"
        hidden_cols = set()
        for col in descs(root, "col"):
            mn, mx = to_int(att(col, "min"), 1), to_int(att(col, "max"), 1)
            width = att(col, "width")
            if att(col, "hidden") in ("1", "true") or (width is not None and float(width) < 0.5):
                hidden_cols.update(range(mn, min(mx, 16384) + 1))
        zero_h = att(kid(root, "sheetFormatPr"), "zeroHeight") in ("1", "true")
        groups, visible, formulas, all_text, coords = {}, [], [], [], []
        row_no = 0
        for row in descs(root, "row"):
            row_no = to_int(att(row, "r"), row_no + 1)
            ht = att(row, "ht")
            row_hidden = att(row, "hidden") in ("1", "true") or (ht is not None and float(ht) < 0.5) or (zero_h and ht is None)
            col_no = 0
            for c in kids(row, "c"):
                ref = att(c, "r")
                m = re.match(r"([A-Z]+)(\d+)", ref or "")
                col_no = col_index(m.group(1)) if m else col_no + 1
                ref = ref or f"{col_letters(col_no)}{row_no}"
                t = att(c, "t", "n")
                v = kid(c, "v")
                f = kid(c, "f")
                val = ""
                hidden_rich = None
                if t == "s" and v is not None:
                    i = to_int(v.text)
                    val = self.sst[i] if i is not None and i < len(self.sst) else ""
                    hidden_rich = self.sst_hidden.get(i)
                elif t == "inlineStr":
                    val = texts(kid(c, "is"))
                elif v is not None:
                    val = v.text or ""
                if f is not None and (f.text or "").strip():
                    formulas.append((ref, f.text))
                if not str(val).strip():
                    continue
                coords.append((row_no, col_no, ref))
                all_text.append(str(val))
                reasons = []
                if row_hidden:
                    reasons.append("hidden row")
                if col_no in hidden_cols:
                    reasons.append("hidden column")
                style_r, mask = self.styles.reasons(to_int(att(c, "s"), 0))
                reasons.extend(style_r)
                if mask:
                    groups.setdefault((mask,), []).append((ref, val))
                if hidden_rich:
                    groups.setdefault(("part of the cell text formatted invisible",), []).append((ref, hidden_rich))
                if reasons:
                    groups.setdefault(tuple(reasons), []).append((ref, val))
                else:
                    visible.append(str(val))

        if state in ("hidden", "veryHidden") and all_text:
            rep.add(HIGH if state == "veryHidden" else MEDIUM, "Data on hidden sheet", label,
                    f"{len(all_text)} non-empty cell(s) on a {state} sheet.", " | ".join(all_text[:60]))
            analyze_text(rep, "\n".join(all_text), label, hidden=True, context=f"{state} sheet")
        else:
            for rs, cells in groups.items():
                weak = all(r in ("hidden row", "hidden column") for r in rs)
                masking = any("displays fixed text" in r for r in rs)
                sev = MEDIUM if (weak or masking) else HIGH
                cat = "Masked cell values" if masking else ("Cells in hidden rows/columns" if weak else "Hidden cell content")
                sample = " | ".join(f"{r}: {v}" for r, v in cells[:40])
                rep.add(sev, cat, label, f"{len(cells)} cell(s): " + "; ".join(rs), sample)
                analyze_text(rep, "\n".join(str(v) for _, v in cells), label, hidden=True, context=cat.lower())
            analyze_text(rep, "\n".join(visible), label)

        # Data parked far away from the main table
        if len(coords) >= 2:
            rows = sorted(r for r, _, _ in coords)
            cols = sorted(c for _, c, _ in coords)
            p90r, p90c = rows[int(len(rows) * 0.9) - 1 if len(rows) > 1 else 0], cols[int(len(cols) * 0.9) - 1 if len(cols) > 1 else 0]
            far = [ref for r, c, ref in coords if (r > p90r * 10 + 200) or (c > p90c * 4 + 60)]
            if far and len(far) < len(coords) * 0.1 + 1:
                rep.add(MEDIUM, "Data far outside main area", label,
                        f"{len(far)} cell(s) placed far away from the rest of the data, where nobody scrolls.", ", ".join(far[:30]))

        for ref, fx in formulas:
            loc = f"{label}!{ref}"
            if re.search(r"\bWEBSERVICE\s*\(|\bFILTERXML\s*\(", fx, re.I):
                rep.add(MEDIUM, "Formula fetches web content", loc, "WEBSERVICE/FILTERXML formula contacts a URL.", fx)
            if re.search(r"^\s*[=@+-]?\s*['\"]?\w+\|['\"]", fx) or re.search(r"\bcmd\|", fx, re.I):
                rep.add(HIGH, "DDE formula", loc, "Formula invokes a DDE command (can execute programs).", fx)
            if len(re.findall(r"\bCHAR\s*\(", fx, re.I)) >= 5:
                rep.add(MEDIUM, "Obfuscated formula", loc, "Formula builds a string from many CHAR() calls.", fx)
            lits = " ".join(re.findall(r'"([^"]{8,})"', fx))
            if lits:
                analyze_text(rep, lits, loc, hidden=True, context="formula string")


# ======================================================================================
# Entry point
# ======================================================================================

def scan_ooxml(raw, report, nested):
    check_zip_container(report, raw, "Office package")
    try:
        pkg = Package(raw, report)
    except zipfile.BadZipFile as e:
        report.error(f"Not a valid Office package: {e}")
        return
    main = pkg.main_part()
    pkg.handled.update(n for n in pkg.names if n.endswith(".rels") or n == "[Content_Types].xml")
    scan_package_level(pkg, report, nested)
    if not main:
        report.error("No main document part found")
    elif main.lower().endswith(".bin"):
        report.file_type = "Excel binary workbook (.xlsb)"
        report.add(INFO, "Limited analysis", main, "Binary .xlsb sheets can't be inspected cell-by-cell; save as .xlsx for a full scan.")
    elif main.startswith("word/"):
        report.file_type = "Word document (OOXML)"
        WordScanner(pkg, report, main, nested).run()
    elif main.startswith("xl/"):
        report.file_type = "Excel workbook (OOXML)"
        ExcelScanner(pkg, report, main, nested).run()
    elif main.startswith("ppt/"):
        report.file_type = "PowerPoint presentation (OOXML)"
        PptScanner(pkg, report, main, nested).run()
    else:
        report.file_type = f"OOXML package ({main})"

    # Anything not covered above: still check for smuggled Unicode / injection text
    for n in pkg.names:
        if n in pkg.handled or not n.lower().endswith((".xml", ".vml")):
            continue
        root = pkg.xml(n)
        if root is None:
            continue
        txt = " ".join(t.strip() for t in root.itertext() if t.strip())
        attrs = " ".join(v for el in root.iter() for k, v in el.attrib.items()
                         if len(v) > 20 and local(k) in ("descr", "title", "val", "name", "content", "value"))
        visible_part = re.search(r"/(charts|diagrams)/", n) is not None
        analyze_text(report, txt + " " + attrs, n, hidden=not visible_part)
