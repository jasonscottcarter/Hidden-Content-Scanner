"""OpenDocument (.odt/.ods/.odp) scanner."""
from __future__ import annotations

import io
import re
import zipfile

from .core import HIGH, MEDIUM, LOW, INFO, WHITE, INVISIBLE_CONTRAST, analyze_text, contrast, hexs, parse_hex
from .xmlutil import local, att, parse_xml, UnsafeXml


def _styles(root, out):
    for st in root.iter():
        if local(st.tag) != "style":
            continue
        name = att(st, "name")
        props = dict(out.get(att(st, "parent-style-name"), {}))
        for p in st:
            if local(p.tag) == "text-properties":
                if att(p, "color"):
                    props["color"] = parse_hex(att(p, "color"))
                if att(p, "background-color") and att(p, "background-color") != "transparent":
                    props["bg"] = parse_hex(att(p, "background-color"))
                fs = att(p, "font-size")
                if fs and fs.endswith("pt"):
                    try:
                        props["size"] = float(fs[:-2])
                    except ValueError:
                        pass
                if att(p, "display") == "none":
                    props["display_none"] = True
                if att(p, "text-position") and re.match(r"-?\d+%?\s+[0-5]%", att(p, "text-position")):
                    props["size"] = 0.5
            elif local(p.tag) in ("table-row-properties", "table-column-properties"):
                if att(p, "use-optimal-row-height") is None and att(p, "row-height") in ("0cm", "0in", "0mm"):
                    props["zero"] = True
            elif local(p.tag) == "table-properties" and att(p, "display") == "false":
                props["hidden_table"] = True
        if name:
            out[name] = props
    return out


def scan_odf(raw, report, nested):
    from .ooxml import check_zip_container
    check_zip_container(report, raw, "OpenDocument package")
    z = zipfile.ZipFile(io.BytesIO(raw))
    names = z.namelist()
    mt = z.read("mimetype").decode("ascii", "replace") if "mimetype" in names else ""
    report.file_type = {"text": "OpenDocument Text", "spreadsheet": "OpenDocument Spreadsheet",
                        "presentation": "OpenDocument Presentation"}.get(mt.rsplit(".", 1)[-1], "OpenDocument")

    if any(n.startswith(("Basic/", "Scripts/")) for n in names):
        report.add(HIGH, "Macros", "Basic/ or Scripts/", "Document contains LibreOffice/StarBasic or script macros.",
                   "\n".join(n for n in names if n.startswith(("Basic/", "Scripts/")))[:600])
    objs = sorted({n.split("/")[0] for n in names if n.startswith("Object ")})
    if objs:
        report.add(MEDIUM, "Embedded objects", "package", f"{len(objs)} embedded object(s).", ", ".join(objs))
    for n in names:
        if n.startswith("ObjectReplacements/") or n.lower().endswith((".bin", ".ole")):
            nested(n.rsplit("/", 1)[-1], z.read(n))

    def load(n):
        if n not in names:
            return None
        try:
            return parse_xml(z.read(n))
        except UnsafeXml as e:
            report.add(HIGH, "Malicious XML construct", n, f"DTD/entity declarations ({e}); part not parsed.")
            return None

    styles = {}
    for n in ("styles.xml", "content.xml"):
        r = load(n)
        if r is not None:
            _styles(r, styles)

    meta = load("meta.xml")
    if meta is not None:
        vals = [f"{local(e.tag)}: {e.text.strip()}" for e in meta.iter() if e.text and e.text.strip()]
        if vals:
            report.add(INFO, "Document metadata", "meta.xml", "Author / revision metadata.", "\n".join(vals))
            analyze_text(report, "\n".join(vals), "meta.xml", hidden=True, context="document property")

    root = load("content.xml")
    if root is None:
        return
    hidden, visible = {}, []

    def walk(el, reasons, style_props, bg):
        t = local(el.tag)
        r = list(reasons)
        sp = dict(style_props)
        sname = att(el, "style-name")
        if sname and sname in styles:
            sp.update(styles[sname])
        if t in ("hidden-text", "hidden-paragraph"):
            r.append(f"text:{t} field")
        if t == "section" and (att(el, "display") in ("none", "condition")):
            r.append(f"section display={att(el, 'display')}")
        if t == "table" and sp.get("hidden_table"):
            r.append("hidden sheet")
        if t in ("table-row", "table-column") and att(el, "visibility") in ("collapse", "filter"):
            r.append(f"{t.replace('table-', '')} visibility={att(el, 'visibility')}")
        if sp.get("zero"):
            r.append("zero-height row")
        if sp.get("display_none"):
            r.append("display:none")
        if sp.get("bg"):
            bg = sp["bg"]
        col = sp.get("color")
        if col and bg and contrast(col, bg) < INVISIBLE_CONTRAST:
            r.append(f"font color {hexs(col)} on background {hexs(bg)}")
        if sp.get("size") is not None and sp["size"] < 2:
            r.append(f"tiny font ({sp['size']:g}pt)")
        if t == "annotation":
            txt = " ".join(el.itertext())
            report.add(INFO, "Comments", "content.xml", "Review comment.", txt)
            analyze_text(report, txt, "comment")
            return
        if t == "tracked-changes":
            txt = " ".join(el.itertext()).strip()
            if txt:
                report.add(MEDIUM, "Tracked changes retained", "content.xml", "Tracked-change text is stored in the file.", txt)
                analyze_text(report, txt, "tracked changes", hidden=True)
            return
        if el.text:
            (hidden.setdefault(tuple(dict.fromkeys(r)), []) if r else visible).append(el.text)
        for ch in el:
            walk(ch, r, sp, bg)
            if ch.tail:
                (hidden.setdefault(tuple(dict.fromkeys(r)), []) if r else visible).append(ch.tail)
        if t in ("p", "h"):
            visible.append("\n")

    walk(root, [], {}, WHITE)
    for rs, chunks in hidden.items():
        txt = " ".join(chunks)
        if re.search(r"\w{2,}", txt):
            weak = all("visibility" in r or "zero-height" in r for r in rs)
            report.add(MEDIUM if weak else HIGH, "Hidden text", "content.xml", "; ".join(rs), txt)
    if hidden:
        analyze_text(report, " ".join(" ".join(c) for c in hidden.values()), "content.xml", hidden=True)
    analyze_text(report, "".join(visible), "content.xml")
