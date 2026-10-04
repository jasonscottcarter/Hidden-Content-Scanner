"""PDF scanner: invisible/white/tiny/covered/off-page text, hidden layers, JavaScript, attachments,
earlier revisions, orphaned objects, appended data."""
from __future__ import annotations

import re

import pymupdf

from .core import (HIGH, MEDIUM, LOW, INFO, WHITE, INVISIBLE_CONTRAST, analyze_text, contrast, hexs, printable_strings,
                   current_budget)

pymupdf.TOOLS.mupdf_display_errors(False)

RISKY_KEYS = [
    ("/JavaScript", HIGH, "JavaScript", "Document contains JavaScript."),
    ("/JS", HIGH, "JavaScript", "Document contains JavaScript."),
    ("/Launch", HIGH, "Launch action", "Action that launches an external program or file."),
    ("/RichMedia", MEDIUM, "Rich media", "Embedded Flash/rich-media content."),
    ("/XFA", MEDIUM, "XFA form", "Dynamic XFA form (can carry scripts and content not shown by all viewers)."),
    ("/SubmitForm", MEDIUM, "Form submission", "Action that submits form data to a URL."),
    ("/ImportData", MEDIUM, "Data import", "Action that imports external data."),
    ("/GoToR", MEDIUM, "Remote go-to", "Link that opens another (possibly remote) PDF."),
    ("/GoToE", MEDIUM, "Embedded go-to", "Link into an embedded PDF."),
    ("/AA", MEDIUM, "Automatic actions", "Additional actions triggered by events (open, close, page view, field focus)."),
    ("/OpenAction", LOW, "Open action", "An action runs when the document opens."),
]


def to_rgb(color, n):
    if color is None:
        return None
    try:
        if isinstance(color, int):
            return ((color >> 16) & 255, (color >> 8) & 255, color & 255)
        c = list(color)
        if len(c) == 1:
            v = int(c[0] * 255)
            return (v, v, v)
        if len(c) == 3:
            return tuple(int(x * 255) for x in c)
        if len(c) == 4:
            C, M, Y, K = c
            return tuple(int(255 * (1 - x) * (1 - K)) for x in (C, M, Y))
    except Exception:
        return None
    return None


def contains(outer, inner, tol=1.0):
    return (outer[0] - tol <= inner[0] and outer[1] - tol <= inner[1]
            and outer[2] + tol >= inner[2] and outer[3] + tol >= inner[3])


def scan_pdf(raw, report, nested):
    report.file_type = "PDF document"
    start = raw.find(b"%PDF")
    if start > 0:
        report.add(MEDIUM, "Data prepended before PDF header", "file",
                   f"{start:,} bytes precede the %PDF header (polyglot file).", "\n".join(printable_strings(raw[:start], limit=10)))
    eofs = [m.end() for m in re.finditer(rb"%%EOF", raw)]
    if eofs:
        tail = raw[eofs[-1]:]
        if len(tail.strip(b"\x00\r\n \t")) > 32:
            report.add(HIGH, "Data appended after file end", "file",
                       f"{len(tail):,} bytes after the final %%EOF marker - ignored by viewers.", "\n".join(printable_strings(tail, limit=15)))
            analyze_text(report, tail.decode("latin-1"), "appended data", hidden=True)

    try:
        doc = pymupdf.open(stream=raw, filetype="pdf")
    except Exception as e:
        report.error(f"Cannot open PDF: {e}")
        return
    if doc.needs_pass and not doc.authenticate(""):
        report.add(INFO, "Encrypted document", "file", "PDF requires a password - contents can't be inspected.")
        return

    _metadata(doc, report)
    _attachments(doc, report, nested)
    _objects(doc, report)
    hidden_layers = _layers(doc, report)
    final_text = []
    for pno in range(doc.page_count):
        try:
            _page(doc, doc[pno], pno + 1, report, hidden_layers, nested)
            final_text.append(doc[pno].get_text())
        except Exception as e:
            report.error(f"Page {pno + 1}: {e}")
    _revisions(raw, eofs, report, "\n".join(final_text))
    doc.close()


def _metadata(doc, report):
    md = {k: v for k, v in (doc.metadata or {}).items() if v}
    if md:
        report.add(INFO, "Document metadata", "info dictionary", "Producer/author metadata.",
                   "\n".join(f"{k}: {v}" for k, v in md.items()))
        analyze_text(report, "\n".join(str(v) for v in md.values()), "metadata", hidden=True, context="document property")
    try:
        xmp = doc.get_xml_metadata()
    except Exception:
        xmp = ""
    if xmp:
        txt = re.sub(r"<[^>]+>", " ", xmp)
        analyze_text(report, txt, "XMP metadata", hidden=True)
        if len(re.sub(r"\s+", "", txt)) > 4000:
            report.add(LOW, "Large XMP metadata", "XMP metadata", f"XMP metadata contains {len(txt):,} characters of text.")


def _attachments(doc, report, nested):
    try:
        names = doc.embfile_names()
    except Exception:
        names = []
    for n in names:
        try:
            info = doc.embfile_info(n)
            data = doc.embfile_get(n)
        except Exception:
            continue
        current_budget().charge(len(data), f"attachment {n}")
        fname = info.get("filename") or n
        report.add(MEDIUM, "Embedded file attachment", f"attachment '{fname}'",
                   f"PDF carries an attached file ({len(data):,} bytes) - scanned recursively below.")
        nested(fname, data)


def _objects(doc, report):
    found = {}
    uris = []
    js_snips = []
    n = doc.xref_length()
    for x in range(1, min(n, 200_000)):
        try:
            obj = doc.xref_object(x, compressed=False)
        except Exception:
            continue
        for key, sev, cat, desc in RISKY_KEYS:
            if re.search(re.escape(key) + r"(?![A-Za-z])", obj):
                found.setdefault((sev, cat, desc), []).append(x)
        if "/JS" in obj:
            try:
                kind, val = doc.xref_get_key(x, "JS")
                if kind == "xref":
                    raw_js = doc.xref_stream(int(val.split()[0]))
                    current_budget().charge(len(raw_js), f"JavaScript stream {val}")
                    val = raw_js.decode("latin-1", "replace")
                js_snips.append(val)
            except Exception:
                pass
        for m in re.finditer(r"/URI\s*\(([^)]*)\)", obj):
            uris.append(m.group(1))
    for (sev, cat, desc), xs in found.items():
        if cat == "JavaScript" and js_snips:
            continue
        report.add(sev, cat, "objects " + ", ".join(map(str, xs[:12])), desc)
    if js_snips:
        js = "\n\n".join(js_snips)
        report.add(HIGH, "JavaScript", "document", f"{len(js_snips)} JavaScript block(s).", js)
        analyze_text(report, js, "JavaScript", hidden=True)
    if uris:
        report.add(INFO, "Links", "document", f"{len(uris)} URI link(s).", "\n".join(dict.fromkeys(uris[:40])))

    # Orphaned objects: not reachable from the trailer
    try:
        if n > 100_000:
            return
        seen, stack = set(), [int(r) for r in re.findall(r"(\d+)\s+0\s+R", doc.pdf_trailer())]
        while stack:
            x = stack.pop()
            if x in seen or x <= 0 or x >= n:
                continue
            seen.add(x)
            try:
                stack.extend(int(r) for r in re.findall(r"(\d+)\s+\d+\s+R", doc.xref_object(x, compressed=False)))
            except Exception:
                pass
        orphans = []
        for x in range(1, n):
            if x in seen:
                continue
            try:
                obj = doc.xref_object(x, compressed=False)
            except Exception:
                continue
            if obj.strip() in ("null", "") or "/Type /XRef" in obj or "/Type /ObjStm" in obj:
                continue
            orphans.append(x)
        if orphans:
            texts = []
            for x in orphans[:200]:
                if doc.xref_is_stream(x):
                    try:
                        s = doc.xref_stream(x)
                    except Exception:
                        continue
                    current_budget().charge(len(s), f"orphaned object {x}")
                    texts += re.findall(r"\(((?:[^()\\]|\\.){3,})\)\s*Tj", s.decode("latin-1", "replace"))
            report.add(MEDIUM if texts else LOW, "Orphaned objects", "file structure",
                       f"{len(orphans)} object(s) are stored but not reachable from the document - viewers never display them.",
                       " | ".join(texts[:40]))
            if texts:
                analyze_text(report, " ".join(texts), "orphaned objects", hidden=True)
    except Exception as e:
        report.error(f"Orphan analysis skipped: {e}")


def _layers(doc, report):
    hidden = set()
    try:
        ocgs = doc.get_ocgs() or {}
    except Exception:
        return hidden
    for xref, info in ocgs.items():
        if not info.get("on", True):
            hidden.add(info.get("name"))
    if hidden:
        report.add(MEDIUM, "Hidden layers", "optional content", f"{len(hidden)} layer(s) are switched off by default.",
                   ", ".join(str(h) for h in hidden))
    return hidden


def _page(doc, page, pno, report, hidden_layers, nested):
    label = f"Page {pno}"
    crop = page.cropbox
    prect = (crop.x0, crop.y0, crop.x1, crop.y1)
    area = max(1.0, crop.width * crop.height)

    # Filled shapes (for background color + "covered by" detection)
    fills = []
    try:
        for d in page.get_drawings():
            if d.get("fill") is not None and d.get("rect") is not None:
                r = d["rect"]
                fills.append(((r.x0, r.y0, r.x1, r.y1), to_rgb(d["fill"], 3), d.get("seqno", 0), d.get("fill_opacity") or 1.0))
    except Exception:
        pass

    # Images drawn after text (z-order from the bbox log) cover that text
    covered_by_image = []
    image_rects = []
    try:
        log = page.get_bboxlog()
        for i, (kind, bb) in enumerate(log):
            if kind == "fill-image":
                image_rects.append(tuple(bb))
        for i, (kind, bb) in enumerate(log):
            if kind.endswith("-text"):
                for kind2, bb2 in log[i + 1:]:
                    if kind2 == "fill-image" and contains(bb2, bb):
                        covered_by_image.append(tuple(bb))
                        break
    except Exception:
        pass
    big_image = any((r[2] - r[0]) * (r[3] - r[1]) > 0.5 * area for r in image_rects)

    visible, hidden, ocr = [], {}, []
    last_y = None
    for span in page.get_texttrace():
        text = "".join(chr(c[0]) for c in span["chars"] if c[0] >= 0)
        if not text:
            continue
        bb = tuple(span["bbox"])
        reasons = []
        typ = span.get("type", 0)
        if typ == 3:
            if big_image:
                ocr.append(text)
                continue
            reasons.append("invisible text render mode (Tr 3)")
        if (span.get("opacity") if span.get("opacity") is not None else 1) < 0.1:
            reasons.append(f"opacity {span['opacity']:.2f}")
        if span.get("size", 12) < 1.5:
            reasons.append(f"tiny font ({span['size']:.2f}pt)")
        if bb[2] < prect[0] or bb[0] > prect[2] or bb[3] < prect[1] or bb[1] > prect[3]:
            reasons.append("positioned outside the visible page area")
        layer = span.get("layer")
        if layer and layer in hidden_layers:
            reasons.append(f"in hidden layer '{layer}'")
        seq = span.get("seqno", 0)
        color = to_rgb(span.get("color"), 3)
        under = [f for f in fills if f[2] < seq and f[3] >= 0.9 and contains(f[0], bb, 2)]
        over_image = any(contains(r, bb, 2) for r in image_rects)
        bg = under[-1][1] if under else (None if over_image else WHITE)
        if color and bg and typ != 3:
            cr = contrast(color, bg)
            if cr < INVISIBLE_CONTRAST:
                reasons.append(f"text color {hexs(color)} on background {hexs(bg)} (contrast {cr:.2f}:1)")
        cover = [f for f in fills if f[2] > seq and f[3] >= 0.9 and contains(f[0], bb, 1)]
        if cover:
            reasons.append(f"covered by a filled shape ({hexs(cover[0][1])}) drawn on top")
        elif any(contains(r, bb, 1) for r in covered_by_image):
            reasons.append("covered by an image drawn on top")
        if reasons:
            hidden.setdefault(tuple(reasons), []).append(text)
        else:
            if last_y is not None and abs(bb[1] - last_y) > 2:
                visible.append("\n")
            visible.append(text)
            last_y = bb[1]

    for rs, chunks in hidden.items():
        txt = " ".join(chunks)
        if re.search(r"\w{2,}", txt):
            report.add(HIGH, "Hidden text", label, "; ".join(rs), txt)
    if hidden:
        analyze_text(report, " ".join(" ".join(c) for c in hidden.values()), label, hidden=True)
    if ocr:
        otxt = " ".join(ocr)
        report.add(INFO, "OCR text layer", label, "Invisible text over a scanned image (normal for OCR'd scans).", otxt[:300])
        analyze_text(report, otxt, label, context="OCR layer")
    vis = "".join(visible)
    analyze_text(report, vis, label)

    # Annotations and form fields
    for annot in page.annots() or []:
        try:
            info = annot.info or {}
            content = " ".join(v for v in (info.get("content"), info.get("title"), info.get("subject")) if v)
            flags = annot.flags
            is_hidden = bool(flags & (pymupdf.PDF_ANNOT_IS_HIDDEN | pymupdf.PDF_ANNOT_IS_NO_VIEW))
            atype = annot.type[1]
            if atype == "FileAttachment":
                try:
                    data = annot.get_file()
                    current_budget().charge(len(data), "attachment annotation")
                    fname = annot.file_info.get("filename", "attachment")
                    report.add(MEDIUM, "Attached file annotation", label, f"File '{fname}' attached via annotation.")
                    nested(fname, data)
                except Exception:
                    pass
            if content.strip():
                if is_hidden:
                    report.add(HIGH, "Hidden annotation", label, f"{atype} annotation flagged hidden/no-view.", content)
                analyze_text(report, content, label, hidden=is_hidden, context=f"{atype} annotation")
            elif is_hidden:
                report.add(LOW, "Hidden annotation", label, f"{atype} annotation flagged hidden.")
        except Exception:
            continue
    try:
        for w in page.widgets() or []:
            val = str(w.field_value or "")
            if val.strip():
                hidden_w = getattr(w, "field_display", 0) in (1, 3)  # 1 = hidden, 3 = no-view
                analyze_text(report, val, label, hidden=hidden_w, context=f"form field '{w.field_name}'")
                if hidden_w:
                    report.add(HIGH, "Hidden form field", label, f"Form field '{w.field_name}' is hidden.", val)
    except Exception:
        pass
    return vis


def _revisions(raw, eofs, report, final_text):
    if len(eofs) <= 1:
        return
    # Linearized PDFs legitimately have two %%EOF markers close to each other
    report.add(INFO, "Incremental updates", "file",
               f"{len(eofs)} saved revisions are stacked in the file - earlier versions can be recovered.")
    final_lines = {ln.strip() for ln in final_text.splitlines() if ln.strip()}
    removed = []
    for end in eofs[:-1][-6:]:
        try:
            old = pymupdf.open(stream=raw[:end], filetype="pdf")
            for p in old:
                for ln in p.get_text().splitlines():
                    s = ln.strip()
                    if s and s not in final_lines and len(s) > 3 and s not in removed:
                        removed.append(s)
            old.close()
        except Exception:
            continue
    if removed:
        report.add(MEDIUM, "Content from earlier revision", "previous revisions",
                   f"{len(removed)} line(s) of text exist in an earlier saved version but not in the current one.",
                   "\n".join(removed[:60]))
        analyze_text(report, "\n".join(removed), "previous revisions", hidden=True)
