"""Plain text / CSV / Markdown / HTML / XML / JSON scanner."""
from __future__ import annotations

import codecs
import re

from .core import HIGH, MEDIUM, LOW, INFO, analyze_text
from . import htmlscan

MAX_TEXT = 20_000_000


def decode(raw):
    for bom, enc in ((codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
                     (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16")):
        if raw.startswith(bom):
            return raw.decode(enc, "replace"), enc
    sample = raw[:4000]
    if sample and sample.count(b"\x00") > len(sample) * 0.3:
        enc = "utf-16-le" if sample[1:2] == b"\x00" else "utf-16-be"
        return raw.decode(enc, "replace"), enc
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("cp1252", "replace"), "cp1252"


def looks_texty(raw):
    sample = raw[:8000]
    if not sample:
        return True
    text, _ = decode(sample)
    bad = sum(1 for c in text if ord(c) < 32 and c not in "\r\n\t\x0c")
    return bad < len(text) * 0.05


def scan_text(raw, report, name):
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    text, enc = decode(raw[:MAX_TEXT])
    report.file_type = {"csv": "CSV", "md": "Markdown", "html": "HTML", "htm": "HTML", "xml": "XML", "json": "JSON",
                        "svg": "SVG image"}.get(ext, "Text file") + f" ({enc})"

    nulls = text.count("\x00")
    if nulls and not enc.startswith("utf-16"):
        report.add(MEDIUM, "Null bytes in text", "file", f"{nulls} NUL characters - may hide content from editors that stop at NUL.")

    lines = text.splitlines()
    trailing = [ln for ln in lines if re.search(r"[ \t]+$", ln) and ln.strip()]
    mixed = [ln for ln in trailing if re.search(r"(?: \t|\t )[ \t]*$", ln)]
    if len(trailing) >= 5 and (len(mixed) >= 3 or len(trailing) > 0.4 * max(1, len([l for l in lines if l.strip()]))):
        report.add(MEDIUM, "Whitespace steganography pattern", "file",
                   f"{len(trailing)} line(s) end in trailing spaces/tabs ({len(mixed)} mixing both) - consistent with "
                   "whitespace-encoding tools such as SNOW.",
                   "\n".join(repr(ln[-40:]) for ln in trailing[:10]))
    ws_only = [ln for ln in lines if ln and not ln.strip() and " " in ln and "\t" in ln]
    if len(ws_only) >= 8:
        report.add(MEDIUM, "Whitespace-only encoded lines", "file",
                   f"{len(ws_only)} lines contain only mixed spaces and tabs (whitespace-encoded data).")

    for i, ln in enumerate(lines, 1):
        m = re.search(r"\S([ \t]{150,})(\S.*)", ln) or re.match(r"^([ \t]{200,})(\S.*)", ln)
        if m:
            report.add(MEDIUM, "Text pushed off-screen", f"line {i}",
                       f"Content preceded by {len(m.group(1))} whitespace characters, pushing it far past the visible edge.", m.group(2))
            analyze_text(report, m.group(2), f"line {i}", hidden=True)
    blank_run, start = 0, 0
    for i, ln in enumerate(lines, 1):
        if not ln.strip():
            if blank_run == 0:
                start = i
            blank_run += 1
        else:
            if blank_run >= 40:
                rest = "\n".join(lines[i - 1:i + 20])
                report.add(MEDIUM, "Content after large blank gap", f"line {i}",
                           f"{blank_run} consecutive blank lines (from line {start}) precede this content.", rest)
                analyze_text(report, rest, f"line {i}", hidden=True)
            blank_run = 0

    if ext in ("html", "htm", "xhtml", "svg") or re.search(r"<html|<body|<div", text[:3000], re.I):
        htmlscan.scan_html(report, text, "document")
        return
    if ext == "md":
        hid = re.findall(r"<!--(.*?)-->", text, re.S) + re.findall(r"^\[[^\]]*\]:\s*#\s*\((.*)\)\s*$", text, re.M)
        if hid:
            report.add(LOW, "Markdown comments", "file", f"{len(hid)} comment(s) that don't render but are read by AI tools.", "\n".join(hid))
            analyze_text(report, "\n".join(hid), "markdown comments", hidden=True)
    if ext in ("csv", "tsv"):
        cells = re.findall(r"(?:^|[,;\t])\s*\"?([=+\-@][A-Za-z]{2,}[^,\n]*)", text, re.M)
        dde = [c for c in cells if re.search(r"\w+\|['\"]|cmd\||HYPERLINK\(|WEBSERVICE\(", c, re.I)]
        if dde:
            report.add(HIGH, "CSV formula injection", "file", "Cells that execute as formulas/DDE when opened in Excel.", "\n".join(dde[:20]))
        elif cells:
            report.add(LOW, "CSV formulas", "file", f"{len(cells)} cell(s) begin with a formula character.", "\n".join(cells[:10]))
    analyze_text(report, text, "document")
