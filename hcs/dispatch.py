"""Identify a file by content and route it to the right scanner; recurse into attachments/embedded files."""
from __future__ import annotations

import io
import os
import re
import traceback
import zipfile

from .core import (Report, HIGH, MEDIUM, LOW, INFO, analyze_text, check_image_trailer, printable_strings,
                   read_zip_member, new_budget, BudgetExceeded)

MAX_DEPTH = 4
MAX_FILE = 500 * 1024 * 1024

SUPPORTED_EXT = {
    ".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb", ".pptx", ".pptm", ".ppsx",
    ".ppsm", ".potx", ".potm", ".doc", ".dot", ".xls", ".xlt", ".ppt", ".pps", ".pot", ".rtf", ".pdf", ".eml",
    ".msg", ".mht", ".mhtml", ".txt", ".csv", ".tsv", ".md", ".html", ".htm", ".xml", ".json", ".log", ".ini",
    ".odt", ".ods", ".odp", ".pub", ".vsd", ".vsdx", ".svg", ".yaml", ".yml",
}

OOXML_EXT = {".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb", ".pptx", ".pptm",
             ".ppsx", ".ppsm", ".potx", ".potm", ".vsdx"}
OLE_EXT = {".doc", ".dot", ".xls", ".xlt", ".ppt", ".pps", ".pot", ".msg", ".pub", ".vsd"}


def detect(name, raw):
    ext = os.path.splitext(name)[1].lower()
    head = raw[:16]
    if head.startswith(b"PK\x03\x04") or (raw[:2] == b"PK" and raw.rfind(b"PK\x05\x06") > 0):
        try:
            z = zipfile.ZipFile(io.BytesIO(raw))
            names = z.namelist()
            if "[Content_Types].xml" in names:
                return "ooxml"
            if "mimetype" in names and z.getinfo("mimetype").file_size < 200 and \
                    z.read("mimetype").startswith(b"application/vnd.oasis.opendocument"):
                return "odf"
            return "zip"
        except zipfile.BadZipFile:
            pass
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "msg" if ext == ".msg" or b"_\x00_\x00s\x00u\x00b\x00s\x00t\x00g\x001" in raw[:200_000] else "ole"
    if b"%PDF" in raw[:1024]:
        return "pdf"
    if raw.lstrip()[:5] == b"{\\rtf":
        return "rtf"
    if head[:8] == b"\x89PNG\r\n\x1a\n" or head[:3] == b"\xff\xd8\xff" or head[:6] in (b"GIF87a", b"GIF89a"):
        return "image"
    if ext in (".eml", ".mht", ".mhtml") or re.match(rb"(?:[\w-]+:[^\r\n]*\r?\n)+", raw[:2000]) and \
            re.search(rb"^(Received|From|MIME-Version|Message-ID|Return-Path):", raw[:4000], re.I | re.M) and \
            re.search(rb"^(Subject|Content-Type):", raw[:20000], re.I | re.M):
        return "eml"
    from .textscan import looks_texty
    if looks_texty(raw):
        return "text"
    return "binary"


EXPECTED = {
    "ooxml": OOXML_EXT, "ole": OLE_EXT - {".msg"}, "msg": {".msg"}, "pdf": {".pdf"}, "rtf": {".rtf", ".doc"},
    "odf": {".odt", ".ods", ".odp", ".odg"}, "eml": {".eml", ".mht", ".mhtml"},
}


def scan_bytes(name, raw, depth=0, path=None):
    rep = Report(name)

    def nested(child_name, data):
        if depth + 1 > MAX_DEPTH or not data:
            return
        child = scan_bytes(child_name, data, depth + 1)
        if child.findings or child.errors or child.children:
            rep.children.append(child)

    kind = detect(name, raw)
    ext = os.path.splitext(name)[1].lower()
    exp = EXPECTED.get(kind)
    if exp and ext and ext not in exp and depth == 0:
        rep.add(MEDIUM, "File type mismatch", "file",
                f"Extension is '{ext}' but the content is actually {kind.upper()} - disguised file type.")
    try:
        if kind == "ooxml":
            from .ooxml import scan_ooxml
            scan_ooxml(raw, rep, nested)
        elif kind == "odf":
            from .odf import scan_odf
            scan_odf(raw, rep, nested)
        elif kind == "ole":
            from .legacy import scan_ole
            scan_ole(raw, rep, nested, ext)
        elif kind == "msg":
            from .emailscan import scan_msg
            scan_msg(raw, rep, nested, path)
        elif kind == "pdf":
            from .pdfscan import scan_pdf
            scan_pdf(raw, rep, nested)
        elif kind == "rtf":
            from .legacy import scan_rtf
            scan_rtf(raw, rep, nested)
        elif kind == "eml":
            from .emailscan import scan_eml
            scan_eml(raw, rep, nested)
        elif kind == "zip":
            from .ooxml import check_zip_container
            rep.file_type = "ZIP archive"
            check_zip_container(rep, raw, "archive")
            z = zipfile.ZipFile(io.BytesIO(raw))
            for i in z.infolist()[:200]:
                if not i.is_dir() and not i.flag_bits & 1:
                    nested(i.filename, read_zip_member(z, i))
        elif kind == "image":
            rep.file_type = "Image"
            extra = check_image_trailer(rep, raw, "image")
            if extra and extra[:2] == b"PK":
                nested(name + ".appended.zip", extra)
        elif kind == "text":
            from .textscan import scan_text
            scan_text(raw, rep, name)
        else:
            rep.file_type = "Unrecognized binary"
            strs = printable_strings(raw[:5_000_000], min_len=8, limit=2000)
            analyze_text(rep, "\n".join(strs), "embedded strings")
            if depth == 0:
                rep.add(INFO, "Unsupported file type", "file", "Only generic string checks were performed.")
    except BudgetExceeded as e:
        rep.add(HIGH, "Decompression limit exceeded", "file",
                f"Scanning stopped: {e}. Legitimate documents rarely expand this much - possible decompression bomb.")
    except Exception as e:
        rep.error(f"Scanner crashed: {e}\n{traceback.format_exc(limit=3)}")
    return rep


def scan_path(path, check_ads=True):
    """Scan one file. Disk-slack checks are separate (see ntfs.collect_slack) so parsing never needs admin."""
    size = os.path.getsize(path)
    if size > MAX_FILE:
        rep = Report(path)
        rep.error(f"File too large ({size:,} bytes)")
        return rep
    with open(path, "rb") as f:
        raw = f.read()
    new_budget()
    rep = scan_bytes(os.path.basename(path), raw, 0, path)
    rep.path = path
    if check_ads:
        from .ntfs import scan_ads

        def nested(n, d):
            rep.children.append(scan_bytes(n, d, 1))
        try:
            scan_ads(path, rep, nested)
        except Exception as e:
            rep.error(f"ADS check failed: {e}")
    return rep


def expand_paths(paths, include_all=False):
    out = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                for f in files:
                    if include_all or os.path.splitext(f)[1].lower() in SUPPORTED_EXT:
                        out.append(os.path.join(root, f))
        elif os.path.isfile(p):
            out.append(p)
    return out
