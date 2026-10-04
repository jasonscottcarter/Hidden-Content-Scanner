"""Legacy binary Office (OLE2: .doc/.xls/.ppt/.pub/.vsd), RTF, and VBA macro analysis."""
from __future__ import annotations

import re
import struct

import olefile

from .core import HIGH, MEDIUM, LOW, INFO, analyze_text, printable_strings

DANGEROUS = (".exe", ".dll", ".scr", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta", ".lnk",
             ".msi", ".jar", ".wsf", ".cpl", ".com", ".pif")


# --------------------------------------------------------------------------------------
# VBA / XLM macros
# --------------------------------------------------------------------------------------

def analyze_vba(report, data, location):
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        report.error("oletools not installed - macro details unavailable")
        return
    try:
        vp = VBA_Parser(filename=location, data=data)
    except Exception as e:
        report.error(f"Macro parser failed: {e}")
        return
    try:
        if not vp.detect_vba_macros() and not getattr(vp, "detect_xlm_macros", lambda: False)():
            return
        code = []
        for _, stream, vname, src in vp.extract_macros():
            if src and src.strip():
                code.append(f"' --- {vname} ({stream}) ---\n{src.strip()}")
        results = vp.analyze_macros() or []
        auto = sorted({kw for t, kw, _ in results if t == "AutoExec"})
        susp = sorted({kw for t, kw, _ in results if t == "Suspicious"})
        iocs = sorted({kw for t, kw, _ in results if t == "IOC"})
        detail = []
        if auto:
            detail.append("Runs automatically via: " + ", ".join(auto))
        if susp:
            detail.append("Suspicious keywords: " + ", ".join(susp[:25]))
        if iocs:
            detail.append("Indicators (URLs/IPs/files): " + ", ".join(iocs[:15]))
        sev = HIGH if auto or susp else MEDIUM
        report.add(sev, "Macro code analysis", location, " | ".join(detail) or "Macro code present.", "\n\n".join(code))
        try:
            if vp.detect_vba_stomping():
                report.add(HIGH, "VBA stomping", location,
                           "Compiled macro p-code doesn't match the visible source - the real code is concealed.")
        except Exception:
            pass
        lits = " ".join(re.findall(r'"([^"]{8,})"', "\n".join(code)))
        if lits:
            analyze_text(report, lits, location, hidden=True, context="macro strings")
    finally:
        vp.close()


# --------------------------------------------------------------------------------------
# OLE2 compound files
# --------------------------------------------------------------------------------------

KNOWN_STREAMS = {
    "WordDocument", "1Table", "0Table", "Data", "\x05SummaryInformation", "\x05DocumentSummaryInformation",
    "\x01CompObj", "ObjectPool", "Macros", "_VBA_PROJECT_CUR", "MsoDataStore", "Workbook", "Book",
    "PowerPoint Document", "Current User", "Pictures", "_signatures", "\x06DataSpaces", "EncryptedPackage",
    "EncryptionInfo", "VBA", "PROJECT", "PROJECTwm", "_xmlsignatures", "\x01Ole", "Ole", "CompObj",
    "Contents", "Quill", "Escher", "Envelope", "VisioDocument", "EncryptedSummary", "Revision Log",
    "User Names", "Workspace", "_signatures",
}


def word97_text(ole):
    """Extract the full text of a Word 97-2003 document via the piece table."""
    wd = ole.openstream("WordDocument").read()
    if len(wd) < 426 or struct.unpack("<H", wd[:2])[0] != 0xA5EC:
        return None
    flags = struct.unpack("<H", wd[0x0A:0x0C])[0]
    if flags & 0x0100:  # fEncrypted
        return None
    table_name = "1Table" if flags & 0x0200 else "0Table"
    if not ole.exists(table_name):
        return None
    tbl = ole.openstream(table_name).read()
    fc_clx, lcb_clx = struct.unpack("<II", wd[418:426])
    clx = tbl[fc_clx:fc_clx + lcb_clx]
    i = 0
    while i < len(clx) and clx[i] == 0x01:
        i += 3 + struct.unpack("<H", clx[i + 1:i + 3])[0]
    if i >= len(clx) or clx[i] != 0x02:
        return None
    lcb = struct.unpack("<I", clx[i + 1:i + 5])[0]
    plc = clx[i + 5:i + 5 + lcb]
    n = (lcb - 4) // 12
    cps = struct.unpack(f"<{n + 1}I", plc[:(n + 1) * 4])
    out = []
    for k in range(n):
        pcd = plc[(n + 1) * 4 + k * 8:(n + 1) * 4 + k * 8 + 8]
        fc = struct.unpack("<I", pcd[2:6])[0]
        count = cps[k + 1] - cps[k]
        if fc & 0x40000000:
            off = (fc & ~0x40000000) // 2
            out.append(wd[off:off + count].decode("cp1252", "replace"))
        else:
            out.append(wd[fc:fc + count * 2].decode("utf-16le", "replace"))
    return "".join(out)


def ppt97_text(ole):
    data = ole.openstream("PowerPoint Document").read()
    out, pos, n = [], 0, len(data)
    while pos + 8 <= n:
        ver_inst, rtype, rlen = struct.unpack("<HHI", data[pos:pos + 8])
        if ver_inst & 0x0F == 0x0F:  # container: descend
            pos += 8
            continue
        body = data[pos + 8:pos + 8 + rlen]
        if rtype == 0x0FA0:
            out.append(body.decode("utf-16le", "replace"))
        elif rtype == 0x0FA8:
            out.append(body.decode("cp1252", "replace"))
        elif rtype == 0x0FBA:
            out.append(body.decode("utf-16le", "replace"))
        pos += 8 + rlen
    return "\n".join(out)


def xls_sheets(ole):
    name = "Workbook" if ole.exists("Workbook") else ("Book" if ole.exists("Book") else None)
    if not name:
        return [], False
    data = ole.openstream(name).read()
    sheets, pos, encrypted = [], 0, False
    while pos + 4 <= len(data):
        rid, ln = struct.unpack("<HH", data[pos:pos + 4])
        body = data[pos + 4:pos + 4 + ln]
        if rid == 0x002F:
            encrypted = True
        elif rid == 0x0085 and len(body) >= 8:
            state, kind, nlen, fl = body[4] & 0x03, body[5], body[6], body[7]
            raw = body[8:8 + (nlen * 2 if fl & 1 else nlen)]
            sname = raw.decode("utf-16le" if fl & 1 else "cp1252", "replace")
            sheets.append((sname, state, kind))
        pos += 4 + ln
    return sheets, encrypted


def scan_ole(raw, report, nested, ext=""):
    try:
        ole = olefile.OleFileIO(raw)
    except Exception as e:
        report.error(f"Not a valid OLE file: {e}")
        return
    paths = ["/".join(p) for p in ole.listdir(streams=True, storages=True)]
    tops = {p.split("/")[0] for p in paths}

    if "EncryptedPackage" in tops:
        report.file_type = "Encrypted Office document"
        report.add(INFO, "Encrypted document", "file", "Password-protected Office file - contents can't be inspected without the password.")
        check_ole_slack(report, ole, raw)
        ole.close()
        return

    if "WordDocument" in tops:
        report.file_type = "Word 97-2003 document (.doc)"
    elif "Workbook" in tops or "Book" in tops:
        report.file_type = "Excel 97-2003 workbook (.xls)"
    elif "PowerPoint Document" in tops:
        report.file_type = "PowerPoint 97-2003 presentation (.ppt)"
    elif "VisioDocument" in tops:
        report.file_type = "Visio drawing"
    elif "Quill" in tops:
        report.file_type = "Publisher document"
    else:
        report.file_type = "OLE compound file"

    # Metadata
    try:
        md = ole.get_metadata()
        meta = []
        for attr in ("title", "subject", "author", "keywords", "comments", "last_saved_by", "revision_number",
                     "create_time", "last_saved_time", "company", "manager", "category", "template"):
            v = getattr(md, attr, None)
            if v:
                v = v.decode("cp1252", "replace") if isinstance(v, bytes) else v
                meta.append(f"{attr}: {v}")
                if attr in ("comments", "keywords", "subject", "title"):
                    analyze_text(report, str(v), f"metadata [{attr}]", hidden=True, context="document property")
        if meta:
            report.add(INFO, "Document metadata", "summary information", "Author / revision metadata.", "\n".join(meta))
    except Exception:
        pass

    # Macros
    if any(p.split("/")[-1] in ("VBA", "_VBA_PROJECT", "PROJECT", "dir") or p.startswith("Macros") for p in paths):
        report.add(HIGH, "VBA macros", "file", "Document contains a VBA macro project.")
    analyze_vba(report, raw, "macros")

    # Text and type-specific checks
    try:
        if "WordDocument" in tops:
            txt = word97_text(ole)
            if txt is None:
                txt = "\n".join(printable_strings(ole.openstream("WordDocument").read(), min_len=8, limit=4000))
            analyze_text(report, txt, "document text")
            report.add(INFO, "Limited analysis", "file",
                       "Legacy .doc formatting (white/hidden/tiny text) can't be fully evaluated; save as .docx and rescan for a complete check. "
                       "Text and Unicode-smuggling checks were performed.")
            if re.search(r"\x13\s*(DDE|DDEAUTO|INCLUDETEXT)\b", txt or "", re.I):
                report.add(HIGH, "Field code", "document text", "DDE/INCLUDETEXT field present.")
        elif "PowerPoint Document" in tops:
            analyze_text(report, ppt97_text(ole), "presentation text")
            report.add(INFO, "Limited analysis", "file", "Save as .pptx and rescan to check shape-level hiding (off-slide, white text).")
        elif "Workbook" in tops or "Book" in tops:
            sheets, encrypted = xls_sheets(ole)
            if encrypted:
                report.add(INFO, "Encrypted workbook", "file", "Workbook is encrypted (FILEPASS).")
            for name, state, kind in sheets:
                if kind == 0x01:
                    report.add(HIGH, "Excel 4.0 (XLM) macro sheet", f"Sheet '{name}'", "Legacy XLM macro sheet - common malware technique.")
                if state == 2:
                    report.add(HIGH, "Very hidden sheet", f"Sheet '{name}'", "Sheet is 'very hidden' (cannot be unhidden from Excel's menus).")
                elif state == 1:
                    report.add(MEDIUM, "Hidden sheet", f"Sheet '{name}'", "Sheet is hidden.")
            wb = ole.openstream("Workbook" if ole.exists("Workbook") else "Book").read()
            analyze_text(report, "\n".join(printable_strings(wb, min_len=6, limit=5000)), "workbook strings")
            report.add(INFO, "Limited analysis", "file", "Save as .xlsx and rescan for cell-level hidden-content checks.")
    except Exception as e:
        report.error(f"Text extraction failed: {e}")

    # Embedded objects / packages
    for p in paths:
        last = p.split("/")[-1]
        try:
            if last == "\x01Ole10Native":
                data = ole.openstream(p).read()
                fname, payload = "embedded.bin", data
                try:
                    from oletools.oleobj import OleNativeStream
                    ns = OleNativeStream(data)
                    fname = ns.filename or fname
                    payload = ns.data or data
                except Exception:
                    pass
                sev = HIGH if str(fname).lower().endswith(DANGEROUS) else MEDIUM
                report.add(sev, "Embedded package", p.replace("\x01", ""), f"Embedded file '{fname}' ({len(payload):,} bytes).")
                nested(str(fname), payload)
            elif last == "Package":
                data = ole.openstream(p).read()
                report.add(MEDIUM, "Embedded document", p, f"Embedded Office document ({len(data):,} bytes).")
                nested("embedded_package.zip", data)
            elif last in ("CONTENTS", "Contents") and p.startswith(("ObjectPool", "MBD")):
                data = ole.openstream(p).read()
                if data[:4] == b"%PDF":
                    nested("embedded.pdf", data)
        except Exception as e:
            report.error(f"Embedded object {p}: {e}")
    storages = sorted({p.split("/")[0] + "/" + p.split("/")[1] for p in paths if p.startswith(("ObjectPool/", "MBD")) and "/" in p})
    if storages:
        report.add(MEDIUM, "Embedded OLE objects", "file", f"{len(storages)} embedded object storage(s).", "\n".join(storages[:30]))

    odd = sorted(t for t in tops if t not in KNOWN_STREAMS and not t.startswith(("MBD", "_", "\x05", "\x01", "\x03", "Ole")))
    if odd:
        report.add(LOW, "Non-standard streams", "file", "Streams not normally found in this file type.",
                   ", ".join(o.encode("unicode_escape").decode() for o in odd))

    check_ole_slack(report, ole, raw)
    ole.close()


def check_ole_slack(report, ole, raw):
    """Unallocated sectors inside the compound file and data appended after its end."""
    try:
        ss = ole.sectorsize
        fat = ole.fat
        nsect = (len(raw) - ss) // ss
        free_data = []
        last_used = -1
        for i in range(min(len(fat), nsect)):
            if fat[i] != olefile.FREESECT:
                last_used = i
            else:
                chunk = raw[(i + 1) * ss:(i + 2) * ss]
                if chunk.strip(b"\x00\xff"):
                    free_data.append(chunk)
        if free_data:
            blob = b"".join(free_data)
            strs = printable_strings(blob, min_len=6, limit=30)
            report.add(MEDIUM if strs else LOW, "Data in unallocated OLE sectors", "compound-file free space",
                       f"{len(free_data)} unallocated sector(s) still contain data ({len(blob):,} bytes) - leftovers from "
                       "earlier saves (e.g. Word 'fast save') or deliberately hidden content.", "\n".join(strs))
            if strs:
                analyze_text(report, "\n".join(strs), "OLE free sectors", hidden=True)
        end = (last_used + 2) * ss
        if last_used >= 0 and len(raw) > end + ss:
            extra = raw[end:]
            if extra.strip(b"\x00"):
                report.add(HIGH, "Data appended after file end", "file",
                           f"{len(extra):,} bytes after the last allocated sector.", "\n".join(printable_strings(extra, limit=10)))
    except Exception as e:
        report.error(f"OLE slack check skipped: {e}")


# --------------------------------------------------------------------------------------
# RTF
# --------------------------------------------------------------------------------------

def rtf_plain(text):
    text = re.sub(r"\\'([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]).decode("cp1252", "replace"), text)
    text = re.sub(r"\\u(-?\d+)\??", lambda m: chr(int(m.group(1)) % 65536), text)
    text = re.sub(r"\{\\\*[^{}]*\}", " ", text)
    text = re.sub(r"\\[a-zA-Z]+-?\d* ?", "", text)
    return re.sub(r"[{}]", "", text)


def scan_rtf(raw, report, nested):
    report.file_type = "Rich Text Format (.rtf)"
    text = raw.decode("latin-1")
    try:
        from oletools.rtfobj import RtfObjParser
        p = RtfObjParser(raw)
        p.parse()
        for obj in p.objects:
            if obj.is_ole:
                cls = (obj.class_name or b"").decode("latin-1", "replace") if isinstance(obj.class_name, bytes) else str(obj.class_name)
                sev = HIGH if re.search(r"equation\.3|package|htmlfile|ole2link|script", cls, re.I) else MEDIUM
                report.add(sev, "Embedded OLE object (RTF)", f"offset {obj.start}", f"Object class '{cls}'.")
                if obj.is_package:
                    report.add(HIGH if (obj.filename or "").lower().endswith(DANGEROUS) else MEDIUM, "Embedded package",
                               f"offset {obj.start}", f"Packaged file '{obj.filename}'.")
                    nested(obj.filename or "package.bin", obj.olepkgdata)
                elif obj.oledata:
                    nested(f"rtf_object_{obj.start}.ole", obj.oledata)
            elif obj.rawdata and len(obj.rawdata) > 64:
                report.add(LOW, "Embedded binary data (RTF)", f"offset {obj.start}", f"{len(obj.rawdata):,} bytes of non-OLE object data.")
    except Exception as e:
        report.error(f"RTF object parsing: {e}")

    if re.search(r"\\objupdate", text):
        report.add(MEDIUM, "Auto-updating object", "file", r"\objupdate forces embedded objects to load automatically.")

    hidden = re.findall(r"\\v(?![a-z0-9-])\s?((?:[^\\{}]|\\[^v])*?)(?=\\v0|\}|$)", text)
    hidden = [rtf_plain(h).strip() for h in hidden if rtf_plain(h).strip()]
    if hidden:
        report.add(HIGH, "Hidden text", r"\v formatting", r"Text marked hidden with the \v control word.", " | ".join(hidden))
        analyze_text(report, "\n".join(hidden), "RTF hidden text", hidden=True)

    # Colour table -> near-white text via \cfN
    ct = re.search(r"\\colortbl\s*;?(.*?)\}", text, re.S)
    if ct:
        colors = [None]
        for entry in ct.group(1).split(";"):
            m = [re.search(rf"\\{c}(\d+)", entry) for c in ("red", "green", "blue")]
            colors.append(tuple(int(x.group(1)) for x in m) if all(m) else None)
        white = {i for i, c in enumerate(colors) if c and min(c) >= 235}
        if white:
            hits = [rtf_plain(t).strip() for n, t in re.findall(r"\\cf(\d+)\s?([^{}]*?)(?=\\cf\d|\}|$)", text) if int(n) in white]
            hits = [h for h in hits if re.search(r"\w", h)]
            if hits:
                report.add(HIGH, "Hidden text", "near-white text color", "Text drawn in a white/near-white color.", " | ".join(hits))
                analyze_text(report, "\n".join(hits), "RTF white text", hidden=True)
    tiny = [rtf_plain(t).strip() for t in re.findall(r"\\fs[0-3](?!\d)\s?([^{}\\]*)", text)]
    tiny = [t for t in tiny if re.search(r"\w", t)]
    if tiny:
        report.add(HIGH, "Hidden text", "tiny font", "Text at 1.5pt or smaller.", " | ".join(tiny))
        analyze_text(report, "\n".join(tiny), "RTF tiny text", hidden=True)

    last = text.rfind("}")
    if last != -1 and text[last + 1:].strip("\x00\r\n "):
        extra = raw[last + 1:]
        report.add(HIGH, "Data appended after file end", "file", f"{len(extra):,} bytes after the closing brace of the RTF document.",
                   "\n".join(printable_strings(extra, limit=10)))
    analyze_text(report, rtf_plain(text), "document text")
