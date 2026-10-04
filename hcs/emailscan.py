"""Email scanners: .eml / .mht (MIME) and Outlook .msg."""
from __future__ import annotations

import email
import email.policy
import re
from email.utils import parseaddr

from .core import HIGH, MEDIUM, LOW, INFO, analyze_text
from . import htmlscan

DANGEROUS = (".exe", ".dll", ".scr", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta", ".lnk",
             ".msi", ".jar", ".wsf", ".cpl", ".com", ".pif", ".iso", ".img", ".vhd", ".vhdx", ".one", ".xll",
             ".html", ".htm", ".svg")


def _domain(addr):
    a = parseaddr(addr or "")[1]
    return a.rsplit("@", 1)[-1].lower() if "@" in a else ""


def check_headers(report, h):
    """h: dict of header name (lower) -> value."""
    summary = [f"{k.title()}: {h[k]}" for k in ("from", "to", "reply-to", "return-path", "subject", "date") if h.get(k)]
    if summary:
        report.add(INFO, "Message headers", "headers", "Key headers.", "\n".join(summary))
    fd, rd, rp = _domain(h.get("from")), _domain(h.get("reply-to")), _domain(h.get("return-path"))
    if fd and rd and rd != fd:
        report.add(LOW, "Reply-To differs from sender", "headers", f"Replies go to '{rd}', not the sender's domain '{fd}'.")
    if fd and rp and rp != fd and not rp.endswith("." + fd):
        report.add(INFO, "Return-Path differs from sender", "headers", f"Envelope sender domain '{rp}' vs From domain '{fd}'.")
    auth = h.get("authentication-results", "")
    fails = re.findall(r"\b(spf|dkim|dmarc)=(fail|softfail|permerror)", auth, re.I)
    if fails:
        report.add(MEDIUM, "Authentication failure", "headers", "Sender authentication failed: " +
                   ", ".join(f"{a}={b}" for a, b in fails), auth)
    analyze_text(report, " ".join(str(h.get(k, "")) for k in ("from", "subject", "to")), "headers")


def compare_parts(report, plain, html_visible, location):
    """AI tools often read the text/plain part; people see the HTML. Flag content that only exists in one."""
    if not plain or not html_visible:
        return
    pw = set(re.findall(r"[a-z]{4,}", plain.lower()))
    hw = set(re.findall(r"[a-z]{4,}", html_visible.lower()))
    only_plain = pw - hw
    if len(only_plain) >= 12 and len(only_plain) > 0.3 * max(1, len(pw)):
        lines = [ln for ln in plain.splitlines() if set(re.findall(r"[a-z]{4,}", ln.lower())) & only_plain]
        report.add(MEDIUM, "Plain-text part differs from HTML", location,
                   f"{len(only_plain)} words appear only in the text/plain version (which AI assistants and some clients read) "
                   "and not in the HTML version people see.", "\n".join(lines[:30]))
        analyze_text(report, "\n".join(lines), location, hidden=True, context="text/plain-only content")


def scan_eml(raw, report, nested):
    report.file_type = "Email message (.eml)"
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    h = {k.lower(): str(v) for k, v in msg.items()}
    check_headers(report, h)
    _walk_mime(msg, report, nested, "body")


def _walk_mime(msg, report, nested, label):
    plain, html_vis = [], []
    attachments = []
    for i, part in enumerate(msg.walk()):
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        fname = part.get_filename()
        disp = (part.get_content_disposition() or "").lower()
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        if ctype == "message/rfc822":
            inner = part.get_payload()
            data = inner[0].as_bytes() if isinstance(inner, list) and inner else payload
            attachments.append(fname or "attached-message.eml")
            nested(fname or "attached-message.eml", data)
            continue
        if fname or disp == "attachment" or not ctype.startswith("text/"):
            name = fname or f"part{i}.{ctype.split('/')[-1]}"
            attachments.append(f"{name} ({ctype}, {len(payload):,} bytes)")
            if name.lower().endswith(DANGEROUS):
                report.add(HIGH, "Risky attachment type", name, "Attachment type commonly used to deliver malware or phishing pages.")
            if payload:
                nested(name, payload)
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, "replace")
        except LookupError:
            text = payload.decode("utf-8", "replace")
        if ctype == "text/html":
            html_vis.append(htmlscan.scan_html(report, text, f"{label} (HTML)", is_email=True))
        else:
            plain.append(text)
            analyze_text(report, text, f"{label} ({ctype})")
    if attachments:
        report.add(INFO, "Attachments", label, f"{len(attachments)} attachment(s) - each is scanned below.", "\n".join(attachments))
    compare_parts(report, "\n".join(plain), " ".join(html_vis), label)


def scan_msg(raw, report, nested, path=None):
    report.file_type = "Outlook message (.msg)"
    import extract_msg
    try:
        m = extract_msg.openMsg(path if path else raw)
    except Exception as e:
        report.error(f"Cannot open .msg: {e}")
        from .legacy import scan_ole
        scan_ole(raw, report, nested)
        return
    try:
        h = {}
        try:
            hdr = m.header
            if hdr is not None:
                h = {k.lower(): str(v) for k, v in hdr.items()}
        except Exception:
            pass
        h.setdefault("from", str(m.sender or ""))
        h.setdefault("to", str(m.to or ""))
        h.setdefault("subject", str(m.subject or ""))
        h.setdefault("date", str(m.date or ""))
        check_headers(report, h)

        plain = m.body or ""
        if plain:
            analyze_text(report, plain, "body (text)")
        html_vis = ""
        html = None
        try:
            html = m.htmlBody
        except Exception:
            pass
        if html:
            html = html.decode("utf-8", "replace") if isinstance(html, bytes) else html
            html_vis = htmlscan.scan_html(report, html, "body (HTML)", is_email=True)
        elif getattr(m, "rtfBody", None):
            from .legacy import scan_rtf
            from .core import Report
            sub = Report("body.rtf")
            scan_rtf(m.rtfBody, sub, nested)
            for f in sub.findings:
                report.add(f.severity, f.category, "body (RTF): " + f.location, f.detail, f.snippet)
        compare_parts(report, plain, html_vis, "body")

        names = []
        for a in m.attachments:
            name = getattr(a, "longFilename", None) or getattr(a, "shortFilename", None) or getattr(a, "name", None) or "attachment"
            data = a.data
            hidden = getattr(a, "hidden", False)
            if hasattr(data, "exportBytes"):  # embedded .msg
                try:
                    data = data.exportBytes()
                except Exception:
                    data = None
                name = name if name.lower().endswith(".msg") else name + ".msg"
            if isinstance(data, (bytes, bytearray)):
                names.append(f"{name} ({len(data):,} bytes)" + (" [hidden]" if hidden else ""))
                if name.lower().endswith(DANGEROUS):
                    report.add(HIGH, "Risky attachment type", name, "Attachment type commonly used to deliver malware or phishing pages.")
                if hidden:
                    report.add(MEDIUM, "Hidden attachment", name, "Attachment is flagged hidden (e.g. inline image or concealed file).")
                nested(name, bytes(data))
            else:
                names.append(f"{name} (not extractable)")
        if names:
            report.add(INFO, "Attachments", "message", f"{len(names)} attachment(s) - each is scanned below.", "\n".join(names))
    finally:
        try:
            m.close()
        except Exception:
            pass
    from .legacy import check_ole_slack
    try:
        import olefile
        ole = olefile.OleFileIO(raw)
        check_ole_slack(report, ole, raw)
        ole.close()
    except Exception:
        pass
