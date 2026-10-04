"""Export scan results as a standalone HTML report."""
from __future__ import annotations

import datetime
import html

from .core import visible_repr

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#5d6675;--line:#e2e5ea;
--high:#c62828;--med:#d97706;--low:#2563eb;--info:#6b7280}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--fg:#e6e8eb;--muted:#9aa3ae;--line:#2c323b}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}.sub{color:var(--muted);margin-bottom:20px}
.file{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:14px 0;padding:14px 16px}
.file .child{margin-left:18px;border-left:3px solid var(--line);padding-left:12px;border-radius:0;border-top:0;border-right:0;border-bottom:0}
.hdr{display:flex;flex-wrap:wrap;gap:8px;align-items:baseline}.path{font-weight:600;word-break:break-all}
.type{color:var(--muted)}.pill{font-size:12px;font-weight:600;padding:1px 8px;border-radius:99px;color:#fff}
.HIGH{background:var(--high)}.MEDIUM{background:var(--med)}.LOW{background:var(--low)}.INFO{background:var(--info)}
table{width:100%;border-collapse:collapse;margin-top:10px;table-layout:fixed}
td,th{text-align:left;vertical-align:top;padding:6px 8px;border-top:1px solid var(--line);word-wrap:break-word}
th{color:var(--muted);font-weight:600;font-size:12px}
col.s{width:80px}col.c{width:20%}col.l{width:18%}
pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px 8px;margin:6px 0 0;font:12px Consolas,monospace;max-height:220px;overflow:auto}
.clean{color:#15803d;font-weight:600}.err{color:var(--high);font-size:12px}
"""


def _file(rep, child=False):
    e = html.escape
    c = rep.counts(recursive=False)
    pills = "".join(f'<span class="pill {k}">{v} {k}</span>' for k, v in c.items() if v)
    out = [f'<section class="file{" child" if child else ""}"><div class="hdr"><span class="path">{e(rep.path)}</span>'
           f'<span class="type">{e(rep.file_type)}</span>{pills}</div>']
    if rep.findings:
        out.append('<table><colgroup><col class="s"><col class="c"><col class="l"><col></colgroup>'
                   "<tr><th>Severity</th><th>Category</th><th>Location</th><th>Detail</th></tr>")
        for f in rep.sorted_findings():
            snip = f"<pre>{e(visible_repr(f.snippet))}</pre>" if f.snippet else ""
            out.append(f'<tr><td><span class="pill {f.severity}">{f.severity}</span></td><td>{e(f.category)}</td>'
                       f"<td>{e(f.location)}</td><td>{e(f.detail)}{snip}</td></tr>")
        out.append("</table>")
    elif not rep.children:
        out.append('<p class="clean">No hidden content found.</p>')
    for err in rep.errors:
        out.append(f'<div class="err">Scanner note: {e(err.splitlines()[0])}</div>')
    for ch in rep.children:
        out.append(_file(ch, True))
    out.append("</section>")
    return "".join(out)


def to_html(reports):
    total = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in reports:
        for k, v in r.counts().items():
            total[k] += v
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    summary = " · ".join(f"{v} {k.lower()}" for k, v in total.items())
    body = "".join(_file(r) for r in reports)
    return (f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>Hidden Content Report</title><style>{CSS}</style></head><body><main>"
            f"<h1>Hidden Content Scan Report</h1><div class='sub'>{now} · {len(reports)} file(s) · {summary}</div>"
            f"{body}</main></body></html>")
