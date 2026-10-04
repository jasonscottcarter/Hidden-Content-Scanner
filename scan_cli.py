"""Command-line interface:  python scan_cli.py <files/folders...> [--json out.json] [--html out.html] [--slack]"""
import argparse
import json
import os
import sys

from hcs.dispatch import scan_path, expand_paths
from hcs.ntfs import collect_slack, report_slack
from hcs.report_export import to_html


def show(rep, indent=0):
    pad = "  " * indent
    c = rep.counts()
    print(f"{pad}== {rep.path}  [{rep.file_type}]  HIGH={c['HIGH']} MED={c['MEDIUM']} LOW={c['LOW']} INFO={c['INFO']}")
    for f in rep.sorted_findings():
        snip = f.snippet.replace("\n", " ")[:140]
        print(f"{pad}  [{f.severity:6}] {f.category} @ {f.location}: {f.detail[:160]}" + (f"\n{pad}           > {snip}" if snip else ""))
    for e in rep.errors:
        print(f"{pad}  [ERROR ] {e.splitlines()[0]}")
    for ch in rep.children:
        show(ch, indent + 1)


def main():
    ap = argparse.ArgumentParser(description="Hidden Content Scanner")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json")
    ap.add_argument("--html")
    ap.add_argument("--slack", action="store_true",
                    help="check NTFS file slack (prompts once for Administrator permission for a disk-reading helper)")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    paths = expand_paths(a.paths)
    reports = [scan_path(p) for p in paths]
    if a.slack:  # raw disk reads happen in a separate elevated helper; parsing above stayed unprivileged
        infos = collect_slack(paths)
        for r in reports:
            report_slack(r, infos.get(os.path.abspath(r.path)))
    for r in reports:
        show(r)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump([r.to_dict() for r in reports], f, indent=2, ensure_ascii=False)
    if a.html:
        with open(a.html, "w", encoding="utf-8") as f:
            f.write(to_html(reports))


if __name__ == "__main__":
    main()
