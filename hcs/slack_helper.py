"""Elevated helper for the disk-slack check. Launched only by ntfs.collect_slack().

  python -m hcs.slack_helper <request.json> <response.json>

Reads the list of file paths from the request, collects raw slack bytes for each and writes them to the
response. It deliberately does nothing else: no document parsing ever runs with Administrator rights.
"""
import json
import sys

from hcs.ntfs import read_slack


def main(argv):
    req, resp = argv[1], argv[2]
    with open(req, encoding="utf-8") as f:
        paths = [p for p in json.load(f) if isinstance(p, str)]
    with open(resp, "w", encoding="utf-8") as f:
        json.dump({p: read_slack(p) for p in paths}, f)


if __name__ == "__main__":
    main(sys.argv)
