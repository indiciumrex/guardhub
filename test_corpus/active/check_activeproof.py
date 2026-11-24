"""Checks a `scanner activeproof` report against the target's own access record (ADR-0008 §8.1).

Usage: check_activeproof.py REPORT.json ACCESS.log EXCLUDED_PREFIX...

The scanner's report must have no failed assertion and must show a kill that stopped the scan
within its target. The access record (one "avlab HOST PATH USER-AGENT" line per request; on prod,
the same fields from nginx) must show:
  - no request for an excluded path, in any form a server resolves to it;
  - no request carrying the scope-probe marker;
  - exactly as many GuardHub-Active requests as the report says were sent.
Exit 0 when everything holds, 1 otherwise (the reasons are printed).
"""

from __future__ import annotations

import json
import posixpath
import sys
import urllib.parse

UA = "GuardHub-Active/"


def resolved(path: str) -> str:
    p = urllib.parse.unquote(path.split("?", 1)[0]).replace("\\", "/")
    p = "/".join(seg.split(";", 1)[0] for seg in p.split("/"))
    return posixpath.normpath("/" + p.lstrip("/")).lower()


def under(path: str, prefix: str) -> bool:
    pre = prefix.rstrip("/").lower()
    return path == pre or path.startswith(pre + "/")


def main() -> int:
    report_path, access_path, *excluded = sys.argv[1:]
    with open(report_path, encoding="utf-8") as f:
        rep = json.load(f)
    problems: list[str] = []
    if rep.get("failed_assertions"):
        problems.append(f"report assertions failed: {rep['failed_assertions']}")
    kill = rep.get("kill") or {}
    if not kill.get("seen_at"):
        problems.append("the kill switch was never seen during the proof")
    elif kill.get("stop_latency_ms", 10**9) > kill.get("target_ms", 2000):
        problems.append(
            f"stop latency {kill.get('stop_latency_ms')} ms > {kill.get('target_ms')} ms"
        )
    if not rep.get("scope_probes"):
        problems.append("no scope probes in the report")

    ours = 0
    with open(access_path, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split(" ", 3)
            if len(parts) < 4:
                continue
            _, host, path, ua = parts
            if not ua.startswith(UA):
                continue
            ours += 1
            r = resolved(path)
            if "gh-scope-probe" in path.lower():
                problems.append(f"a scope probe reached the target: {host} {path}")
            for pre in excluded:
                if under(r, pre):
                    problems.append(
                        f"an excluded path reached the target: {host} {path}"
                    )
            if (
                host.split(":")[0].lower()
                != urllib.parse.urlsplit(rep["origin"]).hostname
            ):
                problems.append(
                    f"a request for another host reached the target: {host} {path}"
                )
    if ours != rep.get("sent"):
        problems.append(
            f"the target saw {ours} GuardHub-Active requests, the report says {rep.get('sent')} were sent"
        )

    summary = (
        f"activeproof {rep.get('origin')} {rep.get('check')}: {len(rep.get('scope_probes') or [])} scope probes refused, "
        f"{rep.get('sent')} sent (target saw {ours}), min gap {rep.get('min_gap_ms')} ms, "
        f"kill seen -> last request {kill.get('stop_latency_ms')} ms, {kill.get('refused_as_killed')} refused after the kill"
    )
    print(summary)
    for p in problems:
        print("FAIL:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
