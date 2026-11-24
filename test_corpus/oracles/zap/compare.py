"""Compare the ZAP oracle (oracle_zap.py) with the active manifests (test_corpus/active/manifests).

    python3 compare.py OUT_DIR

For every active manifest, the set of (check, location) the oracle reports for GET requests
(CORS: only risk Medium or higher, i.e. credentialed access; "*" without credentials is not
cors_origin_reflected) must equal the manifest's expectations that are not `outside`. An
`outside` expectation (beyond what the checks declare, e.g. reachable only from JavaScript) is
listed with whether the oracle reached it; it never fails the run. A target with no oracle output
is UNMEASURED and fails. Writes OUT_DIR/summary.md and summary.json; exit 1 on any mismatch.
"""

from __future__ import annotations

import glob
import json
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFESTS = os.path.join(HERE, "..", "..", "active", "manifests")
RISK_OK = {"Medium", "High"}


def load_truth(out: str) -> dict[str, dict]:
    truth: dict[str, dict] = {}
    for path in sorted(glob.glob(os.path.join(out, "zap-*.json"))):
        with open(path, encoding="utf-8") as f:
            truth.update(json.load(f))
    return truth


def oracle_set(t: dict, checks: set[str]) -> set[tuple[str, str]]:
    got = set()
    for a in t["alerts"]:
        if a["method"] != "GET" or a["check"] not in checks:
            continue
        if a["check"] == "active_cors" and a["risk"] not in RISK_OK:
            continue
        got.add((a["check"], a["location"]))
    return got


def main() -> int:
    out = sys.argv[1]
    truth = load_truth(out)
    rows, bad = [], 0
    for path in sorted(glob.glob(os.path.join(MANIFESTS, "*.yaml"))):
        with open(path, encoding="utf-8") as f:
            m = yaml.safe_load(f)
        t = truth.get(m["origin"].rstrip("/"))
        want = {(e["check"], e["location"]) for e in m.get("expect") or [] if not e.get("outside")}
        outside = {(e["check"], e.get("location", "")) for e in m.get("expect") or [] if e.get("outside")}
        if t is None:
            status, got = "UNMEASURED", set()
        else:
            got = oracle_set(t, set(m["checks"])) - outside
            status = "ok" if got == want else "MISMATCH"
        bad += status != "ok"
        rows.append(
            {
                "target": m["target"],
                "status": status,
                "oracle_only": sorted(map(list, got - want)),
                "manifest_only": sorted(map(list, want - got)),
                "agree": sorted(map(list, got & want)),
                "outside_reached_by_oracle": sorted(
                    [list(o) for o in outside if t and any((o[0], o[1]) == (a["check"], a["location"]) for a in t["alerts"])]
                ),
                "notes": (t or {}).get("notes", ["no oracle output"]),
            }
        )
    lines = ["# Gate M ground truth: OWASP ZAP vs the active manifests", "",
             f"{len(rows)} targets, {len(rows) - bad} agree, {bad} do not.", "",
             "| Target | Status | Agree | ZAP only | Manifest only |", "|---|---|---|---|---|"]  # fmt: skip
    for r in rows:
        fmt = lambda xs: "<br>".join(f"{c} {loc}" for c, loc in xs) or "-"  # noqa: E731
        lines.append(f"| `{r['target']}` | {r['status']} | {fmt(r['agree'])} | {fmt(r['oracle_only'])} | {fmt(r['manifest_only'])} |")
    text = "\n".join(lines) + "\n"
    with open(os.path.join(out, "summary.md"), "w", encoding="utf-8") as f:
        f.write(text)
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=1)
    print(text)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
