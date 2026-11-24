"""Compare the ZAP oracle (oracle_zap.py) with the active manifests (test_corpus/active/manifests).

    python3 compare.py OUT_DIR

For every active manifest, the set of (check, location) the oracle reports for GET requests at
risk Medium or higher (CORS: only risk High, i.e. a foreign or null origin granted with
credentials; "*" or an echo without credentials is not cors_origin_reflected; XSS at risk Low is
ZAP's "reflected in a JSON response" weakness, not an HTML reflection) must equal the manifest's
expectations that are not `outside`, for every check ZAP has a rule for (active_idor has none:
its expectations are listed as manifest-only truth, never compared). Not counted either: an SSRF
alert at a location where ZAP also reports an External Redirect (ZAP's scan requests follow
redirects, so its callback is fetched by ZAP itself, not by the server; the redirect is counted as
active_redirect), and an oracle verdict a manifest disputes (`oracle_disputed`: check, location
and the evidence that ZAP's alert is wrong or that ZAP misses a vulnerability the source shows;
such an entry is excluded from both sides of the comparison, never from the scanner's score). Every alert not counted is listed in the summary. An
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
RISK_OK_BY_CHECK = {"active_cors": {"High"}}
ORACLE_CHECKS = {
    "active_xss",
    "active_sqli",
    "active_redirect",
    "active_cors",
    "active_ssrf",
}


def load_truth(out: str) -> dict[str, dict]:
    truth: dict[str, dict] = {}
    for path in sorted(glob.glob(os.path.join(out, "zap-*.json"))):
        with open(path, encoding="utf-8") as f:
            truth.update(json.load(f))
    return truth


def oracle_set(
    t: dict, checks: set[str], disputed: frozenset = frozenset()
) -> set[tuple[str, str]]:
    got = set()
    redirects = {a["location"] for a in t["alerts"] if a["check"] == "active_redirect"}
    for a in t["alerts"]:
        if a.get("confidence") == "False Positive":
            continue
        if a["check"] == "active_ssrf" and a["location"] in redirects:
            continue
        if (a["check"], a["location"]) in disputed:
            continue
        if a["method"] != "GET" or a["check"] not in checks:
            continue
        if a["risk"] not in RISK_OK_BY_CHECK.get(a["check"], RISK_OK):
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
        disp = frozenset(
            (d["check"], d["location"]) for d in m.get("oracle_disputed") or []
        )
        want = (
            {
                (e["check"], e["location"])
                for e in m.get("expect") or []
                if not e.get("outside") and e["check"] in ORACLE_CHECKS
            }
            - disp
        )  # an expectation the oracle demonstrably misses is disputed the same way
        no_oracle = sorted(
            [e["check"], e["location"]]
            for e in m.get("expect") or []
            if e["check"] not in ORACLE_CHECKS
        )
        outside = {
            (e["check"], e.get("location", ""))
            for e in m.get("expect") or []
            if e.get("outside")
        }
        if t is None:
            status, got = "UNMEASURED", set()
        else:
            got = oracle_set(t, set(m["checks"]), disp) - outside
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
                    [
                        list(o)
                        for o in outside
                        if t
                        and any(
                            (o[0], o[1]) == (a["check"], a["location"])
                            for a in t["alerts"]
                        )
                    ]
                ),
                "manifest_only_truth_no_oracle_rule": no_oracle,
                "oracle_disputed": [
                    [d["check"], d["location"], d["why"]]
                    for d in m.get("oracle_disputed") or []
                ],
                "oracle_not_counted": sorted(
                    [
                        a["check"],
                        a["location"],
                        a.get("risk", ""),
                        a.get("confidence", ""),
                    ]
                    for a in (t or {}).get("alerts", [])
                    if (a["check"], a["location"])
                    not in oracle_set(t, set(m["checks"]), disp)
                ),
                "notes": (t or {}).get("notes", ["no oracle output"]),
            }
        )
    lines = ["# Gate M ground truth: OWASP ZAP vs the active manifests", "",
             f"{len(rows)} targets, {len(rows) - bad} agree, {bad} do not.", "",
             "| Target | Status | Agree | ZAP only | Manifest only |", "|---|---|---|---|---|"]  # fmt: skip
    for r in rows:
        fmt = lambda xs: "<br>".join(f"{c} {loc}" for c, loc in xs) or "-"  # noqa: E731
        lines.append(
            f"| `{r['target']}` | {r['status']} | {fmt(r['agree'])} | {fmt(r['oracle_only'])} | {fmt(r['manifest_only'])} |"
        )
    text = "\n".join(lines) + "\n"
    with open(os.path.join(out, "summary.md"), "w", encoding="utf-8") as f:
        f.write(text)
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=1)
    print(text)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
