"""Compare the header oracle's output with the manifests' header_quality expectations.

    python3 compare.py OUT_DIR

Reads OUT_DIR/light.json, OUT_DIR/light-relaxed.json (targets re-read with certificate checks
relaxed) and OUT_DIR/app-*.json from run.sh. For every manifest that lists header_quality,
the set of keys the oracle found must equal the set the manifest expects (a cookie key is
compared with its cookie name, taken from the expectation's location). A target the oracle
could not fetch at all is UNMEASURED and fails too: it cannot count as correct.

Writes OUT_DIR/summary.md and OUT_DIR/summary.json. Exit 1 on any mismatch or unmeasured
target. The oracle output itself is the evidence the manifests cite.
"""

from __future__ import annotations

import glob
import json
import os
import sys

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFESTS = os.path.join(HERE, "..", "..", "manifests")
CHECK = "header_quality"


def load_truth(out: str) -> dict[str, dict]:
    truth: dict[str, dict] = {}
    files = [os.path.join(out, "light.json"), *sorted(glob.glob(os.path.join(out, "app-*.json")))]
    for path in files:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                truth.update(json.load(f))
    relaxed = os.path.join(out, "light-relaxed.json")
    if os.path.exists(relaxed):
        with open(relaxed, encoding="utf-8") as f:
            for origin, t in json.load(f).items():
                t["notes"].insert(0, "read with certificate checks relaxed (Node refused the TLS)")
                truth[origin] = t
    return truth


def expected_keys(manifest: dict) -> set[str]:
    keys = set()
    for e in manifest.get("expect") or []:
        if e.get("check") != CHECK:
            continue
        loc = e.get("location") or ""
        if e["key"] == "cookie_response_cacheable" and "#set-cookie=" in loc:
            keys.add(f"{e['key']}:{loc.split('#set-cookie=', 1)[1]}")
        else:
            keys.add(e["key"])
    return keys


def main() -> int:
    out = sys.argv[1]
    truth = load_truth(out)
    rows = []
    for path in sorted(glob.glob(os.path.join(MANIFESTS, "*.yaml"))):
        with open(path, encoding="utf-8") as f:
            m = yaml.safe_load(f)
        if CHECK not in (m.get("checks") or []):
            continue
        origin = m.get("origin", "")
        want = expected_keys(m)
        t = truth.get(origin)
        if t is None or any(n.startswith("fetch failed") for n in t["notes"]):
            status, got = "UNMEASURED", set()
        else:
            got = set(t["keys"])
            status = "ok" if got == want else "MISMATCH"
        rows.append(
            {
                "target": m["target"],
                "origin": origin,
                "status": status,
                "oracle": sorted(got),
                "manifest": sorted(want),
                "notes": (t or {}).get("notes", ["no oracle output"]),
            }
        )

    bad = [r for r in rows if r["status"] != "ok"]
    lines = [
        "# header_quality ground truth vs manifests",
        "",
        f"{len(rows)} targets, {len(rows) - len(bad)} agree, {len(bad)} do not.",
        "",
        "| Target | Status | Oracle keys | Manifest keys |",
        "|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| `{r['target']}` | {r['status']} | {', '.join(r['oracle']) or '-'} | {', '.join(r['manifest']) or '-'} |"
        )
    lines += ["", "## Oracle notes", ""]
    for r in rows:
        lines.append(f"- `{r['target']}`: " + " · ".join(r["notes"]))
    text = "\n".join(lines) + "\n"
    with open(os.path.join(out, "summary.md"), "w", encoding="utf-8") as f:
        f.write(text)
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=1)
    print(text)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
