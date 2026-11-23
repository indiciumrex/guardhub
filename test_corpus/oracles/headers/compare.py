"""Compare the oracles' output with the manifests' header_quality, cookie_depth, exposed_files and js_libraries expectations.

    python3 compare.py OUT_DIR

Reads OUT_DIR/light.json, OUT_DIR/light-relaxed.json (targets re-read with certificate checks
relaxed) and OUT_DIR/app-*.json from run.sh. For every manifest and each of those checks it
lists, the set of keys the oracle found must equal the set the manifest expects (a cookie key is
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
from urllib.parse import urlparse

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFESTS = os.path.join(HERE, "..", "..", "manifests")
# check -> the oracle output field holding its keys
CHECKS = {"header_quality": "keys", "cookie_depth": "cookie_keys", "exposed_files": "file_keys", "js_libraries": "js_keys"}
COOKIE_KEYS = {"cookie_response_cacheable", "cookie_prefix_invalid", "cookie_domain_too_broad"}


def load_truth(out: str) -> dict[str, dict]:
    truth: dict[str, dict] = {}
    files = [os.path.join(out, "light.json"), *sorted(glob.glob(os.path.join(out, "app-*.json")))]
    for path in files:
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                truth.update(json.load(f))
    # exposed_files truth (oracles/files): merged field by field into the same origins
    for path in sorted(glob.glob(os.path.join(out, "files-*.json"))):
        with open(path, encoding="utf-8") as f:
            for origin, t in json.load(f).items():
                entry = truth.setdefault(origin, {"keys": [], "notes": []})
                entry["file_keys"] = t["file_keys"]
                entry["notes"] = entry.get("notes", []) + t["notes"]
    # js_libraries truth (oracles/js, retire.js): merged the same way
    for path in sorted(glob.glob(os.path.join(out, "js-*.json"))):
        with open(path, encoding="utf-8") as f:
            for origin, t in json.load(f).items():
                entry = truth.setdefault(origin, {"keys": [], "notes": []})
                entry["js_keys"] = t["js_keys"]
                entry["notes"] = entry.get("notes", []) + [n for n in t["notes"] if not n.startswith("GET / ->")]
                if any(n.startswith("fetch failed") for n in t["notes"]):
                    entry["notes"].append("fetch failed (js oracle)")
    relaxed = os.path.join(out, "light-relaxed.json")
    if os.path.exists(relaxed):
        with open(relaxed, encoding="utf-8") as f:
            for origin, t in json.load(f).items():
                t["notes"].insert(0, "read with certificate checks relaxed (Node refused the TLS)")
                before = truth.get(origin, {})
                if "file_keys" in before:  # the files oracle does not depend on Node's TLS
                    t["file_keys"] = before["file_keys"]
                    t["notes"] += [n for n in before.get("notes", []) if not n.startswith("fetch failed")]
                if "js_keys" in before:  # nor does the js oracle (it reads with TLS relaxed)
                    t["js_keys"] = before["js_keys"]
                truth[origin] = t
    return truth


def expected_keys(manifest: dict, check: str) -> set[str]:
    keys = set()
    for e in manifest.get("expect") or []:
        if e.get("check") != check:
            continue
        loc = e.get("location") or ""
        if check == "exposed_files" and loc:
            keys.add(f"{e['key']}:{urlparse(loc).path or '/'}")
        elif check == "js_libraries" and loc:
            keys.add(f"{e['key']}:{loc}")
        elif e["key"] in COOKIE_KEYS and "#set-cookie=" in loc:
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
        origin = m.get("origin", "")
        t = truth.get(origin)
        for check, field in CHECKS.items():
            if check not in (m.get("checks") or []):
                continue
            want = expected_keys(m, check)
            if t is None or any(n.startswith("fetch failed") for n in t["notes"]):
                status, got = "UNMEASURED", set()
            else:
                got = set(t.get(field, []))
                status = "ok" if got == want else "MISMATCH"
            rows.append(
                {
                    "target": m["target"],
                    "check": check,
                    "origin": origin,
                    "status": status,
                    "oracle": sorted(got),
                    "manifest": sorted(want),
                    "notes": (t or {}).get("notes", ["no oracle output"]),
                }
            )

    bad = [r for r in rows if r["status"] != "ok"]
    lines = [
        "# header_quality, cookie_depth, exposed_files and js_libraries ground truth vs manifests",
        "",
        f"{len(rows)} target/check pairs, {len(rows) - len(bad)} agree, {len(bad)} do not.",
        "",
        "| Target | Check | Status | Oracle keys | Manifest keys |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| `{r['target']}` | {r['check']} | {r['status']} | {', '.join(r['oracle']) or '-'} | {', '.join(r['manifest']) or '-'} |"
        )
    lines += ["", "## Oracle notes", ""]
    for r in rows:
        if r["check"] == "header_quality":  # one notes line per target
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
