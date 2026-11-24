"""Compare the oracles' output with the manifests' header_quality, cookie_depth, exposed_files, js_libraries and content_signals expectations.

    python3 compare.py OUT_DIR

Reads OUT_DIR/light.json, OUT_DIR/light-relaxed.json (targets re-read with certificate checks
relaxed) and OUT_DIR/app-*.json from run.sh. For every manifest and each of those checks it
lists, the set of keys the oracle found must equal the set the manifest expects (a cookie key is
compared with its cookie name, taken from the expectation's location). A target the oracle
could not fetch at all is UNMEASURED and fails too: it cannot count as correct.

Writes OUT_DIR/summary.md and OUT_DIR/summary.json. Exit 1 on any mismatch or unmeasured
target. The oracle output itself is the evidence the manifests cite.

With LAB_SKIP_HEAVY=1 (pull requests) the heavy apps of test_corpus/heavy-apps.txt were not
started: their pairs are listed as SKIPPED and do not fail the run; pushes to main measure them.
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
CHECKS = {"header_quality": "keys", "cookie_depth": "cookie_keys", "exposed_files": "file_keys", "js_libraries": "js_keys", "content_signals": "content_keys"}
COOKIE_KEYS = {"cookie_response_cacheable", "cookie_prefix_invalid", "cookie_domain_too_broad"}


def skipped_targets() -> set[str]:
    """Heavy-app manifest targets left out of a light run (LAB_SKIP_HEAVY=1)."""
    if os.environ.get("LAB_SKIP_HEAVY") != "1":
        return set()
    with open(os.path.join(HERE, "..", "..", "heavy-apps.txt"), encoding="utf-8") as f:
        return {ln.split()[0] for ln in f if ln.strip() and not ln.startswith("#")}


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
    # content_signals truth: mixed content from Chromium (oracles/content), merged with the
    # sri_missing the header oracle took from Observatory (content_keys above)
    for path in sorted(glob.glob(os.path.join(out, "content-*.json"))):
        with open(path, encoding="utf-8") as f:
            for origin, t in json.load(f).items():
                entry = truth.setdefault(origin, {"keys": [], "notes": []})
                entry["content_keys"] = sorted(set(entry.get("content_keys", [])) | set(t["content_keys"]))
                entry["notes"] = entry.get("notes", []) + t["notes"]
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
                # Chromium's mixed-content keys survive; Observatory's sri_missing is re-read relaxed
                t["content_keys"] = sorted(set(t.get("content_keys", [])) | {k for k in before.get("content_keys", []) if k != "sri_missing"})
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
    skipped = skipped_targets()
    for path in sorted(glob.glob(os.path.join(MANIFESTS, "*.yaml"))):
        with open(path, encoding="utf-8") as f:
            m = yaml.safe_load(f)
        origin = m.get("origin", "")
        t = truth.get(origin)
        for check, field in CHECKS.items():
            if check not in (m.get("checks") or []):
                continue
            want = expected_keys(m, check)
            if os.path.basename(path)[: -len(".yaml")] in skipped:
                status, got = "SKIPPED", set()
            elif t is None or any(n.startswith("fetch failed") for n in t["notes"]):
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

    bad = [r for r in rows if r["status"] not in ("ok", "SKIPPED")]
    n_skip = sum(r["status"] == "SKIPPED" for r in rows)
    lines = [
        "# header_quality, cookie_depth, exposed_files, js_libraries and content_signals ground truth vs manifests",
        "",
        f"{len(rows)} target/check pairs, {len(rows) - len(bad) - n_skip} agree, {len(bad)} do not"
        + (f", {n_skip} skipped (heavy apps, light run)." if n_skip else "."),
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
