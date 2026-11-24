"""Accuracy gate for a lab measurement that is not a committed scorecard (pull requests).

    python3 ops/ci/accuracy_gate.py COMMITTED_JSON MEASURED_JSON

A pull request measures the light lab (test_corpus/run.sh with LAB_SKIP_HEAVY=1): fewer targets
than the committed packages/shared/accuracy.json, so the two files are not compared byte for
byte. For unchanged code, the light run's errors are a subset of the full run's errors, so the
gate is:

  * a check the committed file has: measured FP <= committed FP and measured FN <= committed FN,
    and if it met the gate there, it still meets it here (no new false positive, no new miss,
    no lost gate);
  * a check the committed file does not have yet (a new module): it must meet the gate on the
    light targets (precision >= gate, recall >= gate) and have no false positive.

Exit 1 on any violation. Pushes to main measure the full lab, which is the scorecard.
"""

from __future__ import annotations

import json
import sys


def main() -> int:
    committed = json.load(open(sys.argv[1], encoding="utf-8"))
    measured = json.load(open(sys.argv[2], encoding="utf-8"))
    c_checks, m_checks = committed.get("checks", {}), measured.get("checks", {})
    bad: list[str] = []
    print(f"{'check':<22} {'tp':>4} {'fp':>4} {'fn':>4}  {'gate':<5} committed(tp/fp/fn,gate)")
    for cid in sorted(set(c_checks) | set(m_checks)):
        m = m_checks.get(cid)
        c = c_checks.get(cid)
        if m is None:
            bad.append(f"{cid}: in the committed accuracy.json but not measured")
            continue
        ref = f"{c['tp']}/{c['fp']}/{c['fn']},{c['meets_gate']}" if c else "new"
        print(f"{cid:<22} {m['tp']:>4} {m['fp']:>4} {m['fn']:>4}  {str(m['meets_gate']):<5} {ref}")
        if c is None:
            if m["fp"] > 0 or not m["meets_gate"]:
                bad.append(f"{cid}: new check fails on the light lab (fp={m['fp']}, meets_gate={m['meets_gate']})")
            continue
        if m["fp"] > c["fp"]:
            bad.append(f"{cid}: new false positive(s): {m['fp']} > committed {c['fp']}")
        if m["fn"] > c["fn"]:
            bad.append(f"{cid}: new miss(es): {m['fn']} > committed {c['fn']}")
        # a check whose positives all sit on heavy apps has nothing to find in a light run: its
        # precision/recall are undefined there, so only the FP/FN rules above apply to it
        if c["meets_gate"] and not m["meets_gate"] and m["tp"] + m["fn"] > 0:
            bad.append(f"{cid}: met the gate in the committed scorecard, fails it now")
    if bad:
        print("\naccuracy gate FAILED:\n  " + "\n  ".join(bad))
        return 1
    print("\naccuracy gate: ok (light lab; the full lab runs on main)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
