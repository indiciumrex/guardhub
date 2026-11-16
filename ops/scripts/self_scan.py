"""Dogfooding release gate (GUARDHUB_STANDARDS §2.5, §9.1): GuardHub scans its own site.

Runs the scanner image in one-shot mode. Ownership is still proven first: publish the token at
https://<host>/.well-known/guardhub-verify.txt, or as DNS TXT `guardhub-verify=<token>` on
_guardhub.<host>. Exit code 0 means no critical or high findings; any other code blocks the release.

Usage:
  GUARDHUB_SELF_VERIFY_TOKEN=ghv_... python ops/scripts/self_scan.py https://guardhub.dev
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys

IMAGE = os.environ.get("GUARDHUB_SCANNER_IMAGE", "guardhub-scanner:local")
EXIT_MEANING = {0: "PASS", 3: "BLOCKED: critical/high findings", 4: "ownership not verified", 2: "usage error"}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    token = os.environ.get("GUARDHUB_SELF_VERIFY_TOKEN", "")
    if not token:
        print("set GUARDHUB_SELF_VERIFY_TOKEN to the published verification token", file=sys.stderr)
        return 2
    docker = shutil.which("docker")
    if docker is None:
        print("docker is required", file=sys.stderr)
        return 2
    proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
        [docker, "run", "--rm", "--read-only", "--cap-drop=ALL", IMAGE, "selfscan", sys.argv[1], token],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.stdout.strip():
        report = json.loads(proc.stdout)
        print(f"self-scan of {report['target']} (ownership proven via {report['verified_by']})")
        for f in sorted(report["findings"], key=lambda x: x["severity"]):
            print(f"  [{f['severity']:>8}] {f['check_id']}/{f['finding_key']}  {f['evidence']['location']}")
        failed = [r["check_id"] for r in report["check_results"] if r["status"] != "done"]
        if failed:
            print(f"  checks that could not complete: {failed}")
    else:
        print(proc.stderr.strip(), file=sys.stderr)
    print(EXIT_MEANING.get(proc.returncode, f"FAILED (exit {proc.returncode})"))
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
