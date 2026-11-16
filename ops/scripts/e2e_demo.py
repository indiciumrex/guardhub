"""End-to-end proof against the running stack, through the public web entrypoint as a browser would.

Enter URL → challenge → place the ownership token (on the local demo target) → verify & scan →
poll live progress → localised plain-language report. Exits non-zero if any step fails.

Usage (stack started with docker-compose.demo.yml):
  python ops/scripts/e2e_demo.py [--base http://localhost:3000] [--locale tr]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOKEN_FILE = ROOT / "ops" / "demo-target" / "site" / ".well-known" / "guardhub-verify.txt"
TARGET = "http://demo-target:8080"


def call(base: str, method: str, path: str, *, body: object = None, headers: dict[str, str] | None = None) -> dict:
    req = urllib.request.Request(  # noqa: S310 — fixed http(s) base supplied by the operator
        base + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", "X-GuardHub-CSRF": "1", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310
            return json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"{method} {path} → {exc.code}: {exc.read().decode(errors='replace')}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://localhost:3000")
    parser.add_argument("--locale", default="tr")
    args = parser.parse_args()

    print(f"1) challenge for {TARGET}")
    ch = call(args.base, "POST", "/api/v1/public/challenges", body={"target_url": TARGET})
    TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_FILE.write_text(ch["token"] + "\n", encoding="utf-8")
    print(f"   token placed at {ch['instructions']['well_known_url']}")

    print("2) verify ownership + start scan")
    started = call(args.base, "POST", f"/api/v1/public/challenges/{ch['challenge_id']}/scan")
    headers = {"X-Scan-Token": started["access_token"]}

    print("3) live progress")
    seen: dict[str, str] = {}
    view: dict = {}
    for _ in range(240):
        view = call(args.base, "GET", f"/api/v1/public/scans/{started['scan_id']}?locale={args.locale}", headers=headers)
        for item in view["progress"]:
            if seen.get(item["check_id"]) != item["status"]:
                seen[item["check_id"]] = item["status"]
                print(f"   {item['name']:<40} {item['status']}")
        if view["status"] in ("done", "failed"):
            break
        time.sleep(1)

    print(f"4) result: status={view['status']} score={view['score']} counts={view['finding_counts']}")
    for f in view.get("findings", []):
        print(f"   [{f['severity']:>8}] {f['check_id']}/{f['finding_key']}: {f['title']}")
    if view.get("status") != "done" or not view.get("findings"):
        print("E2E FAILED", file=sys.stderr)
        return 1
    missing = [f["finding_key"] for f in view["findings"] if not all(f[k] for k in ("title", "summary", "why", "fix"))]
    if missing:
        print(f"E2E FAILED: findings without full plain-language text: {missing}", file=sys.stderr)
        return 1
    print("E2E OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
