"""Gate M ground truth (ADR-0008 §9): OWASP ZAP's active scanner on one lab origin.

Runs inside the pinned ZAP image (test_corpus/oracles/zap/run.sh), with ZAP's daemon already up
on localhost:8090. Spiders the origin (with the lab session's Cookie, when given), then active-
scans it with a policy limited to the rules that correspond to GuardHub's active checks, and
prints {origin: {"alerts": [...], "notes": [...]}} as JSON on stdout.

    python3 oracle_zap.py ORIGIN [COOKIE]

Paths that would end the lab session or change the lab app's state (logout, setup, the
password-change and brute-force forms) are excluded from the crawl and the scan.
"""

from __future__ import annotations

import json
import sys
import time
from urllib.parse import urlsplit

from zapv2 import ZAPv2

# ZAP scan rule id -> GuardHub active check
RULES = {
    40012: "active_xss",  # Cross Site Scripting (Reflected)
    40018: "active_sqli",  # SQL Injection
    40019: "active_sqli",  # SQL Injection - MySQL (time based: disabled below, listed for mapping)
    40021: "active_sqli",  # SQL Injection - Oracle
    40022: "active_sqli",  # SQL Injection - PostgreSQL
    40024: "active_sqli",  # SQL Injection - SQLite
    40027: "active_sqli",  # SQL Injection - MsSQL
    20019: "active_redirect",  # External Redirect
    40040: "active_cors",  # CORS Header
}
ENABLED = [40012, 40018, 40024, 20019, 40040]  # error/boolean based; no time-based (lab speed)
EXCLUDE = r".*(logout|setup\.php|/csrf/|/brute/|security\.php|login\.php).*"


def wait(fn, status, timeout: float) -> None:
    start = time.time()
    while int(status()) < 100:
        if time.time() - start > timeout:
            raise SystemExit(f"{fn} did not finish within {timeout}s")
        time.sleep(2)


def main() -> int:
    origin = sys.argv[1].rstrip("/")
    cookie = sys.argv[2] if len(sys.argv) > 2 else ""
    zap = ZAPv2(apikey="", proxies={"http": "http://127.0.0.1:8090", "https": "http://127.0.0.1:8090"})
    notes: list[str] = []
    if cookie:
        zap.replacer.add_rule(description="lab-session", enabled="true", matchtype="REQ_HEADER",
                              matchregex="false", matchstring="Cookie", replacement=cookie)  # fmt: skip
        notes.append("lab session cookie sent on every request")
    zap.spider.exclude_from_scan(EXCLUDE)
    zap.ascan.exclude_from_scan(EXCLUDE)
    zap.core.access_url(origin + "/", followredirects="true")
    sid = zap.spider.scan(origin + "/", maxchildren=None, recurse="true", subtreeonly=None)
    wait("spider", lambda: zap.spider.status(sid), 600)
    policy = "guardhub-gate-m"
    zap.ascan.add_scan_policy(policy, alertthreshold="MEDIUM", attackstrength="MEDIUM")
    zap.ascan.disable_all_scanners(scanpolicyname=policy)
    zap.ascan.enable_scanners(",".join(str(i) for i in ENABLED), scanpolicyname=policy)
    aid = zap.ascan.scan(origin + "/", recurse="true", scanpolicyname=policy)
    wait("active scan", lambda: zap.ascan.status(aid), 1800)
    alerts = []
    for a in zap.core.alerts(baseurl=origin):
        rule = int(a.get("pluginId", "0"))
        if rule not in RULES:
            continue
        u = urlsplit(a["url"])
        alerts.append(
            {
                "check": RULES[rule],
                "rule": rule,
                "name": a.get("name", ""),
                "risk": a.get("risk", ""),
                "confidence": a.get("confidence", ""),
                "method": a.get("method", ""),
                "location": f"{u.scheme}://{u.netloc}{u.path}" + (f"?{a['param']}" if a.get("param") else ""),
                "evidence": (a.get("evidence") or "")[:200],
            }
        )
    notes.append(f"spidered {len(zap.spider.results(sid))} URLs")
    json.dump({origin: {"alerts": alerts, "notes": notes}}, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
