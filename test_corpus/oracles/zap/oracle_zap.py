"""Gate M ground truth (ADR-0008 §9): OWASP ZAP's active scanner on one lab origin.

Runs inside the pinned ZAP image (test_corpus/oracles/zap/run.sh), with ZAP's daemon already up
on localhost:8090. Spiders the origin and the manifest's route list (with lab account A's
Cookie, when given), then active-scans it with a policy limited to the rules that correspond to
GuardHub's active checks, and prints {origin: {"alerts": [...], "notes": [...]}} as JSON on
stdout. SSRF (40046) is confirmed through ZAP's own callback listener, reachable on the lab
network as this container's address; no external OAST service is used (the lab has no internet).

    python3 oracle_zap.py ORIGIN [COOKIE] [START_URLS_JSON]

Paths that would end the lab session or change the lab app's state (logout, setup, the
password-change and brute-force forms) are excluded from the crawl and the scan.
"""

from __future__ import annotations

import json
import socket
import sys
import time
import urllib.parse
import urllib.request
from urllib.parse import parse_qsl, urlsplit

from zapv2 import ZAPv2

# ZAP scan rule id -> GuardHub active check
RULES = {
    40012: "active_xss",  # Cross Site Scripting (Reflected)
    40018: "active_sqli",  # SQL Injection
    40019: "active_sqli",  # SQL Injection - MySQL (time based: disabled below, listed for mapping)
    40021: "active_sqli",  # SQL Injection - Oracle
    40022: "active_sqli",  # SQL Injection - PostgreSQL
    40027: "active_sqli",  # SQL Injection - MsSQL
    20019: "active_redirect",  # External Redirect
    40040: "active_cors",  # CORS Header (pinned ascanrulesBeta)
    40046: "active_ssrf",  # Server Side Request Forgery (pinned ascanrulesBeta)
}
# Error/boolean based only, no time-based rules (lab speed; the SQLite rule 40024 is time-based
# only). ZAP has no IDOR rule: the manifests stay the only truth for active_idor (noted).
ENABLED = [40012, 40018, 20019, 40040, 40046]
CALLBACK_PORT = 9099
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
    start = json.loads(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else []
    zap = ZAPv2(
        apikey="",
        proxies={"http": "http://127.0.0.1:8090", "https": "http://127.0.0.1:8090"},
    )
    notes: list[str] = []
    if cookie:
        zap.replacer.add_rule(description="lab-session", enabled="true", matchtype="REQ_HEADER",
                              matchregex="false", matchstring="Cookie", replacement=cookie)  # fmt: skip
        notes.append("lab session cookie sent on every request")
    zap.spider.exclude_from_scan(EXCLUDE)
    zap.ascan.exclude_from_scan(EXCLUDE)
    me = socket.gethostbyname(socket.gethostname())
    api = "http://127.0.0.1:8090/JSON/oast/action/setCallbackOptions/?" + urllib.parse.urlencode(
        {"localAddress": "0.0.0.0", "remoteAddress": me, "port": CALLBACK_PORT})  # fmt: skip
    with urllib.request.urlopen(api, timeout=30) as r:  # noqa: S310 (ZAP's local API)
        if json.load(r).get("Result") != "OK":
            raise SystemExit("ZAP refused the callback options")
    notes.append(
        f"SSRF callbacks to ZAP's own listener http://{me}:{CALLBACK_PORT}/ (lab network)"
    )
    zap.core.access_url(origin + "/", followredirects="true")
    for u in start:
        zap.core.access_url(u, followredirects="false")
    if start:
        notes.append(f"route list: {len(start)} start URLs")
    sid = zap.spider.scan(
        origin + "/", maxchildren=None, recurse="true", subtreeonly=None
    )
    wait("spider", lambda: zap.spider.status(sid), 600)
    seen = len(zap.spider.results(sid))
    for u in start:
        s2 = zap.spider.scan(u, maxchildren=None, recurse="true", subtreeonly=None)
        wait("spider", lambda: zap.spider.status(s2), 600)  # noqa: B023
        seen += len(zap.spider.results(s2))
    policy = "guardhub-gate-m"
    zap.ascan.add_scan_policy(policy, alertthreshold="MEDIUM", attackstrength="MEDIUM")
    zap.ascan.disable_all_scanners(scanpolicyname=policy)
    # one rule at a time, and every answer checked: an unknown id makes ZAP enable nothing and
    # the "scan" then tests nothing (Gate M's second CI run: 48 requests, 0 alerts on DVWA)
    for rule in ENABLED:
        ok = zap.ascan.enable_scanners(str(rule), scanpolicyname=policy)
        if ok != "OK":
            raise SystemExit(f"ZAP could not enable scan rule {rule}: {ok}")
    enabled = {
        int(s["id"])
        for s in zap.ascan.scanners(scanpolicyname=policy)
        if s["enabled"] == "true"
    }
    if enabled != set(ENABLED):
        raise SystemExit(f"ZAP policy has rules {sorted(enabled)}, expected {ENABLED}")
    notes.append("no ZAP rule for active_idor: manifests only")
    aid = zap.ascan.scan(origin + "/", recurse="true", scanpolicyname=policy)
    wait("active scan", lambda: zap.ascan.status(aid), 1800)
    time.sleep(5)  # late SSRF callbacks
    alerts = []
    for a in zap.core.alerts(baseurl=origin):
        rule = int(a.get("pluginId", "0"))
        if rule not in RULES:
            continue
        u = urlsplit(a["url"])
        param = a.get("param") or ""
        if (
            rule == 40046 and not param
        ):  # callback alerts carry no param: the one holding the callback URL
            param = next(
                (k for k, v in parse_qsl(u.query) if v.startswith(f"http://{me}:")), ""
            )
        alerts.append(
            {
                "check": RULES[rule],
                "rule": rule,
                "name": a.get("name", ""),
                "risk": a.get("risk", ""),
                "confidence": a.get("confidence", ""),
                "method": a.get("method", ""),
                "location": f"{u.scheme}://{u.netloc}{u.path}"
                + (f"?{param}" if param else ""),
                "evidence": (a.get("evidence") or "")[:200],
            }
        )
    notes.append(f"spidered {seen} URLs")
    json.dump({origin: {"alerts": alerts, "notes": notes}}, sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
