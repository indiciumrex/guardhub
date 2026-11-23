"""Independent ground truth for js_secrets (CI's header-truth job, via oracles/headers/run.sh).

    python3 oracle_secrets.py ORIGIN [ORIGIN ...]   -> JSON on stdout: {origin: {secret_keys, notes}}

Nothing here shares code with the scanner:
  - the home page is fetched with curl (at most 3 same-host redirects, the documented rule) and
    its <script src> tags are read with Python's HTML parser; every same-origin script is fetched
    (cross-origin ones never are);
  - gitleaks v8.21.2, unmodified with its default rules, scans the page and the scripts;
  - its findings are kept only for the credential kinds js_secrets declares (docs/checks/
    js_secrets.md); gitleaks rules for publishable browser keys (gcp-api-key) and its generic
    rule are out of that scope and listed in the notes only.
Key: "<key>:<url>#<GuardHub rule id>", the scanner's evidence location.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

# gitleaks rule -> (GuardHub rule id, key); stripe-access-token is split by its mode prefix
RULES = {
    "github-pat": ("github_pat", "secret_in_javascript"),
    "github-fine-grained-pat": ("github_pat", "secret_in_javascript"),
    "github-oauth": ("github_oauth", "secret_in_javascript"),
    "github-refresh-token": ("github_oauth", "secret_in_javascript"),
    "gitlab-pat": ("gitlab_pat", "secret_in_javascript"),
    "slack-bot-token": ("slack_token", "secret_in_javascript"),
    "slack-user-token": ("slack_token", "secret_in_javascript"),
    "slack-app-token": ("slack_token", "secret_in_javascript"),
    "slack-webhook-url": ("slack_webhook", "secret_in_javascript"),
    "private-key": ("private_key", "secret_in_javascript"),
    "npm-access-token": ("npm_token", "secret_in_javascript"),
    "sendgrid-api-token": ("sendgrid_key", "secret_in_javascript"),
    "openai-api-key": ("openai_key", "secret_in_javascript"),
    "anthropic-api-key": ("anthropic_key", "secret_in_javascript"),
    "anthropic-admin-api-key": ("anthropic_key", "secret_in_javascript"),
    "pypi-upload-token": ("pypi_token", "secret_in_javascript"),
    "shopify-access-token": ("shopify_token", "secret_in_javascript"),
    "shopify-custom-access-token": ("shopify_token", "secret_in_javascript"),
    "shopify-private-app-access-token": ("shopify_token", "secret_in_javascript"),
    "digitalocean-pat": ("digitalocean_token", "secret_in_javascript"),
    "huggingface-access-token": ("huggingface_token", "secret_in_javascript"),
    "telegram-bot-api-token": ("telegram_bot_token", "secret_in_javascript"),
}


def same_host_hop(src: str, dst: str) -> bool:
    a, b = urlparse(src), urlparse(dst)
    if b.scheme not in ("http", "https") or (a.hostname or "").lower() != (b.hostname or "").lower():
        return False
    if a.scheme == "https" and b.scheme == "http":
        return False
    port = lambda u: u.port or (443 if u.scheme == "https" else 80)  # noqa: E731
    if a.scheme == b.scheme:
        return port(a) == port(b)
    return b.port in (None, 443) or b.port == a.port


def fetch(url: str, dest: str) -> tuple[int, str, str]:
    """(status, content type, final URL) after at most 3 same-host redirects; body in dest."""
    for _ in range(4):
        out = subprocess.run(["curl", "-sS", "-k", "--max-time", "15", "-o", dest,
                              "-w", "%{http_code} %{redirect_url} %{content_type}", url],
                             capture_output=True, text=True)
        if out.returncode not in (0, 23, 63):
            return 0, "", url
        code, _, rest = out.stdout.partition(" ")
        loc, _, ctype = rest.partition(" ")
        st = int(code or 0)
        if st in (301, 302, 303, 307, 308) and loc and same_host_hop(url, loc):
            url = loc
            continue
        return st, ctype, url
    return 0, "", url


class Scripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.src: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            for k, v in attrs:
                if k == "src" and v:
                    self.src.append(v)


def truth(origin: str) -> dict:
    keys, notes = set(), []
    work = tempfile.mkdtemp()
    try:
        files = {}
        st, ctype, page = fetch(origin + "/", os.path.join(work, "f0.html"))
        if st == 0:
            return {"secret_keys": [], "notes": [f"fetch failed: {origin}/"]}
        notes.append(f"GET / -> {st} {page}")
        if st != 200 or "html" not in ctype.lower():
            return {"secret_keys": [], "notes": notes}
        files["f0.html"] = page
        p = Scripts()
        with open(os.path.join(work, "f0.html"), encoding="utf-8", errors="replace") as f:
            p.feed(f.read())
        base = urlparse(page)
        for i, src in enumerate(p.src, 1):
            u = urljoin(page, src.strip()).split("#")[0]
            pu = urlparse(u)
            if (pu.scheme, pu.netloc.lower()) != (base.scheme, base.netloc.lower()):
                continue
            name = f"f{i}.js"
            s, ct, final = fetch(u, os.path.join(work, name))
            if s == 200 and "html" not in ct.lower():
                files[name] = u
            else:
                os.remove(os.path.join(work, name))
        report = os.path.join(tempfile.mkdtemp(), "r.json")
        subprocess.run(["gitleaks", "detect", "--no-git", "--no-banner", "--source", work,
                        "--report-format", "json", "--report-path", report, "--exit-code", "0"],
                       capture_output=True, text=True, check=True)
        with open(report, encoding="utf-8") as f:
            found = json.load(f) or []
        for r in found:
            url = files.get(os.path.basename(r["File"]), r["File"])
            rid = r["RuleID"]
            notes.append(f"gitleaks {rid} in {url} line {r['StartLine']}")
            if rid == "stripe-access-token":
                secret = r.get("Secret", "")
                if re.match(r"(?:sk|rk)_live_", secret):
                    keys.add(f"secret_in_javascript:{url}#stripe_live_secret")
                elif re.match(r"(?:sk|rk)_test_", secret):
                    keys.add(f"test_secret_in_javascript:{url}#stripe_test_secret")
                continue
            if rid in RULES:
                gid, key = RULES[rid]
                keys.add(f"{key}:{url}#{gid}")
            else:
                notes.append(f"  ({rid} is outside js_secrets' declared kinds)")
        return {"secret_keys": sorted(keys), "notes": notes}
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    print(json.dumps({o: truth(o.rstrip("/")) for o in sys.argv[1:]}, indent=1))
