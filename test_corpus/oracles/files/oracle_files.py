"""Independent ground truth for exposed_files (CI's header-truth job, via oracles/headers/run.sh).

    python3 oracle_files.py ORIGIN [ORIGIN ...]   -> JSON on stdout: {origin: {file_keys, notes}}

Nothing here shares code with the scanner:
  - each path of the documented list (docs/checks/exposed_files.md) is fetched with curl
    (certificate checks off: content, not TLS, is judged here), following at most 3 same-host
    redirects as the documented rule says (a cross-host redirect is never followed);
  - file types come from libmagic (`file`): "PHP script", "gzip compressed data", "Zip archive
    data", "Apple Desktop Services Store";
  - a dump counts only with data rows (INSERT INTO / COPY ... FROM stdin), after zcat for .gz;
  - source maps are found with Python's HTML parser on the home page, then the map's JSON;
  - default pages: the stock welcome page titles of the web servers.
A path whose body equals the answer for a path that cannot exist (soft 404) never counts.
A key is "<key>:<path>" (compare.py matches it with the expectation's location path).
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import subprocess
import sys
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

DUMPS = ["/backup.sql", "/dump.sql", "/db.sql", "/database.sql", "/backup.sql.gz", "/db.sql.gz"]
SOURCES = ["/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save", "/wp-config.php.old",
           "/config.php.bak", "/index.php.bak", "/index.php~"]
ARCHIVES = ["/backup.zip", "/backup.tar.gz", "/site.zip", "/www.zip"]
DEFAULT_TITLES = {
    "Welcome to nginx!": "nginx",
    "Apache2 Ubuntu Default Page: It works": "Apache (Ubuntu)",
    "Apache2 Debian Default Page: It works": "Apache (Debian)",
    "IIS Windows Server": "IIS",
    "Caddy works!": "Caddy",
}
CAP = 256 * 1024


def same_host_hop(src: str, dst: str) -> bool:
    """The documented redirect rule (docs/checks/exposed_files.md: never a cross-host redirect):
    same hostname; same scheme and port, or an http->https upgrade; never a downgrade."""
    a, b = urlparse(src), urlparse(dst)
    if b.scheme not in ("http", "https") or (a.hostname or "").lower() != (b.hostname or "").lower():
        return False
    if a.scheme == "https" and b.scheme == "http":
        return False
    port = lambda u: u.port or (443 if u.scheme == "https" else 80)  # noqa: E731
    if a.scheme == b.scheme:
        return port(a) == port(b)
    return b.port in (None, 443) or b.port == a.port


def fetch(url: str) -> tuple[int, str, bytes, str]:
    """(status, content type, body up to CAP, final URL), following at most 3 same-host
    redirects; a cross-host redirect is returned as is. Status 0 on failure."""
    for _ in range(4):
        out = subprocess.run(["curl", "-sS", "-k", "--max-time", "15", "-o", "/tmp/body",
                              "-w", "%{http_code} %{redirect_url} %{content_type}", url],
                             capture_output=True, text=True)
        if out.returncode not in (0, 23, 63):
            return 0, "", b"", url
        code, _, rest = out.stdout.partition(" ")
        loc, _, ctype = rest.partition(" ")
        with open("/tmp/body", "rb") as f:
            body = f.read(CAP)
        st = int(code or 0)
        if st in (301, 302, 303, 307, 308) and loc and same_host_hop(url, loc):
            url = loc
            continue
        return st, ctype, body, url
    return 0, "", b"", url


def magic(body: bytes) -> str:
    return subprocess.run(["file", "-b", "-"], input=body, capture_output=True).stdout.decode().strip()


class Scripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.src: list[str] = []
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            for k, v in attrs:
                if k == "src" and v:
                    self.src.append(v)
        self._in_title = tag == "title"

    def handle_endtag(self, tag):
        self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


def same_origin(base: str, ref: str) -> str | None:
    u = urljoin(base, ref.strip())
    a, b = urlparse(base), urlparse(u)
    return u.split("#")[0] if (a.scheme, a.netloc.lower()) == (b.scheme, b.netloc.lower()) else None


def truth(origin: str) -> dict:
    keys, notes = [], []
    st, _, base, _ = fetch(origin + "/guardhub-oracle-404-probe-31b7")
    base_sig = (st, hashlib.sha256(base).hexdigest()) if base else None

    def hit(path: str):
        code, ctype, body, _ = fetch(origin + path)
        if code != 200 or not body or (code, hashlib.sha256(body).hexdigest()) == base_sig:
            return None
        return ctype, body

    root_code, _, root, root_url = fetch(origin + "/")
    if root_code == 0:
        return {"file_keys": [], "notes": [f"fetch failed: {origin}/"]}
    notes.append(f"GET / -> {root_code}" + (f" (after same-host redirects: {urlparse(root_url).path})" if root_url != origin + "/" else ""))
    for p in DUMPS:
        r = hit(p)
        if not r:
            continue
        body, m = r[1], magic(r[1])
        if p.endswith(".gz"):
            if not m.startswith("gzip compressed data"):
                notes.append(f"{p}: libmagic '{m[:60]}' (not gzip)")
                continue
            try:
                body = gzip.GzipFile(fileobj=__import__("io").BytesIO(body)).read(CAP)
            except (OSError, EOFError):
                body = b""
        text = body.decode("utf-8", "replace")
        data = re.search(r"(?im)^\s*INSERT INTO\b|^\s*COPY\s+\S+.*\bFROM stdin;", text)
        header = re.search(r"(?im)^-- (MySQL|MariaDB) dump|^-- PostgreSQL database dump|^\s*CREATE TABLE\b", text)
        notes.append(f"{p}: libmagic '{m[:60]}', dump header={bool(header)}, data rows={bool(data)}")
        if header and data:
            keys.append(f"database_dump_exposed:{p}")
    for p in SOURCES:
        r = hit(p)
        if not r:
            continue
        m = magic(r[1])
        notes.append(f"{p}: libmagic '{m[:60]}'")
        if m.startswith("PHP script"):
            keys.append(f"source_backup_exposed:{p}")
    for p in ARCHIVES:
        r = hit(p)
        if not r:
            continue
        m = magic(r[1])
        notes.append(f"{p}: libmagic '{m[:60]}'")
        if m.startswith(("gzip compressed data", "Zip archive data")):
            keys.append(f"archive_backup_exposed:{p}")
    r = hit("/.DS_Store")
    if r:
        m = magic(r[1])
        notes.append(f"/.DS_Store: libmagic '{m[:60]}'")
        if m.startswith("Apple Desktop Services Store"):
            keys.append("ds_store_exposed:/.DS_Store")
    if root_code == 200:
        page = Scripts()
        page.feed(root.decode("utf-8", "replace"))
        title = page.title.strip()
        if title in DEFAULT_TITLES:
            keys.append("default_page_exposed:/")
            notes.append(f"home page title '{title}' ({DEFAULT_TITLES[title]} stock page)")
        for src in [s for s in (same_origin(root_url, s) for s in page.src) if s][:3]:
            code, _, js, _ = fetch(src)
            if code != 200:
                continue
            refs = re.findall(r"(?m)^[ \t]*//[#@] sourceMappingURL=(\S+)\s*$", js[-4096:].decode("utf-8", "replace"))
            if not refs or refs[-1].startswith("data:"):
                continue
            mp = same_origin(src, refs[-1])
            if not mp:
                continue
            code, _, raw, _ = fetch(mp)
            try:
                sm = json.loads(raw)
            except ValueError:
                continue
            embedded = [c for c in (sm.get("sourcesContent") or []) if isinstance(c, str) and c.strip()]
            notes.append(f"{urlparse(mp).path}: HTTP {code}, version {sm.get('version')}, {len(sm.get('sources') or [])} sources, {len(embedded)} embedded")
            if code == 200 and sm.get("version") == 3 and sm.get("sources") and embedded:
                keys.append(f"source_map_exposed:{urlparse(mp).path}")
    return {"file_keys": sorted(set(keys)), "notes": notes}


if __name__ == "__main__":
    print(json.dumps({o: truth(o.rstrip("/")) for o in sys.argv[1:]}, indent=1))
