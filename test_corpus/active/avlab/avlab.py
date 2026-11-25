"""Gate M purpose-built lab targets (ADR-0008 §9). DELIBERATELY VULNERABLE: lab network only.

One stdlib-only server answers for several *.lab.test hosts (the Host header picks the site).
Every site mixes known vulnerabilities with look-alike pages that are safe, so the active checks
are measured on both: a vulnerability is the source line marked VULN, everything else is a
control and encodes, binds or validates its input. The active manifests
(test_corpus/active/manifests/av-*.yaml) list exactly the VULN lines; OWASP ZAP confirms them
independently (test_corpus/oracles/zap), except IDOR, for which ZAP has no rule.

    python3 avlab.py [PORT]

Sites:
  av-xss       reflected XSS in text, double- and single-quoted attributes; script context (outside)
  av-sqli      SQLite: error-based, string- and number-boolean blind; parameterized look-alikes
  av-redirect  Location / proto-relative / Refresh-header open redirects; meta refresh (outside)
  av-cors      credentialed origin reflection (any origin, null)
  av-cors-safe "*", allow-list, reflection without credentials, fixed own origin
  av-ssrf      server-side fetch of a URL parameter; allow-listed and non-fetching look-alikes
  av-idor      two accounts; objects readable across accounts vs owner-checked/public/shared
  av-clean     a small shop where every parameter is handled safely

Second sample (more variants per class, more look-alikes; each site fits one scan's budget):
  av-xss2       blocklist filter, quotes-only escaping, 400 error page, JSON served as HTML, href
                attribute, &-only escaping, one of two parameters; encoded/text-plain look-alikes
  av-sqli2      string/number/parenthesised/LIKE, shown or hidden errors, blind on values other
                than 1 (review, lookup), ORDER BY (outside); WAF, cast, ever-changing look-alikes
  av-redirect2  301/303/307, javascript:-only and prefix-strip filters, Refresh URL=; table,
                signed, interstitial and fixed look-alikes
  av-cors2/3    credentialed echo (JSON, HTML, 401, any header), null trusted
  av-cors-safe2 "True", "*" with credentials, parsed subdomain allow-list, credentials false
  av-ssrf2      webhook test, thumbnail, feed, proxy, link preview; allow-list, cache, pattern
  av-idor2      JSON path id, UUID, number, 24-hex key, ref; 404-checked, public, ignored id,
                200 refusal and shared look-alikes (sessions: the av-idor accounts)
"""

from __future__ import annotations

import hashlib
import hmac
import html
import json
import re
import secrets
import sqlite3
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

E = html.escape  # quote=True: & < > " '


def page(title: str, body: str, nav: str = "") -> str:
    return (f"<!doctype html><html><head><meta charset=utf-8><title>{E(title)}</title></head>"
            f"<body><header>{nav}</header><h1>{E(title)}</h1>{body}"
            "<footer>GuardHub lab target (deliberately vulnerable, lab only)</footer></body></html>")  # fmt: skip


def links(*hrefs: str) -> str:
    return (
        "<ul>"
        + "".join(f'<li><a href="{E(h)}">{E(h)}</a></li>' for h in hrefs)
        + "</ul>"
    )


# ---------------------------------------------------------------- data (SQLite, in memory)
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript("""
CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT, price REAL);
INSERT INTO items VALUES (1,'apple',1.5),(2,'pear',2.0),(3,'plum',0.9);
CREATE TABLE accounts(uid TEXT PRIMARY KEY, name TEXT);
INSERT INTO accounts VALUES ('1','Ada Lab'),('2','Bo Lab');
CREATE TABLE orders(id INTEGER PRIMARY KEY, item TEXT);
INSERT INTO orders VALUES (1,'apple x3'),(2,'pear x1');
""")


def q(sql: str, args: tuple = ()) -> list[tuple]:
    return DB.execute(sql, args).fetchall()


# ---------------------------------------------------------------- IDOR accounts
USERS = {
    "alice": ("alice-lab-pass", "alice.gh7@av-idor.lab.test"),
    "bob": ("bob-lab-pass", "bob.gh7@av-idor.lab.test"),
}
SESSIONS: dict[str, str] = {}  # sid -> user
INVOICES = {"101": "alice", "102": "bob"}
PROFILES = {"1001": "alice", "1002": "bob"}
MESSAGES = {"7001": "alice", "7002": "bob"}
RECEIPTS = {"301": "alice", "302": "bob"}
POSTS = {"9001": "alice"}
OWN = {u: {"invoice": i, "profile": p, "message": m, "receipt": r}
       for u, i, p, m, r in [("alice", "101", "1001", "7001", "301"), ("bob", "102", "1002", "7002", "302")]}  # fmt: skip


def mail(u: str) -> str:
    return USERS[u][1]


class Resp:
    def __init__(
        self,
        status: int = 200,
        body: str = "",
        ctype: str = "text/html; charset=utf-8",
        headers: dict | None = None,
    ):
        self.status, self.body, self.ctype, self.headers = (
            status,
            body,
            ctype,
            headers or {},
        )


def redirect(loc: str, status: int = 302) -> Resp:
    return Resp(status, "", headers={"Location": loc})


def as_int(v: str) -> int | None:
    return int(v) if v.isdigit() and len(v) < 10 else None


# ---------------------------------------------------------------- sites
def site_xss(path: str, a: dict, h: "Handler") -> Resp:
    v = lambda k, d="": a.get(k, d)  # noqa: E731
    if path == "/":
        return Resp(body=page("av-xss", links("/search?q=shoes", "/profile?name=guest", "/greet?who=friend", "/lang?l=en",
                                              "/search-safe?q=shoes", "/profile-safe?name=guest", "/api/search?q=shoes",
                                              "/len?q=shoes", "/comment?text=hello")))  # fmt: skip
    if path == "/search":  # VULN: q reflected into text unencoded
        return Resp(body=page("Search", f"<p>Results for <b>{v('q')}</b>: none</p>"))
    if (
        path == "/profile"
    ):  # VULN: name reflected into a double-quoted attribute unencoded
        return Resp(
            body=page(
                "Profile", f'<form><input name="name" value="{v("name")}"></form>'
            )
        )
    if path == "/greet":  # VULN: who reflected into a single-quoted attribute unencoded
        return Resp(body=page("Greet", f"<div title='{v('who')}'>Hello</div>"))
    if (
        path == "/lang"
    ):  # VULN (outside: script context): l reflected into a JS string unencoded
        return Resp(
            body=page(
                "Language",
                f'<script>var lang = "{v("l")}";</script><p>Language set.</p>',
            )
        )
    if path == "/search-safe":
        return Resp(body=page("Search", f"<p>Results for <b>{E(v('q'))}</b>: none</p>"))
    if path == "/profile-safe":
        return Resp(
            body=page(
                "Profile", f'<form><input name="name" value="{E(v("name"))}"></form>'
            )
        )
    if path == "/api/search":  # JSON, never rendered as HTML (nosniff)
        return Resp(
            body=json.dumps({"q": v("q"), "results": []}), ctype="application/json"
        )
    if path == "/len":
        return Resp(body=page("Length", f"<p>{len(v('q'))} characters</p>"))
    if path == "/comment":
        return Resp(body=page("Comment", f"<pre>{E(v('text'))}</pre>"))
    return Resp(404, page("Not found", ""))


def site_sqli(path: str, a: dict, h: "Handler") -> Resp:
    v = lambda k, d="": a.get(k, d)  # noqa: E731
    if path == "/":
        return Resp(body=page("av-sqli", links("/item?id=1", "/account?uid=1", "/order?id=1", "/item-safe?id=1",
                                               "/account-safe?uid=1", "/search?q=apple", "/docs?topic=errors", "/int?id=1")))  # fmt: skip
    if path == "/item":  # VULN: number concatenated; the database error is shown
        try:
            rows = q(f"SELECT name, price FROM items WHERE id = {v('id')}")  # noqa: S608 (lab VULN)
        except sqlite3.Error as e:
            return Resp(
                body=page(
                    "Item",
                    f"<p>Database error: sqlite3.{type(e).__name__}: {E(str(e))}</p>",
                )
            )
        return Resp(
            body=page(
                "Item",
                "".join(f"<p>{E(n)}: {p}</p>" for n, p in rows)
                or "<p>No such item</p>",
            )
        )
    if (
        path == "/account"
    ):  # VULN: string concatenated; errors hidden; found 200 / missing 404 (blind)
        try:
            rows = q(f"SELECT name FROM accounts WHERE uid = '{v('uid')}'")  # noqa: S608 (lab VULN)
        except sqlite3.Error:
            rows = []
        if not rows:
            return Resp(404, page("Account", "<p>No such account</p>"))
        return Resp(body=page("Account", f"<p>Account holder: {E(rows[0][0])}</p>"))
    if (
        path == "/order"
    ):  # VULN: number concatenated; errors hidden; same status, different text (blind)
        try:
            rows = q(f"SELECT item FROM orders WHERE id = {v('id')}")  # noqa: S608 (lab VULN)
        except sqlite3.Error:
            rows = []
        return Resp(
            body=page(
                "Order",
                f"<p>Order contents: {E(rows[0][0])}</p>"
                if rows
                else "<p>We could not find that order</p>",
            )
        )
    if path == "/item-safe":
        rows = q("SELECT name, price FROM items WHERE id = ?", (v("id"),))
        if not rows:
            return Resp(404, page("Item", "<p>No such item</p>"))
        return Resp(body=page("Item", f"<p>{E(rows[0][0])}: {rows[0][1]}</p>"))
    if path == "/account-safe":
        rows = q("SELECT name FROM accounts WHERE uid = ?", (v("uid"),))
        if not rows:
            return Resp(404, page("Account", "<p>No such account</p>"))
        return Resp(body=page("Account", f"<p>Account holder: {E(rows[0][0])}</p>"))
    if path == "/search":  # bound parameter; the page changes with every input
        rows = q("SELECT name FROM items WHERE name LIKE ?", ("%" + v("q") + "%",))
        return Resp(
            body=page(
                "Search",
                f"<p>{len(rows)} results for {E(v('q'))}</p>"
                + "".join(f"<p>{E(r[0])}</p>" for r in rows),
            )
        )
    if path == "/docs":  # static help text that always quotes database errors
        return Resp(body=page("Docs", "<p>Common messages: <code>You have an error in your SQL syntax</code>, "
                                      "<code>SQLITE_ERROR: near \"x\": syntax error</code>. Report them to support.</p>"))  # fmt: skip
    if path == "/int":
        n = as_int(v("id"))
        if n is None:
            return Resp(400, page("Bad request", "<p>id must be a number</p>"))
        rows = q("SELECT name FROM items WHERE id = ?", (n,))
        return Resp(body=page("Item", f"<p>{E(rows[0][0]) if rows else 'none'}</p>"))
    return Resp(404, page("Not found", ""))


def site_redirect(path: str, a: dict, h: "Handler") -> Resp:
    v = lambda k, d="": a.get(k, d)  # noqa: E731
    if path == "/":
        return Resp(body=page("av-redirect", links("/go?url=/home", "/login?next=/home", "/out?to=/home", "/jump?dest=/home",
                                                   "/go-safe?url=/home", "/back?url=/home", "/link?url=/home", "/lang?set=tr")))  # fmt: skip
    if path == "/home":
        return Resp(body=page("Home", "<p>Welcome.</p>"))
    if path == "/go":  # VULN: any URL into Location
        return redirect(v("url", "/"))
    if path == "/login":  # VULN: "starts with /" also accepts //other-host/
        n = v("next", "/")
        return redirect(n if n.startswith("/") else "/")
    if path == "/out":  # VULN: any URL into the Refresh header
        return Resp(
            body=page("Leaving", "<p>Goodbye.</p>"),
            headers={"Refresh": f"0; url={v('to', '/')}"},
        )
    if path == "/jump":  # VULN (outside: meta refresh in the body, no redirect header)
        return Resp(
            body=page(
                "Jump",
                f'<meta http-equiv="refresh" content="0; url={E(v("dest", "/"))}"><p>Redirecting.</p>',
            )
        )
    if path == "/go-safe":  # same-site paths only
        u = v("url", "/")
        ok = (
            u.startswith("/")
            and not u.startswith("//")
            and not u.startswith("/\\")
            and "\\" not in u
        )
        return redirect(u if ok else "/")
    if path == "/back":
        return redirect("/")
    if path == "/link":  # shows the link, never redirects
        return Resp(
            body=page(
                "Continue",
                f'<p><a href="/home" data-target="{E(v("url"))}">continue</a></p>',
            )
        )
    if path == "/lang":
        return redirect("/home?lang=" + urllib.parse.quote(v("set", "en"), safe=""))
    return Resp(404, page("Not found", ""))


def site_cors(path: str, a: dict, h: "Handler") -> Resp:
    origin = h.headers.get("Origin")
    data = lambda: json.dumps({"path": path, "user": "lab"})  # noqa: E731
    if path == "/":
        return Resp(
            body=page("av-cors", links("/api/me", "/api/orders", "/api/settings"))
        )
    if path in (
        "/api/me",
        "/api/settings",
    ):  # VULN: any Origin echoed, with credentials
        hd = (
            {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }
            if origin
            else {}
        )
        return Resp(body=data(), ctype="application/json", headers=hd)
    if (
        path == "/api/orders"
    ):  # VULN: the "null" origin (sandboxed frames, data: URLs) trusted with credentials
        hd = (
            {
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Credentials": "true",
            }
            if origin == "null"
            else {}
        )
        return Resp(body=data(), ctype="application/json", headers=hd)
    return Resp(404, page("Not found", ""))


def site_cors_safe(path: str, a: dict, h: "Handler") -> Resp:
    origin = h.headers.get("Origin")
    data = lambda: json.dumps({"path": path})  # noqa: E731
    if path == "/":
        return Resp(
            body=page(
                "av-cors-safe",
                links("/api/public", "/api/partner", "/api/echo", "/api/self"),
            )
        )
    if path == "/api/public":  # public data: "*" never carries credentials
        return Resp(
            body=data(),
            ctype="application/json",
            headers={"Access-Control-Allow-Origin": "*"},
        )
    if path == "/api/partner":  # exact allow-list
        hd = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true", "Vary": "Origin"} \
            if origin == "https://partner.av-cors-safe.lab.test" else {}  # fmt: skip
        return Resp(body=data(), ctype="application/json", headers=hd)
    if path == "/api/echo":  # echoed, but without credentials: no cookie-bearing read
        hd = {"Access-Control-Allow-Origin": origin, "Vary": "Origin"} if origin else {}
        return Resp(body=data(), ctype="application/json", headers=hd)
    if path == "/api/self":  # always its own origin
        return Resp(body=data(), ctype="application/json",
                    headers={"Access-Control-Allow-Origin": "http://av-cors-safe.lab.test", "Access-Control-Allow-Credentials": "true"})  # fmt: skip
    return Resp(404, page("Not found", ""))


def fetch(u: str) -> str:
    if not u.lower().startswith(("http://", "https://")):
        return "only http(s) URLs"
    try:
        with urllib.request.urlopen(u, timeout=3) as r:  # noqa: S310 (lab VULN: the point of SSRF)
            return f"fetched {len(r.read(65536))} bytes (HTTP {r.status})"
    except Exception as e:  # noqa: BLE001
        return f"fetch failed ({type(e).__name__})"


def site_ssrf(path: str, a: dict, h: "Handler") -> Resp:
    v = lambda k, d="": a.get(k, d)  # noqa: E731
    me = "http://av-ssrf.lab.test"
    if path == "/":
        return Resp(body=page("av-ssrf", links(f"/fetch?url={me}/hello", f"/preview?src={me}/hello", f"/hook?callback={me}/hello",
                                               f"/img?u={me}/logo", f"/fetch-safe?url={me}/hello", f"/link?url={me}/hello",
                                               f"/validate?url={me}/hello")))  # fmt: skip
    if path in ("/hello", "/logo"):
        return Resp(body="hello", ctype="text/plain; charset=utf-8")
    if path in (
        "/fetch",
        "/preview",
        "/hook",
        "/img",
    ):  # VULN: the server fetches whatever URL it is given
        u = v(
            {"/fetch": "url", "/preview": "src", "/hook": "callback", "/img": "u"}[path]
        )
        return Resp(body=page("Fetch", f"<p>{E(fetch(u))}</p>"))
    if path == "/fetch-safe":  # only its own host
        u = v("url")
        if urllib.parse.urlsplit(u).hostname != "av-ssrf.lab.test":
            return Resp(
                400,
                page("Fetch", "<p>blocked: only av-ssrf.lab.test may be fetched</p>"),
            )
        return Resp(body=page("Fetch", f"<p>{E(fetch(u))}</p>"))
    if (
        path == "/link"
    ):  # shows the URL, never fetches it; only http(s) URLs become links
        u = v("url")
        if urllib.parse.urlsplit(u).scheme not in ("http", "https"):
            return Resp(body=page("Link", f"<p>Saved text: {E(u)}</p>"))
        return Resp(
            body=page("Link", f'<p>Saved link: <a href="{E(u)}">{E(u)}</a></p>')
        )
    if path == "/validate":  # parses, never fetches
        s = urllib.parse.urlsplit(v("url"))
        return Resp(
            body=page(
                "Validate",
                f"<p>{'looks valid' if s.scheme in ('http', 'https') and s.hostname else 'invalid'}</p>",
            )
        )
    return Resp(404, page("Not found", ""))


def site_idor(path: str, a: dict, h: "Handler") -> Resp:
    v = lambda k, d="": a.get(k, d)  # noqa: E731
    user = h.user()
    nav = f"<p>Signed in as {E(mail(user))}</p>" if user else ""
    if path == "/login" and h.command == "POST":
        f = h.form()
        u = f.get("user", "")
        if u in USERS and secrets.compare_digest(USERS[u][0], f.get("password", "")):
            sid = secrets.token_hex(16)
            SESSIONS[sid] = u
            return Resp(
                302,
                "",
                headers={"Location": "/", "Set-Cookie": f"sid={sid}; Path=/; HttpOnly"},
            )
        return Resp(403, page("Login", "<p>wrong user or password</p>"))
    if path == "/post":  # public: anyone may read a post (it names its author)
        o = POSTS.get(v("id"))
        return (
            Resp(
                body=page(
                    "Post",
                    f"<p>Post {E(v('id'))} by {E(mail(o))}: hello world</p>",
                    nav,
                )
            )
            if o
            else Resp(404, page("Post", "", nav))
        )
    if not user:
        if path == "/":
            return Resp(
                body=page(
                    "av-idor",
                    '<form method="post" action="/login"><input name="user"><input type="password" name="password"></form>',
                )
            )
        return redirect("/")
    o = OWN[user]
    if path == "/":
        return Resp(body=page("av-idor", links(f"/invoice?id={o['invoice']}", f"/profile/{o['profile']}", f"/message?msg_id={o['message']}",
                                               f"/receipt?id={o['receipt']}", "/post?id=9001", "/team?id=55",
                                               f"/settings?id={o['profile']}"), nav))  # fmt: skip

    def show(kind: str, table: dict, key: str, check_owner: bool) -> Resp:
        owner = table.get(key)
        if owner is None:
            return Resp(404, page(kind, "<p>not found</p>", nav))
        if check_owner and owner != user:
            return Resp(403, page(kind, "<p>not yours</p>", nav))
        return Resp(
            body=page(
                kind,
                f"<p>{kind} {E(key)} belongs to {E(mail(owner))}. Total 42.00 EUR. Private notes: none.</p>",
                nav,
            )
        )

    if path == "/invoice":  # VULN: no owner check
        return show("Invoice", INVOICES, v("id"), False)
    if path.startswith("/profile/"):  # VULN: no owner check (id in the path)
        return show("Profile", PROFILES, path.rsplit("/", 1)[1], False)
    if path == "/message":  # VULN: no owner check
        return show("Message", MESSAGES, v("msg_id"), False)
    if path == "/receipt":
        return show("Receipt", RECEIPTS, v("id"), True)
    if path == "/team":  # shared between both accounts
        return Resp(
            body=page(
                "Team",
                f"<p>Team {E(v('id'))}: {E(mail('alice'))}, {E(mail('bob'))}</p>",
                nav,
            )
        )
    if path == "/settings":  # ignores the id: always the signed-in account
        return Resp(body=page("Settings", f"<p>Settings of {E(mail(user))}</p>", nav))
    return Resp(404, page("Not found", "", nav))


def site_clean(path: str, a: dict, h: "Handler") -> Resp:
    v = lambda k, d="": a.get(k, d)  # noqa: E731
    if path == "/":
        return Resp(body=page("av-clean", links("/products?page=2", "/product?id=3", "/sort?order=price", "/download?file=report.pdf",
                                                "/find?q=plum", "/next?url=/products", "/share?link=http://av-clean.lab.test/product?id=3")))  # fmt: skip
    if path == "/products":
        n = as_int(v("page", "1")) or 1
        return Resp(body=page("Products", f"<p>Page {n} of 3</p>"))
    if path == "/product":
        rows = q("SELECT name, price FROM items WHERE id = ?", (v("id"),))
        return (
            Resp(body=page("Product", f"<p>{E(rows[0][0])}</p>"))
            if rows
            else Resp(404, page("Product", "<p>not found</p>"))
        )
    if path == "/sort":
        col = {"price": "price", "name": "name"}.get(v("order"), "id")
        return Resp(
            body=page(
                "Sorted",
                "".join(
                    f"<p>{E(r[0])}</p>"
                    for r in q(f"SELECT name FROM items ORDER BY {col}")
                ),
            )
        )  # noqa: S608 (allow-listed)
    if path == "/download":
        f = v("file")
        return (
            Resp(body=page("Download", "<p>report ready</p>"))
            if f in ("report.pdf", "terms.pdf")
            else Resp(404, page("Download", "<p>no such file</p>"))
        )
    if path == "/find":
        rows = q("SELECT name FROM items WHERE name = ?", (v("q"),))
        return Resp(body=page("Find", f"<p>{len(rows)} match(es) for {E(v('q'))}</p>"))
    if path == "/next":
        u = v("url", "/")
        return redirect(
            u if u.startswith("/") and not u.startswith("//") and "\\" not in u else "/"
        )
    if path == "/share":
        return Resp(
            body=page("Share", f"<p>Share this: <code>{E(v('link'))}</code></p>")
        )
    return Resp(404, page("Not found", ""))


# ================================================================ second sample (Gate M depth)
# More variants of each vulnerability class, on their own hosts so every site stays inside one
# scan's request budget, and more look-alikes that are safe. Same rule as above: VULN lines are
# the truth, everything else encodes, binds, validates or does not act on its input.

DB.executescript("""
CREATE TABLE people(name TEXT PRIMARY KEY, email TEXT);
INSERT INTO people VALUES ('ada','ada@av-sqli2.lab.test'),('bo','bo@av-sqli2.lab.test');
CREATE TABLE reviews(id INTEGER PRIMARY KEY, body TEXT);
INSERT INTO reviews VALUES (1,'too sweet'),(2,'fine'),(3,'great value');
CREATE TABLE tags(name TEXT PRIMARY KEY, n INTEGER);
INSERT INTO tags VALUES ('fruit',3),('red',1);
""")

SCRIPT_TAG = re.compile(r"(?i)<\s*/?\s*script[^>]*>")


def site_xss2(path: str, a: dict, h: "Handler") -> Resp:
    v = lambda k, d="": a.get(k, d)  # noqa: E731
    if path == "/":
        return Resp(body=page("av-xss2", links("/find?term=shoes", "/tag?label=new", "/err?code=E1", "/json-html?q=shoes",
                                               "/list?dir=asc", "/hello?name=guest", "/page?id=1&ref=home",
                                               "/find-safe?term=shoes", "/plain?q=shoes", "/attr-safe?v=blue",
                                               "/textarea?msg=hi")))  # fmt: skip
    if (
        path == "/find"
    ):  # VULN: a blocklist strips <script> tags only; any other element passes
        return Resp(
            body=page("Find", f"<p>No results for {SCRIPT_TAG.sub('', v('term'))}</p>")
        )
    if (
        path == "/tag"
    ):  # VULN: quotes are encoded, angle brackets are not (text context)
        t = v("label").replace('"', "&quot;").replace("'", "&#x27;")
        return Resp(body=page("Tag", f"<p>Tag: <span>{t}</span></p>"))
    if path == "/err":  # VULN: an error page (HTTP 400) reflects code unencoded
        return Resp(400, page("Bad request", f"<p>Unknown code {v('code')}</p>"))
    if path == "/json-html":  # VULN: JSON with the input unencoded, served as text/html
        return Resp(body=json.dumps({"q": v("q"), "results": []}))
    if path == "/list":  # VULN: dir reflected into a double-quoted href unencoded
        return Resp(
            body=page("List", f'<p><a href="/list?dir={v("dir")}">reverse</a></p>')
        )
    if path == "/hello":  # VULN: a home-made escape that encodes & only
        return Resp(
            body=page("Hello", f"<p>Hello {v('name').replace('&', '&amp;')}</p>")
        )
    if path == "/page":  # VULN (ref): ref reflected unencoded; id is validated
        n = as_int(v("id")) or 1
        return Resp(
            body=page("Page", f"<p>Page {n}</p><p>Back to <i>{v('ref')}</i></p>")
        )
    if path == "/find-safe":  # the same blocklist, then encoded
        return Resp(
            body=page(
                "Find", f"<p>No results for {E(SCRIPT_TAG.sub('', v('term')))}</p>"
            )
        )
    if path == "/plain":  # unencoded, but text/plain with nosniff: never parsed as HTML
        return Resp(body=f"No results for {v('q')}", ctype="text/plain; charset=utf-8")
    if path == "/attr-safe":
        return Resp(body=page("Colour", f'<p><input name="v" value="{E(v("v"))}"></p>'))
    if path == "/textarea":
        return Resp(
            body=page("Message", f"<p><textarea name=msg>{E(v('msg'))}</textarea></p>")
        )
    return Resp(404, page("Not found", ""))


def site_sqli2(path: str, a: dict, h: "Handler") -> Resp:
    v = lambda k, d="": a.get(k, d)  # noqa: E731
    if path == "/":
        return Resp(body=page("av-sqli2", links("/user?name=ada", "/price?max=1", "/stock?sku=1", "/tag?name=fruit", "/item?id=1",
                                                "/review?id=3", "/lookup?email=bo@av-sqli2.lab.test", "/sorted?order=name",
                                                "/user-safe?name=ada", "/live?id=1", "/waf?id=1", "/numcast?id=2")))  # fmt: skip

    def failed(title: str, e: Exception, prefix: str = "Query failed") -> Resp:
        return Resp(body=page(title, f"<p>{prefix}: {E(str(e))}</p>"))

    if path == "/user":  # VULN: string concatenated; the database message is shown
        try:
            rows = q(f"SELECT email FROM people WHERE name = '{v('name')}'")  # noqa: S608 (lab VULN)
        except sqlite3.Error as e:
            return failed("User", e)
        return Resp(
            body=page(
                "User", f"<p>{E(rows[0][0])}</p>" if rows else "<p>No such user</p>"
            )
        )
    if (
        path == "/price"
    ):  # VULN: number concatenated into a comparison; the message is shown
        try:
            rows = q(f"SELECT name FROM items WHERE price <= {v('max')} ORDER BY id")  # noqa: S608 (lab VULN)
        except sqlite3.Error as e:
            return failed("Prices", e)
        return Resp(
            body=page(
                "Prices",
                "".join(f"<p>{E(r[0])}</p>" for r in rows)
                or "<p>Nothing that cheap</p>",
            )
        )
    if (
        path == "/stock"
    ):  # VULN: number inside parentheses; errors hidden; same status, other text (blind)
        try:
            rows = q(f"SELECT name FROM items WHERE (id = {v('sku')}) AND price > 0")  # noqa: S608 (lab VULN)
        except sqlite3.Error:
            rows = []
        return Resp(
            body=page(
                "Stock",
                f"<p>In stock: {E(rows[0][0])}</p>"
                if rows
                else "<p>Not stocked here</p>",
            )
        )
    if (
        path == "/tag"
    ):  # VULN: string concatenated into LIKE (no wildcard added); SQLITE_ERROR shown
        try:
            rows = q(f"SELECT n FROM tags WHERE name LIKE '{v('name')}'")  # noqa: S608 (lab VULN)
        except sqlite3.Error as e:
            return failed("Tag", e, "SQLITE_ERROR")
        return Resp(
            body=page(
                "Tag", f"<p>{rows[0][0]} products</p>" if rows else "<p>No such tag</p>"
            )
        )
    if (
        path == "/item"
    ):  # VULN: number inside parentheses; errors hidden; found 200, missing 404 (blind)
        try:
            rows = q(f"SELECT name FROM items WHERE id = ({v('id')})")  # noqa: S608 (lab VULN)
        except sqlite3.Error:
            rows = []
        if not rows:
            return Resp(404, page("Item", "<p>No such item</p>"))
        return Resp(body=page("Item", f"<p>{E(rows[0][0])}</p>"))
    if (
        path == "/review"
    ):  # VULN: number concatenated; errors hidden; the linked value is 3, not 1 (blind)
        try:
            rows = q(f"SELECT body FROM reviews WHERE id = {v('id')}")  # noqa: S608 (lab VULN)
        except sqlite3.Error:
            rows = []
        return Resp(
            body=page(
                "Review",
                f"<p>Review: {E(rows[0][0])}</p>" if rows else "<p>No review yet</p>",
            )
        )
    if (
        path == "/lookup"
    ):  # VULN: string concatenated; errors hidden; the linked value is an e-mail (blind)
        try:
            rows = q(f"SELECT name FROM people WHERE email = '{v('email')}'")  # noqa: S608 (lab VULN)
        except sqlite3.Error:
            rows = []
        return Resp(
            body=page(
                "Lookup",
                f"<p>Found {E(rows[0][0])}</p>"
                if rows
                else "<p>Nobody with that address</p>",
            )
        )
    if (
        path == "/sorted"
    ):  # VULN (outside: ORDER BY): column name concatenated; the message is shown
        try:
            rows = q(f"SELECT name FROM items ORDER BY {v('order')}")  # noqa: S608 (lab VULN)
        except sqlite3.Error as e:
            return failed("Sorted", e)
        return Resp(body=page("Sorted", "".join(f"<p>{E(r[0])}</p>" for r in rows)))
    if path == "/user-safe":
        rows = q("SELECT email FROM people WHERE name = ?", (v("name"),))
        return Resp(
            body=page(
                "User", f"<p>{E(rows[0][0])}</p>" if rows else "<p>No such user</p>"
            )
        )
    if (
        path == "/live"
    ):  # bound; every answer carries a fresh request id (a page that never repeats)
        rows = q("SELECT name FROM items WHERE id = ?", (v("id"),))
        return Resp(
            body=page(
                "Live",
                f"<p>{E(rows[0][0]) if rows else 'none'}</p><p>request {secrets.token_hex(4)}</p>",
            )
        )
    if (
        path == "/waf"
    ):  # a filter answers 403 to quotes and SQL words; the query is bound anyway
        if re.search(r"(?i)['\"]|\b(and|or|union|select)\b", v("id")):
            return Resp(
                403, page("Blocked", "<p>Request blocked by the input filter</p>")
            )
        rows = q("SELECT name FROM items WHERE id = ?", (v("id"),))
        return Resp(body=page("Item", f"<p>{E(rows[0][0]) if rows else 'none'}</p>"))
    if path == "/numcast":  # anything that is not a number falls back to item 1
        n = as_int(v("id")) or 1
        rows = q("SELECT name FROM items WHERE id = ?", (n,))
        return Resp(body=page("Item", f"<p>{E(rows[0][0]) if rows else 'none'}</p>"))
    return Resp(404, page("Not found", ""))


SIGN_KEY = secrets.token_bytes(16)


def sign(u: str) -> str:
    return hmac.new(SIGN_KEY, u.encode(), hashlib.sha256).hexdigest()[:16]


def site_redirect2(path: str, a: dict, h: "Handler") -> Resp:
    v = lambda k, d="": a.get(k, d)  # noqa: E731
    if path == "/":
        return Resp(body=page("av-redirect2", links("/r301?u=/home", "/r307?return=/home", "/r303?continue=/home",
                                                    "/auth/callback?redirect_uri=/home", "/bye?returnTo=/home", "/r?next=/home",
                                                    "/to?url=/home", "/r-safe?u=home", f"/r-signed?u=/home&sig={sign('/home')}",
                                                    "/r-leave?u=/home", "/r-static?u=/home")))  # fmt: skip
    if path == "/home":
        return Resp(body=page("Home", "<p>Welcome.</p>"))
    if path == "/r301":  # VULN: any URL, permanent redirect
        return redirect(v("u", "/"), 301)
    if path == "/r307":  # VULN: any URL, 307
        return redirect(v("return", "/"), 307)
    if path == "/r303":  # VULN: any URL, 303
        return redirect(v("continue", "/"), 303)
    if path == "/auth/callback":  # VULN: only javascript: is refused
        u = v("redirect_uri", "/")
        return redirect("/" if u.strip().lower().startswith("javascript:") else u)
    if path == "/bye":  # VULN: any URL after signing off
        return redirect(v("returnTo", "/"))
    if path == "/r":  # VULN: strips a leading http:// or https:// once; //host/ passes
        return redirect(
            v("next", "/").removeprefix("https://").removeprefix("http://") or "/"
        )
    if path == "/to":  # VULN: any URL into the Refresh header (upper-case URL=, quoted)
        return Resp(
            body=page("Leaving", "<p>Goodbye.</p>"),
            headers={"Refresh": f"0;URL='{v('url', '/')}'"},
        )
    if path == "/r-safe":  # a fixed table of destinations
        return redirect({"home": "/home", "help": "/home#help"}.get(v("u"), "/"))
    if path == "/r-signed":  # only destinations the site itself signed
        u = v("u", "/")
        return redirect(u if hmac.compare_digest(sign(u), v("sig")) else "/")
    if path == "/r-leave":  # an interstitial page: the link is shown, nothing redirects
        return Resp(
            body=page(
                "Leaving", f'<p>You are leaving. <a href="{E(v("u"))}">Continue</a></p>'
            )
        )
    if path == "/r-static":  # the parameter is ignored
        return redirect("/home")
    return Resp(404, page("Not found", ""))


def cors_json(path: str, hd: dict, status: int = 200) -> Resp:
    return Resp(
        status, json.dumps({"path": path, "user": "lab"}), "application/json", hd
    )


def site_cors2(path: str, a: dict, h: "Handler") -> Resp:
    origin = h.headers.get("Origin")
    if path == "/":
        return Resp(
            body=page(
                "av-cors2", links("/v1/profile", "/v1/notifications", "/v1/tokens")
            )
        )
    if (
        path == "/v1/profile"
    ):  # VULN: any Origin echoed, with credentials (framework-style headers)
        hd = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
              "Access-Control-Allow-Methods": "GET, POST", "Vary": "Origin"} if origin else {}  # fmt: skip
        return cors_json(path, hd)
    if (
        path == "/v1/notifications"
    ):  # VULN: answers 401 without a session, but grants any Origin credentials
        hd = (
            {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
            if origin
            else {}
        )
        return cors_json(path, hd, 401)
    if path == "/v1/tokens":  # VULN: the null origin trusted with credentials
        hd = (
            {
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Credentials": "true",
            }
            if origin == "null"
            else {}
        )
        return cors_json(path, hd)
    return Resp(404, page("Not found", ""))


def site_cors3(path: str, a: dict, h: "Handler") -> Resp:
    origin = h.headers.get("Origin")
    if path == "/":
        return Resp(
            body=page("av-cors3", links("/data/export", "/data/feed", "/data/stats"))
        )
    if (
        path == "/data/export"
    ):  # VULN: an HTML export readable by any Origin, with credentials
        hd = (
            {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
            if origin
            else {}
        )
        return Resp(body=page("Export", "<p>3 rows</p>"), headers=hd)
    if (
        path == "/data/feed"
    ):  # VULN: any Origin echoed with credentials and any request header
        hd = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true",
              "Access-Control-Allow-Headers": "*"} if origin else {}  # fmt: skip
        return cors_json(path, hd)
    if (
        path == "/data/stats"
    ):  # VULN: an allow-list that also admits "null" (local files, sandboxed frames)
        ok = origin in ("null", "http://av-cors3.lab.test")
        hd = (
            {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            }
            if ok
            else {}
        )
        return cors_json(path, hd)
    return Resp(404, page("Not found", ""))


def site_cors_safe2(path: str, a: dict, h: "Handler") -> Resp:
    origin = h.headers.get("Origin") or ""
    if path == "/":
        return Resp(
            body=page(
                "av-cors-safe2",
                links("/api/legacy", "/api/wild", "/api/sub", "/api/cred-false"),
            )
        )
    if (
        path == "/api/legacy"
    ):  # echoed with "True": browsers require exactly "true" (Fetch, CORS check)
        hd = (
            {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "True",
            }
            if origin
            else {}
        )
        return cors_json(path, hd)
    if path == "/api/wild":  # "*" with credentials: browsers refuse the combination
        return cors_json(
            path,
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )
    if (
        path == "/api/sub"
    ):  # only this site's own subdomains, checked on the parsed host
        s = urllib.parse.urlsplit(origin)
        ok = s.scheme in ("http", "https") and (s.hostname or "").endswith(
            ".av-cors-safe2.lab.test"
        )
        hd = (
            {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
                "Vary": "Origin",
            }
            if ok
            else {}
        )
        return cors_json(path, hd)
    if path == "/api/cred-false":  # echoed, credentials explicitly refused
        hd = (
            {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "false",
            }
            if origin
            else {}
        )
        return cors_json(path, hd)
    return Resp(404, page("Not found", ""))


FEEDS = {"http://av-ssrf2.lab.test/feed": "<rss>cached</rss>"}


def site_ssrf2(path: str, a: dict, h: "Handler") -> Resp:
    v = lambda k, d="": a.get(k, d)  # noqa: E731
    me = "http://av-ssrf2.lab.test"
    if path == "/":
        return Resp(body=page("av-ssrf2", links(f"/api/webhook-test?webhook={me}/hello", f"/thumb?image_url={me}/logo",
                                                f"/rss?feed={me}/feed", f"/proxy?target={me}/hello", f"/share?q={me}/hello",
                                                f"/thumb-safe?image_url={me}/logo", f"/rss-cached?feed={me}/feed",
                                                f"/check-url?url={me}/hello")))  # fmt: skip
    if path in ("/hello", "/logo", "/feed"):
        return Resp(body="hello", ctype="text/plain; charset=utf-8")
    vuln = {
        "/api/webhook-test": "webhook",
        "/thumb": "image_url",
        "/rss": "feed",
        "/proxy": "target",
        "/share": "q",
    }
    if (
        path in vuln
    ):  # VULN: the server fetches the URL it is given (webhook test, thumbnail, feed, proxy, link preview)
        return Resp(body=page("Fetch", f"<p>{E(fetch(v(vuln[path])))}</p>"))
    if path == "/thumb-safe":  # only its own host
        u = v("image_url")
        if urllib.parse.urlsplit(u).hostname != "av-ssrf2.lab.test":
            return Resp(
                400, page("Thumbnail", "<p>blocked: only av-ssrf2.lab.test images</p>")
            )
        return Resp(body=page("Thumbnail", f"<p>{E(fetch(u))}</p>"))
    if path == "/rss-cached":  # served from a cache filled at start; never fetches
        return Resp(
            body=page("Feed", f"<p>{E(FEEDS.get(v('feed'), 'not cached'))}</p>")
        )
    if path == "/check-url":  # a pattern check, never a fetch
        ok = re.fullmatch(r"https?://[A-Za-z0-9.-]+(/[^\s]*)?", v("url")) is not None
        return Resp(
            body=page("Check", f"<p>{'looks like a URL' if ok else 'not a URL'}</p>")
        )
    return Resp(404, page("Not found", ""))


IDOR2 = {  # kind -> {object id: owner}
    "order": {"5001": "alice", "5002": "bob"},
    "doc": {
        "3f2a6c1e-8b4d-4e7a-9c11-2b5d7e9f0a13": "alice",
        "7c9e1d2b-4a6f-4b8c-8d3e-5f1a2b3c4d5e": "bob",
    },
    "address": {"12": "alice", "13": "bob"},
    "statement": {
        "5f1b2c3d4e5f60718293a4b5": "alice",
        "6a2c3d4e5f60718293a4b5c6": "bob",
    },
    "ticket": {"4401": "alice", "4402": "bob"},
    "card": {"8801": "alice", "8802": "bob"},
    "report": {"601": "alice", "602": "bob"},
}
PUBLIC_DOC = ("0b1c2d3e-4f50-4a61-8b72-93a4b5c6d7e8", "alice")
OWN2 = {
    u: {k: next(i for i, o in t.items() if o == u) for k, t in IDOR2.items()}
    for u in USERS
}


def site_idor2(path: str, a: dict, h: "Handler") -> Resp:
    v = lambda k, d="": a.get(k, d)  # noqa: E731
    user = h.user()
    nav = f"<p>Signed in as {E(mail(user))}</p>" if user else ""
    if path == "/doc-public":  # public: anyone may read it (it names its author)
        if v("doc_id") != PUBLIC_DOC[0]:
            return Resp(404, page("Document", "", nav))
        return Resp(
            body=page(
                "Document", f"<p>Public guide by {E(mail(PUBLIC_DOC[1]))}</p>", nav
            )
        )
    if not user:
        return (
            Resp(body=page("av-idor2", "<p>Please sign in at av-idor.lab.test.</p>"))
            if path == "/"
            else redirect("/")
        )
    o = OWN2[user]
    if path == "/":
        return Resp(body=page("av-idor2", links(f"/api/orders/{o['order']}", f"/download?doc_id={o['doc']}", f"/address?addr_no={o['address']}",
                                                f"/statement?account_key={o['statement']}", f"/ticket?ref={o['ticket']}",
                                                f"/api/cards/{o['card']}", f"/doc-public?doc_id={PUBLIC_DOC[0]}", f"/inbox?id={o['ticket']}",
                                                f"/report?id={o['report']}", "/folder?id=77"), nav))  # fmt: skip

    def show(kind: str, key: str, check: str) -> Resp:
        owner = IDOR2[kind].get(key)
        if owner is None or (check == "404" and owner != user):
            return Resp(404, page(kind, "<p>not found</p>", nav))
        if check == "denied" and owner != user:  # HTTP 200 with a refusal page
            return Resp(
                body=page(kind, "<p>Access denied: this is not your report.</p>", nav)
            )
        return Resp(
            body=page(
                kind,
                f"<p>{kind} {E(key)} of {E(mail(owner))}. Balance 42.00 EUR. Notes: none.</p>",
                nav,
            )
        )

    if path.startswith(
        "/api/orders/"
    ):  # VULN: JSON order by id in the path, no owner check
        owner = IDOR2["order"].get(path.rsplit("/", 1)[1])
        if owner is None:
            return Resp(404, json.dumps({"error": "not found"}), "application/json")
        return Resp(body=json.dumps({"order": path.rsplit("/", 1)[1], "owner": mail(owner), "total": "42.00 EUR"}),
                    ctype="application/json")  # fmt: skip
    if path == "/download":  # VULN: document by UUID, no owner check
        return show("doc", v("doc_id"), "none")
    if path == "/address":  # VULN: address by number, no owner check
        return show("address", v("addr_no"), "none")
    if path == "/statement":  # VULN: statement by a 24-hex key, no owner check
        return show("statement", v("account_key"), "none")
    if path == "/ticket":  # VULN: support ticket by ref, no owner check
        return show("ticket", v("ref"), "none")
    if path.startswith(
        "/api/cards/"
    ):  # owner-checked: someone else's card is "not found"
        return show("card", path.rsplit("/", 1)[1], "404")
    if path == "/inbox":  # ignores the id: always the signed-in account's inbox
        return Resp(body=page("Inbox", f"<p>Inbox of {E(mail(user))}: empty</p>", nav))
    if path == "/report":  # owner-checked with HTTP 200 and a refusal text
        return show("report", v("id"), "denied")
    if path == "/folder":  # shared between both accounts
        return Resp(
            body=page(
                "Folder",
                f"<p>Folder {E(v('id'))}: {E(mail('alice'))}, {E(mail('bob'))}</p>",
                nav,
            )
        )
    return Resp(404, page("Not found", "", nav))


SITES = {"av-xss": site_xss, "av-sqli": site_sqli, "av-redirect": site_redirect, "av-cors": site_cors,
         "av-cors-safe": site_cors_safe, "av-ssrf": site_ssrf, "av-idor": site_idor, "av-clean": site_clean,
         "av-xss2": site_xss2, "av-sqli2": site_sqli2, "av-redirect2": site_redirect2, "av-cors2": site_cors2,
         "av-cors3": site_cors3, "av-cors-safe2": site_cors_safe2, "av-ssrf2": site_ssrf2, "av-idor2": site_idor2}  # fmt: skip


class Handler(BaseHTTPRequestHandler):
    server_version = "avlab"
    sys_version = ""

    def user(self) -> str | None:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, val = part.strip().partition("=")
            if k == "sid" and val in SESSIONS:
                return SESSIONS[val]
        return None

    def form(self) -> dict:
        n = min(int(self.headers.get("Content-Length") or 0), 4096)
        return dict(
            urllib.parse.parse_qsl(self.rfile.read(n).decode("utf-8", "replace"))
        )

    def handle_any(self) -> None:
        host = (self.headers.get("Host") or "").split(":")[0].removesuffix(".lab.test")
        u = urllib.parse.urlsplit(self.path)
        args = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        site = SITES.get(host)
        r = (
            site(u.path, args, self)
            if site
            else Resp(404, "unknown site", "text/plain")
        )
        body = r.body.encode()
        self.send_response(r.status)
        self.send_header("Content-Type", r.ctype)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        for (
            k,
            val,
        ) in r.headers.items():  # no CR/LF in a header value (no response splitting)
            self.send_header(k, val.replace(chr(13), "").replace(chr(10), ""))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_HEAD = do_OPTIONS = do_PUT = do_DELETE = handle_any  # noqa: N815

    def log_message(self, fmt: str, *args) -> None:
        # the target's own access record (host, path, User-Agent): the activeproof step checks it
        # for requests the scope guard must have refused (test_corpus/active/run.sh)
        host = (self.headers.get("Host") or "-") if self.headers else "-"
        ua = (self.headers.get("User-Agent") or "-") if self.headers else "-"
        sys.stderr.write(f"avlab {host} {self.path} {ua}" + chr(10))


if __name__ == "__main__":
    ThreadingHTTPServer(
        ("0.0.0.0", int(sys.argv[1]) if len(sys.argv) > 1 else 80), Handler
    ).serve_forever()  # noqa: S104
