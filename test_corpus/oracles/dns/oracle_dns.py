"""Independent ground truth for dns_depth on every lab site target, then a comparison with the
manifests (CI's dns-truth job).

    python3 oracle_dns.py MANIFEST_DIR OUT_DIR

Nothing here shares code with the scanner. The DNS data comes from BIND's dig, DNSSEC validation
from BIND's delv (with the parent's DS records as the only trust anchor), DKIM key sizes from
OpenSSL, and the MTA-STS policy from curl (lab CA, no redirects). This script only applies the
published rules (RFC 8659 CAA, RFC 8461 MTA-STS, RFC 8460 TLS-RPT, RFC 7672 DANE, RFC 8301 DKIM
key sizes) to what those tools return. The DKIM selectors probed are the scanner's documented
list (docs/checks/dns_depth.md), since the truth is per selector.

A lookup that fails (SERVFAIL, timeout) yields no key, as it does in the scanner, and is listed
in the notes. A target whose every lookup failed is reported as "no DNS data" (all its names are
Docker-served lab hosts outside the lab zones). It counts as agreeing only because neither side
may derive a finding from it, and the summary lists it separately.

Writes OUT_DIR/summary.md and OUT_DIR/summary.json. Exit 1 on any mismatch.
"""

from __future__ import annotations

import base64
import glob
import json
import os
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlparse

import yaml

RESOLVER = os.environ.get("DNS_ORACLE_RESOLVER", "dns-res.lab.test")
CA = os.environ.get("DNS_ORACLE_CA", "/pki/ca.pem")
CHECK = "dns_depth"
SELECTORS = ["default", "dkim", "google", "k1", "k2", "mail", "resend", "s1", "s2", "selector1", "selector2", "smtp"]


class Dig:
    def __init__(self) -> None:
        self.asked = 0
        self.answered = 0
        self.notes: list[str] = []

    def q(self, name: str, qtype: str, cd: bool = False) -> tuple[str, list[list[str]]]:
        """(status, answer records as token lists) from dig; status UNKNOWN on failure."""
        self.asked += 1
        args = [
            "dig",
            "+tries=1",
            "+time=3",
            "+dnssec",
            "+noall",
            "+answer",
            "+authority",
            "+comments",
            f"@{RESOLVER}",
            name,
            qtype,
        ]
        if cd:
            args.insert(1, "+cd")
        try:
            out = subprocess.run(args, capture_output=True, text=True, timeout=15).stdout
        except subprocess.TimeoutExpired:
            return "UNKNOWN", []
        m = re.search(r"status: (\w+)", out)
        status = m.group(1) if m else "UNKNOWN"
        if status in ("NOERROR", "NXDOMAIN"):
            self.answered += 1
        else:
            self.notes.append(f"{name} {qtype}: {status}")
            return "UNKNOWN", []
        section, recs = "", []
        for line in out.splitlines():
            if line.startswith(";; ANSWER SECTION"):
                section = "answer"
            elif line.startswith(";; AUTHORITY SECTION"):
                section = "authority"
            elif line and not line.startswith(";"):
                parts = line.split()
                recs.append([section] + parts)
        return status, recs


def rr(recs: list[list[str]], rtype: str, owner: str | None = None, section: str = "answer") -> list[list[str]]:
    out = []
    for r in recs:
        if r[0] == section and len(r) > 4 and r[4] == rtype and (owner is None or r[1].rstrip(".").lower() == owner):
            out.append(r[5:])
    return out


def txt_strings(fields: list[str]) -> str:
    """The TXT record's strings joined without a separator (as dig prints them quoted)."""
    return "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', " ".join(fields)))


def zone_of(d: Dig, name: str) -> str:
    for _ in range(2):
        st, recs = d.q(name, "SOA", cd=True)
        if st == "UNKNOWN":
            return ""
        if rr(recs, "SOA", name):
            return name
        if rr(recs, "CNAME", name):
            parts = name.split(".", 1)
            if len(parts) < 2 or "." not in parts[1]:
                return ""
            name = parts[1]
            continue
        for r in recs:
            if r[0] == "authority" and len(r) > 4 and r[4] == "SOA":
                return r[1].rstrip(".").lower()
        return ""
    return ""


def dnssec_broken(d: Dig, zone: str, notes: list[str]) -> bool:
    st, recs = d.q(zone, "DS", cd=True)
    ds = rr(recs, "DS", zone)
    if st == "UNKNOWN" or not ds:
        notes.append(
            f"DNSSEC {zone}: no DS at the parent (unsigned)" if st != "UNKNOWN" else f"DNSSEC {zone}: DS lookup failed"
        )
        return False
    anchors = "".join(f'  "{zone}." static-ds {f[0]} {f[1]} {f[2]} "{"".join(f[3:])}";\n' for f in ds)
    with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as fh:
        fh.write("trust-anchors {\n" + anchors + "};\n")
        path = fh.name
    try:
        out = subprocess.run(
            ["delv", f"@{RESOLVER}", "-a", path, f"+root={zone}", zone, "SOA"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        os.unlink(path)
    text = (out.stdout + out.stderr).strip()
    first = next((ln for ln in text.splitlines() if ln.startswith(";")), text[:120])
    notes.append(f"delv {zone} (anchor = parent DS): {first}")
    return "fully validated" not in text


def registrable(host: str) -> str:
    # ".test" is not on the Public Suffix List: the default rule makes the last two labels the
    # registrable domain (lab.test), as the scanner's publicsuffix library does.
    return ".".join(host.split(".")[-2:])


def caa_missing(d: Dig, host: str, notes: list[str]) -> bool:
    reg, name, checked = registrable(host), host, []
    while True:
        st, recs = d.q(name, "CAA")
        if st == "UNKNOWN":
            notes.append(f"CAA {name}: lookup failed, nothing derivable")
            return False
        checked.append(name)
        if rr(recs, "CAA"):
            notes.append(f"CAA found at {name}")
            return False
        if name == reg or "." not in name:
            break
        name = name.split(".", 1)[1]
    notes.append("CAA: none at " + ", ".join(checked))
    return True


def mta_sts_record(txts: list[str]) -> str:
    sts = [t for t in txts if t.startswith("v=STSv1;") or t == "v=STSv1"]
    if len(sts) != 1:
        return ""
    for field in sts[0].split(";"):
        k, _, v = field.strip().partition("=")
        if k == "id" and re.fullmatch(r"[A-Za-z0-9]{1,32}", v):
            return sts[0]
    return ""


def fetch_policy(host: str, notes: list[str]) -> tuple[str, dict | None]:
    url = f"https://mta-sts.{host}/.well-known/mta-sts.txt"
    out = subprocess.run(
        [
            "curl",
            "-sS",
            "--max-time",
            "10",
            "--max-redirs",
            "0",
            "--cacert",
            CA,
            "-w",
            "\n%{http_code} %{content_type}",
            url,
        ],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        notes.append(f"curl {url}: {out.stderr.strip()[:120]}")
        return "unreachable", None
    body, _, meta = out.stdout.rpartition("\n")
    code, _, ctype = meta.partition(" ")
    notes.append(f"curl {url}: HTTP {code} {ctype}")
    if code != "200":
        return "http_status", None
    if ctype.split(";")[0].strip().lower() != "text/plain":
        return "content_type", None
    fields, mx = {}, []
    for line in body.replace("\r\n", "\n").split("\n"):
        k, sep, v = line.partition(":")
        if not sep:
            continue
        k, v = k.strip(), v.strip()
        if k == "mx":
            mx.append(v.lower().rstrip("."))
        else:
            fields.setdefault(k, v)
    ok = (
        fields.get("version") == "STSv1"
        and fields.get("mode") in ("enforce", "testing", "none")
        and fields.get("max_age", "").isdigit()
        and 0 <= int(fields["max_age"]) <= 31557600
        and (fields.get("mode") == "none" or mx)
    )
    if not ok:
        return "policy_invalid", None
    return "", {"mode": fields["mode"], "mx": mx}


def mx_covered(mx: str, patterns: list[str]) -> bool:
    for p in patterns:
        if p.startswith("*."):
            label, _, rest = mx.partition(".")
            if label and rest == p[2:]:
                return True
        elif p == mx:
            return True
    return False


def rsa_bits(p: str) -> int | None:
    try:
        der = base64.b64decode(p, validate=True)
    except Exception:  # noqa: BLE001 - not base64: not a key
        return None
    for args in (
        ["openssl", "pkey", "-pubin", "-inform", "DER", "-text", "-noout"],
        ["openssl", "rsa", "-RSAPublicKey_in", "-inform", "DER", "-text", "-noout"],
    ):
        out = subprocess.run(args, input=der, capture_output=True)
        m = re.search(rb"Public-Key: \((\d+) bit\)", out.stdout)
        if out.returncode == 0 and m and b"Modulus:" in out.stdout:  # an RSA key
            return int(m.group(1))
    return None


def dkim_keys(d: Dig, host: str, notes: list[str]) -> set[str]:
    keys, seen = set(), set()
    for sel in SELECTORS:
        name = f"{sel}._domainkey.{host}"
        st, recs = d.q(name, "TXT")
        if st != "NOERROR":
            continue
        for fields in rr(recs, "TXT", name):
            rec = txt_strings(fields)
            tags = {}
            for f in rec.split(";"):
                k, sep, v = f.partition("=")
                if sep:
                    tags[k.strip()] = "".join(v.split())
            if tags.get("v", "DKIM1") != "DKIM1" or tags.get("k", "rsa").lower() != "rsa" or not tags.get("p"):
                continue
            if tags["p"] in seen:
                continue
            seen.add(tags["p"])
            bits = rsa_bits(tags["p"])
            notes.append(f"DKIM {name}: " + (f"RSA {bits} bits (OpenSSL)" if bits else "not an RSA key OpenSSL reads"))
            if bits and bits < 1024:
                keys.add("dkim_key_too_short")
            elif bits and bits < 2048:
                keys.add("dkim_weak_key")
    return keys


def truth(host: str) -> tuple[set[str], list[str], bool]:
    d, keys, notes = Dig(), set(), []
    zone = zone_of(d, host)
    if zone and dnssec_broken(d, zone, notes):
        keys.add("dnssec_broken")
    if caa_missing(d, host, notes):
        keys.add("caa_missing")
    st, recs = d.q(host, "MX")
    mxs = [f[1].rstrip(".").lower() for f in rr(recs, "MX", host)]
    if st == "NOERROR" and mxs and mxs != [""]:
        notes.append("MX: " + ", ".join(mxs))
        st, recs = d.q(f"_mta-sts.{host}", "TXT")
        if st != "UNKNOWN":
            record = mta_sts_record([txt_strings(f) for f in rr(recs, "TXT", f"_mta-sts.{host}")])
            if not record:
                keys.add("mta_sts_missing")
                notes.append("_mta-sts: no single valid v=STSv1 record")
            else:
                reason, pol = fetch_policy(host, notes)
                if reason:
                    keys.add("mta_sts_policy_broken")
                elif pol["mode"] == "testing":
                    keys.add("mta_sts_testing")
                elif pol["mode"] == "enforce" and any(not mx_covered(m, pol["mx"]) for m in mxs):
                    keys.add("mta_sts_mx_mismatch")
                st, recs = d.q(f"_smtp._tls.{host}", "TXT")
                rpt = [txt_strings(f) for f in rr(recs, "TXT", f"_smtp._tls.{host}")]
                if st != "UNKNOWN" and not any(t.startswith("v=TLSRPTv1;") or t == "v=TLSRPTv1" for t in rpt):
                    keys.add("tlsrpt_missing")
        for mx in mxs[:4]:
            st, recs = d.q(f"_25._tcp.{mx}", "TLSA", cd=True)
            if st != "NOERROR" or not rr(recs, "TLSA", f"_25._tcp.{mx}"):
                continue
            z = zone_of(d, mx)
            if not z:
                continue
            st, recs = d.q(z, "DS", cd=True)
            if st != "UNKNOWN" and not rr(recs, "DS", z):
                keys.add("dane_unsigned")
                notes.append(f"TLSA at _25._tcp.{mx}, zone {z} has no DS")
    elif st == "NOERROR":
        notes.append("MX: none or null MX (no mail-transport rules)")
    keys |= dkim_keys(d, host, notes)
    notes.extend(d.notes[:6])
    return keys, notes, d.answered == 0


def expected(manifest: dict) -> set[str]:
    return {e["key"] for e in manifest.get("expect") or [] if e.get("check") == CHECK}


def main() -> int:
    mdir, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    rows = []
    for path in sorted(glob.glob(os.path.join(mdir, "*.yaml"))):
        with open(path, encoding="utf-8") as f:
            m = yaml.safe_load(f)
        if CHECK not in (m.get("checks") or []):
            continue
        host = (urlparse(m["origin"]).hostname or "").lower()
        got, notes, nodata = truth(host)
        want = expected(m)
        status = "MISMATCH" if got != want else ("ok (no DNS data)" if nodata else "ok")
        rows.append(
            {
                "target": m["target"],
                "host": host,
                "status": status,
                "oracle": sorted(got),
                "manifest": sorted(want),
                "notes": notes,
            }
        )
        print(f"{m['target']:<22} {status:<16} {','.join(sorted(got)) or '-'}", flush=True)
    bad = [r for r in rows if r["status"] == "MISMATCH"]
    nodata = [r for r in rows if r["status"] == "ok (no DNS data)"]
    lines = [
        "# dns_depth ground truth vs manifests",
        "",
        f"{len(rows)} targets, {len(rows) - len(bad)} agree, {len(bad)} do not. "
        f"{len(nodata)} of the agreeing targets have no DNS data (Docker-served names, every lookup failed): "
        "nothing can be derived there, by the oracle or the scanner.",
        "",
        "| Target | Status | Oracle keys | Manifest keys |",
        "|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| `{r['target']}` | {r['status']} | {', '.join(r['oracle']) or '-'} | {', '.join(r['manifest']) or '-'} |"
        )
    lines += ["", "## Oracle notes", ""]
    for r in rows:
        lines.append(f"- `{r['target']}` ({r['host']}): " + " · ".join(r["notes"]))
    text = "\n".join(lines) + "\n"
    with open(os.path.join(out, "summary.md"), "w", encoding="utf-8") as f:
        f.write(text)
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=1)
    print(f"\n{len(rows)} targets, {len(bad)} mismatches")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
