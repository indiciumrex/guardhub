// Ground truth for header_quality (ADR-0007), independent of GuardHub's Go code:
//  - csp_unsafe_eval, csp_object_src_unrestricted: Mozilla's HTTP Observatory scanner
//    (@mdn/mdn-http-observatory, policy.unsafeEval / policy.unsafeObjects)
//  - csp_base_uri_missing: Google's CSP Evaluator (checkMultipleMissingBaseUriDirective)
//  - permissions_policy_missing, coop_missing, cookie_response_cacheable: the response headers
//    as fetched here (presence; RFC 9111 shared-cache directives)
// Ground truth for cookie_depth (cookie_keys), from tough-cookie (the RFC 6265bis cookie jar
// Observatory uses): cookie_prefix_invalid = the jar refuses the cookie for its __Secure-/__Host-
// prefix (prefixSecurity "strict"); cookie_domain_too_broad = a session-named cookie the jar
// stores as NOT host-only (a Domain attribute it accepted). Session names: sess, sid, auth,
// token, login, never csrf/xsrf (docs/checks/cookie_depth.md).
// usage (lab network): node oracle_headers.mjs origin [origin ...]  -> JSON on stdout
import { scan } from "@mdn/mdn-http-observatory";
import { CspParser } from "csp_evaluator/dist/parser.js";
import { checkMultipleMissingBaseUriDirective } from "csp_evaluator/dist/checks/security_checks.js";
import { CookieJar, Cookie } from "tough-cookie";

function sessionName(name) {
  const n = name.toLowerCase();
  if (n.includes("csrf") || n.includes("xsrf")) return false;
  return ["sess", "sid", "auth", "token", "login"].some((h) => n.includes(h));
}

function cookieTruth(h, url, notes) {
  const keys = [];
  const seen = new Set();
  for (const raw of h.getSetCookie ? h.getSetCookie() : []) {
    const c = Cookie.parse(raw);
    if (!c || seen.has(c.key)) continue;
    seen.add(c.key);
    const jar = new CookieJar(undefined, { prefixSecurity: "strict" });
    try {
      jar.setCookieSync(raw, url.toString());
    } catch (e) {
      notes.push(`tough-cookie refused ${c.key}: ${e.message}`);
      if (/prefix/i.test(e.message)) keys.push(`cookie_prefix_invalid:${c.key}`);
      continue;
    }
    const stored = jar.getCookiesSync(url.toString(), { allPaths: true }).find((x) => x.key === c.key);
    notes.push(`tough-cookie stored ${c.key}: domain=${stored?.domain} hostOnly=${stored?.hostOnly}`);
    if (stored && stored.hostOnly === false && sessionName(c.key)) keys.push(`cookie_domain_too_broad:${c.key}`);
  }
  return keys;
}

async function fetchRoot(origin) {
  let url = new URL("/", origin);
  for (let i = 0; i < 10; i++) {
    const r = await fetch(url, { redirect: "manual", headers: { "User-Agent": "guardhub-lab-oracle" } });
    if (r.status >= 300 && r.status < 400 && r.headers.get("location")) {
      const next = new URL(r.headers.get("location"), url);
      if (next.hostname !== url.hostname) return { r, body: "", url, refused: true };
      url = next;
      continue;
    }
    return { r, body: await r.text(), url, refused: false };
  }
  throw new Error("too many redirects");
}

function isDocument(r, body) {
  const ct = (r.headers.get("content-type") || "").toLowerCase();
  if (ct.includes("html")) return true;
  return ct === "" && /<!doctype html|<html[\s>]|<head[\s>]|<body[\s>]/i.test(body.slice(0, 2048));
}

function metaCsps(body) {
  const out = [];
  const head = body.slice(0, 64 * 1024);
  for (const tag of head.match(/<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gis) || []) {
    const m = tag.match(/\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')/is);
    if (m && (m[1] || m[2] || "").trim()) out.push((m[1] || m[2]).replace(/&#39;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&"));
  }
  return out;
}

function cacheableCookie(h) {
  const sc = h.getSetCookie ? h.getSetCookie() : [];
  if (!sc.length) return null;
  const cc = (h.get("cache-control") || "").toLowerCase();
  const dirs = cc.split(",").map((d) => d.trim()).filter(Boolean);
  let pub = false, shared = false, priv = false;
  for (const d of dirs) {
    const [k, v] = d.split("=").map((x) => x.trim().replace(/"/g, ""));
    if (k === "public") pub = true;
    if ((k === "max-age" || k === "s-maxage") && Number(v) > 0) shared = true;
    if (["private", "no-store", "no-cache"].includes(k)) priv = true;
  }
  if (priv || !(pub || shared)) return null;
  return sc[0].split("=")[0].trim();
}

const result = {};
for (const origin of process.argv.slice(2)) {
  const target = { keys: [], cookie_keys: [], notes: [] };
  result[origin] = target;
  try {
    const { r, body, url, refused } = await fetchRoot(origin);
    const doc = !refused && isDocument(r, body);
    target.notes.push(`fetched ${url} -> ${r.status} ${r.headers.get("content-type") || "-"} document=${doc}`);
    if (doc) {
      const headerCsps = (r.headers.get("content-security-policy") || "").split(",").map((s) => s.trim()).filter(Boolean);
      const metas = metaCsps(body);
      const all = [...headerCsps, ...metas];
      if (all.length) {
        const u = new URL(origin);
        const opts = u.protocol === "https:" ? { httpsPort: u.port || undefined } : { httpPort: u.port || undefined };
        try {
          const obs = await scan(u.hostname, opts);
          const csp = obs.tests["content-security-policy"];
          target.notes.push(`observatory csp: ${csp.result} unsafeEval=${csp.policy?.unsafeEval} unsafeObjects=${csp.policy?.unsafeObjects}`);
          if (csp.policy?.unsafeEval) target.keys.push("csp_unsafe_eval");
          if (csp.policy?.unsafeObjects) target.keys.push("csp_object_src_unrestricted");
        } catch (e) {
          target.notes.push(`observatory failed: ${e.message}`);
        }
        const parsed = all.map((p) => new CspParser(p).csp);
        if (checkMultipleMissingBaseUriDirective(parsed).length) target.keys.push("csp_base_uri_missing");
      }
      if (!(r.headers.get("permissions-policy") || "").trim()) target.keys.push("permissions_policy_missing");
      if (!(r.headers.get("cross-origin-opener-policy") || "").trim()) target.keys.push("coop_missing");
    }
    target.cookie_keys = cookieTruth(r.headers, url, target.notes);
    const ck = cacheableCookie(r.headers);
    if (ck) target.keys.push(`cookie_response_cacheable:${ck}`);
  } catch (e) {
    target.notes.push(`fetch failed: ${e.message}`);
  }
}
console.log(JSON.stringify(result, null, 1));
