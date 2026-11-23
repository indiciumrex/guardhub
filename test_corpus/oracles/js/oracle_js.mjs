// Independent ground truth for js_libraries (CI's header-truth job, via oracles/headers/run.sh).
//
//   node oracle_js.mjs ORIGIN [ORIGIN ...]   -> JSON on stdout: {origin: {js_keys, notes}}
//
// Nothing here shares code with the scanner:
//   - the home page is fetched with Node's fetch (at most 3 same-host redirects, the documented
//     rule) and its <script src> tags are read with htmlparser2;
//   - a same-origin script is fetched and judged by its CONTENT only: retire.js's
//     scanFileContent (its banner, replacement and hash matchers), never by its file name;
//   - a cross-origin script is never fetched: retire.js's scanUri judges its URL;
//   - "vulnerable" is retire.js's verdict from its pinned repository (Dockerfile).
// A library counts once per (component, version), at the first script that shows it.
// Key: "vulnerable_js_library:<script URL>".
import { createRequire } from 'node:module';
import crypto from 'node:crypto';
import { Parser } from 'htmlparser2';

const require = createRequire(import.meta.url);
const retire = require('retire/lib/retire.js');
const repoLoader = require('retire/lib/repo.js');
const repo = await repoLoader.loadrepositoryFromFile('/o/jsrepository.json', { log: { debug() {}, info() {}, warn: console.error, error: console.error } });
const hasher = { sha1: (d) => crypto.createHash('sha1').update(d).digest('hex') };

function sameHostHop(from, to) {
  const a = new URL(from), b = new URL(to);
  if (!['http:', 'https:'].includes(b.protocol) || a.hostname.toLowerCase() !== b.hostname.toLowerCase()) return false;
  if (a.protocol === 'https:' && b.protocol === 'http:') return false;
  const port = (u) => u.port || (u.protocol === 'https:' ? '443' : '80');
  if (a.protocol === b.protocol) return port(a) === port(b);
  return b.port === '' || b.port === '443' || b.port === a.port;
}

async function get(url) {
  for (let i = 0; i < 4; i++) {
    let r;
    try {
      r = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(15000) });
    } catch (e) {
      return { status: 0, url, body: '', error: String(e.cause?.code || e.message) };
    }
    const loc = r.headers.get('location');
    if ([301, 302, 303, 307, 308].includes(r.status) && loc) {
      const next = new URL(loc, url).href;
      if (sameHostHop(url, next)) { url = next; continue; }
    }
    return { status: r.status, url, body: await r.text() };
  }
  return { status: 0, url, body: '', error: 'too many redirects' };
}

function scripts(html) {
  const out = [];
  const p = new Parser({ onopentag(name, attrs) { if (name === 'script' && attrs.src) out.push(attrs.src); } });
  p.write(html); p.end();
  return out;
}

async function truth(origin) {
  const notes = [], keys = [], seen = new Set();
  const root = await get(origin + '/');
  if (root.status === 0) return { js_keys: [], notes: [`fetch failed: ${origin}/ (${root.error})`] };
  notes.push(`GET / -> ${root.status}` + (root.url !== origin + '/' ? ` (after same-host redirects: ${new URL(root.url).pathname})` : ''));
  if (root.status !== 200) return { js_keys: [], notes };
  const base = new URL(root.url);
  for (const src of scripts(root.body)) {
    let u;
    try { u = new URL(src.trim(), base); } catch { continue; }
    if (!['http:', 'https:'].includes(u.protocol)) continue;
    u.hash = '';
    let results;
    if (u.protocol === base.protocol && u.host.toLowerCase() === base.host.toLowerCase()) {
      const r = await get(u.href);
      if (r.status !== 200) { notes.push(`${u.pathname}: HTTP ${r.status}`); continue; }
      results = retire.scanFileContent(r.body, repo, hasher);
    } else {
      results = retire.scanUri(u.href, repo);
    }
    for (const c of results) {
      const vulns = (c.vulnerabilities || []).map((v) => (v.identifiers?.CVE || [])[0] || v.identifiers?.githubID || v.identifiers?.summary || 'unnamed');
      notes.push(`${u.href}: retire.js ${c.component} ${c.version} (${c.detection}), ${vulns.length} vulnerabilities${vulns.length ? ': ' + [...new Set(vulns)].slice(0, 6).join(', ') : ''}`);
      const k = `${c.component}@${c.version}`;
      if (vulns.length && !seen.has(k)) {
        seen.add(k);
        keys.push(`vulnerable_js_library:${u.href}`);
      }
    }
  }
  return { js_keys: [...new Set(keys)].sort(), notes };
}

const out = {};
for (const o of process.argv.slice(2)) out[o] = await truth(o.replace(/\/$/, ''));
console.log(JSON.stringify(out, null, 1));
