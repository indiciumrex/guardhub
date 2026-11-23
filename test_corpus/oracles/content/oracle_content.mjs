// Independent ground truth for content_signals' mixed-content keys (CI's header-truth job, via
// oracles/headers/run.sh). sri_missing comes from Mozilla's Observatory (oracle_headers.mjs).
//
//   node oracle_content.mjs ORIGIN [ORIGIN ...]   -> JSON on stdout: {origin: {content_keys, notes}}
//
// Chromium loads the home page (certificate errors ignored: content, not TLS, is judged here);
// the DevTools Audits domain reports each MixedContentIssue with the browser's own resolution:
//   - MixedContentBlocked                 -> mixed_content_active
//   - MixedContentAutomaticallyUpgraded,
//     MixedContentWarning                 -> mixed_content_passive
// A home page that ends on another host (cross-host redirect) is not judged: the scanner never
// follows one.
import { chromium } from 'playwright';

const browser = await chromium.launch();
const out = {};
for (const raw of process.argv.slice(2)) {
  const origin = raw.replace(/\/$/, '');
  const notes = [], keys = new Set();
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  const issues = [];
  cdp.on('Audits.issueAdded', (e) => {
    if (e.issue.code === 'MixedContentIssue') issues.push(e.issue.details.mixedContentIssueDetails);
  });
  await cdp.send('Audits.enable');
  let resp = null;
  try {
    resp = await page.goto(origin + '/', { waitUntil: 'load', timeout: 30000 });
  } catch (e) {
    notes.push(`chromium: ${e.message.split('\n')[0]}`);
  }
  await page.waitForTimeout(1500);
  if (!resp) {
    if (!notes.some((n) => n.includes('Timeout'))) notes.push(`fetch failed: ${origin}/`);
  } else {
    const final = new URL(page.url());
    notes.push(`chromium: ${origin}/ -> ${resp.status()} ${final.href}`);
    if (final.hostname !== new URL(origin).hostname) {
      notes.push('ended on another host: not judged');
    } else {
      const seen = new Set();
      for (const d of issues) {
        const k = `${d.resolutionStatus} ${d.resourceType || '-'} ${d.insecureURL}`;
        if (seen.has(k)) continue; // Chromium reports some issues twice
        seen.add(k);
        notes.push(`chromium mixed content: ${d.resolutionStatus} ${d.resourceType || '-'} ${d.insecureURL}`);
        if (d.resolutionStatus === 'MixedContentBlocked') keys.add('mixed_content_active');
        else keys.add('mixed_content_passive');
      }
    }
  }
  out[raw] = { content_keys: [...keys].sort(), notes };
  await context.close();
}
await browser.close();
console.log(JSON.stringify(out, null, 1));
