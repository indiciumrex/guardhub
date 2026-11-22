// Wait until every origin answers "/" with a status below 500 (an app still starting
// answers 502/503 or not at all), then for its answer to stay the same for 10 s.
// usage: node wait.mjs [--soft] origin [origin ...]
// Each origin gets 300 s (exit 1), or 60 s with --soft (warn and go on: a target whose TLS
// Node cannot speak at all is then reported by the oracle as not fetched).
const args = process.argv.slice(2);
const soft = args[0] === "--soft";
if (soft) args.shift();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function status(origin) {
  try {
    const r = await fetch(new URL("/", origin), { redirect: "manual", signal: AbortSignal.timeout(5000) });
    await r.arrayBuffer();
    return r.status;
  } catch {
    return 0;
  }
}

for (const origin of args) {
  const deadline = Date.now() + (soft ? 60_000 : 300_000);
  let last = -1;
  let stableSince = 0;
  for (;;) {
    const s = await status(origin);
    if (s > 0 && s < 500) {
      if (s !== last) {
        last = s;
        stableSince = Date.now();
      } else if (Date.now() - stableSince >= 10_000) {
        console.error(`ready: ${origin} (${s})`);
        break;
      }
    } else {
      last = -1;
    }
    if (Date.now() > deadline) {
      console.error(`never ready: ${origin} (last status ${s})`);
      if (!soft) process.exit(1);
      break;
    }
    await sleep(2000);
  }
}
