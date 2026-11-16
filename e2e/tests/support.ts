/** Test support: RFC 6238 TOTP, the demo target's ownership file, and the operator CLI. */
import { createHmac } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const COMPOSE = ["compose", "-f", "docker-compose.yml", "-f", "docker-compose.demo.yml"];

/** The only target these journeys ever scan: the bundled, deliberately vulnerable demo site. */
export const DEMO_TARGET = "http://demo-target:8080";
/** The fake Stripe key planted in ops/demo-target/site/.env; it must never reach the browser unmasked. */
export const DEMO_RAW_SECRET = (() => {
  const env = readFileSync(resolve(ROOT, "ops/demo-target/site/.env"), "utf8");
  const value = /^STRIPE_SECRET_KEY=(.+)$/m.exec(env)?.[1]?.trim();
  if (!value) throw new Error("demo .env has no STRIPE_SECRET_KEY");
  return value;
})();

function base32Decode(input: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of input.replace(/=+$/, "").toUpperCase()) {
    const v = alphabet.indexOf(ch);
    if (v < 0) throw new Error(`bad base32 character ${ch}`);
    bits += v.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

export function totp(secret: string, at = Date.now()): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const mac = createHmac("sha1", base32Decode(secret.replace(/\s+/g, "")))
    .update(counter)
    .digest();
  const offset = mac[mac.length - 1] & 0xf;
  const code = (mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return code.toString().padStart(6, "0");
}

/** Waits until a new 30 s TOTP step starts (the API rejects a replayed code, as it should). */
export async function nextTotpWindow(): Promise<void> {
  const ms = 30_000 - (Date.now() % 30_000) + 500;
  await new Promise((r) => setTimeout(r, ms));
}

/** Plays the site owner: publishes the token at /.well-known/guardhub-verify.txt on the demo site. */
export function publishOwnershipToken(token: string): void {
  const file = resolve(ROOT, "ops/demo-target/site/.well-known/guardhub-verify.txt");
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${token}\n`, "utf8");
}

export function removeOwnershipToken(): void {
  publishOwnershipToken("");
}

/** Runs a command in a compose service, as an operator with shell access would. */
export function composeExec(service: string, args: string[]): string {
  return execFileSync("docker", [...COMPOSE, "exec", "-T", service, ...args], {
    cwd: ROOT,
    encoding: "utf8",
  });
}

/** Local stack only: clear rate-limit windows so repeated runs from one IP don't trip them. */
export function resetLocalRateLimits(): void {
  composeExec("redis", [
    "sh",
    "-c",
    'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning --scan --pattern "gh:rl:*" | xargs -r redis-cli -a "$REDIS_PASSWORD" --no-auth-warning del',
  ]);
}
