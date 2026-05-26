#!/usr/bin/env node
/**
 * issue-api-key.mjs — generate a new catdef.org/mcp api-key + emit the
 * D1 INSERT statement to register it.
 *
 * Out-of-band tool for the Director. Run locally, copy the key to the
 * recipient (out-of-band), then run the printed SQL via:
 *
 *   wrangler d1 execute catdef-feedback --remote --command="..."
 *
 * Usage:
 *   node scripts/issue-api-key.mjs --tier standard --label "thingalog plugin"
 *   node scripts/issue-api-key.mjs --tier elevated --label "catdef-strategist seat"
 *
 * The script prints THREE things:
 *   1. The plaintext key (give this to the recipient; never goes into git)
 *   2. The SHA-256 hash (this is what's stored in D1)
 *   3. The SQL INSERT statement (run against the catdef-feedback D1 database)
 *
 * After deletion (revocation), set revoked_at via:
 *   UPDATE api_keys SET revoked_at = datetime('now') WHERE key_hash = '...';
 *
 * No npm dependencies; uses built-in crypto and webcrypto.
 */

import { webcrypto } from "node:crypto";

const args = parseArgs(process.argv.slice(2));
const tier = args.tier;
const label = args.label ?? "(unlabeled)";

if (tier !== "standard" && tier !== "elevated") {
  console.error("Usage: node scripts/issue-api-key.mjs --tier (standard|elevated) [--label \"...\"]");
  process.exit(1);
}

const prefix = tier === "elevated" ? "cdfk_dir_" : "cdfk_";
const bytes = new Uint8Array(24);
webcrypto.getRandomValues(bytes);
const random = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
const key = prefix + random;

const hashBuf = await webcrypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
const hash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");

const sqlLabel = label.replace(/'/g, "''");

console.log("");
console.log("─── New catdef.org/mcp api-key ────────────────────────────");
console.log("");
console.log(`Tier:       ${tier}`);
console.log(`Label:      ${label}`);
console.log("");
console.log(`Plaintext key (give to recipient out-of-band; never commit):`);
console.log(`  ${key}`);
console.log("");
console.log(`SHA-256 hash (stored in D1):`);
console.log(`  ${hash}`);
console.log("");
console.log("Run this against the catdef-feedback D1 database:");
console.log("");
console.log(`  wrangler d1 execute catdef-feedback --remote --command="INSERT INTO api_keys (key_hash, tier, label) VALUES ('${hash}', '${tier}', '${sqlLabel}');"`);
console.log("");
console.log("To revoke later:");
console.log(`  wrangler d1 execute catdef-feedback --remote --command="UPDATE api_keys SET revoked_at = datetime('now') WHERE key_hash = '${hash}';"`);
console.log("");

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const key = argv[i].slice(2);
      out[key] = argv[i + 1];
      i++;
    }
  }
  return out;
}
