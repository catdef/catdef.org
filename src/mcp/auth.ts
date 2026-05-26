// Bearer-token authentication and three-tier dispatch for catdef.org/mcp.
//
// Tiers (per proposals/catdef-org-mcp-canonical-surface.md §A.6):
//   - anonymous: no Authorization header; reads spec resources + read-only tools
//   - standard:  Authorization: Bearer cdfk_<random>     — adds feedback submission + own-status read
//   - elevated:  Authorization: Bearer cdfk_dir_<random> — adds queue read + status writes + decision attachment
//
// The Director issues elevated keys out-of-band (no in-band ceremony in v0
// per CA-008's decision). Standard keys are self-serve via the issuance
// endpoint (path TBD; see issuance helper script).

import type { AuthContext, AuthTier } from "./types";

export interface AuthEnv {
  DB: D1Database;
}

const KEY_PREFIX_STANDARD = "cdfk_";
const KEY_PREFIX_ELEVATED = "cdfk_dir_";

/**
 * SHA-256 hash a string into a lowercase hex digest.
 * Keys are stored in D1 by hash so a DB leak doesn't expose live tokens.
 */
export async function hashKey(key: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Parse the Authorization header, look the key up in D1, return the effective
 * tier. Anonymous (no header) is always allowed; an Authorization header that
 * doesn't validate returns null so callers can reject with RPC_UNAUTHORIZED.
 */
export async function resolveAuth(
  request: Request,
  env: AuthEnv,
): Promise<AuthContext | null> {
  const header = request.headers.get("Authorization");
  if (!header) {
    return { tier: "anonymous" };
  }

  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  if (!match) {
    return null;
  }
  const token = match[1].trim();
  if (!token) {
    return null;
  }

  // Tier discrimination by prefix is a defense-in-depth optimization (lets us
  // skip the DB hit for obviously-malformed tokens). The DB-stored tier is the
  // source of truth.
  let expectedTier: AuthTier;
  if (token.startsWith(KEY_PREFIX_ELEVATED)) {
    expectedTier = "elevated";
  } else if (token.startsWith(KEY_PREFIX_STANDARD)) {
    expectedTier = "standard";
  } else {
    return null;
  }

  const keyHash = await hashKey(token);
  const row = await env.DB.prepare(
    "SELECT tier, revoked_at FROM api_keys WHERE key_hash = ?"
  ).bind(keyHash).first<{ tier: AuthTier; revoked_at: string | null }>();

  if (!row || row.revoked_at !== null) {
    return null;
  }

  // Cross-check stored tier with prefix; mismatch means tampering or bad data
  if (row.tier !== expectedTier) {
    return null;
  }

  // Best-effort last_used_at update; do not block on it
  // (caller can ctx.waitUntil if it cares; here we fire-and-forget)
  env.DB.prepare("UPDATE api_keys SET last_used_at = datetime('now') WHERE key_hash = ?")
    .bind(keyHash)
    .run()
    .catch(() => { /* noop */ });

  return { tier: row.tier, keyHash };
}

/**
 * Tier dominance check. Returns true when `auth` is at least `required`.
 *   elevated > standard > anonymous
 */
export function tierAtLeast(auth: AuthContext, required: AuthTier): boolean {
  const rank: Record<AuthTier, number> = { anonymous: 0, standard: 1, elevated: 2 };
  return rank[auth.tier] >= rank[required];
}

/**
 * Generate a fresh key value (not stored — caller stores the hash).
 * Format: `cdfk_<24-byte-random>` for standard, `cdfk_dir_<24-byte-random>` for elevated.
 */
export function generateKey(tier: "standard" | "elevated"): string {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const random = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
  const prefix = tier === "elevated" ? KEY_PREFIX_ELEVATED : KEY_PREFIX_STANDARD;
  return prefix + random;
}
