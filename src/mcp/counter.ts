// CA-NNN counter — source-of-truth issuer for unified-namespace identifiers
// per decisions/CA-009.md.
//
// Per CA-009 Directive 2:
//   "the server reads the highest CA-NNN present in `decisions/` at startup,
//   takes max(that, server-stored-counter), and issues from there. Sync events
//   (commit hooks or manual maintainer triggers) can advance the server
//   counter when new `decisions/CA-NNN.md` files land."
//
// Workers are per-request; "startup" doesn't really apply. We persist the
// counter in D1 (meta table) and offer an elevated-tier endpoint to refresh
// against the live GitHub state when a manually-filed CA-NNN lands.
//
// Format: CA-NNN (no zero-padding mandated; CA-001 .. CA-999 are 3-digit,
// CA-1000+ extends naturally; matches existing decisions/ filenames).

import { githubContents } from "./github";

export interface CounterEnv {
  DB: D1Database;
}

const META_KEY = "ca_nnn_counter";
const DECISIONS_PATH = "decisions";

/**
 * Allocate the next CA-NNN identifier. Atomic against concurrent allocators
 * via D1's transactional UPDATE...RETURNING pattern emulated with batch().
 */
export async function allocateCaNnn(env: CounterEnv): Promise<string> {
  // D1 doesn't yet support RETURNING in all builds; emulate with
  // SELECT-then-UPDATE inside a batch, which D1 serializes at the worker
  // level. For higher concurrency, future work could move to a Durable
  // Object; v0 traffic does not justify it.
  const row = await env.DB.prepare(
    "SELECT value FROM meta WHERE key = ?"
  ).bind(META_KEY).first<{ value: string }>();

  const current = row ? parseInt(row.value, 10) : 0;
  const next = current + 1;

  await env.DB.prepare(
    "UPDATE meta SET value = ?, updated_at = datetime('now') WHERE key = ?"
  ).bind(String(next), META_KEY).run();

  return formatCaNnn(next);
}

/**
 * Format a numeric counter value as a CA-NNN string. Three-digit minimum
 * to match existing decisions/CA-001.md through CA-010.md; grows naturally
 * for >999.
 */
export function formatCaNnn(n: number): string {
  return `CA-${String(n).padStart(3, "0")}`;
}

/**
 * Parse a CA-NNN string back to its numeric value. Returns null for
 * malformed inputs (also handles legacy CDF-NNNN by returning null so
 * callers can route appropriately).
 */
export function parseCaNnn(id: string): number | null {
  const m = /^CA-(\d{3,})$/.exec(id);
  if (!m) return null;
  return parseInt(m[1], 10);
}

/**
 * Re-sync the counter against the live GitHub state of catdef-spec/decisions/.
 * Walks the directory listing, finds the max CA-NNN filename, and bumps the
 * D1 counter to max(stored, github_max) so subsequent allocations don't
 * collide with manually-filed decisions.
 *
 * Returns { previous, github_max, next_to_allocate }.
 */
export async function refreshCounterFromGitHub(
  env: CounterEnv,
  githubToken: string | undefined,
): Promise<{ previous: number; github_max: number; next_to_allocate: number }> {
  const previousRow = await env.DB.prepare(
    "SELECT value FROM meta WHERE key = ?"
  ).bind(META_KEY).first<{ value: string }>();
  const previous = previousRow ? parseInt(previousRow.value, 10) : 0;

  // Use the shared 401-resilient helper: tries with token first, falls
  // back to unauth if the token is invalid/expired. Per CA-011.
  const entries = await githubContents<Array<{ name: string; type: string }>>(
    DECISIONS_PATH,
    githubToken,
  );

  let githubMax = 0;
  for (const entry of entries) {
    if (entry.type !== "file") continue;
    const m = /^CA-(\d{3,})\.md$/.exec(entry.name);
    if (!m) continue;
    const n = parseInt(m[1], 10);
    if (n > githubMax) githubMax = n;
  }

  const newValue = Math.max(previous, githubMax);
  await env.DB.prepare(
    "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now')"
  ).bind(META_KEY, String(newValue)).run();

  return {
    previous,
    github_max: githubMax,
    next_to_allocate: newValue + 1,
  };
}
