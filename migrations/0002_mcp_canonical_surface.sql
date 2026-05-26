-- catdef.org/mcp canonical surface migration
-- Per decisions/CA-008.md (Track D) and decisions/CA-009.md (CA-NNN unification)
--
-- Adds:
--   1. status / public / decision_id / updated_at / api_key_hash columns on feedback
--   2. api_keys table for standard and elevated tier bearer tokens
--   3. meta key-value table for the CA-NNN counter source-of-truth
--
-- The existing feedback table is preserved; legacy CDF-NNNN rows remain queryable.
-- New rows get CA-NNN public_ids per CA-009.

-- ── Extend feedback table ────────────────────────────────────

ALTER TABLE feedback ADD COLUMN status TEXT NOT NULL DEFAULT 'received'
    CHECK (status IN ('received', 'triaged', 'drafted', 'decided', 'shipped', 'rejected'));

ALTER TABLE feedback ADD COLUMN public BOOLEAN NOT NULL DEFAULT 0;

ALTER TABLE feedback ADD COLUMN decision_id TEXT;

ALTER TABLE feedback ADD COLUMN updated_at TEXT;

ALTER TABLE feedback ADD COLUMN api_key_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback (status);
CREATE INDEX IF NOT EXISTS idx_feedback_api_key ON feedback (api_key_hash) WHERE api_key_hash IS NOT NULL;

-- ── api_keys table ──────────────────────────────────────────

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash      TEXT PRIMARY KEY,                                -- SHA-256 of the bearer token
    tier          TEXT NOT NULL CHECK (tier IN ('standard', 'elevated')),
    label         TEXT,                                            -- Human-readable identifier (e.g. "catdef-strategist seat key")
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at  TEXT,
    revoked_at    TEXT                                             -- Soft-delete; queries filter WHERE revoked_at IS NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tier_active ON api_keys (tier) WHERE revoked_at IS NULL;

-- ── meta table for CA-NNN counter and other server state ────

CREATE TABLE IF NOT EXISTS meta (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seed the CA-NNN counter at 10 — CA-001 through CA-010 already exist in
-- decisions/. Next allocated id is CA-011. The admin endpoint
-- POST /mcp/admin/refresh-counter (elevated tier) re-syncs against the
-- live decisions/ directory if a manually-filed CA-NNN lands.
INSERT OR IGNORE INTO meta (key, value) VALUES ('ca_nnn_counter', '10');
