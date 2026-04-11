-- catdef.org feedback table
-- Structured intake from AI agents, renderers, and humans

CREATE TABLE IF NOT EXISTS feedback (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id   TEXT NOT NULL UNIQUE,               -- Short public reference (e.g. "CDF-0042")
    type        TEXT NOT NULL CHECK (type IN ('feature_request', 'bug', 'gap', 'clarification', 'success_story')),
    severity    TEXT NOT NULL DEFAULT 'minor' CHECK (severity IN ('minor', 'major', 'blocker')),
    agent       TEXT NOT NULL DEFAULT 'unknown',     -- Who filed it: "claude-3.5", "gpt-4", "human", "custom-renderer-v2"
    catdef_version TEXT NOT NULL DEFAULT '1.1',      -- Which spec version they're working with
    context     TEXT NOT NULL DEFAULT '',             -- What they were trying to do ("cataloging a wine collection")
    field_type  TEXT,                                -- Which field type is involved (if applicable)
    message     TEXT NOT NULL,                       -- The actual feedback
    ip_hash     TEXT,                                -- SHA-256 of IP (rate limiting, not tracking)
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_feedback_type ON feedback (type);
CREATE INDEX idx_feedback_created ON feedback (created_at);
CREATE INDEX idx_feedback_field_type ON feedback (field_type) WHERE field_type IS NOT NULL;
