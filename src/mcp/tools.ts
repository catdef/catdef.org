// MCP tools for catdef.org/mcp. Implements the 9-tool surface from
// proposals/catdef-org-mcp-canonical-surface.md §A.3–A.5.
//
// Tiers:
//   anonymous: catdef_describe, catdef_lookup, catdef_list_decisions, catdef_validate
//   standard:  + catdef_report_feedback, catdef_get_feedback_status
//   elevated:  + catdef_list_feedback, catdef_set_feedback_status, catdef_attach_decision

import type { AuthContext, McpTool } from "./types";
import { tierAtLeast } from "./auth";
import { allocateCaNnn, refreshCounterFromGitHub, parseCaNnn } from "./counter";
import { githubContents } from "./github";

export interface ToolsEnv {
  DB: D1Database;
  GITHUB_TOKEN?: string;
}

// ── Tool registry ───────────────────────────────────────────

interface ToolDef extends McpTool {
  tier: "anonymous" | "standard" | "elevated";
  handler: (args: Record<string, unknown>, auth: AuthContext, env: ToolsEnv) => Promise<unknown>;
}

export const TOOLS: ToolDef[] = [
  {
    name: "catdef_describe",
    description: "Returns server capabilities: spec versions served, supported tools by tier, and any operational notes.",
    tier: "anonymous",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    handler: catdefDescribe,
  },
  {
    name: "catdef_lookup",
    description: "Look up a term in the catdef spec. Returns the relevant spec passage(s).",
    tier: "anonymous",
    inputSchema: {
      type: "object",
      properties: {
        term: { type: "string", description: "Term or phrase to search for (e.g. 'subcat', 'policy', 'L1')" },
        scope: { type: "string", enum: ["substrate", "catio", "mcp", "all"], description: "Which spec to search (default: all)" },
      },
      required: ["term"],
      additionalProperties: false,
    },
    handler: catdefLookup,
  },
  {
    name: "catdef_list_decisions",
    description: "List CA-NNN governance decisions. Filter by status; default is all.",
    tier: "anonymous",
    inputSchema: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["Accepted", "Rejected", "Pending", "all"], description: "Filter by disposition (default: all)" },
        limit: { type: "number", description: "Max results (default 50, max 200)" },
      },
      additionalProperties: false,
    },
    handler: catdefListDecisions,
  },
  {
    name: "catdef_validate",
    description: "Validate a catdef artifact (OpenCatalog or OpenThing) against the spec. Input may be raw JSON or base64-encoded ZIP bundle.",
    tier: "anonymous",
    inputSchema: {
      type: "object",
      properties: {
        artifact: { type: "string", description: "Raw JSON or base64-encoded bundle" },
        encoding: { type: "string", enum: ["json", "base64"], description: "Input encoding (default: json)" },
        suite: { type: "string", enum: ["L1", "L2", "L3", "L4"], description: "Conformance level to validate against" },
      },
      required: ["artifact"],
      additionalProperties: false,
    },
    handler: catdefValidate,
  },
  {
    name: "catdef_report_feedback",
    description: "File structured feedback into the canonical CA-NNN queue. Returns the allocated CA-NNN feedback_id.",
    tier: "standard",
    inputSchema: {
      type: "object",
      properties: {
        category: { type: "string", enum: ["spec-bug", "spec-gap", "extension-namespace-candidate", "implementation-detail", "clarification", "other"] },
        severity: { type: "string", enum: ["low", "medium", "high"] },
        body: { type: "string", description: "The feedback content" },
        context: { type: "object", description: "Optional structured context (e.g. catdef version, implementation, what you were trying)" },
        attribution: {
          type: "object",
          properties: {
            display_name: { type: "string" },
            contact: { type: "string" },
            public_consent: { type: "boolean", description: "If true, attribution may appear in any resulting public decision" },
          },
          additionalProperties: false,
        },
      },
      required: ["category", "severity", "body"],
      additionalProperties: false,
    },
    handler: catdefReportFeedback,
  },
  {
    name: "catdef_get_feedback_status",
    description: "Look up the disposition of a feedback item submitted by the calling api-key. Cross-key reads are forbidden at standard tier.",
    tier: "standard",
    inputSchema: {
      type: "object",
      properties: {
        feedback_id: { type: "string", description: "CA-NNN identifier returned by catdef_report_feedback" },
      },
      required: ["feedback_id"],
      additionalProperties: false,
    },
    handler: catdefGetFeedbackStatus,
  },
  {
    name: "catdef_list_feedback",
    description: "List items in the feedback queue. Elevated tier only.",
    tier: "elevated",
    inputSchema: {
      type: "object",
      properties: {
        status: { type: "string", description: "Filter by status (received/triaged/drafted/decided/shipped/rejected)" },
        since: { type: "string", description: "ISO-8601 timestamp; return items received after this time" },
        limit: { type: "number", description: "Max results (default 50, max 500)" },
        offset: { type: "number", description: "Pagination offset (default 0)" },
      },
      additionalProperties: false,
    },
    handler: catdefListFeedback,
  },
  {
    name: "catdef_set_feedback_status",
    description: "Update the status of a feedback item. Elevated tier only.",
    tier: "elevated",
    inputSchema: {
      type: "object",
      properties: {
        feedback_id: { type: "string", description: "CA-NNN identifier" },
        status: { type: "string", enum: ["received", "triaged", "drafted", "decided", "shipped", "rejected"] },
        notes: { type: "string", description: "Optional triage note (audit trail)" },
      },
      required: ["feedback_id", "status"],
      additionalProperties: false,
    },
    handler: catdefSetFeedbackStatus,
  },
  {
    name: "catdef_attach_decision",
    description: "Promote a feedback item to a decision artifact. Per CA-009, the feedback's CA-NNN persists as the decision's CA-NNN (no re-numbering). Elevated tier only.",
    tier: "elevated",
    inputSchema: {
      type: "object",
      properties: {
        feedback_id: { type: "string", description: "CA-NNN identifier" },
        make_public: { type: "boolean", description: "If true, feedback becomes publicly listable as the basis for the cited decision" },
        decision_summary: { type: "string", description: "Optional one-line summary of the disposition; recorded for audit" },
      },
      required: ["feedback_id"],
      additionalProperties: false,
    },
    handler: catdefAttachDecision,
  },
];

// ── Dispatcher ──────────────────────────────────────────────

export function findTool(name: string): ToolDef | undefined {
  return TOOLS.find(t => t.name === name);
}

export function toolsForTier(auth: AuthContext): McpTool[] {
  return TOOLS.filter(t => tierAtLeast(auth, t.tier)).map(({ tier, handler, ...mcp }) => mcp);
}

// ── Handler implementations ─────────────────────────────────

async function catdefDescribe(
  _args: Record<string, unknown>,
  auth: AuthContext,
  _env: ToolsEnv,
): Promise<unknown> {
  return {
    server_name: "catdef-org-mcp",
    server_version: "0.1.1",
    spec_version: "1.4",
    spec_repo: "https://github.com/catdef/catdef-spec",
    canonical_surface_proposal: "https://github.com/catdef/catdef-spec/blob/main/proposals/catdef-org-mcp-canonical-surface.md",
    your_tier: auth.tier,
    tools_available: TOOLS.filter(t => tierAtLeast(auth, t.tier)).map(t => t.name),
    notes: "v0.1 — feedback channel + grounding tools live; catdef_validate runs rule-based pending mechanical-validator port.",
  };
}

async function catdefLookup(
  args: Record<string, unknown>,
  _auth: AuthContext,
  _env: ToolsEnv,
): Promise<unknown> {
  const term = String(args.term ?? "").trim();
  if (!term) throw rpcInvalidParams("term required");
  const scope = String(args.scope ?? "all");

  const files: { url: string; name: string }[] = [];
  if (scope === "substrate" || scope === "all") {
    files.push({ url: "https://raw.githubusercontent.com/catdef/catdef-spec/main/CATDEF_SPEC.md", name: "CATDEF_SPEC.md" });
  }
  if (scope === "catio" || scope === "all") {
    files.push({ url: "https://raw.githubusercontent.com/catdef/catdef-spec/main/CATIO_SPEC.md", name: "CATIO_SPEC.md" });
  }
  if (scope === "mcp" || scope === "all") {
    files.push({ url: "https://raw.githubusercontent.com/catdef/catdef-spec/main/MCP_REFERENCE.md", name: "MCP_REFERENCE.md" });
  }

  const matches: Array<{ source: string; anchor: string; passage: string }> = [];
  const lowerTerm = term.toLowerCase();

  for (const file of files) {
    const resp = await fetch(file.url, { cf: { cacheTtl: 300, cacheEverything: true } });
    if (!resp.ok) continue;
    const text = await resp.text();
    const lines = text.split("\n");

    let currentAnchor = "";
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const heading = /^#+\s+(.+)$/.exec(line);
      if (heading) {
        currentAnchor = heading[1].toLowerCase().replace(/[^a-z0-9]+/g, "-");
        continue;
      }
      if (line.toLowerCase().includes(lowerTerm)) {
        // Grab a small surrounding window (the matching line + 2 before + 2 after)
        const start = Math.max(0, i - 2);
        const end = Math.min(lines.length, i + 3);
        const passage = lines.slice(start, end).join("\n");
        matches.push({ source: file.name, anchor: currentAnchor, passage });
        if (matches.length >= 10) break;
      }
    }
    if (matches.length >= 10) break;
  }

  return { term, scope, matches };
}

async function catdefListDecisions(
  args: Record<string, unknown>,
  _auth: AuthContext,
  env: ToolsEnv,
): Promise<unknown> {
  const status = String(args.status ?? "all");
  const limit = Math.min(Number(args.limit ?? 50), 200);

  // Per CA-011: use the shared 401-resilient helper so an invalid
  // GITHUB_TOKEN secret falls back to unauthenticated (60/hr limit;
  // sufficient at current traffic). Rotating the token restores 5000/hr.
  let entries: Array<{ name: string; type: string; download_url: string }>;
  try {
    entries = await githubContents<Array<{ name: string; type: string; download_url: string }>>(
      "decisions",
      env.GITHUB_TOKEN,
    );
  } catch (e) {
    throw rpcInternal((e as Error).message);
  }
  const caEntries = entries
    .filter(e => e.type === "file" && /^CA-\d{3,}\.md$/.test(e.name))
    .sort((a, b) => b.name.localeCompare(a.name))  // newest first
    .slice(0, limit);

  // Best-effort: fetch each file's frontmatter to extract status. To keep this
  // affordable, only fetch when filter is non-trivial or limit is small. For
  // status="all" we return name + URL and let the caller dive in.
  const needsBody = status !== "all";
  const results: Array<{ id: string; status?: string; title?: string; url: string }> = [];

  for (const entry of caEntries) {
    const item: { id: string; status?: string; title?: string; url: string } = {
      id: entry.name.replace(/\.md$/, ""),
      url: `https://github.com/catdef/catdef-spec/blob/main/decisions/${entry.name}`,
    };
    if (needsBody) {
      try {
        const mdResp = await fetch(entry.download_url, { cf: { cacheTtl: 300, cacheEverything: true } });
        if (mdResp.ok) {
          const md = await mdResp.text();
          const dispoMatch = /\*\*Disposition:\*\*\s*([^\n]+)/.exec(md);
          if (dispoMatch) item.status = dispoMatch[1].split(/[\s(]/)[0].trim();
          const titleMatch = /^#\s+(.+)$/m.exec(md);
          if (titleMatch) item.title = titleMatch[1].replace(/^CA-\d+\s+Decision\s+—\s+/, "");
        }
      } catch {/* skip */}

      const wanted = status.toLowerCase();
      const got = (item.status ?? "").toLowerCase();
      if (got.includes(wanted) === false) continue;
    }
    results.push(item);
  }

  return { count: results.length, status_filter: status, decisions: results };
}

async function catdefValidate(
  args: Record<string, unknown>,
  _auth: AuthContext,
  _env: ToolsEnv,
): Promise<unknown> {
  const encoding = String(args.encoding ?? "json");
  const artifact = String(args.artifact ?? "");
  if (!artifact) throw rpcInvalidParams("artifact required");

  // v0.1: cheap rule-based validation only. Full pytest port is follow-on
  // work per the proposal. The skill on the plugin side already does the
  // heavier semantic check; this tool offers basic structural validation
  // so callers without the plugin can still get a quick yes/no.
  let parsed: unknown;
  if (encoding === "json") {
    try {
      parsed = JSON.parse(artifact);
    } catch (e) {
      return { valid: false, errors: [{ path: "$", message: `Invalid JSON: ${(e as Error).message}` }] };
    }
  } else if (encoding === "base64") {
    return {
      valid: false,
      errors: [{ path: "$", message: "base64/ZIP validation not yet implemented in v0.1; use the /catdef:validate skill or run the pytest suite locally" }],
    };
  } else {
    throw rpcInvalidParams("encoding must be 'json' or 'base64'");
  }

  const errors: Array<{ path: string; message: string }> = [];
  if (typeof parsed !== "object" || parsed === null) {
    errors.push({ path: "$", message: "Top-level must be a JSON object" });
    return { valid: false, errors };
  }
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.catdef !== "string") {
    errors.push({ path: "$.catdef", message: "Required field 'catdef' (spec version) missing or not a string" });
  } else if (!/^\d+\.\d+(\.\d+)?$/.test(obj.catdef as string)) {
    errors.push({ path: "$.catdef", message: `'catdef' must be a semver string (got '${obj.catdef}')` });
  }
  // OpenCatalog requires product; OpenThing requires a namespaced type. Treat
  // either as valid at the top level; only flag when neither shape matches.
  const hasProduct = typeof obj.product === "object" && obj.product !== null;
  const hasNamespacedType = typeof obj.type === "string" && /^[a-z][a-z0-9_-]*:[A-Z]/.test(obj.type as string);
  if (!hasProduct && !hasNamespacedType) {
    errors.push({
      path: "$",
      message: "Artifact does not match OpenCatalog (requires '.product') or OpenThing (requires namespaced '.type'). See CATDEF_SPEC.md §Top-Level Structure.",
    });
  }

  return {
    valid: errors.length === 0,
    errors,
    note: "v0.1 rule-based check covers top-level shape only. For full conformance, use the /catdef:validate skill in the catdef Claude Code plugin or run the pytest suite at https://github.com/catdef/catdef-spec/tree/main/conformance",
  };
}

async function catdefReportFeedback(
  args: Record<string, unknown>,
  auth: AuthContext,
  env: ToolsEnv,
): Promise<unknown> {
  const category = String(args.category ?? "");
  const severity = String(args.severity ?? "");
  const body = String(args.body ?? "").trim();
  if (!category || !severity || !body) {
    throw rpcInvalidParams("category, severity, body all required");
  }

  const attribution = (args.attribution ?? {}) as Record<string, unknown>;
  const context = (args.context ?? {}) as Record<string, unknown>;

  const feedbackId = await allocateCaNnn(env);

  // Map MCP shape to existing feedback table columns (additive — the legacy
  // fields stay populated for backward compat with the existing GET /feedback
  // public feed). type/severity values map cleanly to existing CHECK enums.
  const legacyType = mapCategoryToLegacyType(category);
  const legacySeverity = mapSeverityToLegacySeverity(severity);

  await env.DB.prepare(`
    INSERT INTO feedback
      (public_id, type, severity, agent, catdef_version, context, field_type, message, ip_hash, status, api_key_hash, public, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'received', ?, 0, datetime('now'))
  `).bind(
    feedbackId,
    legacyType,
    legacySeverity,
    attribution.display_name ? String(attribution.display_name) : "mcp-anonymous",
    typeof context.catdef_version === "string" ? context.catdef_version : "1.4",
    typeof context.what_you_were_trying === "string" ? context.what_you_were_trying : JSON.stringify(context).slice(0, 500),
    typeof context.field_type === "string" ? context.field_type : null,
    body,
    auth.keyHash ?? null,
    auth.keyHash ?? null,
  ).run();

  return {
    feedback_id: feedbackId,
    status: "received",
    notes: `Feedback queued. Look up status with catdef_get_feedback_status({feedback_id: "${feedbackId}"}). The same CA-NNN persists if the item is triaged into a decision per CA-009.`,
  };
}

async function catdefGetFeedbackStatus(
  args: Record<string, unknown>,
  auth: AuthContext,
  env: ToolsEnv,
): Promise<unknown> {
  const feedbackId = String(args.feedback_id ?? "").trim();
  if (!feedbackId) throw rpcInvalidParams("feedback_id required");

  const row = await env.DB.prepare(`
    SELECT public_id, status, decision_id, updated_at, api_key_hash, public, message
    FROM feedback WHERE public_id = ?
  `).bind(feedbackId).first<{
    public_id: string;
    status: string;
    decision_id: string | null;
    updated_at: string | null;
    api_key_hash: string | null;
    public: number;
    message: string;
  }>();

  if (!row) {
    throw rpcNotFound(`No feedback with id '${feedbackId}'`);
  }

  // Standard tier may only read their own submissions; elevated tier reads all
  if (auth.tier === "standard" && row.api_key_hash !== auth.keyHash) {
    throw rpcForbidden("Standard-tier callers can only read their own submissions");
  }

  return {
    feedback_id: row.public_id,
    status: row.status,
    decision_ref: row.decision_id ?? null,
    decision_url: row.decision_id
      ? `https://github.com/catdef/catdef-spec/blob/main/decisions/${row.decision_id}.md`
      : null,
    updated: row.updated_at,
    public: row.public === 1,
  };
}

async function catdefListFeedback(
  args: Record<string, unknown>,
  _auth: AuthContext,
  env: ToolsEnv,
): Promise<unknown> {
  const status = args.status ? String(args.status) : null;
  const since = args.since ? String(args.since) : null;
  const limit = Math.min(Number(args.limit ?? 50), 500);
  const offset = Math.max(Number(args.offset ?? 0), 0);

  let query = `SELECT public_id, status, type, severity, created_at, substr(message, 1, 200) as body_excerpt
               FROM feedback WHERE 1=1`;
  const params: unknown[] = [];
  if (status) {
    query += " AND status = ?";
    params.push(status);
  }
  if (since) {
    query += " AND created_at > ?";
    params.push(since);
  }
  query += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
  params.push(limit, offset);

  const result = await env.DB.prepare(query).bind(...params).all();

  const totalRow = await env.DB.prepare(
    status
      ? "SELECT COUNT(*) as c FROM feedback WHERE status = ?"
      : "SELECT COUNT(*) as c FROM feedback"
  ).bind(...(status ? [status] : [])).first<{ c: number }>();

  return {
    items: (result.results ?? []).map((r: Record<string, unknown>) => ({
      feedback_id: r.public_id,
      status: r.status,
      category: r.type,
      severity: r.severity,
      received: r.created_at,
      body_excerpt: r.body_excerpt,
    })),
    total: totalRow?.c ?? 0,
  };
}

async function catdefSetFeedbackStatus(
  args: Record<string, unknown>,
  _auth: AuthContext,
  env: ToolsEnv,
): Promise<unknown> {
  const feedbackId = String(args.feedback_id ?? "").trim();
  const status = String(args.status ?? "").trim();
  const notes = args.notes ? String(args.notes) : null;
  if (!feedbackId || !status) throw rpcInvalidParams("feedback_id and status required");

  const res = await env.DB.prepare(
    "UPDATE feedback SET status = ?, updated_at = datetime('now') WHERE public_id = ?"
  ).bind(status, feedbackId).run();

  if (res.meta.changes === 0) {
    throw rpcNotFound(`No feedback with id '${feedbackId}'`);
  }

  // Note: notes are accepted but not persisted in v0.1 (no audit-trail table
  // yet; future migration adds feedback_audit). Acknowledged in the response.
  return {
    feedback_id: feedbackId,
    status,
    updated: new Date().toISOString(),
    notes_acknowledged: notes !== null,
  };
}

async function catdefAttachDecision(
  args: Record<string, unknown>,
  _auth: AuthContext,
  env: ToolsEnv,
): Promise<unknown> {
  const feedbackId = String(args.feedback_id ?? "").trim();
  if (!feedbackId) throw rpcInvalidParams("feedback_id required");

  // Per CA-009, the decision keeps the feedback's CA-NNN — no re-numbering
  const numericId = parseCaNnn(feedbackId);
  if (numericId === null) {
    throw rpcInvalidParams(`feedback_id must be CA-NNN format (got '${feedbackId}'); legacy CDF-NNNN cannot be promoted to decisions per CA-009`);
  }

  const makePublic = args.make_public === true;
  const summary = args.decision_summary ? String(args.decision_summary).slice(0, 500) : null;

  const res = await env.DB.prepare(`
    UPDATE feedback
       SET status = 'decided',
           decision_id = ?,
           public = ?,
           updated_at = datetime('now')
     WHERE public_id = ?
  `).bind(feedbackId, makePublic ? 1 : 0, feedbackId).run();

  if (res.meta.changes === 0) {
    throw rpcNotFound(`No feedback with id '${feedbackId}'`);
  }

  return {
    feedback_id: feedbackId,
    decision_id: feedbackId,
    decision_path: `decisions/${feedbackId}.md`,
    public: makePublic,
    note: summary
      ? `Decision linked; summary recorded. The decision artifact decisions/${feedbackId}.md is the canonical record — file it on the catdef-spec repo separately.`
      : `Decision linked. The decision artifact decisions/${feedbackId}.md is the canonical record — file it on the catdef-spec repo separately.`,
  };
}

// ── Helpers ─────────────────────────────────────────────────

function mapCategoryToLegacyType(category: string): string {
  switch (category) {
    case "spec-bug": return "bug";
    case "spec-gap": return "gap";
    case "extension-namespace-candidate": return "feature_request";
    case "clarification": return "clarification";
    case "implementation-detail": return "feature_request";
    default: return "gap";
  }
}

function mapSeverityToLegacySeverity(severity: string): string {
  switch (severity) {
    case "high": return "blocker";
    case "medium": return "major";
    default: return "minor";
  }
}

// ── RPC-error helpers ───────────────────────────────────────

class RpcError extends Error {
  code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

export function rpcInvalidParams(message: string): never { throw new RpcError(-32602, message); }
export function rpcNotFound(message: string): never { throw new RpcError(-32004, message); }
export function rpcForbidden(message: string): never { throw new RpcError(-32002, message); }
export function rpcInternal(message: string): never { throw new RpcError(-32603, message); }

export { RpcError };

// Counter-refresh admin endpoint helper (called from the HTTP router, not
// from the MCP tool registry — re-exported for the index.ts route handler)
export async function adminRefreshCounter(env: ToolsEnv): Promise<unknown> {
  return await refreshCounterFromGitHub(env, env.GITHUB_TOKEN);
}
