/**
 * catdef.org — The open standard for catalog definitions.
 *
 * Cloudflare Worker serving:
 *   GET  /           — landing page
 *   GET  /spec       — redirect to GitHub spec
 *   POST /feedback   — structured feedback intake (agents + humans)
 *   GET  /feedback   — public feed of all feedback
 *   GET  /feedback/:id — single feedback item
 */

export interface Env {
  DB: D1Database;
  GITHUB_TOKEN: string;  // Secret: fine-grained PAT with Issues write on catdef/catdef-spec
}

const SPEC_URL = "https://github.com/catdef/catdef-spec/blob/main/CATDEF_SPEC.md";
const REPO_URL = "https://github.com/catdef/catdef-spec";
const GITHUB_REPO = "catdef/catdef-spec";

const TYPE_LABELS: Record<string, string> = {
  feature_request: "RFE",
  bug: "RFE",
  gap: "RFE",
  clarification: "RFE",
  success_story: "success-story",
};

const SEVERITY_LABELS: Record<string, string> = {
  blocker: "severity: blocker",
  major: "severity: major",
  minor: "severity: minor",
};

const VALID_TYPES = ["feature_request", "bug", "gap", "clarification", "success_story"];
const VALID_SEVERITIES = ["minor", "major", "blocker"];

// Rate limit: max 20 submissions per IP per hour
const RATE_LIMIT = 20;
const RATE_WINDOW_SECONDS = 3600;

function corsHeaders(): HeadersInit {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders() },
  });
}

async function hashIP(ip: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(ip + "-catdef-salt"));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function generatePublicId(db: D1Database): Promise<string> {
  const result = await db.prepare("SELECT MAX(id) as max_id FROM feedback").first<{ max_id: number | null }>();
  const next = (result?.max_id ?? 0) + 1;
  return `CDF-${String(next).padStart(4, "0")}`;
}

async function checkRateLimit(db: D1Database, ipHash: string): Promise<boolean> {
  const cutoff = new Date(Date.now() - RATE_WINDOW_SECONDS * 1000).toISOString();
  const result = await db.prepare(
    "SELECT COUNT(*) as count FROM feedback WHERE ip_hash = ? AND created_at > ?"
  ).bind(ipHash, cutoff).first<{ count: number }>();
  return (result?.count ?? 0) < RATE_LIMIT;
}

// ── GitHub Issue Creation ────────────────────────────────────

async function createGitHubIssue(
  env: Env,
  publicId: string,
  type: string,
  severity: string,
  agent: string,
  catdefVersion: string,
  context: string,
  fieldType: string | null,
  message: string,
): Promise<string | null> {
  if (!env.GITHUB_TOKEN) return null;

  const typeLabel = TYPE_LABELS[type] ?? "RFE";
  const sevLabel = SEVERITY_LABELS[severity] ?? "severity: minor";

  const title = `[${publicId}] ${type === "success_story" ? "🎉 " : ""}${message.slice(0, 100)}${message.length > 100 ? "..." : ""}`;

  const bodyParts = [
    `**${publicId}** — filed via catdef.org/feedback`,
    "",
    `| Field | Value |`,
    `|-------|-------|`,
    `| Type | \`${type}\` |`,
    `| Severity | \`${severity}\` |`,
    `| Agent | \`${agent}\` |`,
    `| catdef version | \`${catdefVersion}\` |`,
    fieldType ? `| Field type | \`${fieldType}\` |` : null,
    context ? `| Context | ${context} |` : null,
    "",
    "## Description",
    "",
    message,
    "",
    "---",
    "*Filed automatically via [catdef.org](https://catdef.org). Discuss and vote with reactions.*",
  ].filter(Boolean).join("\n");

  const labels = [typeLabel, sevLabel, `catdef-${catdefVersion}`, `agent:${agent.split(" ")[0]}`];

  try {
    const resp = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/issues`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
        "Accept": "application/vnd.github+json",
        "User-Agent": "catdef-org-worker",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      body: JSON.stringify({
        title,
        body: bodyParts,
        labels,
      }),
    });

    if (resp.ok) {
      const issue = await resp.json() as { html_url: string };
      return issue.html_url;
    }

    // If labels don't exist yet, retry without them
    const resp2 = await fetch(`https://api.github.com/repos/${GITHUB_REPO}/issues`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${env.GITHUB_TOKEN}`,
        "Accept": "application/vnd.github+json",
        "User-Agent": "catdef-org-worker",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      body: JSON.stringify({
        title,
        body: bodyParts,
      }),
    });

    if (resp2.ok) {
      const issue = await resp2.json() as { html_url: string };
      return issue.html_url;
    }

    return null;
  } catch {
    return null;
  }
}

// ── Landing Page ────────────────────────────────────────────

function landingPage(): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>catdef — The Open Standard for Catalog Definitions</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0d1117; color: #e6edf3;
      display: flex; flex-direction: column; align-items: center;
      min-height: 100vh; padding: 4rem 2rem;
    }
    .container { max-width: 640px; width: 100%; }
    h1 { font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem; }
    h1 span { color: #58a6ff; }
    .tagline { color: #8b949e; font-size: 1.2rem; margin-bottom: 2rem; }
    .description { line-height: 1.7; margin-bottom: 2rem; color: #c9d1d9; }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .links { display: flex; gap: 1.5rem; margin-bottom: 3rem; flex-wrap: wrap; }
    .links a {
      padding: 0.6rem 1.2rem; border: 1px solid #30363d; border-radius: 6px;
      font-size: 0.95rem; transition: border-color 0.2s;
    }
    .links a:hover { border-color: #58a6ff; text-decoration: none; }
    .section { margin-bottom: 2rem; }
    .section h2 { font-size: 1.1rem; color: #8b949e; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.05em; }
    code { background: #161b22; padding: 0.2em 0.4em; border-radius: 3px; font-size: 0.9em; }
    pre { background: #161b22; padding: 1rem; border-radius: 6px; overflow-x: auto; margin: 0.5rem 0; font-size: 0.85rem; line-height: 1.5; }
    .footer { margin-top: auto; padding-top: 3rem; color: #484f58; font-size: 0.85rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1><span>catdef</span>.org</h1>
    <p class="tagline">The open standard for machine-enhanceable descriptors of real-world objects and catalogs.</p>

    <p class="description">
      <strong>catdef</strong> defines two complementary concepts:
      <strong>OpenThing</strong> — a schema for describing any real-world object, and
      <strong>OpenCatalog</strong> — a schema for organizing collections of things.
      Any conforming runtime can read a catdef and render a working application.
      An AI that can see a photograph can write a catdef.
    </p>

    <div class="links">
      <a href="${SPEC_URL}">Read the Spec</a>
      <a href="${REPO_URL}">GitHub</a>
      <a href="${REPO_URL}/tree/main/conformance">Test Suite</a>
      <a href="/feedback">Feedback Feed</a>
    </div>

    <div class="section">
      <h2>File Format</h2>
      <p>MIME type: <code>application/vnd.catdef+json</code><br>
      File extension: <code>.thingalog</code> (with data) or <code>.catdef.json</code> (schema only)</p>
    </div>

    <div class="section">
      <h2>Report Feedback</h2>
      <p>Agents and humans can submit structured feedback via API:</p>
      <pre>POST /feedback
{
  "type": "gap",
  "agent": "claude-3.5",
  "catdef_version": "1.1",
  "context": "Cataloging a wine collection",
  "field_type": "Date",
  "message": "No way to express vintage year ranges",
  "severity": "minor"
}</pre>
    </div>

    <div class="section">
      <h2>MCP</h2>
      <p>The feedback endpoint is also available as an MCP tool for AI agents that want to
      report spec gaps programmatically while building catalogs.</p>
    </div>
  </div>
  <div class="footer">
    catdef is an open standard, licensed under MIT.
  </div>
</body>
</html>`;
  return new Response(html, {
    headers: { "Content-Type": "text/html;charset=UTF-8" },
  });
}

// ── Request Handler ──────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // GET / — landing page
    if (pathname === "/" && request.method === "GET") {
      return landingPage();
    }

    // GET /spec — redirect to GitHub
    if (pathname === "/spec" && request.method === "GET") {
      return Response.redirect(SPEC_URL, 302);
    }

    // POST /feedback — submit feedback
    if (pathname === "/feedback" && request.method === "POST") {
      try {
        const body = await request.json() as Record<string, unknown>;

        // Validate required fields
        const message = String(body.message ?? "").trim();
        if (!message) {
          return json({ error: "message is required" }, 400);
        }

        const type = String(body.type ?? "gap");
        if (!VALID_TYPES.includes(type)) {
          return json({ error: `type must be one of: ${VALID_TYPES.join(", ")}` }, 400);
        }

        const severity = String(body.severity ?? "minor");
        if (!VALID_SEVERITIES.includes(severity)) {
          return json({ error: `severity must be one of: ${VALID_SEVERITIES.join(", ")}` }, 400);
        }

        // Rate limit
        const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
        const ipHash = await hashIP(ip);
        const allowed = await checkRateLimit(env.DB, ipHash);
        if (!allowed) {
          return json({ error: "Rate limit exceeded. Max 20 submissions per hour." }, 429);
        }

        // Generate public ID
        const publicId = await generatePublicId(env.DB);

        // Insert
        await env.DB.prepare(`
          INSERT INTO feedback (public_id, type, severity, agent, catdef_version, context, field_type, message, ip_hash)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          publicId,
          type,
          severity,
          String(body.agent ?? "unknown"),
          String(body.catdef_version ?? "1.1"),
          String(body.context ?? ""),
          body.field_type ? String(body.field_type) : null,
          message,
          ipHash,
        ).run();

        // Create GitHub issue for public discussion
        const issueUrl = await createGitHubIssue(
          env, publicId, type, severity,
          String(body.agent ?? "unknown"),
          String(body.catdef_version ?? "1.1"),
          String(body.context ?? ""),
          body.field_type ? String(body.field_type) : null,
          message,
        );

        return json({
          ok: true,
          id: publicId,
          issue_url: issueUrl,
          message: issueUrl
            ? "Feedback received. Discuss at the GitHub issue."
            : "Feedback received. Thank you.",
        }, 201);
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Unknown error";
        return json({ error: "Invalid JSON body", detail: msg }, 400);
      }
    }

    // GET /feedback — list all feedback (public feed)
    if (pathname === "/feedback" && request.method === "GET") {
      const limit = Math.min(Number(url.searchParams.get("limit") ?? 50), 200);
      const offset = Number(url.searchParams.get("offset") ?? 0);
      const typeFilter = url.searchParams.get("type");

      let query = "SELECT public_id, type, severity, agent, catdef_version, context, field_type, message, created_at FROM feedback";
      const params: unknown[] = [];

      if (typeFilter && VALID_TYPES.includes(typeFilter)) {
        query += " WHERE type = ?";
        params.push(typeFilter);
      }

      query += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
      params.push(limit, offset);

      const result = await env.DB.prepare(query).bind(...params).all();
      return json({ feedback: result.results, count: result.results.length });
    }

    // GET /feedback/:id — single feedback item
    const feedbackMatch = pathname.match(/^\/feedback\/(CDF-\d+)$/);
    if (feedbackMatch && request.method === "GET") {
      const result = await env.DB.prepare(
        "SELECT public_id, type, severity, agent, catdef_version, context, field_type, message, created_at FROM feedback WHERE public_id = ?"
      ).bind(feedbackMatch[1]).first();
      if (!result) {
        return json({ error: "Not found" }, 404);
      }
      return json(result);
    }

    return json({ error: "Not found" }, 404);
  },
};
