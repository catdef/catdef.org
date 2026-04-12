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

// ── Reference Renderer ──────────────────────────────────────

function renderPage(): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>catdef — Reference Renderer</title>
<style>
:root { --accent:#6366f1; --bg:#f8fafc; --panel:#fff; --ink:#1e293b; --muted:#64748b; --border:#e2e8f0; }
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--ink);min-height:100vh}
.header{background:var(--ink);color:var(--bg);padding:16px 20px;display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:50}
.header h1{font-size:18px;font-weight:700}
.header .tagline{font-size:13px;opacity:0.6}
.header .spacer{flex:1}
.header .stats{font-size:12px;opacity:0.5}
.toolbar{padding:12px 20px;display:flex;gap:10px;align-items:center;flex-wrap:wrap;border-bottom:1px solid var(--border);background:var(--panel)}
.search-input{flex:1;min-width:180px;padding:8px 12px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--ink);font-size:14px}
.search-input:focus{outline:2px solid var(--accent);outline-offset:-1px}
.sort-select{padding:8px 10px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--ink);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px;padding:20px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden;cursor:pointer;transition:box-shadow 0.2s}
.card:hover{box-shadow:0 4px 12px rgba(0,0,0,0.08)}
.card-img{width:100%;aspect-ratio:4/3;background:var(--border);display:flex;align-items:center;justify-content:center;color:var(--muted);font-size:32px}
.card-body{padding:12px}
.card-title{font-size:14px;font-weight:600;margin-bottom:4px}
.card-sub{font-size:12px;color:var(--muted)}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);z-index:100;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--panel);border-radius:12px;max-width:640px;width:90%;max-height:85vh;overflow-y:auto;padding:24px}
.modal h2{font-size:18px;margin-bottom:16px}
.modal .close{float:right;background:none;border:none;font-size:24px;cursor:pointer;color:var(--muted)}
.field{margin-bottom:12px}
.field-label{font-size:11px;text-transform:uppercase;color:var(--muted);margin-bottom:2px;letter-spacing:0.05em}
.field-value{font-size:14px}
.chip{display:inline-block;padding:2px 8px;background:var(--bg);border:1px solid var(--border);border-radius:12px;font-size:12px;margin:2px}
.drop-zone{border:3px dashed var(--border);border-radius:16px;padding:60px 40px;text-align:center;margin:40px auto;max-width:500px;cursor:pointer;transition:border-color 0.2s}
.drop-zone:hover,.drop-zone.dragover{border-color:var(--accent)}
.drop-zone h2{font-size:20px;margin-bottom:8px}
.drop-zone p{color:var(--muted);font-size:14px}
.drop-zone .formats{margin-top:12px;font-size:12px;color:var(--muted)}
.drop-zone input[type=file]{display:none}
.powered{text-align:center;padding:20px;font-size:12px;color:var(--muted)}
.powered a{color:var(--accent);text-decoration:none}
</style>
</head>
<body>
<div id="picker">
  <div class="header">
    <h1>catdef</h1>
    <span class="tagline">Reference Renderer</span>
  </div>
  <div class="drop-zone" id="dropZone">
    <h2>Open a catdef file</h2>
    <p>Drop a file here or click to browse</p>
    <div class="formats">.openthing &nbsp; .opencatalog &nbsp; .catdef &nbsp; .thingalog</div>
    <input type="file" id="fileInput" accept=".openthing,.opencatalog,.catdef,.thingalog,.json">
  </div>
  <div class="powered">L1 Reference Renderer &middot; <a href="https://github.com/catdef/catdef-spec">catdef standard</a></div>
</div>
<div id="app" style="display:none">
  <div class="header" id="appHeader"></div>
  <div class="toolbar">
    <input class="search-input" id="searchInput" placeholder="Search...">
    <select class="sort-select" id="sortSelect"></select>
  </div>
  <div class="grid" id="grid"></div>
</div>
<div class="modal-overlay" id="modalOverlay">
  <div class="modal" id="modal"></div>
</div>
<script>
const $ = s => document.querySelector(s);
const dropZone = $('#dropZone');
const fileInput = $('#fileInput');
let DATA = null;

// File picker
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => { e.preventDefault(); dropZone.classList.remove('dragover'); handleFile(e.dataTransfer.files[0]); });
fileInput.addEventListener('change', e => { if (e.target.files[0]) handleFile(e.target.files[0]); });

function handleFile(file) {
  const reader = new FileReader();
  reader.onload = e => {
    try {
      const json = JSON.parse(e.target.result);
      loadCatdef(json);
    } catch (err) {
      alert('Invalid JSON: ' + err.message);
    }
  };
  reader.readAsText(file);
}

function loadCatdef(json) {
  // Normalize: handle catio envelope or raw catdef
  let product = json.product || {};
  let templates = json.templates || [];
  let items = [];
  let values = {};

  if (json.type === 'thing' && json.thing) {
    // Single .openthing — wrap in a minimal catalog
    product = { name: json.thing.fields?.Title || json.thing.template || 'Thing', slug: 'thing' };
    templates = [{ name: json.thing.template || 'Thing', field_defs: inferFieldDefs(json.thing.fields) }];
    items = [json.thing];
    values = {};
  } else if (json.type === 'schema') {
    // .catdef — schema only, no items
    product = { name: 'Schema Preview', slug: 'schema' };
  } else {
    // .opencatalog or legacy .thingalog
    items = (json.data && json.data.items) || [];
    values = (json.data && json.data.values) || {};
  }

  // Apply theme
  if (product.theme && typeof product.theme === 'object') {
    const r = document.documentElement.style;
    Object.entries(product.theme).forEach(([k,v]) => {
      if (typeof v === 'string') r.setProperty('--' + k.replace(/_/g,'-'), v);
    });
  }

  DATA = { product, templates, items, values };

  // Render header
  $('#appHeader').innerHTML =
    '<h1>' + esc(product.name || 'Catalog') + '</h1>' +
    (product.tagline ? '<span class="tagline">' + esc(product.tagline) + '</span>' : '') +
    '<span class="spacer"></span>' +
    '<span class="stats">' + items.length + ' items</span>';

  // Build sort options from first template
  const sortSelect = $('#sortSelect');
  sortSelect.innerHTML = '';
  if (templates[0]) {
    templates[0].field_defs.forEach(fd => {
      if (['String','Integer','Number','Date'].includes(fd.type)) {
        sortSelect.innerHTML += '<option value="' + esc(fd.label) + '">' + esc(fd.label) + '</option>';
      }
    });
  }

  // Show app, hide picker
  $('#picker').style.display = 'none';
  $('#app').style.display = '';

  renderGrid(items);

  // Search
  let debounce;
  $('#searchInput').addEventListener('input', e => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      const q = e.target.value.toLowerCase();
      const filtered = items.filter(item => {
        const fields = item.fields || {};
        return Object.values(fields).some(v => String(v).toLowerCase().includes(q));
      });
      renderGrid(filtered);
    }, 200);
  });

  // Sort
  sortSelect.addEventListener('change', () => {
    const field = sortSelect.value;
    const sorted = [...items].sort((a,b) => {
      const va = (a.fields||{})[field] || '';
      const vb = (b.fields||{})[field] || '';
      if (typeof va === 'number' && typeof vb === 'number') return va - vb;
      return String(va).localeCompare(String(vb));
    });
    renderGrid(sorted);
  });
}

function inferFieldDefs(fields) {
  if (!fields) return [];
  return Object.entries(fields).map(([label, value], i) => {
    let type = 'String';
    if (typeof value === 'number') type = Number.isInteger(value) ? 'Integer' : 'Number';
    else if (typeof value === 'boolean') type = 'Boolean';
    else if (typeof value === 'object' && value && value.value && value.unit) type = 'Number';
    return { label, type, sort_order: (i+1)*10 };
  });
}

function renderGrid(items) {
  const grid = $('#grid');
  grid.innerHTML = '';
  if (!items.length) {
    grid.innerHTML = '<div style="grid-column:1/-1;text-align:center;padding:60px;color:var(--muted)"><div style="font-size:48px;margin-bottom:12px">📦</div><h3>No items found</h3></div>';
    return;
  }
  items.forEach((item, idx) => {
    const fields = item.fields || {};
    const title = fields.Title || fields.Name || fields.title || fields.name || '(untitled)';
    const sub = Object.entries(fields).filter(([k]) => !['Title','Name','title','name','Notes','Description','Photos'].includes(k)).slice(0,2).map(([k,v]) => typeof v === 'object' ? JSON.stringify(v) : v).join(' · ');
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = '<div class="card-img">📷</div><div class="card-body"><div class="card-title">' + esc(title) + '</div><div class="card-sub">' + esc(sub) + '</div></div>';
    card.onclick = () => showModal(item);
    grid.appendChild(card);
  });
}

function showModal(item) {
  const fields = item.fields || {};
  const template = DATA.templates.find(t => t.name === item.template) || { field_defs: inferFieldDefs(fields) };
  let html = '<button class="close" onclick="closeModal()">&times;</button>';
  html += '<h2>' + esc(fields.Title || fields.Name || item.template || 'Item') + '</h2>';

  template.field_defs.forEach(fd => {
    const val = fields[fd.label];
    if (val === undefined || val === null || val === '') return;
    html += '<div class="field"><div class="field-label">' + esc(fd.label) + '</div><div class="field-value">';
    if (typeof val === 'object' && val.value !== undefined && val.unit) {
      html += esc(val.value + ' ' + val.unit);
    } else if (Array.isArray(val)) {
      html += val.map(v => '<span class="chip">' + esc(v) + '</span>').join('');
    } else {
      html += esc(String(val));
    }
    html += '</div></div>';
  });

  // Show any fields not in template
  Object.entries(fields).forEach(([k,v]) => {
    if (template.field_defs.some(fd => fd.label === k)) return;
    if (v === undefined || v === null || v === '') return;
    html += '<div class="field"><div class="field-label">' + esc(k) + '</div><div class="field-value">' + esc(typeof v === 'object' ? JSON.stringify(v) : String(v)) + '</div></div>';
  });

  $('#modal').innerHTML = html;
  $('#modalOverlay').classList.add('open');
}

function closeModal() { $('#modalOverlay').classList.remove('open'); }
$('#modalOverlay').addEventListener('click', e => { if (e.target === $('#modalOverlay')) closeModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
</script>
</body>
</html>`;
  return new Response(html, {
    headers: { "Content-Type": "text/html;charset=UTF-8" },
  });
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
      <a href="/render">Reference Renderer</a>
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

    // GET /render — L1 reference renderer with file picker
    if (pathname === "/render" && request.method === "GET") {
      return renderPage();
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
