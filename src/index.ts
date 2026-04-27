/**
 * catdef.org — The open standard for catalog definitions.
 *
 * Cloudflare Worker serving:
 *   GET  /           — landing page (catdef.org); reference renderer on render.catdef.org
 *   GET  /render     — L1 reference renderer with file picker
 *   GET  /fetch?url= — server-side proxy that fetches a remote catdef and returns JSON
 *                      (used by the renderer's ?url= bootstrap; SSRF-guarded; size-capped; cached)
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

// ── /fetch — server-side proxy for the URL-loadable renderer ─
//
// SSRF defense (best-effort within the Cloudflare Workers runtime):
//
//   • https only — http://, file://, ftp://, etc. rejected at the URL layer.
//   • Hostname blocklist — localhost, 127.0.0.1, ::1, *.local, *.internal,
//     *.localhost rejected by direct match / suffix match.
//   • Private-IP literal blocklist — IPv4 ranges 10/8, 172.16/12, 192.168/16,
//     127/8, 169.254/16, 100.64/10 (CGNAT), 0/8 rejected. IPv6 ::1, ::,
//     fc00::/7, fe80::/10, and IPv4-mapped (::ffff:x.x.x.x) rejected.
//   • Redirects — handled manually with a 3-redirect cap and a re-check of
//     the SSRF guard against each redirect target. A redirect to localhost
//     is the classic SSRF bypass; this prevents it.
//   • Method — GET only on the upstream call.
//   • Size cap — 5 MB, enforced via Content-Length first then streamed-read.
//   • Timeout — 10 seconds total (AbortController).
//
// The one defense Workers can't run cheaply: pre-resolving the hostname's
// DNS records and rejecting if any A/AAAA points to a private IP. The
// Workers runtime does not expose a DNS-resolution API; fetch() resolves
// at Cloudflare's edge. The practical SSRF surface is therefore limited
// by Cloudflare's egress behaviour (it does not route to RFC1918 from edge
// PoPs) plus the literal-IP and hostname-suffix checks above. An attacker
// who controls a public DNS record pointing to a private IP would still
// be filtered by Cloudflare's egress, but that is environmental defense
// rather than in-Worker defense — call out in the PR if this matters.

const PRIVATE_HOSTNAMES = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
  "::",
  "0:0:0:0:0:0:0:0",
  "0:0:0:0:0:0:0:1",
]);

const PRIVATE_HOSTNAME_SUFFIXES = [".local", ".internal", ".localhost"];

const FETCH_TIMEOUT_MS = 10_000;
const FETCH_MAX_BYTES = 5 * 1024 * 1024;
const FETCH_MAX_REDIRECTS = 3;
const CACHE_TTL_OK_SECONDS = 300;
const CACHE_TTL_ERR_SECONDS = 30;

function isPrivateIPv4(host: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return false;
  const o = m.slice(1).map(Number);
  if (o.some(n => n < 0 || n > 255)) return false;
  if (o[0] === 10) return true;                                  // 10.0.0.0/8
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true;     // 172.16.0.0/12
  if (o[0] === 192 && o[1] === 168) return true;                 // 192.168.0.0/16
  if (o[0] === 127) return true;                                 // 127.0.0.0/8 loopback
  if (o[0] === 169 && o[1] === 254) return true;                 // 169.254.0.0/16 link-local
  if (o[0] === 100 && o[1] >= 64 && o[1] <= 127) return true;    // 100.64.0.0/10 CGNAT
  if (o[0] === 0) return true;                                   // 0.0.0.0/8
  return false;
}

function isPrivateIPv6(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (!h.includes(":")) return false;
  if (h === "::1" || h === "0:0:0:0:0:0:0:1") return true;       // loopback
  if (h === "::" || h === "0:0:0:0:0:0:0:0") return true;        // unspecified
  if (/^f[cd]/.test(h)) return true;                             // fc00::/7 unique-local
  const firstSeg = /^([0-9a-f]{1,4}):/.exec(h);
  if (firstSeg) {
    const seg = parseInt(firstSeg[1], 16);
    if (seg >= 0xfe80 && seg <= 0xfebf) return true;             // fe80::/10 link-local
  }
  // IPv4-mapped IPv6 (::ffff:0:0/96). URL.hostname canonicalizes the dotted
  // form to two hex segments — `::ffff:127.0.0.1` becomes `::ffff:7f00:1`.
  // Handle both shapes; convert the hex form to dotted and re-check.
  const v4mappedDotted = /::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(h);
  if (v4mappedDotted && isPrivateIPv4(v4mappedDotted[1])) return true;
  const v4mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
  if (v4mappedHex) {
    const hi = parseInt(v4mappedHex[1], 16);
    const lo = parseInt(v4mappedHex[2], 16);
    const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
    if (isPrivateIPv4(ipv4)) return true;
  }
  return false;
}

type SSRFResult = { ok: true; url: URL } | { ok: false; reason: string; status: number };

function ssrfCheck(rawUrl: string): SSRFResult {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return { ok: false, reason: "Invalid URL", status: 400 };
  }
  if (url.protocol !== "https:") {
    return { ok: false, reason: "Only https:// URLs are accepted", status: 400 };
  }
  const host = url.hostname.toLowerCase();
  if (PRIVATE_HOSTNAMES.has(host)) {
    return { ok: false, reason: `Hostname '${host}' is blocked`, status: 400 };
  }
  if (PRIVATE_HOSTNAME_SUFFIXES.some(suffix => host.endsWith(suffix))) {
    return { ok: false, reason: `Hostname suffix is blocked (${PRIVATE_HOSTNAME_SUFFIXES.join(", ")})`, status: 400 };
  }
  if (isPrivateIPv4(host)) {
    return { ok: false, reason: "Private IPv4 address", status: 400 };
  }
  if (isPrivateIPv6(host)) {
    return { ok: false, reason: "Private IPv6 address", status: 400 };
  }
  return { ok: true, url };
}

type UpstreamResult = {
  status: number;
  body: string | null;
  contentType: string | null;
  error?: string;
  finalUrl?: string;
};

async function fetchUpstream(rawUrl: string): Promise<UpstreamResult> {
  let currentUrl = rawUrl;
  let redirects = 0;
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    while (true) {
      const guard = ssrfCheck(currentUrl);
      if (!guard.ok) {
        return { status: guard.status, body: null, contentType: null, error: guard.reason };
      }

      const resp = await fetch(guard.url.toString(), {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "User-Agent": "catdef-org-renderer-fetch/1.0 (+https://catdef.org)",
          "Accept": "application/json, application/vnd.catdef+json, application/vnd.opencatalog+json, application/vnd.openthing+json, */*",
        },
      });

      if (resp.status >= 300 && resp.status < 400) {
        const loc = resp.headers.get("Location");
        if (!loc) {
          return { status: 502, body: null, contentType: null, error: "Upstream redirect without Location" };
        }
        if (++redirects > FETCH_MAX_REDIRECTS) {
          return { status: 502, body: null, contentType: null, error: `Too many redirects (>${FETCH_MAX_REDIRECTS})` };
        }
        try {
          currentUrl = new URL(loc, currentUrl).toString();
        } catch {
          return { status: 502, body: null, contentType: null, error: "Upstream redirect to invalid URL" };
        }
        continue;
      }

      const contentLength = resp.headers.get("Content-Length");
      if (contentLength && Number(contentLength) > FETCH_MAX_BYTES) {
        return { status: 413, body: null, contentType: null, error: `Upstream Content-Length ${contentLength} exceeds ${FETCH_MAX_BYTES}` };
      }

      if (!resp.ok) {
        return { status: 502, body: null, contentType: null, error: `Upstream returned HTTP ${resp.status}` };
      }

      const reader = resp.body?.getReader();
      if (!reader) {
        return { status: 502, body: null, contentType: null, error: "Upstream returned no body" };
      }

      let received = 0;
      const chunks: Uint8Array[] = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;
        received += value.byteLength;
        if (received > FETCH_MAX_BYTES) {
          try { await reader.cancel(); } catch { /* noop */ }
          return { status: 413, body: null, contentType: null, error: `Upstream body exceeded ${FETCH_MAX_BYTES} bytes` };
        }
        chunks.push(value);
      }

      const buf = new Uint8Array(received);
      let pos = 0;
      for (const c of chunks) { buf.set(c, pos); pos += c.byteLength; }

      let body: string;
      try {
        body = new TextDecoder("utf-8", { fatal: true }).decode(buf);
      } catch {
        return { status: 502, body: null, contentType: null, error: "Upstream body is not valid UTF-8" };
      }

      return {
        status: 200,
        body,
        contentType: resp.headers.get("Content-Type"),
        finalUrl: currentUrl,
      };
    }
  } catch (e: unknown) {
    if (e instanceof Error && (e.name === "AbortError" || e.name === "TimeoutError")) {
      return { status: 504, body: null, contentType: null, error: `Upstream timeout (>${FETCH_TIMEOUT_MS}ms)` };
    }
    return { status: 502, body: null, contentType: null, error: e instanceof Error ? e.message : "Upstream fetch failed" };
  } finally {
    clearTimeout(timeoutHandle);
  }
}

async function handleFetchRoute(request: Request, ctx: ExecutionContext): Promise<Response> {
  if (request.method !== "GET") {
    return json({ error: "Method not allowed; GET only" }, 405);
  }
  const reqUrl = new URL(request.url);
  const target = reqUrl.searchParams.get("url");
  if (!target) {
    return json({ error: "Missing required query parameter: url" }, 400);
  }

  // Cache key uses the request URL (the /fetch?url=... URL itself).
  // Note: catdef.org/fetch?url=X and render.catdef.org/fetch?url=X cache as
  // separate entries because the request URL hostname differs. Acceptable
  // duplication for v1; optimisation deferred.
  // `caches.default` is the Workers-specific extension to the standard
  // CacheStorage interface; cast to access it without depending on which
  // version of @cloudflare/workers-types is in scope.
  const cache = (caches as unknown as { default: Cache }).default;
  const cacheKey = new Request(reqUrl.toString(), { method: "GET" });
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  const result = await fetchUpstream(target);

  let response: Response;
  if (result.status === 200 && result.body) {
    response = new Response(result.body, {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": `public, max-age=${CACHE_TTL_OK_SECONDS}`,
        "X-Upstream-Content-Type": result.contentType ?? "unknown",
        "X-Upstream-Url": result.finalUrl ?? target,
        ...corsHeaders(),
      },
    });
  } else {
    // Wrap upstream errors; do not leak upstream response bodies verbatim.
    response = new Response(JSON.stringify({
      error: result.error ?? "Upstream fetch failed",
      upstream_url: target,
    }, null, 2), {
      status: result.status,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": `public, max-age=${CACHE_TTL_ERR_SECONDS}`,
        ...corsHeaders(),
      },
    });
  }

  // Async cache write — don't block client response.
  ctx.waitUntil(cache.put(cacheKey, response.clone()));

  return response;
}

// ── Reference Renderer ──────────────────────────────────────
//
// renderPage() returns the entire HTML+JS as a JavaScript template literal.
// In a plain template literal, JS would strip any backslash from `\X` where
// X is not a recognized escape character (n, t, r, b, f, v, 0, ', ", \, x,
// u). That silently mangled regex literals in the embedded JS — `\d` arrived
// at the browser as `d`, `\/\/` as `//` (which lexes as a comment-start and
// breaks the surrounding statement; see PR #4 commit message for the full
// failure mode).
//
// We avoid that bug class by tagging the outer template literal with
// String.raw, which preserves all backslashes verbatim. Regex literals in
// the embedded JS can be written naturally — `/\.(...)$/`, `/\d+/`,
// `/\/\//` — and they deploy as written.
//
// Side effect of String.raw: standard escape sequences (\n, \t, \r, \\,
// etc.) inside the template are NOT processed by the outer-template's
// escape rules. They pass through as the literal characters `\` + `n`. This
// is fine because the only consumer of the resulting string is the browser,
// and the browser's JS parser processes its own escape sequences when it
// parses string literals inside the embedded JS — so a JS source line
// `'hello\nworld'` still ends up as "hello" + newline + "world" at JS
// execution time, regardless of whether the outer template processed \n.
// HTML and CSS in the body don't use backslash escapes, so they're
// unaffected.
//
// If you remove the String.raw tag, you MUST re-apply per-regex
// double-escaping (\\d for \d, \\. for \., \\/ for /) — see PR #4 for the
// pattern. The syntax guard test will catch the script-fails subset of the
// bug class either way; it does not catch functional regex bugs.
//
// Before pushing changes that touch the embedded JS, run:
//
//     node tests/embedded-js-syntax.js
//
// It evaluates the template literal with the same escape processing the
// Worker runtime does, then parses the resulting <script> contents through
// `new Function`. A SyntaxError there means a backslash got eaten and the
// script block won't execute in the browser.

function renderPage(): Response {
  const html = String.raw`<!DOCTYPE html>
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
    <div class="formats">.openthing &nbsp; .opencatalog &nbsp; .catdef</div>
    <input type="file" id="fileInput" accept=".openthing,.opencatalog,.catdef,.json">
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
// Source URL the current document was loaded from (set by bootstrap() when
// the page is opened with ?url=<u>). Used by resolveRenderableLink to
// resolve relative paths inside catalog entries (e.g. "roledefs/x.openthing"
// becomes an absolute URL relative to the catalog's directory). Null when
// the document was loaded via the file picker.
let CATALOG_SOURCE_URL = null;

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

// ── catdef-family shape helpers (additive) ──────────────────
// A namespaced type is "<lowercase-ns>:<CapitalType>" — e.g. roledef:Role,
// catdef:Strategist. Distinguishes catdef-family flat objects from the
// legacy {type:"thing",thing:{...}} envelope and the legacy plain "schema"
// type. When matched and the document carries no .data.items, the whole
// JSON is treated as one thing.
const NAMESPACED_TYPE_RE = /^[a-z][a-z0-9_-]*:[A-Z]/;

// A consumer-spec stamp is a top-level key whose key is lowercase and whose
// value is a semver string — e.g. "roledef": "0.2.0", "catdef": "1.4". These
// are envelope markers, not renderable fields.
function isConsumerSpecStamp(key, val) {
  return typeof val === 'string'
    && /^\d+\.\d+\.\d+$/.test(val)
    && /^[a-z][a-z0-9_-]*$/.test(key);
}

// Tolerant field lookup. Legacy items wrap fields in .fields; catdef-family
// flat items put fields at the top level. Try .fields first then top-level.
function fieldOf(item, name) {
  if (item && item.fields && item.fields[name] !== undefined) return item.fields[name];
  if (item && item[name] !== undefined) return item[name];
  return undefined;
}

// Return the rendering source for an item. Legacy → item.fields. Flat →
// item itself, minus envelope keys (catdef, type, consumer-spec stamps).
function fieldSource(item) {
  if (item && item.fields) return item.fields;
  if (!item || typeof item !== 'object') return {};
  const out = {};
  for (const k in item) {
    if (k === 'catdef' || k === 'type') continue;
    if (isConsumerSpecStamp(k, item[k])) continue;
    out[k] = item[k];
  }
  return out;
}

// ── Renderable-path linkification ────────────────────────────
// File extensions the renderer can render. Path-extension test strips any
// query/fragment first so "https://host/x.opencatalog?ref=main" still counts.
const RENDERABLE_EXT_RE = /\.(openthing|opencatalog|catdef)$/i;

// Given a string field value, return an absolute URL the renderer can load
// (via ?url=...), or null if the value isn't a renderable path. Resolution:
//   - absolute (https://... or //host/...) ending in renderable ext → as-is
//   - relative (no scheme, doesn't start with /) ending in renderable ext
//     AND CATALOG_SOURCE_URL is set → new URL(value, CATALOG_SOURCE_URL)
//   - everything else (incl. /-rooted absolute paths, .md/.json/etc., and
//     relative paths when no CATALOG_SOURCE_URL is known) → null
function resolveRenderableLink(value) {
  if (typeof value !== 'string') return null;
  const v = value.trim();
  if (!v) return null;
  const pathOnly = v.replace(/[?#].*$/, '');
  if (!RENDERABLE_EXT_RE.test(pathOnly)) return null;
  if (/^(https?:)?\/\//i.test(v)) return v;
  if (!v.startsWith('/') && CATALOG_SOURCE_URL) {
    try {
      return new URL(v, CATALOG_SOURCE_URL).toString();
    } catch (_) {
      return null;
    }
  }
  return null;
}

// Render a scalar value as HTML. Wraps in an in-page link when the value is
// a renderable path. Used for individual scalars and inside Array chips.
//   opts.stopPropagation — emit onclick="event.stopPropagation()" on the
//     anchor so a click inside a card doesn't also trigger the card's modal-
//     open handler.
function renderScalarValue(v, opts) {
  opts = opts || {};
  if (v === null || v === undefined) return '';
  if (typeof v === 'object') return esc(JSON.stringify(v));
  if (typeof v === 'string') {
    const link = resolveRenderableLink(v);
    if (link) {
      const stop = opts.stopPropagation ? ' onclick="event.stopPropagation()"' : '';
      return '<a href="?url=' + encodeURIComponent(link) + '"' + stop + '>' + esc(v) + '</a>';
    }
  }
  return esc(String(v));
}

function loadCatdef(json) {
  // Normalize: handle catio envelope or raw catdef
  let product = json.product || {};
  let templates = json.templates || [];
  let items = [];
  let values = {};

  const isNamespacedType = typeof json.type === 'string' && NAMESPACED_TYPE_RE.test(json.type);
  const hasCatalogItems = json.data && Array.isArray(json.data.items);

  if (json.type === 'thing' && json.thing) {
    // Legacy single-thing envelope — wrap in a minimal catalog
    product = { name: json.thing.fields?.Title || json.thing.template || 'Thing', slug: 'thing' };
    templates = [{ name: json.thing.template || 'Thing', field_defs: inferFieldDefs(json.thing.fields) }];
    items = [json.thing];
    values = {};
  } else if (isNamespacedType && !hasCatalogItems) {
    // catdef-family flat single-thing (e.g. roledef:Role). The whole JSON
    // IS the thing; fields live at the top level. Pre-filter the renderable
    // set so envelope keys (catdef, roledef, type) and identity keys (id,
    // name, version - already shown in the page header) don't double-render
    // in the detail view. Note: identity keys are filtered from .fields
    // (which drives field-def-based rendering) but kept at the top level via
    // Object.assign so fieldOf() can still find them for the card title and
    // modal h2 (which prefer the role name over the type string).
    const renderable = {};
    for (const k in json) {
      if (k === 'catdef' || k === 'type') continue;
      if (isConsumerSpecStamp(k, json[k])) continue;
      if (k === 'id' || k === 'name' || k === 'version') continue;
      renderable[k] = json[k];
    }
    product = { name: json.name || json.id || json.type || 'Thing', slug: 'thing' };
    templates = [{ name: json.type, field_defs: inferFieldDefs(renderable) }];
    items = [Object.assign({}, json, { template: json.type, fields: renderable })];
    values = {};
  } else if (json.type === 'schema') {
    // .catdef — schema only, no items
    product = { name: 'Schema Preview', slug: 'schema' };
  } else {
    // .opencatalog (legacy + catdef-family library shapes like roledef:Library)
    // Catalog-level product/name fallback for namespaced libraries that
    // carry their identity at the top level rather than under .product.
    if (!product.name && (isNamespacedType || json.name)) {
      product = Object.assign({ name: json.name || json.id || 'Catalog', slug: 'catalog' }, product);
    }
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

  // Search — uses fieldSource so flat (catdef-family) items are searchable too
  let debounce;
  $('#searchInput').addEventListener('input', e => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      const q = e.target.value.toLowerCase();
      const filtered = items.filter(item => {
        const src = fieldSource(item);
        return Object.values(src).some(v => String(typeof v === 'object' ? JSON.stringify(v) : v).toLowerCase().includes(q));
      });
      renderGrid(filtered);
    }, 200);
  });

  // Sort — uses fieldOf so flat items sort on their top-level keys
  sortSelect.addEventListener('change', () => {
    const field = sortSelect.value;
    const sorted = [...items].sort((a,b) => {
      const va = fieldOf(a, field) ?? '';
      const vb = fieldOf(b, field) ?? '';
      if (typeof va === 'number' && typeof vb === 'number') return va - vb;
      return String(va).localeCompare(String(vb));
    });
    renderGrid(sorted);
  });
}

function inferFieldDefs(thingOrFields) {
  // Accept either a legacy .fields-style object or a flat catdef-family thing.
  // For a flat thing, exclude envelope keys (catdef, type, consumer-spec
  // stamps); the caller (loadCatdef in single-thing mode) is responsible for
  // any further filtering (e.g. identity keys shown in the page header).
  if (!thingOrFields || typeof thingOrFields !== 'object') return [];
  const isFlat = !('fields' in thingOrFields);
  const source = isFlat ? thingOrFields : thingOrFields.fields;
  if (!source || typeof source !== 'object') return [];
  return Object.entries(source).filter(([key, val]) => {
    if (!isFlat) return true;
    if (key === 'catdef' || key === 'type') return false;
    if (isConsumerSpecStamp(key, val)) return false;
    return true;
  }).map(([label, value], i) => {
    let type = 'String';
    if (typeof value === 'number') type = Number.isInteger(value) ? 'Integer' : 'Number';
    else if (typeof value === 'boolean') type = 'Boolean';
    else if (Array.isArray(value)) type = 'Array';
    else if (typeof value === 'object' && value !== null) {
      if (value.value !== undefined && value.unit) type = 'Number';
      else type = 'Object';
    }
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
    const title = fieldOf(item, 'Title')
      || fieldOf(item, 'Name')
      || fieldOf(item, 'name')
      || fieldOf(item, 'title')
      || fieldOf(item, 'id')
      || '(untitled)';
    // Prefer an explicit description-family field; fall back to the legacy
    // top-two-other-fields concat for items that don't carry one. Each
    // value goes through renderScalarValue so renderable paths in the
    // fallback concat become clickable. stopPropagation on those anchors
    // so a click on the link doesn't also fire the card-opens-modal handler.
    let subHtml;
    const desc = fieldOf(item, 'Description') || fieldOf(item, 'description');
    if (desc) {
      subHtml = renderScalarValue(desc, { stopPropagation: true });
    } else {
      const src = fieldSource(item);
      subHtml = Object.entries(src)
        .filter(([k]) => !['Title','Name','title','name','id','Notes','Description','description','Photos'].includes(k))
        .slice(0, 2)
        .map(([k,v]) => renderScalarValue(v, { stopPropagation: true }))
        .join(' · ');
    }
    const card = document.createElement('div');
    card.className = 'card';
    card.innerHTML = '<div class="card-img">📷</div><div class="card-body"><div class="card-title">' + esc(title) + '</div><div class="card-sub">' + subHtml + '</div></div>';
    card.onclick = () => showModal(item);
    grid.appendChild(card);
  });
}

function showModal(item) {
  // Template lookup falls back to inferred field defs from the item itself
  // (works for both legacy {fields:{...}} and flat catdef-family items).
  const template = DATA.templates.find(t => t.name === item.template) || { field_defs: inferFieldDefs(item) };
  let html = '<button class="close" onclick="closeModal()">&times;</button>';
  const headTitle = fieldOf(item, 'Title')
    || fieldOf(item, 'Name')
    || fieldOf(item, 'name')
    || fieldOf(item, 'title')
    || fieldOf(item, 'id')
    || item.template
    || 'Item';
  html += '<h2>' + esc(headTitle) + '</h2>';

  template.field_defs.forEach(fd => {
    const val = fieldOf(item, fd.label);
    if (val === undefined || val === null || val === '') return;
    html += '<div class="field"><div class="field-label">' + esc(fd.label) + '</div><div class="field-value">';
    if (typeof val === 'object' && val !== null && val.value !== undefined && val.unit) {
      html += esc(val.value + ' ' + val.unit);
    } else if (Array.isArray(val)) {
      // Each chip is rendered through renderScalarValue so chip strings that
      // happen to be renderable paths become clickable.
      html += val.map(v => '<span class="chip">' + renderScalarValue(v) + '</span>').join('');
    } else if (typeof val === 'object' && val !== null) {
      html += '<pre style="white-space:pre-wrap;word-break:break-word;font-size:12px;background:var(--bg);padding:8px;border-radius:4px">' + esc(JSON.stringify(val, null, 2)) + '</pre>';
    } else {
      html += renderScalarValue(val);
    }
    html += '</div></div>';
  });

  // Second pass — render any field present on the item but not in the
  // template's field_defs. Uses fieldSource so flat items (no .fields)
  // still surface their top-level keys, minus envelope.
  const extras = fieldSource(item);
  Object.entries(extras).forEach(([k,v]) => {
    if (template.field_defs.some(fd => fd.label === k)) return;
    if (v === undefined || v === null || v === '') return;
    let valHtml;
    if (Array.isArray(v)) {
      valHtml = v.map(x => '<span class="chip">' + renderScalarValue(x) + '</span>').join('');
    } else if (typeof v === 'object' && v !== null) {
      valHtml = esc(JSON.stringify(v));
    } else {
      valHtml = renderScalarValue(v);
    }
    html += '<div class="field"><div class="field-label">' + esc(k) + '</div><div class="field-value">' + valHtml + '</div></div>';
  });

  $('#modal').innerHTML = html;
  $('#modalOverlay').classList.add('open');
}

function closeModal() { $('#modalOverlay').classList.remove('open'); }
$('#modalOverlay').addEventListener('click', e => { if (e.target === $('#modalOverlay')) closeModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// ── URL bootstrap ────────────────────────────────────────────
// If the page is loaded with ?url=<u>, fetch the catdef via the server-side
// /fetch proxy (browser-side cross-origin fetches break for many hosts) and
// hand the parsed JSON to loadCatdef(). When no ?url= is present, the
// existing file-picker behaviour is unchanged.
(async function bootstrap() {
  const params = new URLSearchParams(window.location.search);
  const remoteUrl = params.get('url');
  if (!remoteUrl) return;

  // Replace the file picker with a loading state. Do not show #app until we
  // have data — loadCatdef() will swap visibility on success.
  dropZone.innerHTML =
    '<h2>Loading…</h2>' +
    '<p>Fetching <code>' + esc(remoteUrl) + '</code></p>';

  try {
    const resp = await fetch('/fetch?url=' + encodeURIComponent(remoteUrl));
    if (!resp.ok) {
      let detail = 'HTTP ' + resp.status;
      try {
        const errBody = await resp.json();
        if (errBody && errBody.error) detail = errBody.error;
      } catch (_) { /* upstream wrapper or non-JSON; keep detail */ }
      throw new Error(detail);
    }
    // Remember where the document came from so resolveRenderableLink can
    // turn relative paths (e.g. "roledefs/x.openthing") into absolute URLs.
    // Prefer the upstream's final URL after redirects when /fetch surfaced
    // it, otherwise use what the user requested.
    CATALOG_SOURCE_URL = resp.headers.get('X-Upstream-Url') || remoteUrl;
    const json = await resp.json();
    loadCatdef(json);
  } catch (err) {
    dropZone.innerHTML =
      '<h2 style="color:#dc2626">Could not load</h2>' +
      '<p style="margin-top:8px">' + esc(err && err.message ? err.message : String(err)) + '</p>' +
      '<p class="formats" style="margin-top:16px;word-break:break-all">URL: <code>' + esc(remoteUrl) + '</code></p>' +
      '<p class="formats" style="margin-top:12px"><a href="' + esc(window.location.pathname) + '" style="color:var(--accent)">Open a different file</a></p>';
  }
})();
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
      File extensions: <code>.opencatalog</code> (catalog with data), <code>.openthing</code> (single object), <code>.catdef</code> (schema only)</p>
    </div>

    <div class="section">
      <h2>Report Feedback</h2>
      <p>Agents and humans can submit structured feedback via API:</p>
      <pre>POST /feedback
{
  "type": "gap",
  "agent": "claude-3.5",
  "catdef_version": "1.3",
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
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const { pathname } = url;
    const isRenderHost = url.hostname === "render.catdef.org";

    // CORS preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    // GET / — landing page on catdef.org / www; reference renderer on render.catdef.org
    if (pathname === "/" && request.method === "GET") {
      return isRenderHost ? renderPage() : landingPage();
    }

    // GET /render — L1 reference renderer with file picker
    if (pathname === "/render" && request.method === "GET") {
      return renderPage();
    }

    // GET /fetch?url= — server-side proxy for the URL-loadable renderer
    if (pathname === "/fetch" && request.method === "GET") {
      return handleFetchRoute(request, ctx);
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
          String(body.catdef_version ?? "1.3"),
          String(body.context ?? ""),
          body.field_type ? String(body.field_type) : null,
          message,
          ipHash,
        ).run();

        // Create GitHub issue for public discussion
        const issueUrl = await createGitHubIssue(
          env, publicId, type, severity,
          String(body.agent ?? "unknown"),
          String(body.catdef_version ?? "1.3"),
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
