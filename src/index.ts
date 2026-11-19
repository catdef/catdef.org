/**
 * catdef.org — The open standard for catalog definitions.
 *
 * Cloudflare Worker serving:
 *   GET  /           — landing page (catdef.org); reference renderer on render.catdef.org
 *   GET  /render     — L1 reference renderer with file picker
 *   GET  /fetch?url= — server-side proxy that fetches a remote catdef and returns JSON
 *                      (used by the renderer's ?url= bootstrap; SSRF-guarded; size-capped; cached)
 *   GET  /spec       — redirect to GitHub spec
 *   POST /feedback   — legacy structured feedback intake (humans + agents); now
 *                      mints CA-NNN per CA-009 and routes through the unified queue
 *                      shared with /mcp's catdef_report_feedback tool
 *   GET  /feedback   — public feed (legacy CDF-NNNN + new CA-NNN)
 *   GET  /feedback/:id — single feedback item (accepts CDF-NNNN and CA-NNN)
 *   POST /mcp        — canonical AI-peer MCP surface (per CA-008 Track D)
 *                      JSON-RPC 2.0 over HTTP; three-tier bearer auth;
 *                      see proposals/catdef-org-mcp-canonical-surface.md
 *   POST /mcp/admin/refresh-counter — elevated tier; re-syncs CA-NNN counter
 *                                      against the live decisions/ directory
 */

import { handleMcpRequest } from "./mcp/server";
import { resolveAuth, tierAtLeast } from "./mcp/auth";
import { adminRefreshCounter } from "./mcp/tools";
import { allocateCaNnn } from "./mcp/counter";

export interface Env {
  DB: D1Database;
  // Secret: GitHub PAT used by the canonical-surface MCP tools
  // (catdef_list_decisions, refresh-counter) to raise the public-repo
  // read rate limit from 60/hr to 5000/hr. The createGitHubIssue
  // auto-creation on legacy POST /feedback was sunset by CA-013 Call 1,
  // so the token's old `issues: write` scope is no longer required;
  // public_repo read (the default for most fine-grained PATs) suffices.
  GITHUB_TOKEN: string;
}

const SPEC_URL = "https://github.com/catdef/catdef-spec/blob/main/CATDEF_SPEC.md";
const REPO_URL = "https://github.com/catdef/catdef-spec";

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

// Per decisions/CA-009.md (CA-NNN namespace unification), new feedback gets
// CA-NNN identifiers from the unified counter. CDF-NNNN is sunset; legacy
// rows persist as historical references. The counter is shared with the
// /mcp tool surface via src/mcp/counter.ts so both submission paths
// (legacy POST /feedback and tools/call catdef_report_feedback) allocate
// from the same sequence.
async function generatePublicId(db: D1Database): Promise<string> {
  return await allocateCaNnn({ DB: db });
}

async function checkRateLimit(db: D1Database, ipHash: string): Promise<boolean> {
  const cutoff = new Date(Date.now() - RATE_WINDOW_SECONDS * 1000).toISOString();
  const result = await db.prepare(
    "SELECT COUNT(*) as count FROM feedback WHERE ip_hash = ? AND created_at > ?"
  ).bind(ipHash, cutoff).first<{ count: number }>();
  return (result?.count ?? 0) < RATE_LIMIT;
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
// Per decisions/CA-016.md, the renderer source lives in catdef-spec/renderer/
// (publicly addressable canonical artifact, parallel to conformance/ and
// canonical/). This Worker fetches the source from GitHub raw at request time
// with Cloudflare edge caching; render.catdef.org always serves the latest
// renderer pushed to catdef-spec's main branch.
//
// Why fetch at runtime instead of vendoring or submoduling:
//   - No build step changes; matches existing src/mcp/resources.ts pattern
//   - No SHA-pinning ceremony for renderer-only updates
//   - Cloudflare edge cache (5-minute TTL) keeps tail-latency low
//   - Single source of truth: catdef-spec main is canonical
//
// Fallback: if the upstream fetch fails (network blip, GitHub outage), a
// minimal error page surfaces the canonical source URL so users can still
// download and open the renderer locally.

const RENDERER_URL = "https://raw.githubusercontent.com/catdef/catdef-spec/refs/heads/release/renderer/index.html";
const RENDERER_CACHE_TTL_SECONDS = 300;

async function renderPage(): Promise<Response> {
  const upstream = await fetch(RENDERER_URL, {
    cf: { cacheTtl: RENDERER_CACHE_TTL_SECONDS, cacheEverything: true },
  });
  if (!upstream.ok) {
    return new Response(rendererFallbackHtml(upstream.status), {
      status: 502,
      headers: { "Content-Type": "text/html;charset=UTF-8" },
    });
  }
  return new Response(upstream.body, {
    headers: {
      "Content-Type": "text/html;charset=UTF-8",
      "Cache-Control": `public, max-age=${RENDERER_CACHE_TTL_SECONDS}`,
    },
  });
}

function rendererFallbackHtml(upstreamStatus: number): string {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>catdef — Renderer Unavailable</title></head><body style="font-family:system-ui;padding:2rem;max-width:600px;margin:0 auto;line-height:1.5"><h1>Renderer temporarily unavailable</h1><p>The reference renderer source could not be fetched (upstream status ${upstreamStatus}). The canonical source lives at <a href="https://github.com/catdef/catdef-spec/tree/main/renderer">github.com/catdef/catdef-spec/tree/main/renderer</a> — you can download <code>index.html</code> and open it locally to view catdef artifacts.</p></body></html>`;
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
    .container { max-width: 720px; width: 100%; }
    h1 { font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem; }
    h1 span { color: #58a6ff; }
    .tagline { color: #8b949e; font-size: 1.2rem; margin-bottom: 2rem; }
    .description { line-height: 1.7; margin-bottom: 2rem; color: #c9d1d9; }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .cta { display: flex; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap; }
    .cta a {
      padding: 0.7rem 1.3rem; border-radius: 6px;
      font-size: 0.95rem; font-weight: 600; transition: all 0.2s;
    }
    .cta a.primary { background: #238636; color: #fff; border: 1px solid #2ea043; }
    .cta a.primary:hover { background: #2ea043; text-decoration: none; }
    .cta a.secondary { background: #21262d; color: #e6edf3; border: 1px solid #30363d; }
    .cta a.secondary:hover { border-color: #58a6ff; text-decoration: none; }
    .links { display: flex; gap: 1.5rem; margin-bottom: 3rem; flex-wrap: wrap; font-size: 0.9rem; }
    .pitch { display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; margin-bottom: 3rem; }
    @media (max-width: 600px) { .pitch { grid-template-columns: 1fr; } }
    .card {
      background: #161b22; border: 1px solid #30363d; border-radius: 8px;
      padding: 1.25rem;
    }
    .card h3 { font-size: 1rem; color: #e6edf3; margin-bottom: 0.5rem; }
    .card p { color: #8b949e; font-size: 0.92rem; line-height: 1.55; }
    .card .examples { color: #c9d1d9; font-size: 0.88rem; margin-top: 0.5rem; }
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
      A key concept is that catalogs are recursive, so that a catalog may contain sub-catalogs.
      Any conforming runtime can read, write, and render valid OpenCatalogs and OpenThings.
      The catdef spec also describes how to serialize both catalogs and things into single files,
      which may then be transported and shared.
    </p>

    <div class="cta">
      <a class="primary" href="${REPO_URL}">View on GitHub</a>
      <a class="secondary" href="https://render.catdef.org/?url=https%3A%2F%2Fraw.githubusercontent.com%2Fcatdef%2Fcatdef-spec%2Fmain%2Fcanonical%2Friverside-heritage-reference-v1.4.opencatalog">Try the Reference Renderer</a>
    </div>
    <div class="links">
      <a href="${SPEC_URL}">Read the Spec</a>
      <a href="${REPO_URL}/tree/main/conformance">Test Suite</a>
      <a href="/feedback">Feedback Feed</a>
    </div>

    <div class="pitch">
      <div class="card">
        <h3>For any collection</h3>
        <p>One format, every domain. Whatever you can describe, you can catalog.</p>
        <p class="examples">Museum artifacts · vintage watches · wine cellars · magazine archives · artist portfolios · field-guide species · concert calendars · photo timelines.</p>
      </div>

      <div class="card">
        <h3>AI-native authoring</h3>
        <p>An AI that can see a photograph can write a catdef. Schemas, data, and presentation are all expressed in one declarative format that any model can produce and any runtime can consume — zero context backfill required.</p>
      </div>

      <div class="card">
        <h3>One file. Complete product.</h3>
        <p>Schema, data, and presentation in a single <code>.opencatalog</code> file. Drop it into any conformant renderer and a working application comes out the other side. Transportable, shareable, self-contained.</p>
      </div>

      <div class="card">
        <h3>The test suite is the standard</h3>
        <p>164 conformance tests define what catdef means. Anyone can build a renderer; if it passes the tests, it's catdef. No vendor, no lock-in, no proprietary extensions required.</p>
      </div>
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
  "agent": "claude-sonnet-4-6",
  "catdef_version": "1.4",
  "context": "Cataloging a wine collection",
  "field_type": "Date",
  "message": "No way to express vintage year ranges",
  "severity": "minor"
}</pre>
    </div>

    <div class="section">
      <h2>MCP — the canonical AI-peer surface</h2>
      <p>An MCP server is live at <code>https://catdef.org/mcp</code> (streamable-HTTP transport, JSON-RPC 2.0). AI peers
      can read the full spec as MCP resources (e.g. <code>catdef://spec/CATDEF_SPEC.md</code>), ground themselves with
      <code>catdef_lookup</code> and <code>catdef_list_decisions</code>, and (with a self-serve api-key) file structured
      feedback via <code>catdef_report_feedback</code>. The maintainer/strategist seats use elevated keys for queue triage.
      See <a href="${REPO_URL}/blob/main/proposals/catdef-org-mcp-canonical-surface.md">the canonical-surface proposal</a> for the full surface description.</p>
    </div>

    <div class="section">
      <h2>Claude plugin</h2>
      <p>catdef ships as a plugin for Claude: three skills (validate, scaffold, extract) plus the catdef.org MCP connector.
      Install it from <a href="https://claude.ai/plugins/id/f94e53de-df9b-4ef4-b044-ba2ec836683b@anthropic-plugin-directory">Anthropic's plugin directory</a> — Community tier, scanned by Anthropic.</p>
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

        // Generate public ID (CA-NNN per CA-009, via shared allocator)
        const publicId = await generatePublicId(env.DB);

        // Insert. Status defaults to 'received'; private at submission per CA-008
        // privacy posture (formalized in CA-013 Call 1 — submission method no
        // longer determines privacy state).
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

        // Per CA-013 Call 1: the legacy createGitHubIssue auto-creation is
        // sunset. Submissions are private at submission for all paths (HTML
        // form AND MCP); public visibility arrives only via curation (a
        // CA-NNN decision artifact citing the item, or elevated-tier
        // catdef_attach_decision with make_public:true). Existing GitHub
        // issues from past submissions remain as historical record.

        return json({
          ok: true,
          id: publicId,
          message: "Feedback received. Triage status is queryable via the catdef_get_feedback_status MCP tool (with the api-key used to submit) or via GET /feedback/" + publicId + ".",
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

    // GET /feedback/:id — single feedback item (CA-NNN or legacy CDF-NNNN)
    const feedbackMatch = pathname.match(/^\/feedback\/((?:CA-\d{3,}|CDF-\d+))$/);
    if (feedbackMatch && request.method === "GET") {
      const result = await env.DB.prepare(
        "SELECT public_id, type, severity, agent, catdef_version, context, field_type, message, created_at, status, decision_id FROM feedback WHERE public_id = ?"
      ).bind(feedbackMatch[1]).first();
      if (!result) {
        return json({ error: "Not found" }, 404);
      }
      return json(result);
    }

    // POST /mcp — canonical AI-peer MCP surface per CA-008 Track D
    if (pathname === "/mcp" && request.method === "POST") {
      return handleMcpRequest(request, env);
    }

    // POST /mcp/admin/refresh-counter — elevated tier only; re-syncs CA-NNN
    // counter against the live catdef-spec/decisions/ directory per CA-009 Dir 2.
    if (pathname === "/mcp/admin/refresh-counter" && request.method === "POST") {
      const auth = await resolveAuth(request, env);
      if (!auth) return json({ error: "Invalid Authorization" }, 401);
      if (!tierAtLeast(auth, "elevated")) {
        return json({ error: "Elevated tier required" }, 403);
      }
      try {
        const out = await adminRefreshCounter(env);
        return json({ ok: true, counter: out });
      } catch (e) {
        return json({ ok: false, error: e instanceof Error ? e.message : "Refresh failed" }, 500);
      }
    }

    return json({ error: "Not found" }, 404);
  },
};
