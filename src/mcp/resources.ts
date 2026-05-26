// MCP resources for catdef.org/mcp. Implements the `catdef://spec/*` URI
// scheme from proposals/catdef-org-mcp-canonical-surface.md §A.2.
//
// Storage strategy: fetch spec content from GitHub raw with edge caching
// (Cloudflare automatically caches fetch() responses at the PoP). This keeps
// content always-fresh against the canonical repo without bundling a vendored
// snapshot into the Worker.
//
// Resource URIs:
//   catdef://spec                                — default landing (CATDEF_SPEC.md)
//   catdef://spec/CATDEF_SPEC.md
//   catdef://spec/CATIO_SPEC.md
//   catdef://spec/MCP_REFERENCE.md
//   catdef://spec/CONTRIBUTING.md
//   catdef://spec/CLAUDE.md
//   catdef://spec/canonical/<filename>
//   catdef://spec/decisions/<CA-NNN>             — resolves to decisions/CA-NNN.md
//   catdef://spec/proposals/<slug>               — resolves to proposals/<slug>.md
//   catdef://spec/conformance/index               — synthetic; lists test files
//
// Resources beyond this set return RPC_NOT_FOUND.

import type { McpResource, McpResourceContents } from "./types";

const GITHUB_RAW_BASE = "https://raw.githubusercontent.com/catdef/catdef-spec/main";
const GITHUB_API_BASE = "https://api.github.com/repos/catdef/catdef-spec/contents";

const RESOURCE_MAP: Record<string, { path: string; mime: string; description: string }> = {
  "catdef://spec": {
    path: "CATDEF_SPEC.md",
    mime: "text/markdown",
    description: "catdef substrate specification (default landing)",
  },
  "catdef://spec/CATDEF_SPEC.md": {
    path: "CATDEF_SPEC.md",
    mime: "text/markdown",
    description: "catdef substrate specification",
  },
  "catdef://spec/CATIO_SPEC.md": {
    path: "CATIO_SPEC.md",
    mime: "text/markdown",
    description: "catdef bundled-transport specification (CATIO)",
  },
  "catdef://spec/MCP_REFERENCE.md": {
    path: "MCP_REFERENCE.md",
    mime: "text/markdown",
    description: "MCP reference design for catdef catalogs",
  },
  "catdef://spec/CONTRIBUTING.md": {
    path: "CONTRIBUTING.md",
    mime: "text/markdown",
    description: "Contributor guide",
  },
  "catdef://spec/CLAUDE.md": {
    path: "CLAUDE.md",
    mime: "text/markdown",
    description: "catdef Maintainer Operating Manual (AI-maintainer role)",
  },
  "catdef://spec/canonical/riverside-heritage-reference-v1.4.opencatalog": {
    path: "canonical/riverside-heritage-reference-v1.4.opencatalog",
    mime: "application/vnd.opencatalog+zip",
    description: "Canonical reference catalog (v1.4)",
  },
  "catdef://spec/canonical/README.md": {
    path: "canonical/README.md",
    mime: "text/markdown",
    description: "Canonical reference catalog README",
  },
};

/**
 * Stable list of resources advertised at /mcp resources/list.
 */
export function listResources(): McpResource[] {
  return Object.entries(RESOURCE_MAP).map(([uri, info]) => ({
    uri,
    name: uri.replace(/^catdef:\/\/spec\/?/, "") || "CATDEF_SPEC.md",
    description: info.description,
    mimeType: info.mime,
  }));
}

/**
 * Resolve a `catdef://spec/<path>` URI to its content. Handles:
 *   - Stable resources from RESOURCE_MAP
 *   - Dynamic CA-NNN decisions at catdef://spec/decisions/CA-NNN
 *   - Dynamic proposal slugs at catdef://spec/proposals/<slug>
 *
 * Returns null for unknown URIs (caller maps to RPC_NOT_FOUND).
 */
export async function readResource(uri: string): Promise<McpResourceContents | null> {
  // Stable resources
  const stable = RESOURCE_MAP[uri];
  if (stable) {
    return await fetchAndWrap(uri, stable.path, stable.mime);
  }

  // Dynamic: catdef://spec/decisions/CA-NNN
  const decisionMatch = /^catdef:\/\/spec\/decisions\/(CA-\d{3,})$/.exec(uri);
  if (decisionMatch) {
    return await fetchAndWrap(uri, `decisions/${decisionMatch[1]}.md`, "text/markdown");
  }

  // Dynamic: catdef://spec/proposals/<slug>
  const proposalMatch = /^catdef:\/\/spec\/proposals\/([a-z0-9-]+)$/.exec(uri);
  if (proposalMatch) {
    return await fetchAndWrap(uri, `proposals/${proposalMatch[1]}.md`, "text/markdown");
  }

  // Synthetic: catdef://spec/conformance/index — list of test files
  if (uri === "catdef://spec/conformance/index") {
    return await listConformanceTests(uri);
  }

  return null;
}

async function fetchAndWrap(
  uri: string,
  repoPath: string,
  mime: string,
): Promise<McpResourceContents | null> {
  const resp = await fetch(`${GITHUB_RAW_BASE}/${repoPath}`, {
    cf: { cacheTtl: 300, cacheEverything: true },
  });
  if (!resp.ok) {
    return null;
  }

  // Binary content (like .opencatalog ZIP) → base64; text → text
  if (mime.startsWith("text/") || mime.includes("json")) {
    const text = await resp.text();
    return { uri, mimeType: mime, text };
  }

  const buf = await resp.arrayBuffer();
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const b64 = btoa(binary);
  return { uri, mimeType: mime, blob: b64 };
}

async function listConformanceTests(uri: string): Promise<McpResourceContents | null> {
  const resp = await fetch(`${GITHUB_API_BASE}/conformance`, {
    headers: {
      "Accept": "application/vnd.github+json",
      "User-Agent": "catdef-org-mcp-resources",
      "X-GitHub-Api-Version": "2022-11-28",
    },
    cf: { cacheTtl: 300, cacheEverything: true },
  });
  if (!resp.ok) return null;
  const entries = await resp.json() as Array<{ name: string; type: string; download_url: string }>;
  const tests = entries
    .filter(e => e.type === "file" && e.name.startsWith("test_") && e.name.endsWith(".py"))
    .map(e => ({ name: e.name, download_url: e.download_url }));
  const body = JSON.stringify({
    description: "catdef conformance suite test files (pytest)",
    note: "The full pytest suite is in catdef-spec/conformance/; this is an index.",
    tests,
  }, null, 2);
  return { uri, mimeType: "application/json", text: body };
}
