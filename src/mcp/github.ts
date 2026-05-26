// Shared GitHub API helper for catdef.org/mcp.
//
// Wraps GitHub contents-API calls with a single resilience pattern:
//   1. If a token is provided, try with auth first
//   2. On 401 (token invalid/expired/revoked), retry without auth
//   3. Surface a clear error if both paths fail
//
// Unauthenticated requests to public-repo contents endpoints work up to
// the GitHub IP rate limit (60/hr for unauth, 5000/hr for auth). The
// retry-without-token path keeps the server functional when the configured
// GITHUB_TOKEN secret expires; rotating the token restores the higher limit.

const REPO = "catdef/catdef-spec";
const USER_AGENT = "catdef-org-mcp";

/**
 * Fetch a GitHub contents-API endpoint with 401-resilient retry.
 * Returns the parsed JSON body on success; throws with a clear
 * message if both auth and unauth attempts fail.
 *
 * `path` is the path under /repos/{owner}/{repo}/contents/, e.g.
 * "decisions" or "conformance".
 */
export async function githubContents<T = unknown>(
  path: string,
  token: string | undefined,
): Promise<T> {
  const url = `https://api.github.com/repos/${REPO}/contents/${path}`;

  if (token) {
    const authed = await fetch(url, {
      headers: githubHeaders(token),
      cf: { cacheTtl: 300, cacheEverything: true },
    });
    if (authed.ok) {
      return await authed.json() as T;
    }
    // 401 → token problem (invalid/expired/revoked); fall through to unauth
    // Other non-OK status → surface immediately, retry won't help
    if (authed.status !== 401) {
      throw new Error(`GitHub API ${authed.status} on contents/${path}`);
    }
  }

  // Unauthenticated retry (or first attempt if no token)
  const anon = await fetch(url, {
    headers: githubHeaders(undefined),
    cf: { cacheTtl: 300, cacheEverything: true },
  });
  if (anon.ok) {
    return await anon.json() as T;
  }
  if (anon.status === 403 || anon.status === 429) {
    throw new Error(
      `GitHub API ${anon.status} on contents/${path} — IP rate limit exceeded. Provision a valid GITHUB_TOKEN secret on the Worker to raise the limit from 60/hr to 5000/hr.`,
    );
  }
  throw new Error(
    `GitHub API ${anon.status} on contents/${path} (unauthenticated; the configured GITHUB_TOKEN may have expired — verify or rotate).`,
  );
}

function githubHeaders(token: string | undefined): HeadersInit {
  const h: Record<string, string> = {
    "Accept": "application/vnd.github+json",
    "User-Agent": USER_AGENT,
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (token) {
    h["Authorization"] = `Bearer ${token}`;
  }
  return h;
}
