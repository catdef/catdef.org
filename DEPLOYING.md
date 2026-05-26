# Deploying catdef.org

The catdef.org Cloudflare Worker auto-deploys on push to `main` via the GitHub Actions workflow at [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml). No manual `wrangler deploy` required for standard commits.

## Required repository secret

The workflow needs **one** secret:

| Name | Purpose |
|---|---|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API token authorising `wrangler deploy` |

### Creating the token

1. Sign in to the Cloudflare dashboard
2. Go to **My Profile → API Tokens → Create Token**
3. Pick the **"Edit Cloudflare Workers"** template (it grants the right combination of scopes — `Account: Workers Scripts:Edit`, `Account: Workers KV Storage:Edit`, `Account: D1:Edit`, `Account: Account Settings:Read`, `User: User Details:Read`, `Zone: Workers Routes:Edit`)
4. Restrict the token to the catdef.org zone if your account hosts multiple zones
5. Set an expiry (recommended: 1 year)
6. Copy the token immediately — Cloudflare shows it once

### Adding it to the repo

```
gh secret set CLOUDFLARE_API_TOKEN --repo catdef/catdef.org
```

Paste the token when prompted. Or use the GitHub web UI: **Settings → Secrets and variables → Actions → New repository secret**.

## Rotating the token

If the token leaks, expires, or its scopes need to change:

1. Create a new token via the steps above
2. Run `gh secret set CLOUDFLARE_API_TOKEN --repo catdef/catdef.org` with the new value (this overwrites the old secret)
3. Trigger a no-op deploy to confirm the new token works (push an empty commit, or run `gh workflow run deploy.yml`)
4. **After confirmation**, revoke the old token in the Cloudflare dashboard

## Manual deploy (fallback)

If GitHub Actions is unavailable (outage, mis-configuration, etc.), deploy locally:

```
wrangler deploy
```

Requires the operator to be logged in (`wrangler login`) with an account that has Workers edit access on the catdef.org zone.

## Other secrets used by the Worker (not by the deploy workflow)

The Worker process itself uses these secrets, set via `wrangler secret put <NAME>`:

| Name | Purpose | Status |
|---|---|---|
| `GITHUB_TOKEN` | GitHub PAT for raising the public-repo read rate limit on `catdef_list_decisions` and `refresh-counter` from 60/hr to 5000/hr. Per CA-013 Call 1, the old `issues: write` scope is no longer required — `public_repo` read suffices. | Set, but may be expired; the Worker code falls back to unauthenticated requests on 401 (CA-011). Rotate via `wrangler secret put GITHUB_TOKEN` to restore the higher rate limit. |

## D1 migrations

Schema changes live in [`migrations/`](migrations/). Apply against production with:

```
wrangler d1 execute catdef-feedback --remote --yes --file=migrations/0NNN_<name>.sql
```

Always run migrations **before** the code that depends on them deploys. The GitHub Actions deploy workflow does not auto-run migrations.

## Verifying a deploy

After the Action completes (or after a manual `wrangler deploy`), confirm the new code is live:

```
curl -s -X POST https://catdef.org/mcp -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize"}' | jq .result.serverInfo
```

The `serverInfo.version` field is bumped in `src/mcp/server.ts` with each server-surface release. Compare against the commit you expected to deploy.
