# pkgscout

A small remote MCP server that lets an AI assistant check an npm package before it suggests or installs it.

- `inspect_package`: does it exist, is it deprecated, how many weekly downloads, license, repo. If the name doesn't exist, it tries common typos (swapped or dropped letters) and returns the real packages it finds, with warnings.
- `check_vulnerabilities`: checks exact versions against the npm advisory database, the same one `npm audit` uses.

Built with the MCP TypeScript SDK v2 (2026-07-28 spec), Hono, and Cloudflare Workers. No API keys needed. It runs on the Workers free plan.

## Run it locally

```bash
npm install
echo 'MCP_TOKEN=local-dev-token' > .dev.vars
npm run dev
```

In another terminal:

```bash
npm run try
```

## Deploy

```bash
npx wrangler login
printf %s "$MCP_TOKEN" | npx wrangler secret put MCP_TOKEN   # printf avoids a trailing newline
npm run deploy
```

Then point the test script at it:

```bash
MCP_URL=https://pkgscout.<your-subdomain>.workers.dev/mcp MCP_TOKEN=<your token> npm run try
```

## Connect a client

Claude Code:

```bash
claude mcp add --transport http pkgscout https://pkgscout.<your-subdomain>.workers.dev/mcp \
  --header "Authorization: Bearer <your token>"
```

Cursor (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "pkgscout": {
      "url": "https://pkgscout.<your-subdomain>.workers.dev/mcp",
      "headers": { "Authorization": "Bearer <your token>" }
    }
  }
}
```
