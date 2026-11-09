import { Hono } from "hono";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { checkVulnerabilities, inspectPackage } from "./registry";

type Env = { MCP_TOKEN: string };

function buildServer() {
  const server = new McpServer({ name: "pkgscout", version: "1.0.0" });

  server.registerTool(
    "inspect_package",
    {
      title: "Inspect an npm package",
      description:
        "Look up an npm package before suggesting or installing it. Returns whether it exists, " +
        "latest version, weekly downloads, last publish date, license, maintainer count and any " +
        "deprecation notice. If the package does not exist, returns similarly named packages. " +
        "Call this for every package you have not verified in this conversation.",
      inputSchema: z.object({
        name: z.string().min(1).max(214).describe("Exact package name, e.g. 'zod' or '@hono/node-server'"),
      }),
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ name }) => {
      const started = Date.now();
      try {
        const report = await inspectPackage(name.trim().toLowerCase());
        console.log(JSON.stringify({ tool: "inspect_package", name, exists: report.exists, ms: Date.now() - started }));
        return {
          content: [{ type: "text", text: JSON.stringify(report, null, 2) }],
          structuredContent: report,
        };
      } catch (err) {
        console.log(JSON.stringify({ tool: "inspect_package", name, error: String(err), ms: Date.now() - started }));
        // Tool errors go back to the model as a result, not as a protocol error,
        // so it can read the message and decide what to do next.
        return {
          content: [{ type: "text", text: `Could not look up ${name}: ${String(err)}` }],
          isError: true,
        };
      }
    },
  );

  server.registerTool(
    "check_vulnerabilities",
    {
      title: "Check npm packages for known vulnerabilities",
      description:
        "Check exact package versions against the npm security advisory database (the one npm audit uses). " +
        "Pass exact versions like '4.17.15', not ranges like '^4.17.0'. One version per package per call.",
      inputSchema: z.object({
        packages: z
          .array(z.object({ name: z.string().min(1), version: z.string().regex(/^\d+\.\d+\.\d+/, "Use an exact version") }))
          .min(1)
          .max(50),
      }),
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ packages }) => {
      const started = Date.now();
      try {
        const results = await checkVulnerabilities(packages);
        const total = Object.values(results).reduce((n, list) => n + list.length, 0);
        console.log(JSON.stringify({ tool: "check_vulnerabilities", count: packages.length, advisories: total, ms: Date.now() - started }));
        return {
          content: [{ type: "text", text: JSON.stringify(results, null, 2) }],
          structuredContent: { results },
        };
      } catch (err) {
        console.log(JSON.stringify({ tool: "check_vulnerabilities", error: String(err), ms: Date.now() - started }));
        return {
          content: [{ type: "text", text: `Advisory lookup failed: ${String(err)}` }],
          isError: true,
        };
      }
    },
  );

  return server;
}

// One handler per isolate. It calls buildServer() for every request,
// which is exactly what a stateless server should do.
const mcp = createMcpHandler(buildServer);

const app = new Hono<{ Bindings: Env }>();

app.get("/", (c) => c.text("pkgscout MCP server. POST /mcp"));

app.use("/mcp", async (c, next) => {
  const header = c.req.header("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!c.env.MCP_TOKEN || !(await safeEqual(token, c.env.MCP_TOKEN))) {
    return c.json({ error: "unauthorized" }, 401);
  }
  await next();
});

app.all("/mcp", (c) => mcp.fetch(c.req.raw));

// Compare hashes so the check takes the same time whatever the input.
async function safeEqual(a: string, b: string) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const x = new Uint8Array(ha);
  const y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

export default app;
