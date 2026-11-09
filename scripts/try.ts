import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

const url = new URL(process.env.MCP_URL ?? "http://localhost:8787/mcp");
const token = process.env.MCP_TOKEN ?? "local-dev-token";

const client = new Client(
  { name: "pkgscout-test", version: "1.0.0" },
  // v2 still talks the 2025 protocol unless you ask for the new one.
  { versionNegotiation: { mode: "auto" } },
);
await client.connect(
  new StreamableHTTPClientTransport(url, {
    requestInit: { headers: { authorization: `Bearer ${token}` } },
  }),
);

const { tools } = await client.listTools();
console.log("tools:", tools.map((t) => t.name).join(", "));

for (const name of ["hono", "reqeusts", "request"]) {
  const res = await client.callTool({ name: "inspect_package", arguments: { name } });
  console.log(`\n--- inspect_package ${name}\n`, (res.content as any)[0].text);
}

const vulns = await client.callTool({
  name: "check_vulnerabilities",
  arguments: { packages: [{ name: "lodash", version: "4.17.15" }, { name: "express", version: "4.17.1" }, { name: "zod", version: "4.1.0" }] },
});
console.log("\n--- check_vulnerabilities\n", (vulns.content as any)[0].text.slice(0, 1500));

const bad = await client.callTool({
  name: "check_vulnerabilities",
  arguments: { packages: [{ name: "lodash", version: "^4.17.0" }] },
});
console.log("\n--- range instead of exact version\n", JSON.stringify(bad).slice(0, 400));

await client.close();
