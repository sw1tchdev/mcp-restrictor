import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";

serveStdio(() => {
  const instanceId = randomUUID();
  const server = new McpServer({
    name: "dual-era-fixture",
    version: "1.0.0",
  });
  for (const name of ["read_file", "write_file", "delete_file"]) {
    server.registerTool(name, {}, async () => ({
      content: [{ type: "text", text: `upstream:${name}:${instanceId}` }],
    }));
  }
  return server;
});
