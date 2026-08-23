import { randomUUID } from "node:crypto";
import { createInterface } from "node:readline";

const lines = createInterface({ input: process.stdin });
const instanceId = randomUUID();

for await (const line of lines) {
  const request = JSON.parse(line);

  if (request.method === "initialize") {
    respond(request.id, {
      protocolVersion: request.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "fixture", version: "1.0.0" },
    });
    continue;
  }

  if (request.method === "tools/list") {
    respond(request.id, {
      tools: [
        { name: "read_file", description: "Read a file", inputSchema: { type: "object" } },
        { name: "write_file", description: "Write a file", inputSchema: { type: "object" } },
        { name: "delete_file", description: "Delete a file", inputSchema: { type: "object" } },
      ],
    });
    continue;
  }

  if (request.method === "tools/call") {
    respond(request.id, {
      content: [{ type: "text", text: `upstream:${request.params.name}:${instanceId}` }],
    });
  }
}

function respond(id, result) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
}
