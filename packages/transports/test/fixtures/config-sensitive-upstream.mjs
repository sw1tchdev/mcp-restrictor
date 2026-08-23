import { join } from "node:path";
import { createInterface } from "node:readline";

const expectedCwd =
  process.argv[2] === "cwd-from-project-root"
    ? join(process.argv[4], "server-cwd")
    : process.argv[2];

const expectedApiKey = process.env.EXPECTED_API_KEY ?? "secret";
if (process.env.API_KEY !== expectedApiKey || process.cwd() !== expectedCwd) {
  process.exit(1);
}

for (const [index, name] of [
  [4, "PROJECT_DIR"],
  [5, "PROJECT_TAG"],
  [6, "FORWARDED"],
]) {
  if (process.argv[index] !== undefined && process.env[name] !== process.argv[index]) {
    process.exit(1);
  }
}

const lines = createInterface({ input: process.stdin });

if (process.argv[3] === "stderr") process.stderr.write(process.env.API_KEY);

for await (const line of lines) {
  const request = JSON.parse(line);

  if (request.method === "initialize") {
    respond(request.id, {
      protocolVersion: request.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "config-sensitive-fixture", version: "1.0.0" },
    });
    continue;
  }

  if (request.method === "tools/list") {
    const mode = process.argv[3];
    const cursor = request.params?.cursor;
    if (mode === "paginated" && cursor !== "page-2") {
      respond(request.id, {
        tools: [{ name: "write_file", inputSchema: { type: "object" } }],
        nextCursor: "page-2",
      });
      continue;
    }
    if (mode === "paginated" && cursor === "page-2") {
      respond(request.id, {
        tools: [{ name: "read_file", inputSchema: { type: "object" } }],
      });
      continue;
    }
    if (mode === "duplicate" && cursor !== "page-2") {
      respond(request.id, {
        tools: [{ name: "read_file", inputSchema: { type: "object" } }],
        nextCursor: "page-2",
      });
      continue;
    }
    if (mode === "duplicate" && cursor === "page-2") {
      respond(request.id, {
        tools: [{ name: "read_file", inputSchema: { type: "object" } }],
      });
      continue;
    }
    respond(request.id, {
      tools: [{ name: "read_file", inputSchema: { type: "object" } }],
    });
    continue;
  }

  if (request.method === "tools/call") {
    respond(request.id, {
      content: [{ type: "text", text: `configured upstream:${request.params?.name}` }],
    });
  }
}

function respond(id, result) {
  process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id, result })}\n`);
}
