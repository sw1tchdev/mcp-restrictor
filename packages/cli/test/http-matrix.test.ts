import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  certificatePath,
  exercise,
  fetchWithCa,
  privateKeyPath,
  startCli,
  startHttpFixture,
} from "./helpers.js";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const upstreamFixture = resolve(testDirectory, "fixtures/upstream.mjs");

let httpFixture: Awaited<ReturnType<typeof startHttpFixture>>;
let httpsFixture: Awaited<ReturnType<typeof startHttpFixture>>;
let certificate: Buffer;

beforeAll(async () => {
  certificate = await readFile(certificatePath);
  httpFixture = await startHttpFixture();
  httpsFixture = await startHttpFixture({
    tls: {
      cert: certificate,
      key: await readFile(privateKeyPath),
    },
    expectedAuthorization: "Bearer upstream-secret",
  });
});

afterAll(async () => {
  await Promise.all([httpFixture.close(), httpsFixture.close()]);
});

describe("HTTP input transport matrix", () => {
  const routes: Array<{
    route: string;
    listener: "http" | "https";
    upstream: string[] | (() => string[]);
    env?: () => Record<string, string>;
    downstreamToken?: string;
  }> = [
    {
      route: "HTTP -> stdio",
      listener: "http",
      upstream: ["--", process.execPath, upstreamFixture],
    },
    {
      route: "HTTP -> HTTP",
      listener: "http",
      upstream: () => ["--upstream-http", httpFixture.url],
    },
    {
      route: "HTTP -> HTTPS",
      listener: "http",
      upstream: () => [
        "--upstream-http",
        httpsFixture.url,
        "--upstream-bearer-token-env",
        "MCP_TOKEN",
      ],
      env: () => ({
        MCP_TOKEN: "upstream-secret",
        NODE_EXTRA_CA_CERTS: certificatePath,
      }),
    },
    {
      route: "HTTPS -> stdio",
      listener: "https",
      upstream: ["--", process.execPath, upstreamFixture],
    },
    {
      route: "HTTPS -> HTTP",
      listener: "https",
      upstream: () => ["--upstream-http", httpFixture.url],
    },
    {
      route: "HTTPS -> HTTPS",
      listener: "https",
      upstream: () => [
        "--upstream-http",
        httpsFixture.url,
        "--upstream-bearer-token-env",
        "MCP_TOKEN",
      ],
      env: () => ({
        MCP_TOKEN: "upstream-secret",
        NODE_EXTRA_CA_CERTS: certificatePath,
      }),
      downstreamToken: "downstream-secret",
    },
  ];

  it.each(routes)("$route", async ({ listener, upstream, env, downstreamToken }) => {
    const proxy = await startCli(
      typeof upstream === "function" ? upstream() : upstream,
      listener,
      env ? { env: env() } : {},
    );
    try {
      expect(new URL(proxy.url).pathname).toBe("/mcp");
      expect(new URL(proxy.url).port).not.toBe("0");
      const result = await exercise(
        new StreamableHTTPClientTransport(new URL(proxy.url), {
          ...(listener === "https" ? { fetch: fetchWithCa(certificate) } : {}),
          ...(downstreamToken ? { authProvider: { token: async () => downstreamToken } } : {}),
        }),
      );
      expect(result.sessionId).toBeTruthy();
    } finally {
      await proxy.close();
    }
  });

  it("isolates HTTP sessions and their stdio upstream processes", async () => {
    const proxy = await startCli(["--", process.execPath, upstreamFixture]);
    try {
      const first = await exercise(new StreamableHTTPClientTransport(new URL(proxy.url)));
      const second = await exercise(new StreamableHTTPClientTransport(new URL(proxy.url)));
      expect(first.sessionId).toBeTruthy();
      expect(second.sessionId).toBeTruthy();
      expect(first.sessionId).not.toBe(second.sessionId);
      expect(first.instanceId).not.toBe(second.instanceId);
    } finally {
      await proxy.close();
    }
  });

  it("rejects requests from foreign browser origins", async () => {
    const proxy = await startCli(["--", process.execPath, upstreamFixture]);
    try {
      const response = await fetch(proxy.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "http://evil.example",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-06-18",
            capabilities: {},
            clientInfo: { name: "origin-test", version: "1.0.0" },
          },
        }),
      });
      expect(response.status).toBe(403);
    } finally {
      await proxy.close();
    }
  });

  it("does not start an upstream for a sessionless non-initialize POST", async () => {
    const marker = "UNEXPECTED_UPSTREAM_START";
    const proxy = await startCli([
      "--",
      process.execPath,
      "-e",
      `process.stderr.write('${marker}\\n');setTimeout(()=>{},500)`,
    ]);
    try {
      const response = await fetch(proxy.url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
      });
      expect(response.status).toBe(400);
      expect(proxy.stderr()).not.toContain(marker);
    } finally {
      await proxy.close();
    }
  });

  it("accepts a one-element initialization batch supported by the SDK", async () => {
    const proxy = await startCli(["--", process.execPath, upstreamFixture]);
    try {
      const response = await fetch(proxy.url, {
        method: "POST",
        headers: {
          accept: "application/json, text/event-stream",
          "content-type": "application/json",
        },
        body: JSON.stringify([
          {
            jsonrpc: "2.0",
            id: 1,
            method: "initialize",
            params: {
              protocolVersion: "2025-06-18",
              capabilities: {},
              clientInfo: { name: "batch-test", version: "1.0.0" },
            },
          },
        ]),
      });
      expect(response.status).toBe(200);
      expect(response.headers.get("mcp-session-id")).toBeTruthy();
    } finally {
      await proxy.close();
    }
  });

  it("limits request bodies in established legacy sessions", async () => {
    const proxy = await startCli(["--", process.execPath, upstreamFixture]);
    const transport = new StreamableHTTPClientTransport(new URL(proxy.url));
    const client = new Client({ name: "body-limit-test", version: "1.0.0" });
    try {
      await client.connect(transport);
      expect(transport.sessionId).toBeTruthy();
      const response = await fetch(proxy.url, {
        method: "POST",
        headers: {
          accept: "application/json, text/event-stream",
          "content-type": "application/json",
          "mcp-session-id": transport.sessionId!,
        },
        body: Buffer.alloc(10 * 1024 * 1024 + 1, 0x20),
      });

      expect(response.status).toBe(413);
    } finally {
      await client.close();
      await proxy.close();
    }
  });
});
