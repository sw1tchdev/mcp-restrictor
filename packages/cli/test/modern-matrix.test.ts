import { readFile } from "node:fs/promises";
import { once } from "node:events";
import { createServer as createHttpServer } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  Client,
  PROTOCOL_VERSION_META_KEY,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  certificatePath,
  exercise,
  fetchWithCa,
  privateKeyPath,
  startCli,
  startDualEraHttpFixture,
} from "./helpers.js";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(testDirectory, "../../..");
const cli = resolve(projectRoot, "packages/cli/dist/index.js");
const policy = resolve(testDirectory, "fixtures/policy.yaml");
const dualEraUpstream = resolve(testDirectory, "fixtures/dual-era-upstream.mjs");
const legacyOnlyUpstream = resolve(testDirectory, "fixtures/upstream.mjs");

let httpFixture: Awaited<ReturnType<typeof startDualEraHttpFixture>>;
let httpsFixture: Awaited<ReturnType<typeof startDualEraHttpFixture>>;
let certificate: Buffer;

beforeAll(async () => {
  certificate = await readFile(certificatePath);
  httpFixture = await startDualEraHttpFixture();
  httpsFixture = await startDualEraHttpFixture({
    tls: {
      cert: certificate,
      key: await readFile(privateKeyPath),
    },
  });
});

afterAll(async () => {
  await Promise.all([httpFixture.close(), httpsFixture.close()]);
});

describe("MCP 2026 transport matrix", () => {
  const stdioRoutes: Array<{
    route: string;
    args: string[] | (() => string[]);
    env?: Record<string, string>;
  }> = [
    {
      route: "STDIO -> STDIO",
      args: ["--", process.execPath, dualEraUpstream],
    },
    {
      route: "STDIO -> HTTP",
      args: () => ["--upstream-http", httpFixture.url],
    },
    {
      route: "STDIO -> HTTPS",
      args: () => ["--upstream-http", httpsFixture.url],
      env: {
        ...getDefaultEnvironment(),
        NODE_EXTRA_CA_CERTS: certificatePath,
      },
    },
  ];

  it.each(stdioRoutes)("$route", async ({ args, env }) => {
    const result = await exercise(
      new StdioClientTransport({
        command: process.execPath,
        args: [cli, "--policy", policy, ...(typeof args === "function" ? args() : args)],
        stderr: "pipe",
        ...(env ? { env } : {}),
      }),
      "modern",
    );

    expect(result.protocolVersion).toBe("2026-07-28");
    expect(result.sessionId).toBeUndefined();
  });

  const httpRoutes: Array<{
    route: string;
    listener: "http" | "https";
    upstream: string[] | (() => string[]);
    env?: () => Record<string, string>;
  }> = [
    {
      route: "HTTP -> STDIO",
      listener: "http",
      upstream: ["--", process.execPath, dualEraUpstream],
    },
    {
      route: "HTTP -> HTTP",
      listener: "http",
      upstream: () => ["--upstream-http", httpFixture.url],
    },
    {
      route: "HTTP -> HTTPS",
      listener: "http",
      upstream: () => ["--upstream-http", httpsFixture.url],
      env: () => ({ NODE_EXTRA_CA_CERTS: certificatePath }),
    },
    {
      route: "HTTPS -> STDIO",
      listener: "https",
      upstream: ["--", process.execPath, dualEraUpstream],
    },
    {
      route: "HTTPS -> HTTP",
      listener: "https",
      upstream: () => ["--upstream-http", httpFixture.url],
    },
    {
      route: "HTTPS -> HTTPS",
      listener: "https",
      upstream: () => ["--upstream-http", httpsFixture.url],
      env: () => ({ NODE_EXTRA_CA_CERTS: certificatePath }),
    },
  ];

  it.each(httpRoutes)("$route", async ({ listener, upstream, env }) => {
    const proxy = await startCli(
      typeof upstream === "function" ? upstream() : upstream,
      listener,
      env ? { env: env() } : {},
    );
    try {
      const result = await exercise(
        new StreamableHTTPClientTransport(
          new URL(proxy.url),
          listener === "https" ? { fetch: fetchWithCa(certificate) } : {},
        ),
        "modern",
      );
      expect(result.protocolVersion).toBe("2026-07-28");
      expect(result.sessionId).toBeUndefined();
    } finally {
      await proxy.close();
    }
  });

  it("serves legacy and modern clients on one listener", async () => {
    const proxy = await startCli(["--", process.execPath, dualEraUpstream]);
    try {
      const legacy = await exercise(new StreamableHTTPClientTransport(new URL(proxy.url)));
      const modern = await exercise(
        new StreamableHTTPClientTransport(new URL(proxy.url)),
        "modern",
      );

      expect(legacy.sessionId).toBeTruthy();
      expect(modern.sessionId).toBeUndefined();
    } finally {
      await proxy.close();
    }
  });

  it("rejects a non-JSON body before starting an upstream", async () => {
    const marker = "UNEXPECTED_UPSTREAM_START";
    const proxy = await startCli([
      "--",
      process.execPath,
      "-e",
      `process.stderr.write('${marker}\\n');process.stdin.resume()`,
    ]);
    try {
      const response = await fetch(proxy.url, {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: "{}",
      });

      expect(response.status).toBe(415);
      expect(proxy.stderr()).not.toContain(marker);
    } finally {
      await proxy.close();
    }
  });

  it("rejects inconsistent modern headers before starting an upstream", async () => {
    const marker = "UNEXPECTED_UPSTREAM_START";
    const proxy = await startCli([
      "--",
      process.execPath,
      "-e",
      `process.stderr.write('${marker}\\n');process.stdin.resume()`,
    ]);
    try {
      const response = await fetch(proxy.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "mcp-protocol-version": "2026-07-28",
          "mcp-method": "tools/call",
          "mcp-name": "wrong-name",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: "invalid-header",
          method: "tools/call",
          params: {
            name: "read_file",
            arguments: {},
            _meta: {
              [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
              [CLIENT_INFO_META_KEY]: {
                name: "invalid-header-test",
                version: "1.0.0",
              },
              [CLIENT_CAPABILITIES_META_KEY]: {},
            },
          },
        }),
      });

      expect(response.status).toBe(400);
      await expect(response.json()).resolves.toMatchObject({
        error: { code: -32020 },
      });
      expect(proxy.stderr()).not.toContain(marker);
    } finally {
      await proxy.close();
    }
  });

  it("delivers a modern notification before returning 202", async () => {
    let completed = false;
    const upstream = createHttpServer(async (request, response) => {
      for await (const _ of request) {
        // Drain the request before acknowledging it.
      }
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
      completed = true;
      response.writeHead(202).end();
    });
    upstream.listen(0, "127.0.0.1");
    await once(upstream, "listening");
    const address = upstream.address();
    if (!address || typeof address === "string") {
      throw new Error("Missing notification fixture port");
    }
    const proxy = await startCli(["--upstream-http", `http://127.0.0.1:${address.port}/mcp`]);
    try {
      const response = await fetch(proxy.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "mcp-protocol-version": "2026-07-28",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/message",
          params: {
            level: "info",
            data: "notification-test",
            _meta: modernMeta("notification-test"),
          },
        }),
      });

      expect(response.status).toBe(202);
      expect(completed).toBe(true);
    } finally {
      await proxy.close();
      const closed = once(upstream, "close");
      upstream.close();
      await closed;
    }
  });

  it("does not return 202 when a modern notification delivery fails", async () => {
    const upstream = createHttpServer((request, response) => {
      request.destroy();
      response.destroy();
    });
    upstream.listen(0, "127.0.0.1");
    await once(upstream, "listening");
    const address = upstream.address();
    if (!address || typeof address === "string") {
      throw new Error("Missing failing notification fixture port");
    }
    const proxy = await startCli(["--upstream-http", `http://127.0.0.1:${address.port}/mcp`]);
    try {
      const response = await fetch(proxy.url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "mcp-protocol-version": "2026-07-28",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/message",
          params: {
            level: "error",
            data: "delivery-failure-test",
            _meta: modernMeta("delivery-failure-test"),
          },
        }),
      });

      expect(response.status).toBe(500);
    } finally {
      await proxy.close();
      const closed = once(upstream, "close");
      upstream.close();
      await closed;
    }
  });

  it("closes an in-flight modern stdio upstream on shutdown", async () => {
    const marker = "MODERN_UPSTREAM_STARTED";
    const closedMarker = "MODERN_UPSTREAM_CLOSED";
    const proxy = await startCli([
      "--",
      process.execPath,
      "-e",
      `process.stderr.write('${marker}\\n');` +
        `process.on('SIGTERM',()=>{process.stderr.write('${closedMarker}\\n');process.exit(0)});` +
        "process.stdin.resume();setInterval(()=>{},1000)",
    ]);
    const client = modernClient("shutdown-test");
    const outcome = client.connect(new StreamableHTTPClientTransport(new URL(proxy.url))).then(
      () => "connected",
      () => "closed",
    );
    try {
      await vi.waitFor(() => expect(proxy.stderr()).toContain(marker), {
        timeout: 1000,
      });
      await proxy.close();
      await expect(outcome).resolves.toBe("closed");
      expect(proxy.stderr()).toContain(closedMarker);
    } finally {
      await client.close();
      await proxy.close();
    }
  });

  it("does not translate a modern client to a legacy-only upstream", async () => {
    const client = new Client(
      { name: "no-translation-test", version: "1.0.0" },
      {
        versionNegotiation: {
          mode: { pin: "2026-07-28" },
          probe: { timeoutMs: 100 },
        },
      },
    );
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [cli, "--policy", policy, "--", process.execPath, legacyOnlyUpstream],
      stderr: "pipe",
    });

    try {
      await expect(client.connect(transport)).rejects.toThrow();
    } finally {
      await client.close();
    }
  });
});

function modernClient(name: string): Client {
  return new Client(
    { name, version: "1.0.0" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
}

function modernMeta(name: string): Record<string, unknown> {
  return {
    [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
    [CLIENT_INFO_META_KEY]: { name, version: "1.0.0" },
    [CLIENT_CAPABILITIES_META_KEY]: {},
  };
}
