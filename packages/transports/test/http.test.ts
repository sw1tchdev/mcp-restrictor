import { once } from "node:events";
import { createServer, request as httpRequest } from "node:http";
import { networkInterfaces } from "node:os";
import { Writable } from "node:stream";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import {
  CLIENT_CAPABILITIES_META_KEY,
  CLIENT_INFO_META_KEY,
  PROTOCOL_VERSION_META_KEY,
  type Transport,
} from "@modelcontextprotocol/server";
import { afterEach, expect, it, vi } from "vitest";
import { startHttpGateway, startHttpProxy } from "../src/http.js";
import * as upstreamModule from "../src/upstream.js";

const claudeRoutePath =
  "/mcp/claude/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const codexRoutePath =
  "/mcp/codex/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

afterEach(() => vi.restoreAllMocks());

it("routes two exact gateway paths to independent upstreams and policies", async () => {
  installRouteUpstreams({ delay: 25 });
  const gateway = await startTestGateway();

  try {
    const [claude, codex] = await Promise.all([
      exerciseGatewayRoute(
        `${gateway.origin}${claudeRoutePath}`,
        "read_a",
        "read_b",
        "upstream-a:read_a",
      ),
      exerciseGatewayRoute(
        `${gateway.origin}${codexRoutePath}`,
        "read_b",
        "read_a",
        "upstream-b:read_b",
      ),
    ]);

    expect(claude).toEqual(["read_a"]);
    expect(codex).toEqual(["read_b"]);
  } finally {
    await gateway.close();
  }
});

it("returns 404 for unknown and aliased gateway route paths", async () => {
  installRouteUpstreams();
  const gateway = await startTestGateway();

  try {
    await expect(fetch(`${gateway.origin}/unknown`)).resolves.toMatchObject({ status: 404 });
    await expect(fetch(`${gateway.origin}${claudeRoutePath}/`)).resolves.toMatchObject({
      status: 404,
    });
    await expect(fetch(`${gateway.origin}${claudeRoutePath}?alias=1`)).resolves.toMatchObject({
      status: 404,
    });
    await expect(requestStatus(gateway.origin, {}, `${claudeRoutePath}#alias`)).resolves.toBe(404);
  } finally {
    await gateway.close();
  }
});

it.each([
  [
    "literal dot segments",
    "/mcp/claude/../codex/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  ],
  [
    "encoded dot segments",
    "/mcp/claude/%2e%2e/codex/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  ],
  ["an absolute-form target", `http://example.invalid${claudeRoutePath}`],
] as const)("returns 404 for raw managed targets with %s", async (_name, rawTarget) => {
  const gateway = await startTestGateway();

  try {
    await expect(requestStatus(gateway.origin, {}, rawTarget)).resolves.toBe(404);
  } finally {
    await gateway.close();
  }
});

it("keeps the configured search and pathname query matching for a direct proxy", async () => {
  const proxy = await startHttpProxy({
    listen: "http://127.0.0.1:0/mcp?configured=1",
    upstream: { kind: "stdio", command: process.execPath },
    authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
  });

  try {
    expect.soft(new URL(proxy.url).search).toBe("?configured=1");
    await expect(requestStatus(proxy.url, {}, "/mcp?request=1")).resolves.toBe(400);
  } finally {
    await proxy.close();
  }
});

it.each([
  ["empty gateway routes", [], /at least one route/],
  ["duplicate gateway route path", [testRoute("a"), testRoute("a")], /Duplicate route path/],
  ["gateway route path without slash", [{ ...testRoute("a"), path: "mcp/a" }], /leading slash/],
  [
    "gateway route path with query",
    [{ ...testRoute("a"), path: "/mcp/a?x=1" }],
    /query or fragment/,
  ],
  [
    "gateway route path with fragment",
    [{ ...testRoute("a"), path: "/mcp/a#x" }],
    /query or fragment/,
  ],
] as const)("rejects %s before bind", async (_name, routes, message) => {
  await expect(startHttpGateway({ listen: "http://127.0.0.1:0", routes })).rejects.toThrow(message);
});

it.each([
  [
    "literal dot segments",
    "/mcp/claude/../codex/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  ],
  [
    "encoded dot segments",
    "/mcp/claude/%2e%2e/codex/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  ],
  ["an authority-like prefix", "//evil"],
] as const)("rejects a gateway route path with %s before bind", async (_name, path) => {
  await expect(
    startAndCloseAcceptedGateway({
      listen: "http://127.0.0.1:0",
      routes: [testRoute("b"), { ...testRoute("a"), path }],
    }),
  ).rejects.toThrow(/canonical/);
});

it.each([
  ["a route path", "http://127.0.0.1:0/mcp"],
  ["normalized literal dot segments", "http://127.0.0.1:0/mcp/.."],
  ["normalized encoded dot segments", "http://127.0.0.1:0/mcp/%2e%2e"],
] as const)("rejects a gateway listener URL with %s before bind", async (_name, listen) => {
  await expect(startAndCloseAcceptedGateway({ listen, routes: [testRoute("a")] })).rejects.toThrow(
    /root path/,
  );
});

it("keeps a legacy session on its exact gateway route across a cross-route request", async () => {
  installRouteUpstreams();
  const gateway = await startTestGateway();

  try {
    const initialized = await legacyPost(
      `${gateway.origin}${claudeRoutePath}`,
      initializeRequest("route-session"),
    );
    expect(initialized.status).toBe(200);
    const sessionId = initialized.headers.get("mcp-session-id");
    expect(sessionId).toBeTruthy();

    const crossRoute = await legacyPost(
      `${gateway.origin}${codexRoutePath}`,
      { jsonrpc: "2.0", id: "wrong-route", method: "tools/list", params: {} },
      sessionId!,
    );
    expect(crossRoute.status).toBe(404);

    const originalRoute = await legacyPost(
      `${gateway.origin}${claudeRoutePath}`,
      { jsonrpc: "2.0", id: "right-route", method: "tools/list", params: {} },
      sessionId!,
    );
    expect(originalRoute.status).toBe(200);
    await expect(originalRoute.json()).resolves.toMatchObject({
      result: { tools: [{ name: "read_a" }] },
    });
  } finally {
    await gateway.close();
  }
});

it("waits for delayed bridge cleanup in both gateway routes", async () => {
  const upstreamA = delayedClosingTransport();
  const upstreamB = delayedClosingTransport();
  vi.spyOn(upstreamModule, "createUpstreamTransport").mockImplementation(
    (config) =>
      (config.kind === "stdio" && config.command === "route-a"
        ? upstreamA.transport
        : upstreamB.transport) as ReturnType<typeof upstreamModule.createUpstreamTransport>,
  );
  const gateway = await startTestGateway();
  const requests = [claudeRoutePath, codexRoutePath].map((path) =>
    fetch(`${gateway.origin}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "mcp-protocol-version": "2026-07-28",
        "mcp-method": "server/discover",
      },
      body: JSON.stringify(discoverRequest(`cleanup-${path[0]}`)),
    }).catch(() => undefined),
  );

  try {
    await Promise.all([upstreamA.started, upstreamB.started]);
    const closing = gateway.close();
    await Promise.all([upstreamA.closing, upstreamB.closing]);
    let closed = false;
    void closing.then(() => {
      closed = true;
    });

    upstreamA.finishClose();
    await new Promise((resolve) => setImmediate(resolve));
    expect(closed).toBe(false);
    upstreamB.finishClose();
    await closing;
    expect(closed).toBe(true);
    await Promise.all(requests);
  } finally {
    upstreamA.finishClose();
    upstreamB.finishClose();
    await gateway.close();
    await Promise.all(requests);
  }
});

it("keeps Host and Origin validation on gateway route paths", async () => {
  installRouteUpstreams();
  const gateway = await startTestGateway();
  const url = `${gateway.origin}${claudeRoutePath}`;

  try {
    await expect(requestStatus(url, { host: "evil.example" })).resolves.toBe(403);
    await expect(fetch(url, { headers: { origin: "http://evil.example" } })).resolves.toMatchObject(
      { status: 403 },
    );
  } finally {
    await gateway.close();
  }
});

it("binds wildcard while advertising and validating the loopback gateway origin", async () => {
  const externalAddress = Object.values(networkInterfaces())
    .flat()
    .find((address) => address?.family === "IPv4" && !address.internal)?.address;
  const gateway = await startHttpGateway({
    listen: "http://127.0.0.1:0",
    bindHostname: "0.0.0.0",
    routes: [testRoute("a")],
  });
  const port = new URL(gateway.origin).port;
  const routeUrl = `${gateway.origin}${claudeRoutePath}`;

  try {
    expect(gateway.origin).toBe(`http://127.0.0.1:${port}`);
    await expect(
      requestStatus(
        routeUrl,
        { host: `127.0.0.1:${port}`, origin: `http://127.0.0.1:${port}` },
        claudeRoutePath,
      ),
    ).resolves.toBe(400);
    if (externalAddress) {
      await expect(
        requestStatus(
          `http://${externalAddress}:${port}${claudeRoutePath}`,
          { host: `127.0.0.1:${port}`, origin: `http://127.0.0.1:${port}` },
          claudeRoutePath,
        ),
      ).resolves.toBe(400);
    }
    await expect(
      requestStatus(routeUrl, { host: `0.0.0.0:${port}` }, claudeRoutePath),
    ).resolves.toBe(403);
    await expect(
      requestStatus(routeUrl, { origin: `http://0.0.0.0:${port}` }, claudeRoutePath),
    ).resolves.toBe(403);
  } finally {
    await gateway.close();
  }
});

it("waits for bridge cleanup before reporting an aborted proxy closed", async () => {
  const upstream = delayedClosingTransport();
  vi.spyOn(upstreamModule, "createUpstreamTransport").mockReturnValue(
    upstream.transport as ReturnType<typeof upstreamModule.createUpstreamTransport>,
  );
  const controller = new AbortController();
  const proxy = await startHttpProxy({
    listen: "http://127.0.0.1:0/mcp",
    upstream: { kind: "stdio", command: process.execPath },
    authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
    signal: controller.signal,
  });
  const request = fetch(proxy.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "mcp-protocol-version": "2026-07-28",
      "mcp-method": "server/discover",
    },
    body: JSON.stringify(discoverRequest("shutdown-cleanup")),
  }).catch(() => undefined);

  try {
    await upstream.started;
    controller.abort();
    await upstream.closing;
    let closed = false;
    void proxy.closed.then(() => {
      closed = true;
    });
    await new Promise((resolve) => setImmediate(resolve));
    expect(closed).toBe(false);

    upstream.finishClose();
    await proxy.closed;
    expect(closed).toBe(true);
    await request;
  } finally {
    upstream.finishClose();
    controller.abort();
    await proxy.close();
    await request;
  }
});

it("stops accepting requests before waiting for active bridges", async () => {
  let markStarted!: () => void;
  const started = new Promise<void>((resolve) => {
    markStarted = resolve;
  });
  const marker = createServer((_request, response) => {
    markStarted();
    response.end();
  });
  marker.listen(0, "127.0.0.1");
  await once(marker, "listening");
  const markerAddress = marker.address();
  if (!markerAddress || typeof markerAddress === "string") {
    throw new Error("Missing shutdown marker port");
  }
  const proxy = await startHttpProxy({
    listen: "http://127.0.0.1:0/mcp",
    upstream: {
      kind: "stdio",
      command: process.execPath,
      args: [
        "-e",
        `fetch('http://127.0.0.1:${markerAddress.port}').catch(()=>{});` +
          "process.stdin.resume();setInterval(()=>{},1000)",
      ],
    },
    authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
  });
  const pending = fetch(proxy.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "mcp-protocol-version": "2026-07-28",
      "mcp-method": "server/discover",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "shutdown-race",
      method: "server/discover",
      params: {
        _meta: {
          [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
          [CLIENT_INFO_META_KEY]: { name: "shutdown-race", version: "1.0.0" },
          [CLIENT_CAPABILITIES_META_KEY]: {},
        },
      },
    }),
  }).catch(() => undefined);

  try {
    await started;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 20));
    const closing = proxy.close();

    await expect(
      fetch(proxy.url, {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: "{}",
      }),
    ).rejects.toThrow();
    await closing;
    await pending;
  } finally {
    await proxy.close();
    const markerClosed = once(marker, "close");
    marker.close();
    await markerClosed;
  }
});

it("redacts failed remote resource responses before bridge errors reach stderr", async () => {
  const sentinels = ["http-resource-body-sentinel", "http-header-sentinel"];
  const upstream = createServer((_request, response) => {
    response.writeHead(500).end(sentinels.join(":"));
  });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  const address = upstream.address();
  if (!address || typeof address === "string") throw new Error("Missing upstream port");
  const chunks: Buffer[] = [];
  const stderr = new Writable({
    write(chunk: Buffer | string, _encoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  });
  let report!: () => void;
  const reported = new Promise<void>((resolve) => {
    report = resolve;
  });
  const proxy = await startHttpProxy({
    listen: "http://127.0.0.1:0/mcp",
    upstream: {
      kind: "http",
      url: `http://127.0.0.1:${address.port}/mcp`,
      headers: [["X-Upstream-Key", sentinels[1]!]],
    },
    authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
    onerror: (error) => {
      stderr.write(`${error.message}\n`);
      report();
    },
  });

  try {
    await fetch(proxy.url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "mcp-protocol-version": "2026-07-28",
        "mcp-method": "server/discover",
      },
      body: JSON.stringify(discoverRequest("redacted-error")),
    }).catch(() => undefined);
    await reported;

    const output = Buffer.concat(chunks).toString("utf8");
    expect(output).toContain("request failed (status 500)");
    for (const sentinel of sentinels) expect(output).not.toContain(sentinel);
  } finally {
    await proxy.close();
    const closed = once(upstream, "close");
    upstream.close();
    await closed;
  }
});

it("passes an aborted modern request signal through its upstream startup", async () => {
  const upstream = createServer((_request, _response) => {});
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  const address = upstream.address();
  if (!address || typeof address === "string") throw new Error("Missing upstream port");
  let factorySignal: AbortSignal | undefined;
  let startedHandler!: () => void;
  const handlerStarted = new Promise<void>((resolve) => {
    startedHandler = resolve;
  });
  let abortedHandler!: () => void;
  const handlerAborted = new Promise<void>((resolve) => {
    abortedHandler = resolve;
  });
  const proxy = await startHttpProxy({
    listen: "http://127.0.0.1:0/mcp",
    upstream: {
      kind: "http",
      url: `http://127.0.0.1:${address.port}/mcp`,
      authProviderFactory: (signal) => {
        factorySignal = signal;
        return {
          token: async () => {
            startedHandler();
            await new Promise<void>((resolve) => {
              signal?.addEventListener("abort", () => resolve(), { once: true });
            });
            abortedHandler();
            return undefined;
          },
        };
      },
    },
    authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
  });
  const controller = new AbortController();
  const request = fetch(proxy.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "mcp-protocol-version": "2026-07-28",
      "mcp-method": "server/discover",
    },
    body: JSON.stringify(discoverRequest("abort-startup")),
    signal: controller.signal,
  }).catch(() => undefined);

  try {
    await handlerStarted;
    controller.abort();
    await handlerAborted;
    expect(factorySignal?.aborted).toBe(true);
    await request;
  } finally {
    await proxy.close();
    const closed = once(upstream, "close");
    upstream.close();
    await closed;
  }
});

it("aborts a pending session initialization when its client disconnects", async () => {
  const upstream = neverStartingTransport();
  vi.spyOn(upstreamModule, "createUpstreamTransport").mockReturnValue(
    upstream.transport as ReturnType<typeof upstreamModule.createUpstreamTransport>,
  );
  const proxy = await startHttpProxy({
    listen: "http://127.0.0.1:0/mcp",
    upstream: { kind: "stdio", command: process.execPath },
    authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
  });
  const controller = new AbortController();
  const request = fetch(proxy.url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(initializeRequest("session-bootstrap-abort")),
    signal: controller.signal,
  }).catch(() => undefined);

  try {
    await upstream.started;
    controller.abort();
    await request;
    await proxy.close();
    expect(upstream.close).toHaveBeenCalled();
  } finally {
    await proxy.close();
  }
});

function discoverRequest(id: string): {
  jsonrpc: "2.0";
  id: string;
  method: "server/discover";
  params: { _meta: Record<string, unknown> };
} {
  return {
    jsonrpc: "2.0",
    id,
    method: "server/discover",
    params: {
      _meta: {
        [PROTOCOL_VERSION_META_KEY]: "2026-07-28",
        [CLIENT_INFO_META_KEY]: { name: id, version: "1.0.0" },
        [CLIENT_CAPABILITIES_META_KEY]: {},
      },
    },
  };
}

function initializeRequest(id: string): {
  jsonrpc: "2.0";
  id: string;
  method: "initialize";
  params: {
    protocolVersion: string;
    capabilities: Record<string, never>;
    clientInfo: { name: string; version: string };
  };
} {
  return {
    jsonrpc: "2.0",
    id,
    method: "initialize",
    params: {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: id, version: "1.0.0" },
    },
  };
}

function testRoute(id: "a" | "b") {
  return {
    path: id === "a" ? claudeRoutePath : codexRoutePath,
    upstream: { kind: "stdio" as const, command: `route-${id}` },
    authorizer: {
      discover: (name: string) => name === `read_${id}`,
      authorize: (name: string) => ({ allowed: name === `read_${id}` }),
    },
  };
}

function startTestGateway() {
  return startHttpGateway({
    listen: "http://127.0.0.1:0",
    routes: [testRoute("a"), testRoute("b")],
  });
}

async function startAndCloseAcceptedGateway(
  options: Parameters<typeof startHttpGateway>[0],
): Promise<void> {
  const gateway = await startHttpGateway(options);
  await gateway.close();
}

function installRouteUpstreams(options: { delay?: number } = {}): void {
  vi.spyOn(upstreamModule, "createUpstreamTransport").mockImplementation((config) => {
    const id = config.kind === "stdio" && config.command === "route-a" ? "a" : "b";
    return routeUpstream(id, options.delay) as ReturnType<
      typeof upstreamModule.createUpstreamTransport
    >;
  });
}

function routeUpstream(id: "a" | "b", delay = 0): Transport {
  const transport: Transport = {
    start: async () => {},
    send: async (message) => {
      if (!("id" in message) || !("method" in message)) return;
      if (delay) await new Promise((resolve) => setTimeout(resolve, delay));
      const result =
        message.method === "initialize"
          ? {
              protocolVersion: "2025-06-18",
              capabilities: { tools: {} },
              serverInfo: { name: `upstream-${id}`, version: "1.0.0" },
            }
          : message.method === "tools/list"
            ? {
                tools: ["a", "b"].map((tool) => ({
                  name: `read_${tool}`,
                  inputSchema: { type: "object" },
                })),
              }
            : {
                content: [
                  {
                    type: "text",
                    text: `upstream-${id}:${String(message.params?.name)}`,
                  },
                ],
              };
      transport.onmessage?.({ jsonrpc: "2.0", id: message.id, result });
    },
    close: async () => {},
  };
  return transport;
}

async function exerciseGatewayRoute(
  url: string,
  tool: "read_a" | "read_b",
  deniedTool: "read_a" | "read_b",
  expectedContent: "upstream-a:read_a" | "upstream-b:read_b",
): Promise<string[]> {
  const transport = new StreamableHTTPClientTransport(new URL(url));
  const client = new Client({ name: tool, version: "1.0.0" });
  await client.connect(transport);
  try {
    const names = (await client.listTools()).tools.map(({ name }) => name);
    await expect(client.callTool({ name: tool, arguments: {} })).resolves.toMatchObject({
      content: [{ type: "text", text: expectedContent }],
    });
    await expect(client.callTool({ name: deniedTool, arguments: {} })).rejects.toMatchObject({
      code: -32001,
    });
    return names;
  } finally {
    await client.close();
  }
}

function legacyPost(url: string, body: unknown, sessionId?: string): Promise<Response> {
  return fetch(url, {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      ...(sessionId ? { "mcp-protocol-version": "2025-06-18", "mcp-session-id": sessionId } : {}),
    },
    body: JSON.stringify(body),
  });
}

function requestStatus(
  url: string,
  headers: Record<string, string>,
  rawPath?: string,
): Promise<number | undefined> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      url,
      { headers, ...(rawPath ? { path: rawPath } : {}) },
      (response) => {
        response.resume();
        response.on("end", () => resolve(response.statusCode));
      },
    );
    request.on("error", reject);
    request.end();
  });
}

function neverStartingTransport(): {
  transport: import("@modelcontextprotocol/server").Transport;
  started: Promise<void>;
  close: ReturnType<typeof vi.fn>;
} {
  let started!: () => void;
  const close = vi.fn(async () => {});
  return {
    transport: {
      start: async () => {
        started();
        await new Promise<void>(() => {});
      },
      send: async () => {},
      close,
    },
    started: new Promise((resolve) => {
      started = resolve;
    }),
    close,
  };
}

function delayedClosingTransport(): {
  transport: import("@modelcontextprotocol/server").Transport;
  started: Promise<void>;
  closing: Promise<void>;
  finishClose(): void;
} {
  let markStarted!: () => void;
  let markClosing!: () => void;
  let finishClose!: () => void;
  const closed = new Promise<void>((resolve) => {
    finishClose = resolve;
  });
  return {
    transport: {
      start: async () => markStarted(),
      send: async () => {},
      close: async () => {
        markClosing();
        await closed;
      },
    },
    started: new Promise((resolve) => {
      markStarted = resolve;
    }),
    closing: new Promise((resolve) => {
      markClosing = resolve;
    }),
    finishClose,
  };
}
