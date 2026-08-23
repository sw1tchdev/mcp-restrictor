import { once } from "node:events";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import type { Transport } from "@modelcontextprotocol/server";
import { afterEach, describe, expect, test, vi } from "vitest";
import { WebSocketServer } from "ws";
import { discoverToolNames } from "../src/discovery.js";
import * as upstreamModule from "../src/upstream.js";
import type { UpstreamHeader } from "../src/remote.js";
import type { UpstreamConfig } from "../src/upstream.js";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const fixture = resolve(testDirectory, "fixtures/config-sensitive-upstream.mjs");
const packageVersion = (createRequire(import.meta.url)("../package.json") as { version: string })
  .version;

describe("discoverToolNames", () => {
  afterEach(() => vi.restoreAllMocks());

  test("aggregates paginated STDIO tools in deterministic order", async () => {
    await expect(discoverToolNames(stdioUpstream("paginated"))).resolves.toEqual([
      "read_file",
      "write_file",
    ]);
  });

  test("rejects duplicate names from paginated STDIO tools", async () => {
    await expect(discoverToolNames(stdioUpstream("duplicate"))).rejects.toThrow(
      "Duplicate tool name read_file",
    );
  });

  test("routes STDIO diagnostics to an explicit sink", async () => {
    const chunks: Buffer[] = [];
    const stderr = new Writable({
      write(chunk: Buffer | string, _encoding, callback) {
        chunks.push(Buffer.from(chunk));
        callback();
      },
    });

    await discoverToolNames(stdioUpstream("stderr"), { stderr });

    expect(Buffer.concat(chunks).toString("utf8")).toBe("secret");
  });

  test("forwards aborts during listing and still closes the client", async () => {
    const controller = new AbortController();
    const originalListTools = Client.prototype.listTools;
    vi.spyOn(Client.prototype, "listTools").mockImplementation(
      function (this: Client, params, options) {
        const result = originalListTools.call(this, params, options);
        queueMicrotask(() => controller.abort());
        return result;
      },
    );
    const close = spyOnClose();

    await expect(
      discoverToolNames(stdioUpstream("paginated"), {
        signal: controller.signal,
      }),
    ).rejects.toThrow("AbortError");
    expect(close).toHaveBeenCalledOnce();
  });

  test("surfaces a close failure after successful discovery", async () => {
    const closeError = new Error("controlled close failure");
    const close = spyOnClose(closeError);

    await expect(discoverToolNames(stdioUpstream("paginated"))).rejects.toBe(closeError);
    expect(close).toHaveBeenCalledOnce();
  });

  test("keeps discovery failure before close failure", async () => {
    const closeError = new Error("controlled close failure");
    const close = spyOnClose(closeError);

    const failure: unknown = await discoverToolNames(stdioUpstream("duplicate")).catch(
      (error: unknown) => error,
    );

    expect(close).toHaveBeenCalledOnce();
    expect(failure).toBeInstanceOf(AggregateError);
    if (!(failure instanceof AggregateError)) return;
    expect(failure.errors).toHaveLength(2);
    expect(failure.errors[0]).toMatchObject({
      message: "Duplicate tool name read_file",
    });
    expect(failure.errors[1]).toBe(closeError);
    expect(failure.cause).toBe(failure.errors[0]);
  });

  test("discovers unauthenticated and bearer-protected HTTP tools", async () => {
    const unauthenticated = await startHttpFixture();
    const bearerToken = "test-bearer-token";
    const bearerProtected = await startHttpFixture(`Bearer ${bearerToken}`);

    try {
      await expect(discoverToolNames({ kind: "http", url: unauthenticated.url })).resolves.toEqual([
        "read_file",
      ]);
      expect(unauthenticated.clientVersions).toEqual([packageVersion]);
      await expect(
        discoverToolNames({
          kind: "http",
          url: bearerProtected.url,
          bearerToken,
        }),
      ).resolves.toEqual(["read_file"]);
    } finally {
      await Promise.all([unauthenticated.close(), bearerProtected.close()]);
    }
  });

  test("sends configured headers while discovering protected HTTP tools", async () => {
    const fixture = await startHttpFixture(undefined, {
      name: "x-upstream-key",
      value: "fixture-only-key",
    });

    try {
      await expect(
        discoverToolNames({
          kind: "http",
          url: fixture.url,
          headers: [["X-Upstream-Key", "fixture-only-key"]],
        }),
      ).resolves.toEqual(["read_file"]);
      expect(fixture.receivedHeaders).toContain("fixture-only-key");

      await expect(discoverToolNames({ kind: "http", url: fixture.url })).rejects.toThrow();
    } finally {
      await fixture.close();
    }
  });

  test("discovers tools through a WebSocket upstream", async () => {
    const fixture = await startWebSocketFixture();

    try {
      await expect(
        discoverToolNames({
          kind: "websocket",
          url: fixture.url,
          headers: [["X-Upstream-Key", "websocket-fixture-key"]],
        }),
      ).resolves.toEqual(["read_file"]);
      expect(fixture.receivedHeaders).toEqual(["websocket-fixture-key"]);
      expect(fixture.methods).toEqual(expect.arrayContaining(["initialize", "tools/list"]));
    } finally {
      await fixture.close();
    }
  });

  test("sends configured headers on legacy SSE requests while discovering paginated tools", async () => {
    const expectedHeader = { name: "x-upstream-key", value: "sse-fixture-key" };
    const fixture = await startSseFixture({ expectedHeader });

    try {
      await expect(
        discoverToolNames({
          kind: "sse",
          url: fixture.url,
          headers: [["X-Upstream-Key", expectedHeader.value]],
        }),
      ).resolves.toEqual(["read_file", "write_file"]);
      expect(fixture.initialHeaders).toEqual([expectedHeader.value]);
      expect(fixture.messageHeaders).not.toHaveLength(0);
      expect(fixture.messageHeaders.every((value) => value === expectedHeader.value)).toBe(true);
      expect(fixture.methods).toEqual(
        expect.arrayContaining(["initialize", "tools/list", "tools/list"]),
      );
    } finally {
      await fixture.close();
    }
  });

  test("calls a tool through the legacy SSE fixture", async () => {
    const fixture = await startSseFixture();
    const client = new Client({ name: "sse-call-test", version: "1.0.0" });

    try {
      await client.connect(
        upstreamModule.createUpstreamTransport({ kind: "sse", url: fixture.url }),
      );

      await expect(client.callTool({ name: "read_file", arguments: {} })).resolves.toMatchObject({
        content: [{ type: "text", text: "called read_file" }],
      });
      expect(fixture.methods).toContain("tools/call");
    } finally {
      await client.close();
      await fixture.close();
    }
  });

  test("does not follow a legacy SSE initial GET redirect or expose its configured header", async () => {
    const headerValue = "sse-initial-redirect-sentinel";
    const redirected = await startRecordingServer();
    let firstOriginHeader: string | undefined;
    const resource = await startServer((request, response) => {
      const header = request.headers["x-upstream-key"];
      firstOriginHeader = Array.isArray(header) ? header[0] : header;
      response.writeHead(302, { location: redirected.url }).end();
    });

    try {
      const failure = await discoverToolNames({
        kind: "sse",
        url: resource.url,
        headers: [["X-Upstream-Key", headerValue]],
      }).catch((error: unknown) => error);

      expect(firstOriginHeader).toBe(headerValue);
      expect(redirected.receivedHeaders).toEqual([]);
      expect(String(failure)).not.toContain(headerValue);
    } finally {
      await Promise.all([resource.close(), redirected.close()]);
    }
  });

  test("does not follow a legacy SSE message POST redirect or expose its configured header", async () => {
    const headerValue = "sse-post-redirect-sentinel";
    const redirected = await startRecordingServer();
    const fixture = await startSseFixture({
      expectedHeader: { name: "x-upstream-key", value: headerValue },
      messageRedirect: redirected.url,
    });

    try {
      const failure = await discoverToolNames({
        kind: "sse",
        url: fixture.url,
        headers: [["X-Upstream-Key", headerValue]],
      }).catch((error: unknown) => error);

      expect(fixture.initialHeaders).toEqual([headerValue]);
      expect(fixture.messageHeaders).toEqual([headerValue]);
      expect(redirected.receivedHeaders).toEqual([]);
      expect(String(failure)).not.toContain(headerValue);
    } finally {
      await Promise.all([fixture.close(), redirected.close()]);
    }
  });

  test("redacts a legacy SSE message error body that echoes configured secrets", async () => {
    const headerValue = "sse-error-header-sentinel";
    const bodyValue = "sse-error-body-sentinel";
    const fixture = await startSseFixture({
      expectedHeader: { name: "x-upstream-key", value: headerValue },
      messageErrorBody: `${bodyValue}:${headerValue}`,
    });

    try {
      const failure = await discoverToolNames({
        kind: "sse",
        url: fixture.url,
        headers: [["X-Upstream-Key", headerValue]],
      }).catch((error: unknown) => error);

      expect(fixture.initialHeaders).toEqual([headerValue]);
      expect(fixture.messageHeaders).toEqual([headerValue]);
      expect(String(failure)).not.toContain(headerValue);
      expect(String(failure)).not.toContain(bodyValue);
    } finally {
      await fixture.close();
    }
  });

  test.each(redirectCases)(
    "does not follow a redirect after receiving a $name",
    async ({ upstream, received, expected }) => {
      let redirectedRequests = 0;
      const redirected = await startServer((_request, response) => {
        redirectedRequests += 1;
        response.writeHead(200).end();
      });
      let firstOriginValue: string | null = null;
      const resource = await startServer((request, response) => {
        firstOriginValue = received(new Headers(request.headers as Record<string, string>));
        response.writeHead(302, { location: redirected.url }).end();
      });

      try {
        await expect(
          discoverToolNames({ kind: "http", url: resource.url, ...upstream }),
        ).rejects.toThrow();
        expect(firstOriginValue).toBe(expected);
        expect(redirectedRequests).toBe(0);
      } finally {
        await Promise.all([resource.close(), redirected.close()]);
      }
    },
  );

  test("redacts upstream resource bodies from discovery failures", async () => {
    const sentinels = ["resource-body-sentinel", "header-sentinel", "bearer-sentinel"];
    const resource = await startServer((_request, response) => {
      response.writeHead(500).end(sentinels.join(":"));
    });

    try {
      const failure = await discoverToolNames({
        kind: "http",
        url: resource.url,
        headers: [["X-Upstream-Key", sentinels[1]!]],
        bearerToken: sentinels[2]!,
      }).catch((error: unknown) => error);

      expect(failure).toMatchObject({ message: "discovery failed (status 500)" });
      for (const sentinel of sentinels) {
        expect(String(failure)).not.toContain(sentinel);
      }
    } finally {
      await resource.close();
    }
  });

  test("preserves only a caller-recognized local discovery error", async () => {
    const localError = new Error("caller-local-error");
    vi.spyOn(Client.prototype, "connect").mockRejectedValue(localError);
    vi.spyOn(Client.prototype, "close").mockResolvedValue();

    await expect(
      discoverToolNames(
        { kind: "http", url: "https://example.test/mcp" },
        { preserveError: (error) => error === localError },
      ),
    ).rejects.toBe(localError);
  });

  test("preserves an awaited caller-recognized response validation error by identity", async () => {
    const localError = new Error("typed-incompatibility");
    const resource = await startServer((_request, response) => {
      response.writeHead(404).end("not an MCP HTTP endpoint");
    });

    try {
      await expect(
        discoverToolNames(
          {
            kind: "http",
            url: resource.url,
            validateResponse: async (response) => {
              await response.body?.cancel();
              throw localError;
            },
          },
          {
            signal: new AbortController().signal,
            preserveError: (error) => error === localError,
          },
        ),
      ).rejects.toBe(localError);
    } finally {
      await resource.close();
    }
  });

  test("closes a never-settling upstream start when discovery is aborted", async () => {
    const controller = new AbortController();
    const upstream = neverStartingTransport();
    vi.spyOn(upstreamModule, "createUpstreamTransport").mockReturnValue(
      upstream.transport as ReturnType<typeof upstreamModule.createUpstreamTransport>,
    );

    const discovery = discoverToolNames(stdioUpstream("paginated"), {
      signal: controller.signal,
    });
    await upstream.started;
    controller.abort();

    await expect(discovery).rejects.toThrow("AbortError");
    expect(upstream.close).toHaveBeenCalled();
  });
});

function stdioUpstream(mode: "paginated" | "duplicate" | "stderr") {
  return {
    kind: "stdio" as const,
    command: process.execPath,
    args: [fixture, process.cwd(), mode],
    env: { API_KEY: "secret" },
    cwd: process.cwd(),
  };
}

function spyOnClose(closeError?: Error) {
  const originalClose = Client.prototype.close;
  return vi.spyOn(Client.prototype, "close").mockImplementation(async function (this: Client) {
    await originalClose.call(this);
    if (closeError) throw closeError;
  });
}

async function startHttpFixture(
  expectedAuthorization?: string,
  expectedHeader?: { name: string; value: string },
): Promise<{
  url: string;
  receivedHeaders: string[];
  clientVersions: string[];
  close(): Promise<void>;
}> {
  const transport = new NodeStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  const clientVersions: string[] = [];
  transport.onmessage = (message) => {
    if (!("method" in message) || !("id" in message)) return;
    if (message.method === "initialize")
      clientVersions.push(
        (message.params as { clientInfo: { version: string } }).clientInfo.version,
      );
    const result =
      message.method === "initialize"
        ? {
            protocolVersion: (message.params as { protocolVersion: string }).protocolVersion,
            capabilities: { tools: {} },
            serverInfo: { name: "discovery-fixture", version: "1.0.0" },
          }
        : message.method === "tools/list"
          ? { tools: [{ name: "read_file", inputSchema: { type: "object" } }] }
          : {};
    void transport.send(
      { jsonrpc: "2.0", id: message.id, result },
      { relatedRequestId: message.id },
    );
  };
  await transport.start();

  const receivedHeaders: string[] = [];
  const server = createServer((request, response) => {
    const received = expectedHeader ? request.headers[expectedHeader.name] : undefined;
    if (typeof received === "string") receivedHeaders.push(received);
    if (
      request.headers.authorization !== expectedAuthorization ||
      (expectedHeader && received !== expectedHeader.value)
    ) {
      response.writeHead(401).end("Unauthorized");
      return;
    }
    void transport.handleRequest(request, response);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");

  return {
    url: `http://127.0.0.1:${address.port}/mcp`,
    receivedHeaders,
    clientVersions,
    close: async () => {
      await transport.close();
      await closeServer(server);
    },
  };
}

async function startSseFixture(
  options: {
    expectedHeader?: { name: string; value: string };
    messageRedirect?: string;
    messageErrorBody?: string;
  } = {},
): Promise<{
  url: string;
  initialHeaders: string[];
  messageHeaders: string[];
  methods: string[];
  close(): Promise<void>;
}> {
  const initialHeaders: string[] = [];
  const messageHeaders: string[] = [];
  const methods: string[] = [];
  let stream: ServerResponse | undefined;
  const server = createServer(async (request, response) => {
    const header = options.expectedHeader && request.headers[options.expectedHeader.name];
    if (request.method === "GET") {
      if (typeof header === "string") initialHeaders.push(header);
      if (options.expectedHeader && header !== options.expectedHeader.value) {
        response.writeHead(401).end("Unauthorized");
        return;
      }
      stream = response;
      response.writeHead(200, {
        "cache-control": "no-cache",
        "content-type": "text/event-stream",
      });
      response.write(`event: endpoint\ndata: /messages\n\n`);
      return;
    }

    if (request.method !== "POST" || request.url !== "/messages") {
      response.writeHead(404).end();
      return;
    }
    if (typeof header === "string") messageHeaders.push(header);
    if (options.expectedHeader && header !== options.expectedHeader.value) {
      response.writeHead(401).end("Unauthorized");
      return;
    }
    if (options.messageRedirect) {
      response.writeHead(302, { location: options.messageRedirect }).end();
      return;
    }
    if (options.messageErrorBody) {
      response.writeHead(500).end(options.messageErrorBody);
      return;
    }

    const message = await readJsonRequest(request);
    methods.push(message.method);
    const result =
      message.method === "initialize"
        ? {
            protocolVersion: message.params?.protocolVersion ?? "",
            capabilities: { tools: {} },
            serverInfo: { name: "sse-discovery-fixture", version: "1.0.0" },
          }
        : message.method === "tools/list" && message.params?.cursor !== "page-2"
          ? {
              tools: [{ name: "write_file", inputSchema: { type: "object" } }],
              nextCursor: "page-2",
            }
          : message.method === "tools/list"
            ? { tools: [{ name: "read_file", inputSchema: { type: "object" } }] }
            : message.method === "tools/call"
              ? { content: [{ type: "text", text: `called ${message.params?.name ?? ""}` }] }
              : {};
    stream?.write(`data: ${JSON.stringify({ jsonrpc: "2.0", id: message.id, result })}\n\n`);
    response.writeHead(202).end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");

  return {
    url: `http://127.0.0.1:${address.port}/mcp`,
    initialHeaders,
    messageHeaders,
    methods,
    close: async () => {
      stream?.end();
      await closeServer(server);
    },
  };
}

async function startWebSocketFixture(): Promise<{
  url: string;
  receivedHeaders: string[];
  methods: string[];
  close(): Promise<void>;
}> {
  const receivedHeaders: string[] = [];
  const methods: string[] = [];
  const server = new WebSocketServer({
    host: "127.0.0.1",
    port: 0,
    perMessageDeflate: false,
    handleProtocols: (protocols) => (protocols.has("mcp") ? "mcp" : false),
  });
  server.on("connection", (socket, request) => {
    const header = request.headers["x-upstream-key"];
    if (typeof header === "string") receivedHeaders.push(header);
    socket.on("message", (data, isBinary) => {
      if (isBinary) return;
      const message = JSON.parse(data.toString()) as {
        jsonrpc: "2.0";
        id?: string | number;
        method?: string;
        params?: { protocolVersion?: string };
      };
      if (message.method) methods.push(message.method);
      if (message.id === undefined) return;
      const result =
        message.method === "initialize"
          ? {
              protocolVersion: message.params?.protocolVersion ?? "",
              capabilities: { tools: {} },
              serverInfo: { name: "websocket-discovery-fixture", version: "1.0.0" },
            }
          : message.method === "tools/list"
            ? { tools: [{ name: "read_file", inputSchema: { type: "object" } }] }
            : {};
      socket.send(JSON.stringify({ jsonrpc: "2.0", id: message.id, result }));
    });
  });
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");

  return {
    url: `ws://127.0.0.1:${address.port}/mcp`,
    receivedHeaders,
    methods,
    close: async () => {
      for (const client of server.clients) client.terminate();
      await closeWebSocketServer(server);
    },
  };
}

function closeWebSocketServer(server: WebSocketServer): Promise<void> {
  if (server.address() === null) return Promise.resolve();
  return new Promise((resolveClose, reject) => {
    server.close((error) => (error ? reject(error) : resolveClose()));
  });
}

async function readJsonRequest(request: IncomingMessage): Promise<{
  id: string | number;
  method: string;
  params?: { cursor?: string; name?: string; protocolVersion: string };
}> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function startRecordingServer(): Promise<{
  url: string;
  receivedHeaders: string[];
  close(): Promise<void>;
}> {
  const receivedHeaders: string[] = [];
  const server = await startServer((request, response) => {
    const header = request.headers["x-upstream-key"];
    if (typeof header === "string") receivedHeaders.push(header);
    response.writeHead(200).end();
  });
  return { ...server, receivedHeaders };
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolveClose, reject) => {
    server.close((error) => (error ? reject(error) : resolveClose()));
  });
}

async function startServer(
  listener: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<{ url: string; close(): Promise<void> }> {
  const server = createServer(listener);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");
  return {
    url: `http://127.0.0.1:${address.port}/mcp`,
    close: () => closeServer(server),
  };
}

const redirectCases: Array<{
  name: string;
  upstream: Omit<Extract<UpstreamConfig, { kind: "http" }>, "kind" | "url">;
  received: (headers: Headers) => string | null;
  expected: string;
}> = [
  {
    name: "configured header",
    upstream: {
      headers: [["X-Upstream-Key", "redirect-header-sentinel"] as UpstreamHeader],
    },
    received: (headers) => headers.get("x-upstream-key"),
    expected: "redirect-header-sentinel",
  },
  {
    name: "bearer token",
    upstream: { bearerToken: "redirect-bearer-sentinel" },
    received: (headers) => headers.get("authorization"),
    expected: "Bearer redirect-bearer-sentinel",
  },
];

function neverStartingTransport(): {
  transport: Transport;
  started: Promise<void>;
  close: ReturnType<typeof vi.fn>;
} {
  let started!: () => void;
  const close = vi.fn(async () => {});
  const transport: Transport = {
    start: async () => {
      started();
      await new Promise<void>(() => {});
    },
    send: async () => {},
    close,
  };
  return {
    transport,
    started: new Promise((resolve) => {
      started = resolve;
    }),
    close,
  };
}
