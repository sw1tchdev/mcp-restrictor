import { once } from "node:events";
import { createServer, type Server } from "node:http";
import type { Duplex } from "node:stream";
import type { JSONRPCMessage } from "@modelcontextprotocol/client";
import { afterEach, describe, expect, test, vi } from "vitest";
import { WebSocketServer, type WebSocket } from "ws";
import { WebSocketClientTransport } from "../src/websocket.js";

const MAX_PAYLOAD_BYTES = 10 * 1024 * 1024;
const openTransports = new Set<WebSocketClientTransport>();
const openServers = new Set<WebSocketServer>();
const openHttpServers = new Set<Server>();

afterEach(async () => {
  await Promise.all([...openTransports].map((transport) => transport.close()));
  for (const server of openServers) {
    for (const client of server.clients) client.terminate();
    await closeWebSocketServer(server);
  }
  for (const server of openHttpServers) {
    server.closeAllConnections();
    await closeHttpServer(server);
  }
  openTransports.clear();
  openServers.clear();
  openHttpServers.clear();
});

describe("WebSocketClientTransport", () => {
  test("connects with the mcp subprotocol, configured headers, no compression, and no headers required", async () => {
    const offeredProtocols: string[][] = [];
    const server = await startWebSocketServer({
      handleProtocols(protocols) {
        offeredProtocols.push([...protocols]);
        return protocols.has("mcp") ? "mcp" : false;
      },
    });
    const requests: Array<{
      protocol: string | undefined;
      extension: string | undefined;
      key: string | undefined;
    }> = [];
    server.on("connection", (socket, request) => {
      requests.push({
        protocol: request.headers["sec-websocket-protocol"],
        extension: request.headers["sec-websocket-extensions"],
        key: request.headers["x-upstream-key"] as string | undefined,
      });
      expect(socket.protocol).toBe("mcp");
      expect(socket.extensions).toBe("");
    });

    const configured = trackedTransport(
      new WebSocketClientTransport(
        new URL(serverUrl(server)),
        new Headers([["X-Upstream-Key", "fixture-key"]]),
      ),
    );
    await configured.start();
    await configured.close();

    const plain = trackedTransport(new WebSocketClientTransport(new URL(serverUrl(server))));
    await plain.start();

    expect(offeredProtocols).toEqual([["mcp"], ["mcp"]]);
    expect(requests).toEqual([
      { protocol: "mcp", extension: undefined, key: "fixture-key" },
      { protocol: "mcp", extension: undefined, key: undefined },
    ]);
  });

  test("sends exact JSON text and accepts string-like and Buffer-backed text frames", async () => {
    const server = await startWebSocketServer();
    const connection = nextConnection(server);
    const transport = trackedTransport(new WebSocketClientTransport(new URL(serverUrl(server))));
    const received: JSONRPCMessage[] = [];
    transport.onmessage = (message) => received.push(message);

    await transport.start();
    const socket = await connection;
    const sent = once(socket, "message");
    const outgoing = {
      jsonrpc: "2.0",
      id: 7,
      method: "tools/list",
      params: {},
    } satisfies JSONRPCMessage;
    await transport.send(outgoing);

    const [data, isBinary] = await sent;
    expect(isBinary).toBe(false);
    expect(data.toString()).toBe('{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}');

    socket.send('{"jsonrpc":"2.0","method":"notifications/string"}');
    socket.send(Buffer.from('{"jsonrpc":"2.0","method":"notifications/buffer"}', "utf8"), {
      binary: false,
    });
    await vi.waitFor(() => expect(received).toHaveLength(2));
    expect(received).toEqual([
      { jsonrpc: "2.0", method: "notifications/string" },
      { jsonrpc: "2.0", method: "notifications/buffer" },
    ]);
  });

  test.each([
    {
      name: "binary frames",
      send: (socket: WebSocket) => socket.send(Buffer.from("binary")),
    },
    {
      name: "malformed UTF-8",
      send: (socket: WebSocket) => socket.send(Buffer.from([0xc3, 0x28]), { binary: false }),
    },
    {
      name: "malformed JSON",
      send: (socket: WebSocket) => socket.send("{"),
    },
    {
      name: "schema-invalid JSON-RPC",
      send: (socket: WebSocket) => socket.send('{"jsonrpc":"2.0","method":7}'),
    },
    {
      name: "incoming payloads over 10 MiB",
      send: (socket: WebSocket) => socket.send("x".repeat(MAX_PAYLOAD_BYTES + 1)),
    },
  ])("fails closed on $name", async ({ send }) => {
    const server = await startWebSocketServer();
    const connection = nextConnection(server);
    const transport = trackedTransport(new WebSocketClientTransport(new URL(serverUrl(server))));
    const onerror = vi.fn();
    const onmessage = vi.fn();
    transport.onerror = onerror;
    transport.onmessage = onmessage;

    await transport.start();
    const socket = await connection;
    const closed = once(socket, "close");
    send(socket);

    await vi.waitFor(() => expect(onerror).toHaveBeenCalledOnce());
    await closed;
    expect(onmessage).not.toHaveBeenCalled();
  });

  test("ignores later frames after the first protocol violation", async () => {
    const server = await startWebSocketServer();
    const connection = nextConnection(server);
    const transport = trackedTransport(new WebSocketClientTransport(new URL(serverUrl(server))));
    const onerror = vi.fn();
    const onmessage = vi.fn();
    transport.onerror = onerror;
    transport.onmessage = onmessage;

    await transport.start();
    const socket = await connection;
    const closed = once(socket, "close");
    socket.send("{");
    socket.send('{"jsonrpc":"2.0","method":"notifications/after-error"}');

    await vi.waitFor(() => expect(onerror).toHaveBeenCalledOnce());
    await closed;
    expect(onmessage).not.toHaveBeenCalled();
  });

  test("rejects outgoing payloads over 10 MiB without sending", async () => {
    const server = await startWebSocketServer();
    const connection = nextConnection(server);
    const transport = trackedTransport(new WebSocketClientTransport(new URL(serverUrl(server))));
    await transport.start();
    const socket = await connection;
    const received = vi.fn();
    socket.on("message", received);
    const message = {
      jsonrpc: "2.0",
      method: "notifications/oversize",
      params: { value: "x".repeat(MAX_PAYLOAD_BYTES) },
    } satisfies JSONRPCMessage;

    await expect(transport.send(message)).rejects.toThrow();
    await new Promise((resolve) => setImmediate(resolve));
    expect(received).not.toHaveBeenCalled();
  });

  test.each([
    { name: "missing", select: () => false as const },
    { name: "different", select: () => "other" },
  ])("rejects a $name negotiated subprotocol", async ({ select }) => {
    const server = await startWebSocketServer({ handleProtocols: select });
    const transport = trackedTransport(new WebSocketClientTransport(new URL(serverUrl(server))));
    const onerror = vi.fn();
    transport.onerror = onerror;

    await expect(transport.start()).rejects.toThrow();
    expect(onerror).toHaveBeenCalledOnce();
  });

  test("rejects a connection failure and reports it", async () => {
    const server = await startHttpServer();
    const url = httpServerUrl(server).replace("http:", "ws:");
    await closeHttpServer(server);
    openHttpServers.delete(server);
    const transport = trackedTransport(new WebSocketClientTransport(new URL(url)));
    const onerror = vi.fn();
    transport.onerror = onerror;

    await expect(transport.start()).rejects.toThrow();
    expect(onerror).toHaveBeenCalledOnce();
  });

  test("does not follow redirects or expose credentials to the second origin", async () => {
    const redirected = await startWebSocketServer();
    const redirectedHeaders: Array<string | undefined> = [];
    redirected.on("connection", (_socket, request) => {
      redirectedHeaders.push(request.headers["x-upstream-key"] as string | undefined);
    });
    const origin = await startHttpServer();
    origin.on("upgrade", (_request, socket) => {
      socket.end(
        `HTTP/1.1 302 Found\r\nLocation: ${serverUrl(redirected)}\r\nConnection: close\r\n\r\n`,
      );
    });
    const transport = trackedTransport(
      new WebSocketClientTransport(
        new URL(httpServerUrl(origin).replace("http:", "ws:")),
        new Headers([["X-Upstream-Key", "redirect-secret"]]),
      ),
    );

    await expect(transport.start()).rejects.toThrow();
    await new Promise((resolve) => setImmediate(resolve));
    expect(redirectedHeaders).toEqual([]);
  });

  test("aborts a pending opening handshake", async () => {
    const sockets = new Set<Duplex>();
    const server = await startHttpServer();
    server.on("upgrade", (_request, socket) => sockets.add(socket));
    const controller = new AbortController();
    const transport = trackedTransport(
      new WebSocketClientTransport(
        new URL(httpServerUrl(server).replace("http:", "ws:")),
        undefined,
        controller.signal,
      ),
    );
    const onclose = vi.fn();
    transport.onclose = onclose;
    const opening = transport.start();
    await vi.waitFor(() => expect(sockets.size).toBe(1));
    controller.abort();

    await expect(opening).rejects.toMatchObject({ name: "AbortError" });
    await vi.waitFor(() => expect(onclose).toHaveBeenCalledOnce());
    for (const socket of sockets) socket.destroy();
    await transport.close();
  });

  test("rejects when the peer closes during start", async () => {
    const server = await startHttpServer();
    server.on("upgrade", (_request, socket) => socket.destroy());
    const transport = trackedTransport(
      new WebSocketClientTransport(new URL(httpServerUrl(server).replace("http:", "ws:"))),
    );

    await expect(transport.start()).rejects.toThrow();
  });

  test("does not queue, replay, or reconnect and close is idempotent", async () => {
    const server = await startWebSocketServer();
    let connections = 0;
    const frames: string[] = [];
    server.on("connection", (socket) => {
      connections += 1;
      socket.on("message", (data) => frames.push(data.toString()));
    });
    const transport = trackedTransport(new WebSocketClientTransport(new URL(serverUrl(server))));
    const onclose = vi.fn();
    transport.onclose = onclose;
    const message = {
      jsonrpc: "2.0",
      method: "notifications/one",
    } satisfies JSONRPCMessage;

    await expect(transport.send(message)).rejects.toThrow();
    await transport.start();
    await transport.send(message);
    await vi.waitFor(() => expect(frames).toHaveLength(1));
    await transport.close();
    await transport.close();
    await new Promise((resolve) => setImmediate(resolve));

    expect(connections).toBe(1);
    expect(frames).toEqual(['{"jsonrpc":"2.0","method":"notifications/one"}']);
    expect(onclose).toHaveBeenCalledOnce();
  });
});

function trackedTransport(transport: WebSocketClientTransport): WebSocketClientTransport {
  openTransports.add(transport);
  return transport;
}

async function startWebSocketServer(
  options: ConstructorParameters<typeof WebSocketServer>[0] = {},
): Promise<WebSocketServer> {
  const server = new WebSocketServer({
    host: "127.0.0.1",
    port: 0,
    perMessageDeflate: false,
    ...options,
  });
  openServers.add(server);
  await once(server, "listening");
  return server;
}

function nextConnection(server: WebSocketServer): Promise<WebSocket> {
  return once(server, "connection").then(([socket]) => socket as WebSocket);
}

function serverUrl(server: WebSocketServer): string {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");
  return `ws://127.0.0.1:${address.port}/mcp`;
}

function closeWebSocketServer(server: WebSocketServer): Promise<void> {
  if (server.address() === null) return Promise.resolve();
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function startHttpServer(): Promise<Server> {
  const server = createServer();
  openHttpServers.add(server);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return server;
}

function httpServerUrl(server: Server): string {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");
  return `http://127.0.0.1:${address.port}/mcp`;
}

function closeHttpServer(server: Server): Promise<void> {
  if (!server.listening) return Promise.resolve();
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}
