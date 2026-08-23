import { randomUUID } from "node:crypto";
import { once } from "node:events";
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { parse as parseUrl } from "node:url";
import type { AuditEvent, ToolAuthorizer } from "@mcp-restrictor/core";
import {
  hostHeaderValidation,
  NodeStreamableHTTPServerTransport,
  originValidation,
  toWebRequest,
} from "@modelcontextprotocol/node";
import {
  classifyInboundRequest,
  isJsonContentType,
  PerRequestHTTPServerTransport,
  UnsupportedProtocolVersionError,
  type InboundModernRoute,
} from "@modelcontextprotocol/server";
import { bridgeTransports, type TransportBridge } from "./bridge.js";
import {
  isInitializationBody,
  noBody,
  readJsonBody,
  requestId,
  singleHeader,
  validateStandardHeaders,
  writeClassificationError,
  writeJsonRpcError,
  writeWebResponse,
} from "./http/protocol.js";
import { createUpstreamTransport, type UpstreamConfig } from "./upstream.js";

export type HttpProxyOptions = {
  listen: string;
  tls?: { cert: Buffer; key: Buffer };
  upstream: UpstreamConfig;
  authorizer: ToolAuthorizer;
  audit?: (event: AuditEvent) => void;
  onerror?: (error: Error) => void;
  signal?: AbortSignal;
};

export type HttpProxyHandle = {
  url: string;
  readonly closed: Promise<void>;
  close(): Promise<void>;
};

export type HttpGatewayRoute = {
  path: string;
  upstream: UpstreamConfig;
  authorizer: ToolAuthorizer;
  audit?: (event: AuditEvent) => void;
  onerror?: (error: Error) => void;
};

export type HttpGatewayOptions = {
  listen: string;
  bindHostname?: "0.0.0.0";
  tls?: { cert: Buffer; key: Buffer };
  routes: readonly HttpGatewayRoute[];
  onerror?: (error: Error) => void;
  signal?: AbortSignal;
};

export type HttpGatewayHandle = {
  origin: string;
  readonly closed: Promise<void>;
  close(): Promise<void>;
};

type Session = {
  id?: string;
  transport: NodeStreamableHTTPServerTransport;
  bridge: TransportBridge;
};

type RouteRuntime = {
  handle(request: IncomingMessage, response: ServerResponse): Promise<void>;
  close(): Promise<void>;
};

function createRouteRuntime(route: HttpGatewayRoute, gatewaySignal: AbortSignal): RouteRuntime {
  const sessions = new Map<string, Session>();
  const activeBridges = new Set<TransportBridge>();
  const lifetime = new AbortController();
  const lifetimeSignal = AbortSignal.any([gatewaySignal, lifetime.signal]);
  let closing: Promise<void> | undefined;

  const createSession = async (signal?: AbortSignal): Promise<Session> => {
    let session!: Session;
    const transport = new NodeStreamableHTTPServerTransport({
      sessionIdGenerator: randomUUID,
      enableJsonResponse: true,
      onsessioninitialized: (id) => {
        session.id = id;
        sessions.set(id, session);
      },
      onsessionclosed: async (id) => {
        sessions.delete(id);
        await session.bridge.close();
      },
    });
    const bridge = await bridgeTransports({
      downstream: transport,
      upstream: createUpstreamTransport(route.upstream, undefined, signal),
      authorizer: route.authorizer,
      ...(route.audit ? { audit: route.audit } : {}),
      ...(route.onerror ? { onerror: route.onerror } : {}),
      ...(signal ? { signal } : {}),
    });
    session = { transport, bridge };
    activeBridges.add(bridge);
    void bridge.closed.then(() => {
      activeBridges.delete(bridge);
      if (session.id) sessions.delete(session.id);
    });
    return session;
  };

  const handleModern = async (
    inboundRoute: InboundModernRoute,
    request: IncomingMessage,
    response: ServerResponse,
    body: unknown,
  ): Promise<void> => {
    const controller = new AbortController();
    const abort = () => controller.abort();
    response.once("close", abort);
    const transport = new PerRequestHTTPServerTransport({
      classification: inboundRoute.classification,
    });
    let bridge: TransportBridge | undefined;
    try {
      if (response.destroyed || request.aborted || (request.destroyed && !request.complete)) {
        controller.abort();
      }
      if (controller.signal.aborted) return;
      const signal = AbortSignal.any([lifetimeSignal, controller.signal]);
      const startedBridge = await bridgeTransports({
        downstream: transport,
        upstream: createUpstreamTransport(route.upstream, undefined, signal),
        authorizer: route.authorizer,
        ...(route.audit ? { audit: route.audit } : {}),
        ...(route.onerror ? { onerror: route.onerror } : {}),
        signal,
      });
      bridge = startedBridge;
      activeBridges.add(startedBridge);
      void startedBridge.closed.then(() => activeBridges.delete(startedBridge));
      if (controller.signal.aborted || closing) return;
      const webRequest = await toWebRequest(
        request as IncomingMessage & { method: string; url: string },
        body,
        { signal },
      );
      const webResponse = await transport.handleMessage(inboundRoute.message, {
        request: webRequest,
      });
      if (inboundRoute.messageKind === "notification") await bridge.drain();
      await writeWebResponse(webResponse, response);
    } finally {
      response.removeListener("close", abort);
      await bridge?.close();
    }
  };

  const handle = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    if (!request.method || !request.url) {
      response.writeHead(400).end("Missing HTTP request target");
      return;
    }

    const sessionId = request.headers["mcp-session-id"];
    if (Array.isArray(sessionId)) {
      response.writeHead(400).end("Invalid Mcp-Session-Id");
      return;
    }
    if (sessionId) {
      const session = sessions.get(sessionId);
      if (!session) {
        response.writeHead(404).end("Unknown MCP session");
        return;
      }
      if (request.method === "POST") {
        const body = await readJsonBody(request, response);
        if (body === noBody) return;
        await session.transport.handleRequest(request, response, body);
      } else {
        await session.transport.handleRequest(request, response);
      }
      return;
    }
    if (request.method !== "POST") {
      response.writeHead(400).end("Mcp-Session-Id is required");
      return;
    }
    if (!isJsonContentType(request.headers["content-type"])) {
      writeJsonRpcError(
        response,
        415,
        -32000,
        "Unsupported Media Type: Content-Type must be application/json",
        null,
      );
      return;
    }

    const body = await readJsonBody(request, response);
    if (body === noBody) return;
    const protocolVersionHeader = singleHeader(request.headers["mcp-protocol-version"]);
    const mcpMethodHeader = singleHeader(request.headers["mcp-method"]);
    const mcpNameHeader = singleHeader(request.headers["mcp-name"]);
    const route = classifyInboundRequest({
      httpMethod: request.method,
      ...(protocolVersionHeader === undefined ? {} : { protocolVersionHeader }),
      ...(mcpMethodHeader === undefined ? {} : { mcpMethodHeader }),
      ...(mcpNameHeader === undefined ? {} : { mcpNameHeader }),
      body,
    });
    if (route.kind === "reject") {
      writeClassificationError(response, route, body);
      return;
    }
    if (route.kind === "modern") {
      if (route.classification.revision !== "2026-07-28") {
        const error = new UnsupportedProtocolVersionError({
          supported: ["2026-07-28"],
          requested: route.classification.revision ?? "unknown",
        });
        writeJsonRpcError(response, 400, error.code, error.message, requestId(body), error.data);
        return;
      }
      const headerRejection = validateStandardHeaders(route, mcpMethodHeader, mcpNameHeader);
      if (headerRejection) {
        writeClassificationError(response, headerRejection, body);
        return;
      }
      await handleModern(route, request, response, body);
      return;
    }
    if (!isInitializationBody(body)) {
      response.writeHead(400).end("Sessionless POST must be initialize");
      return;
    }
    const controller = new AbortController();
    const abort = () => {
      if (!response.writableEnded) controller.abort();
    };
    response.once("close", abort);
    let session: Session | undefined;
    try {
      if (request.aborted || (request.destroyed && !request.complete)) {
        controller.abort();
      }
      if (closing || controller.signal.aborted) return;
      session = await createSession(AbortSignal.any([lifetimeSignal, controller.signal]));
      if (closing || controller.signal.aborted) return;
      await session.transport.handleRequest(request, response, body);
    } finally {
      response.removeListener("close", abort);
      if (session && !session.id) await session.bridge.close();
    }
  };

  return {
    handle: async (request, response) => {
      try {
        await handle(request, response);
      } catch (error) {
        route.onerror?.(error instanceof Error ? error : new Error(String(error)));
        if (response.destroyed) return;
        if (!response.headersSent) response.writeHead(500);
        response.end("Internal Server Error");
      }
    },
    close: () => {
      closing ??= (async () => {
        lifetime.abort();
        while (activeBridges.size > 0) {
          const bridges = [...activeBridges];
          await Promise.allSettled(bridges.map((bridge) => bridge.close()));
          for (const bridge of bridges) activeBridges.delete(bridge);
        }
      })();
      return closing;
    },
  };
}

export async function startHttpGateway(options: HttpGatewayOptions): Promise<HttpGatewayHandle> {
  return startHttpGatewayMatching(options, false);
}

async function startHttpGatewayMatching(
  options: HttpGatewayOptions,
  matchPathname: boolean,
): Promise<HttpGatewayHandle> {
  const listen = parseGatewayListenUrl(options.listen, options.tls);
  validateRoutes(options.routes);
  const lifetime = new AbortController();
  const routes = new Map(
    options.routes.map((route) => [route.path, createRouteRuntime(route, lifetime.signal)]),
  );
  const validateHost = hostHeaderValidation([listen.hostname]);
  const validateOrigin = originValidation([listen.hostname]);
  const activeRequests = new Set<Promise<void>>();
  let closing: Promise<void> | undefined;

  const requestListener = (request: IncomingMessage, response: ServerResponse) => {
    let active!: Promise<void>;
    active = (async () => {
      if (!request.method || !request.url) {
        response.writeHead(400).end("Missing HTTP request target");
        return;
      }
      const target = matchPathname ? new URL(request.url, listen.origin).pathname : request.url;
      const runtime = routes.get(target);
      if (!runtime) {
        response.writeHead(404).end("Not Found");
        return;
      }
      if (!validateHost(request, response) || !validateOrigin(request, response)) return;
      await runtime.handle(request, response);
    })()
      .catch((error: unknown) => {
        options.onerror?.(error instanceof Error ? error : new Error(String(error)));
        if (response.destroyed) return;
        if (!response.headersSent) response.writeHead(500);
        response.end("Internal Server Error");
      })
      .finally(() => activeRequests.delete(active));
    activeRequests.add(active);
  };
  const server = options.tls
    ? createHttpsServer(options.tls, requestListener)
    : createHttpServer(requestListener);
  server.on("error", (error) => options.onerror?.(error));
  server.listen(
    Number(listen.port || (listen.protocol === "https:" ? 443 : 80)),
    options.bindHostname ?? listen.hostname,
  );
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Missing listener port");
  }

  const origin = new URL(listen);
  origin.port = String(address.port);
  const listenerClosed = once(server, "close").then(() => undefined);
  const close = (): Promise<void> => {
    closing ??= (async () => {
      options.signal?.removeEventListener("abort", abort);
      if (server.listening) {
        server.close();
      }
      server.closeAllConnections();
      lifetime.abort();
      await Promise.allSettled(Array.from(routes.values(), (runtime) => runtime.close()));
      await Promise.allSettled(activeRequests);
      await listenerClosed;
    })();
    return closing;
  };
  const closed = listenerClosed.then(async () => {
    await closing;
  });
  const abort = () => void close();
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) await close();

  return { origin: origin.origin, closed, close };
}

export async function startHttpProxy(options: HttpProxyOptions): Promise<HttpProxyHandle> {
  const listen = parseListenUrl(options.listen);
  const originalPath = listen.pathname;
  const gateway = await startHttpGatewayMatching(
    {
      listen: listen.origin,
      ...(options.tls ? { tls: options.tls } : {}),
      routes: [
        {
          path: originalPath,
          upstream: options.upstream,
          authorizer: options.authorizer,
          ...(options.audit ? { audit: options.audit } : {}),
          ...(options.onerror ? { onerror: options.onerror } : {}),
        },
      ],
      ...(options.onerror ? { onerror: options.onerror } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
    },
    true,
  );
  listen.port = new URL(gateway.origin).port;
  return {
    url: listen.href,
    closed: gateway.closed,
    close: () => gateway.close(),
  };
}

function validateRoutes(routes: readonly HttpGatewayRoute[]): void {
  if (routes.length === 0) throw new Error("HTTP gateway requires at least one route");
  const paths = new Set<string>();
  for (const route of routes) {
    if (!route.path.startsWith("/")) throw new Error("Route path must have a leading slash");
    if (route.path.includes("?") || route.path.includes("#")) {
      throw new Error("Route path cannot include a query or fragment");
    }
    if (new URL(route.path, "http://localhost").pathname !== route.path) {
      throw new Error("Route path must be canonical");
    }
    if (paths.has(route.path)) throw new Error(`Duplicate route path: ${route.path}`);
    paths.add(route.path);
  }
}

function parseGatewayListenUrl(value: string, tls?: { cert: Buffer; key: Buffer }): URL {
  const url = parseListenUrl(value);
  if (url.pathname !== "/" || parseUrl(value).pathname !== "/" || url.search || url.hash) {
    throw new Error("Gateway listener URL must use the root path");
  }
  if ((url.protocol === "https:") !== Boolean(tls)) {
    throw new Error("HTTPS listener requires TLS certificate and key");
  }
  return url;
}

function parseListenUrl(value: string): URL {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Listener must use http: or https:");
  }
  if (!["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) {
    throw new Error("Listener must bind to loopback");
  }
  if (url.username || url.password) {
    throw new Error("Listener URL cannot include credentials");
  }
  return url;
}
