import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import { WebSocketServer } from "ws";
import type { RemoteKind } from "../src/remote.js";

type OAuthExpectation = {
  expectedScope: string;
  expectedCallback: "claude" | "codex" | "manual";
  challengeScope?: string;
};

export async function startRemoteAuthFixture(options: {
  transport: RemoteKind;
  requiredHeaders?: Record<string, string>;
  oauth?: OAuthExpectation;
}): Promise<{
  url: string;
  authorizationRequests(): number;
  tokenRequests(): number;
  refreshRequests(): number;
  expireAccessToken(): void;
  sensitiveValues(): string[];
  close(): Promise<void>;
}> {
  if (options.transport === "websocket") {
    if (options.oauth) throw new Error("OAuth does not support WebSocket");
    return startWebSocket(options.requiredHeaders);
  }

  let origin = "";
  let resourceUrl = "";
  const sseStreams = new Map<string, ServerResponse>();
  let accessToken = "fixture-access-1";
  let refreshToken = "fixture-refresh-1";
  let expired = false;
  let authorizationCount = 0;
  let tokenCount = 0;
  let refreshCount = 0;
  const sensitiveValues = new Set<string>([
    "fixture-header-error-body",
    ...(options.oauth
      ? [
          "fixture-access-1",
          "fixture-refresh-1",
          "fixture-client-secret",
          "fixture-raw-challenge-body",
        ]
      : []),
  ]);
  let registeredRedirectUri: string | undefined;
  let authorization: { code: string; challenge: string; redirectUri: string } | undefined;
  const transport = new NodeStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  transport.onmessage = (message) => {
    if (!("id" in message) || !("method" in message)) return;
    const request = message as RpcRequest;
    void transport.send(rpcResponse(request), { relatedRequestId: request.id });
  };
  await transport.start();

  const server = createServer((request, response) => {
    void handle(request, response).catch(() => response.writeHead(500).end());
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");
  origin = `http://127.0.0.1:${address.port}`;
  resourceUrl = `${origin}/${options.transport === "sse" ? "events" : "mcp"}`;

  async function handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const target = new URL(request.url ?? "/", origin);
    if (
      target.pathname === "/mcp" ||
      target.pathname === "/events" ||
      target.pathname === "/messages"
    ) {
      if (!requiredHeadersMatch(request, options.requiredHeaders)) {
        response.writeHead(400).end("fixture-header-error-body");
        return;
      }
      if (options.oauth && (request.headers.authorization !== `Bearer ${accessToken}` || expired)) {
        const scope =
          options.oauth.challengeScope === undefined
            ? ""
            : `, scope="${options.oauth.challengeScope}"`;
        response
          .writeHead(401, {
            "WWW-Authenticate": `Bearer resource_metadata="${origin}/resource-metadata"${scope}`,
            "content-type": "application/json",
          })
          .end(JSON.stringify({ error: "fixture-raw-challenge-body" }));
        return;
      }
      if (options.transport === "http") {
        await transport.handleRequest(request, response);
        return;
      }
      if (request.method === "GET" && target.pathname === "/events") {
        const sessionId = randomBytes(12).toString("base64url");
        sseStreams.set(sessionId, response);
        response.once("close", () => sseStreams.delete(sessionId));
        response.writeHead(200, {
          "cache-control": "no-cache",
          "content-type": "text/event-stream",
        });
        response.write(`event: endpoint\ndata: /messages?sessionId=${sessionId}\n\n`);
        return;
      }
      if (request.method !== "POST" || target.pathname !== "/messages") {
        response.writeHead(404).end();
        return;
      }
      const rpc = JSON.parse(await requestText(request)) as RpcRequest;
      const stream = sseStreams.get(target.searchParams.get("sessionId") ?? "");
      if (!stream) {
        response.writeHead(404).end();
        return;
      }
      if (rpc.id !== undefined) {
        stream.write(`data: ${JSON.stringify(rpcResponse(rpc))}\n\n`);
      }
      response.writeHead(202).end();
      return;
    }
    if (
      hasFixtureHeader(request, options.requiredHeaders) ||
      /^Bearer fixture-/i.test(request.headers.authorization ?? "")
    ) {
      response.writeHead(400).end("resource header leaked");
      return;
    }
    if (
      target.pathname === "/resource-metadata" ||
      target.pathname.includes(".well-known/oauth-protected-resource")
    ) {
      sendJson(response, {
        resource: resourceUrl,
        authorization_servers: [`${origin}/`],
        scopes_supported: [options.oauth?.expectedScope ?? "fixture-scope"],
      });
      return;
    }
    if (
      target.pathname.includes(".well-known/oauth-authorization-server") ||
      target.pathname.includes(".well-known/openid-configuration")
    ) {
      sendJson(response, {
        issuer: `${origin}/`,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        registration_endpoint: `${origin}/register`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
      });
      return;
    }
    if (target.pathname === "/register") {
      const registration = JSON.parse(await requestText(request)) as Record<string, unknown>;
      registeredRedirectUri =
        Array.isArray(registration.redirect_uris) &&
        typeof registration.redirect_uris[0] === "string"
          ? registration.redirect_uris[0]
          : undefined;
      if (!registeredRedirectUri) throw new Error("missing registered redirect URI");
      validateCallbackUrl(registeredRedirectUri, options.oauth?.expectedCallback);
      sendJson(
        response,
        {
          ...registration,
          client_id: "fixture-client",
          client_secret: "fixture-client-secret",
          token_endpoint_auth_method: "client_secret_post",
        },
        201,
      );
      return;
    }
    if (target.pathname === "/authorize") {
      authorizationCount += 1;
      const redirectUri = requiredParameter(target, "redirect_uri");
      const state = requiredParameter(target, "state");
      const scope = requiredParameter(target, "scope");
      const challenge = requiredParameter(target, "code_challenge");
      if (
        scope !== options.oauth?.expectedScope ||
        target.searchParams.get("resource") !== resourceUrl ||
        redirectUri !== registeredRedirectUri ||
        target.searchParams.get("code_challenge_method") !== "S256"
      )
        throw new Error("invalid authorization request");
      const code = randomBytes(16).toString("base64url");
      sensitiveValues.add(code);
      authorization = { code, challenge, redirectUri };
      const callback = new URL(redirectUri);
      callback.searchParams.set("code", code);
      callback.searchParams.set("state", state);
      callback.searchParams.set("iss", `${origin}/`);
      response.writeHead(302, { location: callback.href }).end();
      return;
    }
    if (target.pathname === "/token") {
      tokenCount += 1;
      const body = new URLSearchParams(await requestText(request));
      if (
        body.get("client_id") !== "fixture-client" ||
        body.get("client_secret") !== "fixture-client-secret" ||
        body.get("resource") !== resourceUrl
      )
        throw new Error("invalid client authentication");
      if (body.get("grant_type") === "refresh_token") {
        if (body.get("refresh_token") !== refreshToken) throw new Error("invalid refresh token");
        refreshCount += 1;
        accessToken = `fixture-access-${refreshCount + 1}`;
        refreshToken = `fixture-refresh-${refreshCount + 1}`;
        sensitiveValues.add(accessToken);
        sensitiveValues.add(refreshToken);
        expired = false;
      } else {
        const verifier = requiredForm(body, "code_verifier");
        sensitiveValues.add(verifier);
        if (
          !authorization ||
          body.get("code") !== authorization.code ||
          body.get("redirect_uri") !== authorization.redirectUri ||
          createHash("sha256").update(verifier).digest("base64url") !== authorization.challenge
        )
          throw new Error("invalid authorization code exchange");
      }
      sendJson(response, {
        access_token: accessToken,
        refresh_token: refreshToken,
        token_type: "Bearer",
        expires_in: 3600,
      });
      return;
    }
    response.writeHead(404).end();
  }

  return {
    url: options.transport === "sse" ? `${origin}/events` : resourceUrl,
    authorizationRequests: () => authorizationCount,
    tokenRequests: () => tokenCount,
    refreshRequests: () => refreshCount,
    expireAccessToken: () => {
      expired = true;
    },
    sensitiveValues: () => [...sensitiveValues],
    close: async () => {
      for (const stream of sseStreams.values()) stream.end();
      sseStreams.clear();
      await transport.close();
      server.closeAllConnections();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}

type RpcRequest = {
  jsonrpc: "2.0";
  id: string | number;
  method: string;
  params?: { protocolVersion?: string; cursor?: string; name?: string };
};

function rpcResponse(request: RpcRequest) {
  const result =
    request.method === "initialize"
      ? {
          protocolVersion: request.params?.protocolVersion ?? "",
          capabilities: { tools: {} },
          serverInfo: { name: "remote-auth-fixture", version: "1.0.0" },
        }
      : request.method === "tools/list" && request.params?.cursor !== "page-2"
        ? {
            tools: [{ name: "allowed_tool", inputSchema: { type: "object" } }],
            nextCursor: "page-2",
          }
        : request.method === "tools/list"
          ? { tools: [{ name: "denied_tool", inputSchema: { type: "object" } }] }
          : request.method === "tools/call"
            ? {
                content: [
                  {
                    type: "text",
                    text: `configured upstream:${request.params?.name ?? ""}`,
                  },
                ],
              }
            : {};
  return { jsonrpc: "2.0" as const, id: request.id, result };
}

async function startWebSocket(
  requiredHeaders: Record<string, string> | undefined,
): ReturnType<typeof startRemoteAuthFixture> {
  const server = new WebSocketServer({
    host: "127.0.0.1",
    port: 0,
    perMessageDeflate: false,
    handleProtocols: (protocols) => (protocols.has("mcp") ? "mcp" : false),
  });
  server.on("connection", (socket, request) => {
    if (!requiredHeadersMatch(request, requiredHeaders)) {
      socket.terminate();
      return;
    }
    socket.on("message", (data, isBinary) => {
      if (isBinary) return;
      const message = JSON.parse(data.toString()) as RpcRequest;
      if (message.id !== undefined) socket.send(JSON.stringify(rpcResponse(message)));
    });
  });
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");
  return {
    url: `ws://127.0.0.1:${address.port}/mcp`,
    authorizationRequests: () => 0,
    tokenRequests: () => 0,
    refreshRequests: () => 0,
    expireAccessToken: () => undefined,
    sensitiveValues: () => [],
    close: async () => {
      for (const client of server.clients) client.terminate();
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}

function validateCallbackUrl(
  value: string,
  expected: OAuthExpectation["expectedCallback"] | undefined,
): void {
  if (!expected) throw new Error("missing callback expectation");
  const callback = new URL(value);
  const port = Number(callback.port);
  if (
    callback.protocol !== "http:" ||
    callback.username ||
    callback.password ||
    callback.search ||
    callback.hash ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65_535
  )
    throw new Error("invalid registered callback URI");
  if (expected === "claude") {
    if (callback.hostname !== "localhost" || callback.pathname !== "/callback") {
      throw new Error("invalid Claude callback URI");
    }
    return;
  }
  if (
    callback.hostname !== "127.0.0.1" ||
    !/^\/callback\/mcp-restrictor\/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
      callback.pathname,
    )
  )
    throw new Error("invalid profile callback URI");
}

function requiredHeadersMatch(
  request: IncomingMessage,
  expected: Record<string, string> | undefined,
): boolean {
  return Object.entries(expected ?? {}).every(
    ([name, value]) => request.headers[name.toLowerCase()] === value,
  );
}

function hasFixtureHeader(
  request: IncomingMessage,
  expected: Record<string, string> | undefined,
): boolean {
  return Object.keys(expected ?? {}).some(
    (name) => request.headers[name.toLowerCase()] !== undefined,
  );
}

function requiredParameter(url: URL, name: string): string {
  const value = url.searchParams.get(name);
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

function requiredForm(body: URLSearchParams, name: string): string {
  const value = body.get(name);
  if (!value) throw new Error(`missing ${name}`);
  return value;
}

async function requestText(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function sendJson(response: ServerResponse, value: unknown, status = 200): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}
