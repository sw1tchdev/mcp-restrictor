import { randomInt } from "node:crypto";
import { createServer, type IncomingMessage, type Server } from "node:http";

import { INVALID_CALLBACK_STRATEGY_MESSAGE } from "../constants.js";
import type { OAuthProfileMetadata } from "../storage.js";
import {
  isExactLoopbackHost,
  isReservedOAuthCallbackParameter,
  MAX_TCP_PORT,
  OAUTH_IPV6_LOOPBACK_HOST,
} from "../urls.js";
import { abortable } from "../../utils/async.js";
import { secureOAuthUrl } from "./discovery.js";

type CallbackIO = {
  readPastedRedirect(): Promise<URL>;
};

export type CallbackPlan = {
  url: URL;
  receive(io: CallbackIO, signal: AbortSignal): Promise<URL>;
  close(): Promise<void>;
};

export async function selectCallback(
  metadata: OAuthProfileMetadata,
  state: string,
  delivery: "listener" | "paste" = "listener",
): Promise<CallbackPlan> {
  if (metadata.callbackUrl) {
    const final = callbackUrl(metadata.callbackUrl);
    if (delivery === "paste") return pasteCallback(final);
    return canListen(final)
      ? openLoopbackCallback(final.hostname, callbackPort(final), state, () => final)
      : pasteCallback(final);
  }

  const strategy = metadata.callback;
  const configuredPort = validPort(strategy.port);
  if (strategy.url !== undefined && (strategy.host !== undefined || strategy.path !== undefined)) {
    throw new Error(INVALID_CALLBACK_STRATEGY_MESSAGE);
  }
  const base = strategy.url === undefined ? undefined : callbackUrl(strategy.url);
  const append = (url: URL) =>
    strategy.appendProfileId ? withProfileSuffix(url, metadata.profileId) : url;
  if (base && !canListen(base)) {
    return pasteCallback(append(base));
  }
  if (!base) {
    if (
      !strategy.host ||
      !isExactLoopbackHost(strategy.host) ||
      !strategy.path?.startsWith("/") ||
      strategy.path.includes("?") ||
      strategy.path.includes("#")
    ) {
      throw new Error(INVALID_CALLBACK_STRATEGY_MESSAGE);
    }
    const host =
      strategy.host === OAUTH_IPV6_LOOPBACK_HOST ? `[${OAUTH_IPV6_LOOPBACK_HOST}]` : strategy.host;
    if (delivery === "paste") {
      const port =
        configuredPort && configuredPort > 0 ? configuredPort : randomInt(49_152, 65_536);
      return pasteCallback(append(callbackUrl(`http://${host}:${port}${strategy.path}`)));
    }
    return openLoopbackCallback(strategy.host, configuredPort ?? 0, state, (port) =>
      append(callbackUrl(`http://${host}:${port}${strategy.path}`)),
    );
  }

  const requestedPort = configuredPort ?? callbackPort(base);
  if (delivery === "paste") {
    const final = new URL(base);
    final.port = String(requestedPort > 0 ? requestedPort : randomInt(49_152, 65_536));
    return pasteCallback(append(final));
  }
  return openLoopbackCallback(base.hostname, requestedPort, state, (port) => {
    const final = new URL(base);
    final.port = String(port);
    return append(final);
  });
}

export function validateCallback(
  received: URL,
  expected: URL,
  state: string,
): { code: string; iss?: string } {
  if (
    received.username ||
    received.password ||
    received.hash ||
    received.protocol !== expected.protocol ||
    received.hostname !== expected.hostname ||
    received.port !== expected.port ||
    received.pathname !== expected.pathname
  ) {
    throw new Error("OAuth callback mismatch");
  }
  const expectedEntries = new Map(expected.searchParams);
  const receivedEntries = new Map<string, string>();
  for (const [name, value] of received.searchParams) {
    if (receivedEntries.has(name)) throw new Error("Duplicate OAuth callback parameter");
    if (!expectedEntries.has(name) && !["code", "state", "iss"].includes(name)) {
      throw new Error("Unexpected OAuth callback parameter");
    }
    receivedEntries.set(name, value);
  }
  for (const [name, value] of expectedEntries) {
    if (receivedEntries.get(name) !== value) throw new Error("OAuth callback query mismatch");
  }
  const code = receivedEntries.get("code");
  if (!code || receivedEntries.get("state") !== state) {
    throw new Error("OAuth callback state mismatch");
  }
  const iss = receivedEntries.get("iss");
  return { code, ...(iss === undefined ? {} : { iss }) };
}

export function redactedCallback(callback: URL): URL {
  const redacted = new URL(callback);
  for (const name of new Set(redacted.searchParams.keys())) {
    redacted.searchParams.set(name, "REDACTED");
  }
  return redacted;
}

export function callbackUrl(value: string): URL {
  const url = secureOAuthUrl(value);
  assertStaticCallback(url);
  return url;
}

function validPort(value: number | undefined): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isInteger(value) || value < 0 || value > MAX_TCP_PORT) {
    throw new Error("Invalid callback port");
  }
  return value;
}

function callbackPort(url: URL): number {
  if (url.port) return Number(url.port);
  return url.protocol === "https:" ? 443 : 80;
}

function canListen(url: URL): boolean {
  return url.protocol === "http:" && isExactLoopbackHost(url.hostname);
}

function withProfileSuffix(url: URL, profileId: string): URL {
  const result = new URL(url);
  result.pathname = `${result.pathname.replace(/\/$/, "")}/mcp-restrictor/${profileId}`;
  assertStaticCallback(result);
  return result;
}

function assertStaticCallback(url: URL): void {
  const seen = new Set<string>();
  for (const [name] of url.searchParams) {
    if (seen.has(name) || isReservedOAuthCallbackParameter(name)) {
      throw new Error("Invalid callback query");
    }
    seen.add(name);
  }
}

function pasteCallback(url: URL): CallbackPlan {
  return {
    url,
    receive: (io, signal) =>
      abortable(
        Promise.resolve().then(() => io.readPastedRedirect()),
        signal,
      ),
    close: async () => undefined,
  };
}

async function openLoopbackCallback(
  hostname: string,
  port: number,
  state: string,
  buildUrl: (boundPort: number) => URL,
): Promise<CallbackPlan> {
  let expected: URL | undefined;
  let settled = false;
  let resolveRedirect!: (url: URL) => void;
  const redirect = new Promise<URL>((resolve) => {
    resolveRedirect = resolve;
  });
  const server = createServer((request, response) => {
    if (settled) {
      response.writeHead(409).end("Authorization callback already received");
      return;
    }
    try {
      if (!expected) throw new Error("Callback is not ready");
      const received = callbackRequestUrl(request, expected);
      validateCallback(received, expected, state);
      settled = true;
      response.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      response.end("Authorization received. You may return to the terminal.");
      resolveRedirect(received);
      server.close();
    } catch {
      response.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      response.end("Invalid authorization callback.");
    }
  });

  const bound = await bind(server, hostname, port);
  if (bound === undefined) {
    if (port === 0) throw new Error("OAuth callback listener failed");
    return pasteCallback(buildUrl(port));
  }
  expected = buildUrl(bound);
  return {
    url: expected,
    receive: (_io, signal) => abortable(redirect, signal),
    close: () => closeServer(server),
  };
}

function callbackRequestUrl(request: IncomingMessage, expected: URL): URL {
  if (request.method !== "GET" || !request.url || !request.headers.host) {
    throw new Error("Invalid callback request");
  }
  return new URL(request.url, `${expected.protocol}//${request.headers.host}`);
}

async function bind(server: Server, hostname: string, port: number): Promise<number | undefined> {
  return new Promise((resolve) => {
    const cleanup = () => {
      server.off("error", onError);
      server.off("listening", onListening);
    };
    const onError = () => {
      cleanup();
      resolve(undefined);
    };
    const onListening = () => {
      cleanup();
      const address = server.address();
      resolve(address && typeof address !== "string" ? address.port : undefined);
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(
      port,
      hostname === `[${OAUTH_IPV6_LOOPBACK_HOST}]` ? OAUTH_IPV6_LOOPBACK_HOST : hostname,
    );
  });
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}
