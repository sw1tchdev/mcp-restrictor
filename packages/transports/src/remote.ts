import { isIP } from "node:net";
import type { FetchLike } from "@modelcontextprotocol/client";
import { CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE } from "./utils.js";

export type RemoteKind = "http" | "sse" | "websocket";
export type UpstreamHeader = readonly [name: string, value: string];
export type HeaderEnvironmentMapping = {
  name: string;
  environmentVariable: string;
  encoding?: "base64url";
};

const environmentName = /^[A-Za-z_][A-Za-z0-9_]*$/;
const transportOwnedHeaders = new Set([
  "host",
  "content-length",
  "connection",
  "upgrade",
  "transfer-encoding",
  "trailer",
  "te",
  "keep-alive",
  "proxy-connection",
  "proxy-authorization",
  "accept",
  "content-type",
  "last-event-id",
]);

export function parseHeaderEnvironmentMapping(
  value: string,
  encoding?: "base64url",
): HeaderEnvironmentMapping {
  const separator = value.indexOf("=");
  if (separator <= 0 || separator === value.length - 1) {
    throw new Error("invalid upstream header environment mapping");
  }
  const name = value.slice(0, separator);
  const environmentVariable = value.slice(separator + 1);
  if (!environmentName.test(environmentVariable)) {
    throw new Error("invalid upstream header environment mapping");
  }
  return { name, environmentVariable, ...(encoding ? { encoding } : {}) };
}

export function resolveHeaderEnvironment(
  mappings: readonly HeaderEnvironmentMapping[],
  environment: NodeJS.ProcessEnv = process.env,
): UpstreamHeader[] {
  return mappings.map(({ name, environmentVariable, encoding }) => {
    const value = Object.hasOwn(environment, environmentVariable)
      ? environment[environmentVariable]
      : undefined;
    if (!value) throw new Error(`Environment variable ${environmentVariable} is missing`);
    const resolved = encoding === "base64url" ? decodeBase64url(value, name) : value;
    try {
      validateHeader(name, resolved);
    } catch {
      throw new Error(`invalid upstream header value for ${name}`);
    }
    return [name, resolved];
  });
}

export function validateRemoteUpstream(options: {
  kind: RemoteKind;
  url: string;
  headers?: readonly UpstreamHeader[];
  auth?: "bearer" | "oauth";
}): { url: URL; headers: Headers } {
  let url: URL;
  try {
    url = new URL(options.url);
  } catch {
    throw new Error("invalid upstream URL");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("unsafe upstream URL");
  }
  const schemes = options.kind === "websocket" ? ["ws:", "wss:"] : ["http:", "https:"];
  if (!schemes.includes(url.protocol)) throw new Error("unsupported upstream URL scheme");

  const seen = new Map<string, string>();
  const headers = options.headers ?? [];
  for (const [name, value] of headers) {
    const normalized = name.toLowerCase();
    const firstName = seen.get(normalized);
    if (firstName) throw new Error(`duplicate upstream header ${firstName}`);
    seen.set(normalized, name);
    validateHeader(name, value);
    if (
      transportOwnedHeaders.has(normalized) ||
      normalized.startsWith("mcp-") ||
      normalized.startsWith("sec-websocket-")
    ) {
      throw new Error("transport-owned upstream header");
    }
    if (normalized === "authorization" && options.auth) {
      throw new Error(CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE);
    }
  }
  if ((options.auth || headers.length > 0) && !isSecureOrLoopback(url)) {
    throw new Error("secure upstream URL is required");
  }
  return {
    url,
    headers: new Headers(headers.map(([name, value]) => [name, value] as [string, string])),
  };
}

export function fetchWithoutRedirects(
  fetchFn?: FetchLike,
  validateResponse?: (response: Response) => void | Promise<void>,
): FetchLike {
  const delegate: FetchLike = fetchFn ?? ((url, init) => fetch(url, init));
  return async (url, init) => {
    const response = await delegate(url, { ...init, redirect: "error" });
    await validateResponse?.(response);
    return response;
  };
}

export function redactUpstreamError(
  phase: "connect" | "request" | "discovery",
  error: unknown,
): Error {
  const status = statusOf(error);
  return new Error(`${phase} failed${status === undefined ? "" : ` (status ${status})`}`);
}

function decodeBase64url(value: string, name: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error(`invalid upstream header value for ${name}`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw new Error(`invalid upstream header value for ${name}`);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(decoded);
  } catch {
    throw new Error(`invalid upstream header value for ${name}`);
  }
}

function validateHeader(name: string, value: string): void {
  try {
    new Headers([[name, value]]);
  } catch {
    throw new Error(`invalid upstream header ${name}`);
  }
}

function isSecureOrLoopback(url: URL): boolean {
  return ["https:", "wss:"].includes(url.protocol) || isLoopback(url.hostname);
}

function isLoopback(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return (
    host === "localhost" ||
    (isIP(host) === 4 && host.startsWith("127.")) ||
    (isIP(host) === 6 && host === "::1")
  );
}

function statusOf(error: unknown): number | undefined {
  if (typeof error !== "object" || error === null) return;
  const record = error as { status?: unknown; data?: { status?: unknown } };
  const status = record.data?.status ?? record.status;
  return typeof status === "number" && Number.isInteger(status) && status >= 100 && status <= 599
    ? status
    : undefined;
}
