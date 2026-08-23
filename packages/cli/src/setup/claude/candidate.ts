import { resolve } from "node:path";
import type { HeaderEnvironmentMapping } from "@mcp-restrictor/transports";
import {
  isManagedWrapperCommand,
  parseManagedWrapper,
  reserveWrapperEnvironmentName,
  type Scope,
  type ServerCandidate,
  type SourceSpec,
  type WrapperEnvironment,
} from "../wrapper.js";
import {
  asciiLower,
  defineOwn,
  isRecord,
  stringArrayOrEmpty,
  stringRecordOrEmpty,
} from "../../utils/values.js";
import {
  INVALID_OAUTH_METADATA_MESSAGE,
  INVALID_STDIO_ARGUMENTS_MESSAGE,
  INVALID_STDIO_ENVIRONMENT_MESSAGE,
} from "../constants.js";
import {
  challengeHint,
  expand,
  explicitOAuthHint,
  occupiedEnvironmentNames,
  resolveClaudeCandidate,
} from "./resolution.js";

const stdioFields = new Set(["type", "command", "args", "env", "timeout", "alwaysLoad"]);
const remoteFields = new Set(["type", "url", "headers", "oauth", "timeout", "alwaysLoad"]);
const bearer = /^Bearer \$\{([A-Za-z_][A-Za-z0-9_]*)\}$/;

export type ClaudeServerOptions = {
  path: string;
  scope: Scope;
  projectRoot: string;
  environment: NodeJS.ProcessEnv;
  name: string;
  entry: unknown;
};

export function parseClaudeServer(
  options: ClaudeServerOptions,
): ServerCandidate | { reason: string } {
  if (!isRecord(options.entry)) return { reason: "invalid server entry" };
  const entry = options.entry;
  for (const field of ["disabled", "headersHelper"]) {
    if (Object.hasOwn(entry, field)) return { reason: `unsupported field: ${field}` };
  }
  if (Object.hasOwn(entry, "type") && typeof entry.type !== "string")
    return { reason: "invalid transport" };
  if (
    entry.type === "http" ||
    entry.type === "streamable-http" ||
    entry.type === "sse" ||
    entry.type === "ws"
  ) {
    return parseRemoteServer(options, entry);
  }
  if (entry.type !== undefined && entry.type !== "stdio")
    return { reason: "unsupported transport" };
  return parseStdioServer(options, entry);
}

function parseStdioServer(
  options: ClaudeServerOptions,
  entry: Record<string, unknown>,
): ServerCandidate | { reason: string } {
  const invalid = unsupportedField(entry, stdioFields);
  if (invalid) return { reason: invalid };
  if (typeof entry.command !== "string" || entry.command.length === 0)
    return { reason: "invalid STDIO command" };
  const args = stringArrayOrEmpty(entry.args);
  if (!args) return { reason: INVALID_STDIO_ARGUMENTS_MESSAGE };
  const env = stringRecordOrEmpty(entry.env);
  if (!env) return { reason: INVALID_STDIO_ENVIRONMENT_MESSAGE };
  const metadata = metadataReason(entry);
  if (metadata) return { reason: metadata };

  const managed = parseManagedWrapper(entry.command, args);
  if (isManagedWrapperCommand(entry.command) && !managed) {
    return { reason: "malformed mcp-restrictor wrapper" };
  }
  const source: SourceSpec = managed?.source ?? {
    kind: "stdio",
    command: entry.command,
    args,
    envNames: Object.keys(env).sort(),
  };
  const oauth = managed ? challengeHint(source) : undefined;
  const wrapperEnvironment: WrapperEnvironment = Object.keys(env).length ? { env } : {};
  const candidate = resolveClaudeCandidate(options, entry, source, wrapperEnvironment, oauth);
  if ("reason" in candidate) return candidate;
  return {
    ...candidate,
    ...(managed
      ? { managedPolicyPath: resolve(options.projectRoot, expand(managed.policyArgument, options)) }
      : {}),
  };
}

function parseRemoteServer(
  options: ClaudeServerOptions,
  entry: Record<string, unknown>,
): ServerCandidate | { reason: string } {
  const invalid = unsupportedField(entry, remoteFields);
  if (invalid) return { reason: invalid };
  const kind = entry.type === "sse" ? "sse" : entry.type === "ws" ? "websocket" : "http";
  const label = kind === "websocket" ? "WebSocket" : "HTTP";
  if (typeof entry.url !== "string") return { reason: `invalid ${label} URL` };
  const metadata = metadataReason(entry);
  if (metadata) return { reason: metadata };
  const headers = entry.headers === undefined ? {} : stringRecordOrEmpty(entry.headers);
  if (!headers) return { reason: "invalid remote header" };

  const hasExplicitOAuth = Object.hasOwn(entry, "oauth");
  if (kind === "websocket" && hasExplicitOAuth) {
    return { reason: "OAuth is not supported for WebSocket" };
  }
  const explicitOAuth = hasExplicitOAuth ? explicitOAuthHint(entry.oauth) : undefined;
  if (explicitOAuth === null) return { reason: INVALID_OAUTH_METADATA_MESSAGE };
  const authorizations = Object.entries(headers).filter(
    ([name]) => asciiLower(name) === "authorization",
  );
  if (explicitOAuth && authorizations.length > 0) {
    return { reason: "conflicting remote authentication" };
  }

  const match =
    kind !== "websocket" && authorizations.length === 1
      ? bearer.exec(authorizations[0]![1])
      : undefined;
  const occupied = occupiedEnvironmentNames(options.environment, [
    entry.url,
    ...Object.values(headers),
  ]);
  const mappings: HeaderEnvironmentMapping[] = [];
  const wrapperValues: Record<string, string> = {};
  for (const [name, raw] of Object.entries(headers)) {
    if (match && name === authorizations[0]![0]) continue;
    const environmentVariable = reserveWrapperEnvironmentName(occupied);
    mappings.push({
      name,
      environmentVariable,
      ...(kind === "websocket" ? { encoding: "base64url" as const } : {}),
    });
    defineOwn(
      wrapperValues,
      environmentVariable,
      kind === "websocket" ? Buffer.from(raw).toString("base64url") : raw,
    );
  }
  if (match) defineOwn(wrapperValues, match[1]!, `\${${match[1]!}}`);

  const source: SourceSpec =
    kind === "websocket"
      ? { kind, url: entry.url, headers: mappings }
      : {
          kind,
          url: entry.url,
          headers: mappings,
          ...(match ? { bearerTokenEnvVar: match[1]! } : {}),
        };
  const oauth = explicitOAuth ?? challengeHint(source);
  const wrapperEnvironment: WrapperEnvironment = Object.keys(wrapperValues).length
    ? { env: wrapperValues }
    : {};
  return resolveClaudeCandidate(options, entry, source, wrapperEnvironment, oauth);
}

function unsupportedField(
  entry: Record<string, unknown>,
  allowed: ReadonlySet<string>,
): string | undefined {
  const field = Object.keys(entry).find((key) => !allowed.has(key));
  return field === undefined ? undefined : `unsupported field: ${field}`;
}

function metadataReason(entry: Record<string, unknown>): string | undefined {
  if (
    entry.timeout !== undefined &&
    (typeof entry.timeout !== "number" || !Number.isFinite(entry.timeout))
  ) {
    return "invalid timeout";
  }
  return entry.alwaysLoad !== undefined && typeof entry.alwaysLoad !== "boolean"
    ? "invalid alwaysLoad"
    : undefined;
}
