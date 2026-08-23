import {
  createStdioEnvironment,
  resolveHeaderEnvironment,
  type HeaderEnvironmentMapping,
} from "@mcp-restrictor/transports";
import { DEFAULT_OAUTH_CALLBACK_PATH, MAX_TCP_PORT, OAUTH_LOCALHOST } from "../../oauth/urls.js";
import { defineOwn, isRecord } from "../../utils/values.js";
import { INVALID_REMOTE_CONFIGURATION_MESSAGE } from "../constants.js";
import {
  remoteEndpointReason,
  remoteStructure,
  supportsOAuthChallenge,
  validRemoteConfiguration,
  withStorageEnvironment,
} from "../remote.js";
import {
  type OAuthSetupHint,
  type ServerCandidate,
  type SourceSpec,
  type WrapperEnvironment,
} from "../wrapper.js";
import type { ClaudeServerOptions } from "./candidate.js";

const variable = /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g;
const scopeToken = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

export function resolveClaudeCandidate(
  options: ClaudeServerOptions,
  original: Record<string, unknown>,
  source: SourceSpec,
  wrapperEnvironment: WrapperEnvironment,
  oauth?: OAuthSetupHint,
): ServerCandidate | { reason: string } {
  if (source.kind === "stdio") {
    const explicit = wrapperEnvironment.env ?? {};
    const env = createStdioEnvironment([], options.environment);
    for (const name of source.envNames) {
      const value = Object.hasOwn(explicit, name)
        ? expand(explicit[name]!, options)
        : expansionValue(name, options);
      if (value === undefined) return { reason: "missing STDIO environment variable" };
      Object.defineProperty(env, name, {
        value,
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return {
      client: "claude",
      scope: options.scope,
      name: options.name,
      configPath: options.path,
      source,
      upstream: {
        kind: "stdio",
        command: expand(source.command, options),
        args: source.args.map((argument) => expand(argument, options)),
        env,
      },
      wrapperEnvironment,
      original,
    };
  }

  if (source.kind === "websocket" && source.url.match(variable)) {
    return { reason: "unsupported WebSocket URL" };
  }
  const structure = remoteStructure(source, oauth);
  if ("reason" in structure) return structure;

  const url = source.kind === "websocket" ? source.url : expand(source.url, options);
  const endpointReason = remoteEndpointReason(source, url, structure);
  if (endpointReason) return { reason: endpointReason };

  const effectiveWrapperEnvironment = withStorageEnvironment(
    wrapperEnvironment,
    options.environment,
    source.kind !== "websocket" && (oauth !== undefined || source.oauthProfileId !== undefined),
  );
  const headers = effectiveHeaders(source.headers, effectiveWrapperEnvironment, options);
  if (!headers) return { reason: INVALID_REMOTE_CONFIGURATION_MESSAGE };
  const bearerTokenEnvVar = source.kind === "websocket" ? undefined : source.bearerTokenEnvVar;
  const token =
    bearerTokenEnvVar === undefined
      ? undefined
      : effectiveEnvironmentValue(bearerTokenEnvVar, effectiveWrapperEnvironment, options);
  if (bearerTokenEnvVar && !token) {
    return { reason: "missing HTTP bearer environment variable" };
  }
  if (!validRemoteConfiguration(source.kind, url, headers, structure.auth)) {
    return { reason: INVALID_REMOTE_CONFIGURATION_MESSAGE };
  }
  const upstream =
    source.kind === "websocket"
      ? { kind: source.kind, url, ...(headers.length ? { headers } : {}) }
      : {
          kind: source.kind,
          url,
          ...(headers.length ? { headers } : {}),
          ...(token !== undefined ? { bearerToken: token } : {}),
        };
  return {
    client: "claude",
    scope: options.scope,
    name: options.name,
    configPath: options.path,
    source,
    upstream,
    wrapperEnvironment: effectiveWrapperEnvironment,
    original,
    ...(oauth ? { oauth } : {}),
  };
}

export function explicitOAuthHint(value: unknown): OAuthSetupHint | null {
  if (!isRecord(value)) return null;
  if (
    Object.keys(value).some(
      (field) => !["clientId", "authServerMetadataUrl", "scopes", "callbackPort"].includes(field),
    )
  )
    return null;
  const clientId = value.clientId;
  if (clientId !== undefined && (typeof clientId !== "string" || clientId.length === 0))
    return null;
  const scopes = value.scopes;
  if (
    scopes !== undefined &&
    (typeof scopes !== "string" || !scopes.split(" ").every((scope) => scopeToken.test(scope)))
  )
    return null;
  const callbackPort = value.callbackPort;
  if (
    callbackPort !== undefined &&
    (typeof callbackPort !== "number" ||
      !Number.isInteger(callbackPort) ||
      callbackPort < 0 ||
      callbackPort > MAX_TCP_PORT)
  )
    return null;
  const metadataUrl = value.authServerMetadataUrl;
  if (metadataUrl !== undefined) {
    if (typeof metadataUrl !== "string") return null;
    try {
      const url = new URL(metadataUrl);
      if (url.protocol !== "https:" || url.username || url.password || url.hash) return null;
    } catch {
      return null;
    }
  }
  return {
    mode: "explicit",
    ...(clientId === undefined ? {} : { clientId }),
    ...(scopes === undefined ? {} : { requestedScope: scopes }),
    ...(metadataUrl === undefined ? {} : { authServerMetadataUrl: metadataUrl }),
    callback: {
      host: OAUTH_LOCALHOST,
      path: DEFAULT_OAUTH_CALLBACK_PATH,
      ...(callbackPort === undefined ? {} : { port: callbackPort }),
      appendProfileId: false,
    },
  };
}

export function challengeHint(source: SourceSpec): OAuthSetupHint | undefined {
  if (!supportsOAuthChallenge(source)) return undefined;
  return {
    mode: "challenge",
    callback: {
      host: OAUTH_LOCALHOST,
      path: DEFAULT_OAUTH_CALLBACK_PATH,
      appendProfileId: false,
    },
  };
}

export function occupiedEnvironmentNames(
  environment: NodeJS.ProcessEnv,
  rawValues: readonly string[],
): Set<string> {
  const occupied = new Set(Object.keys(environment));
  for (const value of rawValues) {
    for (const match of value.matchAll(variable)) occupied.add(match[1]!);
  }
  return occupied;
}

function effectiveHeaders(
  mappings: readonly HeaderEnvironmentMapping[],
  wrapper: WrapperEnvironment,
  options: Pick<ClaudeServerOptions, "environment" | "projectRoot">,
) {
  const environment: Record<string, string> = {};
  for (const { environmentVariable } of mappings) {
    const value = effectiveEnvironmentValue(environmentVariable, wrapper, options);
    if (value === undefined) return undefined;
    defineOwn(environment, environmentVariable, value);
  }
  try {
    return resolveHeaderEnvironment(mappings, environment);
  } catch {
    return undefined;
  }
}

function effectiveEnvironmentValue(
  name: string,
  wrapper: WrapperEnvironment,
  options: Pick<ClaudeServerOptions, "environment" | "projectRoot">,
): string | undefined {
  if (wrapper.env && Object.hasOwn(wrapper.env, name)) return expand(wrapper.env[name]!, options);
  return expansionValue(name, options);
}

export function expand(
  value: string,
  options: Pick<ClaudeServerOptions, "environment" | "projectRoot">,
): string {
  return value.replace(variable, (literal: string, name: string, fallback: string | undefined) => {
    const expanded = expansionValue(name, options);
    if (fallback === undefined) return expanded === undefined ? literal : expanded;
    return expanded === undefined || expanded === "" ? fallback : expanded;
  });
}

function expansionValue(
  name: string,
  options: Pick<ClaudeServerOptions, "environment" | "projectRoot">,
): string | undefined {
  return name === "CLAUDE_PROJECT_DIR"
    ? options.projectRoot
    : Object.hasOwn(options.environment, name)
      ? options.environment[name]
      : undefined;
}
