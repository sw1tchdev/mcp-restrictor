import {
  createStdioEnvironment,
  resolveHeaderEnvironment,
  type HeaderEnvironmentMapping,
} from "@mcp-restrictor/transports";
import {
  DEFAULT_OAUTH_CALLBACK_PATH,
  isExactLoopbackHost,
  MAX_TCP_PORT,
  OAUTH_IPV4_LOOPBACK_HOST,
} from "../../oauth/urls.js";
import { defineOwn } from "../../utils/values.js";
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
import type { CallbackConfig, CodexServerOptions } from "./candidate.js";

export function candidateFromSource(
  options: CodexServerOptions,
  original: Record<string, unknown>,
  source: SourceSpec,
  wrapperEnvironment: WrapperEnvironment,
  oauth?: OAuthSetupHint,
): ServerCandidate | { reason: string } {
  if (source.kind === "stdio") {
    const env = createStdioEnvironment([], options.environment);
    for (const name of source.envNames) {
      const value = environmentValue(name, wrapperEnvironment, options.environment);
      if (value === undefined) return { reason: "required environment variable is missing" };
      Object.defineProperty(env, name, {
        value,
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    return {
      client: "codex",
      scope: options.scope,
      name: options.name,
      configPath: options.path,
      source,
      upstream: {
        kind: "stdio",
        command: source.command,
        args: source.args,
        env,
        ...(source.cwd !== undefined ? { cwd: source.cwd } : {}),
      },
      wrapperEnvironment,
      original,
    };
  }

  const structure = remoteStructure(source, oauth);
  if ("reason" in structure) return structure;

  const endpointReason = remoteEndpointReason(source, source.url, structure);
  if (endpointReason) return { reason: endpointReason };

  const values = new Map<string, string | undefined>();
  const read = (name: string): string | undefined => {
    if (!values.has(name)) {
      values.set(name, environmentValue(name, wrapperEnvironment, options.environment));
    }
    return values.get(name);
  };
  const headers = effectiveHeaders(source.headers, read);
  if (!headers) return { reason: INVALID_REMOTE_CONFIGURATION_MESSAGE };
  const bearerTokenEnvVar = source.kind === "websocket" ? undefined : source.bearerTokenEnvVar;
  const bearerToken = bearerTokenEnvVar === undefined ? undefined : read(bearerTokenEnvVar);
  if (bearerTokenEnvVar && !bearerToken) {
    return { reason: "required environment variable is missing" };
  }
  if (!validRemoteConfiguration(source.kind, source.url, headers, structure.auth)) {
    return { reason: INVALID_REMOTE_CONFIGURATION_MESSAGE };
  }

  const effectiveWrapperEnvironment = withStorageEnvironment(
    wrapperEnvironment,
    options.environment,
    source.kind !== "websocket" && (oauth !== undefined || source.oauthProfileId !== undefined),
  );
  const upstream =
    source.kind === "websocket"
      ? {
          kind: source.kind,
          url: source.url,
          ...(headers.length ? { headers } : {}),
        }
      : {
          kind: source.kind,
          url: source.url,
          ...(headers.length ? { headers } : {}),
          ...(bearerToken !== undefined ? { bearerToken } : {}),
        };
  return {
    client: "codex",
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

export function oauthHint(
  mode: "explicit" | "challenge",
  scopes: readonly string[] | undefined,
  resource: string | undefined,
  config: CallbackConfig,
): OAuthSetupHint | null {
  const callback = codexCallback(config);
  if (!callback) return null;
  return {
    mode,
    ...(scopes?.length ? { fallbackScope: scopes.join(" ") } : {}),
    ...(resource === undefined ? {} : { resource }),
    callback,
  };
}

export function challengeHint(
  source: SourceSpec,
  config: CallbackConfig,
): OAuthSetupHint | null | undefined {
  if (!supportsOAuthChallenge(source)) return undefined;
  return oauthHint("challenge", undefined, undefined, config);
}

export function validResource(value: string): boolean {
  try {
    return !new URL(value).hash;
  } catch {
    return false;
  }
}

function codexCallback(config: CallbackConfig): OAuthSetupHint["callback"] | null {
  const port = config.port;
  if (
    port !== undefined &&
    (typeof port !== "number" || !Number.isInteger(port) || port < 0 || port > MAX_TCP_PORT)
  )
    return null;
  const baseUrl = config.baseUrl;
  if (baseUrl !== undefined) {
    if (typeof baseUrl !== "string") return null;
    try {
      const parsed = new URL(baseUrl);
      if (
        parsed.username ||
        parsed.password ||
        parsed.hash ||
        (parsed.protocol !== "https:" &&
          !(parsed.protocol === "http:" && isExactLoopbackHost(parsed.hostname)))
      )
        return null;
    } catch {
      return null;
    }
  }
  return baseUrl === undefined
    ? {
        host: OAUTH_IPV4_LOOPBACK_HOST,
        path: DEFAULT_OAUTH_CALLBACK_PATH,
        ...(port === undefined ? {} : { port }),
        appendProfileId: true,
      }
    : {
        url: baseUrl,
        ...(port === undefined ? {} : { port }),
        appendProfileId: true,
      };
}

function effectiveHeaders(
  mappings: readonly HeaderEnvironmentMapping[],
  read: (name: string) => string | undefined,
) {
  const headers: Array<readonly [string, string]> = [];
  for (const mapping of mappings) {
    const value = read(mapping.environmentVariable);
    if (value === undefined) return undefined;
    const environment: Record<string, string> = {};
    defineOwn(environment, mapping.environmentVariable, value);
    try {
      headers.push(resolveHeaderEnvironment([mapping], environment)[0]!);
    } catch {
      return undefined;
    }
  }
  return headers;
}

function environmentValue(
  name: string,
  wrapper: WrapperEnvironment,
  environment: NodeJS.ProcessEnv,
): string | undefined {
  if (wrapper.env && Object.hasOwn(wrapper.env, name)) return wrapper.env[name];
  const declared = wrapper.envVars?.some((variable) =>
    typeof variable === "string"
      ? variable === name
      : variable.source === "local" && variable.name === name,
  );
  const value = declared && Object.hasOwn(environment, name) ? environment[name] : undefined;
  return typeof value === "string" ? value : undefined;
}
