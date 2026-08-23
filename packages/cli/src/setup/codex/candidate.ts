import { resolve } from "node:path";
import {
  parseHeaderEnvironmentMapping,
  type HeaderEnvironmentMapping,
} from "@mcp-restrictor/transports";
import {
  isManagedWrapperCommand,
  parseManagedWrapper,
  reserveWrapperEnvironmentName,
  type CodexEnvVar,
  type Scope,
  type ServerCandidate,
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
  INVALID_REMOTE_CONFIGURATION_MESSAGE,
  INVALID_STDIO_ARGUMENTS_MESSAGE,
  INVALID_STDIO_ENVIRONMENT_MESSAGE,
} from "../constants.js";
import { candidateFromSource, challengeHint, oauthHint, validResource } from "./resolution.js";

const clientFields = new Set([
  "enabled",
  "required",
  "startup_timeout_sec",
  "tool_timeout_sec",
  "default_tools_approval_mode",
  "tools",
  "enabled_tools",
  "disabled_tools",
]);
const stdioFields = new Set(["command", "args", "env", "env_vars", "cwd", ...clientFields]);
const httpFields = new Set([
  "url",
  "http_headers",
  "env_http_headers",
  "bearer_token_env_var",
  "auth",
  "scopes",
  "oauth_resource",
  ...clientFields,
]);
const namedUnsupportedFields = new Set(["oauth"]);
const scopeToken = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

export type CallbackConfig = { port: unknown; baseUrl: unknown };

export type CodexServerOptions = {
  path: string;
  scope: Scope;
  environment: NodeJS.ProcessEnv;
  name: string;
  entry: unknown;
  callback: CallbackConfig;
};

export function parseCodexServer(
  options: CodexServerOptions,
): ServerCandidate | { reason: string } {
  if (!isRecord(options.entry)) return { reason: "invalid server entry" };
  const entry = options.entry;
  const metadata = metadataReason(entry);
  if (metadata) return { reason: metadata };
  if (entry.enabled === false) return { reason: "disabled server is not supported" };
  if (Object.hasOwn(entry, "command") && Object.hasOwn(entry, "url")) {
    return { reason: "mixed MCP transports are not supported" };
  }
  if (typeof entry.command === "string" && isManagedWrapperCommand(entry.command)) {
    return parseManagedServer(options, entry, entry.command);
  }
  if (Object.hasOwn(entry, "url")) return parseHttpServer(options, entry);
  return parseStdioServer(options, entry);
}

export function preservedCodexClientFields(
  original: Record<string, unknown>,
): Record<string, unknown> {
  const preserved: Record<string, unknown> = {};
  for (const field of clientFields) {
    if (Object.hasOwn(original, field)) preserved[field] = original[field];
  }
  return preserved;
}

function parseManagedServer(
  options: CodexServerOptions,
  entry: Record<string, unknown>,
  command: string,
): ServerCandidate | { reason: string } {
  const invalid = unsupportedField(entry, stdioFields);
  if (invalid) return { reason: invalid };
  const args = stringArrayOrEmpty(entry.args);
  if (!args) return { reason: INVALID_STDIO_ARGUMENTS_MESSAGE };
  const env = stringRecordOrEmpty(entry.env);
  if (!env) return { reason: INVALID_STDIO_ENVIRONMENT_MESSAGE };
  const envVars = codexEnvVars(entry.env_vars);
  if (!envVars) return { reason: "invalid STDIO environment variables" };
  if (hasRemoteEnvVar(envVars)) return { reason: "remote STDIO executor is not supported" };
  const cwd = optionalString(entry.cwd);
  if (cwd === null) return { reason: "invalid STDIO working directory" };
  const managed = parseManagedWrapper(command, args);
  if (!managed) return { reason: "malformed mcp-restrictor wrapper" };
  const wrapperEnvironment = rawEnvironment(env, envVars);
  const oauth = challengeHint(managed.source, options.callback);
  if (oauth === null) return { reason: INVALID_OAUTH_METADATA_MESSAGE };
  const candidate = candidateFromSource(options, entry, managed.source, wrapperEnvironment, oauth);
  if ("reason" in candidate) return candidate;
  return {
    ...candidate,
    managedPolicyPath: resolve(cwd ?? ".", managed.policyArgument),
  };
}

function parseStdioServer(
  options: CodexServerOptions,
  entry: Record<string, unknown>,
): ServerCandidate | { reason: string } {
  const invalid = unsupportedField(entry, stdioFields);
  if (invalid) return { reason: invalid };
  if (typeof entry.command !== "string" || entry.command.length === 0) {
    return { reason: "invalid STDIO command" };
  }
  const args = stringArrayOrEmpty(entry.args);
  if (!args) return { reason: INVALID_STDIO_ARGUMENTS_MESSAGE };
  const env = stringRecordOrEmpty(entry.env);
  if (!env) return { reason: INVALID_STDIO_ENVIRONMENT_MESSAGE };
  const envVars = codexEnvVars(entry.env_vars);
  if (!envVars) return { reason: "invalid STDIO environment variables" };
  if (hasRemoteEnvVar(envVars)) return { reason: "remote STDIO executor is not supported" };
  const cwd = optionalString(entry.cwd);
  if (cwd === null) return { reason: "invalid STDIO working directory" };
  const envNames = [
    ...new Set([
      ...Object.keys(env),
      ...envVars.map((variable) => (typeof variable === "string" ? variable : variable.name)),
    ]),
  ].sort();
  return candidateFromSource(
    options,
    entry,
    {
      kind: "stdio",
      command: entry.command,
      args,
      envNames,
      ...(cwd !== undefined ? { cwd } : {}),
    },
    rawEnvironment(env, envVars),
  );
}

function parseHttpServer(
  options: CodexServerOptions,
  entry: Record<string, unknown>,
): ServerCandidate | { reason: string } {
  const invalid = unsupportedField(entry, httpFields);
  if (invalid) return { reason: invalid };
  if (typeof entry.url !== "string") return { reason: "invalid HTTP URL" };

  const staticHeaders = stringRecordOrEmpty(entry.http_headers);
  const environmentHeaders = stringRecordOrEmpty(entry.env_http_headers);
  if (!staticHeaders || !environmentHeaders) return { reason: "invalid HTTP headers" };

  const auth = entry.auth;
  if (auth !== undefined && typeof auth !== "string") {
    return { reason: INVALID_OAUTH_METADATA_MESSAGE };
  }
  if (auth !== undefined && auth !== "oauth") {
    return { reason: "unsupported Codex authentication" };
  }

  let scopes: string[] | undefined;
  if (entry.scopes !== undefined) {
    if (
      !Array.isArray(entry.scopes) ||
      !entry.scopes.every((scope) => typeof scope === "string" && scopeToken.test(scope))
    )
      return { reason: INVALID_OAUTH_METADATA_MESSAGE };
    scopes = entry.scopes as string[];
  }

  let resource: string | undefined;
  if (entry.oauth_resource !== undefined) {
    if (typeof entry.oauth_resource !== "string" || !validResource(entry.oauth_resource)) {
      return { reason: INVALID_OAUTH_METADATA_MESSAGE };
    }
    resource = entry.oauth_resource;
  }

  if (
    entry.bearer_token_env_var !== undefined &&
    (typeof entry.bearer_token_env_var !== "string" || !entry.bearer_token_env_var)
  ) {
    return { reason: "invalid bearer token environment variable" };
  }
  const bearerTokenEnvVar = entry.bearer_token_env_var as string | undefined;
  if (bearerTokenEnvVar) {
    try {
      parseHeaderEnvironmentMapping(`Authorization=${bearerTokenEnvVar}`);
    } catch {
      return { reason: "invalid bearer token environment variable" };
    }
  }

  const occupied = new Set(Object.keys(options.environment));
  for (const name of Object.values(environmentHeaders)) occupied.add(name);
  if (bearerTokenEnvVar) occupied.add(bearerTokenEnvVar);
  const headers: HeaderEnvironmentMapping[] = [];
  const wrapperValues: Record<string, string> = {};
  for (const [name, value] of Object.entries(staticHeaders)) {
    const environmentVariable = reserveWrapperEnvironmentName(occupied);
    headers.push({ name, environmentVariable });
    defineOwn(wrapperValues, environmentVariable, value);
  }
  for (const [name, environmentVariable] of Object.entries(environmentHeaders)) {
    try {
      headers.push(parseHeaderEnvironmentMapping(`${name}=${environmentVariable}`));
    } catch {
      return { reason: INVALID_REMOTE_CONFIGURATION_MESSAGE };
    }
  }

  const authorization = headers.some(({ name }) => asciiLower(name) === "authorization");
  const explicitOAuth = auth === "oauth";
  if (
    (bearerTokenEnvVar && explicitOAuth) ||
    (authorization && (bearerTokenEnvVar || explicitOAuth)) ||
    ((bearerTokenEnvVar || authorization) &&
      (Object.hasOwn(entry, "scopes") || Object.hasOwn(entry, "oauth_resource")))
  ) {
    return { reason: "conflicting remote authentication" };
  }

  const oauth = explicitOAuth
    ? oauthHint("explicit", scopes, resource, options.callback)
    : bearerTokenEnvVar || authorization
      ? undefined
      : oauthHint("challenge", scopes, resource, options.callback);
  if (oauth === null) return { reason: INVALID_OAUTH_METADATA_MESSAGE };
  const envVars = [
    ...new Set([
      ...Object.values(environmentHeaders),
      ...(bearerTokenEnvVar ? [bearerTokenEnvVar] : []),
    ]),
  ];
  return candidateFromSource(
    options,
    entry,
    {
      kind: "http",
      url: entry.url,
      headers,
      ...(bearerTokenEnvVar ? { bearerTokenEnvVar } : {}),
    },
    rawEnvironment(wrapperValues, envVars),
    oauth,
  );
}

function metadataReason(entry: Record<string, unknown>): string | undefined {
  if (entry.enabled !== undefined && typeof entry.enabled !== "boolean")
    return "invalid enabled option";
  if (entry.required !== undefined && typeof entry.required !== "boolean")
    return "invalid required option";
  for (const field of ["startup_timeout_sec", "tool_timeout_sec"]) {
    const value = entry[field];
    if (value !== undefined && (typeof value !== "number" || !Number.isFinite(value))) {
      return `invalid ${field} option`;
    }
  }
  if (
    entry.default_tools_approval_mode !== undefined &&
    typeof entry.default_tools_approval_mode !== "string"
  ) {
    return "invalid default_tools_approval_mode option";
  }
  if (entry.tools !== undefined && !isRecord(entry.tools)) return "invalid tools option";
  for (const field of ["enabled_tools", "disabled_tools"]) {
    if (entry[field] !== undefined && stringArrayOrEmpty(entry[field]) === undefined) {
      return `invalid ${field} option`;
    }
  }
  return undefined;
}

function unsupportedField(
  entry: Record<string, unknown>,
  allowed: ReadonlySet<string>,
): string | undefined {
  const field = Object.keys(entry).find((key) => !allowed.has(key));
  if (field === undefined) return undefined;
  return namedUnsupportedFields.has(field)
    ? `unsupported field: ${field}`
    : "unsupported server field";
}

function rawEnvironment(env: Record<string, string>, envVars: CodexEnvVar[]): WrapperEnvironment {
  return {
    ...(Object.keys(env).length ? { env } : {}),
    ...(envVars.length ? { envVars } : {}),
  };
}

function codexEnvVars(value: unknown): CodexEnvVar[] | undefined {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return undefined;
  const result: CodexEnvVar[] = [];
  for (const variable of value) {
    if (typeof variable === "string") {
      result.push(variable);
    } else if (
      isRecord(variable) &&
      Object.keys(variable).length === 2 &&
      typeof variable.name === "string" &&
      (variable.source === "local" || variable.source === "remote")
    ) {
      result.push({ name: variable.name, source: variable.source });
    } else {
      return undefined;
    }
  }
  return result;
}

function hasRemoteEnvVar(envVars: readonly CodexEnvVar[]): boolean {
  return envVars.some((variable) => typeof variable !== "string" && variable.source === "remote");
}

function optionalString(value: unknown): string | undefined | null {
  return value === undefined ? undefined : typeof value === "string" ? value : null;
}
