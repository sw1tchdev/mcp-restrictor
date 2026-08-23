import { join } from "node:path";
import { stringifyPolicy } from "@mcp-restrictor/policy";
import {
  resolveHeaderEnvironment,
  validateRemoteUpstream,
  type UpstreamConfig,
} from "@mcp-restrictor/transports";
import { MASTER_KEY_FILE_ENV } from "../../oauth/storage.js";
import { RESTRICTOR_HOME_DIRECTORY } from "../../utils/paths.js";
import {
  CONTAINER_MARKER_ENV,
  CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE,
  DEFAULT_RESTRICTOR_COMMAND,
  OAUTH_HEADER_MAPPING_CONFLICT_MESSAGE,
  OAUTH_UPSTREAM_REQUIRED_MESSAGE,
  UPSTREAM_KIND_MISMATCH_MESSAGE,
} from "../constants.js";
import { hasMasterKeyHeaderMapping, validOAuthProfileId, validRemoteSource } from "./managed.js";
import type {
  ClientId,
  Replacement,
  RestrictorCommand,
  Scope,
  ServerCandidate,
  SourceSpec,
} from "./model.js";

export function policyLocation(options: {
  client: ClientId;
  scope: Scope;
  serverName: string;
  projectRoot: string;
  restrictorHome: string;
}): { diskPath: string; relativePath: string; argument: string } {
  const fileName = policyFileName(options.serverName);
  const relativePath = join(RESTRICTOR_HOME_DIRECTORY, "policies", options.client, fileName);
  const diskPath =
    options.scope === "project"
      ? join(options.projectRoot, relativePath)
      : join(options.restrictorHome, "policies", options.client, fileName);
  return { diskPath, relativePath, argument: diskPath };
}

export function policyFileName(serverName: string): string {
  return `${encodeURIComponent(serverName)}.yaml`;
}

export function planManagedWrapper(options: {
  server: ServerCandidate;
  allowedTools: readonly string[];
  policy: { diskPath: string; argument: string };
  restrictor: RestrictorCommand;
  projectRoot?: string;
  wrapperCwd?: string;
  verificationEnvironment?: NodeJS.ProcessEnv;
}): {
  replacement: Replacement;
  policySource: string;
  verificationUpstream: UpstreamConfig;
} {
  const effective = validateServerCandidate(options.server);
  const renderedArgs = buildWrapperArgs({
    policyArgument: options.policy.argument,
    source: options.server.source,
    restrictor: options.restrictor,
  });
  const verificationArgs = buildWrapperArgs({
    policyArgument: options.policy.diskPath,
    source: effective,
    restrictor: options.restrictor,
  });
  const wrapperEnvironment = {
    ...(options.server.wrapperEnvironment.env
      ? {
          env: Object.fromEntries(
            Object.entries(options.server.wrapperEnvironment.env).filter(
              ([name]) => name !== CONTAINER_MARKER_ENV,
            ),
          ),
        }
      : {}),
    ...(options.server.wrapperEnvironment.envVars
      ? {
          envVars: options.server.wrapperEnvironment.envVars.filter(
            (variable) =>
              (typeof variable === "string" ? variable : variable.name) !== CONTAINER_MARKER_ENV,
          ),
        }
      : {}),
  };
  const wrapperCwd = options.wrapperCwd;
  const replacement: Replacement = {
    command: options.restrictor.command,
    args: renderedArgs,
    ...wrapperEnvironment,
    ...(wrapperCwd !== undefined ? { cwd: wrapperCwd } : {}),
  };
  const fixedEnvironment: Record<string, string> = {};
  if (
    options.server.source.kind !== "stdio" &&
    options.server.source.kind !== "websocket" &&
    options.server.source.oauthProfileId !== undefined
  ) {
    const keyFile = options.server.wrapperEnvironment.env?.[MASTER_KEY_FILE_ENV];
    if (keyFile !== undefined) fixedEnvironment[MASTER_KEY_FILE_ENV] = keyFile;
  }
  const env = buildVerificationEnvironment({
    source: options.server.source,
    upstream: options.server.upstream,
    fixedEnvironment,
    ...(options.verificationEnvironment
      ? { verificationEnvironment: options.verificationEnvironment }
      : {}),
  });
  const verificationUpstream: UpstreamConfig = {
    kind: "stdio",
    command: options.restrictor.command,
    args: verificationArgs,
    ...(env ? { env } : {}),
    ...(wrapperCwd !== undefined ? { cwd: wrapperCwd } : {}),
  };
  return {
    replacement,
    policySource: stringifyPolicy({
      version: 1,
      default: "deny",
      tools: { allow: options.allowedTools.map((name) => ({ name })), deny: [] },
    }),
    verificationUpstream,
  };
}

export function validateServerCandidate(server: ServerCandidate): SourceSpec {
  const effective = validateCandidateSource(server, server.source, server.upstream);
  for (const alternative of server.alternatives ?? []) {
    validateCandidateSource(server, alternative.source, alternative.upstream);
  }
  buildWrapperArgs({
    policyArgument: "/policy.yaml",
    source: server.source,
    restrictor: { command: DEFAULT_RESTRICTOR_COMMAND, argsPrefix: [] },
  });
  return effective;
}

function validateCandidateSource(
  server: ServerCandidate,
  source: SourceSpec,
  upstream: UpstreamConfig,
): SourceSpec {
  assertNoReservedUpstreamEnvironment(source);
  const candidate = { ...server, source, upstream };
  const effective = effectiveSource(candidate);
  if (source.kind === "stdio") {
    if (upstream.kind !== "stdio") throw new Error(UPSTREAM_KIND_MISMATCH_MESSAGE);
    validateStdioSource(source);
    validateStdioUpstream(upstream);
  }
  validatePlannedSource(candidate, effective);
  return effective;
}

function validateStdioSource(source: Extract<SourceSpec, { kind: "stdio" }>): void {
  if (
    typeof source.command !== "string" ||
    !source.command ||
    !Array.isArray(source.args) ||
    !source.args.every((value) => typeof value === "string") ||
    !Array.isArray(source.envNames) ||
    !source.envNames.every((value) => typeof value === "string") ||
    (source.cwd !== undefined && typeof source.cwd !== "string")
  )
    throw new Error("invalid STDIO upstream");
}

function validateStdioUpstream(upstream: Extract<UpstreamConfig, { kind: "stdio" }>): void {
  if (
    typeof upstream.command !== "string" ||
    !upstream.command ||
    (upstream.args !== undefined &&
      (!Array.isArray(upstream.args) ||
        !upstream.args.every((value) => typeof value === "string"))) ||
    (upstream.cwd !== undefined && typeof upstream.cwd !== "string") ||
    (upstream.env !== undefined &&
      (typeof upstream.env !== "object" ||
        upstream.env === null ||
        Object.hasOwn(upstream.env, CONTAINER_MARKER_ENV) ||
        !Object.values(upstream.env).every((value) => typeof value === "string")))
  )
    throw new Error("invalid STDIO upstream");
}

export function buildWrapperArgs(options: {
  policyArgument: string;
  source: SourceSpec;
  restrictor: RestrictorCommand;
}): string[] {
  const { source } = options;
  assertNoReservedUpstreamEnvironment(source);
  const args = [...options.restrictor.argsPrefix, "--policy", options.policyArgument];
  if (source.kind !== "stdio") {
    const bearerTokenEnvVar = source.kind === "websocket" ? undefined : source.bearerTokenEnvVar;
    const oauthProfileId = source.kind === "websocket" ? undefined : source.oauthProfileId;
    const invalidOAuthProfileId =
      oauthProfileId !== undefined && !validOAuthProfileId(oauthProfileId);
    if (
      (source.kind === "websocket" &&
        (Object.hasOwn(source, "bearerTokenEnvVar") || Object.hasOwn(source, "oauthProfileId"))) ||
      (bearerTokenEnvVar !== undefined &&
        (!bearerTokenEnvVar || bearerTokenEnvVar.startsWith("-"))) ||
      invalidOAuthProfileId
    ) {
      throw new Error(
        invalidOAuthProfileId
          ? "invalid OAuth profile ID"
          : "invalid upstream environment variable name",
      );
    }
    if (oauthProfileId && bearerTokenEnvVar) {
      throw new Error(CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE);
    }
    if (oauthProfileId && hasMasterKeyHeaderMapping(source.headers)) {
      throw new Error(OAUTH_HEADER_MAPPING_CONFLICT_MESSAGE);
    }
    if (
      !validRemoteSource(
        source,
        source.headers,
        bearerTokenEnvVar ? "bearer" : oauthProfileId ? "oauth" : undefined,
      )
    ) {
      throw new Error("invalid remote upstream");
    }
    args.push(`--upstream-${source.kind}`, source.url);
    for (const mapping of source.headers) {
      args.push(
        mapping.encoding === "base64url"
          ? "--upstream-header-base64url-env"
          : "--upstream-header-env",
        `${mapping.name}=${mapping.environmentVariable}`,
      );
    }
    if (source.kind !== "websocket" && source.bearerTokenEnvVar !== undefined) {
      args.push("--upstream-bearer-token-env", source.bearerTokenEnvVar);
    }
    if (source.kind !== "websocket" && source.oauthProfileId !== undefined) {
      args.push("--upstream-oauth-profile", source.oauthProfileId);
    }
    return args;
  }
  if (Object.hasOwn(source, "oauthProfileId")) {
    throw new Error(OAUTH_UPSTREAM_REQUIRED_MESSAGE);
  }
  for (const name of source.envNames) {
    if (!name || name.startsWith("-")) {
      throw new Error("invalid upstream environment variable name");
    }
    args.push("--upstream-env", name);
  }
  if (source.cwd !== undefined) {
    if (!source.cwd || source.cwd.startsWith("-")) {
      throw new Error("invalid upstream working directory");
    }
    args.push("--upstream-cwd", source.cwd);
  }
  args.push("--", source.command, ...source.args);
  return args;
}

function effectiveSource(server: ServerCandidate): SourceSpec {
  if (server.source.kind !== "stdio" && server.upstream.kind === server.source.kind) {
    return { ...server.source, url: server.upstream.url };
  }
  if (server.source.kind === "stdio" && server.upstream.kind === "stdio") {
    return {
      kind: "stdio",
      command: server.upstream.command,
      args: server.upstream.args ?? [],
      envNames: server.source.envNames,
      ...(server.upstream.cwd !== undefined ? { cwd: server.upstream.cwd } : {}),
    };
  }
  throw new Error(UPSTREAM_KIND_MISMATCH_MESSAGE);
}

export function buildVerificationEnvironment(options: {
  source: SourceSpec;
  upstream: UpstreamConfig;
  fixedEnvironment?: Readonly<Record<string, string>>;
  verificationEnvironment?: NodeJS.ProcessEnv;
}): Record<string, string> | undefined {
  const { source, upstream } = options;
  if (upstream.kind === "stdio") {
    const environment: Record<string, string> = {};
    for (const [name, value] of Object.entries(upstream.env ?? {})) {
      if (name !== CONTAINER_MARKER_ENV) defineEnvironmentValue(environment, name, value);
    }
    const containerMarker = options.verificationEnvironment?.[CONTAINER_MARKER_ENV];
    if (containerMarker !== undefined) {
      defineEnvironmentValue(environment, CONTAINER_MARKER_ENV, containerMarker);
    }
    return Object.keys(environment).length > 0 ? environment : undefined;
  }
  if (source.kind === "stdio" || source.kind !== upstream.kind) {
    throw new Error(UPSTREAM_KIND_MISMATCH_MESSAGE);
  }
  const environment: Record<string, string> = {};
  for (const [name, value] of Object.entries(options.fixedEnvironment ?? {})) {
    if (name !== CONTAINER_MARKER_ENV) defineEnvironmentValue(environment, name, value);
  }
  const containerMarker = options.verificationEnvironment?.[CONTAINER_MARKER_ENV];
  if (containerMarker !== undefined) {
    defineEnvironmentValue(environment, CONTAINER_MARKER_ENV, containerMarker);
  }
  const extraCa = options.verificationEnvironment?.NODE_EXTRA_CA_CERTS;
  if (extraCa !== undefined) defineEnvironmentValue(environment, "NODE_EXTRA_CA_CERTS", extraCa);
  for (const mapping of source.headers) {
    const value = upstream.headers?.find(
      ([name]) => name.toLowerCase() === mapping.name.toLowerCase(),
    )?.[1];
    if (value === undefined) throw new Error(`missing upstream header ${mapping.name}`);
    defineEnvironmentValue(
      environment,
      mapping.environmentVariable,
      mapping.encoding === "base64url" ? Buffer.from(value).toString("base64url") : value,
    );
  }
  if (source.kind !== "websocket" && source.bearerTokenEnvVar !== undefined) {
    if (!upstream.bearerToken) {
      throw new Error(`Environment variable ${source.bearerTokenEnvVar} is missing`);
    }
    defineEnvironmentValue(environment, source.bearerTokenEnvVar, upstream.bearerToken);
  }
  return Object.keys(environment).length > 0 ? environment : undefined;
}

function validatePlannedSource(server: ServerCandidate, source: SourceSpec): void {
  if (source.kind === "stdio") {
    if (Object.hasOwn(source, "oauthProfileId")) {
      throw new Error(OAUTH_UPSTREAM_REQUIRED_MESSAGE);
    }
    return;
  }
  if (source.kind === "websocket" && Object.hasOwn(source, "oauthProfileId")) {
    throw new Error("OAuth does not support WebSocket upstreams");
  }
  const oauthProfileId = source.kind === "websocket" ? undefined : source.oauthProfileId;
  if (oauthProfileId !== undefined && !validOAuthProfileId(oauthProfileId)) {
    throw new Error("invalid OAuth profile ID");
  }
  if (source.kind !== "websocket" && oauthProfileId && source.bearerTokenEnvVar) {
    throw new Error(CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE);
  }
  if (oauthProfileId && hasMasterKeyHeaderMapping(source.headers)) {
    throw new Error(OAUTH_HEADER_MAPPING_CONFLICT_MESSAGE);
  }
  const upstream = server.upstream;
  if (upstream.kind !== source.kind) throw new Error(UPSTREAM_KIND_MISMATCH_MESSAGE);
  validateRemoteUpstream({
    kind: upstream.kind,
    url: upstream.url,
    ...(upstream.headers ? { headers: upstream.headers } : {}),
    ...(source.kind !== "websocket" && source.bearerTokenEnvVar
      ? { auth: "bearer" as const }
      : oauthProfileId
        ? { auth: "oauth" as const }
        : {}),
  });
  const explicit = server.wrapperEnvironment.env;
  if (explicit) {
    resolveHeaderEnvironment(
      source.headers.filter(({ environmentVariable }) =>
        Object.hasOwn(explicit, environmentVariable),
      ),
      explicit,
    );
  }
}

export function assertNoReservedUpstreamEnvironment(source: SourceSpec): void {
  const selected =
    source.kind === "stdio"
      ? Array.isArray(source.envNames) && source.envNames.includes(CONTAINER_MARKER_ENV)
      : (Array.isArray(source.headers) &&
          source.headers.some(
            ({ environmentVariable }) => environmentVariable === CONTAINER_MARKER_ENV,
          )) ||
        (source.kind !== "websocket" && source.bearerTokenEnvVar === CONTAINER_MARKER_ENV);
  if (selected) throw new Error("reserved upstream environment variable");
}

function defineEnvironmentValue(
  environment: Record<string, string>,
  name: string,
  value: string,
): void {
  if (Object.hasOwn(environment, name) && environment[name] !== value) {
    throw new Error(`conflicting environment variable ${name}`);
  }
  Object.defineProperty(environment, name, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}
