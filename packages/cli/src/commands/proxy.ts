import { readFile } from "node:fs/promises";
import type { Readable, Writable } from "node:stream";
import { parseArgs } from "node:util";
import { createPolicyAuthorizer, loadPolicy } from "@mcp-restrictor/policy";
import {
  createStdioEnvironment,
  parseHeaderEnvironmentMapping,
  resolveHeaderEnvironment,
  runStdioProxy,
  startHttpProxy,
  validateRemoteUpstream,
  type HttpGatewayRoute,
  type RemoteKind,
  type UpstreamConfig,
  type UpstreamHeader,
} from "@mcp-restrictor/transports";
import { createOAuthAuthProvider, oauthProfileResource } from "../oauth/provider.js";
import { OAUTH_SERVER_BINDING_MISMATCH_MESSAGE } from "../oauth/constants.js";
import {
  MASTER_KEY_FILE_ENV,
  assertProfileId,
  readOAuthProfile,
  type OAuthProfile,
} from "../oauth/storage.js";
import { asciiLower } from "../utils/values.js";
import { TERMINATION_SIGNALS } from "../utils/async.js";
import {
  CONTAINER_MARKER_ENV,
  CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE,
  OAUTH_HEADER_MAPPING_CONFLICT_MESSAGE,
} from "../setup/constants.js";

const directProxyUsage =
  "Usage: mcp-restrictor --policy FILE [--listen-http URL | --listen-https URL --tls-cert FILE --tls-key FILE] (--upstream-http URL | --upstream-sse URL | --upstream-websocket URL | -- COMMAND [ARGS...])";
const routeArgumentOptions = {
  policy: { type: "string" },
  "upstream-http": { type: "string", multiple: true },
  "upstream-sse": { type: "string", multiple: true },
  "upstream-websocket": { type: "string", multiple: true },
  "upstream-header-env": { type: "string", multiple: true },
  "upstream-header-base64url-env": { type: "string", multiple: true },
  "upstream-bearer-token-env": { type: "string" },
  "upstream-oauth-profile": { type: "string", multiple: true },
  "upstream-env": { type: "string", multiple: true },
  "upstream-cwd": { type: "string" },
} as const;
const directArgumentOptions = {
  ...routeArgumentOptions,
  policy: { type: "string", short: "p" },
  "listen-http": { type: "string" },
  "listen-https": { type: "string" },
  "tls-cert": { type: "string" },
  "tls-key": { type: "string" },
} as const;

export type ResolvedProxyRoute = {
  upstream: UpstreamConfig;
  authorizer: HttpGatewayRoute["authorizer"];
};

type DirectArgumentValues = {
  policy?: string;
  "upstream-http"?: string[];
  "upstream-sse"?: string[];
  "upstream-websocket"?: string[];
  "upstream-header-env"?: string[];
  "upstream-header-base64url-env"?: string[];
  "upstream-bearer-token-env"?: string;
  "upstream-oauth-profile"?: string[];
  "upstream-env"?: string[];
  "upstream-cwd"?: string;
};

export type ProxyRuntimeOptions = {
  signal?: AbortSignal;
  readOAuthProfile?: typeof readOAuthProfile;
  createOAuthAuthProvider?: typeof createOAuthAuthProvider;
};

export async function runProxyCommand(
  options: ProxyRuntimeOptions & {
    runStdioProxy?: typeof runStdioProxy;
    startHttpProxy?: typeof startHttpProxy;
  },
  context: {
    argv: readonly string[];
    environment: NodeJS.ProcessEnv;
    home: string;
    input: Readable;
    output: Writable;
  },
): Promise<void> {
  const error = process.stderr;
  const { values, positionals } = parseArgs({
    args: context.argv.slice(2),
    allowPositionals: true,
    options: directArgumentOptions,
    strict: true,
  });

  const listenHttp = values["listen-http"];
  const listenHttps = values["listen-https"];
  const tlsCertificate = values["tls-cert"];
  const tlsKey = values["tls-key"];
  if (listenHttp && listenHttps) {
    throw new Error("--listen-http and --listen-https are mutually exclusive");
  }
  if (listenHttps && (!tlsCertificate || !tlsKey)) {
    throw new Error("--listen-https requires --tls-cert and --tls-key");
  }
  if (!listenHttps && (tlsCertificate || tlsKey)) {
    throw new Error("--tls-cert and --tls-key require --listen-https");
  }

  const ownedController = new AbortController();
  const signal = options.signal ?? ownedController.signal;
  const abort = () => ownedController.abort();
  if (!options.signal) {
    for (const signal of TERMINATION_SIGNALS) process.once(signal, abort);
  }

  try {
    const listen = listenHttps ?? listenHttp;
    let tls: { cert: Buffer; key: Buffer } | undefined;
    const route = await resolveProxyRouteWithPolicyPhase(
      canonicalRouteArguments(values as DirectArgumentValues, positionals),
      {
        ...options,
        signal,
      },
      context,
      async () => {
        tls = listenHttps
          ? { cert: await readFile(tlsCertificate!), key: await readFile(tlsKey!) }
          : undefined;
      },
    );
    type Audit = NonNullable<Parameters<typeof runStdioProxy>[0]["audit"]>;
    const audit: Audit = (event) =>
      error.write(`${JSON.stringify({ time: new Date().toISOString(), ...event })}\n`);
    if (listen) {
      const startProxy = options.startHttpProxy ?? startHttpProxy;
      const proxy = await startProxy({
        listen,
        ...(tls ? { tls } : {}),
        ...route,
        audit,
        onerror: (failure) => error.write(`mcp-restrictor: ${failure.message}\n`),
        signal,
      });
      error.write(`mcp-restrictor listening ${proxy.url}\n`);
      await proxy.closed;
      process.exitCode = 0;
    } else {
      const runProxy = options.runStdioProxy ?? runStdioProxy;
      process.exitCode = await runProxy({
        ...route,
        audit,
        input: context.input,
        output: context.output,
        error,
        signal,
      });
    }
  } finally {
    if (!options.signal) {
      for (const signal of TERMINATION_SIGNALS) process.removeListener(signal, abort);
    }
  }
}

export async function resolveProxyRoute(
  proxyArgs: readonly string[],
  options: ProxyRuntimeOptions,
  context: { home: string; environment: NodeJS.ProcessEnv },
): Promise<ResolvedProxyRoute> {
  return resolveProxyRouteWithPolicyPhase(proxyArgs, options, context, async () => {});
}

async function resolveProxyRouteWithPolicyPhase(
  proxyArgs: readonly string[],
  options: ProxyRuntimeOptions,
  context: { home: string; environment: NodeJS.ProcessEnv },
  beforePolicy: () => Promise<void>,
): Promise<ResolvedProxyRoute> {
  if (proxyArgs[0] !== "--policy") throw new Error(directProxyUsage);
  const { values, positionals } = parseArgs({
    args: [...proxyArgs],
    allowPositionals: true,
    options: routeArgumentOptions,
    strict: true,
  });
  const hasCommand = positionals.length > 0;
  const remoteSelectors = [
    ...(values["upstream-http"] ?? []).map((url) => ["http", url] as const),
    ...(values["upstream-sse"] ?? []).map((url) => ["sse", url] as const),
    ...(values["upstream-websocket"] ?? []).map((url) => ["websocket", url] as const),
  ] satisfies Array<readonly [RemoteKind, string]>;
  if (!values.policy || Number(hasCommand) + remoteSelectors.length !== 1) {
    throw new Error(directProxyUsage);
  }

  const remote = remoteSelectors[0];
  const oauthProfiles = values["upstream-oauth-profile"] ?? [];
  if (oauthProfiles.length > 1) throw new Error("Select exactly one OAuth profile");
  const hasOAuthProfile = oauthProfiles.length === 1;
  const oauthProfileId = oauthProfiles[0];
  const tokenEnvironment = values["upstream-bearer-token-env"];
  const hasBearerSelector = tokenEnvironment !== undefined;
  if (tokenEnvironment === CONTAINER_MARKER_ENV) {
    throw new Error("reserved upstream environment variable");
  }
  if (hasOAuthProfile && !remote) {
    throw new Error("--upstream-oauth-profile requires an HTTP or SSE upstream");
  }
  if (hasOAuthProfile && remote?.[0] === "websocket") {
    throw new Error("--upstream-oauth-profile does not support WebSocket upstreams");
  }
  if (hasOAuthProfile && hasBearerSelector) {
    throw new Error(CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE);
  }
  if (hasBearerSelector && !remote) {
    throw new Error("--upstream-bearer-token-env requires --upstream-http");
  }
  if (hasBearerSelector && remote?.[0] === "websocket") {
    throw new Error("--upstream-bearer-token-env does not support WebSocket upstreams");
  }

  const headerMappings = [
    ...(values["upstream-header-env"] ?? []).map((value) => parseHeaderEnvironmentMapping(value)),
    ...(values["upstream-header-base64url-env"] ?? []).map((value) =>
      parseHeaderEnvironmentMapping(value, "base64url"),
    ),
  ];
  if (
    headerMappings.some(({ environmentVariable }) => environmentVariable === CONTAINER_MARKER_ENV)
  ) {
    throw new Error("reserved upstream environment variable");
  }
  if (headerMappings.length > 0 && !remote) {
    throw new Error("--upstream-header-env requires a remote upstream");
  }
  if (
    hasOAuthProfile &&
    headerMappings.some(
      ({ environmentVariable }) =>
        asciiLower(environmentVariable) === asciiLower(MASTER_KEY_FILE_ENV),
    )
  ) {
    throw new Error(OAUTH_HEADER_MAPPING_CONFLICT_MESSAGE);
  }
  const validatedRemote = remote
    ? validateRemoteUpstream({
        kind: remote[0],
        url: remote[1],
        headers: headerMappings.map(({ name }) => [name, "value"] as const),
        ...(hasOAuthProfile
          ? { auth: "oauth" as const }
          : hasBearerSelector
            ? { auth: "bearer" as const }
            : {}),
      })
    : undefined;

  const upstreamEnvironment = values["upstream-env"];
  if (upstreamEnvironment?.includes(CONTAINER_MARKER_ENV)) {
    throw new Error("reserved upstream environment variable");
  }
  if (upstreamEnvironment && remote) throw new Error("--upstream-env requires a STDIO upstream");
  const upstreamCwd = values["upstream-cwd"];
  if (upstreamCwd !== undefined && remote) {
    throw new Error("--upstream-cwd requires a STDIO upstream");
  }
  if (hasOAuthProfile) assertProfileId(oauthProfileId!);

  const headers = resolveHeaderEnvironment(headerMappings, context.environment);
  const bearerToken =
    hasBearerSelector && Object.hasOwn(context.environment, tokenEnvironment!)
      ? context.environment[tokenEnvironment!]
      : undefined;
  if (hasBearerSelector && (typeof bearerToken !== "string" || !bearerToken)) {
    throw new Error(`Environment variable ${tokenEnvironment} is empty or missing`);
  }

  const storageOptions = { home: context.home, environment: context.environment };
  let binding: { serverUrl: string; resource?: string } | undefined;
  if (hasOAuthProfile) {
    const readProfile = options.readOAuthProfile ?? readOAuthProfile;
    binding = profileBinding(
      await readProfile(oauthProfileId!, storageOptions),
      validatedRemote!.url.href,
    );
  }
  const makeProvider = options.createOAuthAuthProvider ?? createOAuthAuthProvider;
  const authProviderFactory =
    hasOAuthProfile && binding
      ? (transportSignal?: AbortSignal) => {
          const signal =
            options.signal && transportSignal
              ? AbortSignal.any([options.signal, transportSignal])
              : (options.signal ?? transportSignal);
          return makeProvider(oauthProfileId!, binding, {
            ...storageOptions,
            ...(signal ? { signal } : {}),
          });
        }
      : undefined;
  const [command, ...args] = positionals;
  const upstream: UpstreamConfig = remote
    ? remoteUpstream(
        [remote[0], validatedRemote!.url.href],
        headers,
        bearerToken,
        authProviderFactory,
      )
    : {
        kind: "stdio",
        command: command!,
        args,
        ...(upstreamEnvironment?.length
          ? { env: createStdioEnvironment(upstreamEnvironment, context.environment) }
          : {}),
        ...(upstreamCwd !== undefined ? { cwd: upstreamCwd } : {}),
      };
  await beforePolicy();
  return { upstream, authorizer: createPolicyAuthorizer(await loadPolicy(values.policy)) };
}

function canonicalRouteArguments(
  values: DirectArgumentValues,
  positionals: readonly string[],
): string[] {
  const args: string[] = [];
  if (values.policy !== undefined) args.push("--policy", values.policy);
  for (const value of values["upstream-http"] ?? []) args.push("--upstream-http", value);
  for (const value of values["upstream-sse"] ?? []) args.push("--upstream-sse", value);
  for (const value of values["upstream-websocket"] ?? []) {
    args.push("--upstream-websocket", value);
  }
  for (const value of values["upstream-header-env"] ?? []) {
    args.push("--upstream-header-env", value);
  }
  for (const value of values["upstream-header-base64url-env"] ?? []) {
    args.push("--upstream-header-base64url-env", value);
  }
  if (values["upstream-bearer-token-env"] !== undefined) {
    args.push("--upstream-bearer-token-env", values["upstream-bearer-token-env"]);
  }
  for (const value of values["upstream-oauth-profile"] ?? []) {
    args.push("--upstream-oauth-profile", value);
  }
  for (const value of values["upstream-env"] ?? []) args.push("--upstream-env", value);
  if (values["upstream-cwd"] !== undefined) {
    args.push("--upstream-cwd", values["upstream-cwd"]);
  }
  if (positionals.length > 0) args.push("--", ...positionals);
  return args;
}

function profileBinding(
  profile: OAuthProfile,
  serverUrl: string,
): { serverUrl: string; resource?: string } {
  try {
    if (new URL(profile.metadata.serverUrl).href !== serverUrl) throw new Error();
    const resource = oauthProfileResource(profile);
    return {
      serverUrl,
      ...(resource === undefined ? {} : { resource: new URL(resource).href }),
    };
  } catch {
    throw new Error(OAUTH_SERVER_BINDING_MISMATCH_MESSAGE);
  }
}

function remoteUpstream(
  [kind, url]: readonly [RemoteKind, string],
  headers: readonly UpstreamHeader[],
  bearerToken: string | undefined,
  authProviderFactory?: (signal?: AbortSignal) => ReturnType<typeof createOAuthAuthProvider>,
): UpstreamConfig {
  validateRemoteUpstream({
    kind,
    url,
    headers,
    ...(authProviderFactory
      ? { auth: "oauth" as const }
      : bearerToken
        ? { auth: "bearer" as const }
        : {}),
  });
  if (kind === "websocket") {
    return { kind, url, ...(headers.length > 0 ? { headers } : {}) };
  }
  return {
    kind,
    url,
    ...(headers.length > 0 ? { headers } : {}),
    ...(bearerToken ? { bearerToken } : {}),
    ...(authProviderFactory ? { authProviderFactory } : {}),
  };
}
