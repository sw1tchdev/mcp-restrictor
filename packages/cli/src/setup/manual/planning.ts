import { resolve } from "node:path";
import type { ClientHttpInstallEntry, ClientInstallEntry } from "../../client-adapter.js";
import { MASTER_KEY_FILE_ENV } from "../../oauth/storage.js";
import { routePath, routeUrl, serializeRoute, type RouteOwner } from "../../routes.js";
import { DEFAULT_RESTRICTOR_COMMAND } from "../constants.js";
import { withOAuthProfile } from "../remote.js";
import {
  buildWrapperArgs,
  planManagedWrapper,
  type ClientId,
  type RestrictorCommand,
  type Scope,
  type ServerCandidate,
} from "../wrapper.js";
import type { ManualCandidate } from "../manual.js";
import type { UpstreamConfig } from "@mcp-restrictor/transports";

export function planManualDestinationHttpRoute(options: {
  candidate: ManualCandidate;
  client: ClientId;
  scope: Scope;
  configPath: string;
  projectRoot: string;
  ownerProjectRoot?: string;
  allowedTools: readonly string[];
  policy: { diskPath: string };
  restrictor: RestrictorCommand;
  upstream: UpstreamConfig;
  oauthProfileId?: string;
  fixedEnvironment?: Readonly<Record<string, string>>;
  verificationEnvironment?: NodeJS.ProcessEnv;
  inheritedEnvironment: readonly string[];
  port: number;
  home: string;
  policySource?: string;
}): {
  entry: ClientHttpInstallEntry;
  server: ServerCandidate;
  policySource: string;
  verificationUpstream: UpstreamConfig;
  routePath: string;
  routeSource: string;
} {
  const projectRoot = resolve(options.projectRoot);
  const ownerProjectRoot = resolve(options.ownerProjectRoot ?? options.projectRoot);
  const configPath = resolve(options.configPath);
  const source =
    options.candidate.source.kind === "stdio"
      ? { ...options.candidate.source, cwd: projectRoot }
      : options.candidate.source;
  const planned = planManualDestinationWrapper({
    candidate: { ...options.candidate, source },
    client: options.client,
    scope: options.scope,
    configPath,
    allowedTools: options.allowedTools,
    policy: { ...options.policy, argument: options.policy.diskPath },
    restrictor: options.restrictor,
    upstream: options.upstream,
    ...(options.oauthProfileId ? { oauthProfileId: options.oauthProfileId } : {}),
    ...(options.fixedEnvironment ? { fixedEnvironment: options.fixedEnvironment } : {}),
    ...(options.verificationEnvironment
      ? { verificationEnvironment: options.verificationEnvironment }
      : {}),
    inheritedEnvironment: options.inheritedEnvironment,
    ...(options.policySource ? { policySource: options.policySource } : {}),
  });
  const owner: RouteOwner = {
    adapterId: options.client,
    scope: options.scope,
    configPath,
    projectRoot: ownerProjectRoot,
    serverName: options.candidate.name,
  };
  const url = routeUrl(options.port, owner);
  const path = routePath(options.home, owner);
  const routeSource = serializeRoute({
    version: 1,
    owner,
    listenUrl: url,
    proxyArgs: buildWrapperArgs({
      policyArgument: resolve(options.policy.diskPath),
      source: planned.server.source,
      restrictor: { command: DEFAULT_RESTRICTOR_COMMAND, argsPrefix: [] },
    }),
    environment: { set: checkedFixedEnvironment(options.fixedEnvironment) },
  });
  return {
    entry: { name: options.candidate.name, url },
    server: {
      client: options.client,
      scope: options.scope,
      name: options.candidate.name,
      configPath,
      source: { kind: "http", url, headers: [] },
      upstream: { kind: "http", url },
      wrapperEnvironment: {},
      original: {},
    },
    policySource: planned.policySource,
    verificationUpstream: planned.verificationUpstream,
    routePath: path,
    routeSource,
  };
}

export function planManualDestinationWrapper(options: {
  candidate: ManualCandidate;
  client: ClientId;
  scope: Scope;
  configPath: string;
  allowedTools: readonly string[];
  policy: { diskPath: string; argument: string };
  restrictor: RestrictorCommand;
  upstream: UpstreamConfig;
  oauthProfileId?: string;
  fixedEnvironment?: Readonly<Record<string, string>>;
  verificationEnvironment?: NodeJS.ProcessEnv;
  inheritedEnvironment: readonly string[];
  wrapperCwd?: string;
  policySource?: string;
}): {
  entry: ClientInstallEntry;
  server: ServerCandidate;
  policySource: string;
  verificationUpstream: UpstreamConfig;
} {
  const fixedEnvironment = checkedFixedEnvironment(options.fixedEnvironment);
  const source = options.oauthProfileId
    ? withOAuthProfile(options.candidate.source, options.oauthProfileId)
    : options.candidate.source;
  const server: ServerCandidate = {
    client: options.client,
    scope: options.scope,
    name: options.candidate.name,
    configPath: options.configPath,
    source,
    upstream: options.upstream,
    wrapperEnvironment: Object.keys(fixedEnvironment).length ? { env: fixedEnvironment } : {},
    original: {},
  };
  const planned = planManagedWrapper({
    server,
    allowedTools: options.allowedTools,
    policy: options.policy,
    restrictor: options.restrictor,
    ...(options.verificationEnvironment
      ? { verificationEnvironment: options.verificationEnvironment }
      : {}),
    ...(options.wrapperCwd !== undefined ? { wrapperCwd: options.wrapperCwd } : {}),
  });
  const entry: ClientInstallEntry = {
    name: options.candidate.name,
    command: planned.replacement.command,
    args: planned.replacement.args,
    ...(planned.replacement.cwd !== undefined ? { cwd: planned.replacement.cwd } : {}),
    environment: {
      inherit: [...options.inheritedEnvironment],
      set: fixedEnvironment,
    },
  };
  return {
    entry,
    server,
    policySource: options.policySource ?? planned.policySource,
    verificationUpstream: planned.verificationUpstream,
  };
}

function checkedFixedEnvironment(
  environment: Readonly<Record<string, string>> | undefined,
): Record<string, string> {
  if (!environment) return {};
  if (Object.keys(environment).some((name) => name !== MASTER_KEY_FILE_ENV)) {
    throw new Error("Invalid fixed Manual environment");
  }
  return { ...environment };
}
