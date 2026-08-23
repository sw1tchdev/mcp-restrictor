import { resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { parseRoute, type RouteOwner } from "../routes.js";
import type { UpstreamConfig } from "@mcp-restrictor/transports";
import type {
  ClientAdapter,
  ClientAdapterHost,
  ClientHttpInstallEntry,
  ClientInstallEntry,
  ClientLoadContext,
  ClientRestoreEntry,
  ClientResolutionDependency,
  ClientResolveContext,
  ClientResolveResult,
  LoadedClientConfig,
} from "../client-adapter.js";
import { CLIENT_CONFIGURATION_TARGET, readSetupSnapshot } from "./snapshot.js";
import { loadGeneratedConfigurations } from "./generated.js";
import { readPrivateFileSnapshot, sameFileSnapshot, type FileSnapshot } from "./transaction.js";
import {
  matchesPrivateFingerprint,
  readRestoreStateIndex,
  type RestoreServerStateV2,
} from "./restore/state.js";
import {
  type ParsedConfig,
  type ServerCandidate,
  type SourceSpec,
  type UnsupportedServer,
  validateServerCandidate,
} from "./wrapper.js";

const INVALID_CLIENT_RESOLUTION_MESSAGE = "Invalid client resolution returned by adapter";
const CLIENT_CREDENTIAL_SOURCE_CHANGED_MESSAGE = "Client credential source changed during setup";

export type LoadedConfig = LoadedClientConfig & { adapter: ClientAdapter };

const environmentName = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function installAdapterConfig(
  adapter: ClientAdapter,
  config: ParsedConfig,
  entry: ClientInstallEntry,
): string {
  let install: ClientAdapter["install"];
  try {
    install = adapter.install;
  } catch {
    throw new Error("Client configuration installation failed");
  }
  if (install === undefined) throw new Error("Client adapter does not support installation");
  try {
    const installedConfig = structuredClone(config) as ParsedConfig;
    const installedEntry = structuredClone(entry) as ClientInstallEntry;
    validateInstallEntry(installedEntry);
    if (
      installedConfig.servers.some((server) => server.name === installedEntry.name) ||
      installedConfig.unsupported.some((server) => server.name === installedEntry.name)
    ) {
      throw new Error();
    }
    const { client, scope, path, source } = installedConfig;
    const result = install(installedConfig, installedEntry);
    if (
      typeof result !== "string" ||
      result === source ||
      installedConfig.client !== client ||
      installedConfig.scope !== scope ||
      installedConfig.path !== path
    ) {
      throw new Error();
    }
    return result;
  } catch {
    throw new Error("Client configuration installation failed");
  }
}

export function installAdapterHttpConfig(
  adapter: ClientAdapter,
  config: ParsedConfig,
  entry: ClientHttpInstallEntry,
): string {
  let installHttp: ClientAdapter["installHttp"];
  try {
    installHttp = adapter.installHttp;
  } catch {
    throw new Error("Client configuration HTTP installation failed");
  }
  if (installHttp === undefined) {
    throw new Error("Client adapter does not support HTTP installation");
  }
  try {
    const installedConfig = structuredClone(config) as ParsedConfig;
    const installedEntry = structuredClone(entry) as ClientHttpInstallEntry;
    validateHttpInstallEntry(installedEntry);
    if (
      installedConfig.servers.some((server) => server.name === installedEntry.name) ||
      installedConfig.unsupported.some((server) => server.name === installedEntry.name)
    ) {
      throw new Error();
    }
    const { client, scope, path, source } = installedConfig;
    const result = installHttp(installedConfig, installedEntry);
    if (
      typeof result !== "string" ||
      result === source ||
      installedConfig.client !== client ||
      installedConfig.scope !== scope ||
      installedConfig.path !== path
    ) {
      throw new Error();
    }
    return result;
  } catch {
    throw new Error("Client configuration HTTP installation failed");
  }
}

function validateHttpInstallEntry(entry: ClientHttpInstallEntry): void {
  if (!entry || typeof entry.name !== "string" || !entry.name || typeof entry.url !== "string") {
    throw new Error();
  }
  const match = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})(\/[^?#]*)$/.exec(entry.url);
  if (!match || /%(?![0-9a-f]{2})/i.test(match[2]!)) throw new Error();
  const url = new URL(entry.url);
  const port = Number(match[1]);
  if (
    entry.url !== `http://127.0.0.1:${match[1]}${url.pathname}` ||
    !Number.isSafeInteger(port) ||
    port < 1 ||
    port > 65_535 ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error();
  }
}

function validateInstallEntry(entry: ClientInstallEntry): void {
  if (
    !entry ||
    typeof entry.name !== "string" ||
    !entry.name ||
    typeof entry.command !== "string" ||
    !entry.command ||
    !Array.isArray(entry.args) ||
    !entry.args.every((arg) => typeof arg === "string") ||
    (entry.cwd !== undefined && (typeof entry.cwd !== "string" || !entry.cwd)) ||
    !entry.environment ||
    !Array.isArray(entry.environment.inherit) ||
    !entry.environment.set ||
    typeof entry.environment.set !== "object" ||
    Array.isArray(entry.environment.set)
  ) {
    throw new Error();
  }
  const inherited = new Set<string>();
  for (const name of entry.environment.inherit) {
    if (typeof name !== "string" || !environmentName.test(name) || inherited.has(name)) {
      throw new Error();
    }
    inherited.add(name);
  }
  for (const [name, value] of Object.entries(entry.environment.set)) {
    if (!environmentName.test(name) || typeof value !== "string" || inherited.has(name)) {
      throw new Error();
    }
  }
}

export function restoreAdapterConfig(
  adapter: ClientAdapter,
  config: ParsedConfig,
  entries: readonly ClientRestoreEntry[],
  context: ClientLoadContext,
): string {
  let restore: ClientAdapter["restore"];
  try {
    restore = adapter.restore;
  } catch {
    throw new Error("Client configuration restore failed");
  }
  if (restore === undefined) throw new Error("Client adapter does not support restore");
  try {
    const restoredConfig = structuredClone(config) as ParsedConfig;
    const restoredEntries = structuredClone(Array.from(entries)) as ClientRestoreEntry[];
    const restoredContext = structuredClone(context) as ClientLoadContext;
    const names = new Set<string>();
    for (const entry of restoredEntries) {
      if (
        !entry ||
        typeof entry.name !== "string" ||
        !entry.name ||
        typeof entry.originalSource !== "string" ||
        (entry.installedSource !== undefined && typeof entry.installedSource !== "string") ||
        (entry.created !== undefined && entry.created !== true) ||
        names.has(entry.name)
      ) {
        throw new Error();
      }
      names.add(entry.name);
    }
    const result = restore(restoredConfig, restoredEntries, restoredContext);
    if (typeof result !== "string") throw new Error();
    return result;
  } catch {
    throw new Error("Client configuration restore failed");
  }
}

class SetupConfigAliasError extends Error {}
class InvalidClientConfigurationError extends Error {
  constructor() {
    super("Invalid client configuration returned by adapter");
  }
}

export function createAdapterLoader(options: { includeManagedRoutes?: boolean } = {}) {
  const issuedConfigurations = new WeakMap<FileSnapshot, FileSnapshot>();
  const issuedSecrets = new WeakMap<FileSnapshot, FileSnapshot>();
  const issuedPaths = new Set<string>();
  const issuedIdentities = new Set<string>();
  const loadedPaths = new Set<string>();
  const loadedIdentities = new Set<string>();
  const issueConfiguration = (snapshot: FileSnapshot): void => {
    const resolvedPath = resolve(snapshot.path);
    const identity = `${snapshot.dev}:${snapshot.ino}`;
    if (issuedPaths.has(resolvedPath) || issuedIdentities.has(identity)) {
      throw new SetupConfigAliasError(
        "user and project configuration paths resolve to the same file",
      );
    }
    issuedConfigurations.set(snapshot, Object.freeze({ ...snapshot }));
    issuedPaths.add(resolvedPath);
    issuedIdentities.add(identity);
  };
  const host: ClientAdapterHost = {
    readConfig: async (path: string) => {
      const snapshot = await readSetupSnapshot(path, CLIENT_CONFIGURATION_TARGET);
      if (snapshot) issueConfiguration(snapshot);
      return snapshot;
    },
    readSecretFile: async (path: string) => {
      const snapshot = await readPrivateFileSnapshot(path);
      issuedSecrets.set(snapshot, Object.freeze({ ...snapshot }));
      return snapshot;
    },
  };
  return {
    host,
    async load(
      adapter: ClientAdapter,
      context: { home: string; projectRoot: string; cwd: string; environment: NodeJS.ProcessEnv },
    ): Promise<{ configurations: LoadedConfig[]; unsupported: UnsupportedServer[] }> {
      try {
        const result = await adapter.load(context, host);
        const entries = Array.from(result.configurations, ({ config, snapshot }) => ({
          config: structuredClone(config) as ParsedConfig,
          snapshot,
        }));
        const unsupported = Array.from(
          result.unsupported,
          (server) => structuredClone(server) as UnsupportedServer,
        );
        const generated = await loadGeneratedConfigurations(adapter, context);
        for (const entry of generated) issueConfiguration(entry.snapshot);
        entries.push(...generated);
        if (!unsupported.every((server) => validUnsupportedServer(server, adapter.id))) {
          throw new InvalidClientConfigurationError();
        }
        const configurations: LoadedConfig[] = [];
        for (const entry of entries) {
          const snapshot = entry.snapshot;
          const baseline = issuedConfigurations.get(snapshot);
          const config = structuredClone(entry.config) as ParsedConfig;
          if (
            !baseline ||
            !sameFileSnapshot(snapshot, baseline) ||
            !validLoadedConfig(config, adapter.id, baseline.path, baseline.content)
          )
            throw new InvalidClientConfigurationError();
          const path = resolve(baseline.path);
          const identity = `${baseline.dev}:${baseline.ino}`;
          if (loadedPaths.has(path) || loadedIdentities.has(identity)) {
            if (
              config.scope === "user" ||
              configurations.some(({ config }) => config.scope === "user")
            ) {
              throw new SetupConfigAliasError(
                "user and project configuration paths resolve to the same file",
              );
            }
            throw new SetupConfigAliasError("client configuration paths resolve to the same file");
          }
          loadedPaths.add(path);
          loadedIdentities.add(identity);
          configurations.push({ config, snapshot: baseline, adapter });
        }
        if (!options.includeManagedRoutes) {
          await classifyManagedRoutes(adapter, configurations, context);
        }
        return { configurations, unsupported };
      } catch (error) {
        if (
          error instanceof SetupConfigAliasError ||
          error instanceof InvalidClientConfigurationError
        ) {
          throw error;
        }
        throw new Error("Failed to load client configuration");
      }
    },
    acceptDependencies(
      dependencies: readonly ClientResolutionDependency[],
    ): ClientResolutionDependency[] {
      try {
        const accepted: ClientResolutionDependency[] = [];
        for (const dependency of dependencies) {
          const kind = dependency.kind;
          if (kind === "environment") {
            if (!Object.hasOwn(dependency, "name") || !Object.hasOwn(dependency, "value"))
              throw new Error();
            const name = dependency.name;
            const value = dependency.value;
            if (typeof name !== "string" || !name || typeof value !== "string") {
              throw new Error();
            }
            accepted.push(
              Object.freeze({
                kind: "environment",
                name,
                value,
              }),
            );
            continue;
          }
          if (kind !== "file" || !Object.hasOwn(dependency, "snapshot")) throw new Error();
          const snapshot = dependency.snapshot;
          const baseline = issuedSecrets.get(snapshot);
          if (!baseline || !sameFileSnapshot(snapshot, baseline)) {
            throw new Error();
          }
          accepted.push(Object.freeze({ kind: "file", snapshot: baseline }));
        }
        return accepted;
      } catch {
        throw new Error("Invalid client resolution dependency returned by adapter");
      }
    },
  };
}

async function classifyManagedRoutes(
  adapter: ClientAdapter,
  configurations: LoadedConfig[],
  context: ClientLoadContext,
): Promise<void> {
  if (
    !configurations.some(({ config }) =>
      config.servers.some(
        (server) => server.source.kind === "http" && server.managedPolicyPath === undefined,
      ),
    )
  ) {
    return;
  }
  const indexed = await readRestoreStateIndex(context.home);
  if (!indexed) throw new Error("Failed to verify existing route ownership");
  for (const { config } of configurations) {
    const retained: ServerCandidate[] = [];
    for (const server of config.servers) {
      if (server.source.kind !== "http" || server.managedPolicyPath !== undefined) {
        retained.push(server);
        continue;
      }
      const records = indexed.flatMap(({ state }) =>
        state.version === 2 &&
        state.adapterId === adapter.id &&
        resolve(state.configPath) === resolve(config.path)
          ? state.servers.filter(
              (record) =>
                record.name === server.name &&
                record.scope === server.scope &&
                (record.scope === "user" ||
                  resolve(record.projectRoot) === resolve(context.projectRoot)) &&
                record.created === true,
            )
          : [],
      );
      if (!records.length) {
        retained.push(server);
        continue;
      }
      const owned =
        records.length === 1 &&
        records[0]!.route !== undefined &&
        (await isCurrentManagedRoute(adapter, config, server, records[0]!, context));
      config.unsupported.push({
        client: server.client,
        scope: server.scope,
        name: server.name,
        configPath: server.configPath,
        reason: owned
          ? "Managed local HTTP route; Restore it before adding."
          : "Managed local HTTP route ownership could not be verified; Restore is unavailable.",
      });
    }
    config.servers = retained;
  }
}

async function isCurrentManagedRoute(
  adapter: ClientAdapter,
  config: ParsedConfig,
  server: ServerCandidate,
  record: RestoreServerStateV2,
  context: ClientLoadContext,
): Promise<boolean> {
  if (!record.route) return false;
  try {
    const snapshot = await readPrivateFileSnapshot(record.route.path);
    if (!matchesPrivateFingerprint(snapshot, record.route.installed)) return false;
    const definition = parseRoute(snapshot.content, snapshot.path);
    const owner: RouteOwner = {
      adapterId: adapter.id,
      scope: record.scope,
      configPath: resolve(config.path),
      projectRoot: resolve(record.projectRoot),
      serverName: record.name,
    };
    if (
      definition.listenUrl !== (server.source.kind === "http" ? server.source.url : undefined) ||
      !isDeepStrictEqual(definition.owner, owner)
    ) {
      return false;
    }
    restoreAdapterConfig(
      adapter,
      config,
      [
        {
          name: record.name,
          originalSource: record.originalSource,
          installedSource: record.installedSource,
          created: true,
        },
      ],
      context,
    );
    return true;
  } catch {
    return false;
  }
}

function validLoadedConfig(
  config: ParsedConfig,
  client: string,
  snapshotPath: string,
  snapshotContent: string,
): boolean {
  if (
    !config ||
    config.client !== client ||
    (config.scope !== "user" && config.scope !== "project") ||
    resolve(config.path) !== resolve(snapshotPath) ||
    config.source !== snapshotContent ||
    !Array.isArray(config.servers) ||
    !Array.isArray(config.unsupported)
  )
    return false;
  return (
    config.servers.every(
      (server) =>
        server.client === client &&
        server.scope === config.scope &&
        resolve(server.configPath) === resolve(snapshotPath) &&
        isValidServerCandidate(server),
    ) &&
    config.unsupported.every(
      (server) =>
        server.client === client &&
        server.scope === config.scope &&
        resolve(server.configPath) === resolve(snapshotPath),
    )
  );
}

function isValidServerCandidate(server: ServerCandidate): boolean {
  try {
    validateServerCandidate(server);
    return true;
  } catch {
    return false;
  }
}

function validUnsupportedServer(server: UnsupportedServer, client: string): boolean {
  return Boolean(
    server &&
    server.client === client &&
    (server.scope === "user" || server.scope === "project") &&
    typeof server.name === "string" &&
    typeof server.configPath === "string" &&
    typeof server.reason === "string",
  );
}

export async function resolveAdapterCandidate(
  adapter: ClientAdapter,
  candidate: ServerCandidate,
  context: ClientResolveContext,
  host: ClientAdapterHost,
): Promise<ClientResolveResult> {
  if (!adapter.resolve) return { candidate, dependencies: [] };
  let result: ClientResolveResult;
  try {
    result = await adapter.resolve(structuredClone(candidate), context, host);
  } catch {
    throw new Error("Failed to resolve client configuration");
  }
  let resolved: ServerCandidate;
  let dependencies: readonly ClientResolutionDependency[];
  try {
    resolved = structuredClone(result.candidate) as ServerCandidate;
    dependencies = Array.from(result.dependencies);
  } catch {
    throw new Error(INVALID_CLIENT_RESOLUTION_MESSAGE);
  }
  let sameShape: boolean;
  try {
    sameShape = isDeepStrictEqual(candidateShape(candidate), candidateShape(resolved));
  } catch {
    throw new Error(INVALID_CLIENT_RESOLUTION_MESSAGE);
  }
  if (
    resolved.client !== candidate.client ||
    resolved.scope !== candidate.scope ||
    resolved.name !== candidate.name ||
    resolved.configPath !== candidate.configPath ||
    !sameShape
  )
    throw new Error("Client adapter changed confirmed server shape");
  try {
    validateServerCandidate(resolved);
  } catch {
    throw new Error(INVALID_CLIENT_RESOLUTION_MESSAGE);
  }
  return { candidate: resolved, dependencies };
}

function candidateShape(candidate: ServerCandidate) {
  return {
    primary: candidateSourceShape(candidate, candidate.source, candidate.upstream),
    alternatives: (candidate.alternatives ?? []).map(({ source, upstream }) =>
      candidateSourceShape(candidate, source, upstream),
    ),
  };
}

function candidateSourceShape(
  candidate: ServerCandidate,
  source: SourceSpec,
  upstream: UpstreamConfig,
) {
  return {
    kind: source.kind,
    url: source.kind === "stdio" ? undefined : new URL(source.url).href,
    upstreamUrl: upstream.kind === "stdio" ? undefined : new URL(upstream.url).href,
    headers:
      source.kind === "stdio" ? [] : source.headers.map(({ name }) => name.toLowerCase()).sort(),
    upstreamHeaders:
      upstream.kind === "stdio"
        ? []
        : (upstream.headers ?? []).map(([name]) => name.toLowerCase()).sort(),
    upstreamAuth:
      upstream.kind === "http" || upstream.kind === "sse"
        ? {
            bearer: Boolean(upstream.bearerToken),
            oauth: Boolean(upstream.authProviderFactory),
          }
        : { bearer: false, oauth: false },
    auth:
      source.kind === "stdio" || source.kind === "websocket"
        ? "none"
        : source.oauthProfileId
          ? "managed-oauth"
          : (candidate.oauth?.mode ?? (source.bearerTokenEnvVar ? "bearer" : "none")),
  };
}

export async function recheckDependencies(
  dependencies: readonly ClientResolutionDependency[],
  environment: NodeJS.ProcessEnv,
): Promise<void> {
  for (const dependency of dependencies) {
    if (dependency.kind === "environment") {
      if (!Object.hasOwn(environment, dependency.name)) {
        throw new Error(CLIENT_CREDENTIAL_SOURCE_CHANGED_MESSAGE);
      }
      const value = environment[dependency.name];
      if (typeof value !== "string" || value !== dependency.value)
        throw new Error(CLIENT_CREDENTIAL_SOURCE_CHANGED_MESSAGE);
      continue;
    }
    let current: FileSnapshot;
    try {
      current = await readPrivateFileSnapshot(dependency.snapshot.path);
    } catch {
      throw new Error(CLIENT_CREDENTIAL_SOURCE_CHANGED_MESSAGE);
    }
    if (!sameFileSnapshot(current, dependency.snapshot)) {
      throw new Error(CLIENT_CREDENTIAL_SOURCE_CHANGED_MESSAGE);
    }
  }
}
