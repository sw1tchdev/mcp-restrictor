import { lstat } from "node:fs/promises";
import { resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import type { ClientAdapter, ClientLoadContext, ClientRestoreEntry } from "../../client-adapter.js";
import { parseRoute, routePath, type RouteOwner } from "../../routes.js";
import type { LoadedConfig } from "../adapter-boundary.js";
import {
  createAdapterLoader,
  installAdapterHttpConfig,
  restoreAdapterConfig,
} from "../adapter-boundary.js";
import { readSetupSnapshot } from "../snapshot.js";
import {
  generatedPresetBaseline,
  generatedPresetConfig,
  generatedPresetKind,
  generatedPresetKinds,
  type GeneratedPresetKind,
  readGeneratedFileSnapshot,
} from "../generated.js";
import {
  errorCode,
  isPrivateFileMode,
  readPrivateFileSnapshot,
  sameFileSnapshot,
  type FileSnapshot,
  type PlannedFileChange,
  type PlannedWrite,
} from "../transaction.js";
import type { ServerCandidate, UnsupportedServer } from "../wrapper.js";
import { findLegacyRestoreEntry } from "./legacy.js";
import {
  matchesFingerprint,
  matchesPrivateFingerprint,
  planRestoreStateChange,
  policyFingerprint,
  readRestoreState,
  readRestoreStateIndex,
  type RestoreRouteState,
  type FileFingerprint,
  type RestoreState,
  type RestoreServerState,
} from "./state.js";

const RESTORE_INPUTS_CHANGED = "Restore inputs changed during planning";
const RESTORE_ARTIFACTS_RETAINED = "Restore artifacts were retained.";
const RESTORE_ROUTE_MISSING = "Managed HTTP route was already missing.";

export type RestorePlanningContext = ClientLoadContext & {
  loaded: readonly LoadedConfig[];
};

export type RestoreChoice = {
  adapter: ClientAdapter;
  context: ClientLoadContext;
  loaded: LoadedConfig;
  server: ServerCandidate;
  entry: ClientRestoreEntry;
  state?: { value: RestoreState; snapshot: FileSnapshot };
  route?: { value: RestoreRouteState; snapshot?: FileSnapshot };
  legacy: boolean;
};

export async function loadRestoreChoices(options: RestorePlanningContext): Promise<{
  choices: RestoreChoice[];
  unavailable: UnsupportedServer[];
}> {
  const choices: RestoreChoice[] = [];
  const unavailable: UnsupportedServer[] = [];
  const { loaded: _loaded, ...context } = options;
  for (const loaded of options.loaded) {
    let stored: Awaited<ReturnType<typeof readRestoreState>>;
    try {
      stored = await readRestoreState({
        home: options.home,
        adapterId: loaded.adapter.id,
        configPath: loaded.config.path,
        projectRoot: options.projectRoot,
      });
    } catch {
      unavailable.push(
        ...loaded.config.servers
          .filter(({ managedPolicyPath }) => managedPolicyPath)
          .map(unavailableServer),
      );
      continue;
    }
    for (const server of loaded.config.servers) {
      const policyRecord = stored?.state.servers.find(
        ({ name, policy }) =>
          name === server.name &&
          server.managedPolicyPath !== undefined &&
          resolve(policy.path) === resolve(server.managedPolicyPath),
      );
      const routeRecord =
        stored?.state.version === 2
          ? stored.state.servers.find(
              (record) =>
                record.name === server.name &&
                record.scope === server.scope &&
                (record.scope === "user" ||
                  resolve(record.projectRoot) === resolve(options.projectRoot)) &&
                record.created === true &&
                record.route !== undefined &&
                server.source.kind === "http" &&
                server.managedPolicyPath === undefined,
            )
          : undefined;
      if (!policyRecord && !routeRecord && !server.managedPolicyPath) continue;
      if (!loaded.adapter.restore) {
        unavailable.push(unavailableServer(server));
        continue;
      }
      let entry: ClientRestoreEntry | undefined;
      let legacy = false;
      const record = routeRecord ?? policyRecord;
      if (record) {
        entry = {
          name: record.name,
          originalSource: record.originalSource,
          installedSource: record.installedSource,
          ...(record.created ? { created: true } : {}),
        };
      }
      const routeState = routeRecord?.route;
      if (routeRecord && entry && routeState) {
        const route = await currentOwnedRoute(routeState, routeOwner(loaded, routeRecord), server);
        if (route === undefined || !canRestoreCurrentEntry(loaded, entry, context)) {
          unavailable.push(unavailableServer(server));
          continue;
        }
        choices.push({
          adapter: loaded.adapter,
          context,
          loaded,
          server,
          entry,
          state: { value: stored!.state, snapshot: stored!.snapshot },
          route: { value: routeState, ...(route ? { snapshot: route } : {}) },
          legacy: false,
        });
        continue;
      }
      if (!entry && server.managedPolicyPath) {
        entry = await findLegacyRestoreEntry({
          home: options.home,
          adapter: loaded.adapter,
          loaded,
          server,
          context,
        });
        legacy = true;
      }
      if (!entry) {
        if (server.managedPolicyPath) unavailable.push(unavailableServer(server));
        continue;
      }
      choices.push({
        adapter: loaded.adapter,
        context,
        loaded,
        server,
        entry,
        ...(!legacy && stored ? { state: { value: stored.state, snapshot: stored.snapshot } } : {}),
        legacy,
      });
    }
  }
  return { choices, unavailable };
}

function canRestoreCurrentEntry(
  loaded: LoadedConfig,
  entry: ClientRestoreEntry,
  context: ClientLoadContext,
): boolean {
  try {
    restoreAdapterConfig(loaded.adapter, loaded.config, [entry], context);
    return true;
  } catch {
    return false;
  }
}

function routeOwner(loaded: LoadedConfig, record: RestoreServerState): RouteOwner {
  return {
    adapterId: loaded.adapter.id,
    scope: record.scope,
    configPath: resolve(loaded.config.path),
    projectRoot: resolve(record.projectRoot),
    serverName: record.name,
  };
}

async function currentOwnedRoute(
  route: RestoreRouteState,
  owner: RouteOwner,
  server: ServerCandidate,
): Promise<FileSnapshot | null | undefined> {
  try {
    await lstat(route.path);
  } catch (error) {
    return errorCode(error) === "ENOENT" ? null : undefined;
  }
  let snapshot: FileSnapshot;
  try {
    snapshot = await readPrivateFileSnapshot(route.path);
  } catch (error) {
    return errorCode(error) === "ENOENT" ? null : undefined;
  }
  if (!matchesPrivateFingerprint(snapshot, route.installed)) return undefined;
  try {
    const definition = parseRoute(snapshot.content, snapshot.path);
    if (
      server.source.kind !== "http" ||
      definition.listenUrl !== server.source.url ||
      !isDeepStrictEqual(definition.owner, owner)
    ) {
      return undefined;
    }
    return snapshot;
  } catch {
    return undefined;
  }
}

export async function planSelectedRestore(options: {
  home: string;
  projectRoot: string;
  environment: NodeJS.ProcessEnv;
  choices: readonly RestoreChoice[];
}): Promise<{ changes: PlannedFileChange[]; warnings: string[]; verify: () => Promise<void> }> {
  const indexed = await readRestoreStateIndex(options.home);
  if (!indexed && options.choices.some(({ route }) => route)) {
    throw new Error(RESTORE_INPUTS_CHANGED);
  }
  const groups = new Map<string, RestoreChoice[]>();
  for (const choice of options.choices) {
    const path = resolve(choice.server.configPath);
    const group = groups.get(path) ?? [];
    group.push(choice);
    groups.set(path, group);
  }
  const configChanges: PlannedFileChange[] = [];
  const routeChanges: PlannedFileChange[] = [];
  const stateChanges: PlannedFileChange[] = [];
  const selectedRecords = new Set<string>();
  const policyRecords = new Map<string, Array<{ record: RestoreServerState; private: boolean }>>();
  const plannedConfigs = new Map<string, string | null>();
  let missingRoute = false;

  for (const [configPath, selected] of groups) {
    const loaded = selected[0]!.loaded;
    const generatedKind = generatedPresetKind(options.home, loaded.adapter.id, configPath);
    let freshConfig: FileSnapshot | undefined;
    try {
      freshConfig = generatedKind
        ? await readGeneratedFileSnapshot(configPath)
        : await readSetupSnapshot(configPath, "client configuration");
    } catch {}
    if (!freshConfig || !sameFileSnapshot(freshConfig, loaded.snapshot)) {
      throw new Error(RESTORE_INPUTS_CHANGED);
    }
    const content = restoreAdapterConfig(
      loaded.adapter,
      { ...loaded.config, source: freshConfig.content },
      selected.map(({ entry }) => entry),
      selected[0]!.context,
    );
    const tracked = selected.filter(({ legacy }) => !legacy);
    let remainingState: RestoreServerState[] | undefined;
    if (tracked.length) {
      const expected = tracked[0]!.state?.snapshot;
      if (!expected) throw new Error(RESTORE_INPUTS_CHANGED);
      let stored: Awaited<ReturnType<typeof readRestoreState>>;
      try {
        stored = await readRestoreState({
          home: options.home,
          adapterId: loaded.adapter.id,
          configPath,
          projectRoot: options.projectRoot,
        });
      } catch {
        throw new Error(RESTORE_INPUTS_CHANGED);
      }
      if (!stored || !sameFileSnapshot(stored.snapshot, expected)) {
        throw new Error(RESTORE_INPUTS_CHANGED);
      }
      if (generatedKind) {
        const loadedNames = new Set([
          ...loaded.config.servers.map(({ name }) => name),
          ...loaded.config.unsupported.map(({ name }) => name),
        ]);
        if (stored.state.servers.some(({ name }) => !loadedNames.has(name))) {
          throw new Error(RESTORE_INPUTS_CHANGED);
        }
      }
      const names = new Set(tracked.map(({ server }) => server.name));
      for (const choice of tracked) {
        const record = stored.state.servers.find(({ name }) => name === choice.server.name);
        if (!record) throw new Error(RESTORE_INPUTS_CHANGED);
        if (choice.route) {
          const routeState =
            "route" in record ? (record.route as RestoreRouteState | undefined) : undefined;
          if (stored.state.version !== 2 || !routeState) {
            throw new Error(RESTORE_INPUTS_CHANGED);
          }
          const route = await currentOwnedRoute(
            routeState,
            routeOwner(loaded, record),
            choice.server,
          );
          if (
            route === undefined ||
            (choice.route.snapshot
              ? !route || !sameFileSnapshot(route, choice.route.snapshot)
              : route !== null)
          ) {
            throw new Error(RESTORE_INPUTS_CHANGED);
          }
          if (route) {
            routeChanges.push({
              delete: true,
              path: routeState.path,
              before: route,
              backupKey: routeState.path,
              private: true,
            });
          } else {
            missingRoute = true;
          }
        }
        selectedRecords.add(`${configPath}\0${record.name}`);
        const path = resolve(record.policy.path);
        const records = policyRecords.get(path) ?? [];
        records.push({ record, private: generatedKind !== undefined });
        policyRecords.set(path, records);
      }
      remainingState = stored.state.servers.filter(({ name }) => !names.has(name));
      const stateChange = planRestoreStateChange({
        home: options.home,
        configPath,
        backupKey: configPath,
        before: stored.snapshot,
        ...(remainingState.length ? { state: { ...stored.state, servers: remainingState } } : {}),
      });
      if (stateChange) stateChanges.push(stateChange);
    }

    const removeGeneratedConfig =
      generatedKind !== undefined &&
      remainingState?.length === 0 &&
      isPristineGeneratedEmpty({
        home: options.home,
        kind: generatedKind,
        loaded,
        context: selected[0]!.context,
        content,
      });
    if (removeGeneratedConfig) {
      configChanges.push({
        delete: true,
        path: configPath,
        before: freshConfig,
        backupKey: configPath,
        private: true,
      });
      plannedConfigs.set(configPath, null);
    } else {
      configChanges.push({
        path: configPath,
        before: freshConfig,
        content,
        mode: freshConfig.mode,
        backupKey: configPath,
        ...(generatedKind ? { private: true } : {}),
      });
      plannedConfigs.set(configPath, content);
    }
  }

  let retained = options.choices.some(({ legacy }) => legacy);
  const policyChanges: PlannedFileChange[] = [];
  for (const [path, records] of policyRecords) {
    const privatePolicy = records.every((entry) => entry.private);
    if (privatePolicy !== records.some((entry) => entry.private)) {
      retained = true;
      continue;
    }
    let current: FileSnapshot | undefined;
    if (privatePolicy) {
      current = await readGeneratedFileSnapshot(path);
    } else {
      try {
        current = await readSetupSnapshot(path, "policy");
      } catch {}
    }
    const before = records[0]!.record.policy.before;
    if (
      !indexed ||
      indexed.some(({ state }) =>
        state.servers.some(
          (record) =>
            resolve(record.policy.path) === path &&
            !selectedRecords.has(`${state.configPath}\0${record.name}`),
        ),
      ) ||
      !current ||
      records.some(
        ({ record: { policy } }) =>
          !(privatePolicy
            ? matchesPrivateFingerprint(current!, policy.installed)
            : matchesFingerprint(current!, policy.installed)) ||
          !isDeepStrictEqual(policy.before, before),
      )
    ) {
      retained = true;
      continue;
    }
    policyChanges.push(
      before
        ? {
            path,
            before: current,
            content: before.content,
            mode: before.mode,
            backupKey: path,
            ...(privatePolicy ? { private: true } : {}),
          }
        : {
            delete: true,
            path,
            before: current,
            backupKey: path,
            ...(privatePolicy ? { private: true } : {}),
          },
    );
  }

  const changes = [...routeChanges, ...configChanges, ...policyChanges, ...stateChanges];
  return {
    changes,
    warnings: [
      ...(missingRoute ? [RESTORE_ROUTE_MISSING] : []),
      ...(retained ? [RESTORE_ARTIFACTS_RETAINED] : []),
    ],
    verify: () => verifyRestoredConfigs(plannedConfigs, options.choices),
  };
}

function isPristineGeneratedEmpty(options: {
  home: string;
  kind: GeneratedPresetKind;
  loaded: LoadedConfig;
  context: ClientLoadContext;
  content: string;
}): boolean {
  const baseline = generatedPresetBaseline(options.kind);
  if (options.content === baseline) return true;
  const name = "mcp-restrictor-generated-restore-probe";
  const config = generatedPresetConfig({
    home: options.home,
    kind: options.kind,
    environment: options.context.environment,
  });
  const installedSource = installAdapterHttpConfig(options.loaded.adapter, config, {
    name,
    url: "http://127.0.0.1:17319/mcp/generated-restore-probe",
  });
  const restoredSource = restoreAdapterConfig(
    options.loaded.adapter,
    { ...config, source: installedSource },
    [{ name, originalSource: baseline, installedSource, created: true }],
    options.context,
  );
  return options.content === restoredSource;
}

export async function verifyRestoredConfigs(
  planned: ReadonlyMap<string, string | null>,
  choices: readonly RestoreChoice[],
): Promise<void> {
  try {
    const loaded: LoadedConfig[] = [];
    for (const adapter of new Set(choices.map(({ adapter }) => adapter))) {
      const loader = createAdapterLoader();
      const context = choices.find((choice) => choice.adapter === adapter)!.context;
      loaded.push(...(await loader.load(adapter, context)).configurations);
    }
    for (const choice of choices) {
      const { adapter, server: selected, entry } = choice;
      if (choice.route) {
        try {
          await lstat(choice.route.value.path);
          throw new Error();
        } catch (error) {
          if (errorCode(error) !== "ENOENT") throw error;
        }
      }
      const config = loaded.find(
        (entry) =>
          entry.adapter === adapter && resolve(entry.config.path) === resolve(selected.configPath),
      );
      const server = config?.config.servers.find(({ name }) => name === selected.name);
      const unsupported = config?.config.unsupported.find(({ name }) => name === selected.name);
      const expected = planned.get(resolve(selected.configPath));
      if (!planned.has(resolve(selected.configPath))) throw new Error();
      if (expected === null) {
        if (config || entry.created !== true || !entry.installedSource) throw new Error();
        continue;
      }
      if (
        !config ||
        config.snapshot.content !== expected ||
        unsupported ||
        (server
          ? Boolean(server.managedPolicyPath)
          : entry.created !== true || !entry.installedSource)
      ) {
        throw new Error();
      }
    }
  } catch {
    throw new Error("MCP restore verification failed");
  }
}

export type SetupRestoreSelection = {
  adapter: ClientAdapter;
  server: ServerCandidate;
  policy: { diskPath: string };
  policySource: string;
  unownedPolicyBaseline?: FileSnapshot;
  oauthProfileId?: string;
  created?: true;
  ownerProjectRoot?: string;
  route?: { write: PlannedWrite; installed: FileFingerprint };
};

type SetupLoadedConfig = Omit<LoadedConfig, "snapshot"> & { snapshot?: FileSnapshot };

export async function assertPolicyTakeoversAllowed(
  home: string,
  targets: readonly {
    policyPath: string;
    except?: { configPath: string; serverName: string };
  }[],
): Promise<void> {
  if (!targets.length) return;
  const indexed = await readRestoreStateIndex(home);
  if (!indexed) throw new Error("Failed to verify existing policy ownership");
  for (const target of targets) {
    const policyPath = resolve(target.policyPath);
    const targetIdentity = await nodeIdentity(policyPath);
    for (const { state } of indexed) {
      for (const record of state.servers) {
        if (
          target.except &&
          resolve(state.configPath) === resolve(target.except.configPath) &&
          record.name === target.except.serverName
        ) {
          continue;
        }
        if (
          resolve(record.policy.path) === policyPath ||
          (targetIdentity !== undefined &&
            targetIdentity === (await nodeIdentity(record.policy.path)))
        ) {
          throw new Error("Existing policy is referenced by another MCP restore state");
        }
      }
    }
  }
}

async function nodeIdentity(path: string): Promise<string | undefined> {
  try {
    const metadata = await lstat(path);
    return `${metadata.dev}:${metadata.ino}`;
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
}

export async function planSetupRestoreStateChanges(options: {
  home: string;
  projectRoot: string;
  environment: NodeJS.ProcessEnv;
  loaded: readonly SetupLoadedConfig[];
  selections: readonly SetupRestoreSelection[];
  clientWrites: readonly PlannedWrite[];
}): Promise<PlannedFileChange[]> {
  const indexed = await readRestoreStateIndex(options.home);
  if (!indexed && options.selections.some(({ route }) => route)) {
    throw new Error("Failed to verify existing route ownership");
  }
  const takeovers = options.selections.filter(({ unownedPolicyBaseline }) => unownedPolicyBaseline);
  await assertPolicyTakeoversAllowed(
    options.home,
    takeovers.map((selection) => ({
      policyPath: selection.policy.diskPath,
      except: {
        configPath: selection.server.configPath,
        serverName: selection.server.name,
      },
    })),
  );
  const changes: PlannedFileChange[] = [];
  const configPaths = new Set(options.selections.map(({ server }) => resolve(server.configPath)));
  for (const configPath of configPaths) {
    const selections = options.selections.filter(
      ({ server }) => resolve(server.configPath) === configPath,
    );
    const loaded = options.loaded.filter(({ config }) => resolve(config.path) === configPath);
    const entry = loaded.length === 1 ? loaded[0] : undefined;
    if (!entry || selections.some(({ adapter }) => adapter !== entry.adapter)) {
      throw new Error("Invalid client configuration selected");
    }
    if (!entry.adapter.restore) continue;
    if (!entry.snapshot) {
      const generatedKind = generatedPresetKind(options.home, entry.adapter.id, configPath);
      if (
        generatedKind === undefined ||
        !generatedPresetKinds(entry.adapter).includes(generatedKind) ||
        selections.some(({ created }) => created !== true)
      ) {
        throw new Error("Invalid client configuration selected");
      }
    }

    const selectedOwnerProjectRoot = resolve(
      selections[0]?.ownerProjectRoot ?? options.projectRoot,
    );
    if (
      selections.some(
        (selection) =>
          resolve(selection.ownerProjectRoot ?? options.projectRoot) !== selectedOwnerProjectRoot,
      )
    ) {
      throw new Error("Invalid client configuration selected");
    }

    const configWrite = exactWrite(options.clientWrites, configPath);
    const stored = await readRestoreState({
      home: options.home,
      adapterId: entry.adapter.id,
      configPath,
      projectRoot: options.projectRoot,
    });
    if (!entry.snapshot && stored) throw new Error("Invalid client configuration selected");
    const records = new Map(stored?.state.servers.map((server) => [server.name, server]) ?? []);
    const context = {
      home: options.home,
      projectRoot: resolve(options.projectRoot),
      cwd: resolve(options.projectRoot),
      environment: options.environment,
    };

    for (const selection of selections) {
      let originalSource: string | undefined;
      let policyBefore: RestoreServerState["policy"]["before"] | undefined;
      let created: true | undefined = selection.created;
      if (!selection.server.managedPolicyPath) {
        originalSource = entry.config.source;
      } else {
        const previous = records.get(selection.server.name);
        if (previous) {
          try {
            restoreAdapterConfig(
              entry.adapter,
              entry.config,
              [
                {
                  name: selection.server.name,
                  originalSource: entry.config.source,
                  installedSource: previous.installedSource,
                  ...(previous.created ? { created: true } : {}),
                },
              ],
              context,
            );
            originalSource = previous.originalSource;
            policyBefore = previous.policy.before;
            created = previous.created;
          } catch {}
        }
        if (originalSource === undefined) {
          originalSource = (
            entry.snapshot
              ? await findLegacyRestoreEntry({
                  home: options.home,
                  adapter: entry.adapter,
                  loaded: entry as LoadedConfig,
                  server: selection.server,
                  context,
                })
              : undefined
          )?.originalSource;
        }
      }

      if (originalSource === undefined) {
        records.delete(selection.server.name);
        continue;
      }
      const policyWrite = exactWrite(options.clientWrites, resolve(selection.policy.diskPath));
      if (policyWrite.content !== selection.policySource)
        throw new Error("Invalid setup write plan");
      let route: RestoreRouteState | undefined;
      if (selection.route) {
        const owner: RouteOwner = {
          adapterId: entry.adapter.id,
          scope: selection.server.scope,
          configPath,
          projectRoot: selectedOwnerProjectRoot,
          serverName: selection.server.name,
        };
        const write = selection.route.write;
        let definition;
        try {
          definition = parseRoute(write.content, resolve(write.path));
        } catch {
          throw new Error("Invalid setup write plan");
        }
        if (
          selection.created !== true ||
          selection.server.source.kind !== "http" ||
          write.path !== resolve(write.path) ||
          resolve(write.path) !== routePath(options.home, owner) ||
          write.before !== undefined ||
          write.private !== true ||
          !isPrivateFileMode(write.mode) ||
          !isDeepStrictEqual(
            selection.route.installed,
            policyFingerprint(write.content, write.mode),
          ) ||
          !isDeepStrictEqual(definition.owner, owner) ||
          definition.listenUrl !== selection.server.source.url
        ) {
          throw new Error("Invalid setup write plan");
        }
        route = { path: resolve(write.path), installed: selection.route.installed };
      }
      const record: RestoreServerState = {
        name: selection.server.name,
        scope: selection.server.scope,
        projectRoot: selectedOwnerProjectRoot,
        originalSource,
        installedSource: configWrite.content,
        ...(created ? { created: true } : {}),
        ...(route ? { route } : {}),
        policy: {
          path: resolve(policyWrite.path),
          before:
            policyBefore !== undefined
              ? policyBefore
              : policyWrite.before
                ? { content: policyWrite.before.content, mode: policyWrite.before.mode }
                : null,
          installed: policyFingerprint(policyWrite.content, policyWrite.mode),
        },
        ...(selection.oauthProfileId ? { oauthProfileId: selection.oauthProfileId } : {}),
      };
      records.set(record.name, record);
    }

    const change = planRestoreStateChange({
      home: options.home,
      configPath,
      backupKey: configPath,
      ...(stored ? { before: stored.snapshot } : {}),
      ...(records.size
        ? {
            state: {
              version: 2,
              adapterId: entry.adapter.id,
              configPath,
              servers: [...records.values()],
            },
          }
        : {}),
    });
    if (change) changes.push(change);
  }
  return changes;
}

function exactWrite(writes: readonly PlannedWrite[], path: string): PlannedWrite {
  const matching = writes.filter((write) => resolve(write.path) === resolve(path));
  if (matching.length !== 1) throw new Error("Invalid setup write plan");
  return matching[0]!;
}

function unavailableServer({
  client,
  scope,
  name,
  configPath,
}: ServerCandidate): UnsupportedServer {
  return { client, scope, name, configPath, reason: "MCP restore is unavailable" };
}
