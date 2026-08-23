import { resolve } from "node:path";
import type { ClientAdapter, ClientLoadContext } from "../../client-adapter.js";
import { createAdapterLoader, type LoadedConfig } from "../adapter-boundary.js";
import {
  generatedPolicyLocation,
  generatedPresetConfig,
  generatedPresetKind,
  generatedPresetKinds,
  readGeneratedFileSnapshot,
  type GeneratedPresetKind,
} from "../generated.js";
import { readSetupSnapshot } from "../snapshot.js";
import type { FileSnapshot } from "../transaction.js";
import { policyLocation, type ParsedConfig, type Scope } from "../wrapper.js";

export type ManualDestination = {
  adapter: ClientAdapter;
  config: ParsedConfig;
  snapshot?: FileSnapshot;
  generated?: GeneratedPresetKind;
  policy: ReturnType<typeof policyLocation>;
  policyBaseline?: FileSnapshot;
};

export type GeneratedManualDestination = {
  adapter: ClientAdapter;
  kinds: readonly GeneratedPresetKind[];
};

export async function createGeneratedManualDestination(options: {
  choice: GeneratedManualDestination;
  kind: GeneratedPresetKind;
  context: ClientLoadContext;
  serverName: string;
}): Promise<ManualDestination> {
  if (!options.choice.kinds.includes(options.kind)) {
    throw new Error("Invalid generated preset selection");
  }
  const config = generatedPresetConfig({
    home: options.context.home,
    kind: options.kind,
    environment: options.context.environment,
  });
  const policy = generatedPolicyLocation({
    home: options.context.home,
    adapterId: options.choice.adapter.id,
    serverName: options.serverName,
  });
  const policyBaseline = await readGeneratedFileSnapshot(policy.diskPath);
  return {
    adapter: options.choice.adapter,
    config,
    generated: options.kind,
    policy,
    ...(policyBaseline ? { policyBaseline } : {}),
  };
}

type UnavailableDestination = {
  adapterLabel: string;
  scope?: Scope;
  configPath?: string;
  reason: string;
};

export async function discoverManualDestinations(options: {
  adapters: readonly ClientAdapter[];
  context: ClientLoadContext;
  serverName: string;
  restrictorHome: string;
}): Promise<{
  available: ManualDestination[];
  generated: GeneratedManualDestination[];
  unavailable: UnavailableDestination[];
}> {
  const available: ManualDestination[] = [];
  const generated: GeneratedManualDestination[] = [];
  const unavailable: UnavailableDestination[] = [];
  const loaded: Array<{
    adapter: ClientAdapter;
    label: string;
    entry: LoadedConfig;
    owned: boolean;
  }> = [];
  for (const adapter of options.adapters) {
    let label = "Client adapter";
    try {
      label = adapter.label;
      if (!adapter.install || !adapter.restore) {
        unavailable.push({
          adapterLabel: label,
          reason: "client adapter does not support installation and restore",
        });
        continue;
      }
      const result = await createAdapterLoader().load(adapter, options.context);
      const owned = result.unsupported.some(({ name }) => name === options.serverName);
      const kinds = generatedPresetKinds(adapter);
      if (!result.configurations.length && !owned && kinds.length && adapter.installHttp) {
        generated.push({ adapter, kinds });
      }
      loaded.push(...result.configurations.map((entry) => ({ adapter, label, entry, owned })));
    } catch {
      unavailable.push({ adapterLabel: label, reason: "client configuration could not be loaded" });
    }
  }

  const duplicateKeys = new Set<string>();
  const seen = new Set<string>();
  for (const { entry } of loaded) {
    const { snapshot } = entry;
    for (const key of [
      `path:${resolve(snapshot.path)}`,
      `identity:${snapshot.dev}:${snapshot.ino}`,
    ]) {
      if (seen.has(key)) duplicateKeys.add(key);
      seen.add(key);
    }
  }
  for (const { adapter, label, entry, owned } of loaded) {
    const { config, snapshot } = entry;
    const row = { adapterLabel: label, scope: config.scope, configPath: config.path };
    if (
      duplicateKeys.has(`path:${resolve(snapshot.path)}`) ||
      duplicateKeys.has(`identity:${snapshot.dev}:${snapshot.ino}`)
    ) {
      unavailable.push({ ...row, reason: "client configuration aliases another destination" });
      continue;
    }
    if (
      owned ||
      config.servers.some(({ name }) => name === options.serverName) ||
      config.unsupported.some(({ name }) => name === options.serverName)
    ) {
      unavailable.push({ ...row, reason: "server name already exists" });
      continue;
    }
    if (adapter.id === "manual") {
      unavailable.push({ ...row, reason: "client ID is reserved for Manual configuration" });
      continue;
    }
    const generatedKind = generatedPresetKind(options.context.home, adapter.id, config.path);
    const policy = generatedKind
      ? generatedPolicyLocation({
          home: options.context.home,
          adapterId: adapter.id,
          serverName: options.serverName,
        })
      : policyLocation({
          client: adapter.id,
          scope: config.scope,
          serverName: options.serverName,
          projectRoot: options.context.projectRoot,
          restrictorHome: options.restrictorHome,
        });
    let policyBaseline: FileSnapshot | undefined;
    try {
      policyBaseline = generatedKind
        ? await readGeneratedFileSnapshot(policy.diskPath)
        : await readSetupSnapshot(policy.diskPath, "policy");
    } catch {
      unavailable.push({ ...row, reason: "destination policy path is unavailable" });
      continue;
    }
    available.push({
      adapter,
      config,
      snapshot,
      ...(generatedKind ? { generated: generatedKind } : {}),
      policy,
      ...(policyBaseline ? { policyBaseline } : {}),
    });
  }
  const compare = <T extends { adapterLabel: string; scope?: Scope; configPath?: string }>(
    left: T,
    right: T,
  ) =>
    left.adapterLabel.localeCompare(right.adapterLabel) ||
    (left.scope === right.scope ? 0 : left.scope === "project" ? -1 : 1) ||
    resolve(left.configPath ?? "").localeCompare(resolve(right.configPath ?? ""));
  available.sort((left, right) =>
    compare(
      {
        adapterLabel: safeLabel(left.adapter),
        scope: left.config.scope,
        configPath: left.config.path,
      },
      {
        adapterLabel: safeLabel(right.adapter),
        scope: right.config.scope,
        configPath: right.config.path,
      },
    ),
  );
  generated.sort(
    (left, right) =>
      safeLabel(left.adapter).localeCompare(safeLabel(right.adapter)) ||
      left.adapter.id.localeCompare(right.adapter.id),
  );
  unavailable.sort(compare);
  return { available, generated, unavailable };
}

function safeLabel(adapter: ClientAdapter): string {
  try {
    return adapter.label;
  } catch {
    return "Client adapter";
  }
}
