import { rm } from "node:fs/promises";
import { dirname } from "node:path";

import type { ClientAdapter } from "../client-adapter.js";
import { builtInAdapters, createAdapterRegistry } from "../setup/adapters.js";
import {
  CLIENT_ADAPTER_INSTALLATION_FAILED_MESSAGE,
  CLIENT_ADAPTER_LOAD_FAILURE,
} from "./constants.js";
import { syncDirectory } from "./filesystem.js";
import { isModuleGraphLeased, validateInstalledPackage } from "./module-graphs.js";
import {
  activeClientAdapterPrefixes,
  installedGenerationPrefix,
  readInstalledClientPlugin,
  validateInstalledContainerStructure,
  type InstalledClientPlugin,
} from "./package.js";

export type LoadedClientAdapter = {
  packageName: string;
  adapter: ClientAdapter;
};

export type UnavailableClientAdapter = {
  packageName: string;
  reason: typeof CLIENT_ADAPTER_LOAD_FAILURE;
};

export type ClientAdapterListEntry =
  | {
      packageName: string;
      version: string;
      id: string;
      label: string;
      status: "available";
    }
  | {
      packageName: string;
      version?: string;
      status: "unavailable";
      reason: typeof CLIENT_ADAPTER_LOAD_FAILURE;
    };

export type InspectedClientAdapter = {
  plugin: InstalledClientPlugin;
  adapter: ClientAdapter;
  sourceGraph: string;
  moduleGraph: string;
};

type UnavailableInspectedClientAdapter = UnavailableClientAdapter & {
  plugin?: InstalledClientPlugin;
};

export type InspectedClientAdapters = {
  adapters: InspectedClientAdapter[];
  unavailable: UnavailableInspectedClientAdapter[];
};

const UNKNOWN_PACKAGE = "unknown client adapter";

export async function inspectClientAdaptersFromRoot(
  root: string,
  excludedActiveName?: string,
  retainModuleGraphs = false,
): Promise<InspectedClientAdapters> {
  const adapters: InspectedClientAdapter[] = [];
  const unavailable: UnavailableInspectedClientAdapter[] = [];
  for (const { name, prefix } of await activeClientAdapterPrefixes(root)) {
    if (name === excludedActiveName) continue;
    let packageName = UNKNOWN_PACKAGE;
    let plugin: InstalledClientPlugin | undefined;
    try {
      const loaded = await validateInstalledAdapter(
        prefix,
        name,
        (safeName) => {
          packageName = safeName;
        },
        (safePlugin) => {
          plugin = safePlugin;
        },
        retainModuleGraphs,
      );
      adapters.push(loaded);
    } catch {
      unavailable.push({
        packageName,
        ...(plugin ? { plugin } : {}),
        reason: CLIENT_ADAPTER_LOAD_FAILURE,
      });
    }
  }
  return { adapters, unavailable };
}

export function clientAdapterListEntries(
  inspected: InspectedClientAdapters,
): ClientAdapterListEntry[] {
  const registry = createAdapterRegistry(
    builtInAdapters,
    inspected.adapters.map(({ plugin, adapter }) => ({
      packageName: plugin.packageName,
      adapter,
    })),
  );
  const rejected = new Set(registry.unavailable.map(({ packageName }) => packageName));
  const entries: ClientAdapterListEntry[] = [
    ...inspected.adapters.map(({ plugin, adapter }): ClientAdapterListEntry =>
      rejected.has(plugin.packageName)
        ? {
            packageName: plugin.packageName,
            version: plugin.version,
            status: "unavailable",
            reason: CLIENT_ADAPTER_LOAD_FAILURE,
          }
        : {
            packageName: plugin.packageName,
            version: plugin.version,
            id: adapter.id,
            label: adapter.label,
            status: "available",
          },
    ),
    ...inspected.unavailable.map(({ packageName, plugin }): ClientAdapterListEntry => ({
      packageName,
      ...(plugin ? { version: plugin.version } : {}),
      status: "unavailable",
      reason: CLIENT_ADAPTER_LOAD_FAILURE,
    })),
  ];
  return entries.sort((left, right) =>
    left.packageName < right.packageName ? -1 : Number(left.packageName > right.packageName),
  );
}

export async function validateAcceptedInstalledAdapter(
  prefix: string,
  activeName: string,
  root?: string,
): Promise<{ plugin: InstalledClientPlugin; adapter: ClientAdapter }> {
  let installed: Awaited<ReturnType<typeof validateInstalledAdapter>>;
  try {
    installed = await validateInstalledAdapter(prefix, activeName, () => undefined);
  } catch {
    throw new Error(CLIENT_ADAPTER_INSTALLATION_FAILED_MESSAGE);
  }
  assertNoBuiltInAdapterId(installed.adapter.id);
  if (root !== undefined) {
    await assertNoExternalAdapterIdConflict(root, activeName, installed.adapter.id);
  }
  return installed;
}

export async function validateRestoredInstalledAdapterStructure(
  prefix: string,
  activeName: string,
  root: string,
): Promise<void> {
  const plugin = await readInstalledClientPlugin(prefix, activeName, () => undefined);
  await validateInstalledContainerStructure(await installedGenerationPrefix(prefix, root), plugin);
}

export function assertNoBuiltInAdapterId(adapterId: string): void {
  if (builtInAdapters.some(({ id }) => id === adapterId)) {
    throw new Error("client adapter ID conflicts with a built-in");
  }
}

export async function assertNoExternalAdapterIdConflict(
  root: string,
  activeName: string,
  adapterId: string,
): Promise<void> {
  const inspected = await inspectClientAdaptersFromRoot(root, activeName);
  if (inspected.adapters.some(({ adapter }) => adapter.id === adapterId)) {
    throw new Error("client adapter ID conflicts with another external");
  }
}

async function validateInstalledAdapter(
  prefix: string,
  activeName: string,
  setSafePackageName: (packageName: string) => void,
  setSafePlugin: (plugin: InstalledClientPlugin) => void = () => undefined,
  retainModuleGraph = false,
): Promise<InspectedClientAdapter> {
  const plugin = await readInstalledClientPlugin(prefix, activeName, setSafePackageName);
  setSafePlugin(plugin);
  const installed = await validateInstalledPackage(
    await installedGenerationPrefix(prefix, dirname(prefix)),
    plugin,
    false,
    dirname(prefix),
    retainModuleGraph,
  );
  if (
    !retainModuleGraph &&
    installed.moduleGraph !== installed.sourceGraph &&
    !isModuleGraphLeased(installed.moduleGraph)
  ) {
    await rm(installed.moduleGraph, { recursive: true });
    await syncDirectory(dirname(installed.moduleGraph));
  }
  return {
    plugin,
    adapter: installed.adapter,
    sourceGraph: installed.sourceGraph,
    moduleGraph: installed.moduleGraph,
  };
}
