import { execFile as execFileCallback } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, mkdir, mkdtemp, rm } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";

import {
  ensurePrivateDirectory,
  withPrivateFileLock,
  writePrivateFileAtomically,
  type FileSnapshot,
} from "./setup/transaction.js";
import {
  checkedDirectory,
  directoryExists,
  errorCode,
  readRegularFile,
  syncStagedTree,
} from "./client-plugins/filesystem.js";
import {
  assertNoBuiltInAdapterId,
  clientAdapterListEntries,
  inspectClientAdaptersFromRoot,
  type ClientAdapterListEntry,
  type LoadedClientAdapter,
  type UnavailableClientAdapter,
} from "./client-plugins/loading.js";
import {
  CLIENT_ADAPTER_INSTALLATION_FAILED_MESSAGE,
  CLIENT_ADAPTER_LOAD_FAILURE,
  CLIENT_ADAPTER_NOT_INSTALLED_MESSAGE,
} from "./client-plugins/constants.js";
import {
  createModuleGraphLease,
  retainLoadedModuleGraphs,
  rollbackLoadedClientAdapters,
  sweepUnreferencedModuleGraphs,
  validateInstalledPackage,
} from "./client-plugins/module-graphs.js";
import {
  clientPluginsRoot,
  isCanonicalPackageName,
  METADATA_FILE,
  readInstalledClientPlugin,
  resolveNpmCommand,
  type InstalledClientPlugin,
} from "./client-plugins/package.js";
import {
  moveClientAdapterInactive,
  promoteClientAdapter,
  recoverClientPluginPromotion,
  restoreRemovedClientAdapter,
  rollbackClientAdapterPromotion,
  type PromotionRecovery,
} from "./client-plugins/promotion.js";

export { clientPluginsRoot, resolveNpmCommand } from "./client-plugins/package.js";
export type { InstalledClientPlugin } from "./client-plugins/package.js";
export type { ClientAdapterListEntry } from "./client-plugins/loading.js";

const CLEANUP_WARNING = "inactive client adapter files require manual cleanup";

type ExecFile = (
  file: string,
  args: readonly string[],
  options: { cwd: string; shell: false },
) => Promise<unknown>;

const execFile = promisify(execFileCallback) as ExecFile;

export async function installClientAdapter(
  spec: string,
  options: {
    home?: string;
    environment?: NodeJS.ProcessEnv;
    execFile?: ExecFile;
  } = {},
): Promise<{ plugin: InstalledClientPlugin; warnings: readonly string[] }> {
  if (spec.length === 0) throw new Error("Client adapter package spec is required");
  const root = clientPluginsRoot(options.home ?? homedir());
  await ensurePrivateDirectory(root);
  await withClientPluginRegistry(root, async () => undefined);
  const stage = await mkdtemp(join(root, ".stage-"));
  await chmod(stage, 0o700);
  const generation = join(stage, `.generation-${randomUUID()}`);
  await mkdir(generation, { mode: 0o700 });
  await chmod(generation, 0o700);
  let outcome: { plugin: InstalledClientPlugin; warnings: readonly string[] } | undefined;
  let operationError: unknown;
  try {
    const rootManifestPath = join(generation, "package.json");
    await writePrivateFileAtomically({
      path: rootManifestPath,
      content: JSON.stringify({ private: true }),
    });
    const npm = await resolveNpmCommand(options.environment ?? process.env);
    try {
      const installArgs = [
        ...npm.args,
        "install",
        "--ignore-scripts",
        "--save-exact",
        ...(process.platform === "win32" ? ["--package-lock=false", "--prefix", generation] : []),
        "--",
        spec,
      ];
      await (options.execFile ?? execFile)(npm.file, installArgs, {
        cwd: generation,
        shell: false,
      });
    } catch {
      throw new Error(CLIENT_ADAPTER_INSTALLATION_FAILED_MESSAGE);
    }
    let installed: Awaited<ReturnType<typeof validateInstalledPackage>>;
    try {
      await readRegularFile(rootManifestPath);
      await chmod(rootManifestPath, 0o600);
      installed = await validateInstalledPackage(generation, undefined, true);
    } catch {
      throw new Error(CLIENT_ADAPTER_LOAD_FAILURE);
    }
    const plugin: InstalledClientPlugin = {
      packageName: installed.packageName,
      version: installed.version,
      requestedSpec: spec,
    };
    await writePrivateFileAtomically({
      path: join(stage, METADATA_FILE),
      content: JSON.stringify(plugin),
    });
    assertNoBuiltInAdapterId(installed.adapter.id);
    try {
      await syncStagedTree(stage);
    } catch {
      throw new Error(CLIENT_ADAPTER_LOAD_FAILURE);
    }

    const target = join(root, encodeURIComponent(plugin.packageName));
    const promotion = await withClientPluginRegistry(
      root,
      () => promoteClientAdapter(stage, generation, target, root, installed.adapter.id),
      { rollback: (value) => rollbackClientAdapterPromotion(stage, value, root) },
    );
    let recovery: PromotionRecovery;
    try {
      recovery = await withClientPluginRegistry(root, async (result) => result);
    } catch {
      throw new Error("client adapter registry recovery failed");
    }
    if (recovery.status === "reverted") {
      throw new Error(CLIENT_ADAPTER_INSTALLATION_FAILED_MESSAGE);
    }
    let cleanupWarning = recovery.status === "completed" && recovery.cleanupWarning;
    if (!cleanupWarning && recovery.status === "none" && promotion.backup) {
      try {
        cleanupWarning = await directoryExists(resolve(promotion.backup));
      } catch {
        cleanupWarning = true;
      }
    }
    outcome = {
      plugin,
      warnings: cleanupWarning ? [CLEANUP_WARNING] : [],
    };
  } catch (error) {
    operationError = error;
  }

  try {
    await rm(stage, { recursive: true, force: true });
  } catch (cleanupError) {
    if (outcome !== undefined) {
      outcome = {
        plugin: outcome.plugin,
        warnings: outcome.warnings.includes(CLEANUP_WARNING)
          ? outcome.warnings
          : [...outcome.warnings, CLEANUP_WARNING],
      };
    } else if (operationError !== undefined) {
      throw new AggregateError(
        [operationError, cleanupError],
        "Client adapter installation and stage cleanup failed",
      );
    } else throw cleanupError;
  }
  if (operationError !== undefined) {
    try {
      await withClientPluginRegistry(root, async () => undefined);
    } catch {
      // Preserve the original failure; a later registry entry retries exact graph cleanup.
    }
    throw operationError;
  }
  return outcome!;
}

export async function loadInstalledClientAdapters(options: { home?: string } = {}): Promise<{
  adapters: LoadedClientAdapter[];
  unavailable: UnavailableClientAdapter[];
}> {
  const root = clientPluginsRoot(options.home ?? homedir());
  try {
    await checkedDirectory(root);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return { adapters: [], unavailable: [] };
    throw error;
  }

  const loaded = await withClientPluginRegistry(root, () => acquireInstalledClientAdapters(root), {
    rollback: ({ inspected, leases }) =>
      rollbackLoadedClientAdapters(root, inspected.adapters, leases),
  });
  retainLoadedModuleGraphs(loaded.inspected.adapters);
  return loadedClientAdapters(loaded.inspected);
}

export async function withInstalledClientAdapters<T>(
  options: { home?: string },
  operation: (loaded: {
    adapters: LoadedClientAdapter[];
    unavailable: UnavailableClientAdapter[];
  }) => Promise<T>,
): Promise<T> {
  const root = clientPluginsRoot(options.home ?? homedir());
  try {
    await checkedDirectory(root);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return operation({ adapters: [], unavailable: [] });
    throw error;
  }

  const loaded = await withClientPluginRegistry(root, () => acquireInstalledClientAdapters(root), {
    rollback: ({ inspected, leases }) =>
      rollbackLoadedClientAdapters(root, inspected.adapters, leases),
  });
  let result: T | undefined;
  let operationError: unknown;
  try {
    result = await operation(loadedClientAdapters(loaded.inspected));
  } catch (error) {
    operationError = error;
  }
  try {
    await withPrivateFileLock(join(root, ".registry"), () =>
      rollbackLoadedClientAdapters(root, loaded.inspected.adapters, loaded.leases),
    );
  } catch (cleanupError) {
    if (operationError !== undefined) {
      throw new AggregateError(
        [operationError, cleanupError],
        "Client adapter operation and cleanup failed",
      );
    }
    throw cleanupError;
  }
  if (operationError !== undefined) throw operationError;
  return result as T;
}

async function acquireInstalledClientAdapters(root: string) {
  const inspected = await inspectClientAdaptersFromRoot(root, undefined, true);
  const leases: FileSnapshot[] = [];
  try {
    for (const { moduleGraph } of inspected.adapters) {
      const lease = await createModuleGraphLease(root, moduleGraph);
      if (lease) leases.push(lease);
    }
  } catch {
    await rollbackLoadedClientAdapters(root, inspected.adapters, leases);
    throw new Error("client adapter lease failed");
  }
  return { inspected, leases };
}

function loadedClientAdapters(
  inspected: Awaited<ReturnType<typeof inspectClientAdaptersFromRoot>>,
) {
  return {
    adapters: inspected.adapters.map(({ plugin, adapter }) => ({
      packageName: plugin.packageName,
      adapter,
    })),
    unavailable: inspected.unavailable.map(({ packageName, reason }) => ({
      packageName,
      reason,
    })),
  };
}

export async function listClientAdapters(
  options: { home?: string } = {},
): Promise<ClientAdapterListEntry[]> {
  const root = clientPluginsRoot(options.home ?? homedir());
  try {
    await checkedDirectory(root);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return [];
    throw error;
  }

  return withClientPluginRegistry(root, async () =>
    clientAdapterListEntries(await inspectClientAdaptersFromRoot(root)),
  );
}

export async function removeClientAdapter(
  packageName: string,
  options: { home?: string } = {},
): Promise<{ warnings: readonly string[] }> {
  if (!isCanonicalPackageName(packageName)) {
    throw new Error("client adapter package name is invalid");
  }
  const root = clientPluginsRoot(options.home ?? homedir());
  try {
    await checkedDirectory(root);
  } catch (error) {
    if (errorCode(error) === "ENOENT") throw new Error(CLIENT_ADAPTER_NOT_INSTALLED_MESSAGE);
    throw error;
  }

  const moved = await withClientPluginRegistry(
    root,
    async () => {
      const activeName = encodeURIComponent(packageName);
      const target = join(root, activeName);
      let plugin: InstalledClientPlugin;
      try {
        plugin = await readInstalledClientPlugin(target, activeName, () => undefined);
      } catch {
        throw new Error(CLIENT_ADAPTER_NOT_INSTALLED_MESSAGE);
      }
      if (plugin.packageName !== packageName) {
        throw new Error(CLIENT_ADAPTER_NOT_INSTALLED_MESSAGE);
      }
      return moveClientAdapterInactive(target, root);
    },
    { rollback: (result) => restoreRemovedClientAdapter(result, root) },
  );
  let cleanupWarning = false;
  try {
    await rm(moved.inactive, { recursive: true });
  } catch {
    cleanupWarning = true;
  }
  try {
    await withClientPluginRegistry(root, async () => undefined);
  } catch {
    cleanupWarning = true;
  }
  return { warnings: cleanupWarning ? [CLEANUP_WARNING] : [] };
}

async function withClientPluginRegistry<T>(
  root: string,
  operation: (recovery: PromotionRecovery) => Promise<T>,
  options: { rollback?(result: T): Promise<void> } = {},
): Promise<T> {
  return withPrivateFileLock(
    join(root, ".registry"),
    async () => {
      const recovery = await recoverClientPluginPromotion(root);
      await sweepUnreferencedModuleGraphs(root);
      return operation(recovery);
    },
    options,
  );
}
