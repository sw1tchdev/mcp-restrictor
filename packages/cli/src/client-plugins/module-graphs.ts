import { randomUUID } from "node:crypto";
import { cp, lstat, readdir, realpath, rm, unlink } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { pathToFileURL } from "node:url";

import { defineClientAdapter, type ClientAdapter } from "../client-adapter.js";
import {
  CLIENT_ADAPTER_LOAD_FAILURE,
  INVALID_CLIENT_ADAPTER_GENERATION_MESSAGE,
} from "./constants.js";
import {
  readPrivateFileSnapshot,
  writePrivateFileAtomically,
  type FileSnapshot,
} from "../setup/transaction.js";
import { assertExactKeys, checkedDirectory, parseRecord, syncDirectory } from "./filesystem.js";
import { processIsAlive } from "../utils/filesystem.js";
import {
  activeClientAdapterPrefixes,
  GENERATION_NAME,
  LEASE_NAME,
  readGenerationPointer,
  RUNTIME_NAME,
  validateInstalledContainerStructure,
  type InstalledClientPlugin,
} from "./package.js";

const failedModuleGraphs = new Map<string, "retry" | "exhausted">();
const leasedModuleGraphs = new Set<string>();
const loadedModuleGraphs = new Map<string, { adapter: ClientAdapter; moduleGraph: string }>();

export async function validateInstalledPackage(
  prefix: string,
  expected?: InstalledClientPlugin,
  requirePrivateRoot = false,
  root?: string,
  retryFailedImport = false,
  sourceGraph?: string,
): Promise<{
  packageName: string;
  version: string;
  adapter: ClientAdapter;
  sourceGraph: string;
  moduleGraph: string;
}> {
  const { packageName, version, prefixRealPath, entryRealPath } =
    await validateInstalledContainerStructure(prefix, expected, requirePrivateRoot);
  const sourceGraphRealPath = sourceGraph ?? prefixRealPath;

  const cached =
    prefixRealPath === sourceGraphRealPath
      ? loadedModuleGraphs.get(sourceGraphRealPath)
      : undefined;
  if (cached) {
    return {
      packageName,
      version,
      adapter: cached.adapter,
      sourceGraph: sourceGraphRealPath,
      moduleGraph: cached.moduleGraph,
    };
  }

  const failure = failedModuleGraphs.get(sourceGraphRealPath);
  if (failure === "exhausted") throw new Error(CLIENT_ADAPTER_LOAD_FAILURE);
  if (root !== undefined && prefixRealPath === sourceGraphRealPath && failure === "retry") {
    if (!retryFailedImport) throw new Error(CLIENT_ADAPTER_LOAD_FAILURE);
    return loadRuntimeModuleGraph(sourceGraphRealPath, expected, root);
  }

  const entryStat = await lstat(entryRealPath);
  const entryUrl = pathToFileURL(entryRealPath);
  entryUrl.searchParams.set(
    "mcpRestrictorFile",
    `${entryStat.dev}-${entryStat.ino}-${entryStat.mtimeMs}-${entryStat.size}`,
  );
  try {
    const imported = await import(entryUrl.href);
    const adapter = defineClientAdapter(imported.default as ClientAdapter);
    return {
      packageName,
      version,
      adapter,
      sourceGraph: sourceGraphRealPath,
      moduleGraph: prefixRealPath,
    };
  } catch (error) {
    if (
      root !== undefined &&
      prefixRealPath === sourceGraphRealPath &&
      GENERATION_NAME.test(basename(sourceGraphRealPath))
    )
      failedModuleGraphs.set(sourceGraphRealPath, "retry");
    throw error;
  }
}

export function isModuleGraphLeased(moduleGraph: string): boolean {
  return leasedModuleGraphs.has(moduleGraph);
}

export function retainLoadedModuleGraphs(
  adapters: readonly { adapter: ClientAdapter; sourceGraph: string; moduleGraph: string }[],
): void {
  for (const { adapter, sourceGraph, moduleGraph } of adapters) {
    loadedModuleGraphs.set(sourceGraph, { adapter, moduleGraph });
    failedModuleGraphs.delete(sourceGraph);
    leasedModuleGraphs.add(moduleGraph);
  }
}

export async function createModuleGraphLease(
  root: string,
  moduleGraph: string,
): Promise<FileSnapshot | undefined> {
  const rootRealPath = await checkedDirectory(root);
  const graphRealPath = await checkedDirectory(moduleGraph);
  const graph = basename(graphRealPath);
  if (
    dirname(graphRealPath) !== rootRealPath ||
    (!GENERATION_NAME.test(graph) && !RUNTIME_NAME.test(graph))
  )
    throw new Error("Invalid client adapter module graph");
  if (leasedModuleGraphs.has(graphRealPath)) return undefined;
  return writePrivateFileAtomically({
    path: join(rootRealPath, `.lease-${randomUUID()}`),
    content: JSON.stringify({ version: 1, pid: process.pid, graph }),
  });
}

export async function rollbackLoadedClientAdapters(
  root: string,
  adapters: readonly { sourceGraph: string; moduleGraph: string }[],
  leases: readonly FileSnapshot[],
): Promise<void> {
  const pending = [
    ...new Set(
      adapters
        .filter(
          ({ sourceGraph, moduleGraph }) =>
            moduleGraph !== sourceGraph && !leasedModuleGraphs.has(moduleGraph),
        )
        .map(({ moduleGraph }) => moduleGraph),
    ),
  ];
  const cleanup = await Promise.allSettled([
    removeModuleGraphLeases(leases),
    (async () => {
      for (const graph of pending) await rm(graph, { recursive: true, force: true });
      if (pending.length > 0) await syncDirectory(root);
    })(),
  ]);
  if (cleanup.some(({ status }) => status === "rejected")) {
    throw new Error("client adapter load rollback failed");
  }
}

export async function sweepUnreferencedModuleGraphs(root: string): Promise<void> {
  const rootRealPath = await checkedDirectory(root);
  const retained = new Set(leasedModuleGraphs);
  let protectAllGraphs = false;
  let removed = false;
  for (const name of await readdir(rootRealPath)) {
    if (!LEASE_NAME.test(name)) continue;
    let lease: FileSnapshot;
    let graph: string;
    let pid: number;
    try {
      lease = await readPrivateFileSnapshot(join(rootRealPath, name));
      const value = parseRecord(lease.content);
      assertExactKeys(value, ["graph", "pid", "version"]);
      if (
        value.version !== 1 ||
        typeof value.graph !== "string" ||
        (!GENERATION_NAME.test(value.graph) && !RUNTIME_NAME.test(value.graph)) ||
        typeof value.pid !== "number" ||
        !Number.isSafeInteger(value.pid) ||
        value.pid <= 0
      )
        throw new Error("Invalid client adapter lease");
      graph = value.graph;
      pid = value.pid;
    } catch {
      protectAllGraphs = true;
      continue;
    }
    if (processIsAlive(pid)) {
      retained.add(join(rootRealPath, graph));
      continue;
    }
    try {
      await removeModuleGraphLeases([lease]);
      removed = true;
    } catch {
      retained.add(join(rootRealPath, graph));
    }
  }
  for (const { prefix } of await activeClientAdapterPrefixes(rootRealPath)) {
    try {
      retained.add(await readGenerationPointer(prefix, rootRealPath));
    } catch {
      // Invalid active pointers are handled as unavailable by the loader.
    }
  }
  for (const name of await readdir(rootRealPath)) {
    if (!GENERATION_NAME.test(name) && !RUNTIME_NAME.test(name)) continue;
    const candidate = join(rootRealPath, name);
    let stat;
    let candidateRealPath: string;
    try {
      stat = await lstat(candidate);
      candidateRealPath = await realpath(candidate);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink() || !stat.isDirectory()) continue;
    if (
      protectAllGraphs ||
      dirname(candidateRealPath) !== rootRealPath ||
      retained.has(candidateRealPath)
    )
      continue;
    try {
      await rm(candidateRealPath, { recursive: true });
      failedModuleGraphs.delete(candidateRealPath);
      loadedModuleGraphs.delete(candidateRealPath);
      removed = true;
    } catch {
      // Exact stale graph cleanup is best effort and retried on the next registry entry.
    }
  }
  if (removed) await syncDirectory(rootRealPath);
}

async function loadRuntimeModuleGraph(
  generation: string,
  expected: InstalledClientPlugin | undefined,
  root: string,
): ReturnType<typeof validateInstalledPackage> {
  const rootRealPath = await checkedDirectory(root);
  if (dirname(generation) !== rootRealPath || !GENERATION_NAME.test(basename(generation)))
    throw new Error(INVALID_CLIENT_ADAPTER_GENERATION_MESSAGE);
  const runtime = join(rootRealPath, `.runtime-${randomUUID()}`);
  try {
    await cp(generation, runtime, { recursive: true, errorOnExist: true, force: false });
    const runtimeRealPath = await checkedDirectory(runtime);
    if (
      dirname(runtimeRealPath) !== rootRealPath ||
      !RUNTIME_NAME.test(basename(runtimeRealPath))
    ) {
      throw new Error("Invalid client adapter runtime");
    }
    const installed = await validateInstalledPackage(
      runtimeRealPath,
      expected,
      false,
      rootRealPath,
      false,
      generation,
    );
    failedModuleGraphs.set(generation, "exhausted");
    return installed;
  } catch (error) {
    failedModuleGraphs.set(generation, "exhausted");
    try {
      await rm(runtime, { recursive: true, force: true });
    } catch {
      // A later registry sweep retries exact hidden-runtime cleanup.
    }
    throw error;
  }
}

async function removeModuleGraphLeases(leases: readonly FileSnapshot[]): Promise<void> {
  for (const lease of [...leases].reverse()) {
    const current = await readPrivateFileSnapshot(lease.path);
    if (
      current.dev !== lease.dev ||
      current.ino !== lease.ino ||
      current.size !== lease.size ||
      current.mtimeMs !== lease.mtimeMs ||
      current.mode !== lease.mode ||
      current.content !== lease.content
    )
      throw new Error("client adapter lease changed");
    await unlink(lease.path);
    await syncDirectory(dirname(lease.path));
  }
}
