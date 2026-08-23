import { lstat, readdir, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

import { isPrivateFileMode } from "../setup/transaction.js";
import { RESTRICTOR_HOME_DIRECTORY } from "../utils/paths.js";
import {
  INVALID_CLIENT_ADAPTER_GENERATION_MESSAGE,
  INVALID_CLIENT_ADAPTER_METADATA_MESSAGE,
} from "./constants.js";
import {
  assertExactKeys,
  checkedDirectory,
  isContained,
  parseRecord,
  readRegularFile,
} from "./filesystem.js";

export type InstalledClientPlugin = {
  packageName: string;
  version: string;
  requestedSpec: string;
};

export const METADATA_FILE = ".mcp-restrictor-client-plugin.json";
export const JOURNAL_FILE = ".registry-promotion.json";
export const GENERATION_POINTER_FILE = ".mcp-restrictor-client-generation.json";
export const BACKUP_NAME =
  /^\.backup-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const GENERATION_NAME =
  /^\.generation-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const RUNTIME_NAME =
  /^\.runtime-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export const LEASE_NAME =
  /^\.lease-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$/;

export function clientPluginsRoot(home: string): string {
  return join(home, RESTRICTOR_HOME_DIRECTORY, "client-plugins");
}

export async function resolveNpmCommand(
  environment: NodeJS.ProcessEnv,
): Promise<{ file: string; args: string[] }> {
  if (process.platform !== "win32") return { file: "npm", args: [] };
  const npmCli =
    environment.npm_execpath ??
    join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  try {
    if (!isAbsolute(npmCli) || basename(npmCli) !== "npm-cli.js") throw new Error();
    const stat = await lstat(npmCli);
    if (stat.isSymbolicLink() || !stat.isFile()) throw new Error();
    await readRegularFile(npmCli, false);
  } catch {
    throw new Error("client adapter npm executable is unavailable");
  }
  return { file: process.execPath, args: [resolve(npmCli)] };
}

export async function activeClientAdapterPrefixes(
  root: string,
): Promise<Array<{ name: string; prefix: string }>> {
  return (await readdir(root))
    .filter((name) => !name.startsWith("."))
    .sort()
    .map((name) => ({ name, prefix: join(root, name) }));
}

export async function installedGenerationPrefix(prefix: string, root: string): Promise<string> {
  const names = await readdir(prefix);
  if (
    names.length !== 2 ||
    !names.includes(METADATA_FILE) ||
    !names.includes(GENERATION_POINTER_FILE)
  ) {
    throw new Error(INVALID_CLIENT_ADAPTER_GENERATION_MESSAGE);
  }
  return readGenerationPointer(prefix, root);
}

export async function readGenerationPointer(prefix: string, root: string): Promise<string> {
  const pointer = await readRegularFile(join(prefix, GENERATION_POINTER_FILE));
  if (!isPrivateFileMode(pointer.mode)) {
    throw new Error(INVALID_CLIENT_ADAPTER_GENERATION_MESSAGE);
  }
  const value = parseRecord(pointer.content);
  assertExactKeys(value, ["generation"]);
  if (typeof value.generation !== "string" || !GENERATION_NAME.test(value.generation)) {
    throw new Error(INVALID_CLIENT_ADAPTER_GENERATION_MESSAGE);
  }
  const rootRealPath = await checkedDirectory(root);
  const generationRealPath = await checkedDirectory(join(root, value.generation));
  if (dirname(generationRealPath) !== rootRealPath) {
    throw new Error(INVALID_CLIENT_ADAPTER_GENERATION_MESSAGE);
  }
  return generationRealPath;
}

export async function readInstalledClientPlugin(
  prefix: string,
  activeName: string,
  setSafePackageName: (packageName: string) => void,
): Promise<InstalledClientPlugin> {
  await checkedDirectory(prefix);
  const metadataPath = join(prefix, METADATA_FILE);
  const metadataFile = await readRegularFile(metadataPath);
  const metadataValue = parseRecord(metadataFile.content);
  if (isCanonicalPackageName(metadataValue.packageName)) {
    setSafePackageName(metadataValue.packageName);
  }
  if (!isPrivateFileMode(metadataFile.mode)) {
    throw new Error(INVALID_CLIENT_ADAPTER_METADATA_MESSAGE);
  }
  assertExactKeys(metadataValue, ["packageName", "requestedSpec", "version"]);
  const plugin = parseInstalledClientPlugin(metadataValue);
  if (encodeURIComponent(plugin.packageName) !== activeName) {
    throw new Error("Invalid client adapter directory");
  }
  return plugin;
}

export async function validateInstalledContainerStructure(
  prefix: string,
  expected?: InstalledClientPlugin,
  requirePrivateRoot = false,
): Promise<{
  packageName: string;
  version: string;
  prefixRealPath: string;
  entryRealPath: string;
}> {
  const prefixRealPath = await checkedDirectory(prefix);
  const rootManifestFile = await readRegularFile(join(prefix, "package.json"));
  const rootManifest = parseRecord(rootManifestFile.content);
  if (
    rootManifest.private !== true ||
    (requirePrivateRoot && !isPrivateFileMode(rootManifestFile.mode))
  )
    throw new Error("Invalid client adapter root");
  const dependencies = parseRecord(rootManifest.dependencies);
  const [packageName] = Object.keys(dependencies);
  if (
    Object.keys(dependencies).length !== 1 ||
    !isCanonicalPackageName(packageName) ||
    typeof dependencies[packageName] !== "string" ||
    (expected !== undefined && packageName !== expected.packageName)
  ) {
    throw new Error("Invalid client adapter dependency");
  }

  const packagePath = join(prefix, "node_modules", ...packageName.split("/"));
  await checkedDirectory(join(prefix, "node_modules"));
  if (packageName.startsWith("@")) {
    await checkedDirectory(join(prefix, "node_modules", packageName.split("/")[0]!));
  }
  const packageRealPath = await checkedDirectory(packagePath);
  if (!isContained(prefixRealPath, packageRealPath)) {
    throw new Error("Invalid client adapter package");
  }

  const manifestPath = join(packagePath, "package.json");
  const manifestFile = await readRegularFile(manifestPath);
  if (!isContained(packageRealPath, await realpath(manifestPath))) {
    throw new Error("Invalid client adapter manifest");
  }
  const manifest = parseRecord(manifestFile.content);
  if (
    manifest.name !== packageName ||
    typeof manifest.version !== "string" ||
    manifest.version.length === 0 ||
    (expected !== undefined && manifest.version !== expected.version)
  ) {
    throw new Error("Invalid client adapter identity");
  }
  const restrictor = parseRecord(manifest.mcpRestrictor);
  if (
    restrictor.apiVersion !== 1 ||
    typeof restrictor.clientAdapter !== "string" ||
    restrictor.clientAdapter.length === 0 ||
    isAbsolute(restrictor.clientAdapter)
  ) {
    throw new Error("Invalid client adapter manifest");
  }

  const entryPath = resolve(packagePath, restrictor.clientAdapter);
  const entryRelative = relative(packagePath, entryPath);
  if (
    entryRelative.length === 0 ||
    entryRelative === ".." ||
    entryRelative.startsWith(`..${sep}`) ||
    isAbsolute(entryRelative)
  ) {
    throw new Error("Invalid client adapter entry");
  }
  const components = entryRelative.split(sep);
  let current = packagePath;
  for (const [index, component] of components.entries()) {
    current = join(current, component);
    if (index === components.length - 1) break;
    await checkedDirectory(current);
  }
  await readRegularFile(current, false);
  const entryRealPath = await realpath(current);
  if (!isContained(packageRealPath, entryRealPath)) {
    throw new Error("Invalid client adapter entry");
  }
  return { packageName, version: manifest.version, prefixRealPath, entryRealPath };
}

export function isCanonicalPackageName(value: unknown): value is string {
  return typeof value === "string" && value.length <= 214 && PACKAGE_NAME.test(value);
}

export function isCanonicalActiveName(value: string): boolean {
  try {
    const packageName = decodeURIComponent(value);
    return isCanonicalPackageName(packageName) && encodeURIComponent(packageName) === value;
  } catch {
    return false;
  }
}

function parseInstalledClientPlugin(value: Record<string, unknown>): InstalledClientPlugin {
  if (
    !isCanonicalPackageName(value.packageName) ||
    typeof value.version !== "string" ||
    value.version.length === 0 ||
    typeof value.requestedSpec !== "string" ||
    value.requestedSpec.length === 0
  )
    throw new Error(INVALID_CLIENT_ADAPTER_METADATA_MESSAGE);
  return {
    packageName: value.packageName,
    version: value.version,
    requestedSpec: value.requestedSpec,
  };
}
