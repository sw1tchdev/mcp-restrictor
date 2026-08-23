import { lstat, readdir } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { routePath } from "../../routes.js";
import { RESTRICTOR_HOME_DIRECTORY } from "../../utils/paths.js";
import {
  errorCode,
  isPrivateFileMode,
  readPrivateFileSnapshot,
  sha256,
  validatePrivateDirectory,
  withPrivateFileLock,
  type FileSnapshot,
  type PlannedFileChange,
} from "../transaction.js";
import { policyLocation } from "../wrapper.js";
import { generatedPolicyLocation, isGeneratedConfigPath } from "../generated.js";
import { validOAuthProfileId } from "../wrapper/managed.js";

const INVALID_RESTORE_STATE = "Invalid MCP restore state";
const ADAPTER_ID = /^[a-z][a-z0-9-]{0,63}$/;
class DuplicateRouteOwnershipError extends Error {
  constructor() {
    super(INVALID_RESTORE_STATE);
  }
}

export type StoredFileState = { content: string; mode: number } | null;
export type FileFingerprint = { sha256: string; size: number; mode: number };

export type RestoreServerStateV1 = {
  name: string;
  scope: "user" | "project";
  projectRoot: string;
  originalSource: string;
  installedSource: string;
  created?: true;
  policy: {
    path: string;
    before: StoredFileState;
    installed: FileFingerprint;
  };
  oauthProfileId?: string;
};

export type RestoreRouteState = {
  path: string;
  installed: FileFingerprint;
};

export type RestoreServerStateV2 = RestoreServerStateV1 & {
  route?: RestoreRouteState;
};

export type RestoreServerState = RestoreServerStateV1 | RestoreServerStateV2;

export type RestoreStateV1 = {
  version: 1;
  adapterId: string;
  configPath: string;
  servers: RestoreServerStateV1[];
};

export type RestoreStateV2 = {
  version: 2;
  adapterId: string;
  configPath: string;
  servers: RestoreServerStateV2[];
};

export type RestoreState = RestoreStateV1 | RestoreStateV2;

export function withRestoreStateLock<T>(
  home: string,
  operation: () => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  return withPrivateFileLock(
    join(resolve(home), RESTRICTOR_HOME_DIRECTORY, "restore"),
    operation,
    signal ? { signal } : {},
  );
}

export function restoreStatePath(home: string, configPath: string): string {
  try {
    return join(
      resolve(requiredString(home)),
      RESTRICTOR_HOME_DIRECTORY,
      "restore",
      `${sha256(resolve(requiredString(configPath)))}.json`,
    );
  } catch {
    throw invalidState();
  }
}

export async function readRestoreState(options: {
  home: string;
  adapterId: string;
  configPath: string;
  projectRoot: string;
}): Promise<{ state: RestoreState; snapshot: FileSnapshot } | undefined> {
  try {
    const home = resolve(requiredString(options.home));
    const adapterId = requiredString(options.adapterId);
    const configPath = resolve(requiredString(options.configPath));
    const projectRoot = resolve(requiredString(options.projectRoot));
    if (!ADAPTER_ID.test(adapterId)) throw invalidState();
    const path = restoreStatePath(home, configPath);
    try {
      await validatePrivateDirectory(dirname(path), "Restore state directory");
    } catch (error) {
      if (errorCode(error) === "ENOENT") return undefined;
      throw error;
    }
    try {
      await lstat(path);
    } catch (error) {
      if (errorCode(error) === "ENOENT") return undefined;
      throw error;
    }
    const snapshot = await readPrivateFileSnapshot(path);
    const state = parseState(JSON.parse(snapshot.content), {
      home,
      adapterId,
      configPath,
      projectRoot,
    });
    return { state, snapshot };
  } catch {
    throw invalidState();
  }
}

export async function readRestoreStateIndex(
  homeValue: string,
): Promise<Array<{ state: RestoreState; snapshot: FileSnapshot }> | undefined> {
  try {
    const home = resolve(requiredString(homeValue));
    const directory = join(home, RESTRICTOR_HOME_DIRECTORY, "restore");
    await validatePrivateDirectory(directory, "Restore state directory");
    const indexed: Array<{ state: RestoreState; snapshot: FileSnapshot }> = [];
    const routes = new Set<string>();
    for (const entry of (await readdir(directory, { withFileTypes: true })).sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    )) {
      if (!entry.name.endsWith(".json")) continue;
      const snapshot = await readPrivateFileSnapshot(join(directory, entry.name));
      const raw = JSON.parse(snapshot.content);
      const parsed = parseState(raw);
      const projectRoots = new Set(
        parsed.servers
          .filter(({ scope }) => scope === "project")
          .map(({ projectRoot }) => projectRoot),
      );
      if (projectRoots.size > 1) throw invalidState();
      const state = parseState(raw, {
        home,
        adapterId: parsed.adapterId,
        configPath: parsed.configPath,
        ...(projectRoots.size ? { projectRoot: [...projectRoots][0]! } : {}),
      });
      for (const server of state.servers) {
        if (!("route" in server) || !server.route) continue;
        if (routes.has(server.route.path)) throw new DuplicateRouteOwnershipError();
        routes.add(server.route.path);
      }
      if (snapshot.path !== restoreStatePath(home, state.configPath)) throw invalidState();
      indexed.push({ state, snapshot });
    }
    return indexed;
  } catch (error) {
    if (error instanceof DuplicateRouteOwnershipError) throw error;
    return errorCode(error) === "ENOENT" ? [] : undefined;
  }
}

export function serializeRestoreState(state: RestoreState): string {
  try {
    const parsed = parseState(state);
    parsed.servers.sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    );
    return `${JSON.stringify(parsed, null, 2)}\n`;
  } catch {
    throw invalidState();
  }
}

export function policyFingerprint(content: string, mode: number): FileFingerprint {
  try {
    requiredString(content, true);
    validMode(mode);
    return { sha256: sha256(content), size: Buffer.byteLength(content), mode };
  } catch {
    throw invalidState();
  }
}

export function matchesFingerprint(snapshot: FileSnapshot, expected: FileFingerprint): boolean {
  try {
    const fingerprint = parseFingerprint(expected);
    return (
      snapshot.mode === fingerprint.mode &&
      Buffer.byteLength(snapshot.content) === fingerprint.size &&
      sha256(snapshot.content) === fingerprint.sha256
    );
  } catch {
    return false;
  }
}

export function matchesPrivateFingerprint(
  snapshot: FileSnapshot,
  expected: FileFingerprint,
): boolean {
  return (
    isPrivateFileMode(snapshot.mode) &&
    isPrivateFileMode(expected.mode) &&
    matchesFingerprint({ ...snapshot, mode: expected.mode }, expected)
  );
}

export function planRestoreStateChange(options: {
  home: string;
  configPath: string;
  backupKey: string;
  before?: FileSnapshot;
  state?: RestoreState;
}): PlannedFileChange | undefined {
  try {
    const path = restoreStatePath(options.home, options.configPath);
    const configPath = resolve(requiredString(options.configPath));
    const backupKey = requiredString(options.backupKey);
    const before = options.before;
    if (before) {
      if (
        resolve(requiredString(before.path)) !== path ||
        typeof before.content !== "string" ||
        !isPrivateFileMode(before.mode)
      ) {
        throw invalidState();
      }
    }
    if (!options.state) {
      return before ? { delete: true, path, before, backupKey, private: true } : undefined;
    }
    const state = parseState(options.state, {
      home: resolve(requiredString(options.home)),
      adapterId: requiredString(options.state.adapterId),
      configPath,
    });
    const current = serializeRestoreState(state);
    if (before?.content === current) return undefined;
    const content = serializeRestoreState(
      state.version === 1 ? { ...state, version: 2, servers: state.servers } : state,
    );
    return { path, ...(before ? { before } : {}), content, mode: 0o600, backupKey, private: true };
  } catch {
    throw invalidState();
  }
}

function parseState(
  value: unknown,
  expected?: { home: string; adapterId: string; configPath: string; projectRoot?: string },
): RestoreState {
  const candidate = record(value);
  const version = candidate.version;
  if (version !== 1 && version !== 2) throw invalidState();
  const input = exactRecord(candidate, ["adapterId", "configPath", "servers", "version"]);
  const adapterId = requiredString(input.adapterId);
  const configPath = canonicalPath(input.configPath);
  if (
    !ADAPTER_ID.test(adapterId) ||
    (expected && (adapterId !== expected.adapterId || configPath !== expected.configPath)) ||
    !Array.isArray(input.servers)
  ) {
    throw invalidState();
  }
  const names = new Set<string>();
  const servers = input.servers.map((server) =>
    parseServer(server, adapterId, configPath, version, expected),
  );
  for (const server of servers) {
    if (names.has(server.name)) throw invalidState();
    names.add(server.name);
  }
  return version === 1
    ? { version, adapterId, configPath, servers }
    : { version, adapterId, configPath, servers };
}

function parseServer(
  value: unknown,
  adapterId: string,
  configPath: string,
  version: 1 | 2,
  expected?: { home: string; projectRoot?: string },
): RestoreServerStateV2 {
  const candidate = record(value);
  const optionalOAuth = Object.hasOwn(candidate, "oauthProfileId");
  const created = Object.hasOwn(candidate, "created") ? candidate.created : undefined;
  const optionalRoute = version === 2 && Object.hasOwn(candidate, "route");
  const input = exactRecord(value, [
    ...(created !== undefined ? ["created"] : []),
    "installedSource",
    "name",
    ...(optionalOAuth ? ["oauthProfileId"] : []),
    "originalSource",
    "policy",
    "projectRoot",
    ...(optionalRoute ? ["route"] : []),
    "scope",
  ]);
  const name = requiredString(input.name);
  const scope = input.scope;
  const projectRoot = canonicalPath(input.projectRoot);
  const originalSource = requiredString(input.originalSource, true);
  const installedSource = requiredString(input.installedSource, true);
  if (
    (scope !== "user" && scope !== "project") ||
    (scope === "project" && expected?.projectRoot && projectRoot !== expected.projectRoot)
  ) {
    throw invalidState();
  }
  const policy = parsePolicy(input.policy);
  if (expected) {
    const generated = isGeneratedConfigPath(expected.home, adapterId, configPath);
    if (
      generated &&
      (version !== 2 ||
        scope !== "user" ||
        projectRoot !== resolve(expected.home) ||
        !isPrivateFileMode(policy.installed.mode) ||
        (policy.before !== null && !isPrivateFileMode(policy.before.mode)))
    ) {
      throw invalidState();
    }
    const path = resolve(
      generated
        ? generatedPolicyLocation({ home: expected.home, adapterId, serverName: name }).diskPath
        : policyLocation({
            client: adapterId,
            scope,
            serverName: name,
            projectRoot,
            restrictorHome: join(expected.home, RESTRICTOR_HOME_DIRECTORY),
          }).diskPath,
    );
    if (policy.path !== path) throw invalidState();
  }
  const oauthProfileId = optionalOAuth ? requiredString(input.oauthProfileId) : undefined;
  if (created !== undefined && created !== true) throw invalidState();
  if (oauthProfileId !== undefined && !validOAuthProfileId(oauthProfileId)) throw invalidState();
  const route = optionalRoute
    ? parseRestoreRoute(input.route, {
        ...(expected ? { home: expected.home } : {}),
        adapterId,
        scope,
        configPath,
        projectRoot,
        serverName: name,
      })
    : undefined;
  if (route && created !== true) throw invalidState();
  return {
    name,
    scope,
    projectRoot,
    originalSource,
    installedSource,
    ...(created ? { created } : {}),
    policy,
    ...(route ? { route } : {}),
    ...(oauthProfileId ? { oauthProfileId } : {}),
  };
}

function parseRestoreRoute(
  value: unknown,
  owner: {
    home?: string;
    adapterId: string;
    scope: "user" | "project";
    configPath: string;
    projectRoot: string;
    serverName: string;
  },
): RestoreRouteState {
  const input = exactRecord(value, ["installed", "path"]);
  const path = canonicalPath(input.path);
  const { home: expectedHome, ...routeOwner } = owner;
  const home = expectedHome ?? routeHome(path);
  if (path !== routePath(home, routeOwner)) throw invalidState();
  return { path, installed: parseFingerprint(input.installed) };
}

function routeHome(path: string): string {
  const routes = dirname(path);
  const restrictor = dirname(routes);
  if (basename(routes) !== "routes" || basename(restrictor) !== RESTRICTOR_HOME_DIRECTORY) {
    throw invalidState();
  }
  return dirname(restrictor);
}

function parsePolicy(value: unknown): RestoreServerState["policy"] {
  const input = exactRecord(value, ["before", "installed", "path"]);
  return {
    path: canonicalPath(input.path),
    before: input.before === null ? null : parseStoredFile(input.before),
    installed: parseFingerprint(input.installed),
  };
}

function parseStoredFile(value: unknown): Exclude<StoredFileState, null> {
  const input = exactRecord(value, ["content", "mode"]);
  return { content: requiredString(input.content, true), mode: validMode(input.mode) };
}

function parseFingerprint(value: unknown): FileFingerprint {
  const input = exactRecord(value, ["mode", "sha256", "size"]);
  if (
    typeof input.sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(input.sha256) ||
    typeof input.size !== "number" ||
    !Number.isSafeInteger(input.size) ||
    input.size < 0
  ) {
    throw invalidState();
  }
  return { sha256: input.sha256, size: input.size, mode: validMode(input.mode) };
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  const input = record(value);
  const actual = Object.keys(input).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw invalidState();
  }
  return input;
}

function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw invalidState();
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0) || value.includes("\0")) {
    throw invalidState();
  }
  return value;
}

function canonicalPath(value: unknown): string {
  const path = requiredString(value);
  if (path !== resolve(path)) throw invalidState();
  return path;
}

function validMode(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > 0o7777) {
    throw invalidState();
  }
  return value;
}

function invalidState(): Error {
  return new Error(INVALID_RESTORE_STATE);
}
