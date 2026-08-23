import { createHash } from "node:crypto";
import { lstat, readdir } from "node:fs/promises";
import { basename, isAbsolute, join, resolve } from "node:path";
import { MASTER_KEY_FILE_ENV } from "./oauth/storage.js";
import { DEFAULT_RESTRICTOR_COMMAND } from "./setup/constants.js";
import {
  errorCode,
  readPrivateFileSnapshot,
  validatePrivateDirectory,
  type FileSnapshot,
} from "./setup/transaction.js";
import { parseManagedWrapper } from "./setup/wrapper/managed.js";
import { buildWrapperArgs } from "./setup/wrapper/planning.js";
import { RESTRICTOR_HOME_DIRECTORY } from "./utils/paths.js";
import { isRecord } from "./utils/values.js";

export type RouteOwner = {
  adapterId: string;
  scope: "user" | "project";
  configPath: string;
  projectRoot: string;
  serverName: string;
};

export type RouteDefinitionV1 = {
  version: 1;
  owner: RouteOwner;
  listenUrl: string;
  proxyArgs: string[];
  environment: { set: Record<string, string> };
};

const adapterIdPattern = /^[a-z][a-z0-9-]{0,63}$/;

export function routeId(owner: RouteOwner): string {
  const valid = parseOwner(owner);
  return createHash("sha256")
    .update(`client\0${valid.adapterId}\0${valid.scope}\0${valid.configPath}\0${valid.serverName}`)
    .digest("hex");
}

export function routePath(home: string, owner: RouteOwner): string {
  return join(resolve(home), RESTRICTOR_HOME_DIRECTORY, "routes", `${routeId(owner)}.json`);
}

export function routeUrl(port: number, owner: RouteOwner): string {
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw invalidRoute();
  return `http://127.0.0.1:${port}/mcp/${parseOwner(owner).adapterId}/${routeId(owner)}`;
}

export function serializeRoute(route: RouteDefinitionV1): string {
  return `${JSON.stringify(parseRoute(JSON.stringify(route)), null, 2)}\n`;
}

export function parseRoute(source: string, expectedPath?: string): RouteDefinitionV1 {
  let input: unknown;
  try {
    input = JSON.parse(source);
  } catch {
    throw invalidRoute();
  }
  if (!exactRecord(input, ["environment", "listenUrl", "owner", "proxyArgs", "version"])) {
    throw invalidRoute();
  }
  if (input.version !== 1) throw invalidRoute();
  const owner = parseOwner(input.owner);
  if (typeof input.listenUrl !== "string") throw invalidRoute();
  if (
    !Array.isArray(input.proxyArgs) ||
    input.proxyArgs[0] !== "--policy" ||
    !input.proxyArgs.every((value) => typeof value === "string")
  ) {
    throw invalidRoute();
  }
  const proxyArgs = input.proxyArgs;
  if (!exactRecord(input.environment, ["set"]) || !isRecord(input.environment.set)) {
    throw invalidRoute();
  }
  const environmentEntries = Object.entries(input.environment.set);
  if (
    environmentEntries.some(
      ([name, value]) =>
        name !== MASTER_KEY_FILE_ENV ||
        typeof value !== "string" ||
        !isAbsolute(value) ||
        value.includes("\0"),
    )
  ) {
    throw invalidRoute();
  }

  const managed = parseManagedWrapper(DEFAULT_RESTRICTOR_COMMAND, proxyArgs);
  if (!managed || !isAbsolute(managed.policyArgument) || managed.policyArgument.includes("\0")) {
    throw invalidRoute();
  }
  if (
    managed.source.kind === "stdio" &&
    (!managed.source.command ||
      managed.source.command.includes("\0") ||
      managed.source.args.some((value) => value.includes("\0")) ||
      managed.source.envNames.some((value) => !value || value.includes("\0")) ||
      (managed.source.cwd !== undefined &&
        (!isAbsolute(managed.source.cwd) || managed.source.cwd.includes("\0"))))
  ) {
    throw invalidRoute();
  }
  let canonicalProxyArgs: string[];
  try {
    canonicalProxyArgs = buildWrapperArgs({
      policyArgument: managed.policyArgument,
      source: managed.source,
      restrictor: { command: DEFAULT_RESTRICTOR_COMMAND, argsPrefix: [] },
    });
  } catch {
    throw invalidRoute();
  }
  if (
    canonicalProxyArgs.length !== proxyArgs.length ||
    canonicalProxyArgs.some((value, index) => value !== proxyArgs[index])
  ) {
    throw invalidRoute();
  }

  const portMatch = /^http:\/\/127\.0\.0\.1:([1-9][0-9]{0,4})(?:\/|$)/.exec(input.listenUrl);
  const port = Number(portMatch?.[1]);
  if (!portMatch || port > 65_535 || input.listenUrl !== routeUrl(port, owner)) {
    throw invalidRoute();
  }
  if (
    expectedPath !== undefined &&
    (resolve(expectedPath) !== expectedPath || basename(expectedPath) !== `${routeId(owner)}.json`)
  ) {
    throw invalidRoute();
  }

  return {
    version: 1,
    owner,
    listenUrl: input.listenUrl,
    proxyArgs: [...proxyArgs],
    environment: {
      set:
        environmentEntries.length === 0
          ? {}
          : { [MASTER_KEY_FILE_ENV]: environmentEntries[0]![1] as string },
    },
  };
}

export async function loadRoutes(
  home: string,
): Promise<Array<{ definition: RouteDefinitionV1; snapshot: FileSnapshot }>> {
  const directory = join(resolve(home), RESTRICTOR_HOME_DIRECTORY, "routes");
  try {
    await lstat(directory);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return [];
    throw error;
  }
  await validatePrivateDirectory(directory, "Routes directory");
  const names = (await readdir(directory)).filter((name) => name.endsWith(".json")).sort();
  const loaded: Array<{ definition: RouteDefinitionV1; snapshot: FileSnapshot }> = [];
  const ids = new Set<string>();
  const paths = new Set<string>();
  let origin: string | undefined;
  for (const name of names) {
    const snapshot = await readPrivateFileSnapshot(join(directory, name));
    const definition = parseRoute(snapshot.content, snapshot.path);
    const id = routeId(definition.owner);
    const url = new URL(definition.listenUrl);
    const routeOrigin = definition.listenUrl.slice(
      0,
      definition.listenUrl.length - url.pathname.length,
    );
    if (ids.has(id) || paths.has(url.pathname)) throw invalidRoute();
    if (origin !== undefined && routeOrigin !== origin) throw invalidRoute();
    ids.add(id);
    paths.add(url.pathname);
    origin = routeOrigin;
    loaded.push({ definition, snapshot });
  }
  return loaded;
}

function parseOwner(value: unknown): RouteOwner {
  if (!exactRecord(value, ["adapterId", "configPath", "projectRoot", "scope", "serverName"])) {
    throw invalidRoute();
  }
  const { adapterId, configPath, projectRoot, scope, serverName } = value;
  if (
    typeof adapterId !== "string" ||
    !adapterIdPattern.test(adapterId) ||
    (scope !== "user" && scope !== "project") ||
    !canonicalAbsolutePath(configPath) ||
    !canonicalAbsolutePath(projectRoot) ||
    typeof serverName !== "string" ||
    !serverName ||
    serverName.includes("\0")
  ) {
    throw invalidRoute();
  }
  return { adapterId, scope, configPath, projectRoot, serverName };
}

function canonicalAbsolutePath(value: unknown): value is string {
  return (
    typeof value === "string" &&
    isAbsolute(value) &&
    !value.includes("\0") &&
    resolve(value) === value
  );
}

function exactRecord(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return (
    isRecord(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.hasOwn(value, key))
  );
}

function invalidRoute(): Error {
  return new Error("Invalid managed HTTP route");
}
