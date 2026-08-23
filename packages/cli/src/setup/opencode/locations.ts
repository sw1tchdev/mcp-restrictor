import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type {
  ClientAdapterHost,
  ClientLoadContext,
  ClientLoadResult,
  LoadedClientConfig,
} from "../../client-adapter.js";
import type { FileSnapshot } from "../transaction.js";
import type { ParsedConfig, Scope, ServerCandidate, UnsupportedServer } from "../wrapper.js";
import { openCodeShadowed } from "./candidate.js";
import { invalidOpenCodeConfiguration, parseOpenCodeConfig } from "./jsonc.js";

type Location = { scope: Scope; paths: readonly string[]; label: string; siblings: boolean };
type Owner =
  | { kind: "server"; config: ParsedConfig; row: ServerCandidate }
  | { kind: "unsupported"; row: UnsupportedServer };

const OPENCODE_CONFIG_CONTENT = "OPENCODE_CONFIG_CONTENT";

export async function loadOpenCodeConfigurations(
  context: ClientLoadContext,
  host: ClientAdapterHost,
): Promise<ClientLoadResult> {
  const configPath = ownString(context.environment, "OPENCODE_CONFIG", false);
  const configContent = ownString(context.environment, OPENCODE_CONFIG_CONTENT, true);
  const locations = configLocations(context, configPath);
  const seenFiles = new Set<string>();
  const snapshots = new Map<string, FileSnapshot | undefined>();
  const configurations: LoadedClientConfig[] = [];
  const ownershipSources: ParsedConfig[] = [];
  const unsupported: UnsupportedServer[] = [];

  for (const location of locations) {
    for (const candidatePath of location.paths) {
      const path = resolve(candidatePath);
      if (snapshots.has(path)) continue;
      const snapshot = await host.readConfig(path);
      snapshots.set(path, snapshot);
      if (!snapshot) continue;
      const identity = `${snapshot.dev}:${snapshot.ino}`;
      if (seenFiles.has(identity)) {
        throw new Error("OpenCode configuration paths resolve to the same file");
      }
      seenFiles.add(identity);
    }
  }

  const ambiguousLocations = new Map<string, number>();
  const ambiguousPaths = new Set<string>();
  locations.forEach((location, index) => {
    const paths = location.paths.map((path) => resolve(path));
    if (location.siblings && paths.every((path) => snapshots.get(path))) {
      ambiguousLocations.set(paths.join("\0"), index);
      for (const path of paths) ambiguousPaths.add(path);
    }
  });
  const highestLocations = new Map<string, number>();
  locations.forEach((location, index) => {
    for (const candidatePath of location.paths) {
      const path = resolve(candidatePath);
      if (!ambiguousPaths.has(path)) highestLocations.set(path, index);
    }
  });

  locations.forEach((location, index) => {
    const paths = location.paths.map((path) => resolve(path));
    const ambiguityKey =
      location.siblings && paths.every((path) => snapshots.get(path))
        ? paths.join("\0")
        : undefined;
    if (ambiguityKey) {
      if (ambiguousLocations.get(ambiguityKey) !== index) return;
      for (const path of paths) {
        const snapshot = snapshots.get(path)!;
        try {
          ownershipSources.push(
            parseOpenCodeConfig({
              path: snapshot.path,
              scope: location.scope,
              source: snapshot.content,
              projectRoot: context.projectRoot,
              environment: context.environment,
            }),
          );
        } catch {
          // Ambiguity remains the only sanitized user-facing error for this location.
        }
      }
      unsupported.push(
        configurationRow(
          location.scope,
          location.label,
          "ambiguous OpenCode configuration location",
        ),
      );
      return;
    }
    const path = paths.find(
      (path) =>
        !ambiguousPaths.has(path) && highestLocations.get(path) === index && snapshots.get(path),
    );
    if (!path) return;
    const snapshot = snapshots.get(path)!;
    try {
      const config = parseOpenCodeConfig({
        path: snapshot.path,
        scope: location.scope,
        source: snapshot.content,
        projectRoot: context.projectRoot,
        environment: context.environment,
      });
      configurations.push({ config, snapshot });
      ownershipSources.push(config);
    } catch {
      unsupported.push(
        configurationRow(location.scope, snapshot.path, invalidOpenCodeConfiguration),
      );
    }
  });

  applyPrecedence(ownershipSources, unsupported, configContent, context.environment);
  return { configurations, unsupported };
}

function configLocations(
  context: { home: string; projectRoot: string; cwd: string },
  customPath: string | undefined,
): Location[] {
  const ancestors = projectAncestors(context.projectRoot, context.cwd);
  return [
    siblingLocation("user", join(context.home, ".config/opencode")),
    ...(customPath
      ? [
          {
            scope: "user" as const,
            paths: [resolve(customPath)],
            label: dirname(resolve(customPath)),
            siblings: false,
          },
        ]
      : []),
    ...ancestors.map((path) => siblingLocation("project", path)),
    ...ancestors.map((path) => siblingLocation("project", join(path, ".opencode"))),
  ];
}

function siblingLocation(scope: Scope, directory: string): Location {
  const label = resolve(directory);
  return {
    scope,
    label,
    paths: [join(label, "opencode.json"), join(label, "opencode.jsonc")],
    siblings: true,
  };
}

function projectAncestors(projectRoot: string, cwd: string): string[] {
  const root = resolve(projectRoot);
  const current = resolve(cwd);
  const suffix = relative(root, current);
  if (isAbsolute(suffix) || suffix === ".." || suffix.startsWith(`..${sep}`)) return [root];
  const paths = [root];
  let path = root;
  for (const component of suffix.split(sep).filter(Boolean)) {
    path = join(path, component);
    paths.push(path);
  }
  return paths;
}

function applyPrecedence(
  configurations: readonly ParsedConfig[],
  unsupported: UnsupportedServer[],
  configContent: string | undefined,
  environment: NodeJS.ProcessEnv,
): void {
  const owners = new Map<string, Owner>();
  for (const config of configurations) {
    for (const row of [
      ...config.servers,
      ...config.unsupported.filter(({ reason }) => reason !== openCodeShadowed),
    ]) {
      replaceOwner(
        owners,
        row.name,
        "reason" in row ? { kind: "unsupported", row } : { kind: "server", config, row },
      );
    }
  }
  if (configContent === undefined) return;

  let inline: ParsedConfig;
  try {
    inline = parseOpenCodeConfig({
      path: OPENCODE_CONFIG_CONTENT,
      scope: "user",
      source: configContent,
      environment,
    });
  } catch {
    unsupported.push(
      configurationRow("user", OPENCODE_CONFIG_CONTENT, invalidOpenCodeConfiguration),
    );
    return;
  }
  for (const row of [...inline.servers, ...inline.unsupported]) {
    const effective: UnsupportedServer = {
      client: "opencode",
      scope: row.scope,
      name: row.name,
      configPath: row.configPath,
      reason: "inline OpenCode configuration is not writable",
    };
    replaceOwner(owners, row.name, { kind: "unsupported", row: effective });
    unsupported.push(effective);
  }
}

function replaceOwner(owners: Map<string, Owner>, name: string, next: Owner): void {
  const previous = owners.get(name);
  if (previous?.kind === "unsupported") {
    previous.row.reason = openCodeShadowed;
  } else if (previous) {
    previous.config.servers.splice(previous.config.servers.indexOf(previous.row), 1);
    previous.config.unsupported.push({
      client: "opencode",
      scope: previous.row.scope,
      name,
      configPath: previous.row.configPath,
      reason: openCodeShadowed,
    });
  }
  owners.set(name, next);
}

function ownString(
  environment: NodeJS.ProcessEnv,
  name: string,
  allowEmpty: boolean,
): string | undefined {
  if (!Object.hasOwn(environment, name)) return undefined;
  const value = environment[name];
  return typeof value === "string" && (allowEmpty || value) ? value : undefined;
}

function configurationRow(scope: Scope, path: string, reason: string): UnsupportedServer {
  return { client: "opencode", scope, name: "(configuration)", configPath: path, reason };
}
