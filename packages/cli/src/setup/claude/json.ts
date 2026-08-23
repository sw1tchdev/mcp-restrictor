import { parseTree, type ParseError } from "jsonc-parser";
import { dirname } from "node:path";
import { isDeepStrictEqual } from "node:util";
import type { ClientHttpInstallEntry, ClientInstallEntry } from "../../client-adapter.js";
import type { ParsedConfig, Replacement, Scope, UnsupportedServer } from "../wrapper.js";
import { defineOwn, isRecord } from "../../utils/values.js";
import { hasDuplicateJsonProperties } from "../json.js";
import { parseClaudeServer } from "./candidate.js";

export function parseClaudeConfig(options: {
  path: string;
  scope: Scope;
  source: string;
  projectRoot: string;
  environment: NodeJS.ProcessEnv;
}): ParsedConfig {
  const root = parseRoot(options.source);
  const servers = Object.hasOwn(root, "mcpServers") ? root.mcpServers : undefined;
  if (servers !== undefined && !isRecord(servers)) {
    throw new Error("Claude configuration mcpServers must be an object");
  }

  const parsed: ParsedConfig = {
    client: "claude",
    scope: options.scope,
    path: options.path,
    source: options.source,
    servers: [],
    unsupported: [],
  };
  for (const [name, entry] of Object.entries(servers ?? {})) {
    const result = parseClaudeServer({ ...options, name, entry });
    if ("reason" in result) parsed.unsupported.push(unsupported(options, name, result.reason));
    else parsed.servers.push(result);
  }
  return parsed;
}

export function installClaudeConfig(config: ParsedConfig, entry: ClientInstallEntry): string {
  if (entry.cwd !== undefined)
    throw new Error("Claude does not support wrapper working directories");

  const root = parseRoot(config.source);
  const existing = Object.hasOwn(root, "mcpServers") ? root.mcpServers : undefined;
  if (existing !== undefined && !isRecord(existing)) {
    throw new Error("Claude configuration mcpServers must be an object");
  }
  const servers = existing ?? {};
  if (Object.hasOwn(servers, entry.name)) throw new Error("Claude server name already exists");

  const env: Record<string, string> = {};
  for (const name of entry.environment.inherit) defineOwn(env, name, `\${${name}}`);
  for (const [name, value] of Object.entries(entry.environment.set)) defineOwn(env, name, value);
  defineOwn(servers, entry.name, {
    type: "stdio",
    command: entry.command,
    args: [...entry.args],
    ...(Object.keys(env).length ? { env } : {}),
  });
  if (existing === undefined) defineOwn(root, "mcpServers", servers);

  const source = `${JSON.stringify(root, null, 2)}\n`;
  const environment: NodeJS.ProcessEnv = {};
  for (const name of entry.environment.inherit) defineOwn(environment, name, "inherited");
  for (const [name, value] of Object.entries(entry.environment.set))
    defineOwn(environment, name, value);
  const candidate = parseClaudeConfig({
    path: config.path,
    scope: config.scope,
    source,
    projectRoot: dirname(config.path),
    environment,
  }).servers.find(({ name }) => name === entry.name);
  if (!candidate?.managedPolicyPath)
    throw new Error("Claude installation is not a managed wrapper");
  return source;
}

export function installClaudeHttpConfig(
  config: ParsedConfig,
  entry: ClientHttpInstallEntry,
): string {
  const root = parseRoot(config.source);
  const existing = Object.hasOwn(root, "mcpServers") ? root.mcpServers : undefined;
  if (existing !== undefined && !isRecord(existing)) {
    throw new Error("Claude configuration mcpServers must be an object");
  }
  const servers = existing ?? {};
  if (Object.hasOwn(servers, entry.name)) throw new Error("Claude server name already exists");
  defineOwn(servers, entry.name, { type: "http", url: entry.url });
  if (existing === undefined) defineOwn(root, "mcpServers", servers);

  const source = `${JSON.stringify(root, null, 2)}\n`;
  const candidates = parseClaudeConfig({
    path: config.path,
    scope: config.scope,
    source,
    projectRoot: dirname(config.path),
    environment: {},
  }).servers.filter(({ name }) => name === entry.name);
  if (
    candidates.length !== 1 ||
    !isDeepStrictEqual(candidates[0]!.source, { kind: "http", url: entry.url, headers: [] }) ||
    candidates[0]!.managedPolicyPath !== undefined
  ) {
    throw new Error("Claude HTTP installation is invalid");
  }
  return source;
}

export function renderClaudeConfig(
  config: ParsedConfig,
  replacements: ReadonlyMap<string, Replacement>,
): string {
  const root = parseRoot(config.source);
  const servers = root.mcpServers;
  if (!isRecord(servers)) throw new Error("Claude configuration must contain an mcpServers object");

  for (const candidate of config.servers) {
    const replacement = replacements.get(candidate.name);
    if (!replacement) continue;
    const original = servers[candidate.name];
    if (!isRecord(original)) continue;
    const entry: Record<string, unknown> = {
      type: "stdio",
      command: replacement.command,
      args: replacement.args,
    };
    if (replacement.env !== undefined) entry.env = replacement.env;
    for (const field of ["timeout", "alwaysLoad"] as const) {
      if (Object.hasOwn(original, field)) entry[field] = original[field];
    }
    Object.defineProperty(servers, candidate.name, {
      value: entry,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return `${JSON.stringify(root, null, 2)}\n`;
}

function unsupported(
  options: Pick<Parameters<typeof parseClaudeConfig>[0], "path" | "scope">,
  name: string,
  reason: string,
): UnsupportedServer {
  return { client: "claude", scope: options.scope, name, configPath: options.path, reason };
}

function parseRoot(source: string): Record<string, unknown> {
  let root: unknown;
  try {
    root = JSON.parse(source);
  } catch {
    throw new Error("Invalid Claude JSON");
  }
  const errors: ParseError[] = [];
  const tree = parseTree(source, errors);
  if (!tree || errors.length || hasDuplicateJsonProperties(tree)) {
    throw new Error("Invalid Claude JSON");
  }
  if (!isRecord(root)) throw new Error("Claude configuration root must be an object");
  return root;
}
