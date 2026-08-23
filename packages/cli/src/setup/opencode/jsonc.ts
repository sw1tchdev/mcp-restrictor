import {
  applyEdits,
  findNodeAtLocation,
  modify,
  parse,
  parseTree,
  type Node as JsonNode,
  type ParseError,
} from "jsonc-parser";
import { isDeepStrictEqual } from "node:util";
import type { ClientHttpInstallEntry, ClientInstallEntry } from "../../client-adapter.js";
import type { ParsedConfig, Replacement, Scope } from "../wrapper.js";
import { defineOwn, isRecord } from "../../utils/values.js";
import { hasDuplicateJsonProperties } from "../json.js";
import { addOpenCodeEntry, shadowOpenCodeLocalOwner, type OpenCodeSchema } from "./candidate.js";

export const invalidOpenCodeConfiguration = "Invalid OpenCode configuration";

export function parseOpenCodeConfig(options: {
  path: string;
  scope: Scope;
  source: string;
  projectRoot?: string;
  environment?: NodeJS.ProcessEnv;
}): ParsedConfig {
  const tree = strictTree(options.source);

  const config: ParsedConfig = {
    client: "opencode",
    scope: options.scope,
    path: options.path,
    source: options.source,
    servers: [],
    unsupported: [],
  };
  const mcp = objectProperty(tree, "mcp");
  if (!mcp) return config;
  if (mcp.type !== "object") throw new Error(invalidOpenCodeConfiguration);
  const servers = objectProperty(mcp, "servers");
  const schema: OpenCodeSchema = servers && !isServerEntry(servers) ? "v2" : "v1";

  for (const [name, entry] of objectProperties(mcp)) {
    if (schema === "v1" || (name !== "servers" && name !== "timeout")) {
      addOpenCodeEntry(config, options, "v1", name, nodeValue(entry));
    }
  }
  if (schema === "v2") {
    if (!servers || servers.type !== "object") throw new Error(invalidOpenCodeConfiguration);
    for (const [name, entry] of objectProperties(servers)) {
      shadowOpenCodeLocalOwner(config, name);
      addOpenCodeEntry(config, options, "v2", name, nodeValue(entry));
    }
  }
  return config;
}

export function renderOpenCodeConfig(
  config: ParsedConfig,
  replacements: ReadonlyMap<string, Replacement>,
): string {
  const candidates = new Map(config.servers.map((candidate) => [candidate.name, candidate]));
  let source = config.source;
  for (const [name, replacement] of replacements) {
    const candidate = candidates.get(name);
    if (!candidate) throw new Error("OpenCode replacement does not match a supported server");
    const tree = strictTree(source);
    const mcp = objectProperty(tree, "mcp");
    if (!mcp || mcp.type !== "object") throw new Error(invalidOpenCodeConfiguration);
    const servers = objectProperty(mcp, "servers");
    const v2 = servers && !isServerEntry(servers) && objectProperty(servers, name);
    const path = v2 ? ["mcp", "servers", name] : ["mcp", name];
    const preserved = preservedClientFields(candidate.original, Boolean(v2));
    const localEntry = {
      type: "local",
      command: [replacement.command, ...replacement.args],
      ...(replacement.env !== undefined ? { environment: replacement.env } : {}),
      ...(replacement.cwd !== undefined ? { cwd: replacement.cwd } : {}),
      ...preserved,
    };
    source = applyEdits(
      source,
      modify(source, path, localEntry, {
        formattingOptions: { insertSpaces: true, tabSize: 2, eol: "\n" },
      }),
    );
    strictTree(source);
  }
  return source;
}

export function installOpenCodeConfig(config: ParsedConfig, entry: ClientInstallEntry): string {
  const tree = strictTree(config.source);
  const mcp = objectProperty(tree, "mcp");
  if (mcp && mcp.type !== "object") throw new Error(invalidOpenCodeConfiguration);
  const servers = mcp && objectProperty(mcp, "servers");
  const v2 = Boolean(servers && !isServerEntry(servers));
  if (v2 && servers?.type !== "object") throw new Error(invalidOpenCodeConfiguration);
  const v1 =
    mcp && (!v2 || (entry.name !== "servers" && entry.name !== "timeout"))
      ? objectProperty(mcp, entry.name)
      : undefined;
  const v2Entry = v2 ? objectProperty(servers!, entry.name) : undefined;
  if (v1 || v2Entry) {
    throw new Error("OpenCode server name already exists");
  }

  const environment: Record<string, string> = {};
  for (const name of entry.environment.inherit) defineOwn(environment, name, `{env:${name}}`);
  for (const [name, value] of Object.entries(entry.environment.set))
    defineOwn(environment, name, value);
  const local: Record<string, unknown> = {};
  defineOwn(local, "type", "local");
  defineOwn(local, "command", [entry.command, ...entry.args]);
  defineOwn(local, "environment", environment);
  if (entry.cwd !== undefined) defineOwn(local, "cwd", entry.cwd);
  const source = applyEdits(
    config.source,
    modify(config.source, v2 ? ["mcp", "servers", entry.name] : ["mcp", entry.name], local, {
      formattingOptions: { insertSpaces: true, tabSize: 2, eol: "\n" },
    }),
  );
  strictTree(source);
  const syntheticEnvironment: NodeJS.ProcessEnv = {};
  for (const name of entry.environment.inherit) defineOwn(syntheticEnvironment, name, "inherited");
  const candidate = parseOpenCodeConfig({
    path: config.path,
    scope: config.scope,
    source,
    environment: syntheticEnvironment,
  }).servers.find(({ name }) => name === entry.name);
  if (!candidate?.managedPolicyPath)
    throw new Error("OpenCode installation is not a managed wrapper");
  return source;
}

export function installOpenCodeHttpConfig(
  config: ParsedConfig,
  entry: ClientHttpInstallEntry,
): string {
  const tree = strictTree(config.source);
  const mcp = objectProperty(tree, "mcp");
  if (mcp && mcp.type !== "object") throw new Error(invalidOpenCodeConfiguration);
  const servers = mcp && objectProperty(mcp, "servers");
  const v2 = Boolean(servers && !isServerEntry(servers));
  if (v2 && servers?.type !== "object") throw new Error(invalidOpenCodeConfiguration);
  const v1 =
    mcp && (!v2 || (entry.name !== "servers" && entry.name !== "timeout"))
      ? objectProperty(mcp, entry.name)
      : undefined;
  const v2Entry = v2 ? objectProperty(servers!, entry.name) : undefined;
  if (v1 || v2Entry) throw new Error("OpenCode server name already exists");

  const remote: Record<string, unknown> = {};
  defineOwn(remote, "type", "remote");
  defineOwn(remote, "url", entry.url);
  defineOwn(remote, "oauth", false);
  const source = applyEdits(
    config.source,
    modify(config.source, v2 ? ["mcp", "servers", entry.name] : ["mcp", entry.name], remote, {
      formattingOptions: { insertSpaces: true, tabSize: 2, eol: "\n" },
      getInsertionIndex: () => 0,
    }),
  );
  strictTree(source);
  const candidates = parseOpenCodeConfig({
    path: config.path,
    scope: config.scope,
    source,
  }).servers.filter(({ name }) => name === entry.name);
  if (
    candidates.length !== 1 ||
    !isDeepStrictEqual(candidates[0]!.source, { kind: "http", url: entry.url, headers: [] }) ||
    candidates[0]!.managedPolicyPath !== undefined
  ) {
    throw new Error("OpenCode HTTP installation is invalid");
  }
  return source;
}

export function openCodeEntryPath(source: string, name: string): string[] {
  const tree = strictTree(source);
  const mcp = findNodeAtLocation(tree, ["mcp"]);
  if (!mcp) return ["mcp", name];
  if (mcp.type !== "object") throw new Error(invalidOpenCodeConfiguration);
  const servers = findNodeAtLocation(tree, ["mcp", "servers"]);
  return servers && !isServerEntry(servers) ? ["mcp", "servers", name] : ["mcp", name];
}

function strictTree(source: string): JsonNode {
  const errors: ParseError[] = [];
  const root: unknown = parse(source, errors, { allowTrailingComma: true });
  const treeErrors: ParseError[] = [];
  const tree = parseTree(source, treeErrors, { allowTrailingComma: true });
  if (
    errors.length ||
    treeErrors.length ||
    !tree ||
    !isRecord(root) ||
    hasDuplicateJsonProperties(tree)
  )
    throw new Error(invalidOpenCodeConfiguration);
  return tree;
}

function preservedClientFields(
  original: Record<string, unknown>,
  v2: boolean,
): Record<string, unknown> {
  const preserved: Record<string, unknown> = {};
  for (const field of v2
    ? (["disabled", "codemode", "timeout"] as const)
    : (["enabled", "timeout"] as const)) {
    if (Object.hasOwn(original, field)) preserved[field] = original[field];
  }
  return preserved;
}

function objectProperties(node: JsonNode): Array<[string, JsonNode]> {
  return (node.children ?? []).map((property) => {
    const [key, value] = property.children ?? [];
    if (typeof key?.value !== "string" || !value) throw new Error(invalidOpenCodeConfiguration);
    return [key.value, value];
  });
}

function objectProperty(node: JsonNode, name: string): JsonNode | undefined {
  return objectProperties(node).find(([key]) => key === name)?.[1];
}

function isServerEntry(node: JsonNode): boolean {
  const type = node.type === "object" ? objectProperty(node, "type") : undefined;
  return type?.type === "string";
}

function nodeValue(node: JsonNode): unknown {
  if (node.type === "array") return (node.children ?? []).map(nodeValue);
  if (node.type !== "object") return node.value;
  const value: Record<string, unknown> = {};
  for (const [name, child] of objectProperties(node)) defineOwn(value, name, nodeValue(child));
  return value;
}
