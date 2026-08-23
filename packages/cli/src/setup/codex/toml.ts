import { parse, stringify } from "smol-toml";
import { isDeepStrictEqual } from "node:util";
import type {
  ClientHttpInstallEntry,
  ClientInstallEntry,
  ClientLoadContext,
  ClientRestoreEntry,
} from "../../client-adapter.js";
import {
  type ParsedConfig,
  type Replacement,
  type Scope,
  type UnsupportedServer,
} from "../wrapper.js";
import { parseCodexServer, preservedCodexClientFields } from "./candidate.js";
import { defineOwn, isRecord } from "../../utils/values.js";

type Range = { start: number; end: number };
type Ownership = Map<string, Range[]>;
type LexMode = "normal" | "basic" | "literal" | "multibasic" | "multiliteral";

export function parseCodexConfig(options: {
  path: string;
  scope: Scope;
  source: string;
  environment: NodeJS.ProcessEnv;
}): ParsedConfig {
  const root = parseRoot(options.source);
  const ownership = scanOwnership(options.source);
  const mcpServers = root.mcp_servers;
  if (mcpServers === undefined) {
    if (ownership.size) throw ownershipError();
    return emptyConfig(options);
  }
  if (!isRecord(mcpServers)) throw ownershipError();

  const names = Object.keys(mcpServers);
  if (names.length !== ownership.size || names.some((name) => !ownership.has(name))) {
    throw ownershipError();
  }

  const config = emptyConfig(options);
  const callback = {
    port: root.mcp_oauth_callback_port,
    baseUrl: root.mcp_oauth_callback_url,
  };
  for (const [name, entry] of Object.entries(mcpServers)) {
    const result = parseCodexServer({ ...options, name, entry, callback });
    if ("reason" in result) config.unsupported.push(unsupported(options, name, result.reason));
    else config.servers.push(result);
  }
  return config;
}

export function renderCodexConfig(
  config: ParsedConfig,
  replacements: ReadonlyMap<string, Replacement>,
): string {
  const root = parseRoot(config.source);
  const ownership = scanOwnership(config.source);
  const mcpServers = root.mcp_servers;
  if (!isRecord(mcpServers)) throw ownershipError();
  if (
    Object.keys(mcpServers).length !== ownership.size ||
    Object.keys(mcpServers).some((name) => !ownership.has(name))
  ) {
    throw ownershipError();
  }

  const candidates = new Map(config.servers.map((server) => [server.name, server]));
  const edits: Array<Range & { text: string }> = [];
  for (const [name, replacement] of replacements) {
    const candidate = candidates.get(name);
    const ranges = ownership.get(name);
    if (!candidate || !ranges?.length)
      throw new Error("Codex replacement does not match a supported server");
    const entry: Record<string, unknown> = {
      command: replacement.command,
      args: replacement.args,
      ...(replacement.envVars !== undefined ? { env_vars: replacement.envVars } : {}),
      ...(replacement.cwd !== undefined ? { cwd: replacement.cwd } : {}),
      ...preservedCodexClientFields(candidate.original),
      ...(replacement.env !== undefined ? { env: replacement.env } : {}),
    };
    const text = stringify({ mcp_servers: { [name]: entry } });
    edits.push({ ...ranges[0]!, text });
    for (const range of ranges.slice(1)) edits.push({ ...range, text: "" });
  }

  let rendered = config.source;
  for (const edit of edits.sort((left, right) => right.start - left.start)) {
    rendered = `${rendered.slice(0, edit.start)}${edit.text}${rendered.slice(edit.end)}`;
  }
  parseRoot(rendered);
  return rendered;
}

export function installCodexConfig(config: ParsedConfig, entry: ClientInstallEntry): string {
  const root = parseRoot(config.source);
  const ownership = scanOwnership(config.source);
  const mcpServers = root.mcp_servers;
  if (mcpServers === undefined) {
    if (ownership.size) throw ownershipError();
  } else if (
    !isRecord(mcpServers) ||
    Object.keys(mcpServers).length !== ownership.size ||
    Object.keys(mcpServers).some((name) => !ownership.has(name))
  ) {
    throw ownershipError();
  }
  if (isRecord(mcpServers) && Object.hasOwn(mcpServers, entry.name)) {
    throw new Error("Codex server name already exists");
  }

  const environment: Record<string, string> = {};
  const fixed: Record<string, string> = {};
  for (const name of entry.environment.inherit) defineOwn(environment, name, "inherited");
  for (const [name, value] of Object.entries(entry.environment.set)) {
    defineOwn(fixed, name, value);
    defineOwn(environment, name, value);
  }
  const server: Record<string, unknown> = {};
  defineOwn(server, "command", entry.command);
  defineOwn(server, "args", [...entry.args]);
  if (entry.environment.inherit.length)
    defineOwn(server, "env_vars", [...entry.environment.inherit]);
  if (entry.cwd !== undefined) defineOwn(server, "cwd", entry.cwd);
  if (Object.keys(fixed).length) defineOwn(server, "env", fixed);

  const servers: Record<string, unknown> = {};
  defineOwn(servers, entry.name, server);
  const appended = stringify({ mcp_servers: servers });
  const source = `${config.source}${config.source ? (config.source.endsWith("\n") ? "\n" : "\n\n") : ""}${appended}`;
  const candidate = parseCodexConfig({
    path: config.path,
    scope: config.scope,
    source,
    environment,
  }).servers.find(({ name }) => name === entry.name);
  if (!candidate?.managedPolicyPath) throw new Error("Codex installation is not a managed wrapper");
  return source;
}

export function installCodexHttpConfig(
  config: ParsedConfig,
  entry: ClientHttpInstallEntry,
): string {
  const root = parseRoot(config.source);
  const ownership = scanOwnership(config.source);
  const mcpServers = root.mcp_servers;
  if (mcpServers === undefined) {
    if (ownership.size) throw ownershipError();
  } else if (
    !isRecord(mcpServers) ||
    Object.keys(mcpServers).length !== ownership.size ||
    Object.keys(mcpServers).some((name) => !ownership.has(name))
  ) {
    throw ownershipError();
  }
  if (isRecord(mcpServers) && Object.hasOwn(mcpServers, entry.name)) {
    throw new Error("Codex server name already exists");
  }

  const server: Record<string, unknown> = {};
  defineOwn(server, "url", entry.url);
  const servers: Record<string, unknown> = {};
  defineOwn(servers, entry.name, server);
  const appended = stringify({ mcp_servers: servers });
  const source = `${config.source}${config.source && !config.source.endsWith("\n") ? "\n" : ""}${appended}`;
  const candidates = parseCodexConfig({
    path: config.path,
    scope: config.scope,
    source,
    environment: {},
  }).servers.filter(({ name }) => name === entry.name);
  if (
    candidates.length !== 1 ||
    !isDeepStrictEqual(candidates[0]!.source, { kind: "http", url: entry.url, headers: [] }) ||
    candidates[0]!.managedPolicyPath !== undefined
  ) {
    throw new Error("Codex HTTP installation is invalid");
  }
  return source;
}

export function restoreCodexConfig(
  config: ParsedConfig,
  entries: readonly ClientRestoreEntry[],
  context: ClientLoadContext,
): string {
  const current = parseCodexConfig({
    path: config.path,
    scope: config.scope,
    source: config.source,
    environment: context.environment,
  });
  const root = parseRoot(config.source);
  const ownership = scanOwnership(config.source);
  const edits: Array<Range & { text: string }> = [];
  for (const entry of entries) {
    const currentEntry = codexEntry(root, entry.name);
    const currentRanges = ownership.get(entry.name);
    const originalRanges = scanOwnership(entry.originalSource).get(entry.name);
    if (!currentRanges?.length) throw ownershipError();
    if (entry.installedSource !== undefined) {
      const installedEntry = codexEntry(parseRoot(entry.installedSource), entry.name);
      if (!isDeepStrictEqual(currentEntry, installedEntry)) {
        throw new Error("Restore entry changed");
      }
    } else {
      const currentCandidate = current.servers.find(({ name }) => name === entry.name);
      const original = parseCodexConfig({
        path: config.path,
        scope: config.scope,
        source: entry.originalSource,
        environment: context.environment,
      });
      const originalCandidate = original.servers.find(({ name }) => name === entry.name);
      if (
        !currentCandidate?.managedPolicyPath ||
        !originalCandidate ||
        originalCandidate.managedPolicyPath ||
        !isDeepStrictEqual(currentCandidate.source, originalCandidate.source)
      ) {
        throw new Error("Restore entry does not match managed server");
      }
    }
    if (originalRanges?.length) {
      edits.push({
        ...currentRanges[0]!,
        text: originalRanges
          .map(({ start, end }) => entry.originalSource.slice(start, end))
          .join(""),
      });
      for (const range of currentRanges.slice(1)) edits.push({ ...range, text: "" });
    } else {
      if (entry.created !== true || entry.installedSource === undefined) throw ownershipError();
      const original = parseCodexConfig({
        path: config.path,
        scope: config.scope,
        source: entry.originalSource,
        environment: context.environment,
      });
      if (
        original.servers.some(({ name }) => name === entry.name) ||
        original.unsupported.some(({ name }) => name === entry.name)
      ) {
        throw ownershipError();
      }
      const installedRanges = scanOwnership(entry.installedSource).get(entry.name);
      const installedStart = installedRanges?.[0]?.start;
      const installedPrefix =
        installedStart === undefined ? "" : entry.installedSource.slice(0, installedStart);
      const separator = installedPrefix.startsWith(entry.originalSource)
        ? installedPrefix.slice(entry.originalSource.length)
        : "";
      const first = currentRanges[0]!;
      const installedLast = installedRanges?.at(-1);
      const currentLast = currentRanges.at(-1)!;
      const installedWhitespace = installedLast
        ? /\s*$/.exec(entry.installedSource.slice(installedLast.start, installedLast.end))![0]
        : undefined;
      const currentWhitespace = /\s*$/.exec(
        config.source.slice(currentLast.start, currentLast.end),
      )![0];
      const start =
        /^\n+$/.test(separator) &&
        config.source.slice(0, first.start) === installedPrefix &&
        installedLast?.end === entry.installedSource.length &&
        currentLast.end === config.source.length &&
        currentWhitespace === installedWhitespace &&
        config.source.slice(first.start - separator.length, first.start) === separator
          ? first.start - separator.length
          : first.start;
      edits.push({ ...first, start, text: "" });
      for (const range of currentRanges.slice(1)) edits.push({ ...range, text: "" });
    }
  }
  let restored = config.source;
  for (const edit of edits.sort((left, right) => right.start - left.start)) {
    restored = `${restored.slice(0, edit.start)}${edit.text}${restored.slice(edit.end)}`;
  }
  parseCodexConfig({
    path: config.path,
    scope: config.scope,
    source: restored,
    environment: context.environment,
  });
  return restored;
}

export function scanOwnership(source: string): Ownership {
  const headers: Array<{ start: number; path: string[]; array: boolean }> = [];
  let mode: LexMode = "normal";
  let currentTable: string[] = [];
  for (let start = 0; start < source.length;) {
    const newline = source.indexOf("\n", start);
    const end = newline === -1 ? source.length : newline + 1;
    const line = source.slice(start, end);
    if (mode === "normal") {
      const table = tableHeader(line);
      if (table) {
        if (table.array && table.path[0] === "mcp_servers") throw ownershipError();
        headers.push({ start, ...table });
        currentTable = table.path;
      } else {
        const assignment = assignmentKey(line);
        if (
          (currentTable.length === 0 && assignment?.[0] === "mcp_servers") ||
          (currentTable.length === 1 && currentTable[0] === "mcp_servers" && assignment)
        ) {
          throw ownershipError();
        }
      }
    }
    mode = nextLexMode(line, mode);
    start = end;
  }
  if (mode !== "normal") throw new Error("Invalid Codex TOML");

  const ownership: Ownership = new Map();
  const directTables = new Map<string, number>();
  for (let index = 0; index < headers.length; index += 1) {
    const header = headers[index]!;
    if (header.path[0] !== "mcp_servers" || header.path.length < 2) continue;
    const name = header.path[1]!;
    const ranges = ownership.get(name) ?? [];
    ranges.push({ start: header.start, end: headers[index + 1]?.start ?? source.length });
    ownership.set(name, ranges);
    if (header.path.length === 2) directTables.set(name, (directTables.get(name) ?? 0) + 1);
  }
  for (const name of ownership.keys()) {
    if (directTables.get(name) !== 1) throw ownershipError();
  }
  return ownership;
}

function codexEntry(root: Record<string, unknown>, name: string): Record<string, unknown> {
  if (!isRecord(root.mcp_servers) || !isRecord(root.mcp_servers[name])) throw ownershipError();
  return root.mcp_servers[name];
}

function nextLexMode(line: string, initial: LexMode): LexMode {
  let mode = initial;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index]!;
    if (mode === "normal") {
      if (character === "#") break;
      if (line.startsWith('"""', index)) {
        mode = "multibasic";
        index += 2;
      } else if (line.startsWith("'''", index)) {
        mode = "multiliteral";
        index += 2;
      } else if (character === '"') mode = "basic";
      else if (character === "'") mode = "literal";
    } else if (mode === "basic") {
      if (character === "\\") index += 1;
      else if (character === '"') mode = "normal";
    } else if (mode === "literal") {
      if (character === "'") mode = "normal";
    } else if (mode === "multibasic") {
      if (character === "\\") index += 1;
      else if (line.startsWith('"""', index)) {
        while (line[index + 3] === '"') index += 1;
        mode = "normal";
        index += 2;
      }
    } else if (line.startsWith("'''", index)) {
      while (line[index + 3] === "'") index += 1;
      mode = "normal";
      index += 2;
    }
  }
  return mode;
}

function tableHeader(line: string): { path: string[]; array: boolean } | undefined {
  const trimmed = line.trimStart();
  if (!trimmed.startsWith("[")) return undefined;
  const array = trimmed.startsWith("[[");
  const opening = array ? 2 : 1;
  const closing = array ? "]]" : "]";
  let quote: "basic" | "literal" | undefined;
  let escaped = false;
  for (let index = opening; index < trimmed.length; index += 1) {
    const character = trimmed[index]!;
    if (quote === "basic") {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') quote = undefined;
      continue;
    }
    if (quote === "literal") {
      if (character === "'") quote = undefined;
      continue;
    }
    if (character === '"') quote = "basic";
    else if (character === "'") quote = "literal";
    else if (trimmed.startsWith(closing, index)) {
      const rest = trimmed.slice(index + closing.length).trim();
      if (rest && !rest.startsWith("#")) return undefined;
      const path = dottedKey(trimmed.slice(opening, index));
      return path ? { path, array } : undefined;
    }
  }
  return undefined;
}

function assignmentKey(line: string): string[] | undefined {
  let quote: "basic" | "literal" | undefined;
  let escaped = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index]!;
    if (!quote && character === "#") return undefined;
    if (quote === "basic") {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') quote = undefined;
    } else if (quote === "literal") {
      if (character === "'") quote = undefined;
    } else if (character === '"') quote = "basic";
    else if (character === "'") quote = "literal";
    else if (character === "=") return dottedKey(line.slice(0, index));
  }
  return undefined;
}

function dottedKey(source: string): string[] | undefined {
  const segments: string[] = [];
  let index = 0;
  while (index < source.length) {
    while (/\s/.test(source[index] ?? "")) index += 1;
    const character = source[index];
    let segment: string;
    if (character === '"') {
      let end = index + 1;
      let escaped = false;
      for (; end < source.length; end += 1) {
        const current = source[end]!;
        if (escaped) escaped = false;
        else if (current === "\\") escaped = true;
        else if (current === '"') break;
      }
      if (end === source.length) return undefined;
      const decoded = decodeQuotedKey(source.slice(index, end + 1));
      if (decoded === undefined) return undefined;
      segment = decoded;
      index = end + 1;
    } else if (character === "'") {
      const end = source.indexOf("'", index + 1);
      if (end === -1) return undefined;
      const decoded = decodeQuotedKey(source.slice(index, end + 1));
      if (decoded === undefined) return undefined;
      segment = decoded;
      index = end + 1;
    } else {
      const match = /^[A-Za-z0-9_-]+/.exec(source.slice(index));
      if (!match) return undefined;
      segment = match[0];
      index += segment.length;
    }
    segments.push(segment);
    while (/\s/.test(source[index] ?? "")) index += 1;
    if (index === source.length) return segments;
    if (source[index] !== ".") return undefined;
    index += 1;
  }
  return undefined;
}

function parseRoot(source: string): Record<string, unknown> {
  let root: unknown;
  try {
    root = parse(source);
  } catch {
    throw new Error("Invalid Codex TOML");
  }
  if (!isRecord(root)) throw new Error("Codex configuration root must be a table");
  return root;
}

function emptyConfig(
  options: Pick<Parameters<typeof parseCodexConfig>[0], "path" | "scope" | "source">,
): ParsedConfig {
  return {
    client: "codex",
    scope: options.scope,
    path: options.path,
    source: options.source,
    servers: [],
    unsupported: [],
  };
}

function unsupported(
  options: Pick<Parameters<typeof parseCodexConfig>[0], "path" | "scope">,
  name: string,
  reason: string,
): UnsupportedServer {
  return { client: "codex", scope: options.scope, name, configPath: options.path, reason };
}

function decodeQuotedKey(fragment: string): string | undefined {
  try {
    const decoded = parse(`${fragment} = true`);
    return Object.keys(decoded)[0];
  } catch {
    return undefined;
  }
}

function ownershipError(): Error {
  return new Error("Codex mcp_servers ownership cannot be determined");
}
