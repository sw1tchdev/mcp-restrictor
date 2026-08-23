import { lstat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import type { ClientAdapter, ClientLoadContext } from "../client-adapter.js";
import { RESTRICTOR_HOME_DIRECTORY } from "../utils/paths.js";
import { claudeAdapter, parseClaudeConfig } from "./claude.js";
import { codexAdapter, parseCodexConfig } from "./codex.js";
import { opencodeAdapter, parseOpenCodeConfig } from "./opencode.js";
import { openCodeEntryPath } from "./opencode/jsonc.js";
import {
  errorCode,
  readPrivateFileSnapshot,
  validatePrivateDirectory,
  type FileSnapshot,
} from "./transaction.js";
import { policyFileName, type ParsedConfig } from "./wrapper.js";

export type GeneratedPresetKind = "claude" | "codex" | "opencode-v2" | "opencode-v1";

export function generatedConfigPath(home: string, kind: GeneratedPresetKind): string {
  const root = generatedRoot(home);
  switch (kind) {
    case "claude":
      return join(root, "claude.json");
    case "codex":
      return join(root, "codex.toml");
    case "opencode-v2":
      return join(root, "opencode-v2.jsonc");
    case "opencode-v1":
      return join(root, "opencode-v1.jsonc");
    default:
      throw invalidGeneratedPath();
  }
}

export function isGeneratedConfigPath(home: string, adapterId: string, path: string): boolean {
  return generatedPresetKind(home, adapterId, path) !== undefined;
}

export function generatedPresetKind(
  home: string,
  adapterId: string,
  path: string,
): GeneratedPresetKind | undefined {
  try {
    if (path !== resolve(path)) return undefined;
    if (adapterId === "claude" && path === generatedConfigPath(home, "claude")) return "claude";
    if (adapterId === "codex" && path === generatedConfigPath(home, "codex")) return "codex";
    if (adapterId === "opencode") {
      if (path === generatedConfigPath(home, "opencode-v2")) return "opencode-v2";
      if (path === generatedConfigPath(home, "opencode-v1")) return "opencode-v1";
    }
  } catch {}
  return undefined;
}

export function generatedPolicyLocation(options: {
  home: string;
  adapterId: string;
  serverName: string;
}): { diskPath: string; argument: string; relativePath: string } {
  if (
    !["claude", "codex", "opencode"].includes(options.adapterId) ||
    !options.serverName ||
    options.serverName === "." ||
    options.serverName === ".." ||
    /[\u0000-\u001f\u007f/\\]/.test(options.serverName)
  ) {
    throw invalidGeneratedPath();
  }
  const relativePath = join(
    RESTRICTOR_HOME_DIRECTORY,
    "generated",
    "policies",
    options.adapterId,
    policyFileName(options.serverName),
  );
  const diskPath = join(resolveHome(options.home), relativePath);
  return { diskPath, argument: diskPath, relativePath };
}

export function generatedPresetKinds(adapter: ClientAdapter): readonly GeneratedPresetKind[] {
  if (adapter === claudeAdapter) return ["claude"];
  if (adapter === codexAdapter) return ["codex"];
  if (adapter === opencodeAdapter) return ["opencode-v2", "opencode-v1"];
  return [];
}

export function generatedPresetLabel(kind: GeneratedPresetKind): string {
  switch (kind) {
    case "claude":
      return "Claude Code";
    case "codex":
      return "Codex";
    case "opencode-v2":
      return "OpenCode V2";
    case "opencode-v1":
      return "OpenCode V1";
  }
}

export function generatedPresetConfig(options: {
  home: string;
  kind: GeneratedPresetKind;
  environment: NodeJS.ProcessEnv;
  source?: string;
}): ParsedConfig {
  const path = generatedConfigPath(options.home, options.kind);
  const source = options.source ?? generatedPresetBaseline(options.kind);
  switch (options.kind) {
    case "claude":
      return parseClaudeConfig({
        path,
        scope: "user",
        source,
        projectRoot: resolveHome(options.home),
        environment: options.environment,
      });
    case "codex":
      return parseCodexConfig({ path, scope: "user", source, environment: options.environment });
    case "opencode-v2":
    case "opencode-v1": {
      const v2 = openCodeEntryPath(source, "mcp-restrictor-generated-shape-probe").length === 3;
      if (v2 !== (options.kind === "opencode-v2")) throw invalidGeneratedPath();
      return parseOpenCodeConfig({
        path,
        scope: "user",
        source,
        projectRoot: resolveHome(options.home),
        environment: options.environment,
      });
    }
  }
}

export function generatedPresetBaseline(kind: GeneratedPresetKind): string {
  switch (kind) {
    case "claude":
    case "opencode-v1":
      return "{}\n";
    case "codex":
      return "";
    case "opencode-v2":
      return '{\n  "mcp": {\n    "servers": {}\n  }\n}\n';
  }
}

export async function readGeneratedFileSnapshot(path: string): Promise<FileSnapshot | undefined> {
  try {
    await lstat(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
  await validatePrivateDirectory(dirname(path), "Generated preset directory");
  return readPrivateFileSnapshot(path);
}

export async function loadGeneratedConfigurations(
  adapter: ClientAdapter,
  context: ClientLoadContext,
): Promise<Array<{ config: ParsedConfig; snapshot: FileSnapshot; kind: GeneratedPresetKind }>> {
  const loaded = [];
  for (const kind of generatedPresetKinds(adapter)) {
    const snapshot = await readGeneratedFileSnapshot(generatedConfigPath(context.home, kind));
    if (!snapshot) continue;
    loaded.push({
      config: generatedPresetConfig({
        home: context.home,
        kind,
        environment: context.environment,
        source: snapshot.content,
      }),
      snapshot,
      kind,
    });
  }
  return loaded;
}

function generatedRoot(home: string): string {
  return join(resolveHome(home), RESTRICTOR_HOME_DIRECTORY, "generated");
}

function resolveHome(home: string): string {
  if (!home || home.includes("\0")) throw invalidGeneratedPath();
  return resolve(home);
}

function invalidGeneratedPath(): Error {
  return new Error("Invalid generated preset path");
}
