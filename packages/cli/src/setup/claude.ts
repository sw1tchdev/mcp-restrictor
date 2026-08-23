import { dirname, resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
  defineClientAdapter,
  type ClientLoadContext,
  type ClientRestoreEntry,
} from "../client-adapter.js";
import {
  installClaudeConfig,
  installClaudeHttpConfig,
  parseClaudeConfig,
  renderClaudeConfig,
} from "./claude/json.js";
import { restoreJsonEntries } from "./restore/json-entry.js";
import type { FileSnapshot } from "./transaction.js";
import type { ParsedConfig } from "./wrapper.js";

const renderContexts = new WeakMap<
  ParsedConfig,
  {
    projectRoot: string;
    environment: NodeJS.ProcessEnv;
  }
>();

export { installClaudeConfig, installClaudeHttpConfig, parseClaudeConfig, renderClaudeConfig };

export function restoreClaudeConfig(
  config: ParsedConfig,
  entries: readonly ClientRestoreEntry[],
  context: ClientLoadContext,
): string {
  const current = parseClaudeConfig({
    path: config.path,
    scope: config.scope,
    source: config.source,
    projectRoot: context.projectRoot,
    environment: context.environment,
  });
  for (const entry of entries) {
    const original = parseClaudeConfig({
      path: config.path,
      scope: config.scope,
      source: entry.originalSource,
      projectRoot: context.projectRoot,
      environment: context.environment,
    });
    if (entry.installedSource !== undefined) continue;
    const currentCandidate = current.servers.find(({ name }) => name === entry.name);
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
  const restored = restoreJsonEntries(config.source, entries, (_source, name) => [
    "mcpServers",
    name,
  ]);
  parseClaudeConfig({
    path: config.path,
    scope: config.scope,
    source: restored,
    projectRoot: context.projectRoot,
    environment: context.environment,
  });
  return restored;
}

export function claudeConfigPaths(options: {
  home: string;
  projectRoot: string;
  environment: NodeJS.ProcessEnv;
}): { user: string; project: string } {
  const configDirectory = options.environment.CLAUDE_CONFIG_DIR || options.home;
  return { user: `${configDirectory}/.claude.json`, project: `${options.projectRoot}/.mcp.json` };
}

export const claudeAdapter = defineClientAdapter({
  apiVersion: 1,
  id: "claude",
  label: "Claude Code",
  async load(context, host) {
    const paths = claudeConfigPaths(context);
    const configurations = [];
    const snapshots: Array<{ scope: "user" | "project"; path: string; snapshot: FileSnapshot }> =
      [];
    for (const [scope, path] of [
      ["user", resolve(paths.user)],
      ["project", resolve(paths.project)],
    ] as const) {
      const snapshot = await host.readConfig(path);
      if (!snapshot) continue;
      snapshots.push({ scope, path, snapshot });
    }
    for (const { scope, path, snapshot } of snapshots) {
      const config = parseClaudeConfig({
        path,
        scope,
        source: snapshot.content,
        projectRoot: context.projectRoot,
        environment: context.environment,
      });
      renderContexts.set(config, {
        projectRoot: context.projectRoot,
        environment: context.environment,
      });
      configurations.push({
        config,
        snapshot,
      });
    }
    return { configurations, unsupported: [] };
  },
  projectWrapper(context) {
    return { policyArgument: `\${CLAUDE_PROJECT_DIR:-.}/${context.relativePolicyPath}` };
  },
  render(config, replacements) {
    const rendered = renderClaudeConfig(config, replacements);
    const context = renderContexts.get(config);
    parseClaudeConfig({
      path: config.path,
      scope: config.scope,
      source: rendered,
      projectRoot: context?.projectRoot ?? dirname(config.path),
      environment: context?.environment ?? process.env,
    });
    return rendered;
  },
  install: installClaudeConfig,
  installHttp: installClaudeHttpConfig,
  restore: restoreClaudeConfig,
  completionMessage: () => [
    "Restart Claude Code and approve the project .mcp.json change when prompted.",
  ],
});
