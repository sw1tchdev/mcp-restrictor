import { resolve } from "node:path";
import { defineClientAdapter } from "../client-adapter.js";
import {
  installCodexConfig,
  installCodexHttpConfig,
  parseCodexConfig,
  renderCodexConfig,
  restoreCodexConfig,
} from "./codex/toml.js";
import type { FileSnapshot } from "./transaction.js";
import type { ParsedConfig } from "./wrapper.js";

const renderContexts = new WeakMap<ParsedConfig, NodeJS.ProcessEnv>();

export {
  installCodexConfig,
  installCodexHttpConfig,
  parseCodexConfig,
  renderCodexConfig,
  restoreCodexConfig,
};

export function codexConfigPaths(options: {
  home: string;
  projectRoot: string;
  environment: NodeJS.ProcessEnv;
}): { user: string; project: string } {
  const codexHome = options.environment.CODEX_HOME || `${options.home}/.codex`;
  return {
    user: `${codexHome}/config.toml`,
    project: `${options.projectRoot}/.codex/config.toml`,
  };
}

export const codexAdapter = defineClientAdapter({
  apiVersion: 1,
  id: "codex",
  label: "Codex",
  async load(context, host) {
    const paths = codexConfigPaths(context);
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
      const config = parseCodexConfig({
        path,
        scope,
        source: snapshot.content,
        environment: context.environment,
      });
      renderContexts.set(config, context.environment);
      configurations.push({
        config,
        snapshot,
      });
    }
    return { configurations, unsupported: [] };
  },
  projectWrapper(context) {
    return { policyArgument: context.relativePolicyPath, cwd: context.projectRoot };
  },
  render(config, replacements) {
    const rendered = renderCodexConfig(config, replacements);
    parseCodexConfig({
      path: config.path,
      scope: config.scope,
      source: rendered,
      environment: renderContexts.get(config) ?? process.env,
    });
    return rendered;
  },
  install: installCodexConfig,
  installHttp: installCodexHttpConfig,
  restore: restoreCodexConfig,
  completionMessage: () => ["Restart Codex in a trusted project."],
});
