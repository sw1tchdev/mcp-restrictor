import { isDeepStrictEqual } from "node:util";
import {
  defineClientAdapter,
  type ClientLoadContext,
  type ClientRestoreEntry,
} from "../client-adapter.js";
import { resolveOpenCodeCandidate } from "./opencode/candidate.js";
import {
  installOpenCodeConfig,
  installOpenCodeHttpConfig,
  openCodeEntryPath,
  parseOpenCodeConfig,
  renderOpenCodeConfig,
} from "./opencode/jsonc.js";
import { loadOpenCodeConfigurations } from "./opencode/locations.js";
import { restoreJsonEntries } from "./restore/json-entry.js";
import type { ParsedConfig } from "./wrapper.js";

export {
  installOpenCodeConfig,
  installOpenCodeHttpConfig,
  parseOpenCodeConfig,
  renderOpenCodeConfig,
};

export function restoreOpenCodeConfig(
  config: ParsedConfig,
  entries: readonly ClientRestoreEntry[],
  context: ClientLoadContext,
): string {
  const current = parseOpenCodeConfig({
    ...config,
    projectRoot: context.projectRoot,
    environment: context.environment,
  });
  for (const entry of entries) {
    if (entry.installedSource !== undefined) continue;
    const currentCandidate = current.servers.find(({ name }) => name === entry.name);
    const original = parseOpenCodeConfig({
      path: config.path,
      scope: config.scope,
      source: entry.originalSource,
      projectRoot: context.projectRoot,
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
  const restored = restoreJsonEntries(config.source, entries, openCodeEntryPath);
  parseOpenCodeConfig({
    ...config,
    source: restored,
    projectRoot: context.projectRoot,
    environment: context.environment,
  });
  return restored;
}

export const opencodeAdapter = defineClientAdapter({
  apiVersion: 1,
  id: "opencode",
  label: "OpenCode",
  load: loadOpenCodeConfigurations,
  resolve: resolveOpenCodeCandidate,
  projectWrapper(context) {
    return { policyArgument: context.relativePolicyPath, cwd: context.projectRoot };
  },
  render: renderOpenCodeConfig,
  install: installOpenCodeConfig,
  installHttp: installOpenCodeHttpConfig,
  restore: restoreOpenCodeConfig,
});
