import { defineClientAdapter, type ClientAdapter } from "../client-adapter.js";
import { CLIENT_ADAPTER_LOAD_FAILURE } from "../client-plugins/constants.js";
import { claudeAdapter } from "./claude.js";
import { codexAdapter } from "./codex.js";
import { opencodeAdapter } from "./opencode.js";

type ExternalAdapter =
  | { packageName: string; adapter: ClientAdapter }
  | { packageName: string; error: unknown };

export function createAdapterRegistry(
  builtIns: readonly ClientAdapter[],
  externals: readonly ExternalAdapter[] = [],
) {
  const available = builtIns.map(defineClientAdapter);
  const builtInIds = new Set(available.map(({ id }) => id));
  const externalIds = new Set<string>();
  const unavailable: Array<{ packageName: string; reason: string }> = [];

  for (const external of externals) {
    if ("error" in external) {
      unavailable.push({
        packageName: external.packageName,
        reason: CLIENT_ADAPTER_LOAD_FAILURE,
      });
    } else {
      try {
        const adapter = defineClientAdapter(external.adapter);
        if (builtInIds.has(adapter.id)) {
          unavailable.push({
            packageName: external.packageName,
            reason: "client adapter ID conflicts with a built-in",
          });
        } else if (externalIds.has(adapter.id)) {
          unavailable.push({
            packageName: external.packageName,
            reason: "client adapter ID conflicts with another external",
          });
        } else {
          available.push(adapter);
          externalIds.add(adapter.id);
        }
      } catch {
        unavailable.push({
          packageName: external.packageName,
          reason: CLIENT_ADAPTER_LOAD_FAILURE,
        });
      }
    }
  }

  available.sort(
    (left, right) => left.label.localeCompare(right.label) || left.id.localeCompare(right.id),
  );
  return { available, unavailable };
}

export const builtInAdapters = createAdapterRegistry([
  claudeAdapter,
  codexAdapter,
  opencodeAdapter,
]).available;
