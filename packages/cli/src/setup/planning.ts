import { resolve } from "node:path";
import { isDeepStrictEqual } from "node:util";
import {
  oauthProfilePath,
  prepareOAuthProfileWrite,
  readOAuthProfileSnapshot,
  type OAuthProfile,
  type OAuthStorageOptions,
} from "../oauth/storage.js";
import type { LoadedConfig } from "./adapter-boundary.js";
import { CLIENT_CONFIGURATION_TARGET, readSetupSnapshot } from "./snapshot.js";
import { sameFileSnapshot, type FileSnapshot, type PlannedWrite } from "./transaction.js";
import type { Replacement, ServerCandidate } from "./wrapper.js";

export type PlannedSelection = {
  server: ServerCandidate;
  policy: { diskPath: string };
  replacement: Replacement;
  policySource: string;
  policyBaseline: FileSnapshot | null;
  unownedPolicyBaseline?: FileSnapshot;
  backupKey: string;
};

export type ProfileSelection = {
  oauthProfile?: OAuthProfile;
  oauthBaseline?: Awaited<ReturnType<typeof readOAuthProfileSnapshot>>;
  storage?: OAuthStorageOptions;
  backupKey: string;
};

export async function planWrites(
  loaded: readonly LoadedConfig[],
  selections: readonly PlannedSelection[],
): Promise<PlannedWrite[]> {
  const loadedByPath = new Map<string, LoadedConfig[]>();
  for (const entry of loaded) {
    const path = resolve(entry.config.path);
    loadedByPath.set(path, [...(loadedByPath.get(path) ?? []), entry]);
  }
  const replacements = new Map<string, Map<string, Replacement>>();
  for (const selection of selections) {
    const path = resolve(selection.server.configPath);
    const byName = replacements.get(path) ?? new Map<string, Replacement>();
    byName.set(selection.server.name, selection.replacement);
    replacements.set(path, byName);
  }

  const currentConfigs = new Map<string, FileSnapshot>();
  for (const path of replacements.keys()) {
    const entries = loadedByPath.get(path) ?? [];
    const entry = entries.length === 1 ? entries[0] : undefined;
    const current = await readSetupSnapshot(path, CLIENT_CONFIGURATION_TARGET);
    if (!entry || !current || current.content !== entry.config.source) {
      throw new Error("Client configuration changed during setup; rerun setup");
    }
    currentConfigs.set(path, current);
  }

  const writes: PlannedWrite[] = [];
  const policyPaths = new Set<string>();
  for (const selection of selections) {
    const path = resolve(selection.policy.diskPath);
    if (policyPaths.has(path)) throw new Error("Duplicate policy target");
    policyPaths.add(path);
    const before = await readSetupSnapshot(path, "policy");
    if (selection.unownedPolicyBaseline) {
      if (!before || !sameFileSnapshot(before, selection.unownedPolicyBaseline)) {
        throw new Error("Existing policy changed during setup; rerun setup");
      }
    } else if (selection.policyBaseline) {
      if (!before || !sameFileSnapshot(before, selection.policyBaseline)) {
        throw new Error("Managed policy changed during setup; rerun setup");
      }
    } else if (before) {
      if (
        selection.server.managedPolicyPath &&
        resolve(selection.server.managedPolicyPath) === path
      ) {
        throw new Error("Managed policy changed during setup; rerun setup");
      }
      throw new Error("policy path is not owned by setup");
    }
    writes.push({
      path,
      ...(before ? { before } : {}),
      content: selection.policySource,
      mode: before?.mode ?? 0o600,
      backupKey: resolve(selection.backupKey),
    });
  }

  for (const [path, byName] of replacements) {
    const entries = loadedByPath.get(path) ?? [];
    if (entries.length !== 1) throw new Error("Invalid client configuration selected");
    const entry = entries[0]!;
    const before = currentConfigs.get(path)!;
    let content: string;
    try {
      content = entry.adapter.render(entry.config, byName);
    } catch {
      throw new Error("Failed to render client configuration");
    }
    if (typeof content !== "string" || resolve(entry.config.path) !== path) {
      throw new Error("Invalid client configuration returned by adapter");
    }
    writes.push({
      path,
      before,
      content,
      mode: before.mode,
      backupKey: path,
    });
  }
  return writes;
}

export async function planProfileWrites(
  selections: readonly ProfileSelection[],
): Promise<PlannedWrite[]> {
  const writes = new Map<string, PlannedWrite>();
  const plannedProfiles = new Map<
    string,
    {
      profile: OAuthProfile;
      storage: OAuthStorageOptions;
      before?: FileSnapshot;
      backupKey: string;
      unchanged: boolean;
    }
  >();
  for (const selection of selections) {
    if (!selection.oauthProfile || !selection.storage) continue;
    const path = resolve(
      oauthProfilePath(selection.storage.home!, selection.oauthProfile.metadata.profileId),
    );
    const current = plannedProfiles.get(path);
    const planned = {
      profile: selection.oauthProfile,
      storage: selection.storage,
      ...(selection.oauthBaseline ? { before: selection.oauthBaseline.snapshot } : {}),
      backupKey: resolve(selection.backupKey),
      unchanged:
        selection.oauthBaseline !== undefined &&
        sameProfile(selection.oauthProfile, selection.oauthBaseline.profile),
    };
    if (current) {
      if (
        !sameProfile(current.profile, planned.profile) ||
        !isDeepStrictEqual(current.storage, planned.storage) ||
        !isDeepStrictEqual(current.before, planned.before) ||
        current.unchanged !== planned.unchanged
      )
        throw new Error("Conflicting OAuth profile plan");
      continue;
    }
    plannedProfiles.set(path, planned);
  }
  for (const [path, planned] of plannedProfiles) {
    if (planned.before && planned.unchanged) {
      writes.set(path, {
        path,
        before: planned.before,
        content: planned.before.content,
        mode: 0o600,
        backupKey: planned.backupKey,
        private: true,
      });
      continue;
    }
    const prepared = await prepareOAuthProfileWrite(planned.profile, planned.storage);
    writes.set(path, {
      path: prepared.path,
      ...(planned.before ? { before: planned.before } : {}),
      content: prepared.content,
      mode: prepared.mode,
      backupKey: planned.backupKey,
      private: true,
    });
  }
  return [...writes.values()];
}

function sameProfile(left: OAuthProfile, right: OAuthProfile): boolean {
  return isDeepStrictEqual(left, right);
}
