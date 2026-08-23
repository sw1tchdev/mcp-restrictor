import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { parsePolicy, type Policy } from "@mcp-restrictor/policy";
import type { SetupInteraction } from "./interaction.js";
import { readSetupSnapshot } from "./snapshot.js";
import { RESTRICTOR_HOME_DIRECTORY } from "../utils/paths.js";
import {
  readPrivateFileSnapshot,
  readSnapshot,
  sameFileSnapshot,
  validatePrivateDirectory,
  type FileSnapshot,
  type PlannedWrite,
} from "./transaction.js";

const SAVED_POLICY_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export type SavedPolicyContext = {
  client: string;
  scope: "user" | "project";
  serverName: string;
  projectRoot: string;
  restrictorHome: string;
};

export type PolicySourceChoice =
  | { kind: "current" }
  | {
      kind: "policy";
      source: string;
      policy: Policy;
      saved?: FileSnapshot;
      existing?: FileSnapshot;
    }
  | { kind: "configure" };

export function savedPolicyDirectory(context: SavedPolicyContext): string {
  const root =
    context.scope === "project"
      ? join(context.projectRoot, RESTRICTOR_HOME_DIRECTORY)
      : context.restrictorHome;
  return join(
    root,
    "saved-policies",
    context.client,
    `${encodeURIComponent(context.serverName)}.d`,
  );
}

export async function listSavedPolicyNames(context: SavedPolicyContext): Promise<string[]> {
  const directory = savedPolicyDirectory(context);
  try {
    await validatePrivateDirectory(directory, "Saved policy directory");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  const entries = await readdir(directory, { withFileTypes: true });
  return entries
    .filter(
      (entry) =>
        entry.isFile() &&
        entry.name.endsWith(".yaml") &&
        SAVED_POLICY_NAME.test(entry.name.slice(0, -5)),
    )
    .map((entry) => entry.name.slice(0, -5))
    .sort();
}

export async function choosePolicySource(options: {
  interaction: SetupInteraction;
  context: SavedPolicyContext;
  hasCurrent: boolean;
  existingPolicy?: FileSnapshot;
}): Promise<PolicySourceChoice> {
  const savedNames = await listSavedPolicyNames(options.context);
  const choices = [
    ...(options.hasCurrent ? ["Current"] : []),
    ...(options.existingPolicy ? ["Existing policy"] : []),
    ...savedNames,
    "Configure new",
  ];
  if (!options.interaction.usesTui) {
    choices.forEach((choice, index) => options.interaction.write(`${index + 1}. ${choice}\n`));
  }
  const [selected] = await options.interaction.selectIndexes("Select Tools & Policy: ", choices, {
    allowNone: false,
    single: true,
  });
  if (selected === undefined) throw new Error("Invalid Tools & Policy selection");
  const currentOffset = options.hasCurrent ? 1 : 0;
  if (options.hasCurrent && selected === 0) return { kind: "current" };
  if (options.existingPolicy && selected === currentOffset) {
    return {
      ...parseSelectedPolicy(options.existingPolicy.content),
      existing: options.existingPolicy,
    };
  }
  const savedOffset = currentOffset + (options.existingPolicy ? 1 : 0);
  const savedName = savedNames[selected - savedOffset];
  if (savedName !== undefined) {
    const snapshot = await readPrivateFileSnapshot(
      join(savedPolicyDirectory(options.context), `${savedName}.yaml`),
    );
    return {
      ...parseSelectedPolicy(snapshot.content),
      saved: snapshot,
    };
  }
  return { kind: "configure" };
}

export async function planOptionalSavedPolicy(options: {
  interaction: SetupInteraction;
  context: SavedPolicyContext;
  policySource: string;
  backupKey: string;
}): Promise<PlannedWrite | undefined> {
  const choices = ["No", "Yes"] as const;
  if (!options.interaction.usesTui) {
    choices.forEach((choice, index) => options.interaction.write(`${index + 1}. ${choice}\n`));
  }
  const [selected] = await options.interaction.selectIndexes("Save Tools & Policy? ", choices, {
    allowNone: false,
    single: true,
  });
  if (selected !== 1) return undefined;
  try {
    parsePolicy(options.policySource);
  } catch {
    throw new Error("Saved Tools & Policy is invalid");
  }

  const directory = savedPolicyDirectory(options.context);
  try {
    await validatePrivateDirectory(directory, "Saved policy directory");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  for (;;) {
    const name = await options.interaction.ask("Saved configuration name: ");
    if (!SAVED_POLICY_NAME.test(name)) {
      options.interaction.write("Invalid saved configuration name.\n");
      continue;
    }
    const path = join(directory, `${name}.yaml`);
    if (await readSnapshot(path)) {
      options.interaction.write("Saved configuration already exists.\n");
      continue;
    }
    return {
      path,
      content: options.policySource,
      mode: 0o600,
      backupKey: options.backupKey,
      private: true,
    };
  }
}

export async function recheckPolicySource(choice: PolicySourceChoice): Promise<void> {
  if (choice.kind !== "policy") return;
  if (choice.saved) {
    try {
      const current = await readPrivateFileSnapshot(choice.saved.path);
      if (sameFileSnapshot(current, choice.saved)) return;
    } catch {
      // Report every read, privacy, and replacement failure as setup drift.
    }
    throw new Error("Saved Tools & Policy changed during setup");
  }
  if (!choice.existing) return;
  try {
    const current = await readSetupSnapshot(choice.existing.path, "policy");
    if (current && sameFileSnapshot(current, choice.existing)) return;
  } catch {
    // Report every read, replacement, and policy-path failure as setup drift.
  }
  throw new Error("Existing policy changed during setup; rerun setup");
}

function parseSelectedPolicy(source: string): Extract<PolicySourceChoice, { kind: "policy" }> {
  try {
    return { kind: "policy", source, policy: parsePolicy(source) };
  } catch {
    throw new Error("Saved Tools & Policy is invalid");
  }
}
