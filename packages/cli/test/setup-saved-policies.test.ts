import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, expect, test } from "vitest";
import {
  choosePolicySource,
  listSavedPolicyNames,
  planOptionalSavedPolicy,
  recheckPolicySource,
  savedPolicyDirectory,
  type SavedPolicyContext,
} from "../src/setup/saved-policies.ts";
import type { SetupInteraction } from "../src/setup/interaction.ts";
import { readSetupSnapshot } from "../src/setup/snapshot.ts";
import { RESTRICTOR_HOME_DIRECTORY } from "../src/utils/paths.ts";

const temporaryDirectories: string[] = [];
const validPolicy = `version: 1
default: deny
tools:
  allow:
    - name: read_file
  deny: []
`;
const replacementPolicy = `version: 1
default: allow
tools:
  allow: []
  deny: []
`;

const root = "/project";
const home = "/home/test";
const projectContext: SavedPolicyContext = {
  client: "codex",
  scope: "project",
  serverName: "files",
  projectRoot: root,
  restrictorHome: home,
};
const userContext: SavedPolicyContext = {
  ...projectContext,
  scope: "user",
  restrictorHome: join(home, RESTRICTOR_HOME_DIRECTORY),
};

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { force: true, recursive: true })),
  );
});

test("scopes saved policies by client, scope, and server", () => {
  expect(savedPolicyDirectory(projectContext)).toBe(
    join(root, ".mcp-restrictor/saved-policies/codex/files.d"),
  );
  expect(savedPolicyDirectory(userContext)).toBe(
    join(home, ".mcp-restrictor/saved-policies/codex/files.d"),
  );
});

test("sorts portable saved policy names", async () => {
  const saved = await privateSavedPolicyDirectory(projectContext);
  await writeFile(join(saved.directory, "zeta.yaml"), validPolicy, { mode: 0o600 });
  await writeFile(join(saved.directory, "alpha.yaml"), validPolicy, { mode: 0o600 });
  await mkdir(join(saved.directory, "directory.yaml"));
  await writeFile(join(saved.directory, "Invalid.yaml"), validPolicy, { mode: 0o600 });
  await writeFile(join(saved.directory, "notes.txt"), validPolicy, { mode: 0o600 });
  await expect(listSavedPolicyNames(saved.context)).resolves.toEqual(["alpha", "zeta"]);
});

test("chooses Current without reading a saved policy", async () => {
  const choice = await choosePolicySource({
    interaction: interaction(["1\n"]),
    context: projectContext,
    hasCurrent: true,
  });
  expect(choice).toEqual({ kind: "current" });
});

test("rejects an invalid selected saved policy before caller discovery", async () => {
  const saved = await privateSavedPolicyDirectory(projectContext);
  await writeFile(join(saved.directory, "broken.yaml"), "not: [valid", { mode: 0o600 });
  await expect(
    choosePolicySource({
      interaction: interaction(["1\n"]),
      context: saved.context,
      hasCurrent: false,
    }),
  ).rejects.toThrow("Saved Tools & Policy is invalid");
});

test.each(["upstream", "auth"] as const)(
  "rejects a selected policy carrying the forbidden %s field",
  async (field) => {
    const saved = await privateSavedPolicyDirectory(projectContext);
    await writeFile(join(saved.directory, "forbidden.yaml"), forbiddenPolicy(field), {
      mode: 0o600,
    });
    await expect(
      choosePolicySource({
        interaction: interaction(["1\n"]),
        context: saved.context,
        hasCurrent: false,
      }),
    ).rejects.toThrow("Saved Tools & Policy is invalid");
  },
);

test("rejects a selected saved policy that is not private", async () => {
  const saved = await privateSavedPolicyDirectory(projectContext);
  const path = join(saved.directory, "public.yaml");
  await writeFile(path, validPolicy, { mode: 0o644 });
  await chmod(path, 0o644);
  await expect(
    choosePolicySource({
      interaction: interaction(["1\n"]),
      context: saved.context,
      hasCurrent: false,
    }),
  ).rejects.toThrow("Private file permissions must be 0600");
});

test("plans a private create-only saved policy", async () => {
  const saved = await privateSavedPolicyDirectory(projectContext);
  const configPath = join(saved.context.projectRoot, "config.json");
  const write = await planOptionalSavedPolicy({
    interaction: interaction(["2\n", "read-only\n"]),
    context: saved.context,
    policySource: validPolicy,
    backupKey: configPath,
  });
  expect(write).toMatchObject({
    content: validPolicy,
    mode: 0o600,
    private: true,
    backupKey: configPath,
  });
});

test.each(["upstream", "auth"] as const)(
  "rejects saving a policy carrying the forbidden %s field",
  async (field) => {
    const saved = await privateSavedPolicyDirectory(projectContext);
    await expect(
      planOptionalSavedPolicy({
        interaction: interaction(["2\n"]),
        context: saved.context,
        policySource: forbiddenPolicy(field),
        backupKey: join(saved.context.projectRoot, "config.json"),
      }),
    ).rejects.toThrow("Saved Tools & Policy is invalid");
  },
);

test("plans a private saved policy when the directory is absent", async () => {
  const directory = await mkdtemp(join("/private/tmp", "saved-policies-empty-"));
  temporaryDirectories.push(directory);
  const context: SavedPolicyContext = { ...projectContext, projectRoot: directory };
  const write = await planOptionalSavedPolicy({
    interaction: interaction(["2\n", "read-only\n"]),
    context,
    policySource: validPolicy,
    backupKey: join(directory, "config.json"),
  });
  expect(write?.path).toBe(join(savedPolicyDirectory(context), "read-only.yaml"));
});

test("rejects an existing saved policy name before planning a new one", async () => {
  const saved = await privateSavedPolicyDirectory(projectContext);
  await writeFile(join(saved.directory, "read-only.yaml"), validPolicy, { mode: 0o600 });
  const write = await planOptionalSavedPolicy({
    interaction: interaction(["2\n", "read-only\n", "new-policy\n"]),
    context: saved.context,
    policySource: validPolicy,
    backupKey: join(saved.context.projectRoot, "config.json"),
  });
  expect(write?.path).toBe(join(saved.directory, "new-policy.yaml"));
});

test("rejects an unsafe saved policy directory", async () => {
  const saved = await privateSavedPolicyDirectory(projectContext);
  await chmod(saved.directory, 0o755);
  await expect(
    planOptionalSavedPolicy({
      interaction: interaction(["2\n"]),
      context: saved.context,
      policySource: validPolicy,
      backupKey: join(saved.context.projectRoot, "config.json"),
    }),
  ).rejects.toThrow("permissions must be 0700");
});

test("rechecks the exact selected saved snapshot", async () => {
  const saved = await privateSavedPolicyDirectory(projectContext);
  const savedPath = join(saved.directory, "read-only.yaml");
  await writeFile(savedPath, validPolicy, { mode: 0o600 });
  const choice = await choosePolicySource({
    interaction: interaction(["1\n"]),
    context: saved.context,
    hasCurrent: false,
  });
  await writeFile(savedPath, replacementPolicy, { mode: 0o600 });
  await expect(recheckPolicySource(choice)).rejects.toThrow(
    "Saved Tools & Policy changed during setup",
  );
});

test("preserves and rechecks the exact selected existing policy snapshot", async () => {
  const directory = await mkdtemp(join("/private/tmp", "saved-policies-existing-"));
  temporaryDirectories.push(directory);
  const policyPath = join(directory, "existing.yaml");
  await writeFile(policyPath, validPolicy, { mode: 0o600 });
  const existingPolicy = await readSetupSnapshot(policyPath, "policy");
  if (!existingPolicy) throw new Error("missing test policy");
  const choice = await choosePolicySource({
    interaction: interaction(["1\n"]),
    context: { ...projectContext, projectRoot: directory },
    hasCurrent: false,
    existingPolicy,
  });
  expect(choice).toMatchObject({ kind: "policy", source: validPolicy, existing: existingPolicy });

  await writeFile(policyPath, replacementPolicy, { mode: 0o600 });
  await expect(recheckPolicySource(choice)).rejects.toThrow(
    "Existing policy changed during setup; rerun setup",
  );
});

test("keeps per-destination saved policy bytes independent", async () => {
  const directory = await mkdtemp(join("/private/tmp", "saved-policies-destinations-"));
  temporaryDirectories.push(directory);
  const claudeContext = { ...projectContext, client: "claude", projectRoot: directory };
  const codexContext = { ...projectContext, client: "codex", projectRoot: directory };
  const claudeSource = `# claude bytes\n${validPolicy}`;
  const codexSource = `# codex bytes\n${replacementPolicy}`;
  for (const [context, source] of [
    [claudeContext, claudeSource],
    [codexContext, codexSource],
  ] as const) {
    const saved = savedPolicyDirectory(context);
    await mkdir(saved, { recursive: true, mode: 0o700 });
    await writeFile(join(saved, "selected.yaml"), source, { mode: 0o600 });
  }

  const claude = await choosePolicySource({
    interaction: interaction(["1\n"]),
    context: claudeContext,
    hasCurrent: false,
  });
  const codex = await choosePolicySource({
    interaction: interaction(["1\n"]),
    context: codexContext,
    hasCurrent: false,
  });

  expect(claude).toMatchObject({ kind: "policy", source: claudeSource });
  expect(codex).toMatchObject({ kind: "policy", source: codexSource });
});

async function privateSavedPolicyDirectory(
  context: SavedPolicyContext,
): Promise<{ context: SavedPolicyContext; directory: string }> {
  const directory = await mkdtemp(join("/private/tmp", "saved-policies-test-"));
  temporaryDirectories.push(directory);
  const isolatedContext = {
    ...context,
    ...(context.scope === "project"
      ? { projectRoot: directory }
      : { restrictorHome: join(directory, ".mcp-restrictor") }),
  };
  const saved = savedPolicyDirectory(isolatedContext);
  await mkdir(saved, { recursive: true, mode: 0o700 });
  return { context: isolatedContext, directory: saved };
}

function interaction(answers: string[]): SetupInteraction {
  let index = 0;
  return {
    selectIndexes: async () => [Number((answers[index++] ?? "").trim()) - 1],
    ask: async () => (answers[index++] ?? "").trim(),
    write: () => undefined,
  } as unknown as SetupInteraction;
}

function forbiddenPolicy(field: "upstream" | "auth"): string {
  return `version: 1
default: deny
tools:
  allow: []
  deny: []
${field}:
  value: forbidden
`;
}
