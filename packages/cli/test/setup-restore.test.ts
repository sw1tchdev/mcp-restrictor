import { randomBytes } from "node:crypto";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, join, resolve } from "node:path";
import { Readable, Writable } from "node:stream";
import { afterEach, expect, test, vi } from "vitest";
import { runSetup } from "../src/setup/index.ts";
import { runRestore } from "../src/setup/restore/index.ts";
import type { ClientPluginOperations } from "../src/commands/client.ts";
import { main } from "../src/index.ts";
import { MASTER_KEY_FILE_ENV, type OAuthProfile } from "../src/oauth/storage.ts";
import {
  routePath,
  routeUrl,
  serializeRoute,
  type RouteDefinitionV1,
  type RouteOwner,
} from "../src/routes.ts";
import { createAdapterLoader, installAdapterHttpConfig } from "../src/setup/adapter-boundary.ts";
import { opencodeAdapter } from "../src/setup/opencode.ts";
import {
  assertPolicyTakeoversAllowed,
  loadRestoreChoices,
  planSetupRestoreStateChanges,
  planSelectedRestore,
  verifyRestoredConfigs,
} from "../src/setup/restore/planning.ts";
import {
  policyFingerprint,
  readRestoreState,
  restoreStatePath,
  serializeRestoreState,
} from "../src/setup/restore/state.ts";
import { codexAdapter, parseCodexConfig } from "../src/setup/codex.ts";
import { claudeAdapter } from "../src/setup/claude.ts";
import { applyFileTransaction, readSnapshot, sha256 } from "../src/setup/transaction.ts";
import {
  generatedConfigPath,
  generatedPolicyLocation,
  generatedPresetConfig,
} from "../src/setup/generated.ts";

const setupFakes = vi.hoisted(() => ({
  discover: vi.fn(async (..._args: unknown[]) => ["read_file"]),
  login: undefined as undefined | ((options: any) => Promise<OAuthProfile>),
}));

const restoreAttacks = vi.hoisted(() => ({
  nextRead: undefined as { path: string; content: string } | undefined,
  readBarrier: undefined as { path: string; entered(): void; wait: Promise<void> } | undefined,
  indexBarrier: undefined as { path: string; scanned(): void; wait: Promise<void> } | undefined,
  lockContention: undefined as { path: string; contended(): void } | undefined,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    readdir: (async (...args: Parameters<typeof actual.readdir>) => {
      const entries = await actual.readdir(...args);
      const barrier = restoreAttacks.indexBarrier;
      if (barrier && resolve(String(args[0])) === resolve(barrier.path)) {
        restoreAttacks.indexBarrier = undefined;
        barrier.scanned();
        await barrier.wait;
      }
      return entries;
    }) as typeof actual.readdir,
    link: async (...args: Parameters<typeof actual.link>) => {
      try {
        await actual.link(...args);
      } catch (error) {
        const contention = restoreAttacks.lockContention;
        if (contention && resolve(String(args[1])) === resolve(contention.path)) {
          restoreAttacks.lockContention = undefined;
          contention.contended();
        }
        throw error;
      }
    },
    open: async (...args: Parameters<typeof actual.open>) => {
      const handle = await actual.open(...args);
      const readFile = handle.readFile.bind(handle);
      handle.readFile = (async (...readArgs: Parameters<typeof readFile>) => {
        const content = await readFile(...readArgs);
        const barrier = restoreAttacks.readBarrier;
        if (barrier && resolve(String(args[0])) === resolve(barrier.path)) {
          restoreAttacks.readBarrier = undefined;
          barrier.entered();
          await barrier.wait;
        }
        const attack = restoreAttacks.nextRead;
        if (attack && resolve(String(args[0])) === resolve(attack.path)) {
          restoreAttacks.nextRead = undefined;
          return attack.content;
        }
        return content;
      }) as typeof handle.readFile;
      return handle;
    },
  };
});

vi.mock("@mcp-restrictor/transports", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@mcp-restrictor/transports")>();
  return {
    ...actual,
    discoverToolNames: (upstream: unknown, options: unknown) =>
      setupFakes.discover(upstream, options),
  };
});

vi.mock("../src/oauth/login.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/oauth/login.ts")>();
  return {
    ...actual,
    loginOAuthProfile: (options: any) =>
      setupFakes.login ? setupFakes.login(options) : actual.loginOAuthProfile(options),
  };
});

const roots: string[] = [];

afterEach(async () => {
  setupFakes.discover.mockReset();
  setupFakes.discover.mockResolvedValue(["read_file"]);
  setupFakes.login = undefined;
  restoreAttacks.nextRead = undefined;
  restoreAttacks.readBarrier = undefined;
  restoreAttacks.indexBarrier = undefined;
  restoreAttacks.lockContention = undefined;
  await Promise.all(roots.splice(0).map((path) => rm(path, { force: true, recursive: true })));
});

test("policy takeover rejects a case-only dev:ino alias owned by another state", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-policy-alias-")));
  roots.push(root);
  const home = join(root, "home");
  const configPath = join(root, ".codex", "config.toml");
  const policyDirectory = join(root, ".mcp-restrictor", "policies", "codex");
  const ownedPath = join(policyDirectory, "Files.yaml");
  const targetPath = join(policyDirectory, "files.yaml");
  const policySource = "allow:\n  - read_file\n";
  await mkdir(policyDirectory, { recursive: true });
  await writeFile(ownedPath, policySource, { mode: 0o600 });
  try {
    await stat(targetPath);
  } catch {
    await link(ownedPath, targetPath);
  }
  await privatePlannerFile(
    restoreStatePath(home, configPath),
    serializeRestoreState({
      version: 2,
      adapterId: "codex",
      configPath,
      servers: [
        {
          name: "Files",
          scope: "project",
          projectRoot: root,
          originalSource: "original",
          installedSource: "installed",
          policy: {
            path: ownedPath,
            before: null,
            installed: policyFingerprint(policySource, 0o600),
          },
        },
      ],
    }),
  );

  await expect(assertPolicyTakeoversAllowed(home, [{ policyPath: targetPath }])).rejects.toThrow(
    "Existing policy is referenced by another MCP restore state",
  );
});

test("setup state records the native original and exact installed config and policy", async () => {
  const fixture = await setupFixture(nativeSource("first", "credential-sentinel"));
  const output = await applySetup(fixture, [
    "2\n",
    "all\n",
    "1\n",
    "yes\n",
    "all\n",
    "1\n",
    "yes\n",
  ]);

  const stored = await storedState(fixture);
  const installedSource = await readFile(fixture.configPath, "utf8");
  const policyPath = join(fixture.root, ".mcp-restrictor", "policies", "codex", "first.yaml");
  const policySource = await readFile(policyPath, "utf8");
  const policyMode = (await stat(policyPath)).mode & 0o7777;
  expect(stored.state.servers).toEqual([
    {
      name: "first",
      scope: "project",
      projectRoot: fixture.root,
      originalSource: fixture.source,
      installedSource,
      policy: {
        path: policyPath,
        before: null,
        installed: policyFingerprint(policySource, policyMode),
      },
    },
  ]);
  expect(stored.snapshot.mode).toBe(0o600);
  expect(output).not.toContain(restoreStatePath(fixture.home, fixture.configPath));
  expect(output).not.toContain(fixture.source);
  expect(output).not.toContain("credential-sentinel");
});

test("setup state records a planned HTTP route only for a created native entry", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-route-state-plan-")));
  roots.push(root);
  const home = join(root, "home");
  const configPath = join(root, ".codex", "config.toml");
  const policyPath = join(root, ".mcp-restrictor", "policies", "codex", "created.yaml");
  const originalSource = 'prefix = "exact"\n';
  const owner: RouteOwner = {
    adapterId: "codex",
    scope: "project",
    configPath,
    projectRoot: root,
    serverName: "created",
  };
  const path = routePath(home, owner);
  const url = routeUrl(7319, owner);
  const installedSource = `${originalSource}[mcp_servers.created]\nurl = ${JSON.stringify(url)}\n`;
  const policySource = "allow:\n  - read_file\n";
  const routeSource = serializeRoute({
    version: 1,
    owner,
    listenUrl: url,
    proxyArgs: ["--policy", policyPath, "--", "node", "created.mjs"],
    environment: { set: {} },
  });
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, originalSource);
  const snapshot = await readSnapshot(configPath);
  if (!snapshot) throw new Error("missing config");
  const original = parseCodexConfig({
    path: configPath,
    scope: "project",
    source: originalSource,
    environment: {},
  });
  const server = parseCodexConfig({
    path: configPath,
    scope: "project",
    source: installedSource,
    environment: {},
  }).servers[0]!;
  const routeWrite = {
    path,
    content: routeSource,
    mode: 0o600,
    backupKey: configPath,
    private: true as const,
  };

  const changes = await planSetupRestoreStateChanges({
    home,
    projectRoot: root,
    environment: {},
    loaded: [{ adapter: codexAdapter, config: original, snapshot }],
    selections: [
      {
        adapter: codexAdapter,
        server,
        policy: { diskPath: policyPath },
        policySource,
        created: true,
        route: { write: routeWrite, installed: policyFingerprint(routeSource, 0o600) },
      } as any,
    ],
    clientWrites: [
      { path: configPath, content: installedSource, mode: 0o600, backupKey: configPath },
      { path: policyPath, content: policySource, mode: 0o600, backupKey: configPath },
    ],
  });

  expect(JSON.parse((changes[0] as { content: string }).content)).toMatchObject({
    version: 2,
    servers: [
      {
        name: "created",
        created: true,
        route: { path, installed: policyFingerprint(routeSource, 0o600) },
      },
    ],
  });
});

test.each([
  ["same-name", "fresh"],
  ["different-name", "stale"],
] as const)(
  "snapshotless generated planning rejects %s stale restore state",
  async (_case, stateName) => {
    const fixture = await snapshotlessSetupPlanningFixture({ stateName });

    await expect(planSetupRestoreStateChanges(fixture)).rejects.toThrow(
      "Invalid client configuration selected",
    );
  },
);

test.each([
  ["a non-generated path", { generated: false, created: true }],
  ["a selection without created ownership", { generated: true, created: false }],
] as const)("snapshotless setup planning rejects %s", async (_case, options) => {
  const fixture = await snapshotlessSetupPlanningFixture(options);

  await expect(planSetupRestoreStateChanges(fixture)).rejects.toThrow(
    "Invalid client configuration selected",
  );
});

test("setup state stores two servers from one config in one private state file", async () => {
  const fixture = await setupFixture(
    `${nativeSource("first", "first-secret")}\n${nativeSource("second", "second-secret")}`,
  );
  await applySetup(fixture, [
    "2\n",
    "all\n",
    "1\n",
    "yes\n",
    "all\n",
    "1\n",
    "1\n",
    "yes\n",
    "all\n",
    "1\n",
    "yes\n",
  ]);

  const installed = await readFile(fixture.configPath, "utf8");
  const stored = await storedState(fixture);
  expect(await readdir(dirname(stored.snapshot.path))).toHaveLength(1);
  expect(stored.state.servers.map(({ name }) => name)).toEqual(["first", "second"]);
  expect(stored.state.servers.map(({ installedSource }) => installedSource)).toEqual([
    installed,
    installed,
  ]);
});

test("setup state keeps independent installed sources when a second server changes the config", async () => {
  const fixture = await setupFixture(nativeSource("first", "first-secret"));
  await applySetup(fixture, ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"]);
  const firstState = await storedState(fixture);
  const firstInstalled = firstState.state.servers[0]!.installedSource;

  await writeFile(
    fixture.configPath,
    `${await readFile(fixture.configPath, "utf8")}\n${nativeSource("second", "second-secret")}`,
  );
  await applySetup(fixture, ["2\n", "2\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"]);

  const servers = (await storedState(fixture)).state.servers;
  expect(servers.map(({ name }) => name)).toEqual(["first", "second"]);
  expect(servers[0]!.installedSource).toBe(firstInstalled);
  expect(servers[1]!.installedSource).toBe(await readFile(fixture.configPath, "utf8"));
  expect(servers[1]!.installedSource).not.toBe(firstInstalled);
});

test("setup state preserves the first native original on a matching managed rerun", async () => {
  const fixture = await setupFixture(nativeSource("first", "original-secret"));
  await applySetup(fixture, ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"]);
  const original = (await storedState(fixture)).state.servers[0]!.originalSource;

  await applySetup(fixture, ["2\n", "all\n", "1\n"]);

  const rerun = (await storedState(fixture)).state.servers[0]!;
  expect(rerun.originalSource).toBe(original);
  expect(rerun.policy.before).toBeNull();
});

test("setup state preserves a tracked created marker during managed reconfiguration", async () => {
  const fixture = await restorePlanningFixture();
  const stored = await storedPlanningState(fixture);
  stored.state.servers[0]!.created = true;
  await privatePlannerFile(stored.snapshot.path, serializeRestoreState(stored.state));
  const loaded = await planningLoaded(fixture);
  const policy = await readSnapshot(fixture.firstPolicyPath);
  if (!policy) throw new Error("missing policy");
  const updatedPolicy = "allow:\n  - write_file\n";

  const changes = await planSetupRestoreStateChanges({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    loaded: [loaded],
    selections: [
      {
        adapter: codexAdapter,
        server: loaded.config.servers.find(({ name }) => name === "first")!,
        policy: { diskPath: fixture.firstPolicyPath },
        policySource: updatedPolicy,
      },
    ],
    clientWrites: [
      {
        path: fixture.configPath,
        content: fixture.installedSource,
        mode: loaded.snapshot.mode,
        backupKey: fixture.configPath,
      },
      {
        path: fixture.firstPolicyPath,
        content: updatedPolicy,
        mode: policy.mode,
        before: policy,
        backupKey: fixture.firstPolicyPath,
      },
    ],
  });

  expect(
    JSON.parse((changes[0] as { content: string }).content).servers.find(
      (server: { name: string }) => server.name === "first",
    ),
  ).toMatchObject({ created: true });
});

test("setup state removes a stale managed record with no valid legacy seed", async () => {
  const fixture = await setupFixture(nativeSource("first", "original-secret"));
  await applySetup(fixture, ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"]);
  const stored = await storedState(fixture);
  stored.state.servers[0]!.installedSource = nativeSource("first", "wrong-installed");
  await writeFile(stored.snapshot.path, serializeRestoreState(stored.state), { mode: 0o600 });
  await chmod(stored.snapshot.path, 0o600);
  await rm(join(fixture.home, ".mcp-restrictor", "backups"), { force: true, recursive: true });

  await applySetup(fixture, ["2\n", "all\n", "2\n", "yes\n", "all\n", "1\n", "yes\n"]);

  await expect(maybeRestoreState(fixture)).resolves.toBeUndefined();
});

test.sequential("main reseeds stale setup state from a built-in legacy backup", async () => {
  const fixture = await setupFixture(nativeSource("first", "legacy-secret"));
  await applySetup(fixture, ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"]);
  const stored = await storedState(fixture);
  stored.state.servers[0]!.installedSource = nativeSource("first", "wrong-installed");
  await writeFile(stored.snapshot.path, serializeRestoreState(stored.state), { mode: 0o600 });
  await chmod(stored.snapshot.path, 0o600);

  const previousCwd = process.cwd();
  process.chdir(fixture.root);
  try {
    await main({
      argv: [process.execPath, "mcp-restrictor", "setup"],
      home: fixture.home,
      environment: {
        PATH: `${fixture.root}${delimiter}${process.env.PATH ?? ""}`,
      },
      input: ttyReadable(["1\n", "2\n", "all\n", "2\n", "yes\n", "all\n", "1\n", "yes\n"]),
      output: ttyCapture(),
      clientPlugins: emptyClientPlugins(),
    });
  } finally {
    process.chdir(previousCwd);
  }

  expect((await storedState(fixture)).state.servers[0]!.originalSource).toBe(fixture.source);
});

test("setup state records only the OAuth profile ID, never decrypted tokens", async () => {
  const fixture = await setupFixture(
    'mcp_oauth_callback_port = 0\n[mcp_servers.first]\nurl = "https://resource.example.test/mcp"\nauth = "oauth"\n',
  );
  const keyPath = join(fixture.root, "master.key");
  await writeFile(keyPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
  await chmod(keyPath, 0o600);
  let profileId = "";
  setupFakes.login = async ({ input }: any) => {
    profileId = input.metadata.profileId;
    const issuer = "https://auth.example.test/";
    return {
      metadata: input.metadata,
      credentials: {
        clientInformation: { client_id: "client", issuer },
        tokens: {
          access_token: "access-token-sentinel",
          refresh_token: "refresh-token-sentinel",
          token_type: "Bearer",
          issuer,
        },
        discoveryState: {
          authorizationServerUrl: issuer,
          authorizationServerMetadata: {
            issuer,
            authorization_endpoint: `${issuer}authorize`,
            token_endpoint: `${issuer}token`,
            response_types_supported: ["code"],
          },
        },
      },
    };
  };

  const output = await applySetup(
    fixture,
    ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"],
    {
      PATH: process.env.PATH,
      [MASTER_KEY_FILE_ENV]: keyPath,
    },
  );

  const serialized = serializeRestoreState((await storedState(fixture)).state);
  expect(JSON.parse(serialized).servers[0].oauthProfileId).toBe(profileId);
  expect(`${serialized}\n${output}`).not.toContain("access-token-sentinel");
  expect(`${serialized}\n${output}`).not.toContain("refresh-token-sentinel");
});

test("setup state verification failure rolls back config, policy, and newly created state", async () => {
  const fixture = await setupFixture(nativeSource("first", "rollback-secret"));
  setupFakes.discover.mockResolvedValueOnce(["read_file"]).mockRejectedValueOnce(new Error("fail"));

  await expect(
    applySetup(fixture, ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"]),
  ).rejects.toThrow("Wrapper verification failed");

  expect(await readFile(fixture.configPath, "utf8")).toBe(fixture.source);
  await expect(
    readFile(join(fixture.root, ".mcp-restrictor", "policies", "codex", "first.yaml")),
  ).rejects.toMatchObject({ code: "ENOENT" });
  await expect(maybeRestoreState(fixture)).resolves.toBeUndefined();
});

test.each([
  [
    "server property",
    '{"mcpServers":{"first":{"command":"node","args":["shadowed.mjs"]},"first":{"command":"node","args":["effective.mjs"]}}}',
  ],
  [
    "mcpServers property",
    '{"mcpServers":{"first":{"command":"node","args":["shadowed.mjs"]}},"mcpServers":{"first":{"command":"node","args":["effective.mjs"]}}}',
  ],
] as const)(
  "Claude setup rejects a duplicate %s before publishing restore state",
  async (_name, source) => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-claude-duplicate-")));
    roots.push(root);
    const home = join(root, "home");
    const configPath = join(root, ".mcp.json");
    await writeFile(configPath, source);

    await expect(
      runSetup({
        input: Readable.from(["1\n"]),
        output: capture(),
        error: capture(),
        interactive: true,
        cwd: root,
        home,
        environment: { PATH: process.env.PATH },
        adapters: [claudeAdapter],
      }),
    ).rejects.toThrow("Failed to load client configuration");
    expect(await readFile(configPath, "utf8")).toBe(source);
    await expect(
      readRestoreState({ home, adapterId: "claude", configPath, projectRoot: root }),
    ).resolves.toBeUndefined();
  },
);

test("restore plan merges one selected server and preserves unrelated bytes", async () => {
  const fixture = await restorePlanningFixture();
  const loaded = await planningLoaded(fixture);
  const { choices, unavailable } = await loadRestoreChoices({
    home: fixture.home,
    projectRoot: fixture.root,
    cwd: fixture.root,
    environment: {},
    loaded: [loaded],
  });

  expect(unavailable).toEqual([]);
  const first = choices.find(({ server }) => server.name === "first")!;
  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: [first],
  });

  expect(plan.changes.map(({ path }) => path)).toEqual([
    fixture.configPath,
    fixture.firstPolicyPath,
    restoreStatePath(fixture.home, fixture.configPath),
  ]);
  expect(plan.changes[0]).toMatchObject({
    content: fixture.expectedFirstRestored,
    before: { content: fixture.installedSource },
  });
  expect(plan.changes[1]).toMatchObject({
    delete: true,
    before: { content: fixture.policySource },
  });
  expect(JSON.parse((plan.changes[2] as { content: string }).content).servers).toMatchObject([
    { name: "second" },
  ]);
  expect(plan.warnings).toEqual([]);

  await applyFileTransaction(plan.changes, {
    backupRoot: join(fixture.home, ".mcp-restrictor", "backups"),
    verify: plan.verify,
  });
  expect(await readFile(fixture.configPath, "utf8")).toBe(fixture.expectedFirstRestored);
  await expect(readFile(fixture.firstPolicyPath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  expect((await storedPlanningState(fixture)).state.servers.map(({ name }) => name)).toEqual([
    "second",
  ]);
});

test("restore removes a tracked added entry, its policy, and its final state", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-added-restore-")));
  roots.push(root);
  const home = join(root, "home");
  const configPath = join(root, ".codex", "config.toml");
  const policyPath = join(root, ".mcp-restrictor", "policies", "codex", "added.yaml");
  const original =
    'prefix = "unchanged"\n[mcp_servers.native]\ncommand = "node"\nargs = ["native.mjs"]\n';
  const installed = `${original}[mcp_servers.added]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(policyPath)}, "--", "node", "added.mjs"]\n`;
  const policy = "allow:\n  - read_file\n";
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, installed);
  await privatePlannerFile(policyPath, policy);
  await privatePlannerFile(
    restoreStatePath(home, configPath),
    serializeRestoreState({
      version: 1,
      adapterId: "codex",
      configPath: resolve(configPath),
      servers: [
        {
          name: "added",
          scope: "project",
          projectRoot: resolve(root),
          originalSource: original,
          installedSource: installed,
          created: true,
          policy: {
            path: policyPath,
            before: null,
            installed: policyFingerprint(policy, 0o600),
          },
        },
      ],
    }),
  );
  const snapshot = await readSnapshot(configPath);
  if (!snapshot) throw new Error("missing config");
  const loaded = {
    adapter: codexAdapter,
    snapshot,
    config: parseCodexConfig({
      path: configPath,
      scope: "project",
      source: installed,
      environment: {},
    }),
  };
  const { choices } = await loadRestoreChoices({
    home,
    projectRoot: root,
    cwd: root,
    environment: {},
    loaded: [loaded],
  });
  const plan = await planSelectedRestore({ home, projectRoot: root, environment: {}, choices });

  expect(choices[0]!.entry.created).toBe(true);
  expect(plan.changes).toMatchObject([
    { path: configPath, content: original },
    { path: policyPath, delete: true },
    { path: restoreStatePath(home, configPath), delete: true },
  ]);
  await applyFileTransaction(plan.changes, {
    backupRoot: join(home, ".mcp-restrictor", "backups"),
    verify: plan.verify,
  });

  expect(await readFile(configPath, "utf8")).toBe(original);
  await expect(readFile(policyPath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  await expect(
    readRestoreState({ home, adapterId: "codex", configPath, projectRoot: root }),
  ).resolves.toBeUndefined();
});

test("HTTP route restore deletes only one exact route and leaves its shared-port sibling untouched", async () => {
  const fixture = await httpRestoreFixture();
  const siblingBefore = await httpTargetBytes(fixture.second);
  const { choices, unavailable } = await loadRestoreChoices({
    ...fixture.context,
    loaded: fixture.loaded,
  });
  const selected = choices.find(({ server }) => server.name === "first");

  expect(unavailable).toEqual([]);
  expect(choices.map(({ server }) => server.name).sort()).toEqual(["first", "second"]);
  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: [selected!],
  });
  expect(plan.changes.map(({ path }) => path)).toEqual([
    fixture.first.routePath,
    fixture.first.configPath,
    fixture.first.policyPath,
    fixture.first.statePath,
  ]);

  await applyFileTransaction(plan.changes, {
    backupRoot: join(fixture.home, ".mcp-restrictor", "backups"),
    verify: plan.verify,
  });

  expect(await readFile(fixture.first.configPath, "utf8")).toBe(fixture.first.originalSource);
  await expect(readFile(fixture.first.routePath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  await expect(readFile(fixture.first.policyPath, "utf8")).rejects.toMatchObject({
    code: "ENOENT",
  });
  await expect(readFile(fixture.first.statePath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  expect(await httpTargetBytes(fixture.second)).toEqual(siblingBefore);
});

test("generated preset Restore is selective, private, and deletes the exact final empty artifact", async () => {
  const fixture = await generatedHttpRestoreFixture();
  const loaded = (
    await createAdapterLoader({ includeManagedRoutes: true }).load(codexAdapter, fixture.context)
  ).configurations;
  const discovered = await loadRestoreChoices({ ...fixture.context, loaded });
  expect(discovered.unavailable).toEqual([]);
  expect(discovered.choices.map(({ server }) => server.name).sort()).toEqual(["first", "second"]);

  const first = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: [discovered.choices.find(({ server }) => server.name === "first")!],
  });
  expect(
    first.changes.map(({ path, private: isPrivate, delete: remove }) => ({
      path,
      private: isPrivate,
      delete: remove === true,
    })),
  ).toEqual([
    { path: fixture.routes.first.path, private: true, delete: true },
    { path: fixture.configPath, private: true, delete: false },
    { path: fixture.policies.first.path, private: true, delete: true },
    { path: fixture.statePath, private: true, delete: false },
  ]);
  await applyFileTransaction(first.changes, {
    backupRoot: join(fixture.home, ".mcp-restrictor", "backups"),
    verify: first.verify,
  });
  expect(await readFile(fixture.configPath, "utf8")).toBe(fixture.onlySecondSource);
  await expect(readFile(fixture.routes.first.path, "utf8")).rejects.toMatchObject({
    code: "ENOENT",
  });
  await expect(readFile(fixture.policies.first.path, "utf8")).rejects.toMatchObject({
    code: "ENOENT",
  });
  expect(await readFile(fixture.routes.second.path, "utf8")).toBe(fixture.routes.second.source);
  expect(await readFile(fixture.policies.second.path, "utf8")).toBe("second-policy");

  const refreshed = (
    await createAdapterLoader({ includeManagedRoutes: true }).load(codexAdapter, fixture.context)
  ).configurations;
  const remaining = await loadRestoreChoices({ ...fixture.context, loaded: refreshed });
  const second = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: remaining.choices,
  });
  expect(second.changes).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ path: fixture.configPath, delete: true, private: true }),
      expect.objectContaining({ path: fixture.routes.second.path, delete: true, private: true }),
      expect.objectContaining({ path: fixture.policies.second.path, delete: true, private: true }),
      expect.objectContaining({ path: fixture.statePath, delete: true, private: true }),
    ]),
  );
  await applyFileTransaction(second.changes, {
    backupRoot: join(fixture.home, ".mcp-restrictor", "backups"),
    verify: second.verify,
  });
  for (const path of [
    fixture.configPath,
    fixture.routes.second.path,
    fixture.policies.second.path,
    fixture.statePath,
  ]) {
    await expect(readFile(path, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  }
});

test("generated preset Restore rejects a state sibling absent from the loaded config", async () => {
  const fixture = await generatedHttpRestoreFixture();
  await privatePlannerFile(fixture.configPath, fixture.firstSource);
  const loaded = (
    await createAdapterLoader({ includeManagedRoutes: true }).load(codexAdapter, fixture.context)
  ).configurations;
  const { choices } = await loadRestoreChoices({ ...fixture.context, loaded });

  await expect(
    planSelectedRestore({
      home: fixture.home,
      projectRoot: fixture.root,
      environment: {},
      choices: [choices.find(({ server }) => server.name === "first")!],
    }),
  ).rejects.toThrow("Restore inputs changed during planning");
});

test("generated preset Restore writes an original policy through the private transaction path", async () => {
  const fixture = await generatedHttpRestoreFixture();
  const stored = await readRestoreState({
    home: fixture.home,
    adapterId: "codex",
    configPath: fixture.configPath,
    projectRoot: fixture.root,
  });
  expect(stored).toBeDefined();
  const state = structuredClone(stored!.state);
  state.servers.find(({ name }) => name === "first")!.policy.before = {
    content: "original-policy",
    mode: 0o600,
  };
  await privatePlannerFile(fixture.statePath, serializeRestoreState(state));
  const loaded = (
    await createAdapterLoader({ includeManagedRoutes: true }).load(codexAdapter, fixture.context)
  ).configurations;
  const { choices } = await loadRestoreChoices({ ...fixture.context, loaded });
  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: [choices.find(({ server }) => server.name === "first")!],
  });

  expect(plan.changes).toContainEqual(
    expect.objectContaining({
      path: fixture.policies.first.path,
      content: "original-policy",
      mode: 0o600,
      private: true,
    }),
  );
  await applyFileTransaction(plan.changes, {
    backupRoot: join(fixture.home, ".mcp-restrictor", "backups"),
    verify: plan.verify,
  });
  expect(await readFile(fixture.policies.first.path, "utf8")).toBe("original-policy");
});

test("generated preset Restore propagates an invalid private-policy read", async () => {
  const fixture = await generatedHttpRestoreFixture();
  const loaded = (
    await createAdapterLoader({ includeManagedRoutes: true }).load(codexAdapter, fixture.context)
  ).configurations;
  const { choices } = await loadRestoreChoices({ ...fixture.context, loaded });
  await chmod(fixture.policies.first.path, 0o644);

  await expect(
    planSelectedRestore({
      home: fixture.home,
      projectRoot: fixture.root,
      environment: {},
      choices: [choices.find(({ server }) => server.name === "first")!],
    }),
  ).rejects.toThrow(/private file/i);
  await expect(
    readRestoreState({
      home: fixture.home,
      adapterId: "codex",
      configPath: fixture.configPath,
      projectRoot: fixture.root,
    }),
  ).resolves.toBeDefined();
});

test("generated preset Restore preserves unrelated edits instead of deleting the config", async () => {
  const fixture = await generatedHttpRestoreFixture();
  const edited = `title = "keep"\n${fixture.installedSource}`;
  await writeFile(fixture.configPath, edited, { mode: 0o600 });
  await chmod(fixture.configPath, 0o600);
  const loaded = (
    await createAdapterLoader({ includeManagedRoutes: true }).load(codexAdapter, fixture.context)
  ).configurations;
  const { choices } = await loadRestoreChoices({ ...fixture.context, loaded });
  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices,
  });
  const configChange = plan.changes.find(({ path }) => path === fixture.configPath)!;
  expect(configChange).toMatchObject({ private: true, content: 'title = "keep"\n' });
  expect(configChange).not.toHaveProperty("delete", true);
});

test("generated preset Restore names the exact host fragment that remains manual", async () => {
  const fixture = await generatedHttpRestoreFixture();
  const output = capture();

  await runRestore({
    input: Readable.from(["1\n", "yes\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: fixture.root,
    home: fixture.home,
    environment: { PATH: process.env.PATH },
  });

  expect(output.text()).toContain(
    'Warning: Remove "first" from the host Codex configuration if you pasted its generated fragment.\n',
  );
  expect(output.text()).not.toContain("host entry was restored");
});

test("restores a user-scope HTTP route from another project using its stored owner root", async () => {
  const fixture = await httpRestoreFixture();
  const projectB = join(fixture.root, "project-b");
  await mkdir(projectB);
  const loaded = fixture.loaded.find(({ config }) => config.scope === "user")!;
  const { choices, unavailable } = await loadRestoreChoices({
    home: fixture.home,
    projectRoot: projectB,
    cwd: projectB,
    environment: {},
    loaded: [loaded],
  });

  expect(unavailable).toEqual([]);
  expect(choices.map(({ server }) => server.name)).toEqual([fixture.first.name]);
  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: projectB,
    environment: {},
    choices,
  });
  expect(plan.changes.map(({ path }) => path)).toContain(fixture.first.routePath);

  await applyFileTransaction(plan.changes, {
    backupRoot: join(fixture.home, ".mcp-restrictor", "backups"),
    verify: plan.verify,
  });
  expect(await readFile(fixture.first.configPath, "utf8")).toBe(fixture.first.originalSource);
  await expect(readFile(fixture.first.routePath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
});

test("HTTP route restore keeps a mixed STDIO record in version-2 state", async () => {
  const fixture = await httpRestoreFixture();
  const target = fixture.first;
  const stdioPolicyPath = join(fixture.home, ".mcp-restrictor", "policies", "codex", "stdio.yaml");
  const stdioPolicy = "allow:\n  - write_file\n";
  const stdioManaged = `[mcp_servers.stdio]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(stdioPolicyPath)}, "--", "node", "stdio.mjs"]\n`;
  const stdioNative = '[mcp_servers.stdio]\ncommand = "node"\nargs = ["stdio.mjs"]\n';
  const routeOriginal = `${target.originalSource}${stdioManaged}`;
  const installedSource = `${target.installedSource}${stdioManaged}`;
  const state = JSON.parse(target.stateSource);
  state.servers[0].originalSource = routeOriginal;
  state.servers[0].installedSource = installedSource;
  state.servers.push({
    name: "stdio",
    scope: "user",
    projectRoot: fixture.root,
    originalSource: `${target.installedSource}${stdioNative}`,
    installedSource,
    policy: {
      path: stdioPolicyPath,
      before: null,
      installed: policyFingerprint(stdioPolicy, 0o600),
    },
  });
  await writeFile(target.configPath, installedSource);
  await privatePlannerFile(stdioPolicyPath, stdioPolicy);
  await privatePlannerFile(target.statePath, serializeRestoreState(state));
  const snapshot = await readSnapshot(target.configPath);
  if (!snapshot) throw new Error("missing config");
  fixture.loaded[0] = {
    adapter: codexAdapter,
    snapshot,
    config: parseCodexConfig({
      path: target.configPath,
      scope: target.scope,
      source: installedSource,
      environment: {},
    }),
  };

  const { choices } = await loadRestoreChoices({ ...fixture.context, loaded: fixture.loaded });
  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: [choices.find(({ server }) => server.name === "first")!],
  });
  const stateChange = plan.changes.find(({ path }) => path === target.statePath) as {
    content: string;
  };
  expect(JSON.parse(stateChange.content)).toMatchObject({
    version: 2,
    servers: [{ name: "stdio" }],
  });
  expect(JSON.parse(stateChange.content).servers[0]).not.toHaveProperty("route");

  await applyFileTransaction(plan.changes, {
    backupRoot: join(fixture.home, ".mcp-restrictor", "backups"),
    verify: plan.verify,
  });
  expect(await readFile(target.configPath, "utf8")).toBe(routeOriginal);
});

test.sequential("Windows-reported private route mode 0666 remains owned and restorable", async () => {
  const fixture = await httpRestoreFixture();
  await chmod(fixture.first.routePath, 0o666);

  await withProcessPlatform("win32", async () => {
    const { choices } = await loadRestoreChoices({ ...fixture.context, loaded: fixture.loaded });
    const choice = choices.find(({ server }) => server.name === "first");
    expect(choice).toBeDefined();
    const plan = await planSelectedRestore({
      home: fixture.home,
      projectRoot: fixture.root,
      environment: {},
      choices: [choice!],
    });
    expect(plan.changes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ delete: true, path: fixture.first.routePath }),
      ]),
    );
  });
});

test.sequential("POSIX wrong private route mode is not owned or restorable", async () => {
  const fixture = await httpRestoreFixture();
  await chmod(fixture.first.routePath, 0o640);

  await withProcessPlatform("linux", async () => {
    const { choices } = await loadRestoreChoices({ ...fixture.context, loaded: fixture.loaded });
    expect(choices.find(({ server }) => server.name === "first")).toBeUndefined();
  });
});

test("HTTP route restore removes a dead client URL and warns when its route is already missing", async () => {
  const fixture = await httpRestoreFixture();
  await rm(fixture.first.routePath);
  const { choices } = await loadRestoreChoices({ ...fixture.context, loaded: fixture.loaded });
  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: [choices.find(({ server }) => server.name === "first")!],
  });

  expect(plan.warnings).toEqual(["Managed HTTP route was already missing."]);
  expect(plan.changes.map(({ path }) => path)).not.toContain(fixture.first.routePath);
  await applyFileTransaction(plan.changes, {
    backupRoot: join(fixture.home, ".mcp-restrictor", "backups"),
    verify: plan.verify,
  });
  expect(await readFile(fixture.first.configPath, "utf8")).toBe(fixture.first.originalSource);
});

test("HTTP route restore aborts when a route appears after missing discovery", async () => {
  const fixture = await httpRestoreFixture();
  await rm(fixture.first.routePath);
  const before = await Promise.all(
    [fixture.first.configPath, fixture.first.policyPath, fixture.first.statePath].map((path) =>
      readFile(path, "utf8"),
    ),
  );
  const { choices } = await loadRestoreChoices({ ...fixture.context, loaded: fixture.loaded });
  await privatePlannerFile(fixture.first.routePath, fixture.first.routeSource);

  await expect(
    planSelectedRestore({
      home: fixture.home,
      projectRoot: fixture.root,
      environment: {},
      choices: [choices.find(({ server }) => server.name === "first")!],
    }),
  ).rejects.toThrow("Restore inputs changed during planning");
  expect(await readFile(fixture.first.routePath, "utf8")).toBe(fixture.first.routeSource);
  expect(
    await Promise.all(
      [fixture.first.configPath, fixture.first.policyPath, fixture.first.statePath].map((path) =>
        readFile(path, "utf8"),
      ),
    ),
  ).toEqual(before);
});

test.each(["bytes", "mode"] as const)(
  "HTTP route restore aborts the whole plan on route %s drift",
  async (drift) => {
    const fixture = await httpRestoreFixture();
    const { choices } = await loadRestoreChoices({ ...fixture.context, loaded: fixture.loaded });
    if (drift === "bytes") await writeFile(fixture.first.routePath, "{}", { mode: 0o600 });
    else await chmod(fixture.first.routePath, 0o640);

    await expect(
      planSelectedRestore({
        home: fixture.home,
        projectRoot: fixture.root,
        environment: {},
        choices: [choices.find(({ server }) => server.name === "first")!],
      }),
    ).rejects.toThrow("Restore inputs changed during planning");
    expect(await readFile(fixture.first.configPath, "utf8")).toBe(fixture.first.installedSource);
    expect(await readFile(fixture.first.statePath, "utf8")).toBe(fixture.first.stateSource);
  },
);

test("HTTP route restore aborts after identical route identity replacement", async () => {
  const fixture = await httpRestoreFixture();
  const before = await httpTargetBytes(fixture.first);
  const { choices } = await loadRestoreChoices({ ...fixture.context, loaded: fixture.loaded });
  const replacement = `${fixture.first.routePath}.replacement`;
  await privatePlannerFile(replacement, fixture.first.routeSource);
  await rename(replacement, fixture.first.routePath);

  await expect(
    planSelectedRestore({
      home: fixture.home,
      projectRoot: fixture.root,
      environment: {},
      choices: [choices.find(({ server }) => server.name === "first")!],
    }),
  ).rejects.toThrow("Restore inputs changed during planning");
  expect(await httpTargetBytes(fixture.first)).toEqual(before);
});

test("HTTP route discovery requires matching route state and exact installed client bytes", async () => {
  const fixture = await httpRestoreFixture();
  const firstLoaded = fixture.loaded.find(
    ({ config }) => config.path === fixture.first.configPath,
  )!;
  const noRouteState = JSON.parse(fixture.first.stateSource);
  delete noRouteState.servers[0].route;
  await privatePlannerFile(fixture.first.statePath, serializeRestoreState(noRouteState));

  await expect(
    loadRestoreChoices({ ...fixture.context, loaded: [firstLoaded] }),
  ).resolves.toMatchObject({ choices: [] });

  await privatePlannerFile(fixture.first.statePath, fixture.first.stateSource);
  const changed = fixture.first.installedSource.replace(fixture.first.url, fixture.second.url);
  await writeFile(fixture.first.configPath, changed);
  const snapshot = await readSnapshot(fixture.first.configPath);
  if (!snapshot) throw new Error("missing config");
  const loaded = {
    adapter: codexAdapter,
    snapshot,
    config: parseCodexConfig({
      path: fixture.first.configPath,
      scope: fixture.first.scope,
      source: changed,
      environment: {},
    }),
  };
  await expect(loadRestoreChoices({ ...fixture.context, loaded: [loaded] })).resolves.toMatchObject(
    {
      choices: [],
    },
  );
});

test("HTTP route deletion rolls back when later client verification fails", async () => {
  const fixture = await httpRestoreFixture();
  const badAdapter = {
    ...codexAdapter,
    async load(...args: Parameters<typeof codexAdapter.load>) {
      const result = await codexAdapter.load(...args);
      for (const { config } of result.configurations) {
        if (resolve(config.path) === resolve(fixture.first.configPath)) {
          config.unsupported.push({
            client: "codex",
            scope: config.scope,
            name: "first",
            configPath: config.path,
            reason: "verification fixture",
          });
        }
      }
      return result;
    },
  };
  const loaded = fixture.loaded.map((entry) =>
    entry.config.path === fixture.first.configPath ? { ...entry, adapter: badAdapter } : entry,
  );
  const { choices } = await loadRestoreChoices({ ...fixture.context, loaded });
  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: [choices.find(({ server }) => server.name === "first")!],
  });

  await expect(
    applyFileTransaction(plan.changes, {
      backupRoot: join(fixture.home, ".mcp-restrictor", "backups"),
      verify: plan.verify,
    }),
  ).rejects.toThrow("MCP restore verification failed");
  expect(await readFile(fixture.first.routePath, "utf8")).toBe(fixture.first.routeSource);
  expect(await readFile(fixture.first.configPath, "utf8")).toBe(fixture.first.installedSource);
  expect(await readFile(fixture.first.statePath, "utf8")).toBe(fixture.first.stateSource);
});

test("restore verification accepts only a tracked added-entry absence", async () => {
  const fixture = await restorePlanningFixture();
  const { choices } = await loadPlanningChoices(fixture);
  const choice = choices[0]!;
  const absent = fixture.installedSource.replace(
    /\[mcp_servers\.first\][\s\S]*?(?=\[mcp_servers\.second\])/,
    "",
  );
  const added = {
    ...choice,
    entry: {
      ...choice.entry,
      originalSource: absent,
      created: true as const,
    },
  };
  const planned = new Map([[resolve(fixture.configPath), absent]]);
  await writeFile(fixture.configPath, absent);
  const { created: _created, ...legacyEntry } = added.entry;
  const noRetryAdapter = {
    ...codexAdapter,
    restore: () => {
      throw new Error("restore must not run during verification");
    },
  };

  await expect(verifyRestoredConfigs(planned, [added])).resolves.toBeUndefined();
  await expect(
    verifyRestoredConfigs(planned, [{ ...added, adapter: noRetryAdapter }]),
  ).resolves.toBeUndefined();
  await expect(verifyRestoredConfigs(planned, [{ ...added, entry: legacyEntry }])).rejects.toThrow(
    "MCP restore verification failed",
  );
});

test("restore verification rejects an unsupported entry with the restored name", async () => {
  const fixture = await restorePlanningFixture();
  const { choices } = await loadPlanningChoices(fixture);
  const unsupported = fixture.expectedFirstRestored.replace(
    "[mcp_servers.first]\n# native bytes",
    "[mcp_servers.first]\nenabled = false\n# native bytes",
  );
  await writeFile(fixture.configPath, unsupported);

  await expect(
    verifyRestoredConfigs(new Map([[resolve(fixture.configPath), unsupported]]), [choices[0]!]),
  ).rejects.toThrow("MCP restore verification failed");
});

test("restore planning reaches adapter semantic refusal for an edited tracked addition", async () => {
  const fixture = await restorePlanningFixture();
  const stored = await storedPlanningState(fixture);
  const absent = fixture.installedSource.replace(
    /\[mcp_servers\.first\][\s\S]*?(?=\[mcp_servers\.second\])/,
    "",
  );
  stored.state.servers[0]!.created = true;
  stored.state.servers[0]!.originalSource = absent;
  await privatePlannerFile(stored.snapshot.path, serializeRestoreState(stored.state));

  const edited = fixture.installedSource.replace('"first.mjs"', '"edited.mjs"');
  await writeFile(fixture.configPath, edited);
  const { choices } = await loadPlanningChoices(fixture);
  const first = choices.find(({ server }) => server.name === "first");
  expect(first).toMatchObject({
    entry: { created: true, installedSource: fixture.installedSource },
    loaded: { snapshot: { content: edited } },
  });

  await expect(
    planSelectedRestore({
      home: fixture.home,
      projectRoot: fixture.root,
      environment: {},
      choices: [first!],
    }),
  ).rejects.toThrow("Client configuration restore failed");
});

test.each(["removed", "replaced"] as const)(
  "restore planning does not offer a %s tracked addition from current state",
  async (state) => {
    const fixture = await restorePlanningFixture();
    const stored = await storedPlanningState(fixture);
    const absent = fixture.installedSource.replace(
      /\[mcp_servers\.first\][\s\S]*?(?=\[mcp_servers\.second\])/,
      "",
    );
    stored.state.servers[0]!.created = true;
    stored.state.servers[0]!.originalSource = absent;
    await privatePlannerFile(stored.snapshot.path, serializeRestoreState(stored.state));

    const current =
      state === "removed"
        ? absent
        : fixture.installedSource.replace(
            `command = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(fixture.firstPolicyPath)}, "--", "node", "first.mjs"]`,
            'command = "node"\nargs = ["replacement.mjs"]',
          );
    await writeFile(fixture.configPath, current);

    const { choices, unavailable } = await loadPlanningChoices(fixture);
    expect(choices.map(({ server }) => server.name)).toEqual(["second"]);
    expect(unavailable).toEqual([]);
  },
);

test("restore plan merges two selected servers into one config write", async () => {
  const fixture = await restorePlanningFixture();
  const { choices } = await loadPlanningChoices(fixture);
  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices,
  });

  expect(plan.changes.filter(({ path }) => path === fixture.configPath)).toHaveLength(1);
  expect((plan.changes[0] as { content: string }).content).toBe(fixture.fullyRestored);
  expect(plan.changes.at(-1)).toMatchObject({
    delete: true,
    path: restoreStatePath(fixture.home, fixture.configPath),
    private: true,
  });
});

test("multi-config restore plan returns one ordered atomic change list", async () => {
  const fixture = await restorePlanningFixture();
  const { choices } = await loadPlanningChoices(fixture);
  const legacy = await legacyPlanningChoice(fixture);
  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: [choices[0]!, legacy],
  });

  expect(plan.changes.map(({ path }) => path)).toEqual([
    fixture.configPath,
    legacy.loaded.config.path,
    fixture.firstPolicyPath,
    restoreStatePath(fixture.home, fixture.configPath),
  ]);
  expect(plan.warnings).toEqual(["Restore artifacts were retained."]);
});

test("policy cleanup restores the exact previous policy", async () => {
  const fixture = await restorePlanningFixture();
  const stored = await storedPlanningState(fixture);
  stored.state.servers[0]!.policy.before = { content: "previous policy\n", mode: 0o640 };
  await privatePlannerFile(stored.snapshot.path, serializeRestoreState(stored.state));
  const { choices } = await loadPlanningChoices(fixture);

  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: [choices[0]!],
  });

  expect(plan.changes[1]).toMatchObject({
    path: fixture.firstPolicyPath,
    content: "previous policy\n",
    mode: 0o640,
  });
});

test.each(["edited", "shared"] as const)(
  "policy cleanup retains an %s policy with one fixed warning",
  async (kind) => {
    const fixture = await restorePlanningFixture();
    const { choices } = await loadPlanningChoices(fixture);
    if (kind === "edited") {
      await writeFile(fixture.firstPolicyPath, "user edit\n");
    } else {
      const stored = await storedPlanningState(fixture);
      const otherConfig = join(fixture.root, ".codex", "other.toml");
      await privatePlannerFile(
        restoreStatePath(fixture.home, otherConfig),
        serializeRestoreState({
          ...stored.state,
          configPath: resolve(otherConfig),
          servers: [stored.state.servers[0]!],
        }),
      );
    }

    const plan = await planSelectedRestore({
      home: fixture.home,
      projectRoot: fixture.root,
      environment: {},
      choices: [choices[0]!],
    });

    expect(plan.changes.map(({ path }) => path)).not.toContain(fixture.firstPolicyPath);
    expect(plan.warnings).toEqual(["Restore artifacts were retained."]);
  },
);

test("rejects a stale shared-policy publication after concurrent restore cleanup", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-restore-lock-")));
  roots.push(root);
  const home = join(root, "home");
  const firstHome = join(root, "codex-first");
  const secondHome = join(root, "codex-second");
  const firstConfig = join(firstHome, "config.toml");
  const secondConfig = join(secondHome, "config.toml");
  const restrictor = join(root, "mcp-restrictor");
  const source = nativeSource("first", "shared-policy-source");
  await mkdir(firstHome, { recursive: true });
  await mkdir(secondHome, { recursive: true });
  await writeFile(firstConfig, source);
  await writeFile(secondConfig, source);
  await writeFile(restrictor, "");
  await chmod(restrictor, 0o700);
  const setup = (codexHome: string, policyChoice: string) =>
    runSetup({
      input: Readable.from(["1\n", "all\n", policyChoice, "yes\n", "all\n", "1\n", "yes\n"]),
      output: capture(),
      error: capture(),
      interactive: true,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH, CODEX_HOME: codexHome },
      restrictor: { command: restrictor, argsPrefix: [] },
      adapters: [codexAdapter],
    });
  await setup(firstHome, "1\n");
  await writeFile(secondConfig, await readFile(firstConfig, "utf8"));
  await privatePlannerFile(
    join(
      home,
      ".mcp-restrictor",
      "backups",
      sha256(resolve(secondConfig)),
      "2026-08-16T01-02-03.004Z-backup",
      basename(secondConfig),
    ),
    source,
  );

  const restoreDirectory = dirname(restoreStatePath(home, firstConfig));
  let scanned!: () => void;
  const indexScanned = new Promise<void>((resolveScanned) => {
    scanned = resolveScanned;
  });
  let release!: () => void;
  const wait = new Promise<void>((resolveWait) => {
    release = resolveWait;
  });
  restoreAttacks.indexBarrier = { path: restoreDirectory, scanned, wait };
  const restoring = runRestore({
    input: Readable.from(["1\n", "yes\n"]),
    output: capture(),
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { PATH: process.env.PATH, CODEX_HOME: firstHome },
    adapters: [codexAdapter],
  });
  await indexScanned;

  let contended!: () => void;
  const lockContended = new Promise<"blocked">((resolveContended) => {
    contended = () => resolveContended("blocked");
  });
  restoreAttacks.lockContention = {
    path: join(home, ".mcp-restrictor", ".restore.lock"),
    contended,
  };
  const publishing = setup(secondHome, "2\n");
  const outcome = await Promise.race([publishing.then(() => "published" as const), lockContended]);
  release();
  await restoring;
  await expect(publishing).rejects.toThrow("Managed policy changed during setup; rerun setup");

  const policyPath = join(home, ".mcp-restrictor", "policies", "codex", "first.yaml");
  expect(outcome).toBe("blocked");
  expect(await readFile(firstConfig, "utf8")).toBe(source);
  expect(await readFile(secondConfig, "utf8")).toContain("mcp-restrictor");
  await expect(readFile(policyPath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  await expect(
    readRestoreState({
      home,
      adapterId: "codex",
      configPath: firstConfig,
      projectRoot: root,
    }),
  ).resolves.toBeUndefined();
  await expect(
    readRestoreState({
      home,
      adapterId: "codex",
      configPath: secondConfig,
      projectRoot: root,
    }),
  ).resolves.toBeUndefined();
});

test.each(["config", "state"] as const)(
  "restore plan aborts after concurrent %s mutation",
  async (target) => {
    const fixture = await restorePlanningFixture();
    const { choices } = await loadPlanningChoices(fixture);
    const path =
      target === "config" ? fixture.configPath : restoreStatePath(fixture.home, fixture.configPath);
    await writeFile(path, `${await readFile(path, "utf8")}\n`);

    await expect(
      planSelectedRestore({
        home: fixture.home,
        projectRoot: fixture.root,
        environment: {},
        choices: [choices[0]!],
      }),
    ).rejects.toThrow(/^Restore inputs changed during planning$/);
  },
);

test("malformed state affects only its rows and prevents uncertain policy cleanup", async () => {
  const fixture = await restorePlanningFixture();
  const invalid = await invalidPlanningLoaded(fixture);
  const result = await loadRestoreChoices({
    home: fixture.home,
    projectRoot: fixture.root,
    cwd: fixture.root,
    environment: {},
    loaded: [await planningLoaded(fixture), invalid],
  });

  expect(result.choices.map(({ server }) => server.name)).toEqual(["first", "second"]);
  expect(result.unavailable).toEqual([
    {
      client: "codex",
      scope: "project",
      name: "invalid",
      configPath: invalid.config.path,
      reason: "MCP restore is unavailable",
    },
  ]);
  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: [result.choices[0]!],
  });
  expect(plan.changes.map(({ path }) => path)).not.toContain(fixture.firstPolicyPath);
  expect(plan.warnings).toEqual(["Restore artifacts were retained."]);
});

test("missing restore hook becomes one sanitized unavailable row", async () => {
  const fixture = await restorePlanningFixture();
  const loaded = await planningLoaded(fixture);
  const { restore: _restore, ...adapter } = loaded.adapter;
  const result = await loadRestoreChoices({
    home: fixture.home,
    projectRoot: fixture.root,
    cwd: fixture.root,
    environment: {},
    loaded: [{ ...loaded, adapter }],
  });

  expect(result.choices).toEqual([]);
  expect(result.unavailable).toHaveLength(2);
  expect(new Set(result.unavailable.map(({ reason }) => reason))).toEqual(
    new Set(["MCP restore is unavailable"]),
  );
});

test("legacy restore plan changes only config and retains all artifacts", async () => {
  const fixture = await restorePlanningFixture();
  await rm(restoreStatePath(fixture.home, fixture.configPath));
  const stamp = "2026-08-16T01-02-03.004Z-backup";
  await privatePlannerFile(
    join(
      fixture.home,
      ".mcp-restrictor",
      "backups",
      sha256(resolve(fixture.configPath)),
      stamp,
      basename(fixture.configPath),
    ),
    fixture.originalSource,
  );
  const { choices, unavailable } = await loadPlanningChoices(fixture);
  expect(unavailable).toEqual([]);
  expect(choices.every(({ legacy }) => legacy)).toBe(true);

  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: [choices[0]!],
  });
  expect(plan.changes.map(({ path }) => path)).toEqual([fixture.configPath]);
  expect(plan.warnings).toEqual(["Restore artifacts were retained."]);
});

test.sequential("main restores a built-in legacy backup after repeated registry normalization", async () => {
  const fixture = await restorePlanningFixture();
  await rm(restoreStatePath(fixture.home, fixture.configPath));
  await privatePlannerFile(
    join(
      fixture.home,
      ".mcp-restrictor",
      "backups",
      sha256(resolve(fixture.configPath)),
      "2026-08-16T01-02-03.004Z-backup",
      basename(fixture.configPath),
    ),
    fixture.originalSource,
  );

  const previousCwd = process.cwd();
  process.chdir(fixture.root);
  try {
    await main({
      argv: [process.execPath, "mcp-restrictor", "setup"],
      home: fixture.home,
      environment: { PATH: process.env.PATH },
      input: ttyReadable(["2\n", "1\n", "yes\n"]),
      output: ttyCapture(),
      clientPlugins: emptyClientPlugins(),
    });
  } finally {
    process.chdir(previousCwd);
  }

  expect(await readFile(fixture.configPath, "utf8")).toBe(fixture.expectedFirstRestored);
});

test("applied nested OpenCode restore preserves the original cwd", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-opencode-restore-")));
  roots.push(root);
  const home = join(root, "home");
  const cwd = join(root, "packages", "app");
  const configPath = join(cwd, "opencode.jsonc");
  const policyPath = join(root, ".mcp-restrictor", "policies", "opencode", "files.yaml");
  const policySource = "allow:\n  - read_file\n";
  const installedSource = JSON.stringify({
    mcp: {
      files: {
        type: "local",
        command: ["mcp-restrictor", "--policy", policyPath, "--", "node", "files.mjs"],
      },
    },
  });
  const originalSource = JSON.stringify({
    mcp: { files: { type: "local", command: ["node", "files.mjs"] } },
  });
  await privatePlannerFile(configPath, installedSource);
  await privatePlannerFile(policyPath, policySource);
  await privatePlannerFile(
    restoreStatePath(home, configPath),
    serializeRestoreState({
      version: 1,
      adapterId: "opencode",
      configPath: resolve(configPath),
      servers: [
        {
          name: "files",
          scope: "project",
          projectRoot: resolve(root),
          originalSource,
          installedSource,
          policy: {
            path: policyPath,
            before: null,
            installed: policyFingerprint(policySource, 0o600),
          },
        },
      ],
    }),
  );
  const context = { home, projectRoot: root, cwd, environment: {} };
  const loaded = (await createAdapterLoader().load(opencodeAdapter, context)).configurations;
  const { choices } = await loadRestoreChoices({ ...context, loaded });
  const plan = await planSelectedRestore({
    home,
    projectRoot: root,
    environment: {},
    choices,
  });

  await applyFileTransaction(plan.changes, {
    backupRoot: join(home, ".mcp-restrictor", "backups"),
    verify: plan.verify,
  });

  expect(await readFile(configPath, "utf8")).toBe(originalSource);
});

test("verification uses one config snapshot and rolls back a between-read mutation", async () => {
  const fixture = await restorePlanningFixture();
  const alternate = fixture.expectedFirstRestored.replace('prefix = "exact"', 'prefix = "mutated"');
  const adapter = {
    ...codexAdapter,
    async load(
      context: Parameters<typeof codexAdapter.load>[0],
      host: Parameters<typeof codexAdapter.load>[1],
    ) {
      restoreAttacks.nextRead = { path: fixture.configPath, content: alternate };
      return codexAdapter.load(context, host);
    },
  };
  const loaded = { ...(await planningLoaded(fixture)), adapter };
  const { choices } = await loadRestoreChoices({
    home: fixture.home,
    projectRoot: fixture.root,
    cwd: fixture.root,
    environment: {},
    loaded: [loaded],
  });
  const plan = await planSelectedRestore({
    home: fixture.home,
    projectRoot: fixture.root,
    environment: {},
    choices: [choices[0]!],
  });

  await expect(
    applyFileTransaction(plan.changes, {
      backupRoot: join(fixture.home, ".mcp-restrictor", "backups"),
      verify: plan.verify,
    }),
  ).rejects.toThrow(/^MCP restore verification failed$/);
  expect(await readFile(fixture.configPath, "utf8")).toBe(fixture.installedSource);
  expect(await readFile(fixture.firstPolicyPath, "utf8")).toBe(fixture.policySource);
  expect((await storedPlanningState(fixture)).state.servers).toHaveLength(2);
});

test("restore TUI reports an empty managed choice set", async () => {
  const fixture = await setupFixture("");
  const output = capture();

  await runRestore({
    input: Readable.from([]),
    output,
    error: capture(),
    interactive: true,
    cwd: fixture.root,
    home: fixture.home,
    environment: { PATH: process.env.PATH },
    adapters: [codexAdapter],
  });

  expect(output.text()).toContain("No managed MCP servers can be restored.\n");
});

test.each([
  ["empty selection", ["none\n"], undefined],
  ["negative confirmation", ["1\n", "no\n"], undefined],
  ["EOF", [], undefined],
  ["Ctrl-C", [], new DOMException("cancelled", "AbortError")],
] as const)("restore TUI cancels on %s without writing", async (_caseName, answers, reason) => {
  const fixture = await restorePlanningFixture();
  const output = capture();
  const controller = new AbortController();
  if (reason) controller.abort(reason);

  await runRestore({
    input: Readable.from(answers),
    output,
    error: capture(),
    interactive: true,
    cwd: fixture.root,
    home: fixture.home,
    environment: { PATH: process.env.PATH },
    signal: controller.signal,
    adapters: [codexAdapter],
  });

  expect(output.text()).toContain("Restore cancelled.\n");
  expect(await readFile(fixture.configPath, "utf8")).toBe(fixture.installedSource);
  expect(await readFile(fixture.firstPolicyPath, "utf8")).toBe(fixture.policySource);
  expect((await storedPlanningState(fixture)).state.servers).toHaveLength(2);
});

test("restore commits when Enter confirms the selected plan", async () => {
  const fixture = await restorePlanningFixture();
  const output = capture();

  await runRestore({
    input: Readable.from(["1\n", "\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: fixture.root,
    home: fixture.home,
    environment: { PATH: process.env.PATH },
    adapters: [codexAdapter],
  });

  expect(await readFile(fixture.configPath, "utf8")).toBe(fixture.expectedFirstRestored);
  await expect(readFile(fixture.firstPolicyPath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  expect(await readFile(fixture.secondPolicyPath, "utf8")).toBe(fixture.policySource);
  expect((await storedPlanningState(fixture)).state.servers.map(({ name }) => name)).toEqual([
    "second",
  ]);
  expect(output.text()).toContain(`Restored: ${JSON.stringify(fixture.configPath)}\n`);
  expect(output.text()).not.toContain(fixture.policySource);
  expect(output.text()).not.toContain(fixture.originalSource);
});

test("restore retains a saved Tools & Policy while cleaning active restore state", async () => {
  const fixture = await setupFixture(nativeSource("files", "saved-policy-secret"));
  await applySetup(fixture, [
    "2\n",
    "all\n",
    "1\n",
    "yes\n",
    "all\n",
    "2\n",
    "read-only\n",
    "yes\n",
  ]);
  const activePolicyPath = join(fixture.root, ".mcp-restrictor", "policies", "codex", "files.yaml");
  const savedPolicyPath = join(
    fixture.root,
    ".mcp-restrictor",
    "saved-policies",
    "codex",
    "files.d",
    "read-only.yaml",
  );

  await runRestore({
    input: Readable.from(["1\n", "\n"]),
    output: capture(),
    error: capture(),
    interactive: true,
    cwd: fixture.root,
    home: fixture.home,
    environment: { PATH: process.env.PATH },
    adapters: [codexAdapter],
  });

  await expect(readFile(savedPolicyPath, "utf8")).resolves.toContain("version: 1");
  await expect(readFile(activePolicyPath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  expect(await readFile(fixture.configPath, "utf8")).toBe(fixture.source);
  await expect(maybeRestoreState(fixture)).resolves.toBeUndefined();
});

test("restore TUI cancels after yes before apply without writing", async () => {
  const fixture = await restorePlanningFixture();
  const beforeState = (await storedPlanningState(fixture)).snapshot.content;
  const controller = new AbortController();
  const cancellation = new DOMException("cancelled", "AbortError");
  let confirm!: () => void;
  const confirmation = new Promise<void>((resolveConfirmation) => {
    confirm = resolveConfirmation;
  });
  let entered!: () => void;
  const planning = new Promise<void>((resolvePlanning) => {
    entered = resolvePlanning;
  });
  let release!: () => void;
  const wait = new Promise<void>((resolveWait) => {
    release = resolveWait;
  });
  const output = capture((value) => {
    if (value.includes("Restore selected MCP servers?")) confirm();
  });
  const input = Readable.from(
    (async function* () {
      yield "1\n";
      await confirmation;
      restoreAttacks.readBarrier = { path: fixture.configPath, entered, wait };
      yield "yes\n";
    })(),
  );

  const restoring = runRestore({
    input,
    output,
    error: capture(),
    interactive: true,
    cwd: fixture.root,
    home: fixture.home,
    environment: { PATH: process.env.PATH },
    signal: controller.signal,
    adapters: [codexAdapter],
  });
  await planning;
  controller.abort(cancellation);
  release();
  await restoring;

  expect(await readFile(fixture.configPath, "utf8")).toBe(fixture.installedSource);
  expect(await readFile(fixture.firstPolicyPath, "utf8")).toBe(fixture.policySource);
  expect((await storedPlanningState(fixture)).snapshot.content).toBe(beforeState);
  expect(output.text()).toContain("Restore cancelled.\n");
  expect(output.text()).not.toContain("Restored:");
});

test("restore TUI sanitizes an unavailable external adapter without exposing saved sources", async () => {
  const fixture = await restorePlanningFixture();
  const output = capture();
  const { restore: _restore, ...external } = codexAdapter;

  await runRestore({
    input: Readable.from([]),
    output,
    error: capture(),
    interactive: true,
    cwd: fixture.root,
    home: fixture.home,
    environment: { PATH: process.env.PATH },
    adapters: [{ ...external, label: "External\u202e Adapter" }],
  });

  expect(output.text()).toContain("External\\u202e Adapter");
  expect(output.text()).toContain("MCP restore is unavailable");
  expect(output.text()).not.toContain("\u202e");
  expect(output.text()).not.toContain(fixture.originalSource);
  expect(output.text()).not.toContain(fixture.policySource);
});

type Fixture = {
  root: string;
  home: string;
  configPath: string;
  restrictorPath: string;
  source: string;
};

async function setupFixture(source: string): Promise<Fixture> {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-setup-state-")));
  roots.push(root);
  const home = join(root, "home");
  const configPath = join(root, ".codex", "config.toml");
  const restrictorPath = join(root, "mcp-restrictor");
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, source);
  await writeFile(restrictorPath, "");
  await chmod(restrictorPath, 0o700);
  return { root, home, configPath, restrictorPath, source };
}

async function applySetup(
  fixture: Fixture,
  answers: string[],
  environment: NodeJS.ProcessEnv = { PATH: process.env.PATH },
): Promise<string> {
  const output = capture();
  await runSetup({
    input: Readable.from(answers),
    output,
    error: capture(),
    interactive: true,
    cwd: fixture.root,
    home: fixture.home,
    environment,
    restrictor: { command: fixture.restrictorPath, argsPrefix: [] },
  });
  return output.text();
}

function maybeRestoreState(fixture: Fixture) {
  return readRestoreState({
    home: fixture.home,
    adapterId: "codex",
    configPath: fixture.configPath,
    projectRoot: fixture.root,
  });
}

async function storedState(fixture: Fixture) {
  const stored = await maybeRestoreState(fixture);
  if (!stored) throw new Error("missing restore state");
  return stored;
}

function nativeSource(name: string, secret: string): string {
  return `[mcp_servers.${name}]\ncommand = ${JSON.stringify(process.execPath)}\nargs = ["-e", ${JSON.stringify(secret)}]\n`;
}

function capture(onWrite?: (value: string) => void): Writable & { text(): string } {
  const chunks: Buffer[] = [];
  const stream = new Writable({
    write(chunk: Buffer | string, _encoding, callback) {
      chunks.push(Buffer.from(chunk));
      onWrite?.(chunk.toString());
      callback();
    },
  }) as Writable & { text(): string };
  stream.text = () => Buffer.concat(chunks).toString("utf8");
  return stream;
}

function ttyCapture(): Writable & { isTTY: true; text(): string } {
  return Object.assign(capture(), { isTTY: true as const });
}

function ttyReadable(values: readonly string[]): Readable & { isTTY: true } {
  return Object.assign(Readable.from(values), { isTTY: true as const });
}

function emptyClientPlugins(): ClientPluginOperations {
  return {
    install: vi.fn<ClientPluginOperations["install"]>(),
    list: vi.fn<ClientPluginOperations["list"]>().mockResolvedValue([]),
    load: vi.fn<ClientPluginOperations["load"]>().mockResolvedValue({
      adapters: [],
      unavailable: [],
    }),
    remove: vi.fn<ClientPluginOperations["remove"]>().mockResolvedValue({ warnings: [] }),
  };
}

type RestorePlanningFixture = Awaited<ReturnType<typeof restorePlanningFixture>>;

async function restorePlanningFixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-restore-plan-")));
  roots.push(root);
  const home = join(root, "home");
  const configPath = join(root, ".codex", "config.toml");
  const firstPolicyPath = join(root, ".mcp-restrictor", "policies", "codex", "first.yaml");
  const secondPolicyPath = join(root, ".mcp-restrictor", "policies", "codex", "second.yaml");
  const policySource = "allow:\n  - read_file\n";
  const firstNative = `[mcp_servers.first]\n# native bytes\ncommand = "node"\nargs = ["first.mjs"]\n`;
  const secondNative = `[mcp_servers.second]\ncommand = "node"\nargs = ["second.mjs"]\n`;
  const firstManaged = `[mcp_servers.first]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(firstPolicyPath)}, "--", "node", "first.mjs"]\n`;
  const secondManaged = `[mcp_servers.second]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(secondPolicyPath)}, "--", "node", "second.mjs"]\n`;
  const installedSource = `prefix = "exact"\n${firstManaged}${secondManaged}`;
  const originalSource = `${firstNative}${secondNative}`;
  const expectedFirstRestored = `prefix = "exact"\n${firstNative}${secondManaged}`;
  const fullyRestored = `prefix = "exact"\n${originalSource}`;
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, installedSource);
  await privatePlannerFile(firstPolicyPath, policySource);
  await privatePlannerFile(secondPolicyPath, policySource);
  const state = {
    version: 1 as const,
    adapterId: "codex",
    configPath: resolve(configPath),
    servers: ["first", "second"].map((name) => ({
      name,
      scope: "project" as const,
      projectRoot: resolve(root),
      originalSource,
      installedSource,
      policy: {
        path: name === "first" ? firstPolicyPath : secondPolicyPath,
        before: null,
        installed: policyFingerprint(policySource, 0o600),
      },
    })),
  };
  await privatePlannerFile(restoreStatePath(home, configPath), serializeRestoreState(state));
  return {
    root,
    home,
    configPath,
    firstPolicyPath,
    secondPolicyPath,
    policySource,
    installedSource,
    originalSource,
    expectedFirstRestored,
    fullyRestored,
  };
}

type HttpRestoreTarget = Awaited<ReturnType<typeof httpRestoreTarget>>;

async function generatedHttpRestoreFixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-generated-restore-")));
  roots.push(root);
  const home = join(root, "home");
  const configPath = generatedConfigPath(home, "codex");
  const baseline = generatedPresetConfig({ home, kind: "codex", environment: {} });
  const owners = Object.fromEntries(
    ["first", "second"].map((name) => [
      name,
      {
        adapterId: "codex",
        scope: "user" as const,
        configPath,
        projectRoot: resolve(home),
        serverName: name,
      },
    ]),
  ) as Record<"first" | "second", RouteOwner>;
  const urls = {
    first: routeUrl(17319, owners.first),
    second: routeUrl(17319, owners.second),
  };
  const firstSource = installAdapterHttpConfig(codexAdapter, baseline, {
    name: "first",
    url: urls.first,
  });
  const installedSource = installAdapterHttpConfig(
    codexAdapter,
    generatedPresetConfig({
      home,
      kind: "codex",
      environment: {},
      source: firstSource,
    }),
    { name: "second", url: urls.second },
  );
  const onlySecondSource = installAdapterHttpConfig(codexAdapter, baseline, {
    name: "second",
    url: urls.second,
  });
  const policies = {
    first: {
      path: generatedPolicyLocation({ home, adapterId: "codex", serverName: "first" }).diskPath,
    },
    second: {
      path: generatedPolicyLocation({ home, adapterId: "codex", serverName: "second" }).diskPath,
    },
  };
  const routes = Object.fromEntries(
    (["first", "second"] as const).map((name) => {
      const path = routePath(home, owners[name]);
      const source = serializeRoute({
        version: 1,
        owner: owners[name],
        listenUrl: urls[name],
        proxyArgs: ["--policy", policies[name].path, "--", "node", `${name}.mjs`],
        environment: { set: {} },
      });
      return [name, { path, source }];
    }),
  ) as Record<"first" | "second", { path: string; source: string }>;
  const statePath = restoreStatePath(home, configPath);
  const stateSource = serializeRestoreState({
    version: 2,
    adapterId: "codex",
    configPath,
    servers: (["first", "second"] as const).map((name) => ({
      name,
      scope: "user" as const,
      projectRoot: resolve(home),
      originalSource: name === "first" ? baseline.source : firstSource,
      installedSource: name === "first" ? firstSource : installedSource,
      created: true as const,
      policy: {
        path: policies[name].path,
        before: null,
        installed: policyFingerprint(`${name}-policy`, 0o600),
      },
      route: {
        path: routes[name].path,
        installed: policyFingerprint(routes[name].source, 0o600),
      },
    })),
  });
  await privatePlannerFile(configPath, installedSource);
  await privatePlannerFile(policies.first.path, "first-policy");
  await privatePlannerFile(policies.second.path, "second-policy");
  await privatePlannerFile(routes.first.path, routes.first.source);
  await privatePlannerFile(routes.second.path, routes.second.source);
  await privatePlannerFile(statePath, stateSource);
  return {
    root,
    home,
    configPath,
    firstSource,
    installedSource,
    onlySecondSource,
    policies,
    routes,
    statePath,
    context: { home, projectRoot: root, cwd: root, environment: {} },
  };
}

async function httpRestoreFixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-http-restore-")));
  roots.push(root);
  const home = join(root, "home");
  const first = await httpRestoreTarget({ home, root, name: "first", scope: "user" });
  const second = await httpRestoreTarget({ home, root, name: "second", scope: "project" });
  const loaded = [];
  for (const target of [first, second]) {
    const snapshot = await readSnapshot(target.configPath);
    if (!snapshot) throw new Error("missing config");
    loaded.push({
      adapter: codexAdapter,
      snapshot,
      config: parseCodexConfig({
        path: target.configPath,
        scope: target.scope,
        source: snapshot.content,
        environment: {},
      }),
    });
  }
  return {
    root,
    home,
    first,
    second,
    loaded,
    context: { home, projectRoot: root, cwd: root, environment: {} },
  };
}

async function httpRestoreTarget(options: {
  home: string;
  root: string;
  name: string;
  scope: "user" | "project";
}) {
  const configPath =
    options.scope === "user"
      ? join(options.home, ".codex", "config.toml")
      : join(options.root, ".codex", "config.toml");
  const policyPath = join(
    options.scope === "user" ? options.home : options.root,
    ".mcp-restrictor",
    "policies",
    "codex",
    `${options.name}.yaml`,
  );
  const owner: RouteOwner = {
    adapterId: "codex",
    scope: options.scope,
    configPath: resolve(configPath),
    projectRoot: resolve(options.root),
    serverName: options.name,
  };
  const path = routePath(options.home, owner);
  const url = routeUrl(7319, owner);
  const originalSource = `prefix = ${JSON.stringify(options.name)}\n`;
  const installedSource = `${originalSource}[mcp_servers.${options.name}]\nurl = ${JSON.stringify(url)}\n`;
  const policySource = "allow:\n  - read_file\n";
  const route: RouteDefinitionV1 = {
    version: 1,
    owner,
    listenUrl: url,
    proxyArgs: ["--policy", policyPath, "--", "node", `${options.name}.mjs`],
    environment: { set: {} },
  };
  const routeSource = serializeRoute(route);
  const statePath = restoreStatePath(options.home, configPath);
  const state = {
    version: 2 as const,
    adapterId: "codex",
    configPath: resolve(configPath),
    servers: [
      {
        name: options.name,
        scope: options.scope,
        projectRoot: resolve(options.root),
        originalSource,
        installedSource,
        created: true as const,
        policy: {
          path: policyPath,
          before: null,
          installed: policyFingerprint(policySource, 0o600),
        },
        route: { path, installed: policyFingerprint(routeSource, 0o600) },
      },
    ],
  };
  const stateSource = serializeRestoreState(state);
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, installedSource);
  await privatePlannerFile(policyPath, policySource);
  await privatePlannerFile(path, routeSource);
  await privatePlannerFile(statePath, stateSource);
  return {
    ...options,
    configPath,
    policyPath,
    routePath: path,
    statePath,
    url,
    originalSource,
    installedSource,
    policySource,
    routeSource,
    stateSource,
  };
}

async function httpTargetBytes(target: HttpRestoreTarget) {
  return Promise.all(
    [target.configPath, target.policyPath, target.routePath, target.statePath].map((path) =>
      readFile(path, "utf8"),
    ),
  );
}

async function planningLoaded(fixture: RestorePlanningFixture) {
  const snapshot = await readSnapshot(fixture.configPath);
  if (!snapshot) throw new Error("missing planning config");
  return {
    adapter: codexAdapter,
    snapshot,
    config: parseCodexConfig({
      path: fixture.configPath,
      scope: "project",
      source: snapshot.content,
      environment: {},
    }),
  };
}

async function privatePlannerFile(path: string, content: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await chmod(dirname(path), 0o700);
  await writeFile(path, content, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function snapshotlessSetupPlanningFixture(options: {
  generated?: boolean;
  created?: boolean;
  stateName?: string;
}) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-snapshotless-")));
  roots.push(root);
  const home = join(root, "home");
  const generated = options.generated ?? true;
  const created = options.created ?? true;
  const configPath = generated ? generatedConfigPath(home, "codex") : join(root, "codex.toml");
  const baseline = generated
    ? generatedPresetConfig({ home, kind: "codex", environment: {} })
    : parseCodexConfig({
        path: configPath,
        scope: "project",
        source: "",
        environment: {},
      });
  const url = "http://127.0.0.1:17319/mcp/codex/snapshotless";
  const installedSource = installAdapterHttpConfig(codexAdapter, baseline, {
    name: "fresh",
    url,
  });
  const server = (
    generated
      ? generatedPresetConfig({
          home,
          kind: "codex",
          environment: {},
          source: installedSource,
        })
      : parseCodexConfig({
          path: configPath,
          scope: "project",
          source: installedSource,
          environment: {},
        })
  ).servers[0]!;
  const policyPath = generated
    ? generatedPolicyLocation({ home, adapterId: "codex", serverName: "fresh" }).diskPath
    : join(root, ".mcp-restrictor", "policies", "codex", "fresh.yaml");
  const policySource = "fresh-policy";

  if (options.stateName) {
    const stateInstalled = installAdapterHttpConfig(codexAdapter, baseline, {
      name: options.stateName,
      url: "http://127.0.0.1:17319/mcp/codex/stale",
    });
    await privatePlannerFile(
      restoreStatePath(home, configPath),
      serializeRestoreState({
        version: 2,
        adapterId: "codex",
        configPath,
        servers: [
          {
            name: options.stateName,
            scope: "user",
            projectRoot: resolve(home),
            originalSource: baseline.source,
            installedSource: stateInstalled,
            created: true,
            policy: {
              path: generatedPolicyLocation({
                home,
                adapterId: "codex",
                serverName: options.stateName,
              }).diskPath,
              before: null,
              installed: policyFingerprint("stale-policy", 0o600),
            },
          },
        ],
      }),
    );
  }

  return {
    home,
    projectRoot: root,
    environment: {},
    loaded: [{ adapter: codexAdapter, config: baseline }],
    selections: [
      {
        adapter: codexAdapter,
        server,
        policy: { diskPath: policyPath },
        policySource,
        ...(created ? { created: true as const } : {}),
        ...(generated ? { ownerProjectRoot: home } : {}),
      },
    ],
    clientWrites: [
      { path: configPath, content: installedSource, mode: 0o600, backupKey: configPath },
      { path: policyPath, content: policySource, mode: 0o600, backupKey: configPath },
    ],
  };
}

async function withProcessPlatform<T>(
  value: NodeJS.Platform,
  operation: () => Promise<T>,
): Promise<T> {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value });
  try {
    return await operation();
  } finally {
    Object.defineProperty(process, "platform", platform);
  }
}

function storedPlanningState(fixture: RestorePlanningFixture) {
  return readRestoreState({
    home: fixture.home,
    adapterId: "codex",
    configPath: fixture.configPath,
    projectRoot: fixture.root,
  }).then((stored) => {
    if (!stored) throw new Error("missing planning state");
    return stored;
  });
}

async function loadPlanningChoices(fixture: RestorePlanningFixture) {
  return loadRestoreChoices({
    home: fixture.home,
    projectRoot: fixture.root,
    cwd: fixture.root,
    environment: {},
    loaded: [await planningLoaded(fixture)],
  });
}

async function legacyPlanningChoice(fixture: RestorePlanningFixture) {
  const configPath = join(fixture.root, ".codex", "legacy.toml");
  const policyPath = join(fixture.root, ".mcp-restrictor", "policies", "codex", "legacy.yaml");
  const current = `[mcp_servers.legacy]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(policyPath)}, "--", "node", "legacy.mjs"]\n`;
  const original = `[mcp_servers.legacy]\ncommand = "node"\nargs = ["legacy.mjs"]\n`;
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, current);
  const snapshot = await readSnapshot(configPath);
  if (!snapshot) throw new Error("missing legacy config");
  const loaded = {
    adapter: codexAdapter,
    snapshot,
    config: parseCodexConfig({
      path: configPath,
      scope: "project",
      source: current,
      environment: {},
    }),
  };
  return {
    adapter: codexAdapter,
    context: {
      home: fixture.home,
      projectRoot: fixture.root,
      cwd: fixture.root,
      environment: {},
    },
    loaded,
    server: loaded.config.servers[0]!,
    entry: { name: "legacy", originalSource: original },
    legacy: true,
  };
}

async function invalidPlanningLoaded(fixture: RestorePlanningFixture) {
  const configPath = join(fixture.root, ".codex", "invalid.toml");
  const policyPath = join(fixture.root, ".mcp-restrictor", "policies", "codex", "invalid.yaml");
  const source = `[mcp_servers.invalid]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(policyPath)}, "--", "node", "invalid.mjs"]\n`;
  await writeFile(configPath, source);
  await privatePlannerFile(restoreStatePath(fixture.home, configPath), "{hostile-detail");
  const snapshot = await readSnapshot(configPath);
  if (!snapshot) throw new Error("missing invalid config");
  return {
    adapter: codexAdapter,
    snapshot,
    config: parseCodexConfig({
      path: configPath,
      scope: "project",
      source,
      environment: {},
    }),
  };
}
