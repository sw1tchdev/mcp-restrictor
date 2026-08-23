import { chmod, lstat, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import {
  matchesFingerprint,
  planRestoreStateChange,
  policyFingerprint,
  readRestoreState,
  readRestoreStateIndex,
  restoreStatePath,
  serializeRestoreState,
  type RestoreStateV1,
} from "../src/setup/restore/state.ts";
import { findLegacyRestoreEntry } from "../src/setup/restore/legacy.ts";
import { claudeAdapter, parseClaudeConfig } from "../src/setup/claude.ts";
import type { ClientAdapter, ClientLoadContext } from "../src/client-adapter.ts";
import type { LoadedConfig } from "../src/setup/adapter-boundary.ts";
import { createAdapterRegistry } from "../src/setup/adapters.ts";
import { routePath } from "../src/routes.ts";
import { sha256, type FileSnapshot } from "../src/setup/transaction.ts";
import {
  generatedConfigPath,
  generatedPolicyLocation,
  readGeneratedFileSnapshot,
} from "../src/setup/generated.ts";

const fileAttack = vi.hoisted(() => ({
  nonOwnerPath: undefined as string | undefined,
  replaceAfterRead: undefined as { path: string; moved: string } | undefined,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    lstat: async (path: string) => {
      const stat = await actual.lstat(path);
      if (fileAttack.nonOwnerPath === path) {
        Object.defineProperty(stat, "uid", { value: stat.uid + 1 });
      }
      return stat;
    },
    open: async (...args: Parameters<typeof actual.open>) => {
      const handle = await actual.open(...args);
      const readFile = handle.readFile.bind(handle);
      handle.readFile = (async (...readArgs: Parameters<typeof readFile>) => {
        const content = await readFile(...readArgs);
        const replacement = fileAttack.replaceAfterRead;
        if (replacement?.path === args[0]) {
          fileAttack.replaceAfterRead = undefined;
          await actual.rename(replacement.path, replacement.moved);
          await actual.writeFile(replacement.path, "{}", { mode: 0o600 });
          await actual.chmod(replacement.path, 0o600);
        }
        return content;
      }) as typeof handle.readFile;
      return handle;
    },
  };
});

const temporaryDirectories: string[] = [];

afterEach(async () => {
  fileAttack.nonOwnerPath = undefined;
  fileAttack.replaceAfterRead = undefined;
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true })));
});

test("stores one restore-state file per resolved config path", async () => {
  const home = await temporaryDirectory();
  const configPath = join(home, "config.toml");
  const expected = join(home, ".mcp-restrictor", "restore", `${sha256(resolve(configPath))}.json`);
  expect(restoreStatePath(home, configPath)).toBe(expected);
  expect(restoreStatePath(home, join(home, "nested", "..", "config.toml"))).toBe(expected);
});

test("returns absent state without creating private storage", async () => {
  const fixture = await stateFixture(false);
  await expect(readRestoreState(fixture.options)).resolves.toBeUndefined();
  await expect(lstat(join(fixture.home, ".mcp-restrictor"))).rejects.toMatchObject({
    code: "ENOENT",
  });
});

test("reads a matching private version-1 state and its exact snapshot", async () => {
  const fixture = await stateFixture();
  const content = serializeRestoreState(fixture.state);
  await privateFile(fixture.path, content);
  await expect(readRestoreState(fixture.options)).resolves.toMatchObject({
    state: fixture.state,
    snapshot: { path: fixture.path, content, mode: 0o600 },
  });
});

test("round-trips a strict version-2 state with one created HTTP route", async () => {
  const fixture = await stateFixture();
  const state = stateValueV2(fixture.home, fixture.state);
  const content = serializeRestoreState(state);
  await privateFile(fixture.path, content);

  expect(JSON.parse(content)).toEqual(state);
  await expect(readRestoreState(fixture.options)).resolves.toMatchObject({ state });
});

test("version 2 accepts only exact generated config and generated policy ownership", async () => {
  const home = await temporaryDirectory();
  const configPath = generatedConfigPath(home, "codex");
  const policyPath = generatedPolicyLocation({
    home,
    adapterId: "codex",
    serverName: "files",
  }).diskPath;
  const base = {
    version: 2,
    adapterId: "codex",
    configPath,
    servers: [
      {
        name: "files",
        scope: "user",
        projectRoot: resolve(home),
        originalSource: "",
        installedSource: '[mcp_servers.files]\nurl = "http://127.0.0.1:17319/mcp/codex/id"\n',
        created: true,
        policy: {
          path: policyPath,
          before: null,
          installed: policyFingerprint("policy", 0o600),
        },
      },
    ],
  };
  const read = async (state: any) => {
    const path = restoreStatePath(home, state.configPath);
    await privateFile(path, `${JSON.stringify(state)}\n`);
    return readRestoreState({
      home,
      adapterId: state.adapterId,
      configPath: state.configPath,
      projectRoot: join(home, "unrelated-cwd"),
    });
  };

  await expect(read(structuredClone(base))).resolves.toMatchObject({ state: base });
  const invalid: Array<[string, (state: any) => void]> = [
    ["version 1", (state) => (state.version = 1)],
    [
      "generated-looking config",
      (state) =>
        (state.configPath = join(home, ".mcp-restrictor", "generated", "nested", "codex.toml")),
    ],
    ["wrong adapter", (state) => (state.adapterId = "claude")],
    [
      "wrong encoded server name",
      (state) =>
        (state.servers[0].policy.path = join(
          home,
          ".mcp-restrictor",
          "generated",
          "policies",
          "codex",
          "other.yaml",
        )),
    ],
    [
      "conventional policy swap",
      (state) =>
        (state.servers[0].policy.path = join(
          home,
          ".mcp-restrictor",
          "policies",
          "codex",
          "files.yaml",
        )),
    ],
    ["project scope swap", (state) => (state.servers[0].scope = "project")],
    ["container home swap", (state) => (state.servers[0].projectRoot = join(home, "project"))],
    [
      "permissive installed policy mode",
      (state) => (state.servers[0].policy.installed.mode = 0o644),
    ],
    [
      "permissive original policy mode",
      (state) => (state.servers[0].policy.before = { content: "original", mode: 0o644 }),
    ],
  ];
  for (const [_name, mutate] of invalid) {
    const state = structuredClone(base);
    mutate(state);
    await expect(read(state)).rejects.toThrow(/^Invalid MCP restore state$/);
  }
});

test.each([
  [
    "route on version 1",
    (state: any): void => void (state.servers[0].route = routeState("/route")),
  ],
  ["unknown route key", (state: any): void => void (state.servers[0].route.extra = true)],
  [
    "invalid route fingerprint",
    (state: any): void => void (state.servers[0].route.installed.size = -1),
  ],
  ["arbitrary route path", (state: any): void => void (state.servers[0].route.path = "/route")],
  ["route ID owner mismatch", (state: any): void => void (state.servers[0].name = "other")],
  ["route on a non-created entry", (state: any): void => void delete state.servers[0].created],
] as const)("rejects version/key mixing: %s", async (name, mutate) => {
  const fixture = await stateFixture();
  const state =
    name === "route on version 1"
      ? structuredClone(fixture.state)
      : stateValueV2(fixture.home, fixture.state);
  mutate(state);
  await privateFile(fixture.path, JSON.stringify(state));

  await expect(readRestoreState(fixture.options)).rejects.toThrow(/^Invalid MCP restore state$/);
});

test("keeps untouched v1 bytes but upgrades an updated record to version 2", async () => {
  const fixture = await stateFixture();
  const content = serializeRestoreState(fixture.state);
  await privateFile(fixture.path, content);
  const stored = await readRestoreState(fixture.options);
  if (!stored) throw new Error("missing state");

  expect(
    planRestoreStateChange({
      home: fixture.home,
      configPath: fixture.configPath,
      backupKey: fixture.configPath,
      before: stored.snapshot,
      state: stored.state,
    }),
  ).toBeUndefined();

  stored.state.servers[0]!.installedSource = "updated";
  const changed = planRestoreStateChange({
    home: fixture.home,
    configPath: fixture.configPath,
    backupKey: fixture.configPath,
    before: stored.snapshot,
    state: stored.state,
  });
  expect(JSON.parse((changed as { content: string }).content).version).toBe(2);
});

test("rejects duplicate route ownership across state files", async () => {
  const fixture = await stateFixture();
  const content = serializeRestoreState(stateValueV2(fixture.home, fixture.state));
  await privateFile(fixture.path, content);
  await privateFile(join(dirname(fixture.path), "zz-duplicate.json"), content);

  await expect(readRestoreStateIndex(fixture.home)).rejects.toThrow(/^Invalid MCP restore state$/);
});

test("reads a user-scope state from a different project root", async () => {
  const fixture = await stateFixture();
  await privateFile(fixture.path, serializeRestoreState(fixture.state));

  await expect(
    readRestoreState({
      ...fixture.options,
      projectRoot: join(fixture.home, "another-project"),
    }),
  ).resolves.toMatchObject({ state: fixture.state });
});

test("keeps a project-scope state bound to its stored project root", async () => {
  const fixture = await stateFixture();
  makeProjectScope(fixture.state);
  await privateFile(fixture.path, serializeRestoreState(fixture.state));

  await expect(readRestoreState(fixture.options)).resolves.toMatchObject({ state: fixture.state });
  await expect(
    readRestoreState({
      ...fixture.options,
      projectRoot: join(fixture.home, "another-project"),
    }),
  ).rejects.toThrow(/^Invalid MCP restore state$/);
});

const invalidStateRows: ReadonlyArray<[string, (state: any) => void]> = [
  ["unknown version", (state: any) => (state.version = 3)],
  ["extra key", (state: any) => (state.extra = true)],
  ["missing key", (state: any) => delete state.servers],
  ["duplicate server name", (state: any) => state.servers.push(structuredClone(state.servers[0]))],
  ["wrong adapter", (state: any) => (state.adapterId = "claude")],
  [
    "wrong config path hash binding",
    (state: any) => (state.configPath = resolve(dirname(state.configPath), "other.json")),
  ],
  ["invalid scope", (state: any) => (state.servers[0].scope = "workspace")],
  [
    "mismatched project-scope root",
    (state: any) =>
      makeProjectScope(state, resolve(dirname(state.servers[0].projectRoot), "other")),
  ],
  ["non-string original source", (state: any) => (state.servers[0].originalSource = 1)],
  ["non-string installed source", (state: any) => (state.servers[0].installedSource = {})],
  ["false created marker", (state: any) => (state.servers[0].created = false)],
  ["string created marker", (state: any) => (state.servers[0].created = "true")],
  ["numeric created marker", (state: any) => (state.servers[0].created = 1)],
  ["null created marker", (state: any) => (state.servers[0].created = null)],
  [
    "malformed source state",
    (state: any) => (state.servers[0].policy.before = { content: 1, mode: 0o600 }),
  ],
  [
    "policy path mismatch",
    (state: any) =>
      (state.servers[0].policy.path = resolve(dirname(state.servers[0].policy.path), "other.yaml")),
  ],
  ["traversal-shaped config", (state: any) => (state.configPath = "../config.json")],
  ["traversal-shaped project root", (state: any) => (state.servers[0].projectRoot = "../project")],
  ["invalid policy hash", (state: any) => (state.servers[0].policy.installed.sha256 = "../hash")],
  ["invalid policy size", (state: any) => (state.servers[0].policy.installed.size = -1)],
  ["invalid stored mode", (state: any) => (state.servers[0].policy.before.mode = 0o10000)],
  ["invalid fingerprint mode", (state: any) => (state.servers[0].policy.installed.mode = 1.5)],
  ["invalid OAuth profile ID", (state: any) => (state.servers[0].oauthProfileId = "../profile")],
];

test.each(invalidStateRows)("rejects %s with one fixed state error", async (_name, mutate) => {
  const fixture = await stateFixture();
  const invalid = structuredClone(fixture.state) as any;
  mutate(invalid);
  await privateFile(fixture.path, JSON.stringify(invalid));
  await expect(readRestoreState(fixture.options)).rejects.toThrow(/^Invalid MCP restore state$/);
});

test("ignores a valid state stored under the wrong config hash", async () => {
  const fixture = await stateFixture();
  const wrongPath = join(dirname(fixture.path), `${sha256("wrong")}.json`);
  await privateFile(wrongPath, serializeRestoreState(fixture.state));
  await expect(readRestoreState(fixture.options)).resolves.toBeUndefined();
});

const posixOnly =
  process.platform === "win32" || typeof process.getuid !== "function" ? test.skip : test;

posixOnly.each([
  [
    "symlink file",
    async (path: string) => {
      const external = `${path}.external`;
      await privateFile(external, "content");
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await chmod(dirname(path), 0o700);
      await symlink(external, path);
    },
  ],
  [
    "non-regular node",
    async (path: string) => {
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await chmod(dirname(path), 0o700);
      await mkdir(path, { mode: 0o700 });
    },
  ],
  ["permissive file", async (path: string) => privateFile(path, "content", 0o644)],
  [
    "wrong-owner file",
    async (path: string) => {
      await privateFile(path, "content");
      fileAttack.nonOwnerPath = path;
    },
  ],
  [
    "permissive parent",
    async (path: string) => {
      await privateFile(path, "content");
      await chmod(dirname(path), 0o755);
    },
  ],
] as const)("generated private path rejects a %s", async (_name, prepare) => {
  for (const target of ["config", "policy"] as const) {
    const home = await temporaryDirectory();
    const path =
      target === "config"
        ? generatedConfigPath(home, "claude")
        : generatedPolicyLocation({ home, adapterId: "claude", serverName: "files" }).diskPath;
    await prepare(path);
    await expect(readGeneratedFileSnapshot(path)).rejects.toThrow();
  }
});

test.each([
  [
    "symlinked state file",
    async (fixture: Awaited<ReturnType<typeof stateFixture>>) => {
      const external = join(fixture.home, "external.json");
      await privateFile(external, serializeRestoreState(fixture.state));
      await mkdir(dirname(fixture.path), { recursive: true, mode: 0o700 });
      await chmod(dirname(fixture.path), 0o700);
      await symlink(external, fixture.path);
    },
  ],
  [
    "symlinked state ancestor",
    async (fixture: Awaited<ReturnType<typeof stateFixture>>) => {
      const external = join(fixture.home, "external");
      const statePath = join(external, "restore", `${sha256(resolve(fixture.configPath))}.json`);
      await privateFile(statePath, serializeRestoreState(fixture.state));
      await symlink(external, join(fixture.home, ".mcp-restrictor"));
    },
  ],
] as const)("rejects a %s", async (_name, prepare) => {
  const fixture = await stateFixture(false);
  await prepare(fixture);
  await expect(readRestoreState(fixture.options)).rejects.toThrow(/^Invalid MCP restore state$/);
});

posixOnly.each([
  [
    "0644 state file",
    async (fixture: Awaited<ReturnType<typeof stateFixture>>) => {
      await privateFile(fixture.path, serializeRestoreState(fixture.state), 0o644);
    },
  ],
  [
    "0755 restore directory",
    async (fixture: Awaited<ReturnType<typeof stateFixture>>) => {
      await privateFile(fixture.path, serializeRestoreState(fixture.state));
      await chmod(dirname(fixture.path), 0o755);
    },
  ],
  [
    "wrong owner",
    async (fixture: Awaited<ReturnType<typeof stateFixture>>) => {
      await privateFile(fixture.path, serializeRestoreState(fixture.state));
      fileAttack.nonOwnerPath = fixture.path;
    },
  ],
] as const)("rejects %s", async (_name, prepare) => {
  const fixture = await stateFixture();
  await prepare(fixture);
  await expect(readRestoreState(fixture.options)).rejects.toThrow(/^Invalid MCP restore state$/);
});

test("rejects concurrent state replacement", async () => {
  const fixture = await stateFixture();
  await privateFile(fixture.path, serializeRestoreState(fixture.state));
  fileAttack.replaceAfterRead = { path: fixture.path, moved: `${fixture.path}.old` };
  await expect(readRestoreState(fixture.options)).rejects.toThrow(/^Invalid MCP restore state$/);
});

test("accepts Windows private reads and unchanged state planning", async () => {
  const fixture = await stateFixture();
  const content = serializeRestoreState(fixture.state);
  await privateFile(fixture.path, content, 0o644);
  await chmod(dirname(fixture.path), 0o755);
  fileAttack.nonOwnerPath = fixture.path;

  await withWindowsPlatform(async () => {
    const stored = await readRestoreState(fixture.options);
    expect(stored?.state).toEqual(fixture.state);
    expect(
      planRestoreStateChange({
        home: fixture.home,
        configPath: fixture.configPath,
        backupKey: fixture.configPath,
        before: { ...stored!.snapshot, mode: 0o666 },
        state: fixture.state,
      }),
    ).toBeUndefined();
  });
});

test("serializes sorted records and fingerprints only installed policy bytes", async () => {
  const home = await temporaryDirectory();
  const fixture = stateValue(home, join(home, "project"), join(home, "config.json"));
  const second = structuredClone(fixture.servers[0]!);
  second.name = "alpha";
  second.policy.path = join(home, ".mcp-restrictor", "policies", "codex", "alpha.yaml");
  fixture.servers.unshift(second);
  const serialized = serializeRestoreState(fixture);
  expect(JSON.parse(serialized).servers.map((server: { name: string }) => server.name)).toEqual([
    "alpha",
    "files",
  ]);
  expect(serialized).not.toContain('"originalSha256"');
  expect(policyFingerprint("é", 0o600)).toEqual({ sha256: sha256("é"), size: 2, mode: 0o600 });
});

test("preserves a literal created marker in restore-state version 1", async () => {
  const fixture = await stateFixture();
  fixture.state.servers[0]!.created = true;
  const content = serializeRestoreState(fixture.state);
  await privateFile(fixture.path, content);

  await expect(readRestoreState(fixture.options)).resolves.toMatchObject({
    state: { version: 1, servers: [{ created: true }] },
  });
});

test("matches policy fingerprints by bytes, size, and mode", async () => {
  const root = await temporaryDirectory();
  const snapshot = fakeSnapshot(join(root, "policy.yaml"), "policy", 0o600);
  const fingerprint = policyFingerprint(snapshot.content, snapshot.mode);
  expect(matchesFingerprint(snapshot, fingerprint)).toBe(true);
  expect(matchesFingerprint({ ...snapshot, content: "changed" }, fingerprint)).toBe(false);
  expect(matchesFingerprint({ ...snapshot, mode: 0o640 }, fingerprint)).toBe(false);
});

test("plans one private write, delete, or no-op for one config state file", async () => {
  const home = await temporaryDirectory();
  const configPath = join(home, "config.json");
  const path = restoreStatePath(home, configPath);
  const state = stateValue(home, join(home, "project"), configPath);
  const content = serializeRestoreState(state);
  const v2Content = serializeRestoreState({ ...state, version: 2 });
  const before = fakeSnapshot(path, content, 0o600);
  expect(planRestoreStateChange({ home, configPath, backupKey: configPath, state })).toEqual({
    path,
    content: v2Content,
    mode: 0o600,
    backupKey: configPath,
    private: true,
  });
  expect(
    planRestoreStateChange({ home, configPath, backupKey: configPath, before, state }),
  ).toBeUndefined();
  expect(planRestoreStateChange({ home, configPath, backupKey: configPath, before })).toEqual({
    delete: true,
    path,
    before,
    backupKey: configPath,
    private: true,
  });
  expect(planRestoreStateChange({ home, configPath, backupKey: configPath })).toBeUndefined();
});

test.each([
  [
    "newest matching source",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      await legacyBackup(fixture, "2026-08-10T01-00-00.000Z-old", fixture.nativeSource);
      await legacyBackup(fixture, "2026-08-11T01-00-00.000Z-new", fixture.newerNativeSource);
      const result = await findLegacyRestoreEntry(fixture.options);
      expect(result).toEqual({ name: "first", originalSource: fixture.newerNativeSource });
    },
  ],
  [
    "older native source after wrapper",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      await legacyBackup(fixture, "2026-08-11T01-00-00.000Z-new", fixture.currentSource);
      await legacyBackup(fixture, "2026-08-10T01-00-00.000Z-old", fixture.nativeSource);
      await expect(findLegacyRestoreEntry(fixture.options)).resolves.toEqual({
        name: "first",
        originalSource: fixture.nativeSource,
      });
    },
  ],
  [
    "unrelated server backup",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      await legacyBackup(fixture, "2026-08-11T01-00-00.000Z-new", fixture.unrelatedSource);
      await expect(findLegacyRestoreEntry(fixture.options)).resolves.toBeUndefined();
    },
  ],
  [
    "semantic mismatch",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      await legacyBackup(fixture, "2026-08-11T01-00-00.000Z-new", fixture.mismatchedSource);
      await expect(findLegacyRestoreEntry(fixture.options)).resolves.toBeUndefined();
    },
  ],
  [
    "malformed config",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      await legacyBackup(fixture, "2026-08-11T01-00-00.000Z-new", "secret malformed config");
      await expect(findLegacyRestoreEntry(fixture.options)).resolves.toBeUndefined();
    },
  ],
  [
    "missing file",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      await mkdir(legacyStamp(fixture, "2026-08-11T01-00-00.000Z-new"), {
        recursive: true,
        mode: 0o700,
      });
      await expect(findLegacyRestoreEntry(fixture.options)).resolves.toBeUndefined();
    },
  ],
  [
    "invalid stamp name",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      await legacyBackup(fixture, "secret-invalid-stamp", fixture.nativeSource);
      await expect(findLegacyRestoreEntry(fixture.options)).resolves.toBeUndefined();
    },
  ],
  [
    "invalid calendar timestamp",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      await legacyBackup(fixture, "9999-99-99T99-99-99.999Z-invalid", fixture.nativeSource);
      await expect(findLegacyRestoreEntry(fixture.options)).resolves.toBeUndefined();
    },
  ],
] as const)("legacy lookup: %s", async (_name, prepare) => {
  const fixture = await legacyFixture();
  await prepare(fixture);
});

test.each([
  [
    "symlinked group",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      const external = join(fixture.home, "external");
      await privateFile(join(external, basename(fixture.configPath)), fixture.nativeSource);
      await mkdir(dirname(fixture.groupPath), { recursive: true, mode: 0o700 });
      await chmod(dirname(fixture.groupPath), 0o700);
      await symlink(external, fixture.groupPath);
    },
  ],
  [
    "symlinked stamp",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      const external = join(fixture.home, "external-stamp");
      await privateFile(join(external, basename(fixture.configPath)), fixture.nativeSource);
      await mkdir(fixture.groupPath, { recursive: true, mode: 0o700 });
      await chmod(fixture.groupPath, 0o700);
      await symlink(external, legacyStamp(fixture, "2026-08-11T01-00-00.000Z-new"));
    },
  ],
  [
    "symlinked file",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      const external = join(fixture.home, "secret-sentinel.json");
      await privateFile(external, "secret sentinel");
      const stamp = legacyStamp(fixture, "2026-08-11T01-00-00.000Z-new");
      await mkdir(stamp, { recursive: true, mode: 0o700 });
      await symlink(external, join(stamp, basename(fixture.configPath)));
    },
  ],
] as const)("legacy lookup rejects %s without leaking backup contents", async (_name, prepare) => {
  const fixture = await legacyFixture();
  await prepare(fixture);
  await expect(findLegacyRestoreEntry(fixture.options)).resolves.toBeUndefined();
});

test.each([
  [
    "wrong mode",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      await legacyBackup(fixture, "2026-08-11T01-00-00.000Z-new", fixture.nativeSource, 0o644);
    },
  ],
  [
    "wrong owner",
    async (fixture: Awaited<ReturnType<typeof legacyFixture>>) => {
      await legacyBackup(fixture, "2026-08-11T01-00-00.000Z-new", fixture.nativeSource);
      fileAttack.nonOwnerPath = join(
        legacyStamp(fixture, "2026-08-11T01-00-00.000Z-new"),
        basename(fixture.configPath),
      );
    },
  ],
] as const)("legacy lookup rejects %s", async (_name, prepare) => {
  if (process.platform === "win32" || typeof process.getuid !== "function") return;
  const fixture = await legacyFixture();
  await prepare(fixture);
  await expect(findLegacyRestoreEntry(fixture.options)).resolves.toBeUndefined();
});

test("legacy lookup rejects external adapters", async () => {
  const fixture = await legacyFixture();
  const external = { ...claudeAdapter, id: "external" } as ClientAdapter;
  await legacyBackup(fixture, "2026-08-11T01-00-00.000Z-new", fixture.nativeSource);
  await expect(
    findLegacyRestoreEntry({ ...fixture.options, adapter: external }),
  ).resolves.toBeUndefined();
});

test("legacy lookup falls back past an unsafe newest stamp", async () => {
  const fixture = await legacyFixture();
  await legacyBackup(fixture, "2026-08-10T01-00-00.000Z-old", fixture.nativeSource);
  const external = join(fixture.home, "unsafe-newest");
  await privateFile(join(external, basename(fixture.configPath)), "secret sentinel");
  await mkdir(fixture.groupPath, { recursive: true, mode: 0o700 });
  await chmod(fixture.groupPath, 0o700);
  await symlink(external, legacyStamp(fixture, "2026-08-11T01-00-00.000Z-new"));

  const publicOutput: string[] = [];
  let result: unknown;
  const captured = capturePublicOutput();
  try {
    result = await findLegacyRestoreEntry(fixture.options);
    publicOutput.push(JSON.stringify(result));
  } catch (error) {
    publicOutput.push(String(error));
  } finally {
    captured.restore();
  }
  expect(result).toEqual({ name: "first", originalSource: fixture.nativeSource });
  expect(`${publicOutput.join(" ")} ${captured.text()}`).not.toContain("secret sentinel");
});

test("legacy lookup chooses the deterministic newest duplicate match", async () => {
  const fixture = await legacyFixture();
  await legacyBackup(fixture, "2026-08-11T01-00-00.000Z-a", fixture.nativeSource);
  await legacyBackup(fixture, "2026-08-11T01-00-00.000Z-b", fixture.newerNativeSource);
  await expect(findLegacyRestoreEntry(fixture.options)).resolves.toEqual({
    name: "first",
    originalSource: fixture.newerNativeSource,
  });
});

test("legacy lookup rejects an external clone retaining a built-in ID", async () => {
  const fixture = await legacyFixture();
  const first = createAdapterRegistry([{ ...claudeAdapter } as ClientAdapter]).available[0]!;
  const external = createAdapterRegistry([first]).available[0]!;
  await legacyBackup(fixture, "2026-08-11T01-00-00.000Z-new", fixture.nativeSource);
  await expect(
    findLegacyRestoreEntry({
      ...fixture.options,
      adapter: external,
      loaded: { ...fixture.options.loaded, adapter: external },
    }),
  ).resolves.toBeUndefined();
});

async function legacyFixture() {
  const home = await temporaryDirectory();
  const configPath = join(home, ".claude.json");
  const projectRoot = join(home, "project");
  const context: ClientLoadContext = {
    home,
    projectRoot,
    cwd: projectRoot,
    environment: {},
  };
  const policy = join(projectRoot, "policy.yaml");
  const currentSource = JSON.stringify({
    mcpServers: {
      first: { command: "mcp-restrictor", args: ["--policy", policy, "--", "node", "first.mjs"] },
    },
  });
  const nativeSource = JSON.stringify({
    mcpServers: { first: { command: "node", args: ["first.mjs"] } },
  });
  const newerNativeSource = JSON.stringify(
    { mcpServers: { first: { command: "node", args: ["first.mjs"] } } },
    null,
    2,
  );
  const mismatchedSource = JSON.stringify({
    mcpServers: { first: { command: "node", args: ["other.mjs"] } },
  });
  const unrelatedSource = JSON.stringify({
    mcpServers: { second: { command: "node", args: ["second.mjs"] } },
  });
  const config = parseClaudeConfig({
    path: configPath,
    scope: "user",
    source: currentSource,
    projectRoot,
    environment: {},
  });
  const snapshot = fakeSnapshot(configPath, currentSource, 0o600);
  const loaded: LoadedConfig = { config, snapshot, adapter: claudeAdapter };
  const server = config.servers[0]!;
  const groupPath = join(home, ".mcp-restrictor", "backups", sha256(resolve(configPath)));
  return {
    home,
    configPath,
    groupPath,
    currentSource,
    nativeSource,
    newerNativeSource,
    mismatchedSource,
    unrelatedSource,
    options: { home, adapter: claudeAdapter, loaded, server, context },
  };
}

function legacyStamp(fixture: Awaited<ReturnType<typeof legacyFixture>>, stamp: string): string {
  return join(fixture.groupPath, stamp);
}

async function legacyBackup(
  fixture: Awaited<ReturnType<typeof legacyFixture>>,
  stamp: string,
  content: string,
  mode = 0o600,
): Promise<void> {
  await privateFile(join(legacyStamp(fixture, stamp), basename(fixture.configPath)), content, mode);
}

function capturePublicOutput(): { text(): string; restore(): void } {
  const chunks: string[] = [];
  const capture = (chunk: string | Uint8Array, ...args: unknown[]): boolean => {
    chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8"));
    const callback = args.find((value) => typeof value === "function") as (() => void) | undefined;
    callback?.();
    return true;
  };
  const stdout = process.stdout.write;
  const stderr = process.stderr.write;
  process.stdout.write = capture as typeof process.stdout.write;
  process.stderr.write = capture as typeof process.stderr.write;

  const methods = ["debug", "error", "info", "log", "warn"] as const;
  const consoleOutput = console as unknown as Record<
    (typeof methods)[number],
    (...args: unknown[]) => void
  >;
  const originals = methods.map((method) => consoleOutput[method]);
  for (const method of methods) {
    consoleOutput[method] = (...args) => chunks.push(args.map(String).join(" "));
  }
  return {
    text: () => chunks.join(""),
    restore: () => {
      process.stdout.write = stdout;
      process.stderr.write = stderr;
      methods.forEach((method, index) => {
        consoleOutput[method] = originals[index]!;
      });
    },
  };
}

async function stateFixture(createRestoreDirectory = true) {
  const home = await temporaryDirectory();
  const configPath = join(home, "config.json");
  const projectRoot = join(home, "project");
  const path = restoreStatePath(home, configPath);
  if (createRestoreDirectory) {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    await chmod(dirname(path), 0o700);
  }
  return {
    home,
    configPath,
    path,
    state: stateValue(home, projectRoot, configPath),
    options: { home, adapterId: "codex", configPath, projectRoot },
  };
}

function stateValue(home: string, projectRoot: string, configPath: string): RestoreStateV1 {
  return {
    version: 1,
    adapterId: "codex",
    configPath: resolve(configPath),
    servers: [
      {
        name: "files",
        scope: "user",
        projectRoot: resolve(projectRoot),
        originalSource: "original source",
        installedSource: "installed source",
        policy: {
          path: join(home, ".mcp-restrictor", "policies", "codex", "files.yaml"),
          before: { content: "old policy", mode: 0o640 },
          installed: policyFingerprint("new policy", 0o600),
        },
        oauthProfileId: "11111111-1111-4111-8111-111111111111",
      },
    ],
  };
}

function stateValueV2(home: string, state: RestoreStateV1) {
  const server = structuredClone(state.servers[0]!);
  server.created = true;
  return {
    ...structuredClone(state),
    version: 2 as const,
    servers: [
      {
        ...server,
        route: {
          path: routePath(home, {
            adapterId: state.adapterId,
            scope: server.scope,
            configPath: state.configPath,
            projectRoot: server.projectRoot,
            serverName: server.name,
          }),
          installed: policyFingerprint("route", 0o600),
        },
      },
    ],
  };
}

function routeState(path: string) {
  return { path, installed: policyFingerprint("route", 0o600) };
}

function makeProjectScope(state: RestoreStateV1, projectRoot?: string): void {
  const server = state.servers[0]!;
  server.scope = "project";
  server.projectRoot = resolve(projectRoot ?? server.projectRoot);
  server.policy.path = join(
    server.projectRoot,
    ".mcp-restrictor",
    "policies",
    "codex",
    "files.yaml",
  );
}

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-restore-state-")));
  temporaryDirectories.push(path);
  return path;
}

async function privateFile(path: string, content: string, mode = 0o600): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await chmod(dirname(path), 0o700);
  await writeFile(path, content, { mode });
  await chmod(path, mode);
}

async function withWindowsPlatform<T>(operation: () => Promise<T>): Promise<T> {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  const getuid = Object.getOwnPropertyDescriptor(process, "getuid");
  Object.defineProperty(process, "platform", { ...platform, value: "win32" });
  Object.defineProperty(process, "getuid", { configurable: true, value: undefined });
  try {
    return await operation();
  } finally {
    Object.defineProperty(process, "platform", platform);
    if (getuid) Object.defineProperty(process, "getuid", getuid);
    else delete (process as Partial<NodeJS.Process>).getuid;
  }
}

function fakeSnapshot(path: string, content: string, mode: number): FileSnapshot {
  return { path, content, mode, size: Buffer.byteLength(content), mtimeMs: 1, dev: 1, ino: 1 };
}
