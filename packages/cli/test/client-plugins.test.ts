import {
  execFile as execFileCallback,
  spawn,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, relative } from "node:path";
import { createInterface } from "node:readline";
import { promisify } from "node:util";
import { afterEach, expect, test, vi } from "vitest";
import {
  clientPluginsRoot,
  installClientAdapter,
  listClientAdapters,
  loadInstalledClientAdapters,
  removeClientAdapter,
  resolveNpmCommand,
  withInstalledClientAdapters,
} from "../src/client-plugins.ts";
import { createAdapterRegistry } from "../src/setup/adapters.ts";
import {
  CLIENT_ADAPTER_INSTALLATION_FAILED_MESSAGE,
  CLIENT_ADAPTER_LOAD_FAILURE,
  CLIENT_ADAPTER_NOT_INSTALLED_MESSAGE,
  INVALID_CLIENT_ADAPTER_FILE_MESSAGE,
  INVALID_CLIENT_ADAPTER_GENERATION_MESSAGE,
  INVALID_CLIENT_ADAPTER_METADATA_MESSAGE,
} from "../src/client-plugins/constants.ts";

const fileOperations = vi.hoisted(() => ({
  events: [] as string[],
  renameFailures: [] as Array<{
    fromIncludes: string;
    to?: string;
    toIncludes?: string;
    error: Error;
    after?: boolean;
  }>,
  rmFailureIncludes: [] as string[],
  rmBarrier: undefined as
    | {
        pathIncludes: string;
        arrived(path: string): void;
        wait: Promise<void>;
      }
    | undefined,
  lstatFailures: new Map<string, Array<Error | undefined>>(),
  openFailureIncludes: [] as string[],
  syncFailurePath: undefined as string | undefined,
  unlinkFailures: new Map<string, Error[]>(),
  promotionBarrier: undefined as
    | {
        from?: string;
        to?: string;
        after?: boolean;
        arrived(): void;
        wait: Promise<void>;
      }
    | undefined,
  registryHandoff: undefined as
    | {
        path: string;
        released(): void;
        acquired(): void;
        waitForAcquire: Promise<void>;
      }
    | undefined,
  reportedFileMode: undefined as number | undefined,
  rejectWindowsReadOnlySync: false,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  const withReportedMode = <T extends { isFile(): boolean; mode: number }>(stat: T): T => {
    if (stat.isFile() && fileOperations.reportedFileMode !== undefined) {
      Object.defineProperty(stat, "mode", {
        value: (stat.mode & ~0o7777) | fileOperations.reportedFileMode,
      });
    }
    return stat;
  };
  return {
    ...actual,
    lstat: async (path: string) => {
      const failure = fileOperations.lstatFailures.get(path)?.shift();
      if (failure) throw failure;
      return withReportedMode(await actual.lstat(path));
    },
    link: async (from: string, to: string) => {
      await actual.link(from, to);
      if (fileOperations.registryHandoff?.path === to) {
        fileOperations.registryHandoff.acquired();
      }
    },
    open: async (...args: Parameters<typeof actual.open>) => {
      const [path, flags] = args;
      const failureIndex = fileOperations.openFailureIncludes.findIndex((part) =>
        String(path).includes(part),
      );
      if (failureIndex >= 0) {
        fileOperations.openFailureIncludes.splice(failureIndex, 1);
        throw new Error("injected open failure");
      }
      const handle = await actual.open(...args);
      const stat = handle.stat.bind(handle);
      handle.stat = (async () => withReportedMode(await stat())) as typeof handle.stat;
      const sync = handle.sync.bind(handle);
      handle.sync = async () => {
        fileOperations.events.push(`sync:${path}`);
        if (fileOperations.rejectWindowsReadOnlySync && process.platform === "win32") {
          const opened = await handle.stat();
          if (opened.isDirectory()) {
            throw Object.assign(new Error("injected Windows directory sync failure"), {
              code: "EINVAL",
            });
          }
          const writable =
            typeof flags === "string"
              ? flags.includes("+") || flags.startsWith("w") || flags.startsWith("a")
              : typeof flags === "number" &&
                (flags & (constants.O_WRONLY | constants.O_RDWR)) !== 0;
          if (!writable) {
            throw Object.assign(new Error("injected Windows read-only file sync failure"), {
              code: "EBADF",
            });
          }
        }
        if (fileOperations.syncFailurePath === path) {
          fileOperations.syncFailurePath = undefined;
          throw new Error("injected staged payload sync failure");
        }
        await sync();
      };
      return handle;
    },
    rename: async (from: string, to: string) => {
      fileOperations.events.push(`rename:${from}:${to}`);
      const failureIndex = fileOperations.renameFailures.findIndex(
        (failure) =>
          from.includes(failure.fromIncludes) &&
          (failure.to === undefined || failure.to === to) &&
          (failure.toIncludes === undefined || to.includes(failure.toIncludes)),
      );
      if (failureIndex >= 0) {
        const [failure] = fileOperations.renameFailures.splice(failureIndex, 1);
        if (failure!.after) await actual.rename(from, to);
        throw failure!.error;
      }
      const barrier = fileOperations.promotionBarrier;
      if (
        barrier &&
        (barrier.from === undefined ? from.includes(".stage-") : barrier.from === from) &&
        (barrier.to === undefined || barrier.to === to)
      ) {
        fileOperations.promotionBarrier = undefined;
        if (barrier.after) await actual.rename(from, to);
        barrier.arrived();
        await barrier.wait;
        if (barrier.after) return;
      }
      await actual.rename(from, to);
    },
    rm: async (path: string, options?: Parameters<typeof actual.rm>[1]) => {
      fileOperations.events.push(`rm:${path}`);
      const barrier = fileOperations.rmBarrier;
      if (barrier && path.includes(barrier.pathIncludes)) {
        fileOperations.rmBarrier = undefined;
        barrier.arrived(path);
        await barrier.wait;
      }
      const failureIndex = fileOperations.rmFailureIncludes.findIndex((part) =>
        path.includes(part),
      );
      if (failureIndex >= 0) {
        fileOperations.rmFailureIncludes.splice(failureIndex, 1);
        throw new Error("injected cleanup failure");
      }
      await actual.rm(path, options);
    },
    unlink: async (path: string) => {
      fileOperations.events.push(`unlink:${path}`);
      const failure = fileOperations.unlinkFailures.get(path)?.shift();
      if (failure) throw failure;
      await actual.unlink(path);
      const handoff = fileOperations.registryHandoff;
      if (handoff?.path === path) {
        handoff.released();
        await handoff.waitForAcquire;
        fileOperations.registryHandoff = undefined;
      }
    },
  };
});

const temporaryDirectories: string[] = [];
const runFile = promisify(execFileCallback);

afterEach(async () => {
  fileOperations.events.length = 0;
  fileOperations.renameFailures.length = 0;
  fileOperations.rmFailureIncludes.length = 0;
  fileOperations.rmBarrier = undefined;
  fileOperations.lstatFailures.clear();
  fileOperations.openFailureIncludes.length = 0;
  fileOperations.syncFailurePath = undefined;
  fileOperations.unlinkFailures.clear();
  fileOperations.promotionBarrier = undefined;
  fileOperations.registryHandoff = undefined;
  fileOperations.reportedFileMode = undefined;
  fileOperations.rejectWindowsReadOnlySync = false;
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  );
});

test("shares stable client adapter failure messages", () => {
  expect([
    CLIENT_ADAPTER_LOAD_FAILURE,
    CLIENT_ADAPTER_INSTALLATION_FAILED_MESSAGE,
    CLIENT_ADAPTER_NOT_INSTALLED_MESSAGE,
    INVALID_CLIENT_ADAPTER_FILE_MESSAGE,
    INVALID_CLIENT_ADAPTER_GENERATION_MESSAGE,
    INVALID_CLIENT_ADAPTER_METADATA_MESSAGE,
  ]).toEqual([
    "client adapter failed to load",
    "client adapter installation failed",
    "client adapter is not installed",
    "Invalid client adapter file",
    "Invalid client adapter generation",
    "Invalid client adapter metadata",
  ]);
});

test("locates installed client adapters below the supplied home", () => {
  expect(clientPluginsRoot("/home/fixture")).toBe("/home/fixture/.mcp-restrictor/client-plugins");
});

test("loads valid siblings while sanitizing every broken package", async () => {
  const home = await temporaryDirectory();
  const valid = await writePlugin(home, {
    packageName: "fixture-valid",
    id: "valid-client",
    label: "Valid client",
  });
  await writePlugin(home, {
    packageName: "@fixture/api-two",
    id: "api-two",
    manifestApiVersion: 2,
  });
  await writePlugin(home, {
    packageName: "fixture-invalid-id",
    id: "Invalid",
  });
  await writePlugin(home, {
    packageName: "fixture-named-only",
    id: "named-only",
    entrySource: "export const adapter = {};\n",
  });
  await writePlugin(home, {
    packageName: "fixture-undefined-default",
    id: "undefined-default",
    entrySource: "export default undefined;\n",
  });
  await writePlugin(home, {
    packageName: "@fixture/traversal",
    id: "traversal",
    clientAdapter: "../../../outside.js",
  });
  await writePlugin(home, {
    packageName: "@fixture/absolute",
    id: "absolute",
    clientAdapter: join(home, "secret-entry.js"),
  });
  const malformed = await writePlugin(home, {
    packageName: "@fixture/malformed",
    id: "malformed",
  });
  await writeFile(malformed.manifestPath, '{"name":"manifest-secret"');
  await writePlugin(home, {
    packageName: "fixture-rejects-import",
    id: "rejects-import",
    entrySource: "throw new Error('import-secret-9a87');\n",
  });
  const missingMetadata = await writePlugin(home, {
    packageName: "@fixture/missing-metadata",
    id: "missing-metadata",
    activeName: "directory-secret-7b42",
  });
  await unlink(missingMetadata.metadataPath);
  const missingManifest = await writePlugin(home, {
    packageName: "@fixture/missing-manifest",
    id: "missing-manifest",
  });
  await unlink(missingManifest.manifestPath);

  const result = await loadInstalledClientAdapters({ home });

  expect(
    result.adapters.map(({ packageName, adapter }) => ({
      packageName,
      id: adapter.id,
      label: adapter.label,
    })),
  ).toEqual([
    {
      packageName: "fixture-valid",
      id: "valid-client",
      label: "Valid client",
    },
  ]);
  expect(result.unavailable).toEqual([
    { packageName: "@fixture/absolute", reason: "client adapter failed to load" },
    { packageName: "@fixture/api-two", reason: "client adapter failed to load" },
    { packageName: "@fixture/malformed", reason: "client adapter failed to load" },
    { packageName: "@fixture/missing-manifest", reason: "client adapter failed to load" },
    { packageName: "@fixture/traversal", reason: "client adapter failed to load" },
    { packageName: "unknown client adapter", reason: "client adapter failed to load" },
    { packageName: "fixture-invalid-id", reason: "client adapter failed to load" },
    { packageName: "fixture-named-only", reason: "client adapter failed to load" },
    { packageName: "fixture-rejects-import", reason: "client adapter failed to load" },
    { packageName: "fixture-undefined-default", reason: "client adapter failed to load" },
  ]);
  const serialized = JSON.stringify(result.unavailable);
  expect(serialized).not.toContain(home);
  expect(serialized).not.toContain("directory-secret-7b42");
  expect(serialized).not.toContain("manifest-secret");
  expect(serialized).not.toContain("import-secret-9a87");
  expect(await readFile(valid.metadataPath, "utf8")).toContain("fixture-valid");
});

test("requires exact private metadata and one matching canonical dependency identity", async () => {
  const home = await temporaryDirectory();
  const looseMode = await writePlugin(home, {
    packageName: "@fixture/loose-mode",
    id: "loose-mode",
  });
  await chmod(looseMode.metadataPath, 0o644);
  await writePlugin(home, {
    packageName: "@fixture/extra-metadata",
    id: "extra-metadata",
    metadata: {
      packageName: "@fixture/extra-metadata",
      version: "1.2.3",
      requestedSpec: "@fixture/extra-metadata@1.2.3",
      extra: "metadata-secret",
    },
  });
  await writePlugin(home, {
    packageName: "@fixture/alias",
    manifestName: "@fixture/real-package",
    id: "alias",
  });
  await writePlugin(home, {
    packageName: "@fixture/root-mismatch",
    dependencyName: "@fixture/other",
    id: "root-mismatch",
  });
  await writePlugin(home, {
    packageName: "@fixture/two-dependencies",
    id: "two-dependencies",
    extraDependency: "@fixture/extra",
  });
  await writePlugin(home, {
    packageName: "@fixture/version-mismatch",
    id: "version-mismatch",
    metadataVersion: "9.9.9",
  });
  await writePlugin(home, {
    packageName: "Uppercase",
    id: "uppercase",
  });
  await writePlugin(home, {
    packageName: "a".repeat(215),
    id: "too-long",
  });
  await writePlugin(home, {
    packageName: "@fixture/wrong-directory",
    activeName: "wrong-directory",
    id: "wrong-directory",
  });

  const result = await loadInstalledClientAdapters({ home });

  expect(result.adapters).toEqual([]);
  expect(result.unavailable).toEqual([
    { packageName: "@fixture/alias", reason: "client adapter failed to load" },
    { packageName: "@fixture/extra-metadata", reason: "client adapter failed to load" },
    { packageName: "@fixture/loose-mode", reason: "client adapter failed to load" },
    { packageName: "@fixture/root-mismatch", reason: "client adapter failed to load" },
    { packageName: "@fixture/two-dependencies", reason: "client adapter failed to load" },
    { packageName: "@fixture/version-mismatch", reason: "client adapter failed to load" },
    { packageName: "unknown client adapter", reason: "client adapter failed to load" },
    { packageName: "unknown client adapter", reason: "client adapter failed to load" },
    { packageName: "@fixture/wrong-directory", reason: "client adapter failed to load" },
  ]);
  expect(JSON.stringify(result.unavailable)).not.toContain("metadata-secret");
});

test("requires the pointer to name a regular canonical immutable generation", async () => {
  const home = await temporaryDirectory();
  const missing = await writePlugin(home, {
    packageName: "fixture-generation-missing",
    id: "generation-missing",
  });
  await rename(missing.generation, join(missing.prefix, "payload"));

  const extra = await writePlugin(home, {
    packageName: "fixture-generation-extra",
    id: "generation-extra",
  });
  await mkdir(join(extra.prefix, `.generation-${randomUUID()}`));

  const linked = await writePlugin(home, {
    packageName: "fixture-generation-link",
    id: "generation-link",
  });
  const outside = join(home, "outside-generation");
  await rename(linked.generation, outside);
  await symlink(outside, linked.generation, "dir");

  expect(await loadInstalledClientAdapters({ home })).toEqual({
    adapters: [],
    unavailable: [
      { packageName: "fixture-generation-extra", reason: "client adapter failed to load" },
      { packageName: "fixture-generation-link", reason: "client adapter failed to load" },
      { packageName: "fixture-generation-missing", reason: "client adapter failed to load" },
    ],
  });
});

test("requires an exact private regular generation pointer", async () => {
  const home = await temporaryDirectory();
  const extra = await writePlugin(home, {
    packageName: "fixture-pointer-extra",
    id: "pointer-extra",
  });
  await writeFile(
    join(extra.prefix, ".mcp-restrictor-client-generation.json"),
    JSON.stringify({ generation: basename(extra.generation), extra: true }),
    { mode: 0o600 },
  );

  const linked = await writePlugin(home, {
    packageName: "fixture-pointer-link",
    id: "pointer-link",
  });
  const linkedPointer = join(linked.prefix, ".mcp-restrictor-client-generation.json");
  const outsidePointer = join(home, "outside-generation-pointer");
  await writeFile(outsidePointer, JSON.stringify({ generation: basename(linked.generation) }), {
    mode: 0o600,
  });
  await unlink(linkedPointer);
  await symlink(outsidePointer, linkedPointer);

  if (process.platform !== "win32") {
    const loose = await writePlugin(home, {
      packageName: "fixture-pointer-loose",
      id: "pointer-loose",
    });
    await chmod(join(loose.prefix, ".mcp-restrictor-client-generation.json"), 0o644);
  }

  expect(await loadInstalledClientAdapters({ home })).toEqual({
    adapters: [],
    unavailable: [
      { packageName: "fixture-pointer-extra", reason: "client adapter failed to load" },
      { packageName: "fixture-pointer-link", reason: "client adapter failed to load" },
      ...(process.platform === "win32"
        ? []
        : [{ packageName: "fixture-pointer-loose", reason: "client adapter failed to load" }]),
    ],
  });
});

test("sweeps only exact unreferenced hidden module graphs", async () => {
  const home = await temporaryDirectory();
  const active = await writePlugin(home, {
    packageName: "fixture-sweep-active",
    id: "sweep-active",
  });
  const root = clientPluginsRoot(home);
  const staleGeneration = join(root, `.generation-${randomUUID()}`);
  const staleRuntime = join(root, `.runtime-${randomUUID()}`);
  const nearGeneration = join(root, ".generation-not-a-uuid");
  await mkdir(staleGeneration);
  await mkdir(staleRuntime);
  await mkdir(nearGeneration);
  const outside = join(home, "outside-sweep");
  await mkdir(outside);
  await writeFile(join(outside, "sentinel"), "untouched");
  const linkedGeneration = join(root, `.generation-${randomUUID()}`);
  await symlink(outside, linkedGeneration, "dir");

  expect(
    (await loadInstalledClientAdapters({ home })).adapters.map(({ adapter }) => adapter.id),
  ).toEqual(["sweep-active"]);

  await expect(lstat(staleGeneration)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(lstat(staleRuntime)).rejects.toMatchObject({ code: "ENOENT" });
  expect((await lstat(active.generation)).isDirectory()).toBe(true);
  expect((await lstat(nearGeneration)).isDirectory()).toBe(true);
  expect((await lstat(linkedGeneration)).isSymbolicLink()).toBe(true);
  expect(await readFile(join(outside, "sentinel"), "utf8")).toBe("untouched");
});

test("sweeps stale graphs before scoped adapter acquisition and releases its lease", async () => {
  const home = await temporaryDirectory();
  const active = await writePlugin(home, {
    packageName: "fixture-scoped-sweep",
    id: "scoped-sweep",
  });
  const root = clientPluginsRoot(home);
  const staleGeneration = join(root, `.generation-${randomUUID()}`);
  const staleRuntime = join(root, `.runtime-${randomUUID()}`);
  await mkdir(staleGeneration);
  await mkdir(staleRuntime);

  await withInstalledClientAdapters({ home }, async ({ adapters }) => {
    expect(adapters.map(({ adapter }) => adapter.id)).toEqual(["scoped-sweep"]);
    await expect(lstat(staleGeneration)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(staleRuntime)).rejects.toMatchObject({ code: "ENOENT" });
    expect((await readdir(root)).filter((name) => name.startsWith(".lease-"))).toHaveLength(1);
  });

  expect((await lstat(active.generation)).isDirectory()).toBe(true);
  expect((await readdir(root)).filter((name) => name.startsWith(".lease-"))).toEqual([]);
  expect((await readdir(root)).filter((name) => name.startsWith(".runtime-"))).toEqual([]);
});

test("a live private lease protects only its strict named graph", async () => {
  const home = await temporaryDirectory();
  const root = clientPluginsRoot(home);
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  const protectedName = `.generation-${randomUUID()}`;
  const protectedGraph = join(root, protectedName);
  const staleGraph = join(root, `.generation-${randomUUID()}`);
  await mkdir(protectedGraph);
  await mkdir(staleGraph);
  const lease = join(root, `.lease-${randomUUID()}`);
  await writeFile(lease, JSON.stringify({ version: 1, pid: process.pid, graph: protectedName }), {
    mode: 0o600,
  });

  await expect(listClientAdapters({ home })).resolves.toEqual([]);

  await expectPrivateFile(lease);
  expect((await lstat(protectedGraph)).isDirectory()).toBe(true);
  await expect(lstat(staleGraph)).rejects.toMatchObject({ code: "ENOENT" });
});

test.each([
  ["malformed JSON", "malformed"],
  ["traversal graph", "traversal"],
  ["symlink", "symlink"],
  ...(process.platform === "win32" ? [] : [["loose mode", "loose"] as const]),
] as const)("fails closed without exposing a %s lease", async (_label, kind) => {
  const home = await temporaryDirectory();
  const root = clientPluginsRoot(home);
  await mkdir(root, { recursive: true, mode: 0o700 });
  await chmod(root, 0o700);
  const graph = join(root, `.generation-${randomUUID()}`);
  await mkdir(graph);
  const lease = join(root, `.lease-${randomUUID()}`);
  const valid = JSON.stringify({ version: 1, pid: process.pid, graph: basename(graph) });
  let outside: string | undefined;
  if (kind === "symlink") {
    outside = join(home, "outside-lease-sentinel");
    await writeFile(outside, valid, { mode: 0o600 });
    await symlink(outside, lease, "file");
  } else {
    const content =
      kind === "malformed"
        ? "{lease-sentinel"
        : kind === "traversal"
          ? JSON.stringify({ version: 1, pid: process.pid, graph: "../outside-lease-sentinel" })
          : valid;
    await writeFile(lease, content, { mode: kind === "loose" ? 0o644 : 0o600 });
  }

  await expect(listClientAdapters({ home })).resolves.toEqual([]);

  expect((await lstat(graph)).isDirectory()).toBe(true);
  expect((await lstat(lease)).isSymbolicLink()).toBe(kind === "symlink");
  if (outside) expect(await readFile(outside, "utf8")).toBe(valid);
});

test.sequential("protects a leased graph when PID liveness is indeterminate", async () => {
  const home = await temporaryDirectory();
  const root = clientPluginsRoot(home);
  await mkdir(root, { recursive: true, mode: 0o700 });
  const graph = join(root, `.generation-${randomUUID()}`);
  await mkdir(graph);
  await writeFile(
    join(root, `.lease-${randomUUID()}`),
    JSON.stringify({
      version: 1,
      pid: 424242,
      graph: basename(graph),
    }),
    { mode: 0o600 },
  );
  const kill = vi.spyOn(process, "kill").mockImplementation(() => {
    throw Object.assign(new Error("indeterminate PID"), { code: "EPERM" });
  });
  try {
    await expect(listClientAdapters({ home })).resolves.toEqual([]);
  } finally {
    kill.mockRestore();
  }
  expect((await lstat(graph)).isDirectory()).toBe(true);
});

test("rejects package, intermediate, and entry symlinks without affecting a valid sibling", async () => {
  const home = await temporaryDirectory();
  await writePlugin(home, {
    packageName: "fixture-sibling",
    id: "sibling",
  });

  const packageLink = await writePlugin(home, {
    packageName: "@fixture/package-link",
    id: "package-link",
  });
  const realPackage = join(home, "real-package-secret");
  await rename(packageLink.packagePath, realPackage);
  await symlink(realPackage, packageLink.packagePath, "dir");

  const intermediateLink = await writePlugin(home, {
    packageName: "@fixture/intermediate-link",
    id: "intermediate-link",
  });
  const realDist = join(home, "real-dist-secret");
  await rename(dirname(intermediateLink.entryPath), realDist);
  await symlink(realDist, dirname(intermediateLink.entryPath), "dir");

  const entryLink = await writePlugin(home, {
    packageName: "@fixture/entry-link",
    id: "entry-link",
  });
  const realEntry = join(home, "real-entry-secret.js");
  await rename(entryLink.entryPath, realEntry);
  await symlink(realEntry, entryLink.entryPath, "file");

  const result = await loadInstalledClientAdapters({ home });

  expect(result.adapters.map(({ adapter }) => adapter.id)).toEqual(["sibling"]);
  expect(result.unavailable).toEqual([
    { packageName: "@fixture/entry-link", reason: "client adapter failed to load" },
    { packageName: "@fixture/intermediate-link", reason: "client adapter failed to load" },
    { packageName: "@fixture/package-link", reason: "client adapter failed to load" },
  ]);
  expect(JSON.stringify(result.unavailable)).not.toMatch(/real-(?:package|dist|entry)-secret/);
});

test("reserves accepted external IDs and rejects only later duplicates", async () => {
  const home = await temporaryDirectory();
  await writePlugin(home, {
    packageName: "fixture-a-first",
    id: "duplicate",
    label: "First",
  });
  await writePlugin(home, {
    packageName: "fixture-z-second",
    id: "duplicate",
    label: "Second",
  });
  const loaded = await loadInstalledClientAdapters({ home });

  const registry = createAdapterRegistry([], loaded.adapters);

  expect(registry.available.map(({ label }) => label)).toEqual(["First"]);
  expect(registry.unavailable).toEqual([
    {
      packageName: "fixture-z-second",
      reason: "client adapter ID conflicts with another external",
    },
  ]);
});

test("lists installed adapters by canonical package name with sanitized statuses", async () => {
  const home = await temporaryDirectory();
  await writePlugin(home, {
    packageName: "fixture-z",
    version: "3.0.0",
    id: "client-z",
    label: "Client Z",
  });
  await writePlugin(home, {
    packageName: "fixture-b",
    version: "2.0.0",
    id: "client-b",
    entrySource: "throw new Error('list-import-secret');\n",
  });
  await writePlugin(home, {
    packageName: "fixture-a",
    version: "1.0.0",
    id: "shared-list-id",
    label: "Client A",
  });
  await writePlugin(home, {
    packageName: "fixture-duplicate",
    version: "4.0.0",
    id: "shared-list-id",
  });
  await writePlugin(home, {
    packageName: "fixture-built-in",
    version: "5.0.0",
    id: "claude",
  });
  const malformed = await writePlugin(home, {
    packageName: "fixture-malformed-list",
    id: "malformed-list",
  });
  await writeFile(malformed.metadataPath, "{metadata-secret");
  const metadataLink = await writePlugin(home, {
    packageName: "fixture-linked-metadata",
    id: "linked-metadata",
  });
  const outsideMetadata = join(home, "outside-metadata-secret");
  await writeFile(
    outsideMetadata,
    JSON.stringify({
      packageName: "fixture-linked-metadata",
      version: "8.0.0",
      requestedSpec: "fixture-linked-metadata@8.0.0",
    }),
    { mode: 0o600 },
  );
  await unlink(metadataLink.metadataPath);
  await symlink(outsideMetadata, metadataLink.metadataPath);

  const list = await listClientAdapters({ home });

  expect(list).toEqual([
    {
      packageName: "fixture-a",
      version: "1.0.0",
      id: "shared-list-id",
      label: "Client A",
      status: "available",
    },
    {
      packageName: "fixture-b",
      version: "2.0.0",
      status: "unavailable",
      reason: "client adapter failed to load",
    },
    {
      packageName: "fixture-built-in",
      version: "5.0.0",
      status: "unavailable",
      reason: "client adapter failed to load",
    },
    {
      packageName: "fixture-duplicate",
      version: "4.0.0",
      status: "unavailable",
      reason: "client adapter failed to load",
    },
    {
      packageName: "fixture-z",
      version: "3.0.0",
      id: "client-z",
      label: "Client Z",
      status: "available",
    },
    {
      packageName: "unknown client adapter",
      status: "unavailable",
      reason: "client adapter failed to load",
    },
    {
      packageName: "unknown client adapter",
      status: "unavailable",
      reason: "client adapter failed to load",
    },
  ]);
  expect(JSON.stringify(list)).not.toMatch(
    /list-import-secret|metadata-secret|outside-metadata-secret/,
  );
  expect(
    (await loadInstalledClientAdapters({ home })).adapters.map(({ packageName }) => packageName),
  ).toEqual(["fixture-a", "fixture-built-in", "fixture-duplicate", "fixture-z"]);
});

test("lists no adapters when the client plugin root does not exist", async () => {
  expect(await listClientAdapters({ home: await temporaryDirectory() })).toEqual([]);
});

test("removes an installed package named like a built-in by canonical package identity", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("claude", {
    home,
    execFile: fakeNpmInstall({ packageName: "claude", id: "not-claude" }),
  });

  await removeClientAdapter("claude", { home });

  expect(await loadInstalledClientAdapters({ home })).toEqual({ adapters: [], unavailable: [] });
  await expect(lstat(join(clientPluginsRoot(home), "claude"))).rejects.toMatchObject({
    code: "ENOENT",
  });
});

test("rejects a built-in-like package name without exact installed metadata", async () => {
  const home = await temporaryDirectory();
  const plugin = await writePlugin(home, {
    packageName: "fixture-remains",
    id: "remains",
  });
  const before = await snapshotTree(clientPluginsRoot(home));
  fileOperations.events.length = 0;

  await expect(removeClientAdapter("claude", { home })).rejects.toEqual(
    new Error("client adapter is not installed"),
  );

  expect(await snapshotTree(clientPluginsRoot(home))).toEqual(before);
  expect((await lstat(plugin.prefix)).isDirectory()).toBe(true);
  expect(
    fileOperations.events.filter((event) => event.startsWith("rename:") || event.startsWith("rm:")),
  ).toEqual([]);
});

test.each([
  "../x",
  "/absolute/client-adapter",
  "@fixture%2Fencoded",
  "@fixture%2fencoded",
  "claude",
  "codex",
  "opencode",
  "fixture-unknown",
])("rejects an invalid, built-in, or unknown removal without moving files: %s", async (name) => {
  const home = await temporaryDirectory();
  const plugin = await writePlugin(home, {
    packageName: "fixture-remains",
    id: "remains",
  });
  const before = await snapshotTree(clientPluginsRoot(home));
  fileOperations.events.length = 0;

  await expect(removeClientAdapter(name, { home })).rejects.toThrow();

  expect(await snapshotTree(clientPluginsRoot(home))).toEqual(before);
  expect((await lstat(plugin.prefix)).isDirectory()).toBe(true);
  expect(
    fileOperations.events.filter((event) => event.startsWith("rename:") || event.startsWith("rm:")),
  ).toEqual([]);
});

test("uses only exact trusted metadata as a removal mapping", async () => {
  const mismatchHome = await temporaryDirectory();
  const mismatch = await writePlugin(mismatchHome, {
    packageName: "fixture-metadata-mismatch",
    id: "metadata-mismatch",
  });
  await writeFile(
    mismatch.metadataPath,
    JSON.stringify({
      packageName: "fixture-other-name",
      version: "1.2.3",
      requestedSpec: "fixture-other-name@1.2.3",
    }),
    { mode: 0o600 },
  );

  await expect(removeClientAdapter("fixture-other-name", { home: mismatchHome })).rejects.toThrow();
  expect((await lstat(mismatch.prefix)).isDirectory()).toBe(true);

  const malformedHome = await temporaryDirectory();
  const malformed = await writePlugin(malformedHome, {
    packageName: "fixture-malformed-remove",
    id: "malformed-remove",
  });
  await writeFile(malformed.metadataPath, "{malformed-remove-secret");

  await expect(
    removeClientAdapter("fixture-malformed-remove", { home: malformedHome }),
  ).rejects.toThrow();
  expect((await lstat(malformed.prefix)).isDirectory()).toBe(true);

  const linkedHome = await temporaryDirectory();
  const linked = await writePlugin(linkedHome, {
    packageName: "fixture-linked-remove",
    id: "linked-remove",
  });
  const outside = join(linkedHome, "outside-remove-metadata");
  await writeFile(outside, await readFile(linked.metadataPath, "utf8"), { mode: 0o600 });
  await unlink(linked.metadataPath);
  await symlink(outside, linked.metadataPath);

  await expect(
    removeClientAdapter("fixture-linked-remove", { home: linkedHome }),
  ).rejects.toThrow();
  expect((await lstat(linked.prefix)).isDirectory()).toBe(true);
  expect(await readFile(outside, "utf8")).toContain("fixture-linked-remove");
});

test("rejects metadata whose package name does not match its encoded active basename", async () => {
  const home = await temporaryDirectory();
  const plugin = await writePlugin(home, {
    packageName: "fixture-encoded-mismatch",
    activeName: "fixture-wrong-basename",
    id: "encoded-mismatch",
  });

  await expect(removeClientAdapter("fixture-encoded-mismatch", { home })).rejects.toThrow();
  expect((await lstat(plugin.prefix)).isDirectory()).toBe(true);
});

test("renames an adapter inactive before deleting it and releases readers first", async () => {
  const home = await temporaryDirectory();
  const plugin = await writePlugin(home, {
    packageName: "@fixture/remove-me",
    id: "remove-me",
  });
  fileOperations.events.length = 0;
  const deletionArrived = deferred<string>();
  const releaseDeletion = deferred<void>();
  fileOperations.rmBarrier = {
    pathIncludes: ".removed-",
    arrived: (path) => deletionArrived.resolve(path),
    wait: releaseDeletion.promise,
  };

  const removal = removeClientAdapter("@fixture/remove-me", { home });
  const inactive = await deletionArrived.promise;

  expect(inactive).toMatch(
    new RegExp(`${escapeRegExp(clientPluginsRoot(home))}/\\.removed-[0-9a-f-]+$`),
  );
  await expect(lstat(plugin.prefix)).rejects.toMatchObject({ code: "ENOENT" });
  expect((await lstat(inactive)).isDirectory()).toBe(true);
  await expect(loadInstalledClientAdapters({ home })).resolves.toEqual({
    adapters: [],
    unavailable: [],
  });
  releaseDeletion.resolve();
  await expect(removal).resolves.toEqual({ warnings: [] });

  await expect(lstat(inactive)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(lstat(plugin.generation)).rejects.toMatchObject({ code: "ENOENT" });
  expect(fileOperations.events.filter((event) => event.startsWith("rm:"))).toEqual(
    expect.arrayContaining([`rm:${inactive}`, `rm:${plugin.generation}`]),
  );
});

test("keeps a removal logical and reports only fixed cleanup failure for its inactive sibling", async () => {
  const home = await temporaryDirectory();
  await writePlugin(home, {
    packageName: "fixture-remove-cleanup",
    id: "remove-cleanup",
  });
  const outside = join(home, "outside-removal-target");
  await mkdir(outside);
  await writeFile(join(outside, "sentinel"), "untouched");
  fileOperations.rmFailureIncludes.push(".removed-");

  await expect(removeClientAdapter("fixture-remove-cleanup", { home })).resolves.toEqual({
    warnings: ["inactive client adapter files require manual cleanup"],
  });

  expect(await loadInstalledClientAdapters({ home })).toEqual({ adapters: [], unavailable: [] });
  expect(await readFile(join(outside, "sentinel"), "utf8")).toBe("untouched");
  const removed = fileOperations.events.filter(
    (event) => event.startsWith("rm:") && event.includes(".removed-"),
  );
  expect(removed).toHaveLength(1);
  expect(removed[0]).toMatch(
    new RegExp(`^rm:${escapeRegExp(clientPluginsRoot(home))}/\\.removed-[0-9a-f-]+$`),
  );
});

test.each([
  ["before rename", false],
  ["after rename", true],
] as const)("restores the active adapter when removal fails %s", async (_label, after) => {
  const home = await temporaryDirectory();
  const plugin = await writePlugin(home, {
    packageName: "fixture-remove-rename-failure",
    id: "remove-rename-failure",
  });
  const before = await snapshotTree(plugin.prefix);
  fileOperations.renameFailures.push({
    fromIncludes: plugin.prefix,
    toIncludes: ".removed-",
    error: new Error("injected removal rename failure"),
    after,
  });

  await expect(removeClientAdapter("fixture-remove-rename-failure", { home })).rejects.toThrow(
    "injected removal rename failure",
  );

  expect(await snapshotTree(plugin.prefix)).toEqual(before);
  expect(
    (await readdir(clientPluginsRoot(home))).filter((name) => name.startsWith(".removed-")),
  ).toEqual([]);
});

test("restores the active adapter when removal directory sync fails", async () => {
  const home = await temporaryDirectory();
  const plugin = await writePlugin(home, {
    packageName: "fixture-remove-sync-failure",
    id: "remove-sync-failure",
  });
  const before = await snapshotTree(plugin.prefix);
  fileOperations.syncFailurePath = clientPluginsRoot(home);

  await expect(removeClientAdapter("fixture-remove-sync-failure", { home })).rejects.toThrow(
    "injected staged payload sync failure",
  );

  expect(await snapshotTree(plugin.prefix)).toEqual(before);
});

test("restores the active adapter when registry lock release fails after removal", async () => {
  const home = await temporaryDirectory();
  const plugin = await writePlugin(home, {
    packageName: "fixture-remove-release-failure",
    id: "remove-release-failure",
  });
  const before = await snapshotTree(plugin.prefix);
  fileOperations.unlinkFailures.set(join(clientPluginsRoot(home), "..registry.lock"), [
    new Error("injected removal lock release failure"),
  ]);

  await expect(removeClientAdapter("fixture-remove-release-failure", { home })).rejects.toThrow(
    "injected removal lock release failure",
  );

  expect(await snapshotTree(plugin.prefix)).toEqual(before);
  expect((await lstat(plugin.generation)).isDirectory()).toBe(true);
  expect(
    (await loadInstalledClientAdapters({ home })).adapters.map(({ adapter }) => adapter.id),
  ).toEqual(["remove-release-failure"]);
  expect(
    (await readdir(clientPluginsRoot(home))).filter((name) => name.startsWith(".removed-")),
  ).toEqual([]);
});

test("removes a new graph lease when registry lock release fails during loading", async () => {
  const home = await temporaryDirectory();
  const plugin = await writePlugin(home, {
    packageName: "fixture-load-lease-release-failure",
    id: "load-lease-release-failure",
  });
  const root = clientPluginsRoot(home);
  fileOperations.unlinkFailures.set(join(root, "..registry.lock"), [
    new Error("injected load lease lock release failure"),
  ]);

  await expect(loadInstalledClientAdapters({ home })).rejects.toThrow(
    "injected load lease lock release failure",
  );

  expect((await readdir(root)).filter((name) => name.startsWith(".lease-"))).toEqual([]);
  expect((await lstat(plugin.generation)).isDirectory()).toBe(true);
  expect(
    (await loadInstalledClientAdapters({ home })).adapters.map(({ adapter }) => adapter.id),
  ).toEqual(["load-lease-release-failure"]);
});

test.each(["lease creation", "registry release"] as const)(
  "does not retry a successful runtime after %s failure",
  async (failure) => {
    const home = await temporaryDirectory();
    const observation = join(home, "pending-runtime-evaluations");
    await writePlugin(home, {
      packageName: "fixture-pending-runtime",
      id: "pending-runtime",
      entrySource: `import { appendFileSync } from 'node:fs';
appendFileSync(${JSON.stringify(observation)}, 'evaluation\\n');
if (!decodeURIComponent(import.meta.url).includes('/.runtime-')) {
  throw new Error('original import fails');
}
${adapterModule("pending-runtime", "Pending runtime")}`,
    });
    const root = clientPluginsRoot(home);
    expect(await loadInstalledClientAdapters({ home })).toEqual({
      adapters: [],
      unavailable: [
        {
          packageName: "fixture-pending-runtime",
          reason: "client adapter failed to load",
        },
      ],
    });
    if (failure === "lease creation") {
      fileOperations.openFailureIncludes.push(".lease-");
    } else {
      fileOperations.unlinkFailures.set(join(root, "..registry.lock"), [
        new Error("injected pending runtime registry release failure"),
      ]);
    }

    await expect(loadInstalledClientAdapters({ home })).rejects.toThrow(
      failure === "lease creation"
        ? "client adapter lease failed"
        : "injected pending runtime registry release failure",
    );

    expect(await readFile(observation, "utf8")).toBe("evaluation\nevaluation\n");
    expect((await readdir(root)).filter((name) => name.startsWith(".runtime-"))).toEqual([]);
    expect((await readdir(root)).filter((name) => name.startsWith(".lease-"))).toEqual([]);
    expect(await loadInstalledClientAdapters({ home })).toEqual({
      adapters: [],
      unavailable: [
        {
          packageName: "fixture-pending-runtime",
          reason: "client adapter failed to load",
        },
      ],
    });
    expect(await readFile(observation, "utf8")).toBe("evaluation\nevaluation\n");
  },
);

test("serializes remove with install and leaves the later installed adapter active", async () => {
  const home = await temporaryDirectory();
  const plugin = await writePlugin(home, {
    packageName: "fixture-remove-install",
    version: "1.0.0",
    id: "remove-install-old",
  });
  const moved = deferred<void>();
  const releaseRemoval = deferred<void>();
  fileOperations.promotionBarrier = {
    from: plugin.prefix,
    after: true,
    arrived: () => moved.resolve(),
    wait: releaseRemoval.promise,
  };
  const removal = removeClientAdapter("fixture-remove-install", { home });
  await moved.promise;

  let npmStarted = false;
  const install = installClientAdapter("fixture-remove-install@2.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-remove-install",
      version: "2.0.0",
      id: "remove-install-new",
      installed: () => {
        npmStarted = true;
      },
    }),
  });
  await new Promise<void>((resolve) => setImmediate(resolve));
  expect(npmStarted).toBe(false);
  releaseRemoval.resolve();

  await Promise.all([removal, install]);
  expect(
    (await loadInstalledClientAdapters({ home })).adapters.map(({ adapter }) => adapter.id),
  ).toEqual(["remove-install-new"]);
  expect(
    (await readdir(clientPluginsRoot(home))).filter((name) => name.startsWith(".removed-")),
  ).toEqual([]);
});

test("serializes two removals of one package and removes it exactly once", async () => {
  const home = await temporaryDirectory();
  const plugin = await writePlugin(home, {
    packageName: "fixture-concurrent-remove",
    id: "concurrent-remove",
  });
  const moved = deferred<void>();
  const releaseFirst = deferred<void>();
  fileOperations.promotionBarrier = {
    from: plugin.prefix,
    after: true,
    arrived: () => moved.resolve(),
    wait: releaseFirst.promise,
  };
  const first = removeClientAdapter("fixture-concurrent-remove", { home });
  await moved.promise;
  let secondSettled = false;
  const secondRejection = expect(
    removeClientAdapter("fixture-concurrent-remove", { home }).finally(() => {
      secondSettled = true;
    }),
  ).rejects.toThrow("client adapter is not installed");
  await new Promise<void>((resolve) => setImmediate(resolve));
  expect(secondSettled).toBe(false);
  releaseFirst.resolve();

  await first;
  await secondRejection;
  expect(await loadInstalledClientAdapters({ home })).toEqual({ adapters: [], unavailable: [] });
});

test("installs every npm spec as one final argv element in a private staged prefix", async () => {
  const rows = [
    { spec: "-not-an-option", packageName: "fixture-dash", id: "dash" },
    { spec: "package name with spaces", packageName: "fixture-spaces", id: "spaces" },
    { spec: "file:/tmp/fixture package", packageName: "fixture-file", id: "file" },
    { spec: "@fixture/scoped@^1.2.0", packageName: "fixture-scoped", id: "scoped" },
    { spec: "fixture-range@>=1 <2", packageName: "fixture-range", id: "range" },
    { spec: "claude", packageName: "claude", id: "not-claude" },
  ] as const;

  for (const row of rows) {
    const home = await temporaryDirectory();
    const environment = { ...process.env };
    if (process.platform === "win32") {
      const npmCli = join(home, "npm-cli.js");
      await writeFile(npmCli, "/* fixture npm CLI */\n");
      environment.npm_execpath = npmCli;
    }
    const npm = await resolveNpmCommand(environment);
    const calls: ExecCall[] = [];
    const result = await installClientAdapter(row.spec, {
      home,
      environment,
      execFile: fakeNpmInstall({
        packageName: row.packageName,
        id: row.id,
        calls,
        inspectStage: async (prefix) => {
          await expectPrivateDirectory(prefix);
          await expectPrivateFile(join(prefix, "package.json"));
          expect(JSON.parse(await readFile(join(prefix, "package.json"), "utf8"))).toEqual({
            private: true,
          });
        },
      }),
    });

    const active = join(clientPluginsRoot(home), encodeURIComponent(row.packageName));
    expect(calls).toEqual([
      {
        file: npm.file,
        args: [
          ...npm.args,
          "install",
          "--ignore-scripts",
          "--save-exact",
          ...(process.platform === "win32"
            ? [
                "--package-lock=false",
                "--prefix",
                expect.stringContaining(`${join(clientPluginsRoot(home), ".stage-")}`),
              ]
            : []),
          "--",
          row.spec,
        ],
        cwd: expect.stringContaining(`${join(clientPluginsRoot(home), ".stage-")}`),
        shell: false,
      },
    ]);
    expect(result).toEqual({
      plugin: { packageName: row.packageName, version: "1.2.3", requestedSpec: row.spec },
      warnings: [],
    });
    const generation = await activeGenerationPath(active);
    await expectPrivateDirectory(clientPluginsRoot(home));
    await expectPrivateDirectory(active);
    await expectPrivateDirectory(generation);
    await expectPrivateFile(join(generation, "package.json"));
    await expectPrivateFile(join(active, ".mcp-restrictor-client-plugin.json"));
    await expectPrivateFile(join(active, ".mcp-restrictor-client-generation.json"));
    expect(await hiddenTransactionDirectories(home)).toEqual([]);
  }
});

test("runs a configured regular npm CLI through Node on Windows", async () => {
  const home = await temporaryDirectory();
  const npmCli = join(home, "private-tools", "npm-cli.js");
  await mkdir(dirname(npmCli), { recursive: true, mode: 0o700 });
  await chmod(dirname(npmCli), 0o700);
  await writeFile(npmCli, "/* fixture npm CLI */\n", { mode: 0o600 });
  await chmod(npmCli, 0o666);
  const calls: ExecCall[] = [];
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "win32" });
  try {
    await installClientAdapter("fixture-windows@1.0.0", {
      home,
      environment: { npm_execpath: npmCli },
      execFile: fakeNpmInstall({ packageName: "fixture-windows", id: "windows", calls }),
    });
  } finally {
    Object.defineProperty(process, "platform", platform);
  }

  expect(calls).toEqual([
    {
      file: process.execPath,
      args: [
        npmCli,
        "install",
        "--ignore-scripts",
        "--save-exact",
        "--package-lock=false",
        "--prefix",
        expect.stringContaining(join(clientPluginsRoot(home), ".stage-")),
        "--",
        "fixture-windows@1.0.0",
      ],
      cwd: expect.stringContaining(join(clientPluginsRoot(home), ".stage-")),
      shell: false,
    },
  ]);
  expect(calls[0]!.args[6]).toBe(calls[0]!.cwd);
});

test.sequential("installs and loads 0666-reported private adapter files on Windows", async () => {
  const home = await temporaryDirectory();
  const npmCli = join(home, "private-tools", "npm-cli.js");
  await mkdir(dirname(npmCli), { recursive: true, mode: 0o700 });
  await writeFile(npmCli, "/* fixture npm CLI */\n", { mode: 0o666 });
  await chmod(npmCli, 0o666);
  fileOperations.reportedFileMode = 0o666;

  await withProcessPlatform("win32", async () => {
    const install = fakeNpmInstall({
      packageName: "fixture-windows-private",
      id: "windows-private",
    });
    const result = await installClientAdapter("fixture-windows-private@1.0.0", {
      home,
      environment: { npm_execpath: npmCli },
      execFile: async (file, args, options) => {
        const installed = await install(file, args, options);
        await chmod(join(options.cwd, "package.json"), 0o666);
        return installed;
      },
    });
    const metadata = join(
      clientPluginsRoot(home),
      "fixture-windows-private",
      ".mcp-restrictor-client-plugin.json",
    );
    await chmod(metadata, 0o666);

    expect(result.plugin).toEqual({
      packageName: "fixture-windows-private",
      version: "1.2.3",
      requestedSpec: "fixture-windows-private@1.0.0",
    });
    expect(
      (await loadInstalledClientAdapters({ home })).adapters.map(({ adapter }) => adapter.id),
    ).toEqual(["windows-private"]);
  });
});

test.sequential("uses Windows-compatible handles to durably stage adapter files", async () => {
  const home = await temporaryDirectory();
  const npmCli = join(home, "private-tools", "npm-cli.js");
  await mkdir(dirname(npmCli), { recursive: true });
  await writeFile(npmCli, "/* fixture npm CLI */\n");
  fileOperations.rejectWindowsReadOnlySync = true;

  await withProcessPlatform("win32", async () => {
    await expect(
      installClientAdapter("fixture-windows-durable@1.0.0", {
        home,
        environment: { npm_execpath: npmCli },
        execFile: fakeNpmInstall({
          packageName: "fixture-windows-durable",
          id: "windows-durable",
        }),
      }),
    ).resolves.toMatchObject({
      plugin: { packageName: "fixture-windows-durable" },
      warnings: [],
    });
  });
});

test.sequential("fails closed before promotion for a read-only staged package file on Windows", async () => {
  const home = await temporaryDirectory();
  const npmCli = join(home, "private-tools", "npm-cli.js");
  await mkdir(dirname(npmCli), { recursive: true });
  await writeFile(npmCli, "/* fixture npm CLI */\n");
  const install = fakeNpmInstall({
    packageName: "fixture-windows-readonly",
    id: "windows-readonly",
  });

  await withProcessPlatform("win32", async () => {
    await expect(
      installClientAdapter("fixture-windows-readonly@1.0.0", {
        home,
        environment: { npm_execpath: npmCli },
        execFile: async (file, args, options) => {
          const result = await install(file, args, options);
          await chmod(
            join(options.cwd, "node_modules", "fixture-windows-readonly", "dist", "index.js"),
            0o444,
          );
          return result;
        },
      }),
    ).rejects.toThrow("client adapter failed to load");
  });

  await expect(
    lstat(join(clientPluginsRoot(home), "fixture-windows-readonly")),
  ).rejects.toMatchObject({ code: "ENOENT" });
});

test("derives and validates the adjacent npm CLI fallback on Windows", async () => {
  const home = await temporaryDirectory();
  const node = join(home, "node.exe");
  const npmCli = join(home, "node_modules", "npm", "bin", "npm-cli.js");
  await writeFile(node, "fixture node\n", { mode: 0o700 });
  await mkdir(dirname(npmCli), { recursive: true, mode: 0o700 });
  await writeFile(npmCli, "/* fixture npm CLI */\n", { mode: 0o600 });
  await chmod(npmCli, 0o666);
  const calls: ExecCall[] = [];
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  const execPath = Object.getOwnPropertyDescriptor(process, "execPath")!;
  Object.defineProperty(process, "platform", { ...platform, value: "win32" });
  Object.defineProperty(process, "execPath", { ...execPath, value: node });
  try {
    await installClientAdapter("fixture-windows-fallback@1.0.0", {
      home,
      environment: {},
      execFile: fakeNpmInstall({
        packageName: "fixture-windows-fallback",
        id: "windows-fallback",
        calls,
      }),
    });
  } finally {
    Object.defineProperty(process, "execPath", execPath);
    Object.defineProperty(process, "platform", platform);
  }

  expect(calls).toEqual([
    {
      file: node,
      args: [
        npmCli,
        "install",
        "--ignore-scripts",
        "--save-exact",
        "--package-lock=false",
        "--prefix",
        expect.stringContaining(join(clientPluginsRoot(home), ".stage-")),
        "--",
        "fixture-windows-fallback@1.0.0",
      ],
      cwd: expect.stringContaining(join(clientPluginsRoot(home), ".stage-")),
      shell: false,
    },
  ]);
  expect(calls[0]!.args[6]).toBe(calls[0]!.cwd);
});

test.each(["bad-name.js", "npm-cli.js"] as const)(
  "rejects an unsafe Windows npm CLI: %s",
  async (name) => {
    const home = await temporaryDirectory();
    const npmCli = join(home, name);
    if (name === "bad-name.js") {
      await writeFile(npmCli, "fixture\n");
    } else {
      const target = join(home, "real-npm-cli.js");
      await writeFile(target, "fixture\n");
      await symlink(target, npmCli);
    }
    const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
    Object.defineProperty(process, "platform", { ...platform, value: "win32" });
    try {
      await expect(
        installClientAdapter("fixture-unsafe-windows@1.0.0", {
          home,
          environment: { npm_execpath: npmCli },
          execFile: fakeNpmInstall({ packageName: "fixture-unsafe-windows", id: "unsafe" }),
        }),
      ).rejects.toThrow("client adapter npm executable is unavailable");
    } finally {
      Object.defineProperty(process, "platform", platform);
    }
  },
);

test("rejects a nonregular Windows npm CLI", async () => {
  const home = await temporaryDirectory();
  const npmCli = join(home, "npm-cli.js");
  await mkdir(npmCli);
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value: "win32" });
  try {
    await expect(
      installClientAdapter("fixture-directory-windows@1.0.0", {
        home,
        environment: { npm_execpath: npmCli },
        execFile: fakeNpmInstall({ packageName: "fixture-directory-windows", id: "directory" }),
      }),
    ).rejects.toThrow("client adapter npm executable is unavailable");
  } finally {
    Object.defineProperty(process, "platform", platform);
  }
});

test("runs a real local npm install without executing its lifecycle script", async () => {
  const home = await temporaryDirectory();
  const source = await temporaryDirectory();
  const marker = join(source, "install-script-ran");
  await writeFile(
    join(source, "package.json"),
    JSON.stringify({
      name: "fixture-real-install",
      version: "1.0.0",
      type: "module",
      scripts: { install: "node install.mjs" },
      mcpRestrictor: { clientAdapter: "./index.js", apiVersion: 1 },
    }),
  );
  await writeFile(
    join(source, "install.mjs"),
    `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'ran');\n`,
  );
  await writeFile(join(source, "index.js"), adapterModule("real-install", "Real install"));
  const previousCache = process.env.npm_config_cache;
  process.env.npm_config_cache = join(home, ".npm-cache");
  let result: Awaited<ReturnType<typeof installClientAdapter>>;
  const spec = `file:${join(home, "fixture-real-install-1.0.0.tgz")}`;
  try {
    const npmEnvironment = { ...process.env };
    if (
      process.platform === "win32" &&
      npmEnvironment.npm_execpath !== undefined &&
      !npmEnvironment.npm_execpath.endsWith("npm-cli.js")
    )
      delete npmEnvironment.npm_execpath;
    const npm = await resolveNpmCommand(npmEnvironment);
    await runFile(npm.file, [...npm.args, "pack", "--ignore-scripts", "--pack-destination", home], {
      cwd: source,
    });
    result = await installClientAdapter(spec, { home, environment: npmEnvironment });
  } finally {
    if (previousCache === undefined) delete process.env.npm_config_cache;
    else process.env.npm_config_cache = previousCache;
  }

  expect(result.plugin).toEqual({
    packageName: "fixture-real-install",
    version: "1.0.0",
    requestedSpec: spec,
  });
  await expect(lstat(marker)).rejects.toMatchObject({ code: "ENOENT" });
  const loaded = await loadInstalledClientAdapters({ home });
  expect(loaded.adapters.map(({ adapter }) => adapter.id)).toEqual(["real-install"]);
});

test("validates the installed adapter before writing private Restrictor metadata", async () => {
  const home = await temporaryDirectory();
  const observation = join(home, "metadata-observation");

  await installClientAdapter("fixture-order@1.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-order",
      id: "order",
      entrySource: `
import { existsSync, writeFileSync } from 'node:fs';
const metadata = new URL('../../../.mcp-restrictor-client-plugin.json', import.meta.url);
if (decodeURIComponent(import.meta.url).includes('/.stage-')) {
  writeFileSync(${JSON.stringify(observation)}, existsSync(metadata) ? 'present' : 'absent');
}
${adapterModule("order", "Order")}`,
    }),
  });

  expect(await readFile(observation, "utf8")).toBe("absent");
});

test("loads a fresh complete ESM dependency graph after update and recovery", async () => {
  const home = await temporaryDirectory();
  const entrySource = `import { label } from './implementation.js';
export default {
  apiVersion: 1,
  id: 'dependency-cache',
  label,
  async load() { return { configurations: [], unsupported: [] }; },
  render(config) { return config.source; }
};\n`;
  const installVersion = (version: string, label: string) =>
    installClientAdapter(`fixture-dependency-cache@${version}`, {
      home,
      execFile: fakeNpmInstall({
        packageName: "fixture-dependency-cache",
        version,
        id: "dependency-cache",
        entrySource,
        implementationSource: `export const label = ${JSON.stringify(label)};\n`,
      }),
    });

  await installVersion("1.0.0", "Dependency graph v1");
  expect((await loadInstalledClientAdapters({ home })).adapters[0]!.adapter.label).toBe(
    "Dependency graph v1",
  );

  await installVersion("2.0.0", "Dependency graph v2");
  expect((await loadInstalledClientAdapters({ home })).adapters[0]!.adapter.label).toBe(
    "Dependency graph v2",
  );

  await writePromotionJournal(clientPluginsRoot(home), {
    version: 1,
    target: "fixture-dependency-cache",
  });
  expect((await loadInstalledClientAdapters({ home })).adapters[0]!.adapter.label).toBe(
    "Dependency graph v2",
  );
});

test.each(["update", "remove"] as const)(
  "keeps an already-loaded lazy adapter graph executable after package %s",
  async (operation) => {
    const home = await temporaryDirectory();
    const entrySource = `export default {
  apiVersion: 1,
  id: 'lazy-lifetime',
  label: 'Lazy lifetime',
  async load() {
    const { version } = await import('./implementation.js');
    return { configurations: [], unsupported: [], version };
  },
  render(config) { return config.source; }
};\n`;
    const installVersion = (version: string) =>
      installClientAdapter(`fixture-lazy-lifetime@${version}`, {
        home,
        execFile: fakeNpmInstall({
          packageName: "fixture-lazy-lifetime",
          version,
          id: "lazy-lifetime",
          entrySource,
          implementationSource: `export const version = ${JSON.stringify(version)};\n`,
        }),
      });

    await installVersion("1.0.0");
    const loadedV1 = (await loadInstalledClientAdapters({ home })).adapters[0]!.adapter;
    if (operation === "update") await installVersion("2.0.0");
    else await removeClientAdapter("fixture-lazy-lifetime", { home });

    await expect(loadedV1.load({} as never, {} as never)).resolves.toMatchObject({
      version: "1.0.0",
    });
  },
);

test.each([
  ["generation", "update"],
  ["generation", "remove"],
  ["runtime", "update"],
  ["runtime", "remove"],
] as const)(
  "keeps a child-process %s graph executable across package %s",
  async (graph, operation) => {
    const home = await temporaryDirectory();
    const marker = join(home, "allow-child-runtime");
    const lazyEntry = `export default {
  apiVersion: 1,
  id: 'cross-process-lifetime',
  label: 'Cross-process lifetime',
  async load() {
    const { version } = await import('./implementation.js');
    return { configurations: [], unsupported: [], version };
  },
  render(config) { return config.source; }
};\n`;
    const runtimeEntry = `import { label } from './implementation.js';
export default {
  apiVersion: 1,
  id: 'cross-process-lifetime',
  label,
  async load() {
    const { version } = await import('./late.js');
    return { configurations: [], unsupported: [], version };
  },
  render(config) { return config.source; }
};\n`;
    const plugin = await writePlugin(home, {
      packageName: "fixture-cross-process-lifetime",
      version: "1.0.0",
      id: "cross-process-lifetime",
      entrySource: graph === "runtime" ? runtimeEntry : lazyEntry,
      implementationSource:
        graph === "runtime"
          ? `import { existsSync } from 'node:fs';
if (!existsSync(${JSON.stringify(marker)})) throw new Error('runtime retry sentinel');
export const label = 'Cross-process runtime';\n`
          : "export const version = '1.0.0';\n",
    });
    if (graph === "runtime") {
      await writeFile(
        join(dirname(plugin.entryPath), "late.js"),
        "export const version = '1.0.0';\n",
      );
    }
    const holder = await startAdapterHolder(home, graph);
    let exited = false;
    try {
      if (graph === "runtime") {
        expect(await holder.readLine()).toBe("FAILED");
        await writeFile(marker, "allow");
        holder.write("RETRY");
      }
      expect(await holder.readLine()).toBe("READY");
      const heldGraph =
        graph === "runtime"
          ? join(
              clientPluginsRoot(home),
              (await readdir(clientPluginsRoot(home))).find((name) =>
                name.startsWith(".runtime-"),
              )!,
            )
          : plugin.generation;

      if (operation === "update") {
        await installClientAdapter("fixture-cross-process-lifetime@2.0.0", {
          home,
          execFile: fakeNpmInstall({
            packageName: "fixture-cross-process-lifetime",
            version: "2.0.0",
            id: "cross-process-lifetime",
            entrySource: lazyEntry,
            implementationSource: "export const version = '2.0.0';\n",
          }),
        });
      } else {
        await removeClientAdapter("fixture-cross-process-lifetime", { home });
      }

      holder.write("INVOKE");
      expect(await holder.readLine()).toBe("RESULT:1.0.0");
      expect((await lstat(heldGraph)).isDirectory()).toBe(true);
      const leases = (await readdir(clientPluginsRoot(home))).filter((name) =>
        name.startsWith(".lease-"),
      );
      expect(leases).toHaveLength(1);
      const leasePath = join(clientPluginsRoot(home), leases[0]!);
      await expectPrivateFile(leasePath);
      expect(JSON.parse(await readFile(leasePath, "utf8"))).toEqual({
        version: 1,
        pid: holder.pid,
        graph: basename(heldGraph),
      });
      expect(await readFile(leasePath, "utf8")).not.toContain(home);

      holder.write("EXIT");
      expect(await holder.waitForExit()).toBe(0);
      exited = true;
      await listClientAdapters({ home });
      await expect(lstat(heldGraph)).rejects.toMatchObject({ code: "ENOENT" });
      expect(
        (await readdir(clientPluginsRoot(home))).filter((name) => name.startsWith(".lease-")),
      ).toEqual([]);
    } finally {
      if (!exited) await holder.stop();
    }
  },
);

test("retries a failed child module through a fresh complete graph URL", async () => {
  const home = await temporaryDirectory();
  const marker = join(home, "allow-child-import");
  const runtimeMarker = join(home, "allow-runtime-child-import");
  const plugin = await writePlugin(home, {
    packageName: "fixture-child-retry",
    id: "child-retry",
    entrySource: `import { label } from './implementation.js';
export default {
  apiVersion: 1,
  id: 'child-retry',
  label,
  async load() {
    const { version } = await import('./late.js');
    return { configurations: [], unsupported: [], version };
  },
  render(config) { return config.source; }
};\n`,
    implementationSource: `import { existsSync } from 'node:fs';
if (!existsSync(${JSON.stringify(marker)})) throw new Error('child retry sentinel');
if (import.meta.url.includes('/.runtime-') && !existsSync(${JSON.stringify(runtimeMarker)})) {
  throw new Error('runtime child retry sentinel');
}
export const label = 'Child retry recovered';\n`,
  });
  await writeFile(
    join(dirname(plugin.entryPath), "late.js"),
    "export const version = 'runtime';\n",
  );

  expect(await loadInstalledClientAdapters({ home })).toEqual({
    adapters: [],
    unavailable: [
      {
        packageName: "fixture-child-retry",
        reason: "client adapter failed to load",
      },
    ],
  });

  await writeFile(marker, "allow");
  await writeFile(runtimeMarker, "allow");
  const recovered = await loadInstalledClientAdapters({ home });
  expect(
    recovered.adapters.map(({ adapter }) => ({
      id: adapter.id,
      label: adapter.label,
    })),
  ).toEqual([{ id: "child-retry", label: "Child retry recovered" }]);
  const recoveredRuntimeGraphs = (await readdir(clientPluginsRoot(home))).filter((name) =>
    name.startsWith(".runtime-"),
  );
  expect(recoveredRuntimeGraphs).toHaveLength(1);
  expect((await loadInstalledClientAdapters({ home })).adapters[0]!.adapter).toBe(
    recovered.adapters[0]!.adapter,
  );
  expect(
    (await readdir(clientPluginsRoot(home))).filter((name) => name.startsWith(".runtime-")),
  ).toEqual(recoveredRuntimeGraphs);
  await removeClientAdapter("fixture-child-retry", { home });
  await loadInstalledClientAdapters({ home });
  await expect(
    recovered.adapters[0]!.adapter.load({} as never, {} as never),
  ).resolves.toMatchObject({ version: "runtime" });
});

test("evaluates each broken installed generation at most twice", async () => {
  const home = await temporaryDirectory();
  const observation = join(home, "child-evaluation-count");
  const plugin = {
    packageName: "fixture-exhausted-retry",
    id: "exhausted-retry",
    entrySource: `import './implementation.js';
${adapterModule("exhausted-retry", "Exhausted retry")}`,
    implementationSource: `import { appendFileSync } from 'node:fs';
appendFileSync(${JSON.stringify(observation)}, 'evaluation\\n');
throw new Error('bounded child retry sentinel');
`,
  };
  await writePlugin(home, plugin);
  const root = clientPluginsRoot(home);

  for (let attempt = 0; attempt < 10; attempt += 1) {
    expect((await listClientAdapters({ home }))[0]).toMatchObject({
      packageName: "fixture-exhausted-retry",
      status: "unavailable",
    });
  }
  for (let attempt = 0; attempt < 10; attempt += 1) {
    expect(await loadInstalledClientAdapters({ home })).toEqual({
      adapters: [],
      unavailable: [
        {
          packageName: "fixture-exhausted-retry",
          reason: "client adapter failed to load",
        },
      ],
    });
  }
  expect(await readFile(observation, "utf8")).toBe("evaluation\nevaluation\n");
  expect((await readdir(root)).filter((name) => name.startsWith(".runtime-"))).toEqual([]);

  await writePlugin(home, { ...plugin, version: "2.0.0" });
  await listClientAdapters({ home });
  await loadInstalledClientAdapters({ home });
  await loadInstalledClientAdapters({ home });
  expect(await readFile(observation, "utf8")).toBe(
    "evaluation\nevaluation\nevaluation\nevaluation\n",
  );
  expect((await readdir(root)).filter((name) => name.startsWith(".runtime-"))).toEqual([]);
  expect((await readdir(root)).filter((name) => name.startsWith(".lease-"))).toEqual([]);
});

test("repeated internal install validation retains only the active generation", async () => {
  const home = await temporaryDirectory();
  for (let version = 1; version <= 5; version += 1) {
    await installClientAdapter(`fixture-internal-validation@${version}.0.0`, {
      home,
      execFile: fakeNpmInstall({
        packageName: "fixture-internal-validation",
        version: `${version}.0.0`,
        id: "internal-validation",
      }),
    });
  }
  const root = clientPluginsRoot(home);

  expect((await readdir(root)).filter((name) => name.startsWith(".generation-"))).toHaveLength(1);
  expect((await readdir(root)).filter((name) => name.startsWith(".runtime-"))).toEqual([]);
  expect((await readdir(root)).filter((name) => name.startsWith(".lease-"))).toEqual([]);
});

test("sanitizes npm and staged import failures", async () => {
  const npmHome = await temporaryDirectory();
  const npmSecret = `npm-secret:${npmHome}`;
  let npmError: unknown;
  try {
    await installClientAdapter("fixture-npm-secret@1.0.0", {
      home: npmHome,
      execFile: async () => {
        throw new Error(npmSecret);
      },
    });
  } catch (error) {
    npmError = error;
  }
  expect(npmError).toEqual(new Error("client adapter installation failed"));
  expect((npmError as Error).message).not.toContain(npmSecret);

  const importHome = await temporaryDirectory();
  const importSecret = `import-secret:${importHome}`;
  let importError: unknown;
  try {
    await installClientAdapter("fixture-import-secret@1.0.0", {
      home: importHome,
      execFile: fakeNpmInstall({
        packageName: "fixture-import-secret",
        id: "import-secret",
        entrySource: `throw new Error(${JSON.stringify(importSecret)});\n`,
      }),
    });
  } catch (error) {
    importError = error;
  }
  expect(importError).toEqual(new Error("client adapter failed to load"));
  expect((importError as Error).message).not.toContain(importSecret);
});

test("syncs staged payload files and directories before the first promotion rename", async () => {
  const home = await temporaryDirectory();
  const outside = join(home, "outside-do-not-follow");
  await writeFile(outside, "outside");
  const install = fakeNpmInstall({ packageName: "fixture-sync", id: "sync" });

  await installClientAdapter("fixture-sync@1.0.0", {
    home,
    execFile: async (file, args, options) => {
      const result = await install(file, args, options);
      await symlink(outside, join(options.cwd, "node_modules", "fixture-sync", "payload-link"));
      return result;
    },
  });

  const promotion = fileOperations.events.findIndex(
    (event) =>
      event.startsWith("rename:") &&
      event.includes(".stage-") &&
      event.endsWith(`:${join(clientPluginsRoot(home), "fixture-sync")}`),
  );
  expect(promotion).toBeGreaterThanOrEqual(0);
  for (const suffix of [
    "node_modules/fixture-sync/dist/index.js",
    "node_modules/fixture-sync/package.json",
    "node_modules/fixture-sync/dist",
    "node_modules/fixture-sync",
    "node_modules",
  ]) {
    const synced = fileOperations.events.findIndex(
      (event) => event.startsWith("sync:") && event.endsWith(suffix),
    );
    expect(synced, suffix).toBeGreaterThanOrEqual(0);
    expect(synced, suffix).toBeLessThan(promotion);
  }
  expect(
    fileOperations.events.some(
      (event) => event.includes("payload-link") || event === `sync:${outside}`,
    ),
  ).toBe(false);
});

test("does not promote when syncing a staged payload file fails", async () => {
  const home = await temporaryDirectory();
  const install = fakeNpmInstall({ packageName: "fixture-sync-fails", id: "sync-fails" });

  await expect(
    installClientAdapter("fixture-sync-fails@1.0.0", {
      home,
      execFile: async (file, args, options) => {
        const result = await install(file, args, options);
        fileOperations.syncFailurePath = join(
          options.cwd,
          "node_modules",
          "fixture-sync-fails",
          "dist",
          "index.js",
        );
        return result;
      },
    }),
  ).rejects.toThrow("client adapter failed to load");

  expect(
    fileOperations.events.some(
      (event) =>
        event.startsWith("rename:") &&
        event.endsWith(`:${join(clientPluginsRoot(home), "fixture-sync-fails")}`),
    ),
  ).toBe(false);
});

test("keeps first install absent and an update exact until each atomic promotion", async () => {
  const home = await temporaryDirectory();
  const active = join(clientPluginsRoot(home), "fixture-atomic");
  const firstArrived = deferred<void>();
  const releaseFirst = deferred<void>();
  fileOperations.promotionBarrier = {
    to: active,
    arrived: () => firstArrived.resolve(),
    wait: releaseFirst.promise,
  };
  const first = installClientAdapter("fixture-atomic@1.0.0", {
    home,
    execFile: fakeNpmInstall({ packageName: "fixture-atomic", version: "1.0.0", id: "atomic-old" }),
  });
  await firstArrived.promise;
  await expect(lstat(active)).rejects.toMatchObject({ code: "ENOENT" });
  const journalPath = join(clientPluginsRoot(home), ".registry-promotion.json");
  await expectPrivateFile(journalPath);
  expect(JSON.parse(await readFile(journalPath, "utf8"))).toEqual({
    version: 1,
    target: "fixture-atomic",
  });
  releaseFirst.resolve();
  await first;

  const before = await snapshotTree(active);
  const updateArrived = deferred<void>();
  const releaseUpdate = deferred<void>();
  fileOperations.promotionBarrier = {
    from: active,
    arrived: () => updateArrived.resolve(),
    wait: releaseUpdate.promise,
  };
  const update = installClientAdapter("fixture-atomic@2.0.0", {
    home,
    execFile: fakeNpmInstall({ packageName: "fixture-atomic", version: "2.0.0", id: "atomic-new" }),
  });
  await updateArrived.promise;
  expect(await snapshotTree(active)).toEqual(before);
  await expectPrivateFile(journalPath);
  expect(JSON.parse(await readFile(journalPath, "utf8"))).toEqual({
    version: 1,
    target: "fixture-atomic",
    backup: expect.stringMatching(
      /^\.backup-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    ),
  });
  releaseUpdate.resolve();
  await update;

  expect(
    JSON.parse(await readFile(join(active, ".mcp-restrictor-client-plugin.json"), "utf8")),
  ).toMatchObject({ version: "2.0.0" });
});

test("holds a loader behind the registry lock after moving the old active adapter", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("fixture-reader-lock@1.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-reader-lock",
      version: "1.0.0",
      id: "reader-old",
    }),
  });
  const active = join(clientPluginsRoot(home), "fixture-reader-lock");
  const oldMoved = deferred<void>();
  const releaseUpdate = deferred<void>();
  fileOperations.promotionBarrier = {
    from: active,
    after: true,
    arrived: () => oldMoved.resolve(),
    wait: releaseUpdate.promise,
  };
  const update = installClientAdapter("fixture-reader-lock@2.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-reader-lock",
      version: "2.0.0",
      id: "reader-new",
    }),
  });
  await oldMoved.promise;
  let loaded = false;
  const load = loadInstalledClientAdapters({ home }).then((result) => {
    loaded = true;
    return result;
  });
  await new Promise<void>((resolve) => setImmediate(resolve));

  expect(loaded).toBe(false);
  releaseUpdate.resolve();
  await update;
  expect((await load).adapters.map(({ adapter }) => adapter.id)).toEqual(["reader-new"]);
});

test("rejects an invalid promotion before handing the registry lock to a waiting loader", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("fixture-invalid-handoff@1.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-invalid-handoff",
      version: "1.0.0",
      id: "handoff-old",
    }),
  });
  const root = clientPluginsRoot(home);
  const active = join(root, "fixture-invalid-handoff");
  const before = await snapshotTree(active);
  const promoted = deferred<void>();
  const releasePromotion = deferred<void>();
  fileOperations.promotionBarrier = {
    to: active,
    after: true,
    arrived: () => promoted.resolve(),
    wait: releasePromotion.promise,
  };

  const update = installClientAdapter("fixture-invalid-handoff@2.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-invalid-handoff",
      version: "2.0.0",
      id: "handoff-invalid",
      entrySource: activePathSensitiveAdapter("handoff-invalid", "handoff-active-secret"),
    }),
  });
  await promoted.promise;

  const lockReleased = deferred<void>();
  const lockAcquired = deferred<void>();
  fileOperations.registryHandoff = {
    path: join(root, "..registry.lock"),
    released: () => lockReleased.resolve(),
    acquired: () => lockAcquired.resolve(),
    waitForAcquire: lockAcquired.promise,
  };
  let loadSettled = false;
  const load = loadInstalledClientAdapters({ home }).finally(() => {
    loadSettled = true;
  });
  await new Promise<void>((resolve) => setImmediate(resolve));
  expect(loadSettled).toBe(false);

  releasePromotion.resolve();
  await lockReleased.promise;
  const [updateResult, loaded] = await Promise.all([
    update.then(
      () => ({ status: "fulfilled" as const }),
      (reason: unknown) => ({ status: "rejected" as const, reason }),
    ),
    load,
  ]);

  expect(updateResult).toEqual({
    status: "rejected",
    reason: new Error("client adapter installation failed"),
  });
  expect(loaded.adapters.map(({ adapter }) => adapter.id)).toEqual(["handoff-old"]);
  expect(await snapshotTree(active)).toEqual(before);
  expect(await hiddenTransactionDirectories(home)).toEqual([]);
});

test("recovers every valid promotion journal state before loading adapters", async () => {
  const backupName = ".backup-11111111-1111-4111-8111-111111111111";

  const restoreHome = await temporaryDirectory();
  const restore = await writePlugin(restoreHome, {
    packageName: "fixture-recover-old",
    id: "recover-old",
    entrySource: backupPathSensitiveAdapter("recover-old"),
  });
  const restoreRoot = clientPluginsRoot(restoreHome);
  const restoreBackup = join(restoreRoot, backupName);
  await rename(restore.prefix, restoreBackup);
  await writePromotionJournal(restoreRoot, {
    version: 1,
    target: "fixture-recover-old",
    backup: backupName,
  });

  const restored = await loadInstalledClientAdapters({ home: restoreHome });

  expect(restored.adapters.map(({ adapter }) => adapter.id)).toEqual(["recover-old"]);
  expect(await hiddenTransactionDirectories(restoreHome)).toEqual([]);
  await expect(lstat(join(restoreRoot, ".registry-promotion.json"))).rejects.toMatchObject({
    code: "ENOENT",
  });

  const keepHome = await temporaryDirectory();
  const old = await writePlugin(keepHome, {
    packageName: "fixture-recover-new",
    id: "recover-old-copy",
  });
  const keepRoot = clientPluginsRoot(keepHome);
  const keepBackup = join(keepRoot, backupName);
  await rename(old.prefix, keepBackup);
  const stagedNew = await writePlugin(keepHome, {
    packageName: "fixture-recover-new",
    activeName: ".stage-recover-new",
    id: "recover-new",
  });
  await rename(stagedNew.prefix, old.prefix);
  await writePromotionJournal(keepRoot, {
    version: 1,
    target: "fixture-recover-new",
    backup: backupName,
  });

  const kept = await loadInstalledClientAdapters({ home: keepHome });

  expect(kept.adapters.map(({ adapter }) => adapter.id)).toEqual(["recover-new"]);
  expect(await hiddenTransactionDirectories(keepHome)).toEqual([]);
  await expect(lstat(join(keepRoot, ".registry-promotion.json"))).rejects.toMatchObject({
    code: "ENOENT",
  });

  const clearHome = await temporaryDirectory();
  await writePlugin(clearHome, {
    packageName: "fixture-recover-clear",
    id: "recover-clear",
  });
  const clearRoot = clientPluginsRoot(clearHome);
  await writePromotionJournal(clearRoot, {
    version: 1,
    target: "fixture-recover-clear",
  });

  const cleared = await loadInstalledClientAdapters({ home: clearHome });

  expect(cleared.adapters.map(({ adapter }) => adapter.id)).toEqual(["recover-clear"]);
  await expect(lstat(join(clearRoot, ".registry-promotion.json"))).rejects.toMatchObject({
    code: "ENOENT",
  });
});

test("recovers an interrupted promotion before scoped adapter acquisition", async () => {
  const home = await temporaryDirectory();
  const plugin = await writePlugin(home, {
    packageName: "fixture-scoped-recovery",
    id: "scoped-recovery",
    entrySource: backupPathSensitiveAdapter("scoped-recovery"),
  });
  const root = clientPluginsRoot(home);
  const backupName = ".backup-11111111-1111-4111-8111-111111111111";
  const backup = join(root, backupName);
  await rename(plugin.prefix, backup);
  await writePromotionJournal(root, {
    version: 1,
    target: "fixture-scoped-recovery",
    backup: backupName,
  });

  await withInstalledClientAdapters({ home }, async ({ adapters, unavailable }) => {
    expect(unavailable).toEqual([]);
    expect(adapters.map(({ adapter }) => adapter.id)).toEqual(["scoped-recovery"]);
    expect((await readdir(root)).filter((name) => name.startsWith(".lease-"))).toHaveLength(1);
    await expect(lstat(join(root, ".registry-promotion.json"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    await expect(lstat(backup)).rejects.toMatchObject({ code: "ENOENT" });
  });

  expect((await readdir(root)).filter((name) => name.startsWith(".lease-"))).toEqual([]);
  expect((await readdir(root)).filter((name) => name.startsWith(".runtime-"))).toEqual([]);
});

test.sequential("recovers a 0666 promotion journal on Windows", async () => {
  const home = await temporaryDirectory();
  await writePlugin(home, {
    packageName: "fixture-windows-journal",
    id: "windows-journal",
  });
  const root = clientPluginsRoot(home);
  const journal = join(root, ".registry-promotion.json");
  await writePromotionJournal(root, {
    version: 1,
    target: "fixture-windows-journal",
  });
  await chmod(journal, 0o666);

  await withProcessPlatform("win32", async () => {
    expect(
      (await loadInstalledClientAdapters({ home })).adapters.map(({ adapter }) => adapter.id),
    ).toEqual(["windows-journal"]);
  });
  await expect(lstat(journal)).rejects.toMatchObject({ code: "ENOENT" });
});

test("recovers a stale promotion journal before starting npm work", async () => {
  const home = await temporaryDirectory();
  const old = await writePlugin(home, {
    packageName: "fixture-install-entry-old",
    id: "install-entry-old",
  });
  const root = clientPluginsRoot(home);
  const backupName = ".backup-22222222-2222-4222-8222-222222222222";
  await rename(old.prefix, join(root, backupName));
  await writePromotionJournal(root, {
    version: 1,
    target: "fixture-install-entry-old",
    backup: backupName,
  });
  const install = fakeNpmInstall({
    packageName: "fixture-install-entry-new",
    id: "install-entry-new",
  });

  await installClientAdapter("fixture-install-entry-new@1.0.0", {
    home,
    execFile: async (file, args, options) => {
      expect((await lstat(old.prefix)).isDirectory()).toBe(true);
      await expect(lstat(join(root, ".registry-promotion.json"))).rejects.toMatchObject({
        code: "ENOENT",
      });
      return install(file, args, options);
    },
  });
});

test("rejects an invalid promoted update, restores v1, and permits a later update", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("fixture-active-validation@1.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-active-validation",
      version: "1.0.0",
      id: "active-validation-v1",
      entrySource: backupPathSensitiveAdapter("active-validation-v1"),
    }),
  });
  const active = join(clientPluginsRoot(home), "fixture-active-validation");
  const before = await snapshotTree(active);
  const activeSecret = `active-import-secret:${home}`;

  let caught: unknown;
  try {
    await installClientAdapter("fixture-active-validation@2.0.0", {
      home,
      execFile: fakeNpmInstall({
        packageName: "fixture-active-validation",
        version: "2.0.0",
        id: "active-validation-v2",
        entrySource: activePathSensitiveAdapter("active-validation-v2", activeSecret),
      }),
    });
  } catch (error) {
    caught = error;
  }

  expect(caught).toEqual(new Error("client adapter installation failed"));
  expect((caught as Error).message).not.toContain(activeSecret);
  expect(await snapshotTree(active)).toEqual(before);
  expect(await hiddenTransactionDirectories(home)).toEqual([]);
  await expect(
    lstat(join(clientPluginsRoot(home), ".registry-promotion.json")),
  ).rejects.toMatchObject({ code: "ENOENT" });
  expect(
    (await loadInstalledClientAdapters({ home })).adapters.map(({ adapter }) => adapter.id),
  ).toEqual(["active-validation-v1"]);

  await installClientAdapter("fixture-active-validation@3.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-active-validation",
      version: "3.0.0",
      id: "active-validation-v3",
    }),
  });
  expect(
    (await loadInstalledClientAdapters({ home })).adapters.map(({ adapter }) => adapter.id),
  ).toEqual(["active-validation-v3"]);
});

test("restores a validated backup when crash recovery finds an invalid active target", async () => {
  const home = await temporaryDirectory();
  const old = await writePlugin(home, {
    packageName: "fixture-crash-invalid-update",
    id: "crash-valid-v1",
    entrySource: backupPathSensitiveAdapter("crash-valid-v1"),
  });
  const root = clientPluginsRoot(home);
  const backupName = ".backup-33333333-3333-4333-8333-333333333333";
  const backup = join(root, backupName);
  await rename(old.prefix, backup);
  const before = await snapshotTree(backup);
  const invalid = await writePlugin(home, {
    packageName: "fixture-crash-invalid-update",
    id: "crash-invalid-v2",
    entrySource: "throw new Error('crash-active-secret');\n",
  });
  await writePromotionJournal(root, {
    version: 1,
    target: "fixture-crash-invalid-update",
    backup: backupName,
  });

  const loaded = await loadInstalledClientAdapters({ home });

  expect(loaded.adapters.map(({ adapter }) => adapter.id)).toEqual(["crash-valid-v1"]);
  expect(await snapshotTree(invalid.prefix)).toEqual(before);
  expect((await lstat(old.generation)).isDirectory()).toBe(true);
  await expect(lstat(invalid.generation)).rejects.toMatchObject({ code: "ENOENT" });
  expect(await hiddenTransactionDirectories(home)).toEqual([]);
  await expect(lstat(join(root, ".registry-promotion.json"))).rejects.toMatchObject({
    code: "ENOENT",
  });
});

test("removes an invalid first-install target and clears its crash journal", async () => {
  const home = await temporaryDirectory();
  const activeSecret = `first-active-secret:${home}`;

  await expect(
    installClientAdapter("fixture-invalid-first@1.0.0", {
      home,
      execFile: fakeNpmInstall({
        packageName: "fixture-invalid-first",
        id: "invalid-first",
        entrySource: activePathSensitiveAdapter("invalid-first", activeSecret),
      }),
    }),
  ).rejects.toThrow("client adapter installation failed");

  expect(await loadInstalledClientAdapters({ home })).toEqual({ adapters: [], unavailable: [] });
  expect(await hiddenTransactionDirectories(home)).toEqual([]);
  await expect(
    lstat(join(clientPluginsRoot(home), ".registry-promotion.json")),
  ).rejects.toMatchObject({ code: "ENOENT" });
});

test("keeps invalid-update recovery retryable when restoring the backup rename fails", async () => {
  const home = await temporaryDirectory();
  const old = await writePlugin(home, {
    packageName: "fixture-retry-invalid-update",
    id: "retry-valid-v1",
  });
  const root = clientPluginsRoot(home);
  const active = old.prefix;
  const backupName = ".backup-44444444-4444-4444-8444-444444444444";
  const backup = join(root, backupName);
  await rename(active, backup);
  await writePlugin(home, {
    packageName: "fixture-retry-invalid-update",
    id: "retry-invalid-v2",
    entrySource: "throw new Error('retry-active-secret');\n",
  });
  await writePromotionJournal(root, {
    version: 1,
    target: "fixture-retry-invalid-update",
    backup: backupName,
  });
  fileOperations.renameFailures.push({
    fromIncludes: backupName,
    to: active,
    error: new Error("injected recovery restore failure"),
  });

  await expect(loadInstalledClientAdapters({ home })).rejects.toThrow(
    "client adapter registry recovery failed",
  );
  expect((await lstat(backup)).isDirectory()).toBe(true);
  await expectPrivateFile(join(root, ".registry-promotion.json"));

  const loaded = await loadInstalledClientAdapters({ home });
  expect(loaded.adapters.map(({ adapter }) => adapter.id)).toEqual(["retry-valid-v1"]);
  expect(await hiddenTransactionDirectories(home)).toEqual([]);
});

test("retries validation of an already-restored active adapter while its backup is absent", async () => {
  const home = await temporaryDirectory();
  const marker = join(home, "allow-restored-import");
  const restored = await writePlugin(home, {
    packageName: "fixture-retry-active-validation",
    id: "retry-active-validation",
    entrySource: markerSensitiveAdapter("retry-active-validation", marker),
  });
  const root = clientPluginsRoot(home);
  const journal = join(root, ".registry-promotion.json");
  await writePromotionJournal(root, {
    version: 1,
    target: "fixture-retry-active-validation",
    backup: ".backup-55555555-5555-4555-8555-555555555555",
  });

  expect(await loadInstalledClientAdapters({ home })).toEqual({
    adapters: [],
    unavailable: [
      {
        packageName: "fixture-retry-active-validation",
        reason: "client adapter failed to load",
      },
    ],
  });
  expect((await lstat(restored.prefix)).isDirectory()).toBe(true);
  await expect(lstat(journal)).rejects.toMatchObject({ code: "ENOENT" });

  await writeFile(marker, "allow");
  await writeFile(
    restored.entryPath,
    `${markerSensitiveAdapter("retry-active-validation", marker)}\n`,
  );
  const loaded = await loadInstalledClientAdapters({ home });
  expect(loaded.adapters.map(({ adapter }) => adapter.id)).toEqual(["retry-active-validation"]);
  await expect(lstat(journal)).rejects.toMatchObject({ code: "ENOENT" });
});

test("restores a structurally valid exhausted backup and permits a later update", async () => {
  const home = await temporaryDirectory();
  const broken = await writePlugin(home, {
    packageName: "fixture-exhausted-backup",
    id: "exhausted-backup",
    entrySource: "throw new Error('exhausted backup module');\n",
  });
  await writePlugin(home, {
    packageName: "fixture-exhausted-sibling",
    id: "exhausted-sibling",
  });
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const loaded = await loadInstalledClientAdapters({ home });
    expect(loaded.adapters.map(({ adapter }) => adapter.id)).toEqual(["exhausted-sibling"]);
    expect(loaded.unavailable).toEqual([
      {
        packageName: "fixture-exhausted-backup",
        reason: "client adapter failed to load",
      },
    ]);
  }
  const root = clientPluginsRoot(home);
  const backupName = ".backup-77777777-7777-4777-8777-777777777777";
  const backup = join(root, backupName);
  await rename(broken.prefix, backup);
  await writePromotionJournal(root, {
    version: 1,
    target: "fixture-exhausted-backup",
    backup: backupName,
  });

  const restored = await loadInstalledClientAdapters({ home });

  expect(restored.adapters.map(({ adapter }) => adapter.id)).toEqual(["exhausted-sibling"]);
  expect(restored.unavailable).toEqual([
    {
      packageName: "fixture-exhausted-backup",
      reason: "client adapter failed to load",
    },
  ]);
  await expect(lstat(backup)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(lstat(join(root, ".registry-promotion.json"))).rejects.toMatchObject({
    code: "ENOENT",
  });

  await installClientAdapter("fixture-exhausted-backup@2.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-exhausted-backup",
      version: "2.0.0",
      id: "recovered-backup",
    }),
  });
  expect(
    (await loadInstalledClientAdapters({ home })).adapters.map(({ adapter }) => adapter.id),
  ).toEqual(["recovered-backup", "exhausted-sibling"]);
});

test.each(["backup pending", "backup already restored"] as const)(
  "structurally restores broken adapter code in a fresh process: %s",
  async (state) => {
    const home = await temporaryDirectory();
    const packageName =
      state === "backup pending" ? "fixture-fresh-backup-pending" : "fixture-fresh-backup-restored";
    const broken = await writePlugin(home, {
      packageName,
      id: "fresh-broken",
      entrySource: "throw new Error('fresh process broken module');\n",
    });
    await writePlugin(home, {
      packageName: "fixture-fresh-valid-sibling",
      id: "fresh-valid-sibling",
    });
    const root = clientPluginsRoot(home);
    const backupName = ".backup-88888888-8888-4888-8888-888888888888";
    const backup = join(root, backupName);
    if (state === "backup pending") await rename(broken.prefix, backup);
    await writePromotionJournal(root, {
      version: 1,
      target: packageName,
      backup: backupName,
    });

    expect(await loadAdaptersInChild(home)).toEqual({
      adapters: ["fresh-valid-sibling"],
      unavailable: [
        {
          packageName,
          reason: "client adapter failed to load",
        },
      ],
    });
    expect((await lstat(broken.prefix)).isDirectory()).toBe(true);
    await expect(lstat(backup)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(lstat(join(root, ".registry-promotion.json"))).rejects.toMatchObject({
      code: "ENOENT",
    });
  },
);

test.each(["invalid pointer", "symlink pointer"] as const)(
  "keeps a restored-backup journal when structural validation finds an %s",
  async (kind) => {
    const home = await temporaryDirectory();
    const plugin = await writePlugin(home, {
      packageName: "fixture-invalid-structural-backup",
      id: "invalid-structural-backup",
    });
    const root = clientPluginsRoot(home);
    const backupName = ".backup-99999999-9999-4999-8999-999999999999";
    const backup = join(root, backupName);
    await rename(plugin.prefix, backup);
    const pointer = join(backup, ".mcp-restrictor-client-generation.json");
    if (kind === "invalid pointer") {
      await writeFile(pointer, JSON.stringify({ generation: "../outside" }), { mode: 0o600 });
    } else {
      const content = await readFile(pointer, "utf8");
      const outside = join(home, "outside-generation-pointer");
      await writeFile(outside, content, { mode: 0o600 });
      await unlink(pointer);
      await symlink(outside, pointer, "file");
    }
    await writePromotionJournal(root, {
      version: 1,
      target: "fixture-invalid-structural-backup",
      backup: backupName,
    });
    const journal = join(root, ".registry-promotion.json");

    await expect(loadInstalledClientAdapters({ home })).rejects.toThrow(
      "client adapter registry recovery failed",
    );
    await expectPrivateFile(journal);
    expect((await lstat(plugin.prefix)).isDirectory()).toBe(true);
    await expect(loadInstalledClientAdapters({ home })).rejects.toThrow(
      "client adapter registry recovery failed",
    );
    await expectPrivateFile(journal);
  },
);

test("fails closed when a promotion journal names a missing target and backup", async () => {
  const home = await temporaryDirectory();
  const root = clientPluginsRoot(home);
  await mkdir(root, { recursive: true });
  const journal = join(root, ".registry-promotion.json");
  await writePromotionJournal(root, {
    version: 1,
    target: "fixture-missing-promotion",
    backup: ".backup-66666666-6666-4666-8666-666666666666",
  });

  await expect(loadInstalledClientAdapters({ home })).rejects.toThrow(
    "client adapter registry recovery failed",
  );
  await expectPrivateFile(journal);
});

test.each([
  ["malformed JSON", "{journal-secret"],
  ["path target", JSON.stringify({ version: 1, target: "../outside-secret" })],
  ["encoded traversal", JSON.stringify({ version: 1, target: "%2E%2E%2Foutside-secret" })],
  [
    "path backup",
    JSON.stringify({
      version: 1,
      target: "fixture-journal",
      backup: "../backup-secret",
    }),
  ],
] as const)(
  "fails closed with a fixed error for a corrupt promotion journal: %s",
  async (_name, content) => {
    const home = await temporaryDirectory();
    const root = clientPluginsRoot(home);
    await mkdir(root, { recursive: true });
    await writeFile(join(root, ".registry-promotion.json"), content, { mode: 0o600 });
    const outside = join(home, "outside-secret");
    await writeFile(outside, "untouched");

    let caught: unknown;
    try {
      await loadInstalledClientAdapters({ home });
    } catch (error) {
      caught = error;
    }

    expect(caught).toEqual(new Error("client adapter registry recovery failed"));
    expect(JSON.stringify(caught)).not.toMatch(/outside-secret|backup-secret|journal-secret/);
    expect(await readFile(outside, "utf8")).toBe("untouched");
  },
);

test("rejects a built-in adapter ID without blacklisting a built-in-like package name", async () => {
  const home = await temporaryDirectory();

  await expect(
    installClientAdapter("fixture-conflict@1.0.0", {
      home,
      execFile: fakeNpmInstall({ packageName: "fixture-conflict", id: "claude" }),
    }),
  ).rejects.toThrow("client adapter ID conflicts with a built-in");

  expect(await readdir(clientPluginsRoot(home))).toEqual([]);
});

test("rejects a newly installed package whose ID belongs to another external adapter", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("z-original@1.0.0", {
    home,
    execFile: fakeNpmInstall({ packageName: "z-original", id: "shared-external" }),
  });

  await expect(
    installClientAdapter("a-conflict@1.0.0", {
      home,
      execFile: fakeNpmInstall({ packageName: "a-conflict", id: "shared-external" }),
    }),
  ).rejects.toEqual(new Error("client adapter ID conflicts with another external"));

  const activeSentinel = `external-active-conflict-secret:${home}`;
  let activeError: unknown;
  try {
    await installClientAdapter("b-active-conflict@1.0.0", {
      home,
      execFile: fakeNpmInstall({
        packageName: "b-active-conflict",
        id: "ignored-fixture-id",
        entrySource: stagedExternalActiveAdapter(
          "safe-staged-external",
          "shared-external",
          activeSentinel,
        ),
      }),
    });
  } catch (error) {
    activeError = error;
  }
  expect(activeError).toEqual(new Error("client adapter ID conflicts with another external"));
  expect(JSON.stringify(activeError)).not.toContain(activeSentinel);

  expect(
    (await loadInstalledClientAdapters({ home })).adapters.map(({ packageName, adapter }) => [
      packageName,
      adapter.id,
    ]),
  ).toEqual([["z-original", "shared-external"]]);
  await expect(lstat(join(clientPluginsRoot(home), "a-conflict"))).rejects.toMatchObject({
    code: "ENOENT",
  });
  await expect(lstat(join(clientPluginsRoot(home), "b-active-conflict"))).rejects.toMatchObject({
    code: "ENOENT",
  });
});

test("allows a package update that keeps its external adapter ID", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("fixture-same-id@1.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-same-id",
      version: "1.0.0",
      id: "same-external",
    }),
  });
  await writePlugin(home, {
    packageName: "fixture-broken-update-sibling",
    id: "broken-update-sibling",
    entrySource: "throw new Error('broken sibling sentinel');\n",
  });

  await expect(
    installClientAdapter("fixture-same-id@2.0.0", {
      home,
      execFile: fakeNpmInstall({
        packageName: "fixture-same-id",
        version: "2.0.0",
        id: "same-external",
      }),
    }),
  ).resolves.toMatchObject({
    plugin: { packageName: "fixture-same-id", version: "2.0.0" },
  });
});

test("restores an update that changes to another external adapter ID", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("a-existing@1.0.0", {
    home,
    execFile: fakeNpmInstall({ packageName: "a-existing", id: "already-owned" }),
  });
  await installClientAdapter("z-updating@1.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "z-updating",
      version: "1.0.0",
      id: "update-original",
    }),
  });
  const active = join(clientPluginsRoot(home), "z-updating");
  const before = await snapshotTree(active);

  await expect(
    installClientAdapter("z-updating@2.0.0", {
      home,
      execFile: fakeNpmInstall({
        packageName: "z-updating",
        version: "2.0.0",
        id: "already-owned",
      }),
    }),
  ).rejects.toEqual(new Error("client adapter ID conflicts with another external"));

  expect(await snapshotTree(active)).toEqual(before);
  expect(
    (await loadInstalledClientAdapters({ home })).adapters.map(({ packageName, adapter }) => [
      packageName,
      adapter.id,
    ]),
  ).toEqual([
    ["a-existing", "already-owned"],
    ["z-updating", "update-original"],
  ]);
});

test("rejects a built-in ID that appears only at the canonical active URL", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("fixture-active-conflict@1.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-active-conflict",
      version: "1.0.0",
      id: "active-conflict-old",
    }),
  });
  const active = join(clientPluginsRoot(home), "fixture-active-conflict");
  const before = await snapshotTree(active);
  const sentinel = `active-conflict-secret:${home}`;

  let updateError: unknown;
  try {
    await installClientAdapter("fixture-active-conflict@2.0.0", {
      home,
      execFile: fakeNpmInstall({
        packageName: "fixture-active-conflict",
        version: "2.0.0",
        id: "ignored-fixture-id",
        entrySource: stagedExternalActiveAdapter("safe-stage-update", "claude", sentinel),
      }),
    });
  } catch (error) {
    updateError = error;
  }

  expect(updateError).toEqual(new Error("client adapter ID conflicts with a built-in"));
  expect(JSON.stringify(updateError)).not.toContain(sentinel);
  expect(await snapshotTree(active)).toEqual(before);
  expect(
    (await loadInstalledClientAdapters({ home })).adapters.map(({ adapter }) => adapter.id),
  ).toEqual(["active-conflict-old"]);

  const firstHome = await temporaryDirectory();
  let firstError: unknown;
  try {
    await installClientAdapter("fixture-active-conflict-first@1.0.0", {
      home: firstHome,
      execFile: fakeNpmInstall({
        packageName: "fixture-active-conflict-first",
        id: "ignored-fixture-id",
        entrySource: stagedExternalActiveAdapter("safe-stage-first", "claude", sentinel),
      }),
    });
  } catch (error) {
    firstError = error;
  }

  expect(firstError).toEqual(new Error("client adapter ID conflicts with a built-in"));
  expect(JSON.stringify(firstError)).not.toContain(sentinel);
  expect(await loadInstalledClientAdapters({ home: firstHome })).toEqual({
    adapters: [],
    unavailable: [],
  });
  expect(await hiddenTransactionDirectories(firstHome)).toEqual([]);
});

test("restores the old adapter when crash recovery finds an active built-in ID", async () => {
  const home = await temporaryDirectory();
  const old = await writePlugin(home, {
    packageName: "fixture-crash-conflict",
    id: "crash-conflict-old",
    entrySource: backupPathSensitiveAdapter("crash-conflict-old"),
  });
  const root = clientPluginsRoot(home);
  const backupName = ".backup-77777777-7777-4777-8777-777777777777";
  const backup = join(root, backupName);
  await rename(old.prefix, backup);
  const before = await snapshotTree(backup);
  await writePlugin(home, {
    packageName: "fixture-crash-conflict",
    id: "ignored-fixture-id",
    entrySource: stagedExternalActiveAdapter("safe-stage-crash", "claude", "crash-conflict-secret"),
  });
  await writePromotionJournal(root, {
    version: 1,
    target: "fixture-crash-conflict",
    backup: backupName,
  });

  const loaded = await loadInstalledClientAdapters({ home });

  expect(loaded.adapters.map(({ adapter }) => adapter.id)).toEqual(["crash-conflict-old"]);
  expect(await snapshotTree(old.prefix)).toEqual(before);
  expect(await hiddenTransactionDirectories(home)).toEqual([]);
});

test.each([
  ["npm failure", "npm"],
  ["adapter validation failure", "validation"],
  ["stage promotion failure", "promotion"],
] as const)(
  "keeps an existing adapter exact after %s and removes its stage",
  async (_label, failure) => {
    const home = await temporaryDirectory();
    await installClientAdapter("fixture-update@1.0.0", {
      home,
      execFile: fakeNpmInstall({ packageName: "fixture-update", version: "1.0.0", id: "old" }),
    });
    const active = join(clientPluginsRoot(home), "fixture-update");
    const before = await snapshotTree(active);
    const beforeGraphs = (await readdir(clientPluginsRoot(home)))
      .filter((name) => name.startsWith(".generation-") || name.startsWith(".runtime-"))
      .sort();

    let execFile = fakeNpmInstall({ packageName: "fixture-update", version: "2.0.0", id: "new" });
    if (failure === "npm") {
      execFile = async () => {
        throw new Error("injected npm failure");
      };
    } else if (failure === "validation") {
      execFile = fakeNpmInstall({
        packageName: "fixture-update",
        version: "2.0.0",
        id: "new",
        entrySource: "export default {};\n",
      });
    } else {
      fileOperations.renameFailures.push({
        fromIncludes: ".stage-",
        to: active,
        error: new Error("injected stage promotion failure"),
      });
    }

    const attempt = expect(
      installClientAdapter("fixture-update@2.0.0", { home, execFile }),
    ).rejects;
    if (failure === "validation") await attempt.toThrow();
    else
      await attempt.toThrow(
        failure === "promotion"
          ? "injected stage promotion failure"
          : "client adapter installation failed",
      );

    expect(await snapshotTree(active)).toEqual(before);
    expect(
      (await readdir(clientPluginsRoot(home)))
        .filter((name) => name.startsWith(".generation-") || name.startsWith(".runtime-"))
        .sort(),
    ).toEqual(beforeGraphs);
    expect(await hiddenTransactionDirectories(home)).toEqual([]);
    const stageCleanup = fileOperations.events.findIndex(
      (event) => event.includes("rm:") && event.includes(".stage-"),
    );
    if (failure === "promotion") {
      const lockRelease = fileOperations.events.findIndex(
        (event) => event.includes("unlink:") && event.endsWith("..registry.lock"),
      );
      expect(lockRelease).toBeGreaterThanOrEqual(0);
      expect(stageCleanup).toBeGreaterThan(lockRelease);
    } else {
      expect(stageCleanup).toBeGreaterThanOrEqual(0);
    }
  },
);

test("reports only the original error when moving the old active adapter never took effect", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("fixture-pre-effect@1.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-pre-effect",
      version: "1.0.0",
      id: "pre-effect-old",
    }),
  });
  const active = join(clientPluginsRoot(home), "fixture-pre-effect");
  const before = await snapshotTree(active);
  const original = new Error("injected pre-effect rename failure");
  fileOperations.renameFailures.push({
    fromIncludes: "fixture-pre-effect",
    toIncludes: ".backup-",
    error: original,
  });

  let caught: unknown;
  try {
    await installClientAdapter("fixture-pre-effect@2.0.0", {
      home,
      execFile: fakeNpmInstall({
        packageName: "fixture-pre-effect",
        version: "2.0.0",
        id: "pre-effect-new",
      }),
    });
  } catch (error) {
    caught = error;
  }

  expect(caught).toBe(original);
  expect(caught).not.toBeInstanceOf(AggregateError);
  expect(await snapshotTree(active)).toEqual(before);
});

test("reports promotion then restoration errors in order while retaining the old adapter", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("fixture-dual@1.0.0", {
    home,
    execFile: fakeNpmInstall({ packageName: "fixture-dual", version: "1.0.0", id: "old-dual" }),
  });
  const active = join(clientPluginsRoot(home), "fixture-dual");
  const before = await snapshotTree(active);
  fileOperations.renameFailures.push(
    {
      fromIncludes: ".stage-",
      to: active,
      error: new Error("injected promotion failure"),
    },
    {
      fromIncludes: ".backup-",
      to: active,
      error: new Error("injected restoration failure"),
      after: true,
    },
  );

  let caught: unknown;
  try {
    await installClientAdapter("fixture-dual@2.0.0", {
      home,
      execFile: fakeNpmInstall({ packageName: "fixture-dual", version: "2.0.0", id: "new-dual" }),
    });
  } catch (error) {
    caught = error;
  }

  expect(caught).toBeInstanceOf(AggregateError);
  expect((caught as AggregateError).errors.map((error) => (error as Error).message)).toEqual([
    "injected promotion failure",
    "injected restoration failure",
  ]);
  expect(await snapshotTree(active)).toEqual(before);
  expect(await hiddenTransactionDirectories(home)).toEqual([]);
});

test("restores an existing adapter before reporting registry lock release failure", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("fixture-release@1.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-release",
      version: "1.0.0",
      id: "release-old",
    }),
  });
  const root = clientPluginsRoot(home);
  const active = join(root, "fixture-release");
  const before = await snapshotTree(active);
  const install = fakeNpmInstall({
    packageName: "fixture-release",
    version: "2.0.0",
    id: "release-new",
  });

  await expect(
    installClientAdapter("fixture-release@2.0.0", {
      home,
      execFile: async (file, args, options) => {
        const result = await install(file, args, options);
        fileOperations.unlinkFailures.set(join(root, "..registry.lock"), [
          new Error("injected registry release failure"),
        ]);
        return result;
      },
    }),
  ).rejects.toThrow("injected registry release failure");

  expect(await snapshotTree(active)).toEqual(before);
  expect(await hiddenTransactionDirectories(home)).toEqual([]);
});

test("keeps a valid promoted update active and warns when only backup cleanup fails", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("fixture-cleanup@1.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-cleanup",
      version: "1.0.0",
      id: "cleanup-old",
    }),
  });
  fileOperations.rmFailureIncludes.push(".backup-");

  const result = await installClientAdapter("fixture-cleanup@2.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-cleanup",
      version: "2.0.0",
      id: "cleanup-new",
    }),
  });

  expect(result).toEqual({
    plugin: {
      packageName: "fixture-cleanup",
      version: "2.0.0",
      requestedSpec: "fixture-cleanup@2.0.0",
    },
    warnings: ["inactive client adapter files require manual cleanup"],
  });
  expect(
    JSON.parse(
      await readFile(
        join(clientPluginsRoot(home), "fixture-cleanup", ".mcp-restrictor-client-plugin.json"),
        "utf8",
      ),
    ),
  ).toMatchObject({ version: "2.0.0" });
  const loaded = await loadInstalledClientAdapters({ home });
  expect(loaded.adapters.map(({ adapter }) => adapter.id)).toEqual(["cleanup-new"]);
  await expect(
    lstat(join(clientPluginsRoot(home), ".registry-promotion.json")),
  ).rejects.toMatchObject({ code: "ENOENT" });
  expect(
    (await readdir(clientPluginsRoot(home))).filter((name) => name.startsWith(".backup-")),
  ).toHaveLength(1);
  const journalClear = fileOperations.events.findIndex(
    (event) => event.startsWith("unlink:") && event.endsWith("/.registry-promotion.json"),
  );
  const backupCleanup = fileOperations.events.findIndex(
    (event) => event.startsWith("rm:") && event.includes(".backup-"),
  );
  expect(journalClear).toBeGreaterThanOrEqual(0);
  expect(backupCleanup).toBeGreaterThan(journalClear);
});

test.each([
  ["failed reader cleanup", true, false, ["inactive client adapter files require manual cleanup"]],
  ["successful reader cleanup", false, false, []],
  [
    "unexpected exact-backup check error",
    true,
    true,
    ["inactive client adapter files require manual cleanup"],
  ],
] as const)(
  "preserves cleanup state across a loader handoff: %s",
  async (_label, cleanupFails, existenceCheckFails, expectedWarnings) => {
    const home = await temporaryDirectory();
    await installClientAdapter("fixture-cleanup-handoff@1.0.0", {
      home,
      execFile: fakeNpmInstall({
        packageName: "fixture-cleanup-handoff",
        version: "1.0.0",
        id: "cleanup-handoff-old",
      }),
    });
    const root = clientPluginsRoot(home);
    const active = join(root, "fixture-cleanup-handoff");
    const promoted = deferred<void>();
    const releasePromotion = deferred<void>();
    fileOperations.promotionBarrier = {
      to: active,
      after: true,
      arrived: () => promoted.resolve(),
      wait: releasePromotion.promise,
    };

    const update = installClientAdapter("fixture-cleanup-handoff@2.0.0", {
      home,
      execFile: fakeNpmInstall({
        packageName: "fixture-cleanup-handoff",
        version: "2.0.0",
        id: "cleanup-handoff-new",
      }),
    });
    await promoted.promise;
    const journal = JSON.parse(await readFile(join(root, ".registry-promotion.json"), "utf8")) as {
      backup: string;
    };
    const backup = join(root, journal.backup);
    if (cleanupFails) fileOperations.rmFailureIncludes.push(".backup-");
    if (existenceCheckFails) {
      fileOperations.lstatFailures.set(backup, [
        undefined,
        new Error("injected exact-backup existence failure"),
      ]);
    }
    const acquired = deferred<void>();
    fileOperations.registryHandoff = {
      path: join(root, "..registry.lock"),
      released: () => undefined,
      acquired: () => acquired.resolve(),
      waitForAcquire: acquired.promise,
    };
    let loadSettled = false;
    const load = loadInstalledClientAdapters({ home }).finally(() => {
      loadSettled = true;
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(loadSettled).toBe(false);

    releasePromotion.resolve();
    const [result, loaded] = await Promise.all([update, load]);

    expect(result.warnings).toEqual(expectedWarnings);
    expect(loaded.adapters.map(({ adapter }) => adapter.id)).toEqual(["cleanup-handoff-new"]);
    expect(
      (await loadInstalledClientAdapters({ home })).adapters.map(({ adapter }) => adapter.id),
    ).toEqual(["cleanup-handoff-new"]);
  },
);

test("deduplicates backup and abandoned-stage cleanup failures into one warning", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("fixture-stage-cleanup@1.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-stage-cleanup",
      version: "1.0.0",
      id: "stage-cleanup-old",
    }),
  });
  fileOperations.rmFailureIncludes.push(".backup-", ".stage-");

  const result = await installClientAdapter("fixture-stage-cleanup@2.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-stage-cleanup",
      version: "2.0.0",
      id: "stage-cleanup-new",
    }),
  });

  expect(result.warnings).toEqual(["inactive client adapter files require manual cleanup"]);
  const loaded = await loadInstalledClientAdapters({ home });
  expect(loaded.adapters.map(({ adapter }) => adapter.id)).toEqual(["stage-cleanup-new"]);
});

test("keeps operation and stage cleanup failures in one ordered AggregateError", async () => {
  const home = await temporaryDirectory();
  fileOperations.rmFailureIncludes.push(".stage-");

  let caught: unknown;
  try {
    await installClientAdapter("fixture-operation-cleanup-failure@1.0.0", {
      home,
      execFile: async () => {
        throw new Error("npm-secret-operation-failure");
      },
    });
  } catch (error) {
    caught = error;
  }

  expect(caught).toBeInstanceOf(AggregateError);
  expect((caught as AggregateError).errors.map((error) => (error as Error).message)).toEqual([
    "client adapter installation failed",
    "injected cleanup failure",
  ]);
});

test("serializes concurrent updates and leaves the later fully validated version active", async () => {
  const home = await temporaryDirectory();
  await installClientAdapter("fixture-concurrent@1.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-concurrent",
      version: "1.0.0",
      id: "concurrent-old",
    }),
  });
  fileOperations.events.length = 0;
  const active = join(clientPluginsRoot(home), "fixture-concurrent");
  const firstAtPromotion = deferred<void>();
  const releaseFirst = deferred<void>();
  let secondStaged = false;
  fileOperations.promotionBarrier = {
    to: active,
    arrived: () => firstAtPromotion.resolve(),
    wait: releaseFirst.promise,
  };

  const first = installClientAdapter("fixture-concurrent@2.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-concurrent",
      version: "2.0.0",
      id: "concurrent-two",
    }),
  });
  await firstAtPromotion.promise;
  const second = installClientAdapter("fixture-concurrent@3.0.0", {
    home,
    execFile: fakeNpmInstall({
      packageName: "fixture-concurrent",
      version: "3.0.0",
      id: "concurrent-three",
      installed: () => {
        secondStaged = true;
      },
    }),
  });
  await new Promise<void>((resolve) => setImmediate(resolve));
  expect(secondStaged).toBe(false);
  expect(
    fileOperations.events.filter(
      (event) =>
        event.startsWith("rename:") && event.endsWith(`:${active}`) && event.includes(".stage-"),
    ),
  ).toHaveLength(1);
  releaseFirst.resolve();

  await expect(Promise.all([first, second])).resolves.toHaveLength(2);
  const metadata = JSON.parse(
    await readFile(join(active, ".mcp-restrictor-client-plugin.json"), "utf8"),
  );
  expect(metadata).toMatchObject({ version: "3.0.0", requestedSpec: "fixture-concurrent@3.0.0" });
  const generation = await activeGenerationPath(active);
  expect(dirname(generation)).toBe(clientPluginsRoot(home));
  expect(
    JSON.parse(
      await readFile(
        join(generation, "node_modules", "fixture-concurrent", "package.json"),
        "utf8",
      ),
    ),
  ).toMatchObject({ version: "3.0.0" });
  const loaded = await loadInstalledClientAdapters({ home });
  expect(loaded.adapters.map(({ adapter }) => adapter.id)).toEqual(["concurrent-three"]);
  expect(await hiddenTransactionDirectories(home)).toEqual([]);
});

type ExecCall = {
  file: string;
  args: string[];
  cwd: string;
  shell: false;
};

type TestExecFile = (
  file: string,
  args: readonly string[],
  options: { cwd: string; shell: false },
) => Promise<{ stdout: string; stderr: string }>;

function fakeNpmInstall(options: {
  packageName: string;
  id: string;
  version?: string;
  entrySource?: string;
  implementationSource?: string;
  calls?: ExecCall[];
  inspectStage?(prefix: string): Promise<void>;
  installed?(): void;
}): TestExecFile {
  return async (file, args, execOptions) => {
    options.calls?.push({
      file,
      args: [...args],
      cwd: execOptions.cwd,
      shell: execOptions.shell,
    });
    await options.inspectStage?.(execOptions.cwd);
    const version = options.version ?? "1.2.3";
    const packagePath = join(execOptions.cwd, "node_modules", ...options.packageName.split("/"));
    await mkdir(join(packagePath, "dist"), { recursive: true });
    await writeFile(
      join(execOptions.cwd, "package.json"),
      JSON.stringify({
        private: true,
        dependencies: { [options.packageName]: version },
      }),
    );
    await writeFile(
      join(packagePath, "package.json"),
      JSON.stringify({
        name: options.packageName,
        version,
        type: "module",
        mcpRestrictor: { clientAdapter: "./dist/index.js", apiVersion: 1 },
      }),
    );
    await writeFile(
      join(packagePath, "dist", "index.js"),
      options.entrySource ?? adapterModule(options.id, options.id),
    );
    if (options.implementationSource !== undefined) {
      await writeFile(join(packagePath, "dist", "implementation.js"), options.implementationSource);
    }
    options.installed?.();
    return { stdout: "", stderr: "" };
  };
}

async function expectPrivateFile(path: string): Promise<void> {
  const stat = await lstat(path);
  expect(stat.isFile()).toBe(true);
  expect(stat.isSymbolicLink()).toBe(false);
  if (process.platform !== "win32") expect(stat.mode & 0o7777).toBe(0o600);
}

async function expectPrivateDirectory(path: string): Promise<void> {
  const stat = await lstat(path);
  expect(stat.isDirectory()).toBe(true);
  expect(stat.isSymbolicLink()).toBe(false);
  if (process.platform !== "win32") expect(stat.mode & 0o7777).toBe(0o700);
}

async function hiddenTransactionDirectories(home: string): Promise<string[]> {
  return (await readdir(clientPluginsRoot(home)))
    .filter((name) => name.startsWith(".stage-") || name.startsWith(".backup-"))
    .sort();
}

async function activeGenerationPath(active: string): Promise<string> {
  const pointer = JSON.parse(
    await readFile(join(active, ".mcp-restrictor-client-generation.json"), "utf8"),
  ) as { generation: string };
  return join(dirname(active), pointer.generation);
}

async function writePromotionJournal(
  root: string,
  journal: { version: 1; target: string; backup?: string },
): Promise<void> {
  await writeFile(join(root, ".registry-promotion.json"), JSON.stringify(journal), { mode: 0o600 });
  await chmod(join(root, ".registry-promotion.json"), 0o600);
}

async function snapshotTree(root: string): Promise<
  Array<{
    path: string;
    type: "directory" | "file";
    mode: number;
    content?: string;
  }>
> {
  const entries: Array<{
    path: string;
    type: "directory" | "file";
    mode: number;
    content?: string;
  }> = [];
  async function visit(path: string): Promise<void> {
    const stat = await lstat(path);
    if (stat.isDirectory()) {
      entries.push({
        path: relative(root, path) || ".",
        type: "directory",
        mode: stat.mode & 0o7777,
      });
      for (const name of (await readdir(path)).sort()) await visit(join(path, name));
      return;
    }
    entries.push({
      path: relative(root, path),
      type: "file",
      mode: stat.mode & 0o7777,
      content: await readFile(path, "utf8"),
    });
  }
  await visit(root);
  return entries;
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((fulfill) => {
    resolve = fulfill;
  });
  return { promise, resolve };
}

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-client-plugins-")));
  temporaryDirectories.push(path);
  return path;
}

async function loadAdaptersInChild(home: string): Promise<{
  adapters: string[];
  unavailable: Array<{ packageName: string; reason: string }>;
}> {
  const source = `const { loadInstalledClientAdapters } = await import(process.argv[1]);
const result = await loadInstalledClientAdapters({ home: process.argv[2] });
process.stdout.write(JSON.stringify({
  adapters: result.adapters.map(({ adapter }) => adapter.id),
  unavailable: result.unavailable,
}));`;
  const { stdout, stderr } = await runFile(process.execPath, [
    "--input-type=module",
    "--eval",
    source,
    new URL("../dist/client-plugins.js", import.meta.url).href,
    home,
  ]);
  expect(String(stderr)).toBe("");
  return JSON.parse(String(stdout)) as {
    adapters: string[];
    unavailable: Array<{ packageName: string; reason: string }>;
  };
}

async function startAdapterHolder(
  home: string,
  graph: "generation" | "runtime",
): Promise<{
  pid: number;
  readLine(): Promise<string>;
  write(line: string): void;
  waitForExit(): Promise<number | null>;
  stop(): Promise<void>;
}> {
  const childSource = `import { createInterface } from 'node:readline';
const { loadInstalledClientAdapters } = await import(process.argv[1]);
const home = process.argv[2];
const graph = process.argv[3];
const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
let adapter;
async function load() {
  const result = await loadInstalledClientAdapters({ home });
  if (result.adapters.length !== 1) throw new Error('adapter unavailable');
  adapter = result.adapters[0].adapter;
}
try {
  if (graph === 'runtime') {
    const first = await loadInstalledClientAdapters({ home });
    if (first.adapters.length !== 0 || first.unavailable.length !== 1) {
      throw new Error('expected initial runtime failure');
    }
    process.stdout.write('FAILED\\n');
  } else {
    await load();
    process.stdout.write('READY\\n');
  }
  for await (const line of input) {
    if (line === 'RETRY') {
      await load();
      process.stdout.write('READY\\n');
    } else if (line === 'INVOKE') {
      try {
        const result = await adapter.load({}, {});
        process.stdout.write('RESULT:' + result.version + '\\n');
      } catch (error) {
        process.stdout.write('ERROR:' + (error?.code ?? error?.message ?? 'unknown') + '\\n');
      }
    } else if (line === 'EXIT') {
      break;
    }
  }
} catch (error) {
  process.stderr.write(String(error?.stack ?? error));
  process.exitCode = 1;
}`;
  const child: ChildProcessWithoutNullStreams = spawn(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      childSource,
      new URL("../dist/client-plugins.js", import.meta.url).href,
      home,
      graph,
    ],
    { stdio: "pipe" },
  );
  child.stdin.on("error", () => {});
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity })[
    Symbol.asyncIterator
  ]();
  const exit = once(child, "exit") as Promise<[number | null]>;
  return {
    pid: child.pid!,
    async readLine() {
      const line = await lines.next();
      if (line.done) throw new Error(`adapter holder exited: ${Buffer.concat(stderr).toString()}`);
      return line.value;
    },
    write(line) {
      if (line === "EXIT") child.stdin.end(`${line}\n`);
      else child.stdin.write(`${line}\n`);
    },
    async waitForExit() {
      const [code] = await exit;
      return code;
    },
    async stop() {
      if (child.exitCode === null) child.kill();
      await exit;
    },
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

type PluginOptions = {
  packageName: string;
  id: string;
  version?: string;
  label?: string;
  activeName?: string;
  manifestName?: string;
  manifestApiVersion?: number;
  clientAdapter?: string;
  entrySource?: string;
  implementationSource?: string;
  dependencyName?: string;
  extraDependency?: string;
  metadataVersion?: string;
  metadata?: Record<string, unknown>;
};

async function writePlugin(home: string, options: PluginOptions) {
  const root = clientPluginsRoot(home);
  const prefix = join(root, options.activeName ?? encodeURIComponent(options.packageName));
  const generationName = `.generation-${randomUUID()}`;
  const generation = join(root, generationName);
  const packagePath = join(generation, "node_modules", ...options.packageName.split("/"));
  const manifestPath = join(packagePath, "package.json");
  const entryPath = join(packagePath, "dist", "index.js");
  const metadataPath = join(prefix, ".mcp-restrictor-client-plugin.json");
  const version = options.version ?? "1.2.3";
  const metadata = options.metadata ?? {
    packageName: options.packageName,
    version: options.metadataVersion ?? version,
    requestedSpec: `${options.packageName}@${version}`,
  };
  const dependencies: Record<string, string> = {
    [options.dependencyName ?? options.packageName]: version,
  };
  if (options.extraDependency) dependencies[options.extraDependency] = version;

  await mkdir(dirname(entryPath), { recursive: true, mode: 0o700 });
  await mkdir(prefix, { recursive: true, mode: 0o700 });
  await writeFile(
    join(generation, "package.json"),
    JSON.stringify({
      private: true,
      dependencies,
    }),
  );
  await writeFile(metadataPath, JSON.stringify(metadata), { mode: 0o600 });
  await writeFile(
    join(prefix, ".mcp-restrictor-client-generation.json"),
    JSON.stringify({ generation: generationName }),
    { mode: 0o600 },
  );
  await writeFile(
    manifestPath,
    JSON.stringify({
      name: options.manifestName ?? options.packageName,
      version,
      type: "module",
      mcpRestrictor: {
        clientAdapter: options.clientAdapter ?? "./dist/index.js",
        apiVersion: options.manifestApiVersion ?? 1,
      },
    }),
  );
  await writeFile(
    entryPath,
    options.entrySource ?? adapterModule(options.id, options.label ?? options.id),
  );
  if (options.implementationSource !== undefined) {
    await writeFile(join(dirname(entryPath), "implementation.js"), options.implementationSource);
  }
  return { prefix, generation, packagePath, manifestPath, entryPath, metadataPath };
}

function adapterModule(id: string, label: string): string {
  return `export default {
  apiVersion: 1,
  id: ${JSON.stringify(id)},
  label: ${JSON.stringify(label)},
  async load() { return { configurations: [], unsupported: [] }; },
  render(config) { return config.source; }
};\n`;
}

function activePathSensitiveAdapter(id: string, secret: string): string {
  return `if (!decodeURIComponent(import.meta.url).includes('/.stage-')) {
  throw new Error(${JSON.stringify(secret)});
}
${adapterModule(id, id)}`;
}

function stagedExternalActiveAdapter(stagedId: string, activeId: string, sentinel: string): string {
  return `const active = !decodeURIComponent(import.meta.url).includes('/.stage-');
export default {
  apiVersion: 1,
  id: active ? ${JSON.stringify(activeId)} : ${JSON.stringify(stagedId)},
  label: active ? ${JSON.stringify(sentinel)} : 'safe staged adapter',
  async load() { return { configurations: [], unsupported: [] }; },
  render(config) { return config.source; }
};\n`;
}

function backupPathSensitiveAdapter(id: string): string {
  return `if (decodeURIComponent(import.meta.url).includes('/.backup-')) {
  throw new Error('adapter cannot execute from a backup path');
}
${adapterModule(id, id)}`;
}

function markerSensitiveAdapter(id: string, marker: string): string {
  return `import { existsSync } from 'node:fs';
if (!existsSync(${JSON.stringify(marker)})) {
  throw new Error('restored active import is temporarily unavailable');
}
${adapterModule(id, id)}`;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
