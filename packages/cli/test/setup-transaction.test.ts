import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { getEventListeners, once } from "node:events";
import { existsSync, writeFileSync } from "node:fs";
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
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import {
  applyFileTransaction,
  ensurePrivateDirectory,
  readPrivateFileSnapshot,
  readSnapshot,
  sha256,
  validatePrivateDirectory,
  withPrivateFileLock,
  writePrivateFileAtomically,
  type PlannedDelete,
  type PlannedWrite,
} from "../src/setup/transaction.ts";

const fileOperations = vi.hoisted(() => ({
  events: [] as string[],
  failSyncFor: undefined as string | undefined,
  failSyncTimes: 1,
  failCloseFor: undefined as string | undefined,
  swapBeforeOpen: undefined as { path: string; movedPath: string; target: string } | undefined,
  failReadFor: undefined as string | undefined,
  nonOwnerPath: undefined as string | undefined,
  abortContendedLink: undefined as { path: string; remaining: number } | undefined,
  lockPublicationBarrier: undefined as
    | {
        path: string;
        published(): void;
        release(): void;
        wait: Promise<void>;
      }
    | undefined,
  releaseLockBeforeOpen: undefined as { lock: string; target: string; content: string } | undefined,
  unlinkFailures: new Map<string, Error[]>(),
  unlinkEvent: undefined as { path: string; event: string; observed?: string[] } | undefined,
  pendingDelays: 0,
  delayStarted: undefined as (() => void) | undefined,
  installBarrier: undefined as
    | {
        target: string;
        renameArrivals: number;
        release(): void;
        wait: Promise<void>;
      }
    | undefined,
  reportedFileMode: undefined as number | undefined,
  rejectWindowsDirectorySync: false,
  processStats: new Map<number, string | Error>(),
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
    readFile: async (path: Parameters<typeof actual.readFile>[0], encoding: BufferEncoding) => {
      const match = /^\/proc\/([1-9][0-9]*)\/stat$/.exec(String(path));
      const result = match ? fileOperations.processStats.get(Number(match[1])) : undefined;
      if (result instanceof Error) throw result;
      if (result !== undefined) return result;
      return actual.readFile(path, encoding);
    },
    lstat: async (path: string) => {
      const result = withReportedMode(await actual.lstat(path));
      if (fileOperations.nonOwnerPath === path) {
        Object.defineProperty(result, "uid", { value: result.uid + 1 });
      }
      return result;
    },
    open: async (path: string, flags: string | number, mode?: number) => {
      fileOperations.events.push(`open:${path}:${flags}`);
      const release = fileOperations.releaseLockBeforeOpen;
      if (release?.lock === path) {
        fileOperations.releaseLockBeforeOpen = undefined;
        await actual.writeFile(release.target, release.content);
        await actual.unlink(release.lock);
      }
      const swap = fileOperations.swapBeforeOpen;
      if (swap?.path === path) {
        fileOperations.swapBeforeOpen = undefined;
        await actual.rename(path, swap.movedPath);
        await actual.symlink(swap.target, path);
      }
      const handle = await actual.open(path, flags, mode);
      const stat = handle.stat.bind(handle);
      handle.stat = (async () => withReportedMode(await stat())) as typeof handle.stat;
      if (fileOperations.failReadFor === path) {
        handle.readFile = (async () => {
          throw new Error("injected followed-target read");
        }) as typeof handle.readFile;
      }
      const sync = handle.sync.bind(handle);
      handle.sync = async () => {
        fileOperations.events.push(`sync:${path}`);
        if (
          fileOperations.rejectWindowsDirectorySync &&
          process.platform === "win32" &&
          (await handle.stat()).isDirectory()
        ) {
          throw Object.assign(new Error("injected Windows directory sync failure"), {
            code: "EINVAL",
          });
        }
        await sync();
        if (fileOperations.failSyncFor === path && fileOperations.failSyncTimes > 0) {
          fileOperations.failSyncTimes -= 1;
          if (fileOperations.failSyncTimes === 0) {
            fileOperations.failSyncFor = undefined;
          }
          throw new Error("injected sync failure");
        }
      };
      const close = handle.close.bind(handle);
      handle.close = async () => {
        await close();
        if (fileOperations.failCloseFor === path) {
          fileOperations.failCloseFor = undefined;
          throw new Error("injected close failure");
        }
      };
      return handle;
    },
    rename: async (from: string, to: string) => {
      fileOperations.events.push(`rename:${from}:${to}`);
      const barrier = fileOperations.installBarrier;
      if (barrier?.target === to) {
        barrier.renameArrivals += 1;
        if (barrier.renameArrivals === 2) barrier.release();
        await barrier.wait;
      }
      await actual.rename(from, to);
    },
    link: async (existingPath: string, newPath: string) => {
      try {
        await actual.link(existingPath, newPath);
        const barrier = fileOperations.lockPublicationBarrier;
        if (barrier?.path === newPath) {
          barrier.published();
          await barrier.wait;
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") {
          fileOperations.installBarrier?.release();
          const abort = fileOperations.abortContendedLink;
          if (abort?.path === newPath) {
            abort.remaining -= 1;
            if (abort.remaining === 0) {
              throw new Error("injected retry-loop guard");
            }
          }
        }
        throw error;
      }
    },
    unlink: async (path: string) => {
      if (fileOperations.unlinkEvent?.path === path) {
        fileOperations.events.push(fileOperations.unlinkEvent.event);
        fileOperations.unlinkEvent.observed?.push(fileOperations.unlinkEvent.event);
      }
      const failures = fileOperations.unlinkFailures.get(path);
      const failure = failures?.shift();
      if (failure) throw failure;
      await actual.unlink(path);
    },
  };
});

vi.mock("node:timers/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:timers/promises")>();
  return {
    ...actual,
    setTimeout: async (...args: Parameters<typeof actual.setTimeout>) => {
      fileOperations.pendingDelays += 1;
      fileOperations.delayStarted?.();
      try {
        return await actual.setTimeout(...args);
      } finally {
        fileOperations.pendingDelays -= 1;
      }
    },
  };
});

const temporaryDirectories: string[] = [];
const containerMarkerEnvironment = "MCP_RESTRICTOR_CONTAINER";
const initialContainerMarker = process.env[containerMarkerEnvironment];

afterEach(async () => {
  fileOperations.events.length = 0;
  fileOperations.failSyncFor = undefined;
  fileOperations.failSyncTimes = 1;
  fileOperations.failCloseFor = undefined;
  fileOperations.swapBeforeOpen = undefined;
  fileOperations.failReadFor = undefined;
  fileOperations.nonOwnerPath = undefined;
  fileOperations.abortContendedLink = undefined;
  fileOperations.lockPublicationBarrier?.release();
  fileOperations.lockPublicationBarrier = undefined;
  fileOperations.releaseLockBeforeOpen = undefined;
  fileOperations.unlinkFailures.clear();
  fileOperations.unlinkEvent = undefined;
  fileOperations.pendingDelays = 0;
  fileOperations.delayStarted = undefined;
  fileOperations.installBarrier?.release();
  fileOperations.installBarrier = undefined;
  fileOperations.reportedFileMode = undefined;
  fileOperations.rejectWindowsDirectorySync = false;
  fileOperations.processStats.clear();
  if (initialContainerMarker === undefined) delete process.env[containerMarkerEnvironment];
  else process.env[containerMarkerEnvironment] = initialContainerMarker;
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { force: true, recursive: true })),
  );
});

test("writes a private file through a synced sibling temp and durable rename", async () => {
  const root = await temporaryDirectory();
  const parent = join(root, "private", "profiles");
  const target = join(parent, "profile.json");
  const temporary = join(parent, ".profile.json.private-write.tmp");

  await ensurePrivateDirectory(parent);
  expect(await mode(parent)).toBe(0o700);
  fileOperations.events.length = 0;

  const snapshot = await writePrivateFileAtomically({
    path: target,
    content: "encrypted profile",
    nonce: "private-write",
  });

  expect(await readFile(target, "utf8")).toBe("encrypted profile");
  expect(await mode(target)).toBe(0o600);
  expect((await lstat(target)).ino).toBe(snapshot.ino);
  expect(fileOperations.events.filter((event) => !event.includes(".lock"))).toEqual([
    `open:${temporary}:wx`,
    `sync:${temporary}`,
    `rename:${temporary}:${target}`,
    `open:${parent}:r`,
    `sync:${parent}`,
  ]);
  expect(await exists(temporary)).toBe(false);
});

test("private write preserves old bytes and cleans its temp on failure", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  const temporary = join(dirname(target), ".profile.json.failed-write.tmp");
  await existingFile(target, "before", 0o600);
  const before = await readSnapshot(target);
  fileOperations.failSyncFor = temporary;

  await expect(
    writePrivateFileAtomically({
      path: target,
      content: "replacement",
      before: before!,
      nonce: "failed-write",
    }),
  ).rejects.toThrow(/sync failure/);

  expect(await readFile(target, "utf8")).toBe("before");
  expect(await exists(temporary)).toBe(false);
});

test("private write restores an existing target when parent sync fails after install", async () => {
  const root = await temporaryDirectory();
  const parent = join(root, "profiles");
  const target = join(parent, "profile.json");
  await existingFile(target, "before", 0o600);
  const before = await readSnapshot(target);
  fileOperations.failSyncFor = parent;

  await expect(
    writePrivateFileAtomically({
      path: target,
      content: "installed",
      before: before!,
      nonce: "parent-sync-failure",
    }),
  ).rejects.toThrow(/sync failure/);

  expect(await readFile(target, "utf8")).toBe("before");
  expect(await temporaryFiles(root)).toEqual([]);
});

test("private write removes a new target when parent close fails after install", async () => {
  const root = await temporaryDirectory();
  const parent = join(root, "profiles");
  const target = join(parent, "profile.json");
  fileOperations.failCloseFor = parent;

  await expect(
    writePrivateFileAtomically({
      path: target,
      content: "installed",
      nonce: "parent-close-failure",
    }),
  ).rejects.toThrow(/close failure/);

  expect(await exists(target)).toBe(false);
  expect(await temporaryFiles(root)).toEqual([]);
});

test("private write aggregates a rollback durability failure after restoring bytes", async () => {
  const root = await temporaryDirectory();
  const parent = join(root, "profiles");
  const target = join(parent, "profile.json");
  await existingFile(target, "before", 0o600);
  const before = await readSnapshot(target);
  fileOperations.failSyncFor = parent;
  fileOperations.failSyncTimes = 2;

  let caught: unknown;
  try {
    await writePrivateFileAtomically({
      path: target,
      content: "installed",
      before: before!,
      nonce: "rollback-sync-failure",
    });
  } catch (error) {
    caught = error;
  }

  expect(caught).toBeInstanceOf(AggregateError);
  expect((caught as AggregateError).errors).toHaveLength(2);
  expect(await readFile(target, "utf8")).toBe("before");
  expect(await temporaryFiles(root)).toEqual([]);
});

test.each([
  ["new target", undefined],
  ["existing target", "before"],
] as const)(
  "private write restores %s before reporting a lock release failure",
  async (_name, original) => {
    const root = await temporaryDirectory();
    const target = join(root, "profiles", "profile.json");
    if (original !== undefined) await existingFile(target, original, 0o600);
    const before = await readSnapshot(target);
    const lock = join(dirname(target), ".profile.json.lock");
    fileOperations.unlinkFailures.set(lock, [new Error("injected lock release failure")]);

    await expect(
      writePrivateFileAtomically({
        path: target,
        content: "installed",
        ...(before ? { before } : {}),
      }),
    ).rejects.toThrow("injected lock release failure");

    if (original === undefined) {
      expect(await exists(target)).toBe(false);
    } else {
      expect(await readFile(target, "utf8")).toBe(original);
    }
    expect(await exists(lock)).toBe(false);
  },
);

test("private write aggregates lock release then rollback failure in order", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  const lock = join(dirname(target), ".profile.json.lock");
  fileOperations.unlinkFailures.set(lock, [new Error("injected lock release failure")]);
  fileOperations.unlinkFailures.set(target, [new Error("injected release rollback failure")]);

  let caught: unknown;
  try {
    await writePrivateFileAtomically({ path: target, content: "installed" });
  } catch (error) {
    caught = error;
  }

  expect(caught).toBeInstanceOf(AggregateError);
  expect((caught as AggregateError).errors.map((error) => (error as Error).message)).toEqual([
    "injected lock release failure",
    "injected release rollback failure",
  ]);
  expect(await readFile(target, "utf8")).toBe("installed");
  expect(await exists(lock)).toBe(false);
});

test("private write rejects a stale expected snapshot", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  await existingFile(target, "before", 0o600);
  const before = await readSnapshot(target);
  await writeFile(target, "concurrent edit");

  await expect(
    writePrivateFileAtomically({ path: target, content: "replacement", before: before! }),
  ).rejects.toThrow(/changed/);

  expect(await readFile(target, "utf8")).toBe("concurrent edit");
});

test("serializes snapshot validation with install so exactly one concurrent writer wins", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  await existingFile(target, "before", 0o600);
  const before = await readSnapshot(target);
  let release!: () => void;
  const wait = new Promise<void>((resolve) => {
    release = resolve;
  });
  fileOperations.installBarrier = {
    target,
    renameArrivals: 0,
    release,
    wait,
  };

  const outcomes = await Promise.allSettled([
    writePrivateFileAtomically({
      path: target,
      content: "writer one",
      before: before!,
      nonce: "writer-one",
    }),
    writePrivateFileAtomically({
      path: target,
      content: "writer two",
      before: before!,
      nonce: "writer-two",
    }),
  ]);

  expect(outcomes.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
  const failure = outcomes.find(({ status }) => status === "rejected");
  expect(failure).toMatchObject({
    reason: expect.objectContaining({
      message: expect.stringMatching(/changed|stale/i),
    }),
  });
  expect(["writer one", "writer two"]).toContain(await readFile(target, "utf8"));
});

test("serializes independent operations that share one private lock target", async () => {
  const root = await temporaryDirectory();
  const registry = join(root, "client-plugins", ".registry");
  let releaseFirst!: () => void;
  let firstEntered!: () => void;
  const entered = new Promise<void>((resolve) => {
    firstEntered = resolve;
  });
  const wait = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  const events: string[] = [];

  const first = withPrivateFileLock(registry, async () => {
    events.push("first entered");
    firstEntered();
    await wait;
    events.push("first leaving");
  });
  await entered;
  const second = withPrivateFileLock(registry, async () => {
    events.push("second entered");
  });
  await new Promise<void>((resolve) => setImmediate(resolve));
  expect(events).toEqual(["first entered"]);
  releaseFirst();

  await Promise.all([first, second]);
  expect(events).toEqual(["first entered", "first leaving", "second entered"]);
});

test.sequential("keeps a container lock with the current PID and process start identity contended", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  process.env[containerMarkerEnvironment] = "1";
  fileOperations.processStats.set(process.pid, processStat(process.pid, "101"));
  const lock = await privateLock(target, {
    version: 2,
    pid: process.pid,
    processStart: "101",
    token: "11111111-1111-4111-8111-111111111111",
  });
  const operation = vi.fn(async () => "unexpected");

  await withProcessPlatform("linux", async () => {
    await expect(
      withPrivateFileLock(target, operation, { timeoutMs: 20, delayMs: 1_000 }),
    ).rejects.toThrow(/timed out/i);
  });

  expect(operation).not.toHaveBeenCalled();
  expect(await exists(lock)).toBe(true);
});

test.sequential("reaps a container lock when the PID has a different process start", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  process.env[containerMarkerEnvironment] = "1";
  fileOperations.processStats.set(process.pid, processStat(process.pid, "202"));
  const lock = await privateLock(target, {
    version: 2,
    pid: process.pid,
    processStart: "101",
    token: "11111111-1111-4111-8111-111111111111",
  });

  await withProcessPlatform("linux", async () => {
    await expect(withPrivateFileLock(target, async () => "acquired")).resolves.toBe("acquired");
  });

  expect(await exists(lock)).toBe(false);
});

test.sequential("treats a legacy owner as stale under the exact container marker", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  process.env[containerMarkerEnvironment] = "1";
  fileOperations.processStats.set(process.pid, processStat(process.pid, "101"));
  const lock = await livePrivateLock(target);

  await withProcessPlatform("linux", async () => {
    await expect(
      withPrivateFileLock(target, async () => "acquired", { timeoutMs: 500, delayMs: 1 }),
    ).resolves.toBe("acquired");
  });

  expect(await exists(lock)).toBe(false);
});

test.each([undefined, "true"])(
  "keeps native legacy owner behavior without the exact container marker: %s",
  async (marker) => {
    const root = await temporaryDirectory();
    const target = join(root, "profiles", "profile.json");
    if (marker === undefined) delete process.env[containerMarkerEnvironment];
    else process.env[containerMarkerEnvironment] = marker;
    const lock = await livePrivateLock(target);
    const operation = vi.fn(async () => "unexpected");

    await expect(
      withPrivateFileLock(target, operation, { timeoutMs: 20, delayMs: 1_000 }),
    ).rejects.toThrow(/timed out/i);

    expect(operation).not.toHaveBeenCalled();
    expect(await exists(lock)).toBe(true);
  },
);

test.sequential("keeps a live child process container lock contended", async () => {
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], {
    stdio: "ignore",
  });
  await once(child, "spawn");
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  process.env[containerMarkerEnvironment] = "1";
  fileOperations.processStats.set(process.pid, processStat(process.pid, "101"));
  fileOperations.processStats.set(child.pid!, processStat(child.pid!, "303", "child) worker"));
  const lock = await privateLock(target, {
    version: 2,
    pid: child.pid!,
    processStart: "303",
    token: "11111111-1111-4111-8111-111111111111",
  });
  const operation = vi.fn(async () => "unexpected");

  try {
    await withProcessPlatform("linux", async () => {
      await expect(
        withPrivateFileLock(target, operation, { timeoutMs: 20, delayMs: 1_000 }),
      ).rejects.toThrow(/timed out/i);
    });
  } finally {
    child.kill();
    await once(child, "exit");
  }

  expect(operation).not.toHaveBeenCalled();
  expect(await exists(lock)).toBe(true);
});

test.sequential("leaves decoy lock-like files untouched during container lock recovery", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  process.env[containerMarkerEnvironment] = "1";
  fileOperations.processStats.set(process.pid, processStat(process.pid, "202"));
  const lock = await privateLock(target, {
    version: 2,
    pid: process.pid,
    processStart: "101",
    token: "11111111-1111-4111-8111-111111111111",
  });
  const decoys = [`${lock}.backup`, `${lock}.11111111-1111-4111-8111-111111111111.tmp`];
  await Promise.all(decoys.map((path) => writeFile(path, "decoy", { mode: 0o600 })));

  await withProcessPlatform("linux", async () => {
    await expect(withPrivateFileLock(target, async () => "acquired")).resolves.toBe("acquired");
  });

  await expect(Promise.all(decoys.map((path) => readFile(path, "utf8")))).resolves.toEqual([
    "decoy",
    "decoy",
  ]);
});

test.sequential.each([
  [
    "unavailable",
    Object.assign(new Error("missing proc stat"), { code: "ENOENT" }) as string | Error,
  ],
  ["malformed", "not a process stat" as string | Error],
])(
  "fails closed before publishing a container lock when process start identity is %s",
  async (_case, stat) => {
    const root = await temporaryDirectory();
    const target = join(root, "profiles", "profile.json");
    const lock = join(dirname(target), ".profile.json.lock");
    process.env[containerMarkerEnvironment] = "1";
    fileOperations.processStats.set(process.pid, stat);
    const operation = vi.fn(async () => "unexpected");

    await withProcessPlatform("linux", async () => {
      await expect(withPrivateFileLock(target, operation)).rejects.toThrow(
        /process start identity/i,
      );
    });

    expect(operation).not.toHaveBeenCalled();
    expect(await exists(lock)).toBe(false);
    expect(await temporaryFiles(root)).toEqual([]);
  },
);

test("retries when an incumbent lock disappears between lstat and open", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  await existingFile(target, "before", 0o600);
  const before = await readSnapshot(target);
  const lock = await livePrivateLock(target);
  fileOperations.releaseLockBeforeOpen = {
    lock,
    target,
    content: "winner",
  };

  await expect(
    writePrivateFileAtomically({
      path: target,
      content: "loser",
      before: before!,
      nonce: "disappearing-lock",
    }),
  ).rejects.toThrow(/changed|stale/i);

  expect(await readFile(target, "utf8")).toBe("winner");
  expect(await exists(lock)).toBe(false);
  expect(await temporaryFiles(root)).toEqual([]);
});

test("fails closed instead of spinning on an orphaned lock recovery marker", async () => {
  const root = await temporaryDirectory();
  const parent = join(root, "profiles");
  const target = join(parent, "profile.json");
  const lock = join(parent, ".profile.json.lock");
  const deadPid = 4_000_000;
  await ensurePrivateDirectory(parent);
  await writeFile(
    lock,
    JSON.stringify({
      version: 1,
      pid: deadPid,
      token: "11111111-1111-4111-8111-111111111111",
    }),
    { mode: 0o600 },
  );
  await chmod(lock, 0o600);
  await mkdir(`${lock}.reap`, { mode: 0o700 });
  fileOperations.abortContendedLink = { path: lock, remaining: 3 };
  const originalKill = process.kill.bind(process);
  const kill = vi.spyOn(process, "kill").mockImplementation((pid, signal) => {
    if (pid === deadPid) {
      throw Object.assign(new Error("dead test process"), { code: "ESRCH" });
    }
    return originalKill(pid, signal);
  });

  try {
    await expect(
      writePrivateFileAtomically({ path: target, content: "encrypted" }),
    ).rejects.toThrow(/recovery/i);
  } finally {
    kill.mockRestore();
  }

  expect(await exists(target)).toBe(false);
});

test("bounds live-PID lock contention with a timeout", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  const lock = await livePrivateLock(target);
  fileOperations.abortContendedLink = { path: lock, remaining: 20 };
  const operation = vi.fn(async () => "unexpected");
  const startedAt = Date.now();

  await expect(
    withPrivateFileLock(target, operation, {
      timeoutMs: 20,
      delayMs: 1_000,
    }),
  ).rejects.toThrow(/timed out/i);

  expect(Date.now() - startedAt).toBeLessThan(500);
  expect(operation).not.toHaveBeenCalled();
});

test("cancels live-PID lock contention without a listener or timer leak", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  const lock = await livePrivateLock(target);
  fileOperations.abortContendedLink = { path: lock, remaining: 20 };
  const controller = new AbortController();
  const reason = new Error("injected lock cancellation");
  const operation = vi.fn(async () => "unexpected");
  let started!: () => void;
  const waiting = new Promise<void>((resolve) => {
    started = resolve;
  });
  fileOperations.delayStarted = started;
  const attempt = withPrivateFileLock(target, operation, {
    signal: controller.signal,
    timeoutMs: 30_000,
    delayMs: 30_000,
  });
  void attempt.catch(() => {});
  await waiting;

  expect(fileOperations.pendingDelays).toBe(1);
  expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
  controller.abort(reason);

  await expect(attempt).rejects.toBe(reason);
  expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
  expect(fileOperations.pendingDelays).toBe(0);
  expect(operation).not.toHaveBeenCalled();
});

test("cancels after lock publication before running the operation", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  const lock = join(dirname(target), ".profile.json.lock");
  const controller = new AbortController();
  const reason = new Error("injected publication cancellation");
  const operation = vi.fn(async () => "unexpected");
  let published!: () => void;
  let release!: () => void;
  const publication = new Promise<void>((resolve) => {
    published = resolve;
  });
  const wait = new Promise<void>((resolve) => {
    release = resolve;
  });
  fileOperations.lockPublicationBarrier = { path: lock, published, release, wait };

  const attempt = withPrivateFileLock(target, operation, {
    signal: controller.signal,
  });
  void attempt.catch(() => {});
  await publication;
  controller.abort(reason);
  release();

  await expect(attempt).rejects.toBe(reason);
  expect(operation).not.toHaveBeenCalled();
  expect(await exists(lock)).toBe(false);
  expect(await temporaryFiles(root)).toEqual([]);
  expect(fileOperations.pendingDelays).toBe(0);
  expect(getEventListeners(controller.signal, "abort")).toHaveLength(0);
});

test("aggregates cancellation release failure and removes the published lock", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  const lock = join(dirname(target), ".profile.json.lock");
  const controller = new AbortController();
  const reason = new Error("injected publication cancellation");
  const releaseError = new Error("injected cancellation release failure");
  const operation = vi.fn(async () => "unexpected");
  let published!: () => void;
  let release!: () => void;
  const publication = new Promise<void>((resolve) => {
    published = resolve;
  });
  const wait = new Promise<void>((resolve) => {
    release = resolve;
  });
  fileOperations.lockPublicationBarrier = { path: lock, published, release, wait };
  fileOperations.unlinkFailures.set(lock, [releaseError]);

  const attempt = withPrivateFileLock(target, operation, {
    signal: controller.signal,
  });
  void attempt.catch(() => {});
  await publication;
  controller.abort(reason);
  release();

  let caught: unknown;
  try {
    await attempt;
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(AggregateError);
  expect((caught as AggregateError).errors).toEqual([reason, releaseError]);
  expect(operation).not.toHaveBeenCalled();
  expect(await exists(lock)).toBe(false);
  expect(await temporaryFiles(root)).toEqual([]);
});

test("private write rejects a snapshot for another path", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");
  await existingFile(target, "before", 0o600);
  const before = await readSnapshot(target);

  await expect(
    writePrivateFileAtomically({
      path: target,
      content: "replacement",
      before: { ...before!, path: join(root, "other.json") },
    }),
  ).rejects.toThrow(/snapshot path/i);

  expect(await readFile(target, "utf8")).toBe("before");
});

test("private write rejects a nonce that cannot name a sibling temp", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "profiles", "profile.json");

  await expect(
    writePrivateFileAtomically({
      path: target,
      content: "content",
      nonce: "../../escaped",
    }),
  ).rejects.toThrow(/nonce/i);

  expect(await exists(target)).toBe(false);
  expect(await exists(join(root, "escaped.tmp"))).toBe(false);
});

test("private write rejects symlinked ancestors and targets", async () => {
  const root = await temporaryDirectory();
  const external = join(root, "external");
  const linkedParent = join(root, "linked-parent");
  const regular = join(root, "regular");
  const linkedTarget = join(root, "linked-target");
  await mkdir(external);
  await symlink(external, linkedParent);
  await existingFile(regular, "old bytes", 0o600);
  await symlink(regular, linkedTarget);

  await expect(
    writePrivateFileAtomically({
      path: join(linkedParent, "profile.json"),
      content: "outside write",
    }),
  ).rejects.toThrow(/symlink/i);
  await expect(
    writePrivateFileAtomically({
      path: linkedTarget,
      content: "replacement",
    }),
  ).rejects.toThrow(/regular file|symlink/i);

  expect(await readdir(external)).toEqual([]);
  expect(await readFile(regular, "utf8")).toBe("old bytes");
  expect(await temporaryFiles(root)).toEqual([]);
});

test("commits two policies before two configs with private complete backups", async () => {
  const root = await temporaryDirectory();
  const backupRoot = join(root, ".mcp-restrictor", "backups");
  const claudeConfig = join(root, "configs", "claude.json");
  const codexConfig = join(root, "configs", "config.toml");
  const claudePolicy = join(root, "policies", "claude.yaml");
  const codexPolicy = join(root, "policies", "codex.yaml");
  await Promise.all([
    existingFile(claudeConfig, "old claude", 0o640),
    existingFile(codexConfig, "old codex", 0o600),
    existingFile(claudePolicy, "old claude policy", 0o644),
    existingFile(codexPolicy, "old codex policy", 0o604),
  ]);
  const [beforeClaudeConfig, beforeCodexConfig, beforeClaudePolicy, beforeCodexPolicy] =
    await Promise.all([
      readSnapshot(claudeConfig),
      readSnapshot(codexConfig),
      readSnapshot(claudePolicy),
      readSnapshot(codexPolicy),
    ]);
  const writes: PlannedWrite[] = [
    planned(claudeConfig, beforeClaudeConfig!, "new claude", 0o640, claudeConfig),
    planned(codexConfig, beforeCodexConfig!, "new codex", 0o600, codexConfig),
    planned(claudePolicy, beforeClaudePolicy!, "new claude policy", 0o644, claudeConfig),
    planned(codexPolicy, beforeCodexPolicy!, "new codex policy", 0o604, codexConfig),
  ];

  const result = await applyFileTransaction(writes, {
    backupRoot,
    now: new Date("2026-08-11T01:02:03.004Z"),
    nonce: "fixed",
    verify: async () => {
      expect(await readFile(claudePolicy, "utf8")).toBe("new claude policy");
      expect(await readFile(codexPolicy, "utf8")).toBe("new codex policy");
      expect(await readFile(claudeConfig, "utf8")).toBe("new claude");
      expect(await readFile(codexConfig, "utf8")).toBe("new codex");
    },
  });

  const stamp = "2026-08-11T01-02-03.004Z-fixed";
  const claudeBackup = join(backupRoot, digest(claudeConfig), stamp);
  const codexBackup = join(backupRoot, digest(codexConfig), stamp);
  expect(new Set(result.backupDirectories)).toEqual(new Set([claudeBackup, codexBackup]));
  for (const path of [
    dirname(backupRoot),
    backupRoot,
    dirname(claudeBackup),
    claudeBackup,
    dirname(codexBackup),
    codexBackup,
  ]) {
    expect(await mode(path)).toBe(0o700);
  }
  for (const [directory, path, content] of [
    [claudeBackup, claudeConfig, "old claude"],
    [claudeBackup, claudePolicy, "old claude policy"],
    [codexBackup, codexConfig, "old codex"],
    [codexBackup, codexPolicy, "old codex policy"],
  ] as const) {
    const backup = join(directory, basename(path));
    expect(await readFile(backup, "utf8")).toBe(content);
    expect(await mode(backup)).toBe(0o600);
  }
  expect(await mode(claudeConfig)).toBe(0o640);
  expect(await mode(codexConfig)).toBe(0o600);
  expect(await mode(claudePolicy)).toBe(0o644);
  expect(await mode(codexPolicy)).toBe(0o604);
  expect(await temporaryFiles(root)).toEqual([]);
});

test("applies planned delete in caller order", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const policy = join(root, "policy.yaml");
  const state = join(root, "state.json");
  const backupRoot = join(root, ".mcp-restrictor", "backups");
  await Promise.all([
    existingFile(config, "old config", 0o600),
    existingFile(policy, "old policy", 0o644),
    existingFile(state, "old state", 0o600),
  ]);
  const [beforeConfig, beforePolicy, beforeState] = await Promise.all([
    readSnapshot(config),
    readSnapshot(policy),
    readSnapshot(state),
  ]);
  const observed: string[] = [];
  const configWrite = planned(config, beforeConfig!, "config", 0o600, config);
  const remove: PlannedDelete = {
    delete: true,
    path: policy,
    before: beforePolicy!,
    backupKey: config,
  };
  const stateWrite = planned(state, beforeState!, "state", 0o600, state);
  Object.defineProperty(configWrite, "content", {
    enumerable: true,
    get: () => {
      observed.push("config");
      return "config";
    },
  });
  Object.defineProperty(stateWrite, "content", {
    enumerable: true,
    get: () => {
      observed.push("state");
      return "state";
    },
  });
  fileOperations.unlinkEvent = { path: policy, event: "delete-policy", observed };

  await applyFileTransaction([configWrite, remove, stateWrite], {
    backupRoot,
    verify: async () => {
      observed.push("verify");
    },
  });

  expect(observed).toEqual(["config", "delete-policy", "state", "verify"]);
  expect(await exists(policy)).toBe(false);
  expect(fileOperations.events).toContain(`sync:${dirname(policy)}`);
});

test("planned delete removes a private file", async () => {
  const root = await temporaryDirectory();
  const profile = join(root, "profiles", "profile.json");
  await ensurePrivateDirectory(dirname(profile));
  await existingFile(profile, "secret", 0o600);
  const before = await readSnapshot(profile);

  await applyFileTransaction(
    [
      {
        delete: true,
        path: profile,
        before: before!,
        backupKey: profile,
        private: true,
      } satisfies PlannedDelete,
    ],
    { backupRoot: join(root, "backups"), verify: async () => {} },
  );

  expect(await exists(profile)).toBe(false);
  expect(await exists(join(dirname(profile), ".profile.json.lock"))).toBe(false);
});

test("planned delete restores exact bytes and mode after verification fails", async () => {
  const root = await temporaryDirectory();
  const policy = join(root, "policy.yaml");
  await existingFile(policy, "original policy", 0o640);
  const before = await readSnapshot(policy);
  const failure = new Error("verification failed");

  await expect(
    applyFileTransaction(
      [{ delete: true, path: policy, before: before!, backupKey: policy } satisfies PlannedDelete],
      {
        backupRoot: join(root, "backups"),
        verify: async () => {
          throw failure;
        },
      },
    ),
  ).rejects.toBe(failure);

  expect(await readFile(policy, "utf8")).toBe("original policy");
  expect(await mode(policy)).toBe(0o640);
});

test.each([
  ["non-private", false],
  ["private", true],
] as const)(
  "planned delete restores a %s target when parent sync fails",
  async (_name, privateTarget) => {
    const root = await temporaryDirectory();
    const target = privateTarget
      ? join(root, "profiles", "profile.json")
      : join(root, "policy.yaml");
    if (privateTarget) await ensurePrivateDirectory(dirname(target));
    await existingFile(target, "original", privateTarget ? 0o600 : 0o640);
    const before = await readSnapshot(target);
    fileOperations.failSyncFor = dirname(target);

    await expect(
      applyFileTransaction(
        [
          {
            delete: true,
            path: target,
            before: before!,
            backupKey: target,
            ...(privateTarget ? { private: true } : {}),
          } satisfies PlannedDelete,
        ],
        { backupRoot: join(root, "backups"), verify: async () => {} },
      ),
    ).rejects.toThrow("injected sync failure");

    expect(await readFile(target, "utf8")).toBe("original");
    expect(await mode(target)).toBe(privateTarget ? 0o600 : 0o640);
    if (privateTarget) {
      expect(await exists(join(dirname(target), ".profile.json.lock"))).toBe(false);
    }
  },
);

test("planned delete leaves a target that appears before rollback intact", async () => {
  const root = await temporaryDirectory();
  const policy = join(root, "policy.yaml");
  await existingFile(policy, "original policy", 0o640);
  const before = await readSnapshot(policy);
  const failure = new Error("verification failed");

  await expect(
    applyFileTransaction(
      [{ delete: true, path: policy, before: before!, backupKey: policy } satisfies PlannedDelete],
      {
        backupRoot: join(root, "backups"),
        verify: async () => {
          await existingFile(policy, "concurrent policy", 0o600);
          throw failure;
        },
      },
    ),
  ).rejects.toBe(failure);

  expect(await readFile(policy, "utf8")).toBe("concurrent policy");
  expect(await mode(policy)).toBe(0o600);
});

test("delete failure rolls back earlier changes", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const policy = join(root, "policy.yaml");
  await Promise.all([
    existingFile(config, "original config", 0o600),
    existingFile(policy, "policy", 0o644),
  ]);
  const [beforeConfig, beforePolicy] = await Promise.all([
    readSnapshot(config),
    readSnapshot(policy),
  ]);
  fileOperations.unlinkFailures.set(policy, [new Error("injected delete failure")]);

  await expect(
    applyFileTransaction(
      [
        planned(config, beforeConfig!, "replacement", 0o600, config),
        {
          delete: true,
          path: policy,
          before: beforePolicy!,
          backupKey: config,
        } satisfies PlannedDelete,
      ],
      { backupRoot: join(root, "backups"), verify: async () => {} },
    ),
  ).rejects.toThrow("injected delete failure");

  expect(await readFile(config, "utf8")).toBe("original config");
  expect(await readFile(policy, "utf8")).toBe("policy");
});

test("private planned delete restores its target when lock release fails", async () => {
  const root = await temporaryDirectory();
  const profile = join(root, "profiles", "profile.json");
  await ensurePrivateDirectory(dirname(profile));
  await existingFile(profile, "secret", 0o600);
  const before = await readSnapshot(profile);
  const lock = join(dirname(profile), ".profile.json.lock");
  fileOperations.unlinkFailures.set(lock, [new Error("injected lock release failure")]);

  await expect(
    applyFileTransaction(
      [
        {
          delete: true,
          path: profile,
          before: before!,
          backupKey: profile,
          private: true,
        } satisfies PlannedDelete,
      ],
      { backupRoot: join(root, "backups"), verify: async () => {} },
    ),
  ).rejects.toThrow("injected lock release failure");

  expect(await readFile(profile, "utf8")).toBe("secret");
  expect(await mode(profile)).toBe(0o600);
  expect(await exists(lock)).toBe(false);
});

test("private planned delete rolls back under its lock", async () => {
  const root = await temporaryDirectory();
  const profile = join(root, "profiles", "profile.json");
  await ensurePrivateDirectory(dirname(profile));
  await existingFile(profile, "secret", 0o600);
  const before = await readSnapshot(profile);
  const lock = join(dirname(profile), ".profile.json.lock");
  const failure = new Error("verification failed");

  let caught: unknown;
  try {
    await applyFileTransaction(
      [
        {
          delete: true,
          path: profile,
          before: before!,
          backupKey: profile,
          private: true,
        } satisfies PlannedDelete,
      ],
      {
        backupRoot: join(root, "backups"),
        verify: async () => {
          fileOperations.unlinkFailures.set(lock, [new Error("rollback release failure")]);
          throw failure;
        },
      },
    );
  } catch (error) {
    caught = error;
  }

  expect(caught).toBeInstanceOf(AggregateError);
  expect((caught as AggregateError).errors[0]).toBe(failure);
  expect((caught as AggregateError).errors[1]).toMatchObject({
    message: "rollback release failure",
  });
  expect(await readFile(profile, "utf8")).toBe("secret");
  expect(await exists(lock)).toBe(false);
});

test("validates private directories without repairing unsafe state", async () => {
  const root = await temporaryDirectory();
  const valid = join(root, "valid");
  const missing = join(root, "missing");
  const regular = join(root, "regular");
  const unsafeMode = join(root, "unsafe-mode");
  const nonOwner = join(root, "non-owner");
  const linked = join(root, "linked");
  await Promise.all([
    mkdir(valid, { mode: 0o700 }),
    writeFile(regular, "not a directory"),
    mkdir(unsafeMode, { mode: 0o755 }),
    mkdir(nonOwner, { mode: 0o700 }),
  ]);
  await symlink(valid, linked);

  await expect(validatePrivateDirectory(valid, "Private state directory")).resolves.toBeUndefined();
  await expect(validatePrivateDirectory(missing, "Private state directory")).rejects.toThrow();
  await expect(validatePrivateDirectory(regular, "Private state directory")).rejects.toThrow(
    /directory/i,
  );
  await expect(validatePrivateDirectory(linked, "Private state directory")).rejects.toThrow(
    /symlink/i,
  );
  await expect(validatePrivateDirectory(unsafeMode, "Private state directory")).rejects.toThrow(
    /0700/,
  );
  fileOperations.nonOwnerPath = nonOwner;
  await expect(validatePrivateDirectory(nonOwner, "Private state directory")).rejects.toThrow(
    /owned/i,
  );

  expect(await mode(unsafeMode)).toBe(0o755);
  expect(sha256("backup key")).toBe(
    "08c0805922501f99c041b654e6ca7e71bbe0af81f114b99f1bbb7870c6b5dd73",
  );
});

test("rechecks a later target after an earlier policy rename", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const policy = join(root, "policy.yaml");
  const backupRoot = join(root, ".mcp-restrictor", "backups");
  await existingFile(config, "before", 0o640);
  const before = await readSnapshot(config);
  const configWrite = planned(config, before!, "replacement", 0o640, config);
  Object.defineProperty(configWrite, "content", {
    enumerable: true,
    get: () => {
      writeFileSync(config, "concurrent edit");
      return "replacement";
    },
  });

  await expect(
    applyFileTransaction([planned(policy, undefined, "policy", 0o600, config), configWrite], {
      backupRoot,
      now: new Date("2026-08-11T02:00:00.000Z"),
      nonce: "second-check",
      verify: async () => {},
    }),
  ).rejects.toThrow(/changed/);

  expect(await readFile(config, "utf8")).toBe("concurrent edit");
  expect(await exists(policy)).toBe(false);
  expect(
    await readFile(
      join(backupRoot, digest(config), "2026-08-11T02-00-00.000Z-second-check", basename(config)),
      "utf8",
    ),
  ).toBe("before");
  expect(await temporaryFiles(root)).toEqual([]);
});

test("rejects symlink and non-regular targets", async () => {
  const root = await temporaryDirectory();
  const regular = join(root, "regular");
  const link = join(root, "link");
  const directory = join(root, "directory");
  await writeFile(regular, "content");
  await symlink(regular, link);
  await mkdir(directory);

  await expect(readSnapshot(link)).rejects.toThrow(/regular file/);
  await expect(readSnapshot(directory)).rejects.toThrow(/regular file/);
  await expect(
    applyFileTransaction([planned(link, undefined, "replacement", 0o600, link)], {
      backupRoot: join(root, "backups"),
      verify: async () => {},
    }),
  ).rejects.toThrow(/regular file/);
  expect(await readFile(regular, "utf8")).toBe("content");
});

test("reads only an owner-controlled regular 0600 private file", async () => {
  const root = await temporaryDirectory();
  const privateFile = join(root, "private");
  await existingFile(privateFile, "credential", 0o600);

  await expect(readPrivateFileSnapshot(privateFile)).resolves.toMatchObject({
    path: privateFile,
    content: "credential",
    mode: 0o600,
  });
});

test.sequential("reads a regular identity-safe private file when Windows reports 0666", async () => {
  const root = await temporaryDirectory();
  const privateFile = join(root, "private");
  await existingFile(privateFile, "credential", 0o666);
  fileOperations.reportedFileMode = 0o666;

  await withProcessPlatform("win32", async () => {
    await expect(readPrivateFileSnapshot(privateFile)).resolves.toMatchObject({
      path: privateFile,
      content: "credential",
      mode: 0o666,
    });
  });
});

test.sequential("does not try to sync directories through Node on Windows", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "private", "metadata.json");
  fileOperations.rejectWindowsDirectorySync = true;

  await withProcessPlatform("win32", async () => {
    await expect(
      writePrivateFileAtomically({ path: target, content: "metadata" }),
    ).resolves.toMatchObject({ path: target, content: "metadata" });
  });

  expect(fileOperations.events).not.toContain(`sync:${dirname(target)}`);
});

test.sequential("acquires, reads, and releases a 0666-reported private lock on Windows", async () => {
  const root = await temporaryDirectory();
  const target = join(root, "client-plugins", ".registry");
  const lock = join(dirname(target), "..registry.lock");
  const deadPid = 4_000_000;
  await ensurePrivateDirectory(dirname(target));
  await writeFile(
    lock,
    JSON.stringify({
      version: 1,
      pid: deadPid,
      token: "11111111-1111-4111-8111-111111111111",
    }),
    { mode: 0o666 },
  );
  await chmod(lock, 0o666);
  fileOperations.reportedFileMode = 0o666;
  const originalKill = process.kill.bind(process);
  const kill = vi.spyOn(process, "kill").mockImplementation((pid, signal) => {
    if (pid === deadPid) {
      throw Object.assign(new Error("dead test process"), { code: "ESRCH" });
    }
    return originalKill(pid, signal);
  });

  try {
    await withProcessPlatform("win32", async () => {
      await expect(withPrivateFileLock(target, async () => "acquired")).resolves.toBe("acquired");
    });
  } finally {
    kill.mockRestore();
  }
  expect(await exists(lock)).toBe(false);
});

test.each([
  ["missing", async (root: string) => join(root, "missing")],
  [
    "symlinked",
    async (root: string) => {
      const target = join(root, "target");
      const path = join(root, "link");
      await existingFile(target, "credential", 0o600);
      await symlink(target, path);
      return path;
    },
  ],
  [
    "non-regular",
    async (root: string) => {
      const path = join(root, "directory");
      await mkdir(path);
      return path;
    },
  ],
  [
    "group-readable",
    async (root: string) => {
      const path = join(root, "group-readable");
      await existingFile(path, "credential", 0o640);
      return path;
    },
  ],
  [
    "group-and-other-readable",
    async (root: string) => {
      const path = join(root, "group-and-other-readable");
      await existingFile(path, "credential", 0o644);
      return path;
    },
  ],
  [
    "other-readable",
    async (root: string) => {
      const path = join(root, "other-readable");
      await existingFile(path, "credential", 0o604);
      return path;
    },
  ],
  [
    "non-owner",
    async (root: string) => {
      const path = join(root, "non-owner");
      await existingFile(path, "credential", 0o600);
      fileOperations.nonOwnerPath = path;
      return path;
    },
  ],
] as const)("rejects a %s private file before returning content", async (_name, fixture) => {
  const root = await temporaryDirectory();
  const path = await fixture(root);

  await expect(readPrivateFileSnapshot(path)).rejects.toThrow(/private file|regular file/i);
});

test("does not read a symlink swapped in after lstat and before open", async () => {
  const root = await temporaryDirectory();
  const path = join(root, "profile.json");
  const movedPath = join(root, "profile.original.json");
  const followedTarget = join(root, "credential-target.json");
  await writeFile(path, "original profile");
  await writeFile(followedTarget, "secret sentinel");
  fileOperations.swapBeforeOpen = { path, movedPath, target: followedTarget };
  fileOperations.failReadFor = path;

  await expect(readSnapshot(path)).rejects.toThrow(/changed|regular|symlink/i);

  expect(await readFile(followedTarget, "utf8")).toBe("secret sentinel");
});

test("rejects a symlinked private backup directory", async () => {
  const root = await temporaryDirectory();
  const external = join(root, "external");
  const restrictorHome = join(root, ".mcp-restrictor");
  const target = join(root, "config.toml");
  await mkdir(external, { mode: 0o755 });
  await chmod(external, 0o755);
  await symlink(external, restrictorHome);

  await expect(
    applyFileTransaction([planned(target, undefined, "content", 0o600, target)], {
      backupRoot: join(restrictorHome, "backups"),
      verify: async () => {},
    }),
  ).rejects.toThrow(/backup directory.*symlink/i);

  expect(await exists(target)).toBe(false);
  expect(await mode(external)).toBe(0o755);
});

test("rejects a symlinked target parent before writing outside it", async () => {
  const root = await temporaryDirectory();
  const project = join(root, "project");
  const external = join(root, "external");
  const policyParent = join(project, "policies");
  const policy = join(policyParent, "server.yaml");
  await Promise.all([mkdir(project), mkdir(external)]);
  await symlink(external, policyParent);

  await expect(
    applyFileTransaction(
      [planned(policy, undefined, "policy payload", 0o600, join(project, "config"))],
      {
        backupRoot: join(root, "backups"),
        verify: async () => {},
      },
    ),
  ).rejects.toThrow(/symlink/i);

  expect(await readdir(external)).toEqual([]);
});

test("rejects a symlinked ancestor of the backup root", async () => {
  const root = await temporaryDirectory();
  const external = join(root, "external");
  const linkedHome = join(root, "linked-home");
  const target = join(root, "config.toml");
  await mkdir(external);
  await symlink(external, linkedHome);

  await expect(
    applyFileTransaction([planned(target, undefined, "config payload", 0o600, target)], {
      backupRoot: join(linkedHome, ".mcp-restrictor", "backups"),
      verify: async () => {},
    }),
  ).rejects.toThrow(/backup.*symlink/i);

  expect(await exists(target)).toBe(false);
  expect(await readdir(external)).toEqual([]);
});

test("aborts every write when an existing snapshot is stale", async () => {
  const root = await temporaryDirectory();
  const existing = join(root, "config.toml");
  const newPolicy = join(root, "policy.yaml");
  await existingFile(existing, "before", 0o640);
  const before = await readSnapshot(existing);
  await writeFile(existing, "concurrent edit");

  await expect(
    applyFileTransaction(
      [
        planned(newPolicy, undefined, "policy", 0o600, existing),
        planned(existing, before!, "replacement", 0o640, existing),
      ],
      { backupRoot: join(root, "backups"), verify: async () => {} },
    ),
  ).rejects.toThrow(/changed/);

  expect(await readFile(existing, "utf8")).toBe("concurrent edit");
  expect(await exists(newPolicy)).toBe(false);
  expect(await temporaryFiles(root)).toEqual([]);
});

test("aborts every write when a planned new target appears", async () => {
  const root = await temporaryDirectory();
  const existing = join(root, "config.toml");
  const newPolicy = join(root, "policy.yaml");
  await existingFile(existing, "before", 0o640);
  const before = await readSnapshot(existing);
  await writeFile(newPolicy, "concurrent file");

  await expect(
    applyFileTransaction(
      [
        planned(existing, before!, "replacement", 0o640, existing),
        planned(newPolicy, undefined, "policy", 0o600, existing),
      ],
      { backupRoot: join(root, "backups"), verify: async () => {} },
    ),
  ).rejects.toThrow(/appeared/);

  expect(await readFile(existing, "utf8")).toBe("before");
  expect(await readFile(newPolicy, "utf8")).toBe("concurrent file");
  expect(await temporaryFiles(root)).toEqual([]);
});

test("rejects duplicate resolved targets and backup basename collisions", async () => {
  const root = await temporaryDirectory();
  const duplicate = join(root, "target");
  await expect(
    applyFileTransaction(
      [
        planned(duplicate, undefined, "one", 0o600, duplicate),
        planned(join(root, "nested", "..", "target"), undefined, "two", 0o600, duplicate),
      ],
      { backupRoot: join(root, "backups"), verify: async () => {} },
    ),
  ).rejects.toThrow(/duplicate/i);

  const first = join(root, "one", "config.toml");
  const second = join(root, "two", "config.toml");
  await Promise.all([existingFile(first, "first", 0o600), existingFile(second, "second", 0o600)]);
  const [beforeFirst, beforeSecond] = await Promise.all([
    readSnapshot(first),
    readSnapshot(second),
  ]);
  await expect(
    applyFileTransaction(
      [
        planned(first, beforeFirst!, "new first", 0o600, "shared"),
        planned(second, beforeSecond!, "new second", 0o600, "shared"),
      ],
      { backupRoot: join(root, "other-backups"), verify: async () => {} },
    ),
  ).rejects.toThrow(/backup basename collision/i);
  expect(await readFile(first, "utf8")).toBe("first");
  expect(await readFile(second, "utf8")).toBe("second");
});

test("verification failure restores existing files and removes new files", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const policy = join(root, "policy.yaml");
  await existingFile(config, "before", 0o640);
  const before = await readSnapshot(config);
  const failure = new Error("verification failed");

  await expect(
    applyFileTransaction(
      [
        planned(config, before!, "after", 0o640, config),
        planned(policy, undefined, "policy", 0o600, config),
      ],
      {
        backupRoot: join(root, "backups"),
        nonce: "rollback",
        verify: async () => {
          expect(await readFile(config, "utf8")).toBe("after");
          expect(await readFile(policy, "utf8")).toBe("policy");
          throw failure;
        },
      },
    ),
  ).rejects.toBe(failure);

  expect(await readFile(config, "utf8")).toBe("before");
  expect(await mode(config)).toBe(0o640);
  expect(await exists(policy)).toBe(false);
  expect(await temporaryFiles(root)).toEqual([]);
});

test("cancellation during a transaction rolls back config, policy, and state", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const policy = join(root, "policy.yaml");
  const state = join(root, "state.json");
  await Promise.all([
    existingFile(config, "original config", 0o640),
    existingFile(policy, "original policy", 0o600),
    existingFile(state, "original state", 0o600),
  ]);
  const [beforeConfig, beforePolicy, beforeState] = await Promise.all([
    readSnapshot(config),
    readSnapshot(policy),
    readSnapshot(state),
  ]);
  const controller = new AbortController();
  const cancellation = new DOMException("cancelled", "AbortError");
  let entered!: () => void;
  const verification = new Promise<void>((resolveVerification) => {
    entered = resolveVerification;
  });
  let release!: () => void;
  const wait = new Promise<void>((resolveWait) => {
    release = resolveWait;
  });
  const applying = applyFileTransaction(
    [
      planned(config, beforeConfig!, "installed config", 0o640, config),
      planned(policy, beforePolicy!, "installed policy", 0o600, config),
      privatePlanned(state, beforeState!, "installed state", config),
    ],
    {
      backupRoot: join(root, "backups"),
      signal: controller.signal,
      verify: async () => {
        entered();
        await wait;
      },
    },
  );
  await verification;
  controller.abort(cancellation);
  release();

  await expect(applying).rejects.toBe(cancellation);
  expect(await readFile(config, "utf8")).toBe("original config");
  expect(await mode(config)).toBe(0o640);
  expect(await readFile(policy, "utf8")).toBe("original policy");
  expect(await mode(policy)).toBe(0o600);
  expect(await readFile(state, "utf8")).toBe("original state");
  expect(await mode(state)).toBe(0o600);
});

test("preserves a concurrently replaced existing target and rolls back other files", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const replacement = join(root, "concurrent.toml");
  const policy = join(root, "policy.yaml");
  await existingFile(config, "before", 0o640);
  const before = await readSnapshot(config);
  const failure = new Error("verification failed");
  let replacementInode = 0;
  let caught: unknown;

  try {
    await applyFileTransaction(
      [
        planned(config, before!, "installed", 0o640, config),
        planned(policy, undefined, "policy", 0o600, config),
      ],
      {
        backupRoot: join(root, "backups"),
        verify: async () => {
          await existingFile(replacement, "installed", 0o640);
          replacementInode = (await lstat(replacement)).ino;
          await rename(replacement, config);
          throw failure;
        },
      },
    );
  } catch (error) {
    caught = error;
  }

  expect(caught).toBeInstanceOf(AggregateError);
  expect((caught as AggregateError).errors[0]).toBe(failure);
  expect((caught as AggregateError).errors[1]).toMatchObject({
    message: expect.stringMatching(/rollback.*changed|rollback.*conflict/i),
  });
  expect((await lstat(config)).ino).toBe(replacementInode);
  expect(await readFile(config, "utf8")).toBe("installed");
  expect(await exists(policy)).toBe(false);
  expect(await temporaryFiles(root)).toEqual([]);
});

test("preserves a concurrently edited new target and rolls back other files", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const policy = join(root, "policy.yaml");
  await existingFile(config, "before", 0o640);
  const before = await readSnapshot(config);
  const failure = new Error("verification failed");
  let caught: unknown;

  try {
    await applyFileTransaction(
      [
        planned(config, before!, "installed config", 0o640, config),
        planned(policy, undefined, "installed policy", 0o600, config),
      ],
      {
        backupRoot: join(root, "backups"),
        verify: async () => {
          await writeFile(policy, "concurrent policy edit");
          throw failure;
        },
      },
    );
  } catch (error) {
    caught = error;
  }

  expect(caught).toBeInstanceOf(AggregateError);
  expect((caught as AggregateError).errors[0]).toBe(failure);
  expect((caught as AggregateError).errors[1]).toMatchObject({
    message: expect.stringMatching(/rollback.*changed|rollback.*conflict/i),
  });
  expect(await readFile(config, "utf8")).toBe("before");
  expect(await readFile(policy, "utf8")).toBe("concurrent policy edit");
  expect(await temporaryFiles(root)).toEqual([]);
});

test("install failure rolls back prior writes and removes sibling temps", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const policy = join(root, "policy.yaml");
  await existingFile(config, "before", 0o640);
  const before = await readSnapshot(config);
  let policyWasInstalled = false;
  const configWrite = planned(config, before!, "after", -1, config);
  Object.defineProperty(configWrite, "content", {
    enumerable: true,
    get: () => {
      policyWasInstalled = existsSync(policy);
      return "after";
    },
  });

  await expect(
    applyFileTransaction([planned(policy, undefined, "policy", 0o600, config), configWrite], {
      backupRoot: join(root, "backups"),
      nonce: "install-failure",
      verify: async () => {
        throw new Error("verify must not run");
      },
    }),
  ).rejects.toThrow();

  expect(policyWasInstalled).toBe(true);
  expect(await readFile(config, "utf8")).toBe("before");
  expect(await exists(policy)).toBe(false);
  expect(await temporaryFiles(root)).toEqual([]);
});

test.each([0, 1, 2] as const)(
  "route write failure at position %s rolls back the exact tree",
  async (failedRoute) => {
    const root = await temporaryDirectory();
    const policy = join(root, "policy.yaml");
    const routes = [0, 1, 2].map((index) => join(root, "routes", `route-${index}.json`));
    const state = join(root, "restore", "state.json");
    const config = join(root, "config.toml");
    await existingFile(config, "before", 0o640);
    const before = await readSnapshot(config);

    await expect(
      applyFileTransaction(
        [
          planned(policy, undefined, "policy", 0o600, config),
          ...routes.map((route, index) => ({
            ...planned(
              route,
              undefined,
              `route-${index}`,
              index === failedRoute ? -1 : 0o600,
              config,
            ),
            private: true as const,
          })),
          { ...planned(state, undefined, "state", 0o600, config), private: true },
          planned(config, before!, "after", 0o640, config),
        ],
        {
          backupRoot: join(root, "backups"),
          nonce: `route-write-failure-${failedRoute}`,
          verify: async () => {
            throw new Error("verify must not run");
          },
        },
      ),
    ).rejects.toThrow();

    expect(await exists(policy)).toBe(false);
    for (const route of routes) expect(await exists(route)).toBe(false);
    expect(await exists(state)).toBe(false);
    expect(await readFile(config, "utf8")).toBe("before");
    expect(await temporaryFiles(root)).toEqual([]);
  },
);

test("OAuth profile write failure rolls back earlier saved policies before any later artifact", async () => {
  const root = await temporaryDirectory();
  const savedPolicy = join(root, "saved-policies", "read-only.yaml");
  const profile = join(root, "oauth", "profile.json");
  const policy = join(root, "policies", "policy.yaml");
  const route = join(root, "routes", "route.json");
  const state = join(root, "restore", "state.json");
  const config = join(root, "config.toml");
  await existingFile(config, "before", 0o640);
  const before = await readSnapshot(config);

  await expect(
    applyFileTransaction(
      [
        planned(savedPolicy, undefined, "saved policy", 0o600, config),
        { ...planned(profile, undefined, "encrypted profile", -1, config), private: true },
        planned(policy, undefined, "policy", 0o600, config),
        { ...planned(route, undefined, "route", 0o600, config), private: true },
        { ...planned(state, undefined, "state", 0o600, config), private: true },
        planned(config, before!, "after", 0o640, config),
      ],
      {
        backupRoot: join(root, "backups"),
        nonce: "oauth-profile-write-failure",
        verify: async () => {
          throw new Error("verify must not run");
        },
      },
    ),
  ).rejects.toThrow();

  for (const path of [savedPolicy, profile, policy, route, state])
    expect(await exists(path)).toBe(false);
  expect(await readFile(config, "utf8")).toBe("before");
  expect(await temporaryFiles(root)).toEqual([]);
});

test("reports rollback failures after the original verification error", async () => {
  const root = await temporaryDirectory();
  const parent = join(root, "created");
  const target = join(parent, "config.toml");
  const failure = new Error("verification failed");

  let caught: unknown;
  try {
    await applyFileTransaction([planned(target, undefined, "installed", 0o600, target)], {
      backupRoot: join(root, "backups"),
      verify: async () => {
        await rm(parent, { recursive: true });
        await writeFile(parent, "blocks rollback");
        throw failure;
      },
    });
  } catch (error) {
    caught = error;
  }

  expect(caught).toBeInstanceOf(AggregateError);
  expect((caught as AggregateError).errors[0]).toBe(failure);
  expect((caught as AggregateError).errors).toHaveLength(2);
  expect(await temporaryFiles(root)).toEqual([]);
});

test("installs a private profile with private modes before verification without holding its lock", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const profile = join(root, ".mcp-restrictor", "oauth", "profile.json");
  const lock = join(dirname(profile), `.${basename(profile)}.lock`);
  await ensurePrivateDirectory(dirname(profile));

  await applyFileTransaction(
    [
      privatePlanned(profile, undefined, "encrypted profile", config),
      planned(config, undefined, "managed config", 0o600, config),
    ],
    {
      backupRoot: join(root, ".mcp-restrictor", "backups"),
      verify: async () => {
        expect(await readFile(profile, "utf8")).toBe("encrypted profile");
        expect(await mode(dirname(profile))).toBe(0o700);
        expect(await mode(profile)).toBe(0o600);
        expect(await exists(lock)).toBe(false);
      },
    },
  );
});

test.each([
  ["existing", "original profile"],
  ["new", undefined],
] as const)(
  "does not leave an unjournaled %s profile when the install lock release fails",
  async (_case, original) => {
    const root = await temporaryDirectory();
    const config = join(root, "config.toml");
    const profile = join(root, ".mcp-restrictor", "oauth", "profile.json");
    await ensurePrivateDirectory(dirname(profile));
    if (original !== undefined) await existingFile(profile, original, 0o600);
    const before = await readSnapshot(profile);
    const lock = join(dirname(profile), `.${basename(profile)}.lock`);
    fileOperations.unlinkFailures.set(lock, [new Error("injected lock release failure")]);

    await expect(
      applyFileTransaction([privatePlanned(profile, before, "installed profile", config)], {
        backupRoot: join(root, ".mcp-restrictor", "backups"),
        verify: async () => {
          throw new Error("verification must not run");
        },
      }),
    ).rejects.toThrow(/lock release failure/);

    if (original === undefined) expect(await exists(profile)).toBe(false);
    else expect(await readFile(profile, "utf8")).toBe(original);
  },
);

test("accepts an awaited private profile rotation and restores the original after a later failure", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const profile = join(root, ".mcp-restrictor", "oauth", "profile.json");
  await existingFile(profile, "original profile", 0o600);
  const before = await readSnapshot(profile);
  const laterFailure = new Error("later wrapper verification failed");
  let validatorFinished = false;

  await expect(
    applyFileTransaction([privatePlanned(profile, before!, "installed profile", config)], {
      backupRoot: join(root, ".mcp-restrictor", "backups"),
      verify: async (acceptInstalledUpdate) => {
        const installed = await readSnapshot(profile);
        await writePrivateFileAtomically({
          path: profile,
          content: "rotated profile",
          before: installed!,
        });
        await acceptInstalledUpdate(profile, async (snapshot) => {
          await new Promise<void>((resolveImmediate) => setImmediate(resolveImmediate));
          expect(snapshot.content).toBe("rotated profile");
          validatorFinished = true;
        });
        expect(validatorFinished).toBe(true);
        fileOperations.events.length = 0;
        throw laterFailure;
      },
    }),
  ).rejects.toBe(laterFailure);

  expect(await readFile(profile, "utf8")).toBe("original profile");
  expect(await mode(profile)).toBe(0o600);
  expect(fileOperations.events).toContain(`sync:${dirname(profile)}`);
});

test("removes a new private profile after an accepted rotation and later verification failure", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const profile = join(root, ".mcp-restrictor", "oauth", "profile.json");
  await ensurePrivateDirectory(dirname(profile));

  await expect(
    applyFileTransaction([privatePlanned(profile, undefined, "installed profile", config)], {
      backupRoot: join(root, ".mcp-restrictor", "backups"),
      verify: async (acceptInstalledUpdate) => {
        const installed = await readSnapshot(profile);
        await writePrivateFileAtomically({
          path: profile,
          content: "rotated profile",
          before: installed!,
        });
        await acceptInstalledUpdate(profile, async (snapshot) => {
          expect(snapshot.content).toBe("rotated profile");
        });
        throw new Error("later verification failed");
      },
    }),
  ).rejects.toThrow("later verification failed");

  expect(await exists(profile)).toBe(false);
});

test("rejects an update for an unjournaled path and rolls back the transaction", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const unknown = join(root, "unknown.json");

  await expect(
    applyFileTransaction([planned(config, undefined, "installed", 0o600, config)], {
      backupRoot: join(root, "backups"),
      verify: async (acceptInstalledUpdate) => {
        await acceptInstalledUpdate(unknown, async () => {});
      },
    }),
  ).rejects.toThrow(/journaled|unknown/i);

  expect(await exists(config)).toBe(false);
});

test("rejects accepting an update for a non-private journal entry", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");

  await expect(
    applyFileTransaction([planned(config, undefined, "installed", 0o600, config)], {
      backupRoot: join(root, "backups"),
      verify: async (acceptInstalledUpdate) => {
        await acceptInstalledUpdate(config, async () => {});
      },
    }),
  ).rejects.toThrow(/private/i);

  expect(await exists(config)).toBe(false);
});

test("revalidates a private installed update after the async validator returns", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const profile = join(root, ".mcp-restrictor", "oauth", "profile.json");
  await ensurePrivateDirectory(dirname(profile));
  let caught: unknown;

  try {
    await applyFileTransaction([privatePlanned(profile, undefined, "installed profile", config)], {
      backupRoot: join(root, ".mcp-restrictor", "backups"),
      verify: async (acceptInstalledUpdate) => {
        await acceptInstalledUpdate(profile, async () => {
          await writeFile(profile, "changed during validation");
        });
      },
    });
  } catch (error) {
    caught = error;
  }

  expect(caught).toBeInstanceOf(AggregateError);
  expect((caught as AggregateError).errors[0]).toMatchObject({
    message: expect.stringMatching(/changed.*validation|installed update changed/i),
  });
  expect(await readFile(profile, "utf8")).toBe("changed during validation");
});

test("rolls back an accepted private rotation when releasing its accept lock fails", async () => {
  const root = await temporaryDirectory();
  const config = join(root, "config.toml");
  const profile = join(root, ".mcp-restrictor", "oauth", "profile.json");
  await existingFile(profile, "original profile", 0o600);
  const before = await readSnapshot(profile);
  const lock = join(dirname(profile), `.${basename(profile)}.lock`);
  let rotated = false;

  await expect(
    applyFileTransaction([privatePlanned(profile, before!, "installed profile", config)], {
      backupRoot: join(root, ".mcp-restrictor", "backups"),
      verify: async (acceptInstalledUpdate) => {
        const installed = await readSnapshot(profile);
        await writePrivateFileAtomically({
          path: profile,
          content: "rotated profile",
          before: installed!,
        });
        fileOperations.unlinkFailures.set(lock, [new Error("accept release failure")]);
        await acceptInstalledUpdate(profile, async () => {
          rotated = true;
        });
      },
    }),
  ).rejects.toThrow(/accept release failure/);

  expect(rotated).toBe(true);
  expect(await readFile(profile, "utf8")).toBe("original profile");
});

function planned(
  path: string,
  before: Awaited<ReturnType<typeof readSnapshot>>,
  content: string,
  mode: number,
  backupKey: string,
): PlannedWrite {
  return {
    path,
    ...(before ? { before } : {}),
    content,
    mode,
    backupKey,
  };
}

function privatePlanned(
  path: string,
  before: Awaited<ReturnType<typeof readSnapshot>>,
  content: string,
  backupKey: string,
): PlannedWrite {
  return {
    ...planned(path, before, content, 0o600, backupKey),
    private: true,
  };
}

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-transaction-")));
  temporaryDirectories.push(path);
  return path;
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

async function existingFile(path: string, content: string, permissions: number): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, content);
  await chmod(path, permissions);
}

async function livePrivateLock(target: string): Promise<string> {
  return privateLock(target, {
    version: 1,
    pid: process.pid,
    token: "11111111-1111-4111-8111-111111111111",
  });
}

async function privateLock(
  target: string,
  owner:
    | { version: 1; pid: number; token: string }
    | { version: 2; pid: number; processStart: string; token: string },
): Promise<string> {
  const parent = dirname(target);
  const lock = join(parent, `.${basename(target)}.lock`);
  await ensurePrivateDirectory(parent);
  await writeFile(lock, JSON.stringify(owner), { mode: 0o600 });
  await chmod(lock, 0o600);
  return lock;
}

function processStat(pid: number, start: string, command = "mcp restrictor"): string {
  return `${pid} (${command}) S ${Array.from({ length: 18 }, (_, index) => index + 1).join(" ")} ${start} 20\n`;
}

async function mode(path: string): Promise<number> {
  return (await lstat(path)).mode & 0o7777;
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

async function temporaryFiles(root: string): Promise<string[]> {
  return (await readdir(root, { recursive: true }))
    .map(String)
    .filter((path) => basename(path).startsWith(".") && path.endsWith(".tmp"));
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
