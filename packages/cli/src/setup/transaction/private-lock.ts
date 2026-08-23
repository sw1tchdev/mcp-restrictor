import { randomUUID } from "node:crypto";
import { chmod, link, lstat, mkdir, rmdir, unlink } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { linuxProcessStartIdentity, processIsAlive } from "../../utils/filesystem.js";
import { CONTAINER_MARKER_ENV } from "../constants.js";
import { ensurePrivateDirectory, errorCode, writeBackup } from "./atomic-file.js";
import {
  isPrivateFileMode,
  readSnapshot,
  sameSnapshot,
  validateInstalled,
  type FileSnapshot,
} from "./snapshots.js";

const INVALID_PRIVATE_LOCK_OWNER_MESSAGE = "Invalid private lock owner";

type PrivateLockWaitOptions = {
  signal?: AbortSignal;
  timeoutMs?: number;
  delayMs?: number;
};

type PrivateLockOwner =
  | { version: 1; pid: number }
  | { version: 2; pid: number; processStart: string };

export async function withPrivateFileLock<T>(
  target: string,
  operation: () => Promise<T>,
  options: PrivateLockWaitOptions & {
    rollback?(result: T): Promise<void>;
  } = {},
): Promise<T> {
  const path = resolve(target);
  const parent = dirname(path);
  await ensurePrivateDirectory(parent);
  const lock = await acquirePrivateLock(join(parent, `.${basename(path)}.lock`), options);
  let result: T | undefined;
  let operationError: unknown;
  let completed = false;
  try {
    result = await operation();
    completed = true;
  } catch (error) {
    operationError = error;
  }
  let releaseError: unknown;
  try {
    await releasePrivateLock(lock);
  } catch (error) {
    releaseError = error;
  }
  if (releaseError !== undefined) {
    const errors: unknown[] =
      operationError === undefined ? [releaseError] : [operationError, releaseError];
    if (completed && options.rollback) {
      try {
        await validateInstalled(lock);
        await options.rollback(result as T);
      } catch (rollbackError) {
        errors.push(rollbackError);
      }
    }
    try {
      await releasePrivateLock(lock);
    } catch (recoveryError) {
      errors.push(recoveryError);
    }
    throw errors.length === 1
      ? errors[0]
      : new AggregateError(errors, "Private operation recovery failed");
  }
  if (operationError !== undefined) throw operationError;
  return result as T;
}

async function releasePrivateLock(lock: FileSnapshot): Promise<void> {
  await validateInstalled(lock);
  await unlink(lock.path);
}

async function acquirePrivateLock(
  path: string,
  options: PrivateLockWaitOptions,
): Promise<FileSnapshot> {
  const timeoutSignal = AbortSignal.timeout(options.timeoutMs ?? 30_000);
  const signal = AbortSignal.any(
    options.signal ? [options.signal, timeoutSignal] : [timeoutSignal],
  );
  for (;;) {
    throwIfPrivateLockAborted(signal, timeoutSignal, path);
    const acquired = await tryAcquirePrivateLock(path);
    if (acquired) {
      try {
        throwIfPrivateLockAborted(signal, timeoutSignal, path);
      } catch (cancellation) {
        await releaseCancelledPrivateLock(acquired, cancellation);
      }
      return acquired;
    }
    await recoverDeadPrivateLock(path);
    throwIfPrivateLockAborted(signal, timeoutSignal, path);
    try {
      await delay(options.delayMs ?? 5, undefined, { signal });
    } catch (error) {
      if (!signal.aborted) throw error;
      throwIfPrivateLockAborted(signal, timeoutSignal, path);
    }
  }
}

async function releaseCancelledPrivateLock(
  lock: FileSnapshot,
  cancellation: unknown,
): Promise<never> {
  try {
    await releasePrivateLock(lock);
  } catch (releaseError) {
    const errors = [cancellation, releaseError];
    try {
      await releasePrivateLock(lock);
    } catch (recoveryError) {
      errors.push(recoveryError);
    }
    throw new AggregateError(errors, "Private lock cancellation recovery failed");
  }
  throw cancellation;
}

function throwIfPrivateLockAborted(
  signal: AbortSignal,
  timeoutSignal: AbortSignal,
  path: string,
): void {
  if (!signal.aborted) return;
  if (signal.reason === timeoutSignal.reason) {
    throw new Error(`Private lock acquisition timed out: ${path}`);
  }
  signal.throwIfAborted();
}

async function tryAcquirePrivateLock(path: string): Promise<FileSnapshot | undefined> {
  const token = randomUUID();
  const temporary = `${path}.${token}.tmp`;
  const content = JSON.stringify(await currentPrivateLockOwner(token));
  await writeBackup(temporary, content);
  const temporarySnapshot = await readSnapshot(temporary);
  if (!temporarySnapshot) throw new Error("Private lock owner was not written");
  let acquired = false;
  let primaryError: unknown;
  try {
    await link(temporary, path);
    acquired = true;
  } catch (error) {
    if (errorCode(error) !== "EEXIST") primaryError = error;
  }
  try {
    await unlink(temporary);
  } catch (cleanupError) {
    if (acquired) {
      try {
        await unlink(path);
      } catch (releaseError) {
        throw new AggregateError(
          [cleanupError, releaseError],
          "Private lock cleanup and release failed",
        );
      }
    }
    throw cleanupError;
  }
  if (primaryError !== undefined) throw primaryError;
  return acquired ? { ...temporarySnapshot, path } : undefined;
}

async function recoverDeadPrivateLock(path: string): Promise<void> {
  const lock = await readPrivateLock(path);
  if (!lock) return;
  const { snapshot, owner } = lock;
  if (await privateLockOwnerIsAlive(owner)) return;

  const reaper = `${path}.reap`;
  try {
    await mkdir(reaper, { mode: 0o700 });
    await chmod(reaper, 0o700);
  } catch (error) {
    if (errorCode(error) === "EEXIST") {
      throw new Error(`Private lock recovery is unavailable: ${path}`);
    }
    throw error;
  }
  try {
    const current = await readPrivateLock(path);
    if (!current) return;
    if (!sameSnapshot(current.snapshot, snapshot)) {
      throw new Error(`Private lock changed during recovery: ${path}`);
    }
    if (await privateLockOwnerIsAlive(current.owner)) return;
    await unlink(path);
  } finally {
    try {
      await rmdir(reaper);
    } catch (error) {
      if (errorCode(error) !== "ENOENT") throw error;
    }
  }
}

async function readPrivateLock(
  path: string,
): Promise<{ snapshot: FileSnapshot; owner: PrivateLockOwner } | undefined> {
  let stat;
  try {
    stat = await lstat(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
  const uid = process.getuid?.();
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    !isPrivateFileMode(stat.mode & 0o7777) ||
    (uid !== undefined && stat.uid !== uid)
  ) {
    throw new Error(`Invalid private lock file: ${path}`);
  }
  let snapshot: FileSnapshot | undefined;
  try {
    snapshot = await readSnapshot(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
  if (!snapshot) return undefined;
  if (snapshot.dev !== stat.dev || snapshot.ino !== stat.ino) {
    throw new Error(`Private lock changed while reading: ${path}`);
  }
  return { snapshot, owner: parseLockOwner(snapshot) };
}

function parseLockOwner(snapshot: FileSnapshot): PrivateLockOwner {
  if (!isPrivateFileMode(snapshot.mode)) throw new Error("Invalid private lock mode");
  let value: unknown;
  try {
    value = JSON.parse(snapshot.content);
  } catch {
    throw new Error(INVALID_PRIVATE_LOCK_OWNER_MESSAGE);
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(INVALID_PRIVATE_LOCK_OWNER_MESSAGE);
  }
  const owner = value as Record<string, unknown>;
  const keys = Object.keys(owner).sort().join(",");
  if (
    (owner.version === 1 && keys !== "pid,token,version") ||
    (owner.version === 2 && keys !== "pid,processStart,token,version") ||
    (owner.version !== 1 && owner.version !== 2) ||
    typeof owner.pid !== "number" ||
    !Number.isSafeInteger(owner.pid) ||
    owner.pid <= 0 ||
    typeof owner.token !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(owner.token)
  ) {
    throw new Error(INVALID_PRIVATE_LOCK_OWNER_MESSAGE);
  }
  if (owner.version === 1) return { version: 1, pid: owner.pid };
  if (typeof owner.processStart !== "string" || !/^[0-9]+$/.test(owner.processStart)) {
    throw new Error(INVALID_PRIVATE_LOCK_OWNER_MESSAGE);
  }
  return { version: 2, pid: owner.pid, processStart: owner.processStart };
}

async function currentPrivateLockOwner(
  token: string,
): Promise<
  | { version: 1; pid: number; token: string }
  | { version: 2; pid: number; processStart: string; token: string }
> {
  if (process.env[CONTAINER_MARKER_ENV] !== "1") return { version: 1, pid: process.pid, token };
  const processStart = await linuxProcessStartIdentity(process.pid);
  if (processStart === undefined) {
    throw new Error("Unable to determine current process start identity");
  }
  return { version: 2, pid: process.pid, processStart, token };
}

async function privateLockOwnerIsAlive(owner: PrivateLockOwner): Promise<boolean> {
  if (process.env[CONTAINER_MARKER_ENV] !== "1") return processIsAlive(owner.pid);
  if (owner.version !== 2 || !processIsAlive(owner.pid)) return false;
  return (await linuxProcessStartIdentity(owner.pid)) === owner.processStart;
}
