import { isUtf8 } from "node:buffer";
import { constants } from "node:fs";
import { lstat, open, type FileHandle } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";

import { errorCode, validateDirectoryComponents, validateOwner } from "./atomic-file.js";

export type FileSnapshot = {
  path: string;
  content: string;
  mode: number;
  size: number;
  mtimeMs: number;
  dev: number;
  ino: number;
};

export type PlannedWrite = {
  delete?: false;
  path: string;
  before?: FileSnapshot;
  content: string;
  mode: number;
  backupKey: string;
  private?: true;
};

export type PlannedDelete = {
  delete: true;
  path: string;
  before: FileSnapshot;
  backupKey: string;
  private?: true;
};

export type PlannedFileChange = PlannedWrite | PlannedDelete;

// Windows stat mode bits do not represent ACL privacy; identity checks still apply.
export function isPrivateFileMode(mode: number): boolean {
  return process.platform === "win32" || mode === 0o600;
}

export async function readSnapshot(path: string): Promise<FileSnapshot | undefined> {
  await validateDirectoryComponents(dirname(resolve(path)), "Path parent", true);
  let pathStat;
  try {
    pathStat = await lstat(path);
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
    throw new Error(`Path is not a regular file: ${path}`);
  }

  const readFlags =
    typeof constants.O_NOFOLLOW === "number" ? constants.O_RDONLY | constants.O_NOFOLLOW : "r";
  let handle: FileHandle;
  try {
    handle = await open(path, readFlags);
  } catch (error) {
    if (errorCode(error) === "ELOOP") {
      throw new Error(`Path changed while reading: ${path}`);
    }
    throw error;
  }
  try {
    const openedStat = await handle.stat();
    if (
      !openedStat.isFile() ||
      openedStat.dev !== pathStat.dev ||
      openedStat.ino !== pathStat.ino
    ) {
      throw new Error(`Path changed while reading: ${path}`);
    }
    const bytes = await handle.readFile();
    if (!isUtf8(bytes)) throw new Error(`File is not valid UTF-8: ${path}`);
    const content = bytes.toString("utf8");
    const handleStat = await handle.stat();
    if (
      !handleStat.isFile() ||
      handleStat.dev !== pathStat.dev ||
      handleStat.ino !== pathStat.ino
    ) {
      throw new Error(`Path changed while reading: ${path}`);
    }
    return {
      path,
      content,
      mode: handleStat.mode & 0o7777,
      size: handleStat.size,
      mtimeMs: handleStat.mtimeMs,
      dev: handleStat.dev,
      ino: handleStat.ino,
    };
  } finally {
    await handle.close();
  }
}

export async function readPrivateFileSnapshot(path: string): Promise<FileSnapshot> {
  const snapshot = await readSnapshot(path);
  if (!snapshot) throw new Error("Private file does not exist");
  const current = await lstat(path);
  if (
    !current.isFile() ||
    current.isSymbolicLink() ||
    current.dev !== snapshot.dev ||
    current.ino !== snapshot.ino
  )
    throw new Error("Private file changed while reading");
  if (typeof process.getuid === "function" && current.uid !== process.getuid()) {
    throw new Error("Private file is not owned by the current user");
  }
  if (!isPrivateFileMode(current.mode & 0o7777) || !isPrivateFileMode(snapshot.mode)) {
    throw new Error("Private file permissions must be 0600");
  }
  return snapshot;
}

export function validatePlan(writes: readonly PlannedFileChange[]): void {
  const targets = new Set<string>();
  const backupNames = new Map<string, Set<string>>();
  for (const write of writes) {
    const target = resolve(write.path);
    if (targets.has(target)) {
      throw new Error(`Duplicate planned target: ${target}`);
    }
    targets.add(target);
    if (write.delete === true && !write.before) {
      throw new Error(`Delete target requires a snapshot: ${target}`);
    }
    if (write.before && resolve(write.before.path) !== target) {
      throw new Error(`Snapshot path does not match target: ${target}`);
    }
    if (!write.before) continue;
    const names = backupNames.get(write.backupKey) ?? new Set<string>();
    const name = basename(write.path);
    if (names.has(name)) {
      throw new Error(`Backup basename collision: ${name}`);
    }
    names.add(name);
    backupNames.set(write.backupKey, names);
  }
}

export async function validateTarget(write: PlannedFileChange): Promise<void> {
  const target = resolve(write.path);
  const current = await readSnapshot(target);
  if (!write.before) {
    if (current) throw new Error(`New target appeared: ${target}`);
    return;
  }
  if (!current || !sameSnapshot(current, write.before)) {
    throw new Error(`Target changed after snapshot: ${target}`);
  }
}

export async function validatePrivateTarget(write: PlannedFileChange): Promise<void> {
  await validateTarget(write);
  try {
    await validateOwner(resolve(write.path), "Private file");
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }
}

export async function validateInstalled(installed: FileSnapshot): Promise<void> {
  // ponytail: Node has no conditional rename/unlink by inode, so this narrows
  // but cannot close the race between this check and the path operation.
  let current: FileSnapshot | undefined;
  try {
    current = await readSnapshot(installed.path);
  } catch {
    throw new Error(`Rollback target changed: ${installed.path}`);
  }
  if (!current || !sameSnapshot(current, installed)) {
    throw new Error(`Rollback target changed: ${installed.path}`);
  }
}

export function sameSnapshot(left: FileSnapshot, right: FileSnapshot): boolean {
  return (
    left.content === right.content &&
    left.mode === right.mode &&
    left.size === right.size &&
    left.mtimeMs === right.mtimeMs &&
    left.dev === right.dev &&
    left.ino === right.ino
  );
}

export function sameFileSnapshot(left: FileSnapshot, right: FileSnapshot): boolean {
  return left.path === right.path && sameSnapshot(left, right);
}
