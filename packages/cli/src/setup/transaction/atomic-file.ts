import { chmod, lstat, mkdir, open, rename, unlink, type FileHandle } from "node:fs/promises";
import { basename, dirname, join, parse, resolve, sep } from "node:path";
import { errorCode, syncDirectory } from "../../utils/filesystem.js";

import type { FileSnapshot } from "./snapshots.js";

export { errorCode, syncDirectory };

export async function ensurePrivateDirectory(path: string): Promise<void> {
  await privateDirectory(resolve(path));
}

export async function privateDirectory(path: string): Promise<void> {
  await ensureDirectory(path, "Backup directory", 0o700);
  await chmod(path, 0o700);
  await validatePrivateDirectory(path, "Private directory");
}

export async function validatePrivateDirectory(path: string, label: string): Promise<void> {
  const directory = resolve(path);
  await validateDirectoryComponents(directory, label, false);
  const stat = await lstat(directory);
  if (stat.isSymbolicLink()) throw new Error(`${label} is a symlink: ${directory}`);
  if (!stat.isDirectory()) throw new Error(`${label} is not a directory: ${directory}`);
  await validateOwner(directory, label);
  if (process.platform !== "win32" && (stat.mode & 0o7777) !== 0o700) {
    throw new Error(`${label} permissions must be 0700: ${directory}`);
  }
}

export async function writeBackup(path: string, content: string): Promise<void> {
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.writeFile(content, "utf8");
    await handle.chmod(0o600);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function atomicWrite(
  path: string,
  content: string,
  mode: number,
  nonce: string,
  validate?: () => Promise<void>,
): Promise<FileSnapshot> {
  await ensureDirectory(dirname(path), "Path parent");
  const temporary = join(dirname(path), `.${basename(path)}.${nonce}.tmp`);
  let handle: FileHandle | undefined;
  let snapshot: FileSnapshot | undefined;
  let created = false;
  let installed = false;
  let failed = false;
  let primaryError: unknown;
  try {
    handle = await open(temporary, "wx", 0o600);
    created = true;
    await handle.writeFile(content, "utf8");
    await handle.sync();
    await handle.chmod(mode);
    const stat = await handle.stat();
    snapshot = {
      path,
      content,
      mode: stat.mode & 0o7777,
      size: stat.size,
      mtimeMs: stat.mtimeMs,
      dev: stat.dev,
      ino: stat.ino,
    };
    await handle.close();
    handle = undefined;
    await validate?.();
    await rename(temporary, path);
    installed = true;
  } catch (error) {
    failed = true;
    primaryError = error;
  } finally {
    const cleanupErrors: unknown[] = [];
    if (handle) {
      try {
        await handle.close();
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (created && !installed) {
      try {
        await removeFile(temporary);
      } catch (error) {
        cleanupErrors.push(error);
      }
    }
    if (failed) {
      if (cleanupErrors.length > 0) {
        throw new AggregateError(
          [primaryError, ...cleanupErrors],
          "Atomic write and cleanup failed",
        );
      }
      throw primaryError;
    }
    if (cleanupErrors.length > 0) {
      throw cleanupErrors.length === 1
        ? cleanupErrors[0]
        : new AggregateError(cleanupErrors, "Atomic write cleanup failed");
    }
  }
  if (!snapshot) throw new Error(`Atomic write did not install: ${path}`);
  return snapshot;
}

async function ensureDirectory(path: string, label: string, mode?: number): Promise<void> {
  await validateDirectoryComponents(path, label, true);
  await mkdir(path, { ...(mode === undefined ? {} : { mode }), recursive: true });
  await validateDirectoryComponents(path, label, false);
}

export async function validateOwner(path: string, label: string): Promise<void> {
  const uid = process.getuid?.();
  if (uid === undefined) return;
  if ((await lstat(path)).uid !== uid) {
    throw new Error(`${label} is not owned by the current user: ${path}`);
  }
}

export async function validateDirectoryComponents(
  path: string,
  label: string,
  allowMissing: boolean,
): Promise<void> {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  let current = root;
  for (const name of absolute.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, name);
    let stat;
    try {
      stat = await lstat(current);
    } catch (error) {
      if (allowMissing && errorCode(error) === "ENOENT") return;
      throw error;
    }
    if (stat.isSymbolicLink()) {
      throw new Error(`${label} contains a symlink: ${current}`);
    }
    if (!stat.isDirectory()) {
      throw new Error(`${label} contains a non-directory: ${current}`);
    }
  }
}

export async function removeFile(path: string): Promise<void> {
  try {
    await unlink(path);
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }
}
