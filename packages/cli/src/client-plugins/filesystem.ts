import { constants } from "node:fs";
import { lstat, open, readdir, realpath, type FileHandle } from "node:fs/promises";
import { join, sep } from "node:path";
import {
  INVALID_CLIENT_ADAPTER_FILE_MESSAGE,
  INVALID_CLIENT_ADAPTER_METADATA_MESSAGE,
} from "./constants.js";
import { errorCode, syncDirectory } from "../utils/filesystem.js";

export { errorCode, syncDirectory };

export async function directoryExists(path: string): Promise<boolean> {
  try {
    await checkedDirectory(path);
    return true;
  } catch (error) {
    if (errorCode(error) === "ENOENT") return false;
    throw error;
  }
}

export async function syncStagedTree(path: string): Promise<void> {
  const before = await lstat(path);
  if (before.isSymbolicLink()) return;
  if (before.isDirectory()) {
    for (const name of await readdir(path)) {
      await syncStagedTree(join(path, name));
    }
    const after = await lstat(path);
    if (
      after.isSymbolicLink() ||
      !after.isDirectory() ||
      after.dev !== before.dev ||
      after.ino !== before.ino
    )
      throw new Error("Staged client adapter changed during sync");
    await syncDirectory(path);
    return;
  }
  if (!before.isFile()) throw new Error("Invalid staged client adapter payload");
  const access = process.platform === "win32" ? constants.O_RDWR : constants.O_RDONLY;
  const flags = typeof constants.O_NOFOLLOW === "number" ? access | constants.O_NOFOLLOW : access;
  const handle = await open(path, flags);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino)
      throw new Error("Staged client adapter changed during sync");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function checkedDirectory(path: string): Promise<string> {
  const stat = await lstat(path);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error("Invalid client adapter directory");
  }
  return realpath(path);
}

export async function readRegularFile(
  path: string,
  readContent = true,
): Promise<{ content: string; mode: number }> {
  const before = await lstat(path);
  if (before.isSymbolicLink() || !before.isFile()) {
    throw new Error(INVALID_CLIENT_ADAPTER_FILE_MESSAGE);
  }
  const flags =
    typeof constants.O_NOFOLLOW === "number"
      ? constants.O_RDONLY | constants.O_NOFOLLOW
      : constants.O_RDONLY;
  let handle: FileHandle;
  try {
    handle = await open(path, flags);
  } catch (error) {
    if (errorCode(error) === "ELOOP") throw new Error(INVALID_CLIENT_ADAPTER_FILE_MESSAGE);
    throw error;
  }
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino)
      throw new Error(INVALID_CLIENT_ADAPTER_FILE_MESSAGE);
    const content = readContent ? await handle.readFile("utf8") : "";
    const after = await handle.stat();
    if (!after.isFile() || after.dev !== before.dev || after.ino !== before.ino)
      throw new Error(INVALID_CLIENT_ADAPTER_FILE_MESSAGE);
    return { content, mode: after.mode & 0o7777 };
  } finally {
    await handle.close();
  }
}

export function parseRecord(value: unknown): Record<string, unknown> {
  const parsed = typeof value === "string" ? (JSON.parse(value) as unknown) : value;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Invalid client adapter data");
  }
  return parsed as Record<string, unknown>;
}

export function assertExactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  if (Object.keys(value).sort().join(",") !== [...expected].sort().join(",")) {
    throw new Error(INVALID_CLIENT_ADAPTER_METADATA_MESSAGE);
  }
}

export function isContained(parentRealPath: string, childRealPath: string): boolean {
  return childRealPath.startsWith(`${parentRealPath}${sep}`);
}
