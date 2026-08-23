import { lstat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { readSnapshot, type FileSnapshot } from "./transaction.js";
import { errorCode, validateDirectoryComponents } from "./transaction/atomic-file.js";
import { quoted } from "./presentation.js";

export const CLIENT_CONFIGURATION_TARGET = "client configuration";

export async function readSetupSnapshot(
  path: string,
  target: typeof CLIENT_CONFIGURATION_TARGET | "policy",
): Promise<FileSnapshot | undefined> {
  try {
    return await readSnapshot(path);
  } catch {
    throw new Error(`Failed to read ${target} ${quoted(path)}`);
  }
}

export async function setupTargetExists(
  path: string,
  target: typeof CLIENT_CONFIGURATION_TARGET | "policy",
): Promise<boolean> {
  try {
    await validateDirectoryComponents(dirname(resolve(path)), "Path parent", true);
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new Error(`Path is not a regular file: ${path}`);
    }
    return true;
  } catch (error) {
    if (errorCode(error) === "ENOENT") return false;
    throw new Error(`Failed to read ${target} ${quoted(path)}`);
  }
}
