import { randomBytes } from "node:crypto";
import { lstat } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname, join, resolve } from "node:path";
import { CONTAINER_MARKER_ENV } from "../../setup/constants.js";
import {
  ensurePrivateDirectory,
  errorCode,
  readSnapshot,
  validatePrivateDirectory,
  withPrivateFileLock,
  writePrivateFileAtomically,
} from "../../setup/transaction.js";
import { RESTRICTOR_HOME_DIRECTORY } from "../../utils/paths.js";

export type KeyringEntry = {
  getPassword(): string | null;
  setPassword(password: string): void;
};

export type OAuthStorageOptions = {
  home?: string;
  environment?: NodeJS.ProcessEnv;
  loadKeyringEntry?: () => Promise<KeyringEntry>;
};

export const MASTER_KEY_FILE_ENV = "MCP_RESTRICTOR_MASTER_KEY_FILE";

export function configuredMasterKeyFile(
  environment: NodeJS.ProcessEnv = process.env,
  cwd = process.cwd(),
): string | undefined {
  if (!Object.hasOwn(environment, MASTER_KEY_FILE_ENV)) return undefined;
  const value = environment[MASTER_KEY_FILE_ENV];
  return typeof value === "string" && value.length > 0 ? resolve(cwd, value) : undefined;
}

export async function loadMasterKey(options: OAuthStorageOptions): Promise<Buffer> {
  const keyFile = configuredMasterKeyFile(options.environment);
  if (keyFile) return readMasterKeyFile(keyFile);

  try {
    const loadEntry = options.loadKeyringEntry ?? loadSystemKeyringEntry;
    const entry = await loadEntry();
    const stored = entry.getPassword();
    if (stored !== null) return decodeKey(stored);
    const lockTarget = join(userInfo().homedir, RESTRICTOR_HOME_DIRECTORY, "oauth-master-key-v1");
    return await withPrivateFileLock(lockTarget, async () => {
      const lockedEntry = await loadEntry();
      const winner = lockedEntry.getPassword();
      if (winner !== null) return decodeKey(winner);
      const key = randomBytes(32);
      try {
        lockedEntry.setPassword(key.toString("base64url"));
        return key;
      } catch (error) {
        key.fill(0);
        throw error;
      }
    });
  } catch {
    throw new Error("OAuth master key is unavailable");
  }
}

export async function prepareMasterKeyForSetup(options: OAuthStorageOptions): Promise<void> {
  const environment = options.environment ?? process.env;
  const keyFile = configuredMasterKeyFile(environment);
  if (
    !Object.hasOwn(environment, CONTAINER_MARKER_ENV) ||
    environment[CONTAINER_MARKER_ENV] !== "1" ||
    keyFile !== "/home/restrictor/.mcp-restrictor-key/oauth-master-key-v1"
  ) {
    const key = await loadMasterKey(options);
    key.fill(0);
    return;
  }

  await prepareContainerMasterKey(keyFile, options);
}

async function loadSystemKeyringEntry(): Promise<KeyringEntry> {
  const { Entry } = await import("@napi-rs/keyring");
  return new Entry("mcp-restrictor", "oauth-master-key-v1");
}

async function readMasterKeyFile(path: string): Promise<Buffer> {
  try {
    const initial = await lstat(path);
    if (!initial.isFile() || initial.isSymbolicLink()) throw new Error();
    if (process.platform !== "win32" && (initial.mode & 0o077) !== 0) throw new Error();
    const uid = process.getuid?.();
    if (uid !== undefined && initial.uid !== uid) throw new Error();
    const snapshot = await readSnapshot(path);
    if (
      !snapshot ||
      snapshot.dev !== initial.dev ||
      snapshot.ino !== initial.ino ||
      (process.platform !== "win32" && (snapshot.mode & 0o077) !== 0)
    ) {
      throw new Error();
    }
    return decodeKey(snapshot.content);
  } catch {
    throw new Error("OAuth master key file is invalid");
  }
}

async function prepareContainerMasterKey(
  path: string,
  options: OAuthStorageOptions,
): Promise<void> {
  const parent = dirname(path);
  try {
    await validatePrivateDirectory(parent, "OAuth master key directory");
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw new Error("OAuth master key file is invalid");
    try {
      await ensurePrivateDirectory(parent);
      await validatePrivateDirectory(parent, "OAuth master key directory");
    } catch {
      throw new Error("OAuth master key file is invalid");
    }
  }

  try {
    await lstat(path);
    const existing = await loadMasterKey(options);
    existing.fill(0);
    return;
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }

  const key = randomBytes(32);
  try {
    await writePrivateFileAtomically({ path, content: key.toString("base64url") });
  } catch {
    const winner = await loadMasterKey(options);
    winner.fill(0);
  } finally {
    key.fill(0);
  }
}

function decodeKey(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error("Invalid OAuth master key");
  const key = Buffer.from(value, "base64url");
  if (key.length !== 32 || key.toString("base64url") !== value) {
    key.fill(0);
    throw new Error("Invalid OAuth master key");
  }
  return key;
}
