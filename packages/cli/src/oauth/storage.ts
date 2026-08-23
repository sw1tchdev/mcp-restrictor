import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { Stats } from "node:fs";
import { lstat } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { RESTRICTOR_HOME_DIRECTORY } from "../utils/paths.js";
import {
  readSnapshot,
  writePrivateFileAtomically,
  type FileSnapshot,
} from "../setup/transaction.js";
import { AES_256_GCM_ALGORITHM } from "./constants.js";
import {
  MASTER_KEY_FILE_ENV,
  configuredMasterKeyFile,
  loadMasterKey,
  prepareMasterKeyForSetup,
  type KeyringEntry,
  type OAuthStorageOptions,
} from "./storage/master-key.js";
import {
  assertProfileId,
  jsonCopy,
  normalizeStoredProfileMetadata,
  parseCredentialState,
  parseProfileMetadata,
  parseStoredProfile,
  safeProfileId,
  type EncryptionEnvelope,
  type OAuthCallbackStrategy,
  type OAuthCredentialState,
  type OAuthProfile,
  type OAuthProfileMetadata,
} from "./storage/schema.js";

export { MASTER_KEY_FILE_ENV, assertProfileId, configuredMasterKeyFile };
export type {
  KeyringEntry,
  OAuthCallbackStrategy,
  OAuthCredentialState,
  OAuthProfile,
  OAuthProfileMetadata,
  OAuthStorageOptions,
};

export async function assertOAuthStorageReady(options: OAuthStorageOptions = {}): Promise<void> {
  const key = await loadMasterKey(options);
  key.fill(0);
}

export async function prepareOAuthStorageForSetup(options: OAuthStorageOptions): Promise<void> {
  await prepareMasterKeyForSetup(options);
}

export function oauthProfilePath(home: string, profileId: string): string {
  assertProfileId(profileId);
  return join(home, RESTRICTOR_HOME_DIRECTORY, "oauth", `${profileId}.json`);
}

export async function prepareOAuthProfileWrite(
  profile: OAuthProfile,
  options: OAuthStorageOptions = {},
): Promise<{ path: string; content: string; mode: 0o600 }> {
  const profileId = safeProfileId(profile?.metadata?.profileId);
  let key: Buffer | undefined;
  let plaintext: Buffer | undefined;
  try {
    const metadata = parseProfileMetadata(profile.metadata);
    const credentials = parseCredentialState(jsonCopy(profile.credentials));
    const path = oauthProfilePath(options.home ?? homedir(), metadata.profileId);
    key = await loadMasterKey(options);
    const nonce = randomBytes(12);
    const aad = Buffer.from(JSON.stringify(metadata));
    plaintext = Buffer.from(JSON.stringify(credentials));
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const encryption: EncryptionEnvelope = {
      algorithm: AES_256_GCM_ALGORITHM,
      nonce: nonce.toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
    };
    return { path, content: JSON.stringify({ ...metadata, encryption }), mode: 0o600 };
  } catch {
    throw profileError(profileId, "encrypt");
  } finally {
    key?.fill(0);
    plaintext?.fill(0);
  }
}

export async function readOAuthProfile(
  profileId: string,
  options: OAuthStorageOptions = {},
): Promise<OAuthProfile> {
  return (await readOAuthProfileSnapshot(profileId, options)).profile;
}

export async function readOAuthProfileSnapshot(
  profileId: string,
  options: OAuthStorageOptions = {},
): Promise<{ profile: OAuthProfile; snapshot: FileSnapshot }> {
  assertProfileId(profileId);
  const path = oauthProfilePath(options.home ?? homedir(), profileId);
  let snapshot: FileSnapshot;
  try {
    snapshot = await readPrivateSnapshot(path);
  } catch {
    throw profileError(profileId, "read");
  }

  let stored: ReturnType<typeof parseStoredProfile>;
  try {
    stored = parseStoredProfile(JSON.parse(snapshot.content));
  } catch {
    throw profileError(profileId, "parse");
  }

  let key: Buffer | undefined;
  let plaintext: Buffer | undefined;
  try {
    key = await loadMasterKey(options);
    const decipher = createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(stored.encryption.nonce, "base64url"),
    );
    decipher.setAAD(Buffer.from(JSON.stringify(stored.metadata)));
    decipher.setAuthTag(Buffer.from(stored.encryption.tag, "base64url"));
    plaintext = Buffer.concat([
      decipher.update(Buffer.from(stored.encryption.ciphertext, "base64url")),
      decipher.final(),
    ]);
    if (stored.metadata.profileId !== profileId) {
      throw new Error("OAuth profile identifier mismatch");
    }
    return {
      profile: {
        metadata: normalizeStoredProfileMetadata(stored.metadata),
        credentials: parseCredentialState(JSON.parse(plaintext.toString("utf8"))),
      },
      snapshot,
    };
  } catch {
    throw profileError(profileId, "decrypt");
  } finally {
    key?.fill(0);
    plaintext?.fill(0);
  }
}

export async function writeOAuthProfile(
  profile: OAuthProfile,
  options: OAuthStorageOptions & { before?: FileSnapshot } = {},
): Promise<FileSnapshot> {
  const profileId = safeProfileId(profile?.metadata?.profileId);
  const prepared = await prepareOAuthProfileWrite(profile, options);
  try {
    return await writePrivateFileAtomically({
      path: prepared.path,
      content: prepared.content,
      ...(options.before ? { before: options.before } : {}),
    });
  } catch {
    throw profileError(profileId, "write");
  }
}

async function readPrivateSnapshot(path: string): Promise<FileSnapshot> {
  const parent = await lstat(dirname(path));
  validatePrivateStat(parent, true);
  const initial = await lstat(path);
  validatePrivateStat(initial, false);
  const snapshot = await readSnapshot(path);
  if (
    !snapshot ||
    snapshot.dev !== initial.dev ||
    snapshot.ino !== initial.ino ||
    snapshot.mode !== 0o600
  ) {
    throw new Error("Private profile changed while reading");
  }
  return snapshot;
}

function validatePrivateStat(stat: Stats, directory: boolean): void {
  if (
    stat.isSymbolicLink() ||
    (directory ? !stat.isDirectory() : !stat.isFile()) ||
    (stat.mode & 0o7777) !== (directory ? 0o700 : 0o600)
  ) {
    throw new Error("Invalid private storage path");
  }
  const uid = process.getuid?.();
  if (uid !== undefined && stat.uid !== uid) {
    throw new Error("Invalid private storage owner");
  }
}

function profileError(profileId: string, phase: string): Error {
  return new Error(`OAuth profile ${profileId} ${phase} failed`);
}
