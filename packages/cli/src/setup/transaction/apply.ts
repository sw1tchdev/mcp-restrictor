import { randomUUID } from "node:crypto";
import { chmod, mkdir, unlink } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import { sha256 } from "../../utils/hash.js";

import {
  atomicWrite,
  privateDirectory,
  removeFile,
  syncDirectory,
  writeBackup,
} from "./atomic-file.js";
import { withPrivateFileLock } from "./private-lock.js";
import {
  readSnapshot,
  sameSnapshot,
  validateInstalled,
  validatePlan,
  validatePrivateTarget,
  validateTarget,
  type FileSnapshot,
  type PlannedDelete,
  type PlannedFileChange,
  type PlannedWrite,
} from "./snapshots.js";

export type AcceptInstalledUpdate = (
  path: string,
  validate: (snapshot: FileSnapshot) => Promise<void>,
) => Promise<void>;

export async function writePrivateFileAtomically(options: {
  path: string;
  content: string;
  before?: FileSnapshot;
  nonce?: string;
}): Promise<FileSnapshot> {
  const path = resolve(options.path);
  const write: PlannedWrite = {
    path,
    ...(options.before ? { before: options.before } : {}),
    content: options.content,
    mode: 0o600,
    backupKey: path,
  };
  validatePlan([write]);
  const nonce = options.nonce ?? randomUUID();
  if (!/^[A-Za-z0-9_-]+$/.test(nonce)) {
    throw new Error("Invalid private-write nonce");
  }
  return withPrivateFileLock(
    path,
    async () => {
      await validatePrivateTarget(write);
      let installed: FileSnapshot | undefined;
      try {
        installed = await atomicWrite(path, options.content, 0o600, nonce, () =>
          validatePrivateTarget(write),
        );
        await syncDirectory(dirname(path));
        return installed;
      } catch (originalError) {
        if (!installed) throw originalError;
        try {
          await rollbackPrivateWrite(write, installed, nonce);
        } catch (rollbackError) {
          throw new AggregateError(
            [originalError, rollbackError],
            "Private write and rollback failed",
          );
        }
        throw originalError;
      }
    },
    {
      rollback: (installed) => rollbackPrivateWrite(write, installed, nonce),
    },
  );
}

export async function applyFileTransaction(
  writes: readonly PlannedFileChange[],
  options: {
    backupRoot: string;
    verify(acceptInstalledUpdate: AcceptInstalledUpdate): Promise<void>;
    signal?: AbortSignal;
    now?: Date;
    nonce?: string;
  },
): Promise<{ backupDirectories: string[] }> {
  validatePlan(writes);
  options.signal?.throwIfAborted();
  await Promise.all(writes.map(validateTarget));
  options.signal?.throwIfAborted();

  const nonce = options.nonce ?? randomUUID();
  const backupDirectories = await createBackups(
    writes,
    resolve(options.backupRoot),
    options.now ?? new Date(),
    nonce,
  );
  const journal: Array<{ change: PlannedFileChange; installed?: FileSnapshot }> = [];

  try {
    for (const write of writes) {
      options.signal?.throwIfAborted();
      if (write.delete === true) {
        await removePlannedFile(write, nonce);
        journal.push({ change: write });
        options.signal?.throwIfAborted();
        continue;
      }
      const install = () =>
        atomicWrite(resolve(write.path), write.content, write.mode, nonce, () =>
          write.private ? validatePrivateTarget(write) : validateTarget(write),
        );
      const installed = write.private
        ? await writePrivateFileAtomically({
            path: resolve(write.path),
            content: write.content,
            ...(write.before ? { before: write.before } : {}),
            nonce,
          })
        : await install();
      journal.push({ change: write, installed });
      options.signal?.throwIfAborted();
    }
    options.signal?.throwIfAborted();
    await options.verify(async (path, validate) => {
      const target = resolve(path);
      const entry = journal.find(({ change }) => resolve(change.path) === target);
      if (!entry) throw new Error(`Installed update is not journaled: ${target}`);
      if (entry.change.delete === true || !entry.change.private || !entry.installed) {
        throw new Error(`Installed update is not a private journal entry: ${target}`);
      }
      const accept = async () => {
        const beforeValidation = await readSnapshot(target);
        if (!beforeValidation) throw new Error(`Installed update is missing: ${target}`);
        await validate(beforeValidation);
        const afterValidation = await readSnapshot(target);
        if (!afterValidation || !sameSnapshot(beforeValidation, afterValidation)) {
          throw new Error(`Installed update changed during validation: ${target}`);
        }
        return afterValidation;
      };
      let accepted: FileSnapshot | undefined;
      try {
        await withPrivateFileLock(target, async () => {
          accepted = await accept();
        });
      } catch (error) {
        if (accepted) entry.installed = accepted;
        throw error;
      }
      entry.installed = accepted!;
    });
    options.signal?.throwIfAborted();
    return { backupDirectories };
  } catch (originalError) {
    const errors: unknown[] = [originalError];
    for (const entry of journal.reverse()) {
      const { change } = entry;
      try {
        if (change.delete === true) {
          if (change.private) {
            await withPrivateFileLock(resolve(change.path), () => rollbackDelete(change, nonce));
          } else {
            await rollbackDelete(change, nonce);
          }
          continue;
        }
        const { installed } = entry;
        const rollback = async () => {
          if (change.before) {
            await atomicWrite(
              resolve(change.path),
              change.before.content,
              change.before.mode,
              nonce,
              () => validateInstalled(installed!),
            );
          } else {
            await validateInstalled(installed!);
            await removeFile(resolve(change.path));
          }
        };
        if (change.private) {
          await withPrivateFileLock(resolve(change.path), () =>
            rollbackPrivateWrite(change, installed!, nonce),
          );
        } else await rollback();
      } catch (rollbackError) {
        errors.push(rollbackError);
      }
    }
    if (errors.length > 1) {
      throw new AggregateError(errors, "File transaction and rollback failed");
    }
    throw originalError;
  }
}

async function removePlannedFile(change: PlannedDelete, nonce: string): Promise<void> {
  const path = resolve(change.path);
  const remove = async () => {
    await (change.private ? validatePrivateTarget(change) : validateTarget(change));
    await unlink(path);
    try {
      await syncDirectory(dirname(path));
    } catch (originalError) {
      try {
        await rollbackDelete(change, nonce);
      } catch (rollbackError) {
        throw new AggregateError([originalError, rollbackError], "Delete and rollback failed");
      }
      throw originalError;
    }
    return change.before;
  };
  if (change.private) {
    await withPrivateFileLock(path, remove, {
      rollback: () => rollbackDelete(change, nonce),
    });
  } else {
    await remove();
  }
}

async function rollbackDelete(change: PlannedDelete, nonce: string): Promise<void> {
  const path = resolve(change.path);
  if (await readSnapshot(path)) return;
  await atomicWrite(
    path,
    change.before.content,
    change.before.mode,
    `${nonce}-rollback`,
    async () => {
      if (await readSnapshot(path)) throw new Error(`Rollback target changed: ${path}`);
    },
  );
  await syncDirectory(dirname(path));
}

async function rollbackPrivateWrite(
  write: PlannedWrite,
  installed: FileSnapshot,
  nonce: string,
): Promise<void> {
  if (write.before) {
    await atomicWrite(
      resolve(write.path),
      write.before.content,
      write.before.mode,
      `${nonce}-rollback`,
      () => validateInstalled(installed),
    );
  } else {
    await validateInstalled(installed);
    await unlink(resolve(write.path));
  }
  await syncDirectory(dirname(resolve(write.path)));
}

async function createBackups(
  writes: readonly PlannedFileChange[],
  backupRoot: string,
  now: Date,
  nonce: string,
): Promise<string[]> {
  const restrictorHome = dirname(backupRoot);
  await privateDirectory(restrictorHome);
  await privateDirectory(backupRoot);
  const stamp = `${now.toISOString().replaceAll(":", "-")}-${nonce}`;
  const groups = new Map<string, PlannedFileChange[]>();
  for (const write of writes) {
    const group = groups.get(write.backupKey) ?? [];
    group.push(write);
    groups.set(write.backupKey, group);
  }

  const directories: string[] = [];
  for (const [backupKey, group] of groups) {
    const keyDirectory = join(backupRoot, sha256(backupKey));
    await privateDirectory(keyDirectory);
    const directory = join(keyDirectory, stamp);
    await mkdir(directory, { mode: 0o700 });
    await chmod(directory, 0o700);
    directories.push(directory);
    for (const write of group) {
      if (!write.before) continue;
      await writeBackup(join(directory, basename(write.path)), write.before.content);
    }
  }
  return directories;
}
