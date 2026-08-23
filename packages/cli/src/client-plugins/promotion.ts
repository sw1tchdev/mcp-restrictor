import { randomUUID } from "node:crypto";
import { rename, rm, unlink } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

import { isPrivateFileMode, writePrivateFileAtomically } from "../setup/transaction.js";
import {
  directoryExists,
  errorCode,
  parseRecord,
  readRegularFile,
  syncDirectory,
} from "./filesystem.js";
import {
  assertNoExternalAdapterIdConflict,
  validateAcceptedInstalledAdapter,
  validateRestoredInstalledAdapterStructure,
} from "./loading.js";
import {
  BACKUP_NAME,
  GENERATION_NAME,
  GENERATION_POINTER_FILE,
  isCanonicalActiveName,
  JOURNAL_FILE,
} from "./package.js";

export type RemovedClientAdapter = { target: string; inactive: string };

export type ClientAdapterPromotion = { target: string; backup?: string };

type PromotionJournal = {
  version: 1;
  target: string;
  backup?: string;
};

export type PromotionRecovery =
  | { status: "none" }
  | { status: "completed"; cleanupWarning: boolean }
  | { status: "reverted" };

export async function moveClientAdapterInactive(
  target: string,
  root: string,
): Promise<RemovedClientAdapter> {
  const inactive = resolve(root, `.removed-${randomUUID()}`);
  let moved = false;
  try {
    await rename(target, inactive);
    moved = true;
    await syncDirectory(root);
    return { target, inactive };
  } catch (originalError) {
    try {
      const inactiveExists = moved || (await directoryExists(inactive));
      const targetExists = await directoryExists(target);
      if (inactiveExists && !targetExists) {
        await rename(inactive, target);
        await syncDirectory(root);
      } else if (inactiveExists || !targetExists) {
        throw new Error("Client adapter removal state changed");
      }
    } catch (restoreError) {
      throw new AggregateError(
        [originalError, restoreError],
        "Client adapter removal and restoration failed",
      );
    }
    throw originalError;
  }
}

export async function restoreRemovedClientAdapter(
  removed: RemovedClientAdapter,
  root: string,
): Promise<void> {
  await rename(removed.inactive, removed.target);
  await syncDirectory(root);
}

export async function promoteClientAdapter(
  stage: string,
  stagedGeneration: string,
  target: string,
  root: string,
  stagedAdapterId: string,
): Promise<ClientAdapterPromotion> {
  const targetName = target.slice(root.length + 1);
  await assertNoExternalAdapterIdConflict(root, targetName, stagedAdapterId);
  const generationName = basename(stagedGeneration);
  if (!GENERATION_NAME.test(generationName)) {
    throw new Error("Invalid staged client adapter generation");
  }
  await rename(stagedGeneration, join(root, generationName));
  await syncDirectory(root);
  await writePrivateFileAtomically({
    path: join(stage, GENERATION_POINTER_FILE),
    content: JSON.stringify({ generation: generationName }),
  });
  const targetExists = await directoryExists(target);
  const backupName = targetExists ? `.backup-${randomUUID()}` : undefined;
  const backup = backupName ? join(root, backupName) : undefined;
  await writePromotionJournal(root, {
    version: 1,
    target: targetName,
    ...(backupName ? { backup: backupName } : {}),
  });
  let oldMoved = false;
  let promoted = false;
  try {
    if (targetExists) {
      await rename(target, backup!);
      oldMoved = true;
      await syncDirectory(root);
    }
    await rename(stage, target);
    promoted = true;
    await syncDirectory(root);
    await validateAcceptedInstalledAdapter(target, targetName, root);
    return { target, ...(backup ? { backup } : {}) };
  } catch (promotionError) {
    if (!promoted && !oldMoved) {
      try {
        await clearPromotionJournal(root);
      } catch {
        // Recovery on the next locked entry clears this pre-effect journal.
      }
      throw promotionError;
    }
    try {
      if (promoted) await rename(target, stage);
      if (oldMoved) await rename(backup!, target);
      await syncDirectory(root);
      await clearPromotionJournal(root);
    } catch (restoreError) {
      throw new AggregateError(
        [promotionError, restoreError],
        "Client adapter promotion and restoration failed",
      );
    }
    throw promotionError;
  }
}

export async function rollbackClientAdapterPromotion(
  stage: string,
  promotion: ClientAdapterPromotion,
  root: string,
): Promise<void> {
  await rename(promotion.target, stage);
  if (promotion.backup) await rename(promotion.backup, promotion.target);
  await syncDirectory(root);
  await clearPromotionJournal(root);
}

export async function recoverClientPluginPromotion(root: string): Promise<PromotionRecovery> {
  try {
    const journal = await readPromotionJournal(root);
    if (!journal) return { status: "none" };
    const target = join(root, journal.target);
    const backup = journal.backup ? join(root, journal.backup) : undefined;
    const targetExists = await directoryExists(target);
    const backupExists = backup ? await directoryExists(backup) : false;
    if (backup) {
      if (targetExists && backupExists) {
        let targetValid = true;
        try {
          await validateAcceptedInstalledAdapter(target, journal.target, root);
        } catch {
          targetValid = false;
        }
        if (targetValid) {
          await clearPromotionJournal(root);
          let cleanupWarning = false;
          try {
            await rm(backup, { recursive: true });
            await syncDirectory(root);
          } catch {
            cleanupWarning = true;
          }
          return { status: "completed", cleanupWarning };
        }
        await rm(target, { recursive: true });
        await syncDirectory(root);
        await rename(backup, target);
        await syncDirectory(root);
        await validateRestoredInstalledAdapterStructure(target, journal.target, root);
        await clearPromotionJournal(root);
        return { status: "reverted" };
      }
      if (!targetExists && backupExists) {
        await rename(backup, target);
        await syncDirectory(root);
        await validateRestoredInstalledAdapterStructure(target, journal.target, root);
        await clearPromotionJournal(root);
        return { status: "reverted" };
      }
      if (targetExists) {
        await validateRestoredInstalledAdapterStructure(target, journal.target, root);
        await clearPromotionJournal(root);
        return { status: "reverted" };
      }
      throw new Error("Invalid promotion state");
    }
    if (targetExists) {
      let targetValid = true;
      try {
        await validateAcceptedInstalledAdapter(target, journal.target, root);
      } catch {
        targetValid = false;
      }
      if (targetValid) {
        await clearPromotionJournal(root);
        return { status: "completed", cleanupWarning: false };
      }
      await rm(target, { recursive: true });
      await syncDirectory(root);
      await clearPromotionJournal(root);
      return { status: "reverted" };
    }
    await clearPromotionJournal(root);
    return { status: "none" };
  } catch {
    throw new Error("client adapter registry recovery failed");
  }
}

async function writePromotionJournal(root: string, journal: PromotionJournal): Promise<void> {
  await writePrivateFileAtomically({
    path: join(root, JOURNAL_FILE),
    content: JSON.stringify(journal),
  });
  await syncDirectory(root);
}

async function readPromotionJournal(root: string): Promise<PromotionJournal | undefined> {
  let file: { content: string; mode: number };
  try {
    file = await readRegularFile(join(root, JOURNAL_FILE));
  } catch (error) {
    if (errorCode(error) === "ENOENT") return undefined;
    throw error;
  }
  if (!isPrivateFileMode(file.mode)) throw new Error("Invalid promotion journal");
  const value = parseRecord(file.content);
  const keys = Object.keys(value).sort().join(",");
  if (
    value.version !== 1 ||
    typeof value.target !== "string" ||
    !isCanonicalActiveName(value.target) ||
    (keys !== "target,version" && keys !== "backup,target,version") ||
    (value.backup !== undefined &&
      (typeof value.backup !== "string" || !BACKUP_NAME.test(value.backup)))
  )
    throw new Error("Invalid promotion journal");
  return {
    version: 1,
    target: value.target,
    ...(typeof value.backup === "string" ? { backup: value.backup } : {}),
  };
}

async function clearPromotionJournal(root: string): Promise<void> {
  try {
    await unlink(join(root, JOURNAL_FILE));
  } catch (error) {
    if (errorCode(error) !== "ENOENT") throw error;
  }
  await syncDirectory(root);
}
