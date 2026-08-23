import { readdir } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import type { ClientAdapter, ClientLoadContext, ClientRestoreEntry } from "../../client-adapter.js";
import { builtInAdapters } from "../adapters.js";
import { claudeAdapter } from "../claude.js";
import { codexAdapter } from "../codex.js";
import { opencodeAdapter } from "../opencode.js";
import { restoreAdapterConfig, type LoadedConfig } from "../adapter-boundary.js";
import { readPrivateFileSnapshot, sha256, validatePrivateDirectory } from "../transaction.js";
import { RESTRICTOR_HOME_DIRECTORY } from "../../utils/paths.js";
import type { ServerCandidate } from "../wrapper.js";

const STAMP = /^(\d{4})-(\d{2})-(\d{2})T(\d{2})-(\d{2})-(\d{2})\.(\d{3})Z-[A-Za-z0-9_-]+$/;
const builtInAdapterSet = new Set([
  ...builtInAdapters,
  claudeAdapter,
  codexAdapter,
  opencodeAdapter,
]);

export async function findLegacyRestoreEntry(options: {
  home: string;
  adapter: ClientAdapter;
  loaded: LoadedConfig;
  server: ServerCandidate;
  context: ClientLoadContext;
}): Promise<ClientRestoreEntry | undefined> {
  try {
    if (!builtInAdapterSet.has(options.adapter) || options.loaded.adapter !== options.adapter) {
      return undefined;
    }
    const configPath = resolve(options.loaded.config.path);
    if (
      options.server.client !== options.adapter.id ||
      resolve(options.server.configPath) !== configPath ||
      options.loaded.config.client !== options.adapter.id ||
      options.loaded.config.path !== options.server.configPath
    ) {
      return undefined;
    }
    const backupRoot = join(resolve(options.home), RESTRICTOR_HOME_DIRECTORY, "backups");
    const group = join(backupRoot, sha256(configPath));
    await validatePrivateDirectory(backupRoot, "Legacy backup directory");
    await validatePrivateDirectory(group, "Legacy backup group");

    const names = await readdir(group, { withFileTypes: true });
    const stamps: string[] = [];
    for (const entry of names) {
      try {
        const path = join(group, entry.name);
        if (!entry.isDirectory()) {
          // Validate symlinks and other unexpected entries without reading them.
          await validatePrivateDirectory(path, "Legacy backup stamp");
          continue;
        }
        if (validStamp(entry.name)) stamps.push(entry.name);
      } catch {
        continue;
      }
    }
    stamps.sort((left, right) => right.localeCompare(left));

    const fileName = basename(configPath);
    for (const stamp of stamps) {
      try {
        const directory = join(group, stamp);
        await validatePrivateDirectory(directory, "Legacy backup stamp");
        const snapshot = await readPrivateFileSnapshot(join(directory, fileName));
        const entry: ClientRestoreEntry = {
          name: options.server.name,
          originalSource: snapshot.content,
        };
        restoreAdapterConfig(options.adapter, options.loaded.config, [entry], options.context);
        return entry;
      } catch {}
    }
    return undefined;
  } catch {
    return undefined;
  }
}

function validStamp(name: string): boolean {
  const match = STAMP.exec(name);
  if (!match) return false;
  const year = Number(match[1]!);
  const month = Number(match[2]!);
  const day = Number(match[3]!);
  const hour = Number(match[4]!);
  const minute = Number(match[5]!);
  const second = Number(match[6]!);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const days = [31, leapYear(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]!;
  return day >= 1 && day <= days;
}

function leapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}
