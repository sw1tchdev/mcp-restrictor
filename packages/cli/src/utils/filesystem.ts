import { open, readFile } from "node:fs/promises";

export async function syncDirectory(path: string): Promise<void> {
  // Node/libuv cannot open directories for fsync on Windows.
  if (process.platform === "win32") return;
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export function errorCode(error: unknown): string | undefined {
  return error instanceof Error ? (error as NodeJS.ErrnoException).code : undefined;
}

export function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return errorCode(error) !== "ESRCH";
  }
}

export async function linuxProcessStartIdentity(pid: number): Promise<string | undefined> {
  if (process.platform !== "linux" || !Number.isSafeInteger(pid) || pid <= 0) return undefined;
  try {
    const stat = await readFile(`/proc/${pid}/stat`, "utf8");
    const commandStart = stat.indexOf(" (");
    const commandEnd = stat.lastIndexOf(")");
    if (
      commandStart < 1 ||
      commandEnd <= commandStart ||
      stat.slice(0, commandStart) !== String(pid)
    ) {
      return undefined;
    }
    const fields = stat
      .slice(commandEnd + 1)
      .trim()
      .split(/\s+/);
    const processStart = fields[19];
    return fields.length >= 20 && /^[A-Za-z]$/.test(fields[0]!) && /^[0-9]+$/.test(processStart!)
      ? processStart
      : undefined;
  } catch {
    return undefined;
  }
}
