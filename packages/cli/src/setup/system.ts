import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { access, stat } from "node:fs/promises";
import { delimiter, isAbsolute, resolve } from "node:path";
import { errorCode } from "../utils/filesystem.js";
import { quoted } from "./presentation.js";

export async function resolveProjectRoot(
  cwd: string,
  environment: NodeJS.ProcessEnv,
): Promise<string> {
  return new Promise((resolveRoot, reject) => {
    execFile(
      "git",
      ["rev-parse", "--show-toplevel"],
      { cwd, env: environment, encoding: "utf8" },
      (error, stdout, stderr) => {
        if (!error) {
          const root = stdout.trim();
          if (root) resolveRoot(resolve(root));
          else reject(new Error("Unable to resolve Git project root"));
          return;
        }
        if (
          errorCode(error) === "ENOENT" ||
          /not a git repository|must be run in a work tree/i.test(stderr)
        ) {
          resolveRoot(cwd);
          return;
        }
        reject(new Error("Unable to resolve Git project root"));
      },
    );
  });
}

export async function requireExecutable(
  command: string,
  cwd: string,
  environment: NodeJS.ProcessEnv,
): Promise<string> {
  const explicit = isAbsolute(command) || command.includes("/") || command.includes("\\");
  const candidates = explicit
    ? [resolve(cwd, command)]
    : executableCandidates(command, cwd, environment);
  for (const path of candidates) {
    if (await isExecutable(path)) return path;
  }
  throw new Error(`Restrictor executable was not found: ${quoted(command)}`);
}

function executableCandidates(
  command: string,
  cwd: string,
  environment: NodeJS.ProcessEnv,
): string[] {
  const path = typeof environment.PATH === "string" ? environment.PATH : "";
  const extensions =
    process.platform === "win32"
      ? (typeof environment.PATHEXT === "string" ? environment.PATHEXT : ".COM;.EXE;.BAT;.CMD")
          .split(";")
          .filter(Boolean)
      : [""];
  return path
    .split(delimiter)
    .flatMap((directory) =>
      extensions.map((extension) =>
        resolve(
          directory || cwd,
          process.platform === "win32" && !command.toLowerCase().endsWith(extension.toLowerCase())
            ? `${command}${extension}`
            : command,
        ),
      ),
    );
}

async function isExecutable(path: string): Promise<boolean> {
  try {
    if (!(await stat(path)).isFile()) return false;
    await access(path, process.platform === "win32" ? constants.F_OK : constants.X_OK);
    return true;
  } catch {
    return false;
  }
}
