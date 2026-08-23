import { chmod, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough, Writable } from "node:stream";
import { afterEach, expect, test } from "vitest";
import { runSetupCommand } from "../src/setup/index.ts";
import { resolveProjectRoot } from "../src/setup/system.ts";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { force: true, recursive: true })),
  );
});

test("returns the resolved cwd when Git is missing", async () => {
  const cwd = await temporaryDirectory();
  const emptyPath = await temporaryDirectory();

  await expect(resolveProjectRoot(cwd, { PATH: emptyPath })).resolves.toBe(cwd);
});

test("returns the cwd when Git reports an ordinary non-repository", async () => {
  const cwd = await temporaryDirectory();
  const bin = await temporaryDirectory();
  await fakeGit(
    bin,
    'process.stderr.write("fatal: not a git repository (or any parent up to mount point)\\n"); process.exit(128);',
  );

  await expect(resolveProjectRoot(cwd, { PATH: bin })).resolves.toBe(cwd);
});

test("rejects another Git executable failure", async () => {
  const cwd = await temporaryDirectory();
  const bin = await temporaryDirectory();
  await fakeGit(
    bin,
    'process.stderr.write("fatal: injected executable failure\\n"); process.exit(2);',
  );

  await expect(resolveProjectRoot(cwd, { PATH: bin })).rejects.toThrow(
    "Unable to resolve Git project root",
  );
});

test("uses the injected setup PATH to resolve a Manual upstream project root", async () => {
  const cwd = join(process.cwd(), "packages", "cli");
  const home = await temporaryDirectory();
  const emptyPath = await temporaryDirectory();
  const input = new PassThrough();
  const chunks: Buffer[] = [];
  const output = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  });
  input.end("1\n1\n");

  await runSetupCommand({
    adapters: [],
    cwd,
    home,
    environment: { PATH: emptyPath },
    input,
    output,
    error: output,
    interactive: true,
  });

  expect(Buffer.concat(chunks).toString("utf8")).toContain(
    `Project root: ${JSON.stringify(cwd)}\n`,
  );
});

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-system-")));
  temporaryDirectories.push(path);
  return path;
}

async function fakeGit(directory: string, source: string): Promise<void> {
  const path = join(directory, "git");
  await writeFile(path, `#!${process.execPath}\n${source}\n`);
  await chmod(path, 0o755);
}
