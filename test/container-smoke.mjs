import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const requireFromCli = createRequire(resolve(root, "packages/cli/package.json"));
const loadCliDependency = async (name) => import(pathToFileURL(requireFromCli.resolve(name)).href);
const [{ Client, StreamableHTTPClientTransport }, { toNodeHandler }, serverModule] =
  await Promise.all([
    loadCliDependency("@modelcontextprotocol/client"),
    loadCliDependency("@modelcontextprotocol/node"),
    loadCliDependency("@modelcontextprotocol/server"),
  ]);
const { createMcpHandler, McpServer } = serverModule;

const id = `${process.pid}-${randomBytes(5).toString("hex")}`;
const image = process.env.MCP_RESTRICTOR_TEST_IMAGE || "mcp-restrictor:container-smoke";
const snapshotRegressionOnly = process.env.MCP_RESTRICTOR_SNAPSHOT_REGRESSION === "1";
const secret = `mcp-restrictor-smoke-secret-${randomBytes(12).toString("hex")}`;
process.env.SMOKE_SECRET = secret;
const platform = ["--platform", "linux/amd64"];
const hardenedRuntime = [
  "--read-only",
  "--tmpfs",
  "/tmp:rw,noexec,nosuid,size=16m",
  "--cap-drop",
  "ALL",
  "--security-opt",
  "no-new-privileges=true",
];
const containers = new Set();
const volumes = new Set();
const temporaryFiles = new Set();
const observed = [];
const buildSentinels = [
  join(root, `.env.container-smoke-${id}`),
  join(root, "packages/cli", `.env.container-smoke-${id}`),
];
let fixture;
let setupSequence = 0;

const snapshotProgram = `import { lstat, readFile, readdir, readlink, rm } from "node:fs/promises";
import { join } from "node:path";
const entries = [];
async function visit(path, relative) {
  try {
    const stat = await lstat(path);
    if (relative === process.env.MCP_RESTRICTOR_SNAPSHOT_DISAPPEAR_AFTER_LSTAT) await rm(path);
    if (relative) {
      const entry = { path: relative, mode: stat.mode & 0o7777, uid: stat.uid, type: stat.isDirectory() ? "directory" : stat.isFile() ? "file" : stat.isSymbolicLink() ? "symlink" : "other" };
      if (stat.isFile()) entry.content = await readFile(path, "utf8");
      if (stat.isSymbolicLink()) entry.target = await readlink(path);
      entries.push(entry);
    }
    if (stat.isDirectory()) {
      for (const name of (await readdir(path)).sort()) {
        const child = join(path, name);
        if (!relative && name === process.env.MCP_RESTRICTOR_SNAPSHOT_DISAPPEAR) await rm(child);
        await visit(child, relative ? relative + "/" + name : name);
      }
    }
  } catch (error) {
    if (relative && error && typeof error === "object" && error.code === "ENOENT") return;
    throw error;
  }
}
await visit("/volume", "");
process.stdout.write(JSON.stringify(entries));`;

let inventory;
let failure;
try {
  inventory = await runSmoke();
} catch (error) {
  failure = error;
}
const cleanupFailures = await cleanupResources();
if (failure && cleanupFailures.length > 0)
  throw new AggregateError([failure, ...cleanupFailures], "container smoke and cleanup failed");
if (failure) throw failure;
if (cleanupFailures.length > 0)
  throw new AggregateError(cleanupFailures, "container smoke cleanup failed");
assert(inventory);
process.stdout.write(
  `container smoke passed image=${image} id=${inventory.Id} size=${inventory.Size} architecture=${inventory.Architecture}\n`,
);

async function runSmoke() {
  docker(["version", "--format", "{{.Server.Version}}"], { label: "Docker daemon probe" });
  if (!process.env.MCP_RESTRICTOR_TEST_IMAGE) {
    for (const path of buildSentinels) {
      await writeFile(path, `${secret}\n`, { flag: "wx", mode: 0o600 });
      temporaryFiles.add(path);
    }
    docker(["build", "--platform", "linux/amd64", "--tag", image, "."], {
      cwd: root,
      label: "amd64 image build",
    });
    for (const path of temporaryFiles) await removeTemporaryFile(path);
  }

  const imageInventory = inspectImage();
  assertSnapshotToleratesDisappearedEntry();
  if (snapshotRegressionOnly) return imageInventory;
  assertImageFilesystem();
  assertReadOnlyRuntime();
  assertDefaultAndSetupDispatch();
  assertRejectedMountRoots();
  assertRejectedLockFiles();

  fixture = await startFixture();
  await assertFixtureReachable();
  await assertGeneratedRoutesAndGlobalLock();
  await assertLiveChildLockOwner();

  assert.doesNotMatch(observed.join("\n"), new RegExp(escapeRegExp(secret)));
  return imageInventory;
}

async function removeTemporaryFile(path) {
  await rm(path);
  temporaryFiles.delete(path);
}

async function collectCleanupFailure(failures, label, action) {
  try {
    await action();
  } catch (error) {
    failures.push(new Error(`${label} cleanup failed`, { cause: error }));
  }
}

async function cleanupResources() {
  const failures = [];
  if (fixture) {
    await collectCleanupFailure(failures, "fixture", async () => {
      await fixture.close();
      fixture = undefined;
    });
  }
  for (const name of [...containers].reverse()) {
    await collectCleanupFailure(failures, `container ${name}`, () => {
      docker(["rm", "--force", name], { label: `remove leftover container ${name}` });
      containers.delete(name);
    });
  }
  for (const name of [...volumes].reverse()) {
    await collectCleanupFailure(failures, `volume ${name}`, () => {
      docker(["volume", "rm", "--force", name], { label: `remove smoke volume ${name}` });
      volumes.delete(name);
    });
  }
  for (const path of temporaryFiles) {
    await collectCleanupFailure(failures, `temporary file ${path}`, () =>
      removeTemporaryFile(path),
    );
  }
  return failures;
}

function docker(args, options = {}) {
  const result = spawnSync("docker", args, {
    cwd: options.cwd ?? root,
    encoding: "utf8",
    env: options.env ? { ...process.env, ...options.env } : process.env,
    input: options.input,
    maxBuffer: 128 * 1024 * 1024,
  });
  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";
  const output = `${stdout}\n${stderr}`;
  observed.push(output);
  assert.doesNotMatch(output, new RegExp(escapeRegExp(secret)));
  if (!options.allowFailure && result.status !== 0) {
    throw new Error(
      `${options.label ?? "Docker command"} failed with ${String(result.status)}${stderr ? `: ${stderr.trim()}` : ""}`,
    );
  }
  return { status: result.status, stdout, stderr, output };
}

async function dockerAsync(args, options = {}) {
  const child = spawn("docker", args, {
    cwd: options.cwd ?? root,
    env: options.env ? { ...process.env, ...options.env } : process.env,
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stdout = [];
  const stderr = [];
  let combined = "";
  let searchFrom = 0;
  let stepIndex = 0;
  let writing = false;
  let inputError;
  let timedOut = false;
  const advance = () => {
    if (writing || !options.steps || stepIndex >= options.steps.length) return;
    const step = options.steps[stepIndex];
    const prompts = Array.isArray(step.waitFor) ? step.waitFor : [step.waitFor];
    let promptEnd = searchFrom;
    for (const prompt of prompts) {
      const promptStart = combined.indexOf(prompt, promptEnd);
      if (promptStart < 0) return;
      promptEnd = promptStart + prompt.length;
    }
    stepIndex++;
    writing = true;
    const chunks = Array.isArray(step.input) ? [...step.input] : [step.input];
    const writeNext = () => {
      const chunk = chunks.shift();
      if (chunk !== undefined) child.stdin.write(chunk);
      if (chunks.length > 0) {
        globalThis.setTimeout(writeNext, 25);
        return;
      }
      searchFrom = combined.length;
      writing = false;
      advance();
    };
    globalThis.setTimeout(writeNext, 100);
  };
  const capture = (target, chunk) => {
    target.push(chunk);
    combined += chunk.toString();
    advance();
  };
  child.stdout.on("data", (chunk) => capture(stdout, chunk));
  child.stderr.on("data", (chunk) => capture(stderr, chunk));
  child.stdin.on("error", (error) => {
    inputError = error;
  });
  if (!options.steps) child.stdin.end(options.input);
  const timeout = options.timeoutMs
    ? globalThis.setTimeout(() => {
        timedOut = true;
        child.kill("SIGTERM");
      }, options.timeoutMs)
    : undefined;
  const [status] = await once(child, "close");
  if (timeout) globalThis.clearTimeout(timeout);
  const result = {
    status,
    stdout: Buffer.concat(stdout).toString("utf8"),
    stderr: Buffer.concat(stderr).toString("utf8"),
  };
  result.output = `${result.stdout}\n${result.stderr}`;
  result.missingPrompt = options.steps?.[stepIndex]?.waitFor;
  result.inputError = inputError;
  result.timedOut = timedOut;
  observed.push(result.output);
  assert.doesNotMatch(result.output, new RegExp(escapeRegExp(secret)));
  if (!options.allowFailure && (status !== 0 || result.missingPrompt || inputError || timedOut)) {
    throw new Error(
      `${options.label ?? "Docker command"} failed with ${String(status)}${timedOut ? " after timeout" : ""}${result.missingPrompt ? ` before prompt ${JSON.stringify(result.missingPrompt)}` : ""}${inputError ? `: ${inputError.message}` : result.stderr ? `: ${result.stderr.trim()}` : ""}`,
    );
  }
  return result;
}

function createVolume(label) {
  const name = `mcp-restrictor-smoke-${id}-${label}`;
  docker(["volume", "create", name], { label: `create ${label} volume` });
  volumes.add(name);
  return name;
}

function inspectImage() {
  const result = docker(["image", "inspect", image], { label: "image inspection" });
  const [inventory] = JSON.parse(result.stdout);
  assert.equal(inventory.Architecture, "amd64");
  assert.equal(inventory.Config.User, "1000:1000");
  assert.equal(inventory.Config.WorkingDir, "/workspace");
  assert.deepEqual(inventory.Config.Entrypoint, ["/usr/local/bin/docker-entrypoint.sh"]);
  assert.deepEqual(inventory.Config.Cmd, ["run", "--bind", "0.0.0.0"]);
  assert.deepEqual(inventory.Config.ExposedPorts, { "17319/tcp": {} });
  const environment = Object.fromEntries(
    inventory.Config.Env.map((value) => value.split(/=(.*)/s, 2)),
  );
  assert.equal(environment.HOME, "/home/restrictor");
  assert.equal(environment.NPM_CONFIG_CACHE, "/tmp/npm-cache");
  assert.equal(
    environment.MCP_RESTRICTOR_MASTER_KEY_FILE,
    "/home/restrictor/.mcp-restrictor-key/oauth-master-key-v1",
  );
  assert.equal(environment.MCP_RESTRICTOR_CONTAINER, undefined);
  const history = docker(["image", "history", "--no-trunc", image], {
    label: "image history inspection",
  });
  assert.doesNotMatch(`${result.stdout}\n${history.stdout}`, new RegExp(escapeRegExp(secret)));
  return inventory;
}

function assertImageFilesystem() {
  const script = `set -eu
test "$(id -u):$(id -g)" = "1000:1000"
test -x "$(command -v mcp-restrictor)"
! command -v git >/dev/null 2>&1
for path in \
  /opt/mcp-restrictor/node_modules/@napi-rs/keyring \
  /opt/mcp-restrictor/node_modules/typescript \
  /opt/mcp-restrictor/node_modules/vitest \
  /opt/mcp-restrictor/node_modules/oxlint \
  /opt/mcp-restrictor/node_modules/oxfmt \
  /opt/mcp-restrictor/node_modules/@types \
  /opt/mcp-restrictor/src \
  /opt/mcp-restrictor/test \
  /opt/mcp-restrictor/tests \
  /opt/mcp-restrictor/node_modules/@mcp-restrictor/core/src \
  /opt/mcp-restrictor/node_modules/@mcp-restrictor/core/test \
  /opt/mcp-restrictor/node_modules/@mcp-restrictor/policy/src \
  /opt/mcp-restrictor/node_modules/@mcp-restrictor/policy/test \
  /opt/mcp-restrictor/node_modules/@mcp-restrictor/transports/src \
  /opt/mcp-restrictor/node_modules/@mcp-restrictor/transports/test
do
  test ! -e "$path"
done
test -z "$(find /opt/mcp-restrictor -type f -name '*.map' -print -quit)"
test -z "$(find /opt/mcp-restrictor -name .git -print -quit)"
if grep -R -a -l -F "$SMOKE_SECRET" /opt/mcp-restrictor >/tmp/secret-paths 2>/dev/null; then
  sed -n '1,20p' /tmp/secret-paths
  exit 1
fi`;
  docker(
    [
      "run",
      "--rm",
      ...platform,
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=16m",
      "--env",
      "SMOKE_SECRET",
      "--entrypoint",
      "sh",
      image,
      "-c",
      script,
    ],
    { label: "runtime filesystem inventory" },
  );
  docker(
    [
      "run",
      "--rm",
      ...platform,
      "--user",
      "0:0",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=16m",
      "--env",
      "SMOKE_SECRET",
      "--entrypoint",
      "sh",
      image,
      "-c",
      `matches=$(find / -xdev -type f -exec grep -a -l -F "$SMOKE_SECRET" {} + 2>/dev/null || :)
test -z "$matches"`,
    ],
    { label: "whole-image secret scan" },
  );
}

function assertReadOnlyRuntime() {
  const script = `set -eu
test "$(id -u):$(id -g)" = "1000:1000"
test "$(findmnt -n -b -o SIZE /tmp)" = "16777216"
options=$(findmnt -n -o OPTIONS /tmp)
case ",$options," in *,rw,*) ;; *) exit 1 ;; esac
case ",$options," in *,noexec,*) ;; *) exit 1 ;; esac
case ",$options," in *,nosuid,*) ;; *) exit 1 ;; esac
mkdir -p "$NPM_CONFIG_CACHE"
: > "$NPM_CONFIG_CACHE/write-check"
if touch /workspace/root-write-check 2>/dev/null; then exit 1; fi`;
  docker(
    ["run", "--rm", ...platform, ...hardenedRuntime, "--entrypoint", "sh", image, "-c", script],
    { label: "read-only runtime" },
  );
}

function assertDefaultAndSetupDispatch() {
  const state = createVolume("dispatch-state");
  const key = createVolume("dispatch-key");
  const mounts = pairedMounts(state, key);
  const defaultRun = docker(["run", "--rm", ...platform, ...mounts, image], {
    allowFailure: true,
    label: "default command dispatch",
  });
  assert.notEqual(defaultRun.status, 0);
  assert.match(defaultRun.output, /No managed HTTP routes; run setup/);

  const setup = docker(["run", "--rm", ...platform, ...mounts, image, "setup"], {
    allowFailure: true,
    label: "setup command dispatch",
  });
  assert.notEqual(setup.status, 0);
  assert.match(setup.output, /setup requires an interactive terminal/);
  assert.doesNotMatch(setup.output, /No managed HTTP routes/);
  assert.deepEqual(snapshotVolume(key), []);
}

function assertRejectedMountRoots() {
  for (const row of [
    { name: "state-permissive", target: "state", uid: 1000, mode: 0o755 },
    { name: "key-wrong-owner", target: "key", uid: 0, mode: 0o700 },
  ]) {
    const state = createVolume(`${row.name}-state`);
    const key = createVolume(`${row.name}-key`);
    prepareVolumeRoot(
      state,
      row.target === "state" ? row.uid : 1000,
      row.target === "state" ? row.mode : 0o700,
    );
    prepareVolumeRoot(
      key,
      row.target === "key" ? row.uid : 1000,
      row.target === "key" ? row.mode : 0o700,
    );
    const result = docker(
      ["run", "--rm", ...platform, ...pairedMounts(state, key), image, "client", "list"],
      { allowFailure: true, label: `reject ${row.name}` },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.output, /invalid container private directory/);
    assert.doesNotMatch(result.output, /No installed client adapters/);
  }
}

function assertRejectedLockFiles() {
  const cases = {
    symlink: `: > /state/lock-target
chown 1000:1000 /state/lock-target
chmod 600 /state/lock-target
ln -s lock-target /state/.container.lock`,
    nonregular: `mkdir /state/.container.lock
chown 1000:1000 /state/.container.lock
chmod 700 /state/.container.lock`,
    "wrong-owner": `: > /state/.container.lock
chown 0:0 /state/.container.lock
chmod 600 /state/.container.lock`,
    permissive: `: > /state/.container.lock
chown 1000:1000 /state/.container.lock
chmod 644 /state/.container.lock`,
  };
  for (const [name, seed] of Object.entries(cases)) {
    const state = createVolume(`invalid-${name}-state`);
    const key = createVolume(`invalid-${name}-key`);
    seedVolume(
      state,
      `chown 1000:1000 /state
chmod 700 /state
${seed}`,
    );
    prepareVolumeRoot(key, 1000, 0o700);
    const result = docker(
      ["run", "--rm", ...platform, ...pairedMounts(state, key), image, "client", "list"],
      { allowFailure: true, label: `reject ${name} lock` },
    );
    assert.notEqual(result.status, 0);
    assert.match(result.output, /invalid container lock file/);
    assert.doesNotMatch(result.output, /No installed client adapters/);
  }
}

async function assertGeneratedRoutesAndGlobalLock() {
  const state = createVolume("routes-state");
  const key = createVolume("routes-key");
  seedSavedPolicies(state);
  const setupSteps = [
    { waitFor: "Select action", input: "\r" },
    { waitFor: "Select clients", input: ["\u001B[B", "\u001B[B", "\u001B[B", "\r"] },
    { waitFor: "Server name", input: ["generated-e2e", "\r"] },
    { waitFor: "Transport", input: ["\u001B[B", "\r"] },
    { waitFor: "Upstream URL", input: [fixture.url, "\r"] },
    { waitFor: "Headers", input: ["\u001B[B", "\r"] },
    { waitFor: "Header name", input: ["X-Smoke-Secret", "\r"] },
    { waitFor: "Environment variable", input: ["SMOKE_SECRET", "\r"] },
    { waitFor: "Headers", input: "\r" },
    { waitFor: "Authentication", input: "\r" },
    { waitFor: "Select destination", input: ["\u001B[B", " ", "\r"] },
    {
      waitFor: "Select generated client presets",
      input: ["\u001B[B", "\u001B[B", " ", "\r"],
    },
    { waitFor: "Select HTTP gateway port", input: "\r" },
    {
      waitFor: ["Tools & Policy — Claude Code / user", "Select Tools & Policy"],
      input: "\r",
    },
    {
      waitFor: ["Tools & Policy — Codex / user", "Select Tools & Policy"],
      input: "\r",
    },
    { waitFor: "Connect to this upstream?", input: "\r" },
    { waitFor: "Apply these changes?", input: "\r" },
  ];
  const setup = await runSetupContainer(state, key, setupSteps);
  assert.match(setup.output, /Client preset fragment .* Claude Code/s);
  assert.match(setup.output, /Client preset fragment .* Codex/s);
  assert.deepEqual(snapshotVolume(key), []);

  const before = snapshotVolume(state);
  assertPrivateGeneratedArtifacts(before);
  const routes = installedRoutes(before);
  const claude = routes.get("claude");
  const codex = routes.get("codex");
  assert(claude && codex);
  assert.notEqual(new URL(claude.listenUrl).pathname, new URL(codex.listenUrl).pathname);
  for (const route of [claude, codex]) {
    assert.equal(new URL(route.listenUrl).origin, "http://127.0.0.1:17319");
    assert.equal(route.owner.projectRoot, "/home/restrictor");
    assert.equal(route.owner.scope, "user");
  }

  seedInnerLock(state, { version: 2, pid: 1, processStart: "0" });
  const gateway = `mcp-restrictor-smoke-${id}-gateway`;
  containers.add(gateway);
  docker(
    [
      "run",
      "--detach",
      "--name",
      gateway,
      ...platform,
      ...hardenedRuntime,
      "--add-host",
      "localhost:host-gateway",
      "--publish",
      "127.0.0.1:17319:17319",
      ...pairedMounts(state, key),
      "--env",
      "SMOKE_SECRET",
      image,
    ],
    { label: "first generated gateway" },
  );
  await waitForContainerLogs(gateway, [claude.listenUrl, codex.listenUrl]);

  const sdk = new Client({ name: "container-smoke", version: "1.0.0" });
  await exerciseRoute(sdk, claude.listenUrl, "read_file", "search");
  await exerciseRoute(sdk, codex.listenUrl, "search", "read_file");

  const contender = docker(["run", "--rm", ...platform, ...pairedMounts(state, key), image], {
    allowFailure: true,
    label: "global lock contender",
  });
  assert.notEqual(contender.status, 0);
  assert.match(contender.output, /stop the other container/);
  assert.doesNotMatch(contender.output, /listening|preflight|No managed HTTP routes/);

  observed.push(docker(["logs", gateway], { label: "first gateway logs" }).output);
  docker(["kill", "--signal", "KILL", gateway], { label: "force gateway termination" });
  docker(["wait", gateway], { label: "wait for killed gateway" });
  docker(["rm", gateway], { label: "remove killed gateway" });
  containers.delete(gateway);

  const recovered = docker(
    ["run", "--rm", ...platform, ...pairedMounts(state, key), image, "client", "list"],
    { label: "post-kill stale-lock recovery" },
  );
  assert.match(recovered.output, /No installed client adapters/);
  assertDecoysAndReleasedInnerLock(snapshotVolume(state));

  const restore = await runSetupContainer(state, key, [
    { waitFor: "Select action", input: ["\u001B[B", "\r"] },
    { waitFor: "Select servers to restore", input: "\r" },
    { waitFor: "Restore selected MCP servers?", input: "\r" },
  ]);
  assert.match(restore.output, /Restored:/);
  assert.match(restore.output, /Remove "generated-e2e" from the host Claude Code configuration/);

  const after = snapshotVolume(state);
  assert.equal(installedRoutes(after).size, 1);
  assert.equal(after.filter((entry) => /^restore\/.*\.json$/.test(entry.path)).length, 1);
  assert.equal(
    after.some((entry) => entry.path === "generated/claude.json"),
    false,
  );
  assert.equal(
    after.some((entry) => entry.path === "generated/codex.toml"),
    true,
  );

  const restarted = `mcp-restrictor-smoke-${id}-restarted`;
  containers.add(restarted);
  docker(
    [
      "run",
      "--detach",
      "--name",
      restarted,
      ...platform,
      ...hardenedRuntime,
      "--add-host",
      "localhost:host-gateway",
      "--publish",
      "127.0.0.1:17319:17319",
      ...pairedMounts(state, key),
      "--env",
      "SMOKE_SECRET",
      image,
    ],
    { label: "restarted generated gateway" },
  );
  await waitForContainerLogs(restarted, [codex.listenUrl]);
  assert.equal((await fetch(claude.listenUrl)).status, 404);
  const restartedSdk = new Client({ name: "container-smoke-restart", version: "1.0.0" });
  await exerciseRoute(restartedSdk, codex.listenUrl, "search", "read_file");
  observed.push(docker(["logs", restarted], { label: "restarted gateway logs" }).output);
  docker(["stop", "--time", "10", restarted], { label: "stop restarted gateway" });
  docker(["rm", restarted], { label: "remove restarted gateway" });
  containers.delete(restarted);

  assert.deepEqual(snapshotVolume(key), []);
  assertNoSecretInEntries(before);
  assertNoSecretInEntries(after);
}

async function assertLiveChildLockOwner() {
  const state = createVolume("live-owner-state");
  const key = createVolume("live-owner-key");
  prepareVolumeRoot(key, 1000, 0o700);
  const helper = `mcp-restrictor-smoke-${id}-pid-helper`;
  containers.add(helper);
  docker(
    [
      "run",
      "--detach",
      "--name",
      helper,
      ...platform,
      "--entrypoint",
      "sh",
      image,
      "-c",
      'sleep 300 & child=$!; printf "%s" "$child" >/tmp/child.pid; wait "$child" || true; while :; do sleep 300; done',
    ],
    { label: "live-owner PID helper" },
  );
  const owner = await waitForChildOwner(helper);
  seedInnerLock(state, { version: 2, ...owner });

  const waiter = `mcp-restrictor-smoke-${id}-live-owner`;
  containers.add(waiter);
  docker(
    [
      "run",
      "--detach",
      "--name",
      waiter,
      ...platform,
      "--pid",
      `container:${helper}`,
      ...pairedMounts(state, key),
      image,
      "client",
      "list",
    ],
    { label: "live-child lock waiter" },
  );
  await delay(750);
  assert.equal(containerRunning(waiter), true);
  const waiting = snapshotVolume(state);
  const lock = waiting.find((entry) => entry.path === "client-plugins/..registry.lock");
  assert(lock && lock.type === "file");
  assert.deepEqual(JSON.parse(lock.content), {
    version: 2,
    pid: owner.pid,
    processStart: owner.processStart,
    token: "11111111-1111-4111-8111-111111111111",
  });
  assertDecoys(waiting);

  docker(["exec", helper, "sh", "-c", 'kill "$(cat /tmp/child.pid)"'], {
    label: "terminate live child owner",
  });
  const exit = docker(["wait", waiter], { label: "wait for recovered live-owner command" });
  assert.equal(exit.stdout.trim(), "0");
  const logs = docker(["logs", waiter], { label: "live-owner command logs" });
  assert.match(logs.output, /No installed client adapters/);
  docker(["rm", waiter], { label: "remove live-owner command" });
  containers.delete(waiter);
  assertDecoysAndReleasedInnerLock(snapshotVolume(state));

  docker(["rm", "--force", helper], { label: "remove PID helper" });
  containers.delete(helper);
}

function pairedMounts(state, key) {
  return [
    "--volume",
    `${state}:/home/restrictor/.mcp-restrictor`,
    "--volume",
    `${key}:/home/restrictor/.mcp-restrictor-key`,
  ];
}

async function runSetupContainer(state, key, steps) {
  const name = `mcp-restrictor-smoke-${id}-setup-${++setupSequence}`;
  docker(
    [
      "create",
      "--interactive",
      "--tty",
      "--name",
      name,
      ...platform,
      ...hardenedRuntime,
      "--add-host",
      "localhost:host-gateway",
      ...pairedMounts(state, key),
      "--env",
      "SMOKE_SECRET",
      image,
      "setup",
    ],
    { label: "create generated preset setup" },
  );
  containers.add(name);
  const attached = await dockerAsync(["start", "--attach", "--interactive", name], {
    allowFailure: true,
    steps,
    timeoutMs: 60_000,
    label: "run generated preset setup",
  });
  const stateResult = docker(["inspect", "--format", "{{json .State}}", name], {
    label: "inspect generated preset setup",
  });
  const containerState = JSON.parse(stateResult.stdout);
  const logs = docker(["logs", name], { label: "generated preset setup logs" });
  docker(["rm", ...(containerState.Running ? ["--force"] : []), name], {
    label: "remove generated preset setup",
  });
  containers.delete(name);
  if (
    attached.status !== 0 ||
    attached.timedOut ||
    attached.missingPrompt ||
    attached.inputError ||
    containerState.ExitCode !== 0
  ) {
    throw new Error(
      `Generated preset setup failed${attached.timedOut ? " after timeout" : ""}${attached.missingPrompt ? ` before prompt ${JSON.stringify(attached.missingPrompt)}` : ""}${attached.inputError ? ` while writing input: ${attached.inputError.message}` : ""} at the upstream boundary: ${JSON.stringify(fixture.diagnostics)}\n${logs.output}`,
    );
  }
  return logs;
}

async function assertFixtureReachable() {
  const program = `const missing = await fetch(process.env.FIXTURE_URL, { signal: AbortSignal.timeout(5000) });
if (missing.status !== 401) throw new Error("missing smoke header was accepted");
const accepted = await fetch(process.env.FIXTURE_URL, { headers: { "x-smoke-secret": process.env.SMOKE_SECRET }, signal: AbortSignal.timeout(5000) });
if (accepted.status === 401) throw new Error("exact smoke header was rejected");
process.stdout.write(missing.status + ":" + accepted.status);`;
  const result = await dockerAsync(
    [
      "run",
      "--rm",
      ...platform,
      "--add-host",
      "localhost:host-gateway",
      "--env",
      "FIXTURE_URL",
      "--env",
      "SMOKE_SECRET",
      "--entrypoint",
      "node",
      image,
      "--input-type=module",
      "--eval",
      program,
    ],
    { env: { FIXTURE_URL: fixture.url }, label: "fixture reachability" },
  );
  assert.match(result.stdout, /^401:[1-5][0-9][0-9]$/);
}

function assertSnapshotToleratesDisappearedEntry() {
  const volume = createVolume("snapshot-race");
  seedVolume(
    volume,
    `chown 1000:1000 /state
chmod 700 /state
printf "%s" "stable" > /state/stable
printf "%s" "transient" > /state/transient-before-lstat
printf "%s" "transient" > /state/transient-after-lstat
chown 1000:1000 /state/stable /state/transient-before-lstat /state/transient-after-lstat
chmod 600 /state/stable /state/transient-before-lstat /state/transient-after-lstat`,
  );
  const entries = snapshotVolume(volume, "transient-before-lstat", "transient-after-lstat");
  assert.equal(entries.find((entry) => entry.path === "stable")?.content, "stable");
  assert.equal(
    entries.some((entry) => entry.path.startsWith("transient-")),
    false,
  );
}

function snapshotVolume(volume, disappearingEntry, disappearingAfterLstatEntry) {
  const environment = {
    ...(disappearingEntry ? { MCP_RESTRICTOR_SNAPSHOT_DISAPPEAR: disappearingEntry } : {}),
    ...(disappearingAfterLstatEntry
      ? { MCP_RESTRICTOR_SNAPSHOT_DISAPPEAR_AFTER_LSTAT: disappearingAfterLstatEntry }
      : {}),
  };
  const mutable = Object.keys(environment).length > 0;
  const result = docker(
    [
      "run",
      "--rm",
      ...platform,
      "--volume",
      `${volume}:/volume${mutable ? "" : ":ro"}`,
      ...Object.keys(environment).flatMap((name) => ["--env", name]),
      "--entrypoint",
      "node",
      image,
      "--input-type=module",
      "--eval",
      snapshotProgram,
    ],
    { env: environment, label: "volume snapshot" },
  );
  return JSON.parse(result.stdout);
}

function prepareVolumeRoot(volume, uid, mode) {
  seedVolume(
    volume,
    `: > /state/.smoke-volume
chown ${uid}:${uid} /state /state/.smoke-volume
chmod ${mode.toString(8)} /state
chmod 600 /state/.smoke-volume`,
  );
}

function seedVolume(volume, script, environment = {}) {
  docker(
    [
      "run",
      "--rm",
      ...platform,
      "--user",
      "0:0",
      "--volume",
      `${volume}:/state`,
      ...Object.keys(environment).flatMap((name) => ["--env", name]),
      "--entrypoint",
      "sh",
      image,
      "-c",
      `set -eu\n${script}`,
    ],
    { env: environment, label: "seed test volume" },
  );
}

function seedSavedPolicies(state) {
  seedVolume(
    state,
    `install -d -o 1000 -g 1000 -m 0700 \
  /state \
  /state/saved-policies \
  /state/saved-policies/claude \
  /state/saved-policies/claude/generated-e2e.d \
  /state/saved-policies/codex \
  /state/saved-policies/codex/generated-e2e.d
install -o 1000 -g 1000 -m 0600 /dev/null /state/saved-policies/claude/generated-e2e.d/read-only.yaml
install -o 1000 -g 1000 -m 0600 /dev/null /state/saved-policies/codex/generated-e2e.d/search-only.yaml
printf "%s" "$CLAUDE_POLICY" > /state/saved-policies/claude/generated-e2e.d/read-only.yaml
printf "%s" "$CODEX_POLICY" > /state/saved-policies/codex/generated-e2e.d/search-only.yaml`,
    {
      CLAUDE_POLICY:
        "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n  deny: []\n",
      CODEX_POLICY: "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: search\n  deny: []\n",
    },
  );
}

function seedInnerLock(state, owner) {
  const lockOwner = JSON.stringify({
    ...owner,
    token: "11111111-1111-4111-8111-111111111111",
  });
  seedVolume(
    state,
    `mkdir -p /state/client-plugins
chown 1000:1000 /state /state/client-plugins
chmod 700 /state /state/client-plugins
printf "%s" "$LOCK_OWNER" > /state/client-plugins/..registry.lock
printf "%s" "keep-reap-decoy" > /state/client-plugins/..registry.lock.reap.decoy
printf "%s" "keep-lock-decoy" > /state/client-plugins/.unrelated.lock
chown 1000:1000 /state/client-plugins/..registry.lock /state/client-plugins/..registry.lock.reap.decoy /state/client-plugins/.unrelated.lock
chmod 600 /state/client-plugins/..registry.lock /state/client-plugins/..registry.lock.reap.decoy /state/client-plugins/.unrelated.lock`,
    { LOCK_OWNER: lockOwner },
  );
}

function installedRoutes(entries) {
  return new Map(
    entries
      .filter((entry) => entry.type === "file" && /^routes\/.*\.json$/.test(entry.path))
      .map((entry) => {
        const route = JSON.parse(entry.content);
        return [route.owner.adapterId, route];
      }),
  );
}

function assertPrivateGeneratedArtifacts(entries) {
  assert.equal(installedRoutes(entries).size, 2);
  for (const path of [
    "generated",
    "generated/policies",
    "generated/policies/claude",
    "generated/policies/codex",
    "routes",
    "restore",
  ]) {
    const entry = entries.find((candidate) => candidate.path === path);
    assert(entry && entry.type === "directory", path);
    assert.equal(entry.mode, 0o700, path);
    assert.equal(entry.uid, 1000, path);
  }
  for (const path of [
    "generated/claude.json",
    "generated/codex.toml",
    "generated/policies/claude/generated-e2e.yaml",
    "generated/policies/codex/generated-e2e.yaml",
  ]) {
    const entry = entries.find((candidate) => candidate.path === path);
    assert(entry && entry.type === "file", path);
    assert.equal(entry.mode, 0o600, path);
    assert.equal(entry.uid, 1000, path);
  }
  assert.equal(entries.filter((entry) => /^routes\/.*\.json$/.test(entry.path)).length, 2);
  assert.equal(entries.filter((entry) => /^restore\/.*\.json$/.test(entry.path)).length, 2);
  assertNoSecretInEntries(entries);
}

function assertNoSecretInEntries(entries) {
  for (const entry of entries) {
    assert.doesNotMatch(JSON.stringify(entry), new RegExp(escapeRegExp(secret)), entry.path);
  }
}

function assertDecoys(entries) {
  assert.equal(
    entries.find((entry) => entry.path === "client-plugins/..registry.lock.reap.decoy")?.content,
    "keep-reap-decoy",
  );
  assert.equal(
    entries.find((entry) => entry.path === "client-plugins/.unrelated.lock")?.content,
    "keep-lock-decoy",
  );
}

function assertDecoysAndReleasedInnerLock(entries) {
  assert.equal(
    entries.some((entry) => entry.path === "client-plugins/..registry.lock"),
    false,
  );
  assertDecoys(entries);
}

async function exerciseRoute(client, url, allowed, denied) {
  const transport = new StreamableHTTPClientTransport(new URL(url));
  await client.connect(transport);
  try {
    assert.deepEqual(
      (await client.listTools()).tools.map(({ name }) => name),
      [allowed],
    );
    const result = await client.callTool({ name: allowed, arguments: {} });
    assert.match(result.content[0]?.text ?? "", new RegExp(`^upstream:${allowed}:`));
    await assert.rejects(client.callTool({ name: denied, arguments: {} }), {
      code: -32001,
    });
  } finally {
    await client.close();
  }
}

async function startFixture() {
  const diagnostics = [];
  const handler = createMcpHandler(() => {
    const server = new McpServer({ name: "container-smoke-upstream", version: "1.0.0" });
    for (const name of ["read_file", "search", "delete_file"]) {
      server.registerTool(name, {}, async () => ({
        content: [{ type: "text", text: `upstream:${name}:${id}` }],
      }));
    }
    return server;
  });
  const nodeHandler = toNodeHandler(handler);
  const server = createServer((request, response) => {
    const authorized = request.headers["x-smoke-secret"] === secret;
    diagnostics.push({ method: request.method, url: request.url, authorized });
    if (!authorized) {
      response.writeHead(401).end("Unauthorized");
      return;
    }
    void nodeHandler(request, response);
  });
  server.listen(0, "0.0.0.0");
  await once(server, "listening");
  const address = server.address();
  assert(address && typeof address !== "string");
  return {
    url: `http://localhost:${address.port}/mcp`,
    diagnostics,
    close: async () => {
      const failures = [];
      try {
        await handler.close();
      } catch (error) {
        failures.push(error);
      }
      try {
        await new Promise((resolveClose, reject) =>
          server.close((error) => (error ? reject(error) : resolveClose())),
        );
      } catch (error) {
        failures.push(error);
      }
      if (failures.length > 0) throw new AggregateError(failures, "fixture cleanup failed");
    },
  };
}

async function waitForContainerLogs(name, needles) {
  for (let attempt = 0; attempt < 240; attempt++) {
    const logs = docker(["logs", name], { label: "gateway readiness logs" });
    if (needles.every((needle) => logs.output.includes(needle))) return;
    if (!containerRunning(name)) throw new Error(`Gateway exited before readiness: ${logs.output}`);
    await delay(250);
  }
  throw new Error("Gateway readiness timed out");
}

function containerRunning(name) {
  const result = docker(["inspect", "--format", "{{.State.Running}}", name], {
    label: "container state inspection",
  });
  return result.stdout.trim() === "true";
}

async function waitForChildOwner(helper) {
  const program = `const { readFileSync } = require("node:fs");
const pid = Number(readFileSync("/tmp/child.pid", "utf8"));
const source = readFileSync("/proc/" + pid + "/stat", "utf8");
const close = source.lastIndexOf(")");
const fields = source.slice(close + 1).trim().split(/\\s+/);
process.stdout.write(JSON.stringify({ pid, processStart: fields[19] }));`;
  for (let attempt = 0; attempt < 80; attempt++) {
    const result = docker(["exec", helper, "node", "--eval", program], {
      allowFailure: true,
      label: "read live child identity",
    });
    if (result.status === 0) {
      const owner = JSON.parse(result.stdout);
      assert(Number.isSafeInteger(owner.pid) && owner.pid > 0);
      assert.match(owner.processStart, /^[0-9]+$/);
      return owner;
    }
    await delay(100);
  }
  throw new Error("Live child identity was not published");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
