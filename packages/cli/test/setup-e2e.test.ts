import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import {
  execFile as execFileCallback,
  spawn,
  type ChildProcessWithoutNullStreams,
} from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, join, resolve } from "node:path";
import { PassThrough, Readable, Writable } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { parse as parseJsonc } from "jsonc-parser";
import { parse } from "smol-toml";
import { afterEach, expect, test } from "vitest";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { main } from "../src/index.ts";
import { clientPluginsRoot } from "../src/client-plugins.ts";
import { runSetup } from "../src/setup/index.ts";
import { MASTER_KEY_FILE_ENV } from "../src/oauth/storage.ts";
import { startRemoteAuthFixture } from "../../transports/test/remote-auth-fixture.ts";
import {
  exerciseGeneratedWrapper,
  certificatePath,
  privateKeyPath,
  snapshotTree,
  startDualEraHttpFixture,
  writeNodeLauncher,
  type GeneratedWrapper,
} from "./helpers.ts";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(testDirectory, "../../..");
const compiledCli = resolve(projectRoot, "packages/cli/dist/index.js");
const fixture = resolve(
  projectRoot,
  "packages/transports/test/fixtures/config-sensitive-upstream.mjs",
);
const runFile = promisify(execFileCallback);
const temporaryDirectories: string[] = [];

const remoteCases = [
  {
    name: "Claude Streamable HTTP",
    client: "claude",
    transport: "http",
    oauth: true,
    callback: "claude",
    header: "X-Claude-Key",
    secondHeader: undefined,
  },
  {
    name: "Claude SSE",
    client: "claude",
    transport: "sse",
    oauth: true,
    callback: "claude",
    header: undefined,
    secondHeader: undefined,
  },
  {
    name: "Claude WebSocket",
    client: "claude",
    transport: "websocket",
    oauth: false,
    callback: "claude",
    header: "X-Claude-Key",
    secondHeader: undefined,
  },
  {
    name: "Codex Streamable HTTP",
    client: "codex",
    transport: "http",
    oauth: true,
    callback: "codex",
    header: "X-Codex-Key",
    secondHeader: "X-Codex-Env-Key",
  },
  {
    name: "OpenCode V1 SSE fallback OAuth",
    client: "opencode",
    schema: "v1",
    transport: "sse",
    oauth: true,
    callback: "claude",
    header: undefined,
    secondHeader: undefined,
  },
  {
    name: "OpenCode V2 Streamable HTTP headers",
    client: "opencode",
    schema: "v2",
    transport: "http",
    oauth: false,
    callback: "claude",
    header: "X-OpenCode-Key",
    secondHeader: undefined,
  },
  {
    name: "Manual Streamable HTTP",
    client: "manual",
    transport: "http",
    oauth: true,
    callback: "manual",
    header: "X-Manual-Key",
    secondHeader: undefined,
  },
  {
    name: "Manual SSE",
    client: "manual",
    transport: "sse",
    oauth: true,
    callback: "manual",
    header: undefined,
    secondHeader: undefined,
  },
  {
    name: "Manual WebSocket",
    client: "manual",
    transport: "websocket",
    oauth: false,
    callback: "manual",
    header: "Authorization",
    secondHeader: undefined,
  },
] as const;

const installedManualCases = [
  {
    name: "Claude project STDIO inherits its environment",
    transport: "stdio",
    wrapper: { client: "claude" },
  },
  {
    name: "Codex user SSE OAuth",
    transport: "sse",
    wrapper: { client: "codex" },
  },
  {
    name: "OpenCode V2 WebSocket uses Authorization from its environment",
    transport: "websocket",
    wrapper: { client: "opencode", schema: "v2" },
  },
] as const;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { force: true, recursive: true })),
  );
});

test.each(remoteCases)("$name setup runs the generated wrapper", runRemoteSetupCase, 10_000);

async function runRemoteSetupCase(row: (typeof remoteCases)[number]): Promise<void> {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const keyPath = join(root, "oauth-master.key");
  let keyBytes = "";
  const headerValue =
    row.transport === "websocket" && row.client === "claude"
      ? "${TOKEN}"
      : row.client === "manual" && row.transport === "websocket"
        ? "Basic manual-ws-secret"
        : `${row.client}-${row.transport}-header-secret`;
  if (row.oauth) {
    keyBytes = randomBytes(32).toString("base64url");
    await writeFile(keyPath, keyBytes, { mode: 0o600 });
    await chmod(keyPath, 0o600);
  }
  const upstream = await startRemoteAuthFixture({
    transport: row.transport,
    ...(row.header
      ? {
          requiredHeaders: {
            [row.header]: headerValue,
            ...(row.secondHeader ? { [row.secondHeader]: "codex-env-header-secret" } : {}),
          },
        }
      : {}),
    ...(row.oauth
      ? {
          oauth: {
            expectedScope: row.client === "codex" ? "server-scope" : "fixture-scope",
            expectedCallback: row.callback,
            ...(row.client === "codex" ? {} : { challengeScope: "fixture-scope" }),
          },
        }
      : {}),
  });
  const previousHome = process.env.HOME;
  const previousUserProfile = process.env.USERPROFILE;
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  try {
    const restrictor =
      row.client === "opencode"
        ? await executableRestrictor(root)
        : { command: process.execPath, argsPrefix: [compiledCli] };
    const setup = await remoteSetup(row, {
      root,
      home,
      keyPath,
      url: upstream.url,
      headerValue,
    });
    const output = capture();
    const error = capture();
    try {
      await runSetup({
        input: Readable.from(setup.answers),
        output: authorizationCapture(output),
        error,
        interactive: true,
        cwd: root,
        home,
        environment: setup.environment,
        restrictor,
      });
    } catch (failure) {
      throw new Error(`${String(failure)}\nOUTPUT:\n${output.text()}\nERROR:\n${error.text()}`);
    }
    if (row.client === "manual") {
      expect(output.text()).toContain("Transport (stdio/http/sse/websocket): ");
      expect(output.text()).toContain("Header mapping HEADER=ENV_NAME (empty when done): ");
      expect(output.text()).toContain("Authentication (none/bearer/oauth): ");
      if (row.oauth) {
        expect(output.text()).toContain("OAuth client ID (empty for dynamic registration): ");
        expect(output.text()).toContain("OAuth callback base URL (empty for loopback): ");
      }
    }
    const wrapper = await generatedWrapper(row, {
      root,
      output: output.text(),
      environment: setup.environment,
    });
    const policyPath = join(
      root,
      ".mcp-restrictor",
      "policies",
      row.client,
      `${row.client === "manual" ? `manual-${row.transport}` : "remote"}.yaml`,
    );
    const policy = await readFile(policyPath, "utf8");
    expect(policy).toContain("name: allowed_tool");
    expect(policy).not.toContain("name: denied_tool");
    const first = await exerciseGeneratedWrapper(wrapper, {
      expectedTools: ["allowed_tool"],
      allowedTool: "allowed_tool",
      deniedTool: "denied_tool",
    });
    const secrets = [
      row.client === "claude" && row.transport === "websocket" ? "other" : headerValue,
      row.secondHeader ? "codex-env-header-secret" : "",
      keyBytes,
      ...upstream.sensitiveValues(),
    ].filter(Boolean);
    const wrapperStderr = [first.stderr];
    if (row.oauth) {
      expect(wrapper.env?.[MASTER_KEY_FILE_ENV]).toBe(keyPath);
      expect(wrapper.args.join("\0")).not.toContain(keyPath);
      expect(output.text()).not.toContain(keyBytes);
    }
    await expectIsolation(row, { root, home });
    if (row.oauth) {
      expect(upstream.authorizationRequests()).toBe(1);
      expect(upstream.tokenRequests()).toBe(1);
      upstream.expireAccessToken();
      const refreshed = await exerciseGeneratedWrapper(wrapper, {
        expectedTools: ["allowed_tool"],
        allowedTool: "allowed_tool",
        deniedTool: "denied_tool",
      });
      wrapperStderr.push(refreshed.stderr);
      expect(upstream.refreshRequests()).toBe(1);
      upstream.expireAccessToken();
      const rotatedAgain = await exerciseGeneratedWrapper(wrapper, {
        expectedTools: ["allowed_tool"],
        allowedTool: "allowed_tool",
        deniedTool: "denied_tool",
      });
      wrapperStderr.push(rotatedAgain.stderr);
      expect(upstream.refreshRequests()).toBe(2);
      const current = await exerciseGeneratedWrapper(wrapper, {
        expectedTools: ["allowed_tool"],
        allowedTool: "allowed_tool",
        deniedTool: "denied_tool",
      });
      wrapperStderr.push(current.stderr);
      expect(upstream.refreshRequests()).toBe(2);
    }
    if (row.client === "opencode") {
      const configPath = join(root, "opencode.jsonc");
      const beforeRerun = await readFile(configPath, "utf8");
      const rerunOutput = capture();
      await runSetup({
        input: Readable.from(["3\n", "1\n", "2\n", "yes\n", "1\n", "1\n", "yes\n"]),
        output: authorizationCapture(rerunOutput),
        error,
        interactive: true,
        cwd: root,
        home,
        environment: setup.environment,
        restrictor,
      });
      expect(rerunOutput.text()).toContain("OpenCode / remote");
      expect(rerunOutput.text()).toContain("Preview:");
      expect(rerunOutput.text()).not.toContain("No supported MCP servers found.");
      const rerunWrapper = await generatedWrapper(row, {
        root,
        output: output.text(),
        environment: setup.environment,
      });
      expect(rerunWrapper).toEqual(wrapper);
      expect(rerunWrapper.args).not.toContain(rerunWrapper.command);
      expect(await readFile(configPath, "utf8")).toBe(beforeRerun);
      if ("schema" in row && row.schema === "v2") {
        const policyPath = join(root, ".mcp-restrictor/policies/opencode/remote.yaml");
        const beforePolicy = await readFile(policyPath, "utf8");
        await expect(
          runSetup({
            input: Readable.from(["3\n", "1\n", "2\n", "yes\n", "1\n", "1\n", "yes\n"]),
            output,
            error,
            interactive: true,
            cwd: root,
            home,
            environment: setup.environment,
            restrictor: {
              command: restrictor.command,
              argsPrefix: [...restrictor.argsPrefix, "--unknown-verification-option"],
            },
          }),
        ).rejects.toThrow(/Wrapper verification failed/);
        expect(await readFile(configPath, "utf8")).toBe(beforeRerun);
        expect(await readFile(policyPath, "utf8")).toBe(beforePolicy);
      }
    }
    const observable = [
      output.text(),
      error.text(),
      policy,
      wrapper.args.join("\0"),
      ...wrapperStderr,
    ].join("\n");
    for (const secret of [...secrets, ...upstream.sensitiveValues()]) {
      expect(observable).not.toContain(secret);
    }
  } finally {
    restoreEnvironment("HOME", previousHome);
    restoreEnvironment("USERPROFILE", previousUserProfile);
    await upstream.close();
  }
}

test("installs and configures an external client adapter through the real CLI", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const packageRoot = join(root, "fixture-external-adapter");
  const configPath = join(root, "fixture-client.json");
  const policyPath = join(
    root,
    ".mcp-restrictor",
    "policies",
    "fixture-client",
    "fixture-server.yaml",
  );
  const verificationPath = join(root, "verification-capture.json");
  const configEnvironmentValue = "external-config-env-value-83d194";
  const configDataSentinel = "external-config-data-f0542a";
  const installErrorSentinel = "external-install-error-9981ed";
  const lifecycleSentinel = "external-lifecycle-stderr-25b79e";
  const manifestSentinel = "external-manifest-bytes-5d1f20";
  const requestedSpecSentinel = "external-requested-spec-777ccd";
  const verifierStderrSentinel = "external-verifier-stderr-d21644";
  const originalEntry = {
    command: process.execPath,
    args: [fixture, root, "paginated"],
    env: {
      API_KEY: configEnvironmentValue,
      EXPECTED_API_KEY: configEnvironmentValue,
    },
    enabled: true,
  };
  const source = `{
  "configSentinel": ${JSON.stringify(configDataSentinel)},
  "servers": {
    "fixture-server": ${JSON.stringify(originalEntry)},
    "unselected": {
      "command": "unselected-command",
      "nested": [1, { "keep": true }]
    }
  },
  "after": "keep-exact"
}\n`;
  await Promise.all([mkdir(packageRoot, { recursive: true }), writeFile(configPath, source)]);
  await Promise.all([
    writeFile(
      join(packageRoot, "package.json"),
      JSON.stringify({
        name: "fixture-external-adapter",
        version: "1.0.0",
        type: "module",
        description: manifestSentinel,
        scripts: { install: "node install.cjs" },
        mcpRestrictor: { clientAdapter: "./index.js", apiVersion: 1 },
      }),
    ),
    writeFile(
      join(packageRoot, "install.cjs"),
      `const { writeFileSync } = require('node:fs');\nwriteFileSync(__dirname + '/lifecycle-marker', ${JSON.stringify(lifecycleSentinel)});\nprocess.stderr.write(${JSON.stringify(lifecycleSentinel)});\nthrow new Error(${JSON.stringify(installErrorSentinel)});\n`,
    ),
    writeFile(join(packageRoot, "index.js"), externalAdapterModule()),
  ]);
  const npmEnvironment = { ...process.env, npm_config_cache: join(root, "npm-cache") };
  const npm = npmTestCommand(process.platform, npmEnvironment);
  await runFile(
    npm.file,
    [...npm.args, "pack", "--ignore-scripts", "--pack-destination", root, packageRoot],
    {
      cwd: root,
      env: npmEnvironment,
      shell: false,
    },
  );
  const packageTarball = join(root, "fixture-external-adapter-1.0.0.tgz");
  const installSpec = `file:${packageTarball}`;
  const firstRestrictor = await executableRestrictor(join(root, "first-bin"));

  const previousCwd = process.cwd();
  const errorOutput = capture();
  const restoreStderr = captureProcessStderr(errorOutput);
  const pinnedEnvironment = new Map<string, string | undefined>();
  for (const name of [
    "HOME",
    "USERPROFILE",
    MASTER_KEY_FILE_ENV,
    "npm_config_audit",
    "npm_config_cache",
    "npm_config_fund",
    "npm_config_update_notifier",
  ])
    pinnedEnvironment.set(name, process.env[name]);
  process.chdir(root);
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  delete process.env[MASTER_KEY_FILE_ENV];
  process.env.npm_config_audit = "false";
  process.env.npm_config_cache = join(root, "npm-cache");
  process.env.npm_config_fund = "false";
  process.env.npm_config_update_notifier = "false";
  const environment: NodeJS.ProcessEnv = {
    PATH: testPath([dirname(firstRestrictor.command), process.env.PATH ?? ""]),
    ...(process.platform === "win32"
      ? {
          PATHEXT: process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD",
          npm_execpath: npm.args[0],
        }
      : {}),
    HOME: home,
    USERPROFILE: home,
  };
  try {
    const installOutput = capture();
    await main({
      argv: ["node", "mcp-restrictor", "client", "install", installSpec],
      home,
      environment,
      input: ttyInput("yes\n"),
      output: installOutput,
    });
    expect(installOutput.text()).toContain("Installed fixture-external-adapter@1.0.0.");
    expect(installOutput.text()).not.toContain(packageRoot);

    const active = join(clientPluginsRoot(home), "fixture-external-adapter");
    const metadataPath = join(active, ".mcp-restrictor-client-plugin.json");
    const lifecycleMarker = join(
      active,
      "node_modules",
      "fixture-external-adapter",
      "lifecycle-marker",
    );
    await expect(readFile(lifecycleMarker)).rejects.toMatchObject({ code: "ENOENT" });
    if (process.platform === "win32") {
      expect((await lstat(clientPluginsRoot(home))).isDirectory()).toBe(true);
      expect((await lstat(active)).isDirectory()).toBe(true);
      const metadata = await lstat(metadataPath);
      expect(metadata.isFile()).toBe(true);
      expect(metadata.isSymbolicLink()).toBe(false);
      await expect(readFile(metadataPath, "utf8")).resolves.toContain("fixture-external-adapter");
    } else {
      expect((await lstat(clientPluginsRoot(home))).mode & 0o7777).toBe(0o700);
      expect((await lstat(active)).mode & 0o7777).toBe(0o700);
      expect((await lstat(metadataPath)).mode & 0o7777).toBe(0o600);
    }
    await writeBrokenInstalledAdapter(home, requestedSpecSentinel);

    const setupOutput = capture(true);
    await main({
      argv: ["node", "mcp-restrictor", "setup"],
      home,
      environment,
      input: ttyInput("1\n4\n1\n1\nyes\n1\n1\nyes\n"),
      output: setupOutput,
    }).catch((error: unknown) => {
      expect(setupOutput.text()).toContain("4. Z Fixture Client\n");
      throw error;
    });
    expect(setupOutput.text()).toContain(
      "1. Claude Code\n2. Codex\n3. OpenCode\n4. Z Fixture Client\n5. Manual upstream\n",
    );
    expect(setupOutput.text()).toContain(
      "- fixture-broken-adapter: client adapter failed to load\n",
    );
    expect(setupOutput.text()).toContain("Z Fixture Client / fixture-server");
    const renderedSource = await readFile(configPath, "utf8");
    const wrapperArgs = [
      "--policy",
      policyPath,
      "--upstream-env",
      "API_KEY",
      "--upstream-env",
      "EXPECTED_API_KEY",
      "--",
      process.execPath,
      fixture,
      root,
      "paginated",
    ];
    const expectedRenderedSource = source.replace(
      JSON.stringify(originalEntry),
      JSON.stringify({
        command: firstRestrictor.command,
        args: wrapperArgs,
        env: {
          API_KEY: configEnvironmentValue,
          EXPECTED_API_KEY: configEnvironmentValue,
        },
        enabled: true,
      }),
    );
    expect(renderedSource).toBe(expectedRenderedSource);
    const rendered = JSON.parse(renderedSource) as {
      servers: Record<string, GeneratedWrapper & { enabled?: boolean }>;
    };
    const wrapper = rendered.servers["fixture-server"]!;
    expect(wrapper.enabled).toBe(true);
    expect(wrapper).toEqual({
      command: firstRestrictor.command,
      args: wrapperArgs,
      env: {
        API_KEY: configEnvironmentValue,
        EXPECTED_API_KEY: configEnvironmentValue,
      },
      enabled: true,
    });
    const policy = await readFile(policyPath, "utf8");
    expect(policy).toBe(
      "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n  deny: []\n",
    );
    const wrapperResult = await exerciseGeneratedWrapper(wrapper, {
      expectedTools: ["read_file"],
      allowedTool: "read_file",
      deniedTool: "write_file",
    });

    const beforeFailedRerun = await readFile(configPath, "utf8");
    const beforeFailedPolicy = await readFile(policyPath, "utf8");
    const failingRestrictor = await writeFailingRestrictor(join(root, "failing-bin"), {
      verificationPath,
      configPath,
      policyPath,
      stderrSentinel: verifierStderrSentinel,
    });
    environment.PATH = testPath([
      dirname(failingRestrictor.command),
      dirname(firstRestrictor.command),
      process.env.PATH ?? "",
    ]);
    const failedOutput = capture(true);
    const failedError = await main({
      argv: ["node", "mcp-restrictor", "setup"],
      home,
      environment,
      input: ttyInput("1\n4\n1\n2\nyes\n2\n1\nyes\n"),
      output: failedOutput,
    }).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(failedError).toBeInstanceOf(Error);
    expect((failedError as Error).message).toMatch(/Wrapper verification failed/);
    expect(await readFile(configPath, "utf8")).toBe(beforeFailedRerun);
    expect(await readFile(policyPath, "utf8")).toBe(beforeFailedPolicy);
    const verificationCapture = JSON.parse(await readFile(verificationPath, "utf8")) as {
      argv: string[];
      config: string;
      policy: string;
    };
    const expectedFailedConfig = source.replace(
      JSON.stringify(originalEntry),
      JSON.stringify({
        command: failingRestrictor.command,
        args: wrapperArgs,
        env: {
          API_KEY: configEnvironmentValue,
          EXPECTED_API_KEY: configEnvironmentValue,
        },
        enabled: true,
      }),
    );
    const expectedFailedPolicy =
      "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: write_file\n  deny: []\n";
    expect(verificationCapture.config).toBe(expectedFailedConfig);
    expect(verificationCapture.config).not.toBe(beforeFailedRerun);
    expect(verificationCapture.policy).toBe(expectedFailedPolicy);
    expect(verificationCapture.policy).not.toBe(beforeFailedPolicy);
    const rerunArguments = verificationCapture.argv;
    expect(rerunArguments).toEqual(wrapperArgs);
    expect(rerunArguments).not.toContain(wrapper.command);

    const channels = {
      clientStdout: installOutput.text(),
      setupStdout: [setupOutput.text(), failedOutput.text()],
      stderr: errorOutput.text(),
      publicError: String(failedError),
      firstWrapperArguments: wrapper.args,
      rerunArguments,
      wrapperStderr: wrapperResult.stderr,
      configs: [source, renderedSource, verificationCapture.config],
      policies: [policy, verificationCapture.policy],
    };
    const observable = JSON.stringify(channels);
    for (const hidden of [
      lifecycleSentinel,
      installErrorSentinel,
      manifestSentinel,
      requestedSpecSentinel,
      verifierStderrSentinel,
      packageRoot,
      packageTarball,
      installSpec,
    ])
      expect(observable).not.toContain(hidden);
    const publicObservable = JSON.stringify({
      clientStdout: channels.clientStdout,
      setupStdout: channels.setupStdout,
      stderr: channels.stderr,
      publicError: channels.publicError,
      firstWrapperArguments: channels.firstWrapperArguments,
      rerunArguments: channels.rerunArguments,
      wrapperStderr: channels.wrapperStderr,
      policies: channels.policies,
    });
    expect(publicObservable).not.toContain(configEnvironmentValue);
    expect(publicObservable).not.toContain(configDataSentinel);
    expect(renderedSource).toContain(configEnvironmentValue);
    expect(wrapper.env?.API_KEY).toBe(configEnvironmentValue);
    const joinedArguments = [
      wrapper.command,
      ...wrapper.args,
      failingRestrictor.command,
      ...rerunArguments,
    ].join("\0");
    for (const hidden of [
      MASTER_KEY_FILE_ENV,
      installSpec,
      packageTarball,
      packageRoot,
      home,
      configPath,
      configEnvironmentValue,
      lifecycleSentinel,
      requestedSpecSentinel,
    ])
      expect(joinedArguments).not.toContain(hidden);
  } finally {
    restoreStderr();
    process.chdir(previousCwd);
    for (const [name, value] of pinnedEnvironment) restoreEnvironment(name, value);
  }
}, 30_000);

test("rolls back a remote OAuth config, policy, and profile when wrapper verification fails", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const keyPath = join(root, "oauth-master.key");
  await writeFile(keyPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
  await chmod(keyPath, 0o600);
  const upstream = await startRemoteAuthFixture({
    transport: "http",
    oauth: {
      expectedScope: "fixture-scope",
      challengeScope: "fixture-scope",
      expectedCallback: "claude",
    },
  });
  const configPath = join(root, ".mcp.json");
  const source = `${JSON.stringify(
    {
      unrelated: { keep: true },
      mcpServers: { remote: { type: "http", url: upstream.url } },
    },
    null,
    2,
  )}\n`;
  await writeFile(configPath, source);
  const previousHome = process.env.HOME;
  const previousUserProfile = process.env.USERPROFILE;
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  const output = capture();
  const error = capture();
  try {
    await expect(
      runSetup({
        input: Readable.from(["1\n", "1\n", "1\n", "yes\n", "yes\n", "1\n", "1\n", "yes\n"]),
        output: authorizationCapture(output),
        error,
        interactive: true,
        cwd: root,
        home,
        environment: {
          PATH: process.env.PATH,
          HOME: home,
          USERPROFILE: home,
          [MASTER_KEY_FILE_ENV]: keyPath,
        },
        restrictor: {
          command: process.execPath,
          argsPrefix: [compiledCli, "--unknown-verification-option"],
        },
      }),
    ).rejects.toThrow(/Wrapper verification failed/);

    expect(await readFile(configPath, "utf8")).toBe(source);
    await expect(
      readFile(join(root, ".mcp-restrictor", "policies", "claude", "remote.yaml")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readdir(join(home, ".mcp-restrictor", "oauth"))).resolves.toEqual([]);
    for (const secret of [
      await readFile(keyPath, "utf8"),
      "fixture-access-1",
      "fixture-refresh-1",
      "fixture-client-secret",
      "fixture-raw-challenge-body",
    ]) {
      expect(`${output.text()}\n${error.text()}`).not.toContain(secret);
    }
  } finally {
    restoreEnvironment("HOME", previousHome);
    restoreEnvironment("USERPROFILE", previousUserProfile);
    await upstream.close();
  }
});

test("installs one Manual OAuth profile into independent Claude, Codex, and OpenCode V1 destinations", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const keyPath = join(root, "oauth-master.key");
  const claudeConfig = join(root, ".mcp.json");
  const codexConfig = join(home, ".codex", "config.toml");
  const openCodeConfig = join(root, "opencode.jsonc");
  const keyBytes = randomBytes(32).toString("base64url");
  const upstream = await startRemoteAuthFixture({
    transport: "http",
    oauth: {
      expectedScope: "fixture-scope",
      challengeScope: "fixture-scope",
      expectedCallback: "manual",
    },
  });
  const restrictor = await executableRestrictor(join(root, "bin"));
  await mkdir(dirname(codexConfig), { recursive: true });
  await Promise.all([
    writeFile(keyPath, keyBytes, { mode: 0o600 }),
    writeFile(claudeConfig, '{"mcpServers": {}}\n'),
    writeFile(codexConfig, "# Codex user configuration\n"),
    writeFile(openCodeConfig, '{"mcp": {}}\n'),
  ]);
  await chmod(keyPath, 0o600);
  const environment: NodeJS.ProcessEnv = {
    PATH: testPath([dirname(restrictor.command), process.env.PATH ?? ""]),
    HOME: home,
    USERPROFILE: home,
    [MASTER_KEY_FILE_ENV]: keyPath,
  };
  const output = capture();
  const error = capture();
  const previousHome = process.env.HOME;
  const previousUserProfile = process.env.USERPROFILE;
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  try {
    await runSetup({
      input: Readable.from([
        "4\n",
        "remote\n",
        "http\n",
        `${upstream.url}\n`,
        "\n",
        "oauth\n",
        "\n",
        "fixture-scope\n",
        `${upstream.url}\n`,
        "\n",
        "\n",
        "\n",
        "\n",
        "2,3,4\n",
        "1\n",
        "1\n",
        "1\n",
        "1\n",
        "1\n",
        "1\n",
        "yes\n",
        "yes\n",
        "1\n",
        "1\n",
        "1\n",
        "1\n",
        "1\n",
        "1\n",
        "yes\n",
      ]),
      output: authorizationCapture(output),
      error,
      interactive: true,
      cwd: root,
      home,
      environment,
      restrictor,
    });

    const policySource =
      "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: allowed_tool\n  deny: []\n";
    const policyPaths = [
      join(root, ".mcp-restrictor", "policies", "claude", "remote.yaml"),
      join(home, ".mcp-restrictor", "policies", "codex", "remote.yaml"),
      join(root, ".mcp-restrictor", "policies", "opencode", "remote.yaml"),
    ];
    await expect(Promise.all(policyPaths.map((path) => readFile(path, "utf8")))).resolves.toEqual([
      policySource,
      policySource,
      policySource,
    ]);
    const profilePaths = (await readdir(join(home, ".mcp-restrictor", "oauth"))).filter((name) =>
      name.endsWith(".json"),
    );
    expect(profilePaths).toHaveLength(1);
    const profileSource = await readFile(
      join(home, ".mcp-restrictor", "oauth", profilePaths[0]!),
      "utf8",
    );
    const profile = JSON.parse(profileSource) as { profileId: string };
    expect(profile.profileId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    );

    const wrappers = await Promise.all([
      generatedWrapper(remoteCases[0], {
        root,
        output: "",
        environment,
      }),
      generatedWrapper(remoteCases[3], {
        root: home,
        output: "",
        environment,
      }),
      generatedWrapper(remoteCases[4], {
        root,
        output: "",
        environment,
      }),
    ]);
    const wrapperStderr: string[] = [];
    for (const wrapper of wrappers) {
      const profileIndex = wrapper.args.indexOf("--upstream-oauth-profile");
      expect(profileIndex).toBeGreaterThanOrEqual(0);
      expect(wrapper.args[profileIndex + 1]).toBe(profile.profileId);
      expect(wrapper.env?.[MASTER_KEY_FILE_ENV]).toBe(keyPath);
      const result = await exerciseGeneratedWrapper(wrapper, {
        expectedTools: ["allowed_tool"],
        allowedTool: "allowed_tool",
        deniedTool: "denied_tool",
      });
      wrapperStderr.push(result.stderr);
    }
    expect(upstream.authorizationRequests()).toBe(1);
    expect(upstream.tokenRequests()).toBe(1);

    const observable = [
      output.text(),
      error.text(),
      await readFile(claudeConfig, "utf8"),
      await readFile(codexConfig, "utf8"),
      await readFile(openCodeConfig, "utf8"),
      profileSource,
      ...wrappers.flatMap((wrapper) => [
        wrapper.command,
        ...wrapper.args,
        JSON.stringify(wrapper.env),
      ]),
      ...wrapperStderr,
      ...(await Promise.all(policyPaths.map((path) => readFile(path, "utf8")))),
    ].join("\n");
    for (const secret of [keyBytes, ...upstream.sensitiveValues()]) {
      expect(observable).not.toContain(secret);
    }
  } finally {
    restoreEnvironment("HOME", previousHome);
    restoreEnvironment("USERPROFILE", previousUserProfile);
    await upstream.close();
  }
}, 20_000);

test.each(installedManualCases)(
  "installs Manual $name",
  async (row) => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    const configRoot = row.wrapper.client === "codex" ? home : root;
    const configPath =
      row.wrapper.client === "claude"
        ? join(root, ".mcp.json")
        : row.wrapper.client === "codex"
          ? join(home, ".codex", "config.toml")
          : join(root, "opencode.jsonc");
    const keyPath = join(root, "oauth-master.key");
    const stdioSecret = "secret";
    const authorization = "Basic manual-installed-websocket-secret";
    const keyBytes = randomBytes(32).toString("base64url");
    const upstream =
      row.transport === "sse"
        ? await startRemoteAuthFixture({
            transport: "sse",
            oauth: {
              expectedScope: "fixture-scope",
              challengeScope: "fixture-scope",
              expectedCallback: "manual",
            },
          })
        : row.transport === "websocket"
          ? await startRemoteAuthFixture({
              transport: "websocket",
              requiredHeaders: { Authorization: authorization },
            })
          : undefined;
    const restrictor = await executableRestrictor(join(root, "bin"));
    if (row.wrapper.client === "claude") await writeFile(configPath, '{"mcpServers": {}}\n');
    else if (row.wrapper.client === "codex") {
      await mkdir(dirname(configPath), { recursive: true });
      await writeFile(configPath, "# Codex user configuration\n");
    } else await writeFile(configPath, '{"mcp": {"servers": {}}}\n');
    if (row.transport === "sse") {
      await writeFile(keyPath, keyBytes, { mode: 0o600 });
      await chmod(keyPath, 0o600);
    }
    const environment: NodeJS.ProcessEnv = {
      PATH: testPath([dirname(restrictor.command), process.env.PATH ?? ""]),
      HOME: home,
      USERPROFILE: home,
      ...(row.transport === "stdio" ? { API_KEY: stdioSecret } : {}),
      ...(row.transport === "websocket" ? { AUTHORIZATION: authorization } : {}),
      ...(row.transport === "sse" ? { [MASTER_KEY_FILE_ENV]: keyPath } : {}),
    };
    const answers =
      row.transport === "stdio"
        ? [
            "4\n",
            "remote\n",
            "stdio\n",
            `${process.execPath}\n`,
            `${JSON.stringify([fixture, root, "normal"])}\n`,
            "API_KEY\n",
            "2\n",
            "1\n",
            "1\n",
            "yes\n",
            "1\n",
            "1\n",
            "yes\n",
          ]
        : [
            "4\n",
            "remote\n",
            `${row.transport}\n`,
            `${upstream!.url}\n`,
            ...(row.transport === "websocket" ? ["Authorization=AUTHORIZATION\n"] : []),
            "\n",
            row.transport === "sse" ? "oauth\n" : "none\n",
            ...(row.transport === "sse"
              ? ["\n", "fixture-scope\n", `${upstream!.url}\n`, "\n", "\n", "\n", "\n"]
              : []),
            "2\n",
            "1\n",
            "1\n",
            "yes\n",
            ...(row.transport === "sse" ? ["yes\n"] : []),
            "1\n",
            "1\n",
            "yes\n",
          ];
    const output = capture();
    const error = capture();
    const previousCwd = process.cwd();
    const previousHome = process.env.HOME;
    const previousUserProfile = process.env.USERPROFILE;
    if (row.transport === "stdio") process.chdir(root);
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    try {
      await runSetup({
        input: Readable.from(answers),
        output: authorizationCapture(output),
        error,
        interactive: true,
        cwd: root,
        home,
        environment,
        restrictor,
      });
      expect(output.text()).toContain("Transport (stdio/http/sse/websocket): ");
      if (row.transport === "stdio") {
        expect(output.text()).toContain("Arguments as JSON array (empty for none): ");
        expect(output.text()).toContain(
          "Inherited environment variable names, comma-separated (empty for none): ",
        );
      } else {
        expect(output.text()).toContain("Header mapping HEADER=ENV_NAME (empty when done): ");
        expect(output.text()).toContain("Authentication (none/bearer/oauth): ");
      }
      const wrapper = await generatedWrapper(row.wrapper, {
        root: configRoot,
        output: "",
        environment,
      });
      const expectedTool = row.transport === "stdio" ? "read_file" : "allowed_tool";
      const wrapperResult = await exerciseGeneratedWrapper(wrapper, {
        expectedTools: [expectedTool],
        allowedTool: expectedTool,
        deniedTool: row.transport === "stdio" ? "write_file" : "denied_tool",
      });
      expect(output.text()).toContain(`Changed: ${JSON.stringify(configPath)}\n`);
      expect(output.text()).not.toMatch(/^(command|args|environment):/m);
      if (row.transport === "stdio") expect(wrapper.env?.API_KEY).toBe(stdioSecret);
      if (row.transport === "sse") {
        expect(wrapper.env?.[MASTER_KEY_FILE_ENV]).toBe(keyPath);
        expect(upstream?.authorizationRequests()).toBe(1);
        expect(upstream?.tokenRequests()).toBe(1);
      }
      if (row.transport === "websocket") expect(wrapper.env?.AUTHORIZATION).toBe(authorization);

      const policyPath = join(
        configRoot,
        ".mcp-restrictor",
        "policies",
        row.wrapper.client,
        "remote.yaml",
      );
      const profileIndex = wrapper.args.indexOf("--upstream-oauth-profile");
      if (row.transport === "sse") expect(profileIndex).toBeGreaterThanOrEqual(0);
      const profileSource =
        row.transport === "sse"
          ? await readFile(
              join(home, ".mcp-restrictor", "oauth", `${wrapper.args[profileIndex + 1]}.json`),
              "utf8",
            )
          : "";
      const observable = [
        output.text(),
        error.text(),
        await readFile(configPath, "utf8"),
        await readFile(policyPath, "utf8"),
        profileSource,
        wrapper.command,
        ...wrapper.args,
        wrapperResult.stderr,
      ].join("\n");
      for (const secret of [
        ...(row.transport === "stdio" ? [stdioSecret] : []),
        ...(row.transport === "websocket" ? [authorization] : []),
        ...(row.transport === "sse" ? [keyBytes, ...upstream!.sensitiveValues()] : []),
      ])
        expect(observable).not.toContain(secret);
    } finally {
      process.chdir(previousCwd);
      restoreEnvironment("HOME", previousHome);
      restoreEnvironment("USERPROFILE", previousUserProfile);
      await upstream?.close();
    }
  },
  20_000,
);

test("managed HTTP gateway runs setup, isolated routes, and selective Restore", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const claudeConfig = join(root, ".mcp.json");
  const codexConfig = join(home, ".codex", "config.toml");
  const claudeSource = '{"unrelated":"claude","mcpServers":{}}\n';
  const codexSource = '# Codex user configuration\nmodel = "gpt-5"\n';
  const secret = "managed-gateway-header-secret-79f0c2";
  const restrictor = await writeNodeLauncher(join(root, "bin"), compiledCli);
  const certificate = await readFile(certificatePath);
  const upstream = await startDualEraHttpFixture({
    tls: { cert: certificate, key: await readFile(privateKeyPath) },
    expectedAuthorization: secret,
    tools: ["read_file", "search", "delete_file"],
  });
  await mkdir(dirname(codexConfig), { recursive: true });
  await Promise.all([writeFile(claudeConfig, claudeSource), writeFile(codexConfig, codexSource)]);
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    PATH: testPath([dirname(restrictor), process.env.PATH ?? ""]),
    NODE_EXTRA_CA_CERTS: certificatePath,
    GATEWAY_E2E_HEADER: secret,
  };
  let firstGateway: BuiltGateway | undefined;
  let secondGateway: BuiltGateway | undefined;

  try {
    const setup = await runBuiltSetup(root, environment, [
      "1\n",
      "4\n",
      "gateway-e2e\n",
      "http\n",
      `${upstream.url}\n`,
      "Authorization=GATEWAY_E2E_HEADER\n",
      "\n",
      "none\n",
      "2,3\n",
      "2\n",
      "2\n",
      "1\n",
      "1\n",
      "1\n",
      "yes\n",
      "2\n",
      "1\n",
      "3\n",
      "1\n",
      "yes\n",
    ]);
    expect(setup.stdout).toContain("Start HTTP routes: mcp-restrictor run");

    const routeDirectory = join(home, ".mcp-restrictor", "routes");
    const routeNames = (await readdir(routeDirectory)).filter((name) => name.endsWith(".json"));
    expect(routeNames).toHaveLength(2);
    const installedRoutes = await Promise.all(
      routeNames.map(async (name) => {
        const path = join(routeDirectory, name);
        const source = await readFile(path, "utf8");
        return {
          path,
          source,
          definition: JSON.parse(source) as InstalledRoute,
        };
      }),
    );
    const routes = new Map(
      installedRoutes.map((route) => [route.definition.owner.adapterId, route] as const),
    );
    const claudeRoute = routes.get("claude")!;
    const codexRoute = routes.get("codex")!;
    expect(claudeRoute.definition.owner).toEqual({
      adapterId: "claude",
      scope: "project",
      configPath: claudeConfig,
      projectRoot: root,
      serverName: "gateway-e2e",
    });
    expect(codexRoute.definition.owner).toEqual({
      adapterId: "codex",
      scope: "user",
      configPath: codexConfig,
      projectRoot: root,
      serverName: "gateway-e2e",
    });
    const claudeUrl = claudeRoute.definition.listenUrl;
    const codexUrl = codexRoute.definition.listenUrl;
    expect(new URL(claudeUrl).origin).toBe("http://127.0.0.1:17319");
    expect(new URL(codexUrl).origin).toBe("http://127.0.0.1:17319");
    expect(new URL(claudeUrl).pathname).toMatch(/^\/mcp\/claude\/[0-9a-f]{64}$/);
    expect(new URL(codexUrl).pathname).toMatch(/^\/mcp\/codex\/[0-9a-f]{64}$/);
    expect(new URL(claudeUrl).pathname).not.toBe(new URL(codexUrl).pathname);

    const installedClaudeSource = await readFile(claudeConfig, "utf8");
    const installedCodexSource = await readFile(codexConfig, "utf8");
    expect(
      (JSON.parse(installedClaudeSource) as { mcpServers: Record<string, unknown> }).mcpServers[
        "gateway-e2e"
      ],
    ).toEqual({ type: "http", url: claudeUrl });
    expect(
      (parse(installedCodexSource) as { mcp_servers: Record<string, unknown> }).mcp_servers[
        "gateway-e2e"
      ],
    ).toEqual({ url: codexUrl });

    const claudePolicy = join(root, ".mcp-restrictor", "policies", "claude", "gateway-e2e.yaml");
    const codexPolicy = join(home, ".mcp-restrictor", "policies", "codex", "gateway-e2e.yaml");
    const policySources = await Promise.all([
      readFile(claudePolicy, "utf8"),
      readFile(codexPolicy, "utf8"),
    ]);
    expect(policySources[0]).toContain("name: read_file");
    expect(policySources[0]).not.toContain("name: search");
    expect(policySources[1]).toContain("name: search");
    expect(policySources[1]).not.toContain("name: read_file");
    expect(claudeRoute.definition.proxyArgs[1]).toBe(claudePolicy);
    expect(codexRoute.definition.proxyArgs[1]).toBe(codexPolicy);
    expect(claudeRoute.definition.proxyArgs).not.toEqual(codexRoute.definition.proxyArgs);
    expect((await lstat(routeDirectory)).mode & 0o7777).toBe(0o700);
    for (const path of [claudeRoute.path, codexRoute.path, claudePolicy, codexPolicy]) {
      expect((await lstat(path)).mode & 0o7777).toBe(0o600);
    }
    const restoreSourcesBefore = await readDirectorySources(
      join(home, ".mcp-restrictor", "restore"),
    );

    firstGateway = await startBuiltGateway(restrictor, root, environment, [claudeUrl, codexUrl]);
    const claudeTransport = new StreamableHTTPClientTransport(new URL(claudeUrl));
    const codexTransport = new StreamableHTTPClientTransport(new URL(codexUrl));
    const claude = new Client({ name: "claude-gateway-e2e", version: "1.0.0" });
    const codex = new Client({ name: "codex-gateway-e2e", version: "1.0.0" });
    let crossRouteBody = "";
    try {
      await Promise.all([claude.connect(claudeTransport), codex.connect(codexTransport)]);
      expect((await claude.listTools()).tools.map(({ name }) => name)).toEqual(["read_file"]);
      expect((await codex.listTools()).tools.map(({ name }) => name)).toEqual(["search"]);
      await expect(claude.callTool({ name: "search", arguments: {} })).rejects.toMatchObject({
        code: -32001,
      });
      await expect(codex.callTool({ name: "read_file", arguments: {} })).rejects.toMatchObject({
        code: -32001,
      });
      await expect(claude.callTool({ name: "read_file", arguments: {} })).resolves.toMatchObject({
        content: [{ type: "text", text: expect.stringMatching(/^upstream:read_file:/) }],
      });
      await expect(codex.callTool({ name: "search", arguments: {} })).resolves.toMatchObject({
        content: [{ type: "text", text: expect.stringMatching(/^upstream:search:/) }],
      });
      expect(claudeTransport.sessionId).toBeTruthy();
      const crossRoute = await fetch(codexUrl, {
        method: "POST",
        headers: {
          accept: "application/json, text/event-stream",
          "content-type": "application/json",
          "mcp-session-id": claudeTransport.sessionId!,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 91, method: "tools/list" }),
      });
      crossRouteBody = await crossRoute.text();
      expect(crossRoute.status).toBe(404);
    } finally {
      await Promise.all([claude.close().catch(() => {}), codex.close().catch(() => {})]);
    }
    await stopBuiltGateway(firstGateway);

    const restore = await runBuiltSetup(root, environment, ["2\n", "1\n", "yes\n"]);
    expect(restore.stdout).toContain(`Restored: ${JSON.stringify(claudeConfig)}`);
    const restoredClaudeSource = await readFile(claudeConfig, "utf8");
    expect(JSON.parse(restoredClaudeSource)).toEqual(JSON.parse(claudeSource));
    expect(restoredClaudeSource).not.toContain(claudeUrl);
    expect(await readFile(codexConfig, "utf8")).toBe(installedCodexSource);
    await expect(readFile(claudeRoute.path)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(claudePolicy)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(codexRoute.path, "utf8")).toBe(codexRoute.source);
    expect(await readFile(codexPolicy, "utf8")).toBe(policySources[1]);

    secondGateway = await startBuiltGateway(restrictor, root, environment, [codexUrl]);
    expect((await fetch(claudeUrl)).status).toBe(404);
    const restartedTransport = new StreamableHTTPClientTransport(new URL(codexUrl));
    const restartedCodex = new Client({ name: "codex-restarted-e2e", version: "1.0.0" });
    try {
      await restartedCodex.connect(restartedTransport);
      expect((await restartedCodex.listTools()).tools.map(({ name }) => name)).toEqual(["search"]);
      await expect(
        restartedCodex.callTool({ name: "search", arguments: {} }),
      ).resolves.toMatchObject({
        content: [{ type: "text", text: expect.stringMatching(/^upstream:search:/) }],
      });
    } finally {
      await restartedCodex.close().catch(() => {});
    }
    await stopBuiltGateway(secondGateway);

    const restoreSources = await readDirectorySources(join(home, ".mcp-restrictor", "restore"));
    const observable = [
      setup.stdout,
      setup.stderr,
      restore.stdout,
      restore.stderr,
      installedClaudeSource,
      installedCodexSource,
      claudeRoute.source,
      codexRoute.source,
      ...policySources,
      ...restoreSourcesBefore,
      ...restoreSources,
      restoredClaudeSource,
      firstGateway.stdout(),
      firstGateway.stderr(),
      firstGateway.child.spawnargs.join("\0"),
      secondGateway.stdout(),
      secondGateway.stderr(),
      secondGateway.child.spawnargs.join("\0"),
      crossRouteBody,
    ].join("\n");
    expect(observable).not.toContain(secret);
  } finally {
    if (firstGateway?.child.exitCode === null) firstGateway.child.kill("SIGKILL");
    if (secondGateway?.child.exitCode === null) secondGateway.child.kill("SIGKILL");
    await upstream.close();
  }
}, 20_000);

test("container generated presets survive a gateway restart and selective Restore", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const generatedRoot = join(home, ".mcp-restrictor", "generated");
  const claudeConfig = join(generatedRoot, "claude.json");
  const codexConfig = join(generatedRoot, "codex.toml");
  const secret = "generated-gateway-secret-27f0e1";
  const restrictor = await writeNodeLauncher(join(root, "bin"), compiledCli);
  const certificate = await readFile(certificatePath);
  const upstream = await startDualEraHttpFixture({
    tls: { cert: certificate, key: await readFile(privateKeyPath) },
    expectedAuthorization: secret,
    tools: ["read_file", "search", "delete_file"],
  });
  expect(new URL(upstream.url).protocol).toBe("https:");
  const environment: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    PATH: testPath([dirname(restrictor), process.env.PATH ?? ""]),
    NODE_EXTRA_CA_CERTS: certificatePath,
    GENERATED_GATEWAY_HEADER: secret,
  };
  let firstGateway: BuiltGateway | undefined;
  let restartedGateway: BuiltGateway | undefined;
  const sdk = new Client({ name: "generated-presets-e2e", version: "1.0.0" });

  const exercise = async (url: string, expectedTool: string): Promise<void> => {
    const transport = new StreamableHTTPClientTransport(new URL(url));
    await sdk.connect(transport);
    try {
      expect((await sdk.listTools()).tools.map(({ name }) => name)).toEqual([expectedTool]);
      await expect(sdk.callTool({ name: expectedTool, arguments: {} })).resolves.toMatchObject({
        content: [{ type: "text", text: expect.stringMatching(`^upstream:${expectedTool}:`) }],
      });
    } finally {
      await sdk.close();
    }
  };

  try {
    const setup = await runBuiltSetup(root, environment, [
      "1\n",
      "4\n",
      "generated-e2e\n",
      "http\n",
      `${upstream.url}\n`,
      "Authorization=GENERATED_GATEWAY_HEADER\n",
      "\n",
      "none\n",
      "2\n",
      "1,2\n",
      "1\n",
      "1\n",
      "1\n",
      "yes\n",
      "2\n",
      "1\n",
      "3\n",
      "1\n",
      "yes\n",
    ]);
    expect(setup.stdout).toContain("Start HTTP routes: mcp-restrictor run");
    expect(setup.stdout).toContain("Client preset fragment — Claude Code");
    expect(setup.stdout).toContain("Client preset fragment — Codex");
    expect(setup.stdout).toContain("Merge this entry into the host client configuration");

    const routeDirectory = join(home, ".mcp-restrictor", "routes");
    const installedRoutes = await Promise.all(
      (await readdir(routeDirectory))
        .filter((name) => name.endsWith(".json"))
        .map(async (name) => {
          const path = join(routeDirectory, name);
          const source = await readFile(path, "utf8");
          return { path, source, definition: JSON.parse(source) as InstalledRoute };
        }),
    );
    expect(installedRoutes).toHaveLength(2);
    const routes = new Map(
      installedRoutes.map((route) => [route.definition.owner.adapterId, route] as const),
    );
    const claudeRoute = routes.get("claude")!;
    const codexRoute = routes.get("codex")!;
    for (const [adapterId, configPath, route] of [
      ["claude", claudeConfig, claudeRoute],
      ["codex", codexConfig, codexRoute],
    ] as const) {
      expect(route.definition.owner).toEqual({
        adapterId,
        scope: "user",
        configPath,
        projectRoot: home,
        serverName: "generated-e2e",
      });
      expect(new URL(route.definition.listenUrl).origin).toBe("http://127.0.0.1:17319");
    }

    const claudeUrl = claudeRoute.definition.listenUrl;
    const codexUrl = codexRoute.definition.listenUrl;
    expect(new URL(claudeUrl).pathname).toMatch(/^\/mcp\/claude\/[0-9a-f]{64}$/);
    expect(new URL(codexUrl).pathname).toMatch(/^\/mcp\/codex\/[0-9a-f]{64}$/);
    expect(new URL(claudeUrl).pathname).not.toBe(new URL(codexUrl).pathname);
    expect(claudeRoute.source).toContain("GENERATED_GATEWAY_HEADER");
    expect(codexRoute.source).toContain("GENERATED_GATEWAY_HEADER");
    const claudeConfigSource = await readFile(claudeConfig, "utf8");
    const codexConfigSource = await readFile(codexConfig, "utf8");
    expect(
      (JSON.parse(claudeConfigSource) as { mcpServers: Record<string, unknown> }).mcpServers[
        "generated-e2e"
      ],
    ).toEqual({ type: "http", url: claudeUrl });
    expect(
      (parse(codexConfigSource) as { mcp_servers: Record<string, unknown> }).mcp_servers[
        "generated-e2e"
      ],
    ).toEqual({ url: codexUrl });

    const claudePolicy = join(generatedRoot, "policies", "claude", "generated-e2e.yaml");
    const codexPolicy = join(generatedRoot, "policies", "codex", "generated-e2e.yaml");
    const claudePolicySource = await readFile(claudePolicy, "utf8");
    const codexPolicySource = await readFile(codexPolicy, "utf8");
    expect(claudePolicySource).toContain("name: read_file");
    expect(claudePolicySource).not.toContain("name: search");
    expect(codexPolicySource).toContain("name: search");
    expect(codexPolicySource).not.toContain("name: read_file");
    for (const path of [
      generatedRoot,
      join(generatedRoot, "policies"),
      dirname(claudePolicy),
      dirname(codexPolicy),
    ]) {
      expect((await lstat(path)).mode & 0o7777).toBe(0o700);
    }
    for (const path of [
      claudeConfig,
      codexConfig,
      claudePolicy,
      codexPolicy,
      claudeRoute.path,
      codexRoute.path,
    ]) {
      expect((await lstat(path)).mode & 0o7777).toBe(0o600);
    }

    const restoreDirectory = join(home, ".mcp-restrictor", "restore");
    const restoreSourcesBefore = await readDirectorySources(restoreDirectory);
    expect(restoreSourcesBefore).toHaveLength(2);
    firstGateway = await startBuiltGateway(restrictor, root, environment, [claudeUrl, codexUrl]);
    expect(firstGateway.child.spawnargs.slice(-3)).toEqual(["run", "--bind", "0.0.0.0"]);
    await exercise(claudeUrl, "read_file");
    await exercise(codexUrl, "search");
    await stopBuiltGateway(firstGateway);

    const restore = await runBuiltSetup(root, environment, ["2\n", "1\n", "yes\n"]);
    expect(restore.stdout).toContain(`Restored: ${JSON.stringify(claudeConfig)}`);
    expect(restore.stdout).toContain(
      'Remove "generated-e2e" from the host Claude Code configuration if you pasted its generated fragment',
    );
    await expect(readFile(claudeConfig)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(claudePolicy)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(claudeRoute.path)).rejects.toMatchObject({ code: "ENOENT" });
    expect(await readFile(codexPolicy, "utf8")).toBe(codexPolicySource);
    expect(await readFile(codexRoute.path, "utf8")).toBe(codexRoute.source);
    expect(await readDirectorySources(restoreDirectory)).toHaveLength(1);

    restartedGateway = await startBuiltGateway(restrictor, root, environment, [codexUrl]);
    expect(restartedGateway.child.spawnargs.slice(-3)).toEqual(["run", "--bind", "0.0.0.0"]);
    expect((await fetch(claudeUrl)).status).toBe(404);
    await exercise(codexUrl, "search");
    await stopBuiltGateway(restartedGateway);

    const secretSurfaces = {
      output: [setup.stdout, setup.stderr, restore.stdout, restore.stderr],
      configs: [claudeConfigSource, codexConfigSource],
      routes: [claudeRoute.source, codexRoute.source],
      restoreState: [...restoreSourcesBefore, ...(await readDirectorySources(restoreDirectory))],
      policies: [claudePolicySource, codexPolicySource],
      logs: [
        firstGateway.stdout(),
        firstGateway.stderr(),
        restartedGateway.stdout(),
        restartedGateway.stderr(),
      ],
      argv: [firstGateway.child.spawnargs.join("\0"), restartedGateway.child.spawnargs.join("\0")],
    };
    for (const [surface, values] of Object.entries(secretSurfaces)) {
      expect(values.join("\n"), surface).not.toContain(secret);
    }
  } finally {
    await sdk.close().catch(() => {});
    if (firstGateway?.child.exitCode === null) firstGateway.child.kill("SIGKILL");
    if (restartedGateway?.child.exitCode === null) restartedGateway.child.kill("SIGKILL");
    await upstream.close();
  }
}, 20_000);

test("real CLI Restore removes an added Manual destination without reverting unrelated edits", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const configPath = join(root, ".mcp.json");
  const policyPath = join(root, ".mcp-restrictor", "policies", "claude", "remote.yaml");
  const source = '{"unrelated":"before","mcpServers":{}}\n';
  const restrictor = await executableRestrictor(join(root, "bin"));
  await writeFile(configPath, source);
  const environment: NodeJS.ProcessEnv = {
    PATH: testPath([dirname(restrictor.command), process.env.PATH ?? ""]),
    HOME: home,
    USERPROFILE: home,
    API_KEY: "secret",
  };
  const previousCwd = process.cwd();
  const previousHome = process.env.HOME;
  const previousUserProfile = process.env.USERPROFILE;
  process.chdir(root);
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  try {
    const installOutput = capture(true);
    await main({
      argv: ["node", "mcp-restrictor", "setup"],
      home,
      environment,
      input: ttyInput(
        `1\n4\nremote\nstdio\n${process.execPath}\n${JSON.stringify([fixture, root, "normal"])}\nAPI_KEY\n2\n1\n1\nyes\n1\n1\nyes\n`,
      ),
      output: installOutput,
    });
    const installed = JSON.parse(await readFile(configPath, "utf8")) as {
      unrelated: string;
      mcpServers: Record<string, GeneratedWrapper>;
    };
    expect(installOutput.text()).toContain(`Changed: ${JSON.stringify(configPath)}\n`);
    expect(installed.mcpServers.remote?.args).toContain("--policy");
    installed.unrelated = "after";
    await writeFile(configPath, `${JSON.stringify(installed, null, 2)}\n`);

    await main({
      argv: ["node", "mcp-restrictor", "setup"],
      home,
      environment,
      input: ttyInput("2\n1\nyes\n"),
      output: capture(true),
    });

    expect(JSON.parse(await readFile(configPath, "utf8"))).toEqual({
      unrelated: "after",
      mcpServers: {},
    });
    await expect(readFile(policyPath)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readdir(join(home, ".mcp-restrictor", "restore"))).resolves.toEqual([]);
  } finally {
    process.chdir(previousCwd);
    restoreEnvironment("HOME", previousHome);
    restoreEnvironment("USERPROFILE", previousUserProfile);
  }
}, 20_000);

test("rolls back every Manual destination when the third installed wrapper fails verification", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const configPaths = [
    join(root, ".mcp.json"),
    join(home, ".codex", "config.toml"),
    join(root, "opencode.jsonc"),
  ];
  const configSources = [
    '{"unrelated":"claude","mcpServers":{}}\n',
    "# Codex user configuration\n",
    '{"mcp":{"servers":{}},"unrelated":"opencode"}\n',
  ];
  const policyPaths = [
    join(root, ".mcp-restrictor", "policies", "claude", "remote.yaml"),
    join(home, ".mcp-restrictor", "policies", "codex", "remote.yaml"),
    join(root, ".mcp-restrictor", "policies", "opencode", "remote.yaml"),
  ];
  const verificationPath = join(root, "verification-capture.json");
  const counterPath = join(root, "verification-count");
  const failingDirectory = join(root, "failing-bin");
  const failingEntry = join(failingDirectory, "fail-third-verification.mjs");
  await mkdir(dirname(configPaths[1]!), { recursive: true });
  await Promise.all(configPaths.map((path, index) => writeFile(path, configSources[index]!)));
  await mkdir(failingDirectory, { recursive: true });
  await writeFile(
    failingEntry,
    `import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
let count = 0;
try { count = Number(readFileSync(${JSON.stringify(counterPath)}, 'utf8')); } catch {}
count += 1;
writeFileSync(${JSON.stringify(counterPath)}, String(count));
if (count < 3) {
  const result = spawnSync(process.execPath, [${JSON.stringify(compiledCli)}, ...process.argv.slice(2)], { stdio: 'inherit' });
  process.exitCode = result.status ?? 1;
} else {
  writeFileSync(${JSON.stringify(verificationPath)}, JSON.stringify({
    configs: ${JSON.stringify(configPaths)}.map((path) => readFileSync(path, 'utf8')),
    policies: ${JSON.stringify(policyPaths)}.map((path) => readFileSync(path, 'utf8')),
  }));
  process.exit(1);
}
`,
  );
  const failingRestrictor = { command: await writeNodeLauncher(failingDirectory, failingEntry) };
  const environment: NodeJS.ProcessEnv = {
    PATH: testPath([dirname(failingRestrictor.command), process.env.PATH ?? ""]),
    HOME: home,
    USERPROFILE: home,
    API_KEY: "secret",
  };
  const previousCwd = process.cwd();
  process.chdir(root);
  try {
    await expect(
      runSetup({
        input: Readable.from([
          "4\n",
          "remote\n",
          "stdio\n",
          `${process.execPath}\n`,
          `${JSON.stringify([fixture, root, "normal"])}\n`,
          "API_KEY\n",
          "2,3,4\n",
          "1\n",
          "1\n",
          "1\n",
          "1\n",
          "1\n",
          "1\n",
          "yes\n",
          "1\n",
          "1\n",
          "1\n",
          "1\n",
          "1\n",
          "1\n",
          "yes\n",
        ]),
        output: capture(),
        error: capture(),
        interactive: true,
        cwd: root,
        home,
        environment,
      }),
    ).rejects.toThrow(/Wrapper verification failed/);

    expect(await readFile(counterPath, "utf8")).toBe("3");
    const verification = JSON.parse(await readFile(verificationPath, "utf8")) as {
      configs: string[];
      policies: string[];
    };
    expect(verification.configs).toHaveLength(3);
    expect(verification.policies).toHaveLength(3);
    for (const config of verification.configs) expect(config).toContain(failingRestrictor.command);
    for (const policy of verification.policies) expect(policy).toContain("name: read_file");
    await expect(Promise.all(configPaths.map((path) => readFile(path, "utf8")))).resolves.toEqual(
      configSources,
    );
    await Promise.all(
      policyPaths.map((path) => expect(readFile(path)).rejects.toMatchObject({ code: "ENOENT" })),
    );
    await expect(readdir(join(home, ".mcp-restrictor", "restore"))).resolves.toEqual([]);
  } finally {
    process.chdir(previousCwd);
  }
}, 20_000);

async function remoteSetup(
  row: (typeof remoteCases)[number],
  options: { root: string; home: string; keyPath: string; url: string; headerValue: string },
): Promise<{ answers: string[]; environment: NodeJS.ProcessEnv }> {
  const environment: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: options.home,
    USERPROFILE: options.home,
    TOKEN: "other",
    HEADER_VALUE: options.headerValue,
    AUTHORIZATION: options.headerValue,
    ...(row.oauth ? { [MASTER_KEY_FILE_ENV]: options.keyPath } : {}),
  };
  if (row.client === "manual") {
    return {
      environment,
      answers: [
        "4\n",
        `${row.client}-${row.transport}\n`,
        `${row.transport}\n`,
        `${options.url}\n`,
        ...(row.header
          ? [`${row.header}=${row.header === "Authorization" ? "AUTHORIZATION" : "HEADER_VALUE"}\n`]
          : []),
        "\n",
        row.oauth ? "oauth\n" : "none\n",
        ...(row.oauth ? ["\n", "fixture-scope\n", `${options.url}\n`, "\n", "\n", "\n", "\n"] : []),
        "1\n",
        "1\n",
        "yes\n",
        ...(row.oauth ? ["yes\n"] : []),
        "1\n",
        "1\n",
        "yes\n",
      ],
    };
  }
  if (row.client === "opencode") {
    const callback = row.oauth ? await availableClaudeCallback() : undefined;
    const configPath = join(options.root, "opencode.jsonc");
    const remote =
      "schema" in row && row.schema === "v1"
        ? `{
      "type": "remote",
      "url": ${JSON.stringify(options.url)},
      "oauth": { "scope": "fixture-scope", "redirectUri": ${JSON.stringify(callback)} },
      "enabled": true,
      "timeout": 17000
    }`
        : `{
        "type": "remote",
        "url": ${JSON.stringify(options.url)},
        "oauth": false,
        "headers": { "X-OpenCode-Key": ${JSON.stringify(options.headerValue)} },
        "disabled": false,
        "codemode": true,
        "timeout": { "startup": 1, "catalog": 2, "execution": 3 }
      }`;
    const source =
      "schema" in row && row.schema === "v1"
        ? `{
  // opencode-v1-before
  "mcp": {
    "remote": ${remote},
${openCodeUnselectedBlock("    ")}  }
  // opencode-v1-after
}\n`
        : `{
  // opencode-v2-before
  "mcp": {
    "servers": {
      "remote": ${remote},
${openCodeUnselectedBlock("      ")}    }
  }
  // opencode-v2-after
}\n`;
    await writeFile(configPath, source);
    return {
      environment,
      answers: [
        "3\n",
        "1\n",
        "1\n",
        "yes\n",
        ...(row.oauth ? ["yes\n"] : []),
        "1\n",
        "1\n",
        "yes\n",
      ],
    };
  }
  if (row.client === "claude") {
    const configPath = join(options.root, ".mcp.json");
    const remote =
      row.transport === "http"
        ? {
            type: "http",
            url: options.url,
            headers: { "X-Claude-Key": options.headerValue },
            timeout: 17,
          }
        : row.transport === "sse"
          ? { type: "sse", url: options.url, alwaysLoad: true }
          : {
              type: "ws",
              url: options.url,
              headers: { "X-Claude-Key": "${TOKEN}" },
              timeout: 19,
            };
    await writeFile(
      configPath,
      `${JSON.stringify(
        {
          unrelated: { keep: "claude-unrelated" },
          mcpServers: {
            remote,
            unselected: {
              type: "stdio",
              command: process.execPath,
              args: [fixture, process.cwd(), "paginated"],
            },
          },
        },
        null,
        2,
      )}\n`,
    );
    return {
      environment,
      answers: [
        "1\n",
        "1\n",
        "1\n",
        "yes\n",
        ...(row.oauth ? ["yes\n"] : []),
        "1\n",
        "1\n",
        "yes\n",
      ],
    };
  }

  const configPath = join(options.root, ".codex", "config.toml");
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(
    configPath,
    `# codex-unowned-comment
model = "gpt-5"

[mcp_servers.remote]
url = ${JSON.stringify(options.url)}
http_headers = { X-Codex-Key = ${JSON.stringify(options.headerValue)} }
env_http_headers = { X-Codex-Env-Key = "CODEX_ENV_HEADER" }
scopes = ["codex-fallback"]
required = true

[mcp_servers.unselected]
command = ${JSON.stringify(process.execPath)}
args = []
tool_timeout_sec = 23
`,
  );
  environment.CODEX_ENV_HEADER = "codex-env-header-secret";
  return {
    environment,
    answers: ["2\n", "1\n", "1\n", "yes\n", "yes\n", "1\n", "1\n", "yes\n"],
  };
}

async function expectIsolation(
  row: (typeof remoteCases)[number],
  options: { root: string; home: string },
): Promise<void> {
  if (row.client === "manual") {
    await Promise.all([
      expect(readFile(join(options.home, ".claude.json"))).rejects.toMatchObject({
        code: "ENOENT",
      }),
      expect(readFile(join(options.root, ".mcp.json"))).rejects.toMatchObject({ code: "ENOENT" }),
      expect(readFile(join(options.root, ".codex", "config.toml"))).rejects.toMatchObject({
        code: "ENOENT",
      }),
      expect(readFile(join(options.home, ".codex", "config.toml"))).rejects.toMatchObject({
        code: "ENOENT",
      }),
    ]);
    return;
  }
  if (row.client === "opencode") {
    const source = await readFile(join(options.root, "opencode.jsonc"), "utf8");
    expect(markedOpenCodeBlock(source)).toBe(
      openCodeUnselectedBlock("schema" in row && row.schema === "v1" ? "    " : "      "),
    );
    const parsed = parseJsonc(source) as {
      mcp: Record<string, any> & { servers?: Record<string, any> };
    };
    const entry =
      "schema" in row && row.schema === "v1" ? parsed.mcp.remote : parsed.mcp.servers!.remote;
    expect(entry).toMatchObject({
      type: "local",
      ...("schema" in row && row.schema === "v1"
        ? { enabled: true, timeout: 17000 }
        : {
            disabled: false,
            codemode: true,
            timeout: { startup: 1, catalog: 2, execution: 3 },
          }),
    });
    await Promise.all([
      expect(readFile(join(options.home, ".claude.json"))).rejects.toMatchObject({
        code: "ENOENT",
      }),
      expect(readFile(join(options.root, ".mcp.json"))).rejects.toMatchObject({ code: "ENOENT" }),
      expect(readFile(join(options.root, ".codex/config.toml"))).rejects.toMatchObject({
        code: "ENOENT",
      }),
    ]);
    return;
  }
  if (row.client === "claude") {
    const parsed = JSON.parse(await readFile(join(options.root, ".mcp.json"), "utf8")) as {
      unrelated: unknown;
      mcpServers: Record<string, unknown>;
    };
    expect(parsed.unrelated).toEqual({ keep: "claude-unrelated" });
    expect(parsed.mcpServers.unselected).toEqual({
      type: "stdio",
      command: process.execPath,
      args: [fixture, process.cwd(), "paginated"],
    });
    expect(parsed.mcpServers.remote).toMatchObject({
      type: "stdio",
      ...(row.transport === "websocket"
        ? { timeout: 19 }
        : row.transport === "http"
          ? { timeout: 17 }
          : {}),
      ...(row.transport === "sse" ? { alwaysLoad: true } : {}),
    });
    return;
  }
  const source = await readFile(join(options.root, ".codex", "config.toml"), "utf8");
  expect(source).toContain('# codex-unowned-comment\nmodel = "gpt-5"');
  expect(
    source.endsWith(`[mcp_servers.unselected]
command = ${JSON.stringify(process.execPath)}
args = []
tool_timeout_sec = 23
`),
  ).toBe(true);
  const parsed = parse(source) as { mcp_servers: Record<string, Record<string, unknown>> };
  expect(parsed.mcp_servers.remote).toMatchObject({ command: process.execPath, required: true });
  expect(parsed.mcp_servers.unselected).toEqual({
    command: process.execPath,
    args: [],
    tool_timeout_sec: 23,
  });
}

async function generatedWrapper(
  row: { client: (typeof remoteCases)[number]["client"]; schema?: "v1" | "v2" },
  options: { root: string; output: string; environment: NodeJS.ProcessEnv },
): Promise<GeneratedWrapper> {
  if (row.client === "manual") {
    const command = outputValue(options.output, "command");
    const args = outputValue(options.output, "args");
    const renderedEnvironment = outputValue(options.output, "environment");
    if (
      typeof command !== "string" ||
      !Array.isArray(args) ||
      !args.every((value) => typeof value === "string") ||
      typeof renderedEnvironment !== "object" ||
      renderedEnvironment === null
    )
      throw new Error("invalid generated Manual wrapper");
    const spec = renderedEnvironment as { inherit?: string[]; set?: Record<string, string> };
    const env: Record<string, string> = { ...spec.set };
    for (const name of spec.inherit ?? []) {
      const value = options.environment[name];
      if (value === undefined) throw new Error(`missing generated environment ${name}`);
      env[name] = value;
    }
    return { command, args, env };
  }
  if (row.client === "opencode") {
    const parsed = parseJsonc(await readFile(join(options.root, "opencode.jsonc"), "utf8")) as {
      mcp: Record<string, any> & { servers?: Record<string, any> };
    };
    const entry = (row.schema === "v1" ? parsed.mcp.remote : parsed.mcp.servers!.remote) as {
      command: string[];
      environment?: Record<string, string>;
      cwd?: string;
    };
    const [command, ...args] = entry.command;
    if (!command) throw new Error("invalid generated OpenCode wrapper");
    const env = Object.fromEntries(
      Object.entries(entry.environment ?? {}).map(([name, value]) => {
        const match = /^\{env:([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(value);
        if (!match) return [name, value];
        const resolved = options.environment[match[1]!];
        if (resolved === undefined) throw new Error(`missing generated environment ${match[1]}`);
        return [name, resolved];
      }),
    );
    return { command, args, env, ...(entry.cwd ? { cwd: entry.cwd } : {}) };
  }
  if (row.client === "claude") {
    const parsed = JSON.parse(await readFile(join(options.root, ".mcp.json"), "utf8")) as {
      mcpServers: Record<string, GeneratedWrapper>;
    };
    const entry = parsed.mcpServers.remote!;
    const expansionEnvironment = {
      ...options.environment,
      CLAUDE_PROJECT_DIR: options.root,
    };
    return {
      command: expandClaude(entry.command, expansionEnvironment),
      args: entry.args.map((value) => expandClaude(value, expansionEnvironment)),
      env: Object.fromEntries(
        Object.entries(entry.env ?? {}).map(([name, value]) => [
          name,
          expandClaude(value, expansionEnvironment),
        ]),
      ),
      cwd: options.root,
    };
  }
  const parsed = parse(await readFile(join(options.root, ".codex", "config.toml"), "utf8")) as {
    mcp_servers: Record<string, GeneratedWrapper & { env_vars?: string[] }>;
  };
  const entry = parsed.mcp_servers.remote!;
  const env: Record<string, string> = { ...entry.env };
  for (const name of entry.env_vars ?? []) {
    const value = options.environment[name];
    if (value === undefined) throw new Error(`missing generated environment ${name}`);
    env[name] = value;
  }
  return { ...entry, env };
}

function outputValue(output: string, label: string): unknown {
  const line = output.split("\n").find((value) => value.startsWith(`${label}: `));
  if (!line) throw new Error(`missing generated ${label}`);
  return JSON.parse(line.slice(label.length + 2));
}

function openCodeUnselectedBlock(indent: string): string {
  return `${indent}// unselected-start
${indent}"unselected": {
${indent}  "type": "future",
${indent}  "nested": { "unknown": [1, { "keep": true }] }
${indent}}
${indent}// unselected-end
`;
}

function markedOpenCodeBlock(source: string): string {
  const start = source.indexOf("// unselected-start");
  const end = source.indexOf("// unselected-end") + "// unselected-end\n".length;
  if (start < 0 || end < "// unselected-end\n".length) throw new Error("missing OpenCode marker");
  const lineStart = source.lastIndexOf("\n", start) + 1;
  return source.slice(lineStart, end);
}

async function availableClaudeCallback(): Promise<string> {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("missing callback port");
  await new Promise<void>((resolveClose, reject) =>
    server.close((failure) => (failure ? reject(failure) : resolveClose())),
  );
  return `http://localhost:${address.port}/callback`;
}

async function executableRestrictor(root: string) {
  return {
    command: await writeNodeLauncher(root, compiledCli),
    argsPrefix: [] as string[],
  };
}

function authorizationCapture(output: Writable): Writable {
  let pending = "";
  return new Writable({
    write(chunk: Buffer | string, _encoding, callback) {
      const text = chunk.toString();
      output.write(text);
      pending += text;
      const match = /Open this URL to authorize:\n([^\n]+)\n/.exec(pending);
      if (match?.[1]) {
        pending = "";
        void fetch(match[1])
          .then((response) => response.text())
          .catch(() => undefined);
      }
      callback();
    },
  });
}

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
}

function externalAdapterModule(
  options: {
    client?: string;
    configName?: string;
    label?: string;
    serverNames?: readonly string[];
    verificationMarker?: string;
  } = {},
): string {
  return `import { existsSync, unlinkSync } from 'node:fs';
import { basename, join } from 'node:path';

const client = ${JSON.stringify(options.client ?? "fixture-client")};
const configName = ${JSON.stringify(options.configName ?? "fixture-client.json")};
const label = ${JSON.stringify(options.label ?? "Z Fixture Client")};
const serverNames = ${JSON.stringify(options.serverNames ?? ["fixture-server"])};
const verificationMarker = ${JSON.stringify(options.verificationMarker)};
let verificationArmed = false;

function replaceServer(source, name, value) {
  const current = JSON.parse(source).servers[name];
  const needle = JSON.stringify(current);
  const start = source.indexOf(needle);
  if (start < 0 || source.indexOf(needle, start + needle.length) >= 0) throw new Error('fixture selected entry is ambiguous');
  return source.slice(0, start) + JSON.stringify(value) + source.slice(start + needle.length);
}

export default {
  apiVersion: 1,
  id: client,
  label,
  async load(context, host) {
    const marker = verificationMarker && join(context.projectRoot, verificationMarker);
    if (marker && existsSync(marker)) {
      if (verificationArmed) {
        verificationArmed = false;
        unlinkSync(marker);
        throw new Error('verification failed');
      }
      verificationArmed = true;
    }
    const path = join(context.projectRoot, configName);
    const snapshot = await host.readConfig(path);
    if (!snapshot) return { configurations: [], unsupported: [] };
    const parsed = JSON.parse(snapshot.content);
    const servers = serverNames.map((name) => {
      const original = parsed.servers[name];
      const managed = basename(original.command).replace(/\\.(?:cmd|exe|bat|com)$/i, '') === 'mcp-restrictor';
      const separator = managed ? original.args.indexOf('--') : -1;
      const command = managed ? original.args[separator + 1] : original.command;
      const args = managed ? original.args.slice(separator + 2) : original.args;
      const envNames = managed
        ? original.args.flatMap((value, index) => value === '--upstream-env' ? [original.args[index + 1]] : [])
        : Object.keys(original.env ?? {});
      const policyIndex = managed ? original.args.indexOf('--policy') : -1;
      const source = { kind: 'stdio', command, args, envNames };
      return {
        client,
        scope: 'project',
        name,
        configPath: path,
        source,
        upstream: { kind: 'stdio', command, args, env: original.env ?? {} },
        wrapperEnvironment: original.env ? { env: original.env } : {},
        original,
        ...(policyIndex >= 0 ? { managedPolicyPath: original.args[policyIndex + 1] } : {}),
      };
    });
    return {
      configurations: [{
        snapshot,
        config: {
          client,
          scope: 'project',
          path,
          source: snapshot.content,
          servers,
          unsupported: [],
        },
      }],
      unsupported: [],
    };
  },
  render(config, replacements) {
    let source = config.source;
    for (const [name, replacement] of replacements) {
      const original = JSON.parse(source).servers[name];
      source = replaceServer(source, name, {
        command: replacement.command,
        args: replacement.args,
        ...(replacement.env ? { env: replacement.env } : {}),
        ...(replacement.cwd ? { cwd: replacement.cwd } : {}),
        ...(original.enabled === undefined ? {} : { enabled: original.enabled }),
      });
    }
    return source;
  },
  restore(config, entries) {
    let source = config.source;
    for (const entry of entries) {
      const current = JSON.parse(source).servers[entry.name];
      const installed = JSON.parse(entry.installedSource).servers[entry.name];
      if (JSON.stringify(current) !== JSON.stringify(installed)) throw new Error('managed entry changed');
      source = replaceServer(source, entry.name, JSON.parse(entry.originalSource).servers[entry.name]);
    }
    return source;
  },
};
`;
}

async function writeBrokenInstalledAdapter(home: string, requestedSpec: string): Promise<void> {
  const packageName = "fixture-broken-adapter";
  const prefix = join(clientPluginsRoot(home), packageName);
  await mkdir(prefix, { recursive: true, mode: 0o700 });
  await chmod(prefix, 0o700);
  await writeFile(
    join(prefix, ".mcp-restrictor-client-plugin.json"),
    JSON.stringify({
      packageName,
      version: "1.0.0",
      requestedSpec,
    }),
    { mode: 0o600 },
  );
  await chmod(join(prefix, ".mcp-restrictor-client-plugin.json"), 0o600);
}

async function writeFailingRestrictor(
  directory: string,
  options: {
    verificationPath: string;
    configPath: string;
    policyPath: string;
    stderrSentinel: string;
  },
): Promise<{ command: string }> {
  await mkdir(directory, { recursive: true });
  const entry = join(directory, "fail-verification.mjs");
  await writeFile(
    entry,
    `import { readFileSync, writeFileSync } from 'node:fs';
writeFileSync(${JSON.stringify(options.verificationPath)}, JSON.stringify({
  argv: process.argv.slice(2),
  config: readFileSync(${JSON.stringify(options.configPath)}, 'utf8'),
  policy: readFileSync(${JSON.stringify(options.policyPath)}, 'utf8'),
}));
process.stderr.write(${JSON.stringify(options.stderrSentinel)});
process.exit(1);
`,
  );
  return { command: await writeNodeLauncher(directory, entry) };
}

function npmTestCommand(
  platform: NodeJS.Platform,
  environment: NodeJS.ProcessEnv,
): { file: string; args: string[] } {
  if (platform !== "win32") return { file: "npm", args: [] };
  const configured = environment.npm_execpath;
  const npmCli =
    configured && basename(configured) === "npm-cli.js"
      ? configured
      : join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  return { file: process.execPath, args: [resolve(npmCli)] };
}

function testPath(entries: readonly string[]): string {
  return entries.filter(Boolean).join(delimiter);
}

function captureProcessStderr(output: Writable): () => void {
  const original = process.stderr.write;
  process.stderr.write = ((chunk: string | Uint8Array, ...args: unknown[]) => {
    output.write(chunk);
    const callback = args.find((value) => typeof value === "function") as (() => void) | undefined;
    callback?.();
    return true;
  }) as typeof process.stderr.write;
  return () => {
    process.stderr.write = original;
  };
}

function ttyInput(content: string): PassThrough & { isTTY: true } {
  const input = Object.assign(new PassThrough(), { isTTY: true as const });
  input.end(content);
  return input;
}

test("replaces a Claude project server with an enforceable compiled wrapper", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const configPath = join(root, ".mcp.json");
  const serverName = "project files";
  const environment = {
    PATH: process.env.PATH,
    NODE_BIN: process.execPath,
    FIXTURE: fixture,
    API_KEY: "secret",
    FORWARDED_VALUE: "forwarded-secret",
  };
  const source = `${JSON.stringify(
    {
      unrelated: { keep: true },
      mcpServers: {
        [serverName]: {
          type: "stdio",
          command: "${NODE_BIN}",
          args: [
            "${FIXTURE}",
            process.cwd(),
            "paginated",
            "${CLAUDE_PROJECT_DIR}",
            "${PROJECT_TAG:-project-default}",
            "${FORWARDED_VALUE}",
          ],
          env: {
            API_KEY: "${API_KEY}",
            PROJECT_DIR: "${CLAUDE_PROJECT_DIR}",
            PROJECT_TAG: "${PROJECT_TAG:-project-default}",
            FORWARDED: "${FORWARDED_VALUE}",
          },
        },
      },
    },
    null,
    2,
  )}\n`;
  await writeFile(configPath, source);
  const output = capture();

  await runSetup({
    input: Readable.from(["1\n", "all\n", "1\n", "yes\n", "1\n", "1\n", "yes\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment,
    restrictor: { command: process.execPath, argsPrefix: [compiledCli] },
  });

  const rendered = JSON.parse(await readFile(configPath, "utf8")) as {
    unrelated: { keep: boolean };
    mcpServers: Record<string, GeneratedWrapper>;
  };
  const entry = rendered.mcpServers[serverName]!;
  expect(rendered.unrelated).toEqual({ keep: true });
  expect(Object.keys(rendered.mcpServers)).toEqual([serverName]);
  expect(entry.command).toBe(process.execPath);
  expect(entry.args).toContain(compiledCli);
  expect(entry.env).toEqual({
    API_KEY: "${API_KEY}",
    PROJECT_DIR: "${CLAUDE_PROJECT_DIR}",
    PROJECT_TAG: "${PROJECT_TAG:-project-default}",
    FORWARDED: "${FORWARDED_VALUE}",
  });
  const separator = entry.args.indexOf("--");
  expect(entry.args.slice(separator + 1)).toEqual([
    "${NODE_BIN}",
    "${FIXTURE}",
    process.cwd(),
    "paginated",
    "${CLAUDE_PROJECT_DIR}",
    "${PROJECT_TAG:-project-default}",
    "${FORWARDED_VALUE}",
  ]);
  expect(
    await readFile(
      join(root, ".mcp-restrictor", "policies", "claude", "project%20files.yaml"),
      "utf8",
    ),
  ).toBe("version: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n  deny: []\n");
  expect(await readFile(backupPath(output.text(), configPath), "utf8")).toBe(source);

  const expansionEnvironment = { ...environment, CLAUDE_PROJECT_DIR: root };
  await exerciseGeneratedWrapper(
    {
      command: expandClaude(entry.command, expansionEnvironment),
      args: entry.args.map((argument) => expandClaude(argument, expansionEnvironment)),
      env: Object.fromEntries(
        Object.entries(entry.env ?? {}).map(([name, value]) => [
          name,
          expandClaude(value, expansionEnvironment),
        ]),
      ),
    },
    {
      expectedTools: ["read_file"],
      allowedTool: "read_file",
      deniedTool: "delete_file",
    },
  );
});

test("replaces a Codex project server without changing unrelated TOML bytes", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const serverCwd = join(root, "server-cwd");
  const configPath = join(root, ".codex", "config.toml");
  const prefix = '# keep this comment\nmodel = "gpt-5"\n\n';
  const suffix = '\n[profiles.keep]\nmodel = "gpt-5-mini"\n';
  const source = `${prefix}[mcp_servers.files]\ncommand = ${JSON.stringify(process.execPath)}\nargs = ${JSON.stringify(
    [fixture, "cwd-from-project-root", "paginated", root, "codex-project", "forwarded-secret"],
  )}\ncwd = ${JSON.stringify(serverCwd)}\nenv_vars = ["FORWARDED"]\n\n[mcp_servers.files.env]\nAPI_KEY = "secret"\nPROJECT_DIR = ${JSON.stringify(root)}\nPROJECT_TAG = "codex-project"\n${suffix}`;
  await Promise.all([
    mkdir(dirname(configPath), { recursive: true }),
    mkdir(serverCwd, { recursive: true }),
  ]);
  await writeFile(configPath, source);
  const environment: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    FORWARDED: "forwarded-secret",
  };

  await runSetup({
    input: Readable.from(["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"]),
    output: capture(),
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment,
    restrictor: { command: process.execPath, argsPrefix: [compiledCli] },
  });

  const renderedSource = await readFile(configPath, "utf8");
  expect(renderedSource.startsWith(prefix)).toBe(true);
  expect(renderedSource.endsWith(suffix)).toBe(true);
  const rendered = parse(renderedSource) as {
    mcp_servers: Record<string, GeneratedWrapper & { env_vars?: string[] }>;
  };
  const entry = rendered.mcp_servers.files!;
  expect(Object.keys(rendered.mcp_servers)).toEqual(["files"]);
  expect(entry.command).toBe(process.execPath);
  expect(entry.args).toContain(compiledCli);
  expect(entry.env).toEqual({
    API_KEY: "secret",
    PROJECT_DIR: root,
    PROJECT_TAG: "codex-project",
  });
  expect(entry.env_vars).toEqual(["FORWARDED"]);
  const separator = entry.args.indexOf("--");
  expect(entry.args.slice(separator + 1)).toEqual([
    process.execPath,
    fixture,
    "cwd-from-project-root",
    "paginated",
    root,
    "codex-project",
    "forwarded-secret",
  ]);
  expect(entry.cwd).toBe(root);
  const cwdOption = entry.args.indexOf("--upstream-cwd");
  expect(entry.args.slice(cwdOption, cwdOption + 2)).toEqual(["--upstream-cwd", serverCwd]);
  expect(entry.args.filter((argument) => argument === serverCwd)).toHaveLength(1);
  expect(
    await readFile(join(root, ".mcp-restrictor", "policies", "codex", "files.yaml"), "utf8"),
  ).toBe(
    "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n    - name: write_file\n  deny: []\n",
  );

  const env: Record<string, string> = { ...entry.env };
  for (const name of entry.env_vars ?? []) {
    const value = environment[name];
    if (value === undefined) throw new Error(`Missing test environment ${name}`);
    env[name] = value;
  }
  await exerciseGeneratedWrapper(
    {
      command: entry.command,
      args: entry.args,
      env,
      ...(entry.cwd !== undefined ? { cwd: entry.cwd } : {}),
    },
    {
      expectedTools: ["write_file", "read_file"],
      allowedTool: "write_file",
      deniedTool: "delete_file",
    },
  );
});

test("configures Claude and Codex together through one preview and transaction", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const claudeConfig = join(root, ".mcp.json");
  const codexConfig = join(root, ".codex", "config.toml");
  const claudeSource = `${JSON.stringify(
    {
      mcpServers: {
        files: {
          command: process.execPath,
          args: [fixture, process.cwd(), "normal"],
          env: { API_KEY: "secret" },
        },
      },
    },
    null,
    2,
  )}\n`;
  const codexSource = `[mcp_servers.files]\ncommand = ${JSON.stringify(process.execPath)}\nargs = ${JSON.stringify([fixture, root, "normal"])}\ncwd = ${JSON.stringify(root)}\n\n[mcp_servers.files.env]\nAPI_KEY = "secret"\n`;
  await mkdir(dirname(codexConfig), { recursive: true });
  await Promise.all([writeFile(claudeConfig, claudeSource), writeFile(codexConfig, codexSource)]);
  const output = capture();

  await runSetup({
    input: Readable.from([
      "all\n",
      "all\n",
      "1\n",
      "yes\n",
      "all\n",
      "1\n",
      "1\n",
      "yes\n",
      "all\n",
      "1\n",
      "yes\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [compiledCli] },
  });

  expect(output.text()).toContain("Claude Code / files");
  expect(output.text()).toContain("Codex / files");
  expect(output.text().match(/Preview:/g)).toHaveLength(1);
  expect(output.text().match(/Apply these changes/g)).toHaveLength(1);
  expect(await readFile(claudeConfig, "utf8")).toContain(compiledCli);
  expect(await readFile(codexConfig, "utf8")).toContain(compiledCli);
  expect(
    await readFile(join(root, ".mcp-restrictor", "policies", "claude", "files.yaml"), "utf8"),
  ).toContain("name: read_file");
  expect(
    await readFile(join(root, ".mcp-restrictor", "policies", "codex", "files.yaml"), "utf8"),
  ).toContain("name: read_file");
});

test("real CLI selectively restores setup entries and rolls back failed verification", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const packageRoot = join(root, "fixture-selective-restore-adapter");
  const configPath = join(root, "selective-client.json");
  const markerPath = join(root, "fail-restore-verification");
  const firstPolicy = join(root, ".mcp-restrictor/policies/fixture-selective/first.yaml");
  const secondPolicy = join(root, ".mcp-restrictor/policies/fixture-selective/second.yaml");
  const firstNative = {
    command: process.execPath,
    args: [fixture, root, "normal"],
    env: { API_KEY: "secret", SERVER_NAME: "first" },
  };
  const secondNative = {
    command: process.execPath,
    args: [fixture, root, "normal"],
    env: { API_KEY: "secret", SERVER_NAME: "second" },
  };
  const source = `{"unrelated":"before","servers":{"first":${JSON.stringify(firstNative)},"second":${JSON.stringify(secondNative)}},"tail":"keep"}\n`;
  const masterKeyPath = join(root, "oauth-master.key");
  const masterKeySource = randomBytes(32).toString("base64url");
  const oauthSentinel = join(home, ".mcp-restrictor/oauth/retained.json");
  const backupSentinel = join(home, ".mcp-restrictor/backups/retained.txt");
  await Promise.all([
    mkdir(packageRoot, { recursive: true }),
    mkdir(dirname(configPath), { recursive: true }),
    mkdir(dirname(oauthSentinel), { recursive: true, mode: 0o700 }),
    mkdir(dirname(backupSentinel), { recursive: true, mode: 0o700 }),
  ]);
  await Promise.all([
    writeFile(configPath, source),
    writeFile(masterKeyPath, masterKeySource, { mode: 0o600 }),
    writeFile(oauthSentinel, "oauth-retained", { mode: 0o600 }),
    writeFile(backupSentinel, "backup-retained", { mode: 0o600 }),
    writeFile(
      join(packageRoot, "package.json"),
      JSON.stringify({
        name: "fixture-selective-restore-adapter",
        version: "1.0.0",
        type: "module",
        mcpRestrictor: { clientAdapter: "./index.js", apiVersion: 1 },
      }),
    ),
    writeFile(
      join(packageRoot, "index.js"),
      externalAdapterModule({
        client: "fixture-selective",
        configName: "selective-client.json",
        label: "Z Selective Restore Fixture",
        serverNames: ["first", "second"],
        verificationMarker: "fail-restore-verification",
      }),
    ),
  ]);
  await expect(readFile(firstPolicy)).rejects.toMatchObject({ code: "ENOENT" });

  const npmEnvironment = { ...process.env, npm_config_cache: join(root, "npm-cache") };
  const npm = npmTestCommand(process.platform, npmEnvironment);
  await runFile(
    npm.file,
    [...npm.args, "pack", "--ignore-scripts", "--pack-destination", root, packageRoot],
    { cwd: root, env: npmEnvironment, shell: false },
  );
  const tarball = join(root, "fixture-selective-restore-adapter-1.0.0.tgz");
  const restrictor = await executableRestrictor(join(root, "bin"));
  const environment: NodeJS.ProcessEnv = {
    ...npmEnvironment,
    PATH: testPath([dirname(restrictor.command), process.env.PATH ?? ""]),
    ...(process.platform === "win32"
      ? { PATHEXT: process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD", npm_execpath: npm.args[0] }
      : {}),
    [MASTER_KEY_FILE_ENV]: masterKeyPath,
  };

  const previousCwd = process.cwd();
  const pinnedEnvironment = new Map<string, string | undefined>();
  for (const name of [
    "HOME",
    "USERPROFILE",
    "npm_config_audit",
    "npm_config_cache",
    "npm_config_fund",
    "npm_config_update_notifier",
  ])
    pinnedEnvironment.set(name, process.env[name]);
  process.chdir(root);
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  process.env.npm_config_audit = "false";
  process.env.npm_config_cache = join(root, "npm-cache");
  process.env.npm_config_fund = "false";
  process.env.npm_config_update_notifier = "false";

  try {
    await main({
      argv: ["node", "mcp-restrictor", "client", "install", `file:${tarball}`],
      home,
      environment,
      input: ttyInput("yes\n"),
      output: capture(),
    });
    await main({
      argv: ["node", "mcp-restrictor", "setup"],
      home,
      environment,
      input: ttyInput("1\n4\nall\n1\nyes\nall\n1\n1\nyes\nall\n1\nyes\n"),
      output: capture(true),
    });

    const pluginsBeforeCancelledRestore = await snapshotTree(clientPluginsRoot(home));
    await expect(runFreshRestoreToEof(home, environment, root)).resolves.toContain(
      "Restore cancelled.",
    );
    expect(await snapshotTree(clientPluginsRoot(home))).toEqual(pluginsBeforeCancelledRestore);

    const stateDirectory = join(home, ".mcp-restrictor/restore");
    const stateEntries = (await readdir(stateDirectory)).filter((name) => name.endsWith(".json"));
    expect(stateEntries).toHaveLength(1);
    const statePath = join(stateDirectory, stateEntries[0]!);
    expect(JSON.parse(await readFile(statePath, "utf8")).servers).toHaveLength(2);
    const installedSource = await readFile(configPath, "utf8");
    const installed = JSON.parse(installedSource) as {
      unrelated: string;
      servers: Record<string, GeneratedWrapper>;
    };
    expect(installed.servers.first!.args).toContain("--policy");
    expect(installed.servers.second!.args).toContain("--policy");
    const editedInstalledSource = installedSource.replace(
      '"unrelated":"before"',
      '"unrelated":"after"',
    );
    await writeFile(configPath, editedInstalledSource);

    await main({
      argv: ["node", "mcp-restrictor", "setup"],
      home,
      environment,
      input: ttyInput("2\n1\nyes\n"),
      output: capture(true),
    });

    const selectivelyRestoredSource = await readFile(configPath, "utf8");
    const expectedSelectivelyRestoredSource = editedInstalledSource.replace(
      JSON.stringify(installed.servers.first),
      JSON.stringify(firstNative),
    );
    expect(selectivelyRestoredSource).toBe(expectedSelectivelyRestoredSource);
    const selectivelyRestored = JSON.parse(selectivelyRestoredSource) as {
      unrelated: string;
      servers: Record<string, GeneratedWrapper>;
    };
    expect(selectivelyRestored.unrelated).toBe("after");
    expect(selectivelyRestored.servers.first).toEqual(firstNative);
    expect(selectivelyRestored.servers.second!.args).toContain("--policy");
    await expect(readFile(firstPolicy)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(secondPolicy, "utf8")).resolves.toContain("name: read_file");
    expect(
      JSON.parse(await readFile(statePath, "utf8")).servers.map(
        ({ name }: { name: string }) => name,
      ),
    ).toEqual(["second"]);
    await exerciseGeneratedWrapper(selectivelyRestored.servers.second!, {
      expectedTools: ["read_file"],
      allowedTool: "read_file",
      deniedTool: "delete_file",
    });
    await expect(readFile(oauthSentinel, "utf8")).resolves.toBe("oauth-retained");
    await expect(readFile(masterKeyPath, "utf8")).resolves.toBe(masterKeySource);
    await expect(readFile(backupSentinel, "utf8")).resolves.toBe("backup-retained");

    const beforeRollback = {
      config: await readFile(configPath, "utf8"),
      policy: await readFile(secondPolicy, "utf8"),
      state: await readFile(statePath, "utf8"),
    };
    await writeFile(markerPath, "fail next verification");
    await expect(
      main({
        argv: ["node", "mcp-restrictor", "setup"],
        home,
        environment,
        input: ttyInput("2\n1\nyes\n"),
        output: capture(true),
      }),
    ).rejects.toThrow("MCP restore verification failed");
    await expect(readFile(configPath, "utf8")).resolves.toBe(beforeRollback.config);
    await expect(readFile(secondPolicy, "utf8")).resolves.toBe(beforeRollback.policy);
    await expect(readFile(statePath, "utf8")).resolves.toBe(beforeRollback.state);
    await expect(readFile(oauthSentinel, "utf8")).resolves.toBe("oauth-retained");
    await expect(readFile(masterKeyPath, "utf8")).resolves.toBe(masterKeySource);
    await expect(readFile(backupSentinel, "utf8")).resolves.toBe("backup-retained");
  } finally {
    process.chdir(previousCwd);
    for (const [name, value] of pinnedEnvironment) restoreEnvironment(name, value);
  }
}, 20_000);

type InstalledRoute = {
  version: 1;
  owner: {
    adapterId: string;
    scope: "user" | "project";
    configPath: string;
    projectRoot: string;
    serverName: string;
  };
  listenUrl: string;
  proxyArgs: string[];
  environment: { set: Record<string, string> };
};

type BuiltGateway = {
  child: ChildProcessWithoutNullStreams;
  stdout(): string;
  stderr(): string;
};

async function runBuiltSetup(
  cwd: string,
  environment: NodeJS.ProcessEnv,
  answers: readonly string[],
): Promise<{ stdout: string; stderr: string }> {
  const source = `import { Readable, Writable } from 'node:stream';
const { main } = await import(process.argv[1]);
const input = Object.assign(Readable.from([JSON.parse(process.argv[2]).join('')]), { isTTY: true });
const output = Object.assign(new Writable({ write(chunk, _encoding, callback) { process.stdout.write(chunk, callback); } }), { isTTY: true });
await main({ argv: ['node', 'mcp-restrictor', 'setup'], home: process.env.HOME, environment: process.env, input, output });`;
  const result = await runFile(
    process.execPath,
    [
      "--input-type=module",
      "--eval",
      source,
      pathToFileURL(compiledCli).href,
      JSON.stringify(answers),
    ],
    { cwd, env: environment, encoding: "utf8" },
  );
  return { stdout: result.stdout, stderr: result.stderr };
}

async function startBuiltGateway(
  command: string,
  cwd: string,
  environment: NodeJS.ProcessEnv,
  routeUrls: readonly string[],
): Promise<BuiltGateway> {
  const child = spawn(command, ["run", "--bind", "0.0.0.0"], {
    cwd,
    env: environment,
    stdio: "pipe",
  });
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  child.stdin.end();
  await waitForGatewayOutput(child, stderr, routeUrls);
  return {
    child,
    stdout: () => Buffer.concat(stdout).toString("utf8"),
    stderr: () => Buffer.concat(stderr).toString("utf8"),
  };
}

async function waitForGatewayOutput(
  child: ChildProcessWithoutNullStreams,
  stderr: readonly Buffer[],
  values: readonly string[],
): Promise<void> {
  await new Promise<void>((resolveReady, reject) => {
    const cleanup = () => {
      child.stderr.off("data", check);
      child.off("exit", onExit);
    };
    const check = () => {
      const diagnostics = Buffer.concat(stderr).toString("utf8");
      if (!values.every((value) => diagnostics.includes(value))) return;
      cleanup();
      resolveReady();
    };
    const onExit = (code: number | null) => {
      cleanup();
      reject(
        new Error(
          `mcp-restrictor run exited before readiness (code ${code})\n${Buffer.concat(stderr).toString("utf8")}`,
        ),
      );
    };
    child.stderr.on("data", check);
    child.once("exit", onExit);
    check();
  });
}

async function stopBuiltGateway(gateway: BuiltGateway): Promise<void> {
  if (gateway.child.exitCode === null) {
    const exited = once(gateway.child, "exit");
    gateway.child.kill("SIGTERM");
    await exited;
  }
  if (gateway.child.exitCode !== 0) {
    throw new Error(
      `mcp-restrictor run exited with ${gateway.child.exitCode}\n${gateway.stderr()}`,
    );
  }
}

async function readDirectorySources(directory: string): Promise<string[]> {
  const names = await readdir(directory);
  return Promise.all(names.sort().map((name) => readFile(join(directory, name), "utf8")));
}

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-e2e-")));
  temporaryDirectories.push(path);
  return path;
}

async function runFreshRestoreToEof(
  home: string,
  environment: NodeJS.ProcessEnv,
  cwd: string,
): Promise<string> {
  const childSource = `import { Readable, Writable } from 'node:stream';
const { main } = await import(process.argv[1]);
const input = Object.assign(Readable.from(['2\\n']), { isTTY: true });
const output = Object.assign(new Writable({ write(chunk, _encoding, callback) { process.stdout.write(chunk, callback); } }), { isTTY: true });
await main({ argv: ['node', 'mcp-restrictor', 'setup'], home: process.argv[2], environment: process.env, input, output });`;
  const { stdout } = await runFile(
    process.execPath,
    ["--input-type=module", "--eval", childSource, pathToFileURL(compiledCli).href, home],
    { cwd, env: environment, shell: false },
  );
  return stdout;
}

function expandClaude(value: string, environment: NodeJS.ProcessEnv): string {
  return value.replace(
    /\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}/g,
    (literal: string, name: string, fallback: string | undefined) => {
      const expanded = environment[name];
      if (fallback === undefined) return expanded === undefined ? literal : expanded;
      return expanded === undefined || expanded === "" ? fallback : expanded;
    },
  );
}

function backupPath(output: string, configPath: string): string {
  const prefix = `Restore ${JSON.stringify(configPath)} from `;
  const line = output.split("\n").find((value) => value.startsWith(prefix));
  if (!line) throw new Error("Missing restore instruction");
  return JSON.parse(line.slice(prefix.length)) as string;
}

function capture(tty = false): Writable & { isTTY?: boolean; text(): string } {
  const chunks: Buffer[] = [];
  const stream = new Writable({
    write(chunk: Buffer | string, _encoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  }) as Writable & { isTTY?: boolean; text(): string };
  if (tty) stream.isTTY = true;
  stream.text = () => Buffer.concat(chunks).toString("utf8");
  return stream;
}
