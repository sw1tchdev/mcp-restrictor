import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import {
  link,
  chmod,
  lstat,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { basename, delimiter, dirname, join, resolve } from "node:path";
import { PassThrough, Readable, Writable } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parse } from "smol-toml";
import { afterEach, expect, test, vi } from "vitest";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import type { UpstreamConfig } from "@mcp-restrictor/transports";
import { defineClientAdapter, type ClientAdapter } from "../src/client-adapter.ts";
import {
  MASTER_KEY_FILE_ENV,
  oauthProfilePath,
  readOAuthProfileSnapshot,
  writeOAuthProfile,
  type OAuthProfile,
} from "../src/oauth/storage.ts";
import { loginOAuthProfile } from "../src/oauth/login.ts";
import { loadRoutes, routePath, routeUrl, serializeRoute } from "../src/routes.ts";
import { runSetup } from "../src/setup/index.ts";
import { claudeAdapter } from "../src/setup/claude.ts";
import { codexAdapter } from "../src/setup/codex.ts";
import { SetupInteraction } from "../src/setup/interaction.ts";
import { opencodeAdapter } from "../src/setup/opencode.ts";
import {
  policyFingerprint,
  readRestoreState,
  restoreStatePath,
  serializeRestoreState,
} from "../src/setup/restore/state.ts";
import type { ServerCandidate } from "../src/setup/wrapper.ts";

const setupFakes = vi.hoisted(() => ({
  discover: undefined as undefined | ((...args: any[]) => Promise<string[]>),
  login: undefined as undefined | ((options: any) => Promise<any>),
}));

const setupFileOperations = vi.hoisted(() => ({
  failRenameFor: undefined as string | undefined,
  reportedModeForRoute: undefined as string | undefined,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  const matchesRoute = (path: string | Buffer | URL, target: string | undefined): boolean => {
    if (!target) return false;
    const value = String(path);
    const slash = target.lastIndexOf("/");
    const temporaryPrefix = `${target.slice(0, slash + 1)}.${target.slice(slash + 1)}.`;
    return value === target || value.startsWith(temporaryPrefix);
  };
  return {
    ...actual,
    open: async (...args: Parameters<typeof actual.open>) => {
      const handle = await actual.open(...args);
      if (matchesRoute(args[0], setupFileOperations.reportedModeForRoute)) {
        const stat = handle.stat.bind(handle);
        handle.stat = (async () => {
          const result = await stat();
          Object.defineProperty(result, "mode", {
            value: (result.mode & ~0o7777) | 0o666,
          });
          return result;
        }) as typeof handle.stat;
      }
      return handle;
    },
    rename: async (...args: Parameters<typeof actual.rename>) => {
      if (String(args[1]) === setupFileOperations.failRenameFor) {
        throw new Error("injected Manual route write failure");
      }
      return actual.rename(...args);
    },
  };
});

vi.mock("@mcp-restrictor/transports", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@mcp-restrictor/transports")>();
  return {
    ...actual,
    discoverToolNames: (...args: Parameters<typeof actual.discoverToolNames>) =>
      setupFakes.discover ? setupFakes.discover(...args) : actual.discoverToolNames(...args),
  };
});

vi.mock("../src/oauth/login.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/oauth/login.ts")>();
  return {
    ...actual,
    loginOAuthProfile: (...args: Parameters<typeof actual.loginOAuthProfile>) =>
      setupFakes.login ? setupFakes.login(...args) : actual.loginOAuthProfile(...args),
  };
});

const testDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(testDirectory, "../../..");
const cli = resolve(projectRoot, "packages/cli/dist/index.js");
const upstream = resolve(
  projectRoot,
  "packages/transports/test/fixtures/config-sensitive-upstream.mjs",
);
const temporaryDirectories: string[] = [];

afterEach(async () => {
  setupFakes.discover = undefined;
  setupFakes.login = undefined;
  setupFileOperations.failRenameFor = undefined;
  setupFileOperations.reportedModeForRoute = undefined;
  vi.unstubAllGlobals();
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { force: true, recursive: true })),
  );
});

test("completes managed setup when Enter confirms Connect and Apply", async () => {
  const root = await temporaryDirectory();
  const configPath = join(root, ".codex", "config.toml");
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(
    configPath,
    `[mcp_servers.files]\ncommand = ${JSON.stringify(process.execPath)}\nargs = [${JSON.stringify(upstream)}, ${JSON.stringify(root)}]\ncwd = ${JSON.stringify(root)}\n\n[mcp_servers.files.env]\nAPI_KEY = "secret"\n`,
  );
  const output = capture();

  await runSetup({
    input: Readable.from(["2\n", "all\n", "1\n", "\n", "all\n", "1\n", "\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(await readFile(configPath, "utf8")).toContain(cli);
  expect(
    await readFile(join(root, ".mcp-restrictor", "policies", "codex", "files.yaml"), "utf8"),
  ).toContain("name: read_file");
  expect(output.text()).toContain("Setup complete");
  expect(output.text()).not.toContain("secret");
});

test("runs the sample multi-server flow with escaped untrusted output and grouped rendering", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const fixture = await writeUpstreamFixture(root);
  const configPath = join(root, ".codex", "config.toml");
  const controlledServer = "second\u001b\r\nname";
  const controlledTools = ["alpha\u001btool", "middle\rtool", "zeta\ntool"];
  const source = [
    stdioServer("first", fixture, controlledTools, {
      env: { CONFIGURED_SECRET: "must-never-print" },
    }),
    stdioServer(controlledServer, fixture, ["only_tool"]),
  ].join("\n");
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, source);
  const output = capture();

  await runSetup({
    input: Readable.from([
      "2\n",
      "all\n",
      "1\n",
      "yes\n",
      "1,3\n",
      "1\n",
      "1\n",
      "yes\n",
      "none\n",
      "1\n",
      "yes\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  const rendered = parse(await readFile(configPath, "utf8")) as {
    mcp_servers: Record<string, { command: string; args: string[] }>;
  };
  expect(Object.keys(rendered.mcp_servers).sort()).toEqual(["first", controlledServer].sort());
  expect(rendered.mcp_servers.first?.command).toBe(process.execPath);
  expect(rendered.mcp_servers[controlledServer]?.command).toBe(process.execPath);
  expect(rendered.mcp_servers.first?.args).toContain(cli);
  expect(rendered.mcp_servers[controlledServer]?.args).toContain(cli);
  expect(await exists(join(root, ".mcp-restrictor", "policies", "codex", "first.yaml"))).toBe(true);
  expect(
    await exists(
      join(
        root,
        ".mcp-restrictor",
        "policies",
        "codex",
        `${encodeURIComponent(controlledServer)}.yaml`,
      ),
    ),
  ).toBe(true);

  const text = output.text();
  expect(text.match(/Preview:/g)).toHaveLength(1);
  expect(text.match(/Apply these changes/g)).toHaveLength(1);
  expect(text).toContain(JSON.stringify(controlledServer));
  for (const tool of controlledTools) expect(text).toContain(JSON.stringify(tool));
  expect(text).not.toContain("\u001b");
  expect(text).not.toContain("\r");
  expect(text).not.toContain("must-never-print");
  expect(text).not.toContain(`second\u001b\r\nname`);
});

test("rolls back both clients and policies when the second late verification fails", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const fixture = await writeUpstreamFixture(root);
  const claudeConfig = join(root, ".mcp.json");
  const codexConfig = join(root, ".codex", "config.toml");
  const claudeSource = `${JSON.stringify(
    {
      mcpServers: {
        files: { command: process.execPath, args: [fixture, JSON.stringify(["read_file"])] },
      },
    },
    null,
    2,
  )}\n`;
  const codexSource = stdioServer("files", fixture, ["read_file"]);
  await mkdir(dirname(codexConfig), { recursive: true });
  await Promise.all([writeFile(claudeConfig, claudeSource), writeFile(codexConfig, codexSource)]);
  let discoveries = 0;
  setupFakes.discover = async () => {
    discoveries += 1;
    if (discoveries === 4) throw new Error("late second verification");
    return ["read_file"];
  };

  await expect(
    runSetup({
      input: Readable.from([
        "1,2\n",
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
      output: capture(),
      error: capture(),
      interactive: true,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH },
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Wrapper verification failed for codex project server");

  expect(discoveries).toBe(4);
  expect(await readFile(claudeConfig, "utf8")).toBe(claudeSource);
  expect(await readFile(codexConfig, "utf8")).toBe(codexSource);
  expect(await exists(join(root, ".mcp-restrictor", "policies", "claude", "files.yaml"))).toBe(
    false,
  );
  expect(await exists(join(root, ".mcp-restrictor", "policies", "codex", "files.yaml"))).toBe(
    false,
  );
});

test("orchestrates Claude project setup and prints an exact manual restore source", async () => {
  const root = await temporaryDirectory();
  const fixture = await writeUpstreamFixture(root);
  const configPath = join(root, ".mcp.json");
  const source = `${JSON.stringify(
    {
      mcpServers: {
        files: {
          command: process.execPath,
          args: [fixture, JSON.stringify(["read_file"]), "normal", ""],
        },
      },
    },
    null,
    2,
  )}\n`;
  await writeFile(configPath, source);
  const output = capture();

  await runSetup({
    input: Readable.from(["1\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  const rendered = JSON.parse(await readFile(configPath, "utf8")) as {
    mcpServers: { files: { command: string; args: string[] } };
  };
  expect(rendered.mcpServers.files.command).toBe(process.execPath);
  expect(rendered.mcpServers.files.args).toContain(cli);
  expect(output.text()).toContain("Restart Claude Code");
  expect(output.text()).toContain("approve the project .mcp.json");
  const restore = output
    .text()
    .split("\n")
    .find((line) => line.startsWith("Restore "));
  expect(restore).toBeDefined();
  const match = /^Restore (.+) from (.+)$/.exec(restore!);
  expect(match).not.toBeNull();
  expect(JSON.parse(match![1]!)).toBe(configPath);
  expect(await readFile(JSON.parse(match![2]!), "utf8")).toBe(source);
  expect(output.text()).toContain(
    `Remove newly created file ${JSON.stringify(join(root, ".mcp-restrictor", "policies", "claude", "files.yaml"))}`,
  );
});

test.each([
  { name: "EOF", answers: ["2\n"] },
  { name: "empty selection", answers: ["2\n", "none\n"] },
  {
    name: "negative confirmation",
    answers: ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "no\n"],
  },
])("cancels on $name without writes or listener leaks", async ({ answers }) => {
  const setup = await simpleCodexProject(["read_file"]);
  const beforeSigint = process.listenerCount("SIGINT");
  const beforeSigterm = process.listenerCount("SIGTERM");
  const output = capture();

  await runSetup({
    ...setupOptions(setup, answers, output),
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
  expect(await exists(setup.policyPath)).toBe(false);
  expect(process.listenerCount("SIGINT")).toBe(beforeSigint);
  expect(process.listenerCount("SIGTERM")).toBe(beforeSigterm);
  expect(output.text()).toContain("Setup cancelled");
});

test("keeps signal handlers through repeated signals and removes them after cancellation", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const beforeSigint = process.listenerCount("SIGINT");
  const beforeSigterm = process.listenerCount("SIGTERM");
  const activeCounts: Array<[number, number]> = [];
  const input = Readable.from(
    (async function* () {
      yield "2\n";
      await new Promise<void>((resolveImmediate) => setImmediate(resolveImmediate));
      process.emit("SIGINT", "SIGINT");
      activeCounts.push([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")]);
      process.emit("SIGINT", "SIGINT");
      process.emit("SIGTERM", "SIGTERM");
      process.emit("SIGTERM", "SIGTERM");
      activeCounts.push([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")]);
    })(),
  );

  await runSetup({
    ...setupOptions(setup, [], capture()),
    input,
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
  expect(await exists(setup.policyPath)).toBe(false);
  expect(activeCounts).toEqual([
    [beforeSigint + 1, beforeSigterm + 1],
    [beforeSigint + 1, beforeSigterm + 1],
  ]);
  expect(process.listenerCount("SIGINT")).toBe(beforeSigint);
  expect(process.listenerCount("SIGTERM")).toBe(beforeSigterm);
});

test("does not hide a failed rollback merely because verification was aborted", async () => {
  const parent = await temporaryDirectory();
  const controlledSegment = "project\u001b\r\npath";
  const root = join(parent, controlledSegment);
  await mkdir(root);
  const setup = await simpleCodexProject(["read_file"], root);
  const marker = join(setup.root, "verification-started");
  const controller = new AbortController();
  const output = capture();
  const error = capture();
  const running = runSetup({
    ...setupOptions(setup, ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"], output),
    error,
    signal: controller.signal,
    restrictor: {
      command: process.execPath,
      argsPrefix: [
        setup.fixture,
        JSON.stringify(["read_file"]),
        "sabotage",
        setup.configPath,
        marker,
      ],
    },
  });
  await vi.waitFor(async () => expect(await exists(marker)).toBe(true));
  controller.abort();

  const failure = await running.catch((caught: unknown) => caught);
  expect(failure).toBeInstanceOf(AggregateError);
  const messages = errorMessages(failure);
  expect(messages.join("")).toContain("project\\u001b\\r\\npath");
  for (const message of messages) {
    expect(message).not.toContain(controlledSegment);
    expect(message).not.toContain("\u001b");
    expect(message).not.toContain("\r");
    expect(message).not.toContain("\n");
  }
  expect(`${output.text()}${error.text()}`).not.toContain(controlledSegment);
  expect(output.text()).toContain(JSON.stringify(root));
  expect(output.text()).not.toContain("\u001b");
  expect(output.text()).not.toContain("\r");
  expect(output.text()).not.toContain("Setup cancelled");
});

test("refuses non-interactive setup before reading configuration", async () => {
  await expect(runSetup({ interactive: false })).rejects.toThrow(
    "setup requires an interactive terminal",
  );
});

test("defers adapter credential resolution until after endpoint confirmation", async () => {
  const root = await temporaryDirectory();
  const configPath = join(root, "client.json");
  await writeFile(configPath, "{}");
  let reads = 0;
  const environment: NodeJS.ProcessEnv = { PATH: process.env.PATH };
  Object.defineProperty(environment, "SECRET", {
    enumerable: true,
    configurable: true,
    get() {
      reads += 1;
      return "resolved-secret";
    },
  });
  const adapter = resolvingAdapter(configPath, async (candidate, context) => {
    const value = context.environment.SECRET!;
    return {
      candidate: {
        ...candidate,
        upstream: { kind: "http", url: "https://example.test/mcp", headers: [["X-Key", value]] },
      },
      dependencies: [{ kind: "environment", name: "SECRET", value }],
    };
  });

  await runSetup({
    ...adapterSetupOptions(root, environment, adapter, ["1\n", "1\n", "1\n", "no\n"]),
    output: capture(),
  });
  expect(reads).toBe(0);

  let discovered: UpstreamConfig | undefined;
  setupFakes.discover = async (upstream) => {
    discovered = upstream;
    return ["read_file"];
  };
  const output = capture();
  await runSetup({
    ...adapterSetupOptions(root, environment, adapter, [
      "1\n",
      "1\n",
      "1\n",
      "yes\n",
      "all\n",
      "1\n",
      "no\n",
    ]),
    output,
  });

  expect(reads).toBe(1);
  expect(discovered).toMatchObject({ headers: [["X-Key", "resolved-secret"]] });
  expect(output.text()).not.toContain("resolved-secret");
});

test("OpenCode Connect=no performs no credential read, OAuth work, listener bind, or upstream call", async () => {
  const root = await temporaryDirectory();
  const configPath = join(root, "opencode.json");
  await writeFile(
    configPath,
    JSON.stringify({
      mcp: {
        protected: {
          type: "remote",
          url: "https://example.test/mcp",
          headers: {
            "X-Env": "{env:HEADER_SECRET}",
            "X-File": "{file:secrets/header}",
          },
        },
      },
    }),
  );
  const environment: NodeJS.ProcessEnv = { PATH: process.env.PATH };
  let credentialReads = 0;
  Object.defineProperties(environment, {
    HEADER_SECRET: {
      enumerable: true,
      get() {
        credentialReads += 1;
        return "header-secret";
      },
    },
    [MASTER_KEY_FILE_ENV]: {
      enumerable: true,
      get() {
        credentialReads += 1;
        return join(root, "oauth-master.key");
      },
    },
  });
  const discover = vi.fn(async () => ["must-not-connect"]);
  const login = vi.fn(async () => exampleProfile("unexpected", "https://example.test/mcp"));
  const readSecret = vi.fn(async () => "must-not-read");
  setupFakes.discover = discover;
  setupFakes.login = login;

  const output = capture();
  await runSetup({
    input: Readable.from(["1\n", "all\n", "1\n", "no\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment,
    adapters: [opencodeAdapter],
    readSecret,
  });

  expect(credentialReads).toBe(0);
  expect(discover).not.toHaveBeenCalled();
  expect(login).not.toHaveBeenCalled();
  expect(readSecret).not.toHaveBeenCalled();
  expect(output.text()).toContain("Connect to this upstream?");
  expect(await exists(join(root, "home", ".mcp-restrictor", "oauth"))).toBe(false);
});

test("rejects an empty OpenCode bearer environment value before any upstream call", async () => {
  const root = await temporaryDirectory();
  const configPath = join(root, "opencode.json");
  const serverUrl = "https://empty-env-bearer.example.test/mcp";
  const candidateName = "empty-env-candidate";
  const secretSentinel = "ENV_HEADER_SECRET_VALUE_SENTINEL";
  const authorization = "Bearer {env:EMPTY_BEARER}";
  const source = JSON.stringify({
    mcp: {
      [candidateName]: {
        type: "remote",
        url: serverUrl,
        oauth: false,
        headers: { Authorization: authorization, "X-Secret": secretSentinel },
      },
    },
  });
  await writeFile(configPath, source);
  const discover = vi.fn(async () => ["must-not-connect"]);
  setupFakes.discover = discover;
  const output = capture();
  const error = capture();

  const failure = await runSetup({
    input: Readable.from(["1\n", "all\n", "1\n", "yes\n"]),
    output,
    error,
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH, EMPTY_BEARER: "" },
    adapters: [opencodeAdapter],
  }).catch((caught: unknown) => caught);

  expect(errorMessages(failure)).toEqual(["Failed to resolve client configuration"]);
  expect(error.text()).toBe("");
  expect(discover).not.toHaveBeenCalled();
  expect(output.text()).toContain(
    `OpenCode / ${candidateName} (project, http, ${JSON.stringify(configPath)})`,
  );
  expect(output.text()).toContain(
    `Upstream: transport=http endpoint=${JSON.stringify(serverUrl)} auth=bearer`,
  );
  expect(output.text()).toContain('Bearer token from "MCP_RESTRICTOR_UPSTREAM_HEADER_0"');
  const publicText = `${String(failure)}\n${output.text()}\n${error.text()}`;
  for (const detail of [
    "OpenCode bearer token is missing",
    authorization,
    "{env:EMPTY_BEARER}",
    secretSentinel,
    source,
  ])
    expect(publicText).not.toContain(detail);
});

test("rejects an empty OpenCode bearer file before any upstream call", async () => {
  const root = await temporaryDirectory();
  const configPath = join(root, "opencode.json");
  const secretPath = join(root, "empty-file-bearer.token");
  const serverUrl = "https://empty-file-bearer.example.test/mcp";
  const candidateName = "empty-file-candidate";
  const secretSentinel = "FILE_HEADER_SECRET_VALUE_SENTINEL";
  const authorization = "Bearer {file:empty-file-bearer.token}";
  const source = JSON.stringify({
    mcp: {
      [candidateName]: {
        type: "remote",
        url: serverUrl,
        oauth: false,
        headers: { Authorization: authorization, "X-Secret": secretSentinel },
      },
    },
  });
  await writeFile(configPath, source);
  await writeFile(secretPath, "", { mode: 0o600 });
  await chmod(secretPath, 0o600);
  const discover = vi.fn(async () => ["must-not-connect"]);
  setupFakes.discover = discover;
  const output = capture();
  const error = capture();

  const failure = await runSetup({
    input: Readable.from(["1\n", "all\n", "1\n", "yes\n"]),
    output,
    error,
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
    adapters: [opencodeAdapter],
  }).catch((caught: unknown) => caught);

  expect(errorMessages(failure)).toEqual(["Failed to resolve client configuration"]);
  expect(error.text()).toBe("");
  expect(discover).not.toHaveBeenCalled();
  expect(output.text()).toContain(
    `OpenCode / ${candidateName} (project, http, ${JSON.stringify(configPath)})`,
  );
  expect(output.text()).toContain(
    `Upstream: transport=http endpoint=${JSON.stringify(serverUrl)} auth=bearer`,
  );
  expect(output.text()).toContain('Bearer token from "MCP_RESTRICTOR_UPSTREAM_HEADER_0"');
  const publicText = `${String(failure)}\n${output.text()}\n${error.text()}`;
  for (const detail of [
    "OpenCode bearer token is missing",
    authorization,
    "{file:empty-file-bearer.token}",
    secretPath,
    secretSentinel,
    source,
  ])
    expect(publicText).not.toContain(detail);
});

test("line setup keeps a resolved preconfigured OAuth client secret prompt-free", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const configPath = join(root, "opencode.json");
  const keyPath = join(root, "oauth-master.key");
  const clientSecret = "configured-opencode-client-secret";
  await writeFile(
    configPath,
    JSON.stringify({
      mcp: {
        servers: {
          protected: {
            type: "remote",
            url: "https://example.test/mcp",
            oauth: {
              client_id: "configured-client",
              client_secret: clientSecret,
              scope: "read write",
              redirect_uri: "https://callback.example/finish",
            },
          },
        },
      },
    }),
  );
  await writeFile(keyPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
  await chmod(keyPath, 0o600);
  const readSecret = vi.fn(async () => "prompted-secret");
  setupFakes.login = vi.fn(async (options) => {
    expect(options.input.clientInformation).toEqual({
      client_id: "configured-client",
      client_secret: clientSecret,
    });
    expect(options.input.metadata).toMatchObject({
      serverUrl: "https://example.test/mcp",
      requestedScope: "read write",
      callback: {
        url: "https://callback.example/finish",
        appendProfileId: false,
      },
    });
    return exampleProfile(options.input.metadata.profileId, "https://example.test/mcp", {
      metadata: options.input.metadata,
      clientInformation: options.input.clientInformation,
    });
  });
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture();

  await runSetup({
    input: Readable.from(["1\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "no\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { PATH: process.env.PATH, [MASTER_KEY_FILE_ENV]: keyPath },
    adapters: [opencodeAdapter],
    readSecret,
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(readSecret).not.toHaveBeenCalled();
  expect(setupFakes.login).toHaveBeenCalledOnce();
  expect(output.text()).not.toContain("No client secret");
  expect(output.text()).not.toContain("Enter client secret");
  expect(output.text()).not.toContain("\u001B[");
  expect(output.text()).not.toContain(clientSecret);
  expect(await readFile(configPath, "utf8")).not.toContain("prompted-secret");
});

test("rejects OpenCode file credential drift before transaction writes", async () => {
  const root = await temporaryDirectory();
  const configPath = join(root, "opencode.json");
  const secretPath = join(root, "header.secret");
  const policyPath = join(root, ".mcp-restrictor", "policies", "opencode", "files.yaml");
  const source = JSON.stringify({
    mcp: {
      servers: {
        files: {
          type: "remote",
          url: "https://example.test/mcp",
          oauth: false,
          headers: { "X-Key": "{file:header.secret}" },
        },
      },
    },
  });
  await writeFile(configPath, source);
  await writeFile(secretPath, "first-secret", { mode: 0o600 });
  await chmod(secretPath, 0o600);
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture();
  const mutationOutput = new Writable({
    write(chunk, _encoding, callback) {
      output.write(chunk);
      if (chunk.toString().includes("Apply these changes?")) {
        writeFileSync(secretPath, "second-secret");
      }
      callback();
    },
  });

  await expect(
    runSetup({
      input: Readable.from(["1\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"]),
      output: mutationOutput,
      error: capture(),
      interactive: true,
      cwd: root,
      home: join(root, "home"),
      environment: { PATH: process.env.PATH },
      adapters: [opencodeAdapter],
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Client credential source changed during setup");

  expect(await readFile(configPath, "utf8")).toBe(source);
  expect(await exists(policyPath)).toBe(false);
  expect(output.text()).not.toMatch(/first-secret|second-secret/);
});

test.each([
  ["V1 HTTP success", "v1", 200, "http"],
  ["V1 protocol 404 then SSE success", "v1", 404, "sse"],
  ["V2 protocol 404", "v2", 404, "error"],
  ["V1 OAuth 401", "v1", 401, "oauth-without-fallback"],
  ["V1 server 500", "v1", 500, "error-without-fallback"],
] as const)("negotiates the live OpenCode row: %s", async (_name, schema, status, outcome) => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const configPath = join(root, "opencode.json");
  const fixture = await startOpenCodeNegotiationFixture(status);
  const oauth = status === 401 ? undefined : false;
  const entry = {
    type: "remote",
    url: fixture.url,
    ...(oauth === false ? { oauth } : {}),
  };
  await writeFile(
    configPath,
    JSON.stringify({
      mcp: schema === "v1" ? { files: entry } : { servers: { files: entry } },
    }),
  );
  const keyPath = join(root, "oauth-master.key");
  if (status === 401) {
    await writeFile(keyPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
    await chmod(keyPath, 0o600);
    setupFakes.login = vi.fn(async (options) =>
      exampleProfile(options.input.metadata.profileId, fixture.url, {
        metadata: options.input.metadata,
        accessToken: "oauth-token",
      }),
    );
  }
  const output = capture();
  const setup = runSetup({
    input: Readable.from(["1\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "no\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: {
      PATH: process.env.PATH,
      ...(status === 401 ? { [MASTER_KEY_FILE_ENV]: keyPath } : {}),
    },
    adapters: [opencodeAdapter],
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  try {
    if (outcome === "error" || outcome === "error-without-fallback") {
      await expect(setup).rejects.toThrow();
    } else {
      await expect(setup).resolves.toBeUndefined();
      expect(output.text()).toContain(`transport=${outcome === "sse" ? "sse" : "http"}`);
    }
    if (outcome === "sse") expect(fixture.sseMessages()).toBeGreaterThan(0);
    else expect(fixture.sseMessages()).toBe(0);
    if (outcome === "oauth-without-fallback") {
      expect(setupFakes.login).toHaveBeenCalledOnce();
    }
  } finally {
    await fixture.close();
  }
});

test.each([
  ["abort", new DOMException("Aborted", "AbortError")],
  ["timeout", new Error("TimeoutError")],
  ["TLS rejection", new Error("certificate rejected")],
  ["malformed response", new Error("invalid MCP response")],
  ["duplicate tools", new Error("Duplicate tool name read_file")],
  ["matching message without the type", new Error("Upstream transport protocol is incompatible")],
] as const)("does not try an OpenCode alternative after %s", async (_name, primaryError) => {
  const root = await temporaryDirectory();
  const configPath = join(root, "client.json");
  await writeFile(configPath, "{}");
  const calls: string[] = [];
  setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) => {
    calls.push(upstream.kind);
    if (upstream.kind === "http") throw primaryError;
    return ["must-not-fallback"];
  });

  const setup = runSetup(
    adapterSetupOptions(root, { PATH: process.env.PATH }, alternativeAdapter(configPath), [
      "1\n",
      "1\n",
      "1\n",
      "yes\n",
    ]),
  );

  if (primaryError.name === "AbortError") await expect(setup).resolves.toBeUndefined();
  else await expect(setup).rejects.toThrow();

  expect(calls).toEqual(["http"]);
});

test.each([
  ["typed 404", 404, false],
  ["typed 405", 405, false],
  ["typed 406", 406, false],
  ["typed 415", 415, false],
  ["typed first AggregateError", 404, true],
] as const)(
  "tries the ordered OpenCode alternative after a %s",
  async (_name, status, aggregate) => {
    const root = await temporaryDirectory();
    const configPath = join(root, "client.json");
    await writeFile(configPath, "{}");
    const calls: string[] = [];
    setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) => {
      calls.push(upstream.kind);
      if (upstream.kind === "http") {
        const response = new Response("incompatible response body", { status });
        const failure = await Promise.resolve(upstream.validateResponse?.(response)).then(
          () => new Error("typed failure was not raised"),
          (error: unknown) => error,
        );
        expect(response.bodyUsed).toBe(true);
        throw aggregate ? new AggregateError([failure, new Error("cleanup failed")]) : failure;
      }
      return ["read_file"];
    });

    await runSetup(
      adapterSetupOptions(root, { PATH: process.env.PATH }, alternativeAdapter(configPath), [
        "1\n",
        "1\n",
        "1\n",
        "yes\n",
        "all\n",
        "1\n",
        "no\n",
      ]),
    );

    expect(calls).toEqual(["http", "sse"]);
  },
);

test("logs in once then reuses one OpenCode OAuth profile across a typed SSE fallback and one write", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const configPath = join(root, "client.json");
  const keyPath = join(root, "oauth-master.key");
  await writeFile(configPath, "{}");
  await writeFile(keyPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
  await chmod(keyPath, 0o600);
  const profileIds: string[] = [];
  const tokens: string[] = [];
  setupFakes.login = vi.fn(async (options) => {
    profileIds.push(options.input.metadata.profileId);
    return exampleProfile(options.input.metadata.profileId, "https://example.test/mcp", {
      metadata: options.input.metadata,
      accessToken: "shared-token",
    });
  });
  setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) => {
    if (upstream.kind === "stdio") return ["read_file"];
    if (upstream.kind === "http") {
      tokens.push((await upstream.authProviderFactory?.().token()) ?? "");
      await upstream.validateResponse?.(new Response(null, { status: 404 }));
      return [];
    }
    tokens.push((await upstream.authProviderFactory?.().token()) ?? "");
    return ["read_file"];
  });

  await runSetup({
    ...adapterSetupOptions(
      root,
      { PATH: process.env.PATH, [MASTER_KEY_FILE_ENV]: keyPath },
      alternativeAdapter(configPath, true),
      ["1\n", "1\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"],
    ),
    home,
  });

  expect(setupFakes.login).toHaveBeenCalledOnce();
  expect(new Set(profileIds).size).toBe(1);
  expect(tokens).toEqual(["shared-token", "shared-token"]);
  const profileFiles = await readdir(join(home, ".mcp-restrictor", "oauth"));
  expect(profileFiles.filter((name) => name.endsWith(".json"))).toHaveLength(1);
});

test.each([
  [
    "transport kind",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      source: { kind: "sse", url: "https://example.test/mcp", headers: candidate.source.headers },
      upstream: {
        kind: "sse",
        url: "https://example.test/mcp",
        headers: [["X-Key", "value"] as const],
      },
    }),
  ],
  [
    "canonical URL",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      source: { ...candidate.source, url: "https://example.test/other" },
      upstream: {
        kind: "http",
        url: "https://example.test/other",
        headers: [["X-Key", "value"] as const],
      },
    }),
  ],
  [
    "effective upstream URL",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      upstream: { ...candidate.upstream, url: "https://redirect.example.test/mcp" },
    }),
  ],
  [
    "header-name set",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      source: {
        ...candidate.source,
        headers: [{ name: "X-Other", environmentVariable: "SECRET" }],
      },
      upstream: {
        kind: "http",
        url: "https://example.test/mcp",
        headers: [["X-Other", "value"] as const],
      },
    }),
  ],
  [
    "authentication mode",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      source: { ...candidate.source, bearerTokenEnvVar: "TOKEN" },
      upstream: {
        kind: "http",
        url: "https://example.test/mcp",
        headers: [["X-Key", "value"] as const],
        bearerToken: "token",
      },
    }),
  ],
  [
    "primary upstream header-name set",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      upstream: { ...candidate.upstream, headers: [["X-Other", "value"]] },
    }),
  ],
  [
    "primary upstream bearer presence",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      upstream: { ...candidate.upstream, bearerToken: "value" },
    }),
  ],
  [
    "primary upstream OAuth provider presence",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      upstream: {
        ...candidate.upstream,
        authProviderFactory: {} as () => never,
      },
    }),
  ],
  [
    "alternative upstream header-name set",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      alternatives: candidate.alternatives!.map((alternative, index) =>
        index === 0 && alternative.upstream.kind === "sse"
          ? {
              ...alternative,
              upstream: { ...alternative.upstream, headers: [["X-Other", "value"]] },
            }
          : alternative,
      ),
    }),
  ],
  [
    "alternative upstream bearer presence",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      alternatives: candidate.alternatives!.map((alternative, index) =>
        index === 0 && alternative.upstream.kind === "sse"
          ? {
              ...alternative,
              upstream: { ...alternative.upstream, bearerToken: "value" },
            }
          : alternative,
      ),
    }),
  ],
  [
    "alternative upstream OAuth provider presence",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      alternatives: candidate.alternatives!.map((alternative, index) =>
        index === 0 && alternative.upstream.kind === "sse"
          ? {
              ...alternative,
              upstream: {
                ...alternative.upstream,
                authProviderFactory: {} as () => never,
              },
            }
          : alternative,
      ),
    }),
  ],
  [
    "client identity",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      client: "other",
    }),
  ],
  [
    "scope identity",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      scope: "user",
    }),
  ],
  [
    "name identity",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      name: "other",
    }),
  ],
  [
    "config path identity",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      configPath: `${candidate.configPath}.other`,
    }),
  ],
  [
    "ordered alternatives",
    (candidate: AdapterCandidate): ServerCandidate => ({
      ...candidate,
      alternatives: [...(candidate.alternatives ?? [])].reverse(),
    }),
  ],
] as const)(
  "rejects a resolved candidate that changes its %s before discovery",
  async (_name, mutate) => {
    const root = await temporaryDirectory();
    const configPath = join(root, "client.json");
    await writeFile(configPath, "{}");
    const adapter = resolvingAdapter(configPath, async (candidate) => ({
      candidate: mutate(candidate as AdapterCandidate),
      dependencies: [],
    }));
    const discover = vi.fn(async () => ["read_file"]);
    setupFakes.discover = discover;

    await expect(
      runSetup(
        adapterSetupOptions(root, { PATH: process.env.PATH }, adapter, [
          "1\n",
          "1\n",
          "1\n",
          "yes\n",
        ]),
      ),
    ).rejects.toThrow("Client adapter changed confirmed server shape");
    expect(discover).not.toHaveBeenCalled();
    expect(await readFile(configPath, "utf8")).toBe("{}");
  },
);

test.each([
  [
    "mutable object",
    () => ({
      value: "SECRET",
      toString(): string {
        return "SECRET";
      },
    }),
  ],
  [
    "throwing object",
    () => ({
      toString() {
        throw new Error("secret-dependency-detail");
      },
    }),
  ],
] as const)(
  "rejects a %s environment dependency name without coercion",
  async (_kind, createName) => {
    const root = await temporaryDirectory();
    const configPath = join(root, "client.json");
    const policyPath = join(root, ".mcp-restrictor", "policies", "fake", "files.yaml");
    await writeFile(configPath, "{}");
    const adapter = resolvingAdapter(configPath, async (candidate) => ({
      candidate,
      dependencies: [
        {
          kind: "environment",
          name: createName() as unknown as string,
          value: "value",
        },
      ],
    }));
    const discover = vi.fn(async () => ["read_file"]);
    setupFakes.discover = discover;
    const output = capture();
    const error = capture();

    const failure = await runSetup({
      ...adapterSetupOptions(root, { PATH: process.env.PATH, SECRET: "value" }, adapter, [
        "1\n",
        "1\n",
        "1\n",
        "yes\n",
        "all\n",
        "1\n",
        "yes\n",
      ]),
      output,
      error,
    }).catch((caught: unknown) => caught);

    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toBe(
      "Invalid client resolution dependency returned by adapter",
    );
    expect(discover).not.toHaveBeenCalled();
    expect(`${output.text()}${error.text()}${String(failure)}`).not.toContain(
      "secret-dependency-detail",
    );
    expect(await readFile(configPath, "utf8")).toBe("{}");
    expect(await exists(policyPath)).toBe(false);
  },
);

test.each(["kind", "name", "value"] as const)(
  "snapshots an accessor-backed environment dependency %s exactly once",
  async (field) => {
    const root = await temporaryDirectory();
    const configPath = join(root, "client.json");
    await writeFile(configPath, "{}");
    let reads = 0;
    const adapter = resolvingAdapter(configPath, async (candidate) => {
      const dependency = { kind: "environment" as const, name: "SECRET", value: "value" };
      Object.defineProperty(dependency, field, {
        enumerable: true,
        get() {
          reads += 1;
          if (reads > 1) throw new Error("secret-dependency-detail");
          return field === "kind" ? "environment" : field === "name" ? "SECRET" : "value";
        },
      });
      return { candidate, dependencies: [dependency] };
    });
    const discover = vi.fn(async () => ["read_file"]);
    setupFakes.discover = discover;
    const output = capture();
    const error = capture();

    const failure = await runSetup({
      ...adapterSetupOptions(root, { PATH: process.env.PATH, SECRET: "value" }, adapter, [
        "1\n",
        "1\n",
        "1\n",
        "yes\n",
        "all\n",
        "1\n",
        "yes\n",
      ]),
      output,
      error,
    }).catch((caught: unknown) => caught);

    expect(failure).toBeUndefined();
    expect(reads).toBe(1);
    expect(discover).toHaveBeenCalledTimes(2);
    expect(`${output.text()}${error.text()}${String(failure)}`).not.toContain(
      "secret-dependency-detail",
    );
  },
);

test.each(["kind", "snapshot"] as const)(
  "snapshots an accessor-backed file dependency %s exactly once",
  async (field) => {
    const root = await temporaryDirectory();
    const configPath = join(root, "client.json");
    const secretPath = join(root, "credential");
    await writeFile(configPath, "{}");
    await writeFile(secretPath, "secret", { mode: 0o600 });
    await chmod(secretPath, 0o600);
    let reads = 0;
    const adapter = resolvingAdapter(configPath, async (candidate, _context, host) => {
      const snapshot = await host.readSecretFile(secretPath);
      const dependency = { kind: "file" as const, snapshot };
      Object.defineProperty(dependency, field, {
        enumerable: true,
        get() {
          reads += 1;
          if (reads > 1) throw new Error("secret-dependency-detail");
          return field === "kind" ? "file" : snapshot;
        },
      });
      return {
        candidate,
        dependencies: [dependency],
      };
    });
    const discover = vi.fn(async () => ["read_file"]);
    setupFakes.discover = discover;
    const output = capture();
    const error = capture();

    const failure = await runSetup({
      ...adapterSetupOptions(root, { PATH: process.env.PATH }, adapter, [
        "1\n",
        "1\n",
        "1\n",
        "yes\n",
        "all\n",
        "1\n",
        "yes\n",
      ]),
      output,
      error,
    }).catch((caught: unknown) => caught);

    expect(failure).toBeUndefined();
    expect(reads).toBe(1);
    expect(discover).toHaveBeenCalledTimes(2);
    expect(`${output.text()}${error.text()}${String(failure)}`).not.toContain(
      "secret-dependency-detail",
    );
  },
);

test("rechecks adapter credential dependencies after Apply and before mutation", async () => {
  const root = await temporaryDirectory();
  const configPath = join(root, "client.json");
  const policyPath = join(root, ".mcp-restrictor", "policies", "fake", "files.yaml");
  await writeFile(configPath, "{}");
  let reads = 0;
  const environment: NodeJS.ProcessEnv = { PATH: process.env.PATH };
  Object.defineProperty(environment, "SECRET", {
    enumerable: true,
    configurable: true,
    get() {
      reads += 1;
      return reads === 1 ? "captured-secret" : "changed-secret";
    },
  });
  const adapter = resolvingAdapter(configPath, async (candidate, context) => {
    const value = context.environment.SECRET!;
    return {
      candidate: {
        ...candidate,
        upstream: { kind: "http", url: "https://example.test/mcp", headers: [["X-Key", value]] },
      },
      dependencies: [{ kind: "environment", name: "SECRET", value }],
    };
  });
  setupFakes.discover = async () => ["read_file"];

  await expect(
    runSetup(
      adapterSetupOptions(root, environment, adapter, [
        "1\n",
        "1\n",
        "1\n",
        "yes\n",
        "all\n",
        "1\n",
        "yes\n",
      ]),
    ),
  ).rejects.toThrow("Client credential source changed during setup");

  expect(reads).toBe(2);
  expect(await readFile(configPath, "utf8")).toBe("{}");
  expect(await exists(policyPath)).toBe(false);
});

test("rechecks a managed OpenCode WebSocket header and keeps its value out of output", async () => {
  const root = await temporaryDirectory();
  const configPath = join(root, "opencode.json");
  const restrictor = join(root, "mcp-restrictor");
  await writeFile(restrictor, "#!/bin/sh\nexit 1\n", { mode: 0o700 });
  await chmod(restrictor, 0o700);
  await writeFile(
    configPath,
    JSON.stringify({
      mcp: {
        servers: {
          socket: {
            type: "local",
            command: [
              restrictor,
              "--policy",
              ".mcp-restrictor/policies/opencode/socket.yaml",
              "--upstream-websocket",
              "wss://example.test/mcp",
              "--upstream-header-env",
              "X-Auth=WS_AUTH",
            ],
            environment: { WS_AUTH: "{env:WS_SECRET}" },
          },
        },
      },
    }),
  );
  let reads = 0;
  const environment: NodeJS.ProcessEnv = { PATH: process.env.PATH };
  Object.defineProperty(environment, "WS_SECRET", {
    enumerable: true,
    get() {
      reads += 1;
      return "managed-websocket-secret";
    },
  });
  const discovered: UpstreamConfig[] = [];
  setupFakes.discover = async (configured) => {
    discovered.push(configured);
    return ["read_file"];
  };
  const output = capture();

  await runSetup({
    input: Readable.from(["3\n", "1\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment,
    restrictor: { command: restrictor, argsPrefix: [] },
  });

  expect(reads).toBe(2);
  expect(discovered[0]).toEqual({
    kind: "websocket",
    url: "wss://example.test/mcp",
    headers: [["X-Auth", "managed-websocket-secret"]],
  });
  expect(discovered[1]).toMatchObject({
    kind: "stdio",
    command: restrictor,
    env: { WS_AUTH: "managed-websocket-secret" },
  });
  expect(discovered[1]?.kind === "stdio" ? discovered[1].args : []).not.toContain(
    "managed-websocket-secret",
  );
  expect(output.text()).not.toContain("managed-websocket-secret");
  const rendered = JSON.parse(await readFile(configPath, "utf8")) as {
    mcp: { servers: { socket: { command: string[] } } };
  };
  expect(rendered.mcp.servers.socket.command).toEqual([
    restrictor,
    "--policy",
    ".mcp-restrictor/policies/opencode/socket.yaml",
    "--upstream-websocket",
    "wss://example.test/mcp",
    "--upstream-header-env",
    "X-Auth=WS_AUTH",
  ]);
});

test("defers private-file access until Connect and rejects a changed file after Apply", async () => {
  const root = await temporaryDirectory();
  const configPath = join(root, "client.json");
  const secretPath = join(root, "credential");
  const policyPath = join(root, ".mcp-restrictor", "policies", "fake", "files.yaml");
  await writeFile(configPath, "{}");
  const adapter = resolvingAdapter(configPath, async (candidate, _context, host) => ({
    candidate,
    dependencies: [{ kind: "file", snapshot: await host.readSecretFile(secretPath) }],
  }));

  await runSetup(
    adapterSetupOptions(root, { PATH: process.env.PATH }, adapter, ["1\n", "1\n", "1\n", "no\n"]),
  );

  await writeFile(secretPath, "first", { mode: 0o600 });
  await chmod(secretPath, 0o600);
  setupFakes.discover = async () => ["read_file"];
  const output = capture();
  const mutationOutput = new Writable({
    write(chunk, _encoding, callback) {
      output.write(chunk);
      if (chunk.toString().includes("Apply these changes?")) {
        writeFileSync(secretPath, "second");
      }
      callback();
    },
  });

  await expect(
    runSetup({
      ...adapterSetupOptions(root, { PATH: process.env.PATH }, adapter, [
        "1\n",
        "1\n",
        "1\n",
        "yes\n",
        "all\n",
        "1\n",
        "yes\n",
      ]),
      output: mutationOutput,
    }),
  ).rejects.toThrow("Client credential source changed during setup");
  expect(await readFile(configPath, "utf8")).toBe("{}");
  expect(await exists(policyPath)).toBe(false);
});

test("does not read Manual credential values before endpoint confirmation", async () => {
  const root = await temporaryDirectory();
  let reads = 0;
  const environment: NodeJS.ProcessEnv = { PATH: process.env.PATH };
  Object.defineProperty(environment, "API_KEY", {
    enumerable: true,
    configurable: true,
    get() {
      reads += 1;
      return "manual-header-secret";
    },
  });
  const output = capture();

  await runSetup({
    input: Readable.from([
      "4\n",
      "remote\n",
      "http\n",
      "https://example.test/mcp\n",
      "X-Key=API_KEY\n",
      "\n",
      "none\n",
      "1\n",
      "1\n",
      "no\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment,
  });

  expect(reads).toBe(0);
  expect(output.text()).toContain("Connect to this upstream?");
  expect(output.text()).toContain("API_KEY");
  expect(output.text()).not.toContain("manual-header-secret");
  expect(await exists(join(root, ".mcp-restrictor"))).toBe(false);
});

test("completes Manual setup when Enter confirms Connect and Apply", async () => {
  const root = await temporaryDirectory();
  const fixture = await writeUpstreamFixture(root);
  const output = capture();
  const calls: UpstreamConfig[] = [];
  setupFakes.discover = vi.fn(async (configured: UpstreamConfig) => {
    calls.push(configured);
    return ["read_file"];
  });

  await runSetup({
    input: Readable.from([
      "4\n",
      "files\n",
      "stdio\n",
      `${process.execPath}\n`,
      `${JSON.stringify([fixture, JSON.stringify(["read_file"])])}\n`,
      "\n",
      "1\n",
      "1\n",
      "\n",
      "all\n",
      "1\n",
      "\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "missing-home"),
    environment: { PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  const policyPath = join(root, ".mcp-restrictor", "policies", "manual", "files.yaml");
  expect(await readFile(policyPath, "utf8")).toContain("name: read_file");
  expect(calls).toHaveLength(2);
  expect(calls[0]).toMatchObject({ kind: "stdio", command: process.execPath });
  expect(calls[1]).toEqual({
    kind: "stdio",
    command: process.execPath,
    args: [
      cli,
      "--policy",
      policyPath,
      "--",
      process.execPath,
      fixture,
      JSON.stringify(["read_file"]),
    ],
  });
  expect(output.text()).toContain(`command: ${JSON.stringify(process.execPath)}\n`);
  expect(output.text()).toContain(
    `args: ${JSON.stringify(calls[1]!.kind === "stdio" ? calls[1]!.args : [])}\n`,
  );
  expect(output.text()).toContain('environment: {"inherit":[],"set":{}}\n');
  for (const clientPath of [
    join(root, ".mcp.json"),
    join(root, ".codex", "config.toml"),
    join(root, "missing-home", ".claude.json"),
    join(root, "missing-home", ".codex", "config.toml"),
  ])
    expect(await exists(clientPath)).toBe(false);
});

test("installs one Manual upstream atomically into selected client destinations", async () => {
  const setup = await manualDestinationFixture();
  const { root, home, fixture, claudePath, codexPath, openCodePath } = setup;
  const output = capture();
  const calls: UpstreamConfig[] = [];
  setupFakes.discover = vi.fn(async (configured: UpstreamConfig) => {
    calls.push(configured);
    return ["read_file"];
  });

  await runSetup(manualDestinationSetupOptions(setup, manualDestinationInput(fixture), output));

  const policies = setup.policyPaths;
  const policySources = await Promise.all(policies.map((path) => readFile(path, "utf8")));
  expect(new Set(policySources).size).toBe(1);
  expect(policySources[0]).toContain("name: read_file");
  expect(await exists(join(root, ".mcp-restrictor", "policies", "manual", "files.yaml"))).toBe(
    false,
  );

  const [claudeSource, codexSource, openCodeSource] = await Promise.all([
    readFile(claudePath, "utf8"),
    readFile(codexPath, "utf8"),
    readFile(openCodePath, "utf8"),
  ]);
  expect(claudeSource).toContain(
    "${CLAUDE_PROJECT_DIR:-.}/.mcp-restrictor/policies/claude/files.yaml",
  );
  expect(codexSource).toContain(join(home, ".mcp-restrictor", "policies", "codex", "files.yaml"));
  expect(openCodeSource).toContain(".mcp-restrictor/policies/opencode/files.yaml");
  for (const source of [claudeSource, codexSource, openCodeSource]) {
    expect(source).toContain("API_KEY");
    expect(source).not.toContain("manual-secret");
  }

  expect(calls).toHaveLength(4);
  expect(
    calls.filter((configured) => configured.kind === "stdio" && configured.args?.[0] === fixture),
  ).toHaveLength(1);
  expect(
    calls.filter(
      (configured) => configured.kind === "stdio" && configured.args?.[0] === "--policy",
    ),
  ).toHaveLength(3);
  expect(output.text().match(/Preview:/g)).toHaveLength(1);
  expect(output.text().match(/Apply these changes\?/g)).toHaveLength(1);
  expect(output.text()).toContain("action=add");
  for (const path of [...policies, claudePath, codexPath, openCodePath]) {
    expect(output.text()).toContain(`Changed: ${JSON.stringify(path)}`);
  }
  expect(output.text()).toContain("Backup directory:");
  expect(output.text()).toContain("Restart Claude Code");
  expect(output.text()).toContain("Restart Codex");
  expect(output.text()).not.toMatch(/^(command|args|environment):/m);
  expect(output.text()).not.toContain("manual-secret");

  for (const [adapterId, configPath] of [
    ["claude", claudePath],
    ["codex", codexPath],
    ["opencode", openCodePath],
  ] as const) {
    const state = await readRestoreState({ home, adapterId, configPath, projectRoot: root });
    expect(state?.state.servers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "files",
          created: true,
          policy: expect.objectContaining({ before: null }),
        }),
      ]),
    );
  }
});

test("installs two independent Manual HTTP routes in one transaction", async () => {
  const setup = await manualDestinationFixture();
  setupFakes.discover = vi
    .fn()
    .mockResolvedValueOnce(["read_file", "write_file"])
    .mockResolvedValueOnce(["read_file"])
    .mockResolvedValueOnce(["write_file"]);
  const output = capture();
  const diagnostics = capture();
  const inheritedSecret = "stdio-inherited-env-value-sentinel";

  await runSetup({
    ...manualDestinationSetupOptions(setup, manualTwoHttpInput(setup), output),
    error: diagnostics,
    environment: { PATH: process.env.PATH, API_KEY: inheritedSecret },
  });

  const routes = await loadRoutes(setup.home);
  expect(routes).toHaveLength(2);
  const byAdapter = [...routes].sort((left, right) =>
    left.definition.owner.adapterId.localeCompare(right.definition.owner.adapterId),
  );
  expect(byAdapter.map(({ definition }) => definition.owner.adapterId)).toEqual([
    "claude",
    "codex",
  ]);
  expect(byAdapter.map(({ definition }) => definition.proxyArgs[1])).toEqual([
    setup.policyPaths[0],
    setup.policyPaths[1],
  ]);
  expect(await readFile(setup.policyPaths[0]!, "utf8")).toContain("name: read_file");
  expect(await readFile(setup.policyPaths[0]!, "utf8")).not.toContain("name: write_file");
  expect(await readFile(setup.policyPaths[1]!, "utf8")).toContain("name: write_file");
  expect(await readFile(setup.claudePath, "utf8")).toContain(byAdapter[0]!.definition.listenUrl);
  expect(await readFile(setup.codexPath, "utf8")).toContain(byAdapter[1]!.definition.listenUrl);
  expect(output.text()).toContain("Start HTTP routes: mcp-restrictor run");
  const states = await Promise.all(
    [
      ["claude", setup.claudePath],
      ["codex", setup.codexPath],
    ].map(([adapterId, configPath]) =>
      readRestoreState({
        home: setup.home,
        adapterId: adapterId!,
        configPath: configPath!,
        projectRoot: setup.root,
      }),
    ),
  );
  const persistedAndOutput = [
    ...routes.map(({ snapshot }) => snapshot.content),
    ...byAdapter.map(({ definition }) => JSON.stringify(definition.proxyArgs)),
    ...(await Promise.all(setup.policyPaths.slice(0, 2).map((path) => readFile(path, "utf8")))),
    await readFile(setup.claudePath, "utf8"),
    await readFile(setup.codexPath, "utf8"),
    JSON.stringify(states),
    output.text(),
    diagnostics.text(),
  ].join("\n");
  expect(persistedAndOutput).toContain("API_KEY");
  expect(persistedAndOutput).not.toContain(inheritedSecret);
});

test.each(["valid", "invalid"] as const)(
  "keeps all-STDIO Manual setup route-free with an existing %s route registry",
  async (registry) => {
    const setup = await manualDestinationFixture();
    const routesDirectory = join(setup.home, ".mcp-restrictor", "routes");
    await mkdir(routesDirectory, { recursive: true, mode: 0o700 });
    await chmod(routesDirectory, 0o700);
    const owner = {
      adapterId: "codex",
      scope: "project" as const,
      configPath: resolve(join(setup.root, "unrelated.toml")),
      projectRoot: resolve(setup.root),
      serverName: "unrelated",
    };
    const path =
      registry === "valid" ? routePath(setup.home, owner) : join(routesDirectory, "invalid.json");
    const source =
      registry === "valid"
        ? serializeRoute({
            version: 1,
            owner,
            listenUrl: routeUrl(8123, owner),
            proxyArgs: [
              "--policy",
              resolve(join(setup.root, "unrelated.yaml")),
              "--upstream-http",
              "https://example.test/mcp",
            ],
            environment: { set: {} },
          })
        : "not a managed route\n";
    await writeFile(path, source, { mode: 0o600 });
    await chmod(path, 0o600);
    setupFakes.discover = vi.fn(async () => ["read_file"]);
    const output = capture();

    await runSetup(
      manualDestinationSetupOptions(setup, manualDestinationInput(setup.fixture), output),
    );

    expect(await readFile(path, "utf8")).toBe(source);
    expect(output.text()).not.toContain("HTTP gateway port");
    expect(output.text()).not.toContain("Start HTTP routes: mcp-restrictor run");
    for (const configPath of [setup.claudePath, setup.codexPath, setup.openCodePath]) {
      expect(await readFile(configPath, "utf8")).toContain("--policy");
    }
  },
);

test.sequential("verifies a Manual HTTP route when Windows reports private mode 0666", async () => {
  const setup = await manualDestinationFixture();
  const owner = {
    adapterId: "claude",
    scope: "project" as const,
    configPath: resolve(setup.claudePath),
    projectRoot: resolve(setup.root),
    serverName: "files",
  };
  const path = routePath(setup.home, owner);
  setupFileOperations.reportedModeForRoute = path;
  setupFakes.discover = vi.fn(async () => ["read_file"]);

  await withProcessPlatform("win32", async () => {
    await runSetup(manualDestinationSetupOptions(setup, manualOneHttpInput(setup), capture()));

    expect((await loadRoutes(setup.home))[0]?.snapshot.mode).toBe(0o666);
    const state = await readRestoreState({
      home: setup.home,
      adapterId: "claude",
      configPath: setup.claudePath,
      projectRoot: setup.root,
    });
    if (state?.state.version !== 2) throw new Error("missing route restore state");
    expect(state.state.servers[0]?.route?.installed.mode).toBe(0o600);
  });
});

test.each([0, 1, 2] as const)(
  "rolls back the actual Manual tree when HTTP route write position %s fails",
  async (failedRoute) => {
    const setup = await manualDestinationFixture();
    const routePaths = [
      routePath(setup.home, {
        adapterId: "claude",
        scope: "project",
        configPath: resolve(setup.claudePath),
        projectRoot: resolve(setup.root),
        serverName: "files",
      }),
      routePath(setup.home, {
        adapterId: "codex",
        scope: "user",
        configPath: resolve(setup.codexPath),
        projectRoot: resolve(setup.root),
        serverName: "files",
      }),
      routePath(setup.home, {
        adapterId: "opencode",
        scope: "project",
        configPath: resolve(setup.openCodePath),
        projectRoot: resolve(setup.root),
        serverName: "files",
      }),
    ];
    setupFileOperations.failRenameFor = routePaths[failedRoute];
    setupFakes.discover = vi.fn(async () => ["read_file"]);

    await expect(
      runSetup(manualDestinationSetupOptions(setup, manualThreeHttpInput(setup), capture())),
    ).rejects.toThrow("injected Manual route write failure");

    for (const path of [...setup.policyPaths, ...routePaths])
      expect(await exists(path)).toBe(false);
    expect(await readFile(setup.claudePath, "utf8")).toBe('{"mcpServers": {}}\n');
    expect(await readFile(setup.codexPath, "utf8")).toBe("");
    expect(await readFile(setup.openCodePath, "utf8")).toBe("{}\n");
    for (const [adapterId, configPath] of [
      ["claude", setup.claudePath],
      ["codex", setup.codexPath],
      ["opencode", setup.openCodePath],
    ] as const) {
      await expect(
        readRestoreState({ home: setup.home, adapterId, configPath, projectRoot: setup.root }),
      ).resolves.toBeUndefined();
    }
    const routeEntries = await readdir(dirname(routePaths[0]!));
    expect(routeEntries).toEqual([]);
  },
);

test("rolls back every Manual HTTP route artifact when later route verification fails", async () => {
  const setup = await manualDestinationFixture();
  setupFakes.discover = vi
    .fn()
    .mockResolvedValueOnce(["read_file", "write_file"])
    .mockResolvedValueOnce(["read_file"])
    .mockResolvedValueOnce(["wrong_tool"]);

  await expect(
    runSetup(manualDestinationSetupOptions(setup, manualTwoHttpInput(setup), capture())),
  ).rejects.toThrow("Wrapper verification returned unexpected tools");

  expect(await loadRoutes(setup.home)).toEqual([]);
  for (const path of setup.policyPaths.slice(0, 2)) expect(await exists(path)).toBe(false);
  expect(await readFile(setup.claudePath, "utf8")).toBe('{"mcpServers": {}}\n');
  expect(await readFile(setup.codexPath, "utf8")).toBe("");
  for (const [adapterId, configPath] of [
    ["claude", setup.claudePath],
    ["codex", setup.codexPath],
  ] as const) {
    await expect(
      readRestoreState({ home: setup.home, adapterId, configPath, projectRoot: setup.root }),
    ).resolves.toBeUndefined();
  }
});

test("rejects Manual HTTP route-directory drift after Preview without overwriting it", async () => {
  const setup = await manualDestinationFixture();
  const owner = {
    adapterId: "codex",
    scope: "project" as const,
    configPath: resolve(join(setup.root, "unrelated.toml")),
    projectRoot: resolve(setup.root),
    serverName: "unrelated",
  };
  const externalRoute = serializeRoute({
    version: 1,
    owner,
    listenUrl: routeUrl(7319, owner),
    proxyArgs: [
      "--policy",
      resolve(join(setup.root, "unrelated-policy.yaml")),
      "--",
      "node",
      "server.mjs",
    ],
    environment: { set: {} },
  });
  const externalPath = routePath(setup.home, owner);
  setupFakes.discover = vi.fn(async () => ["read_file", "write_file"]);
  const output = capture((value) => {
    if (!value.includes("Apply these changes?")) return;
    mkdirSync(dirname(externalPath), { recursive: true, mode: 0o700 });
    writeFileSync(externalPath, externalRoute, { mode: 0o600 });
  });

  await expect(
    runSetup(manualDestinationSetupOptions(setup, manualTwoHttpInput(setup), output)),
  ).rejects.toThrow("Managed HTTP routes changed during setup");

  expect(await readFile(externalPath, "utf8")).toBe(externalRoute);
  for (const path of setup.policyPaths.slice(0, 2)) expect(await exists(path)).toBe(false);
  expect(await readFile(setup.claudePath, "utf8")).toBe('{"mcpServers": {}}\n');
  expect(await readFile(setup.codexPath, "utf8")).toBe("");
});

test("rejects a Manual HTTP route target that appears after Preview", async () => {
  const setup = await manualDestinationFixture();
  const owner = {
    adapterId: "claude",
    scope: "project" as const,
    configPath: resolve(setup.claudePath),
    projectRoot: resolve(setup.root),
    serverName: "files",
  };
  const target = routePath(setup.home, owner);
  const externalRoute = serializeRoute({
    version: 1,
    owner,
    listenUrl: routeUrl(7319, owner),
    proxyArgs: ["--policy", resolve(setup.policyPaths[0]!), "--", "node", "external.mjs"],
    environment: { set: {} },
  });
  setupFakes.discover = vi.fn(async () => ["read_file", "write_file"]);
  const output = capture((value) => {
    if (!value.includes("Apply these changes?")) return;
    mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
    writeFileSync(target, externalRoute, { mode: 0o600 });
  });

  await expect(
    runSetup(manualDestinationSetupOptions(setup, manualTwoHttpInput(setup), output)),
  ).rejects.toThrow("Managed HTTP routes changed during setup");

  expect(await readFile(target, "utf8")).toBe(externalRoute);
  expect(await readFile(setup.claudePath, "utf8")).toBe('{"mcpServers": {}}\n');
  expect(await readFile(setup.codexPath, "utf8")).toBe("");
});

test("keeps Manual HTTP route secrets out of persisted and displayed surfaces", async () => {
  const setup = await manualDestinationFixture();
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture();

  await runSetup({
    ...manualDestinationSetupOptions(
      setup,
      [
        "4\n",
        "remote\n",
        "http\n",
        "https://example.test/mcp\n",
        "X-Key=API_KEY\n",
        "\n",
        "bearer\n",
        "TOKEN\n",
        "2\n",
        "2\n",
        "1\n",
        "1\n",
        "yes\n",
        "all\n",
        "1\n",
        "yes\n",
      ],
      output,
    ),
    environment: {
      PATH: process.env.PATH,
      API_KEY: "header-secret-sentinel",
      TOKEN: "bearer-secret-sentinel",
    },
  });

  const route = (await loadRoutes(setup.home))[0]!;
  const surfaces = [
    route.snapshot.content,
    JSON.stringify(route.definition.proxyArgs),
    await readFile(setup.claudePath, "utf8"),
    output.text(),
  ].join("\n");
  expect(surfaces).toContain("X-Key=API_KEY");
  expect(surfaces).toContain("TOKEN");
  for (const sentinel of ["header-secret-sentinel", "bearer-secret-sentinel"]) {
    expect(surfaces).not.toContain(sentinel);
  }
});

test("keeps Manual HTTP OAuth tokens and master-key bytes out of every setup surface", async () => {
  const setup = await manualDestinationFixture();
  const keyPath = join(setup.root, "master.key");
  const keyBytes = Buffer.alloc(32, 7).toString("base64url");
  const serverUrl = "https://resource.example.test/mcp";
  await writeFile(keyPath, keyBytes, { mode: 0o600 });
  let profileId = "";
  setupFakes.login = vi.fn(async (options) => {
    profileId = options.input.metadata.profileId;
    const profile = exampleProfile(profileId, serverUrl, {
      metadata: options.input.metadata,
      accessToken: "oauth-access-secret-sentinel",
    });
    profile.credentials.tokens.refresh_token = "oauth-refresh-secret-sentinel";
    return profile;
  });
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture();
  const diagnostics = capture();

  await runSetup({
    ...manualDestinationSetupOptions(setup, manualHttpOAuthInput(serverUrl), output),
    error: diagnostics,
    environment: { PATH: process.env.PATH, [MASTER_KEY_FILE_ENV]: keyPath },
  });

  const route = (await loadRoutes(setup.home))[0]!;
  expect(route.definition.environment.set).toEqual({ [MASTER_KEY_FILE_ENV]: keyPath });
  const surfaces = [
    route.snapshot.content,
    JSON.stringify(route.definition.proxyArgs),
    await readFile(setup.claudePath, "utf8"),
    await readFile(join(setup.root, ".mcp-restrictor", "policies", "claude", "oauth.yaml"), "utf8"),
    await readFile(oauthProfilePath(setup.home, profileId), "utf8"),
    output.text(),
    diagnostics.text(),
  ].join("\n");
  for (const sentinel of [
    keyBytes,
    "oauth-access-secret-sentinel",
    "oauth-refresh-secret-sentinel",
  ]) {
    expect(surfaces).not.toContain(sentinel);
  }
});

test("installs mixed Manual STDIO and HTTP destinations atomically", async () => {
  const setup = await manualDestinationFixture();
  setupFakes.discover = vi
    .fn()
    .mockResolvedValueOnce(["read_file", "write_file"])
    .mockResolvedValueOnce(["read_file"])
    .mockResolvedValueOnce(["write_file"]);

  await runSetup(
    manualDestinationSetupOptions(
      setup,
      [
        "4\n",
        "files\n",
        "stdio\n",
        `${process.execPath}\n`,
        `${JSON.stringify([setup.fixture, JSON.stringify(["read_file", "write_file"])])}\n`,
        "API_KEY\n",
        "2,3\n",
        "1\n",
        "2\n",
        "1\n",
        "1\n",
        "1\n",
        "yes\n",
        "1\n",
        "1\n",
        "2\n",
        "1\n",
        "yes\n",
      ],
      capture(),
    ),
  );

  const routes = await loadRoutes(setup.home);
  expect(routes).toHaveLength(1);
  expect(routes[0]!.definition.owner.adapterId).toBe("codex");
  expect(JSON.parse(await readFile(setup.claudePath, "utf8")).mcpServers.files.command).toBe(
    setup.restrictor,
  );
  expect(await readFile(setup.codexPath, "utf8")).toContain(routes[0]!.definition.listenUrl);
});

test("rolls back mixed Manual STDIO and HTTP destinations when HTTP verification fails", async () => {
  const setup = await manualDestinationFixture();
  setupFakes.discover = vi
    .fn()
    .mockResolvedValueOnce(["read_file", "write_file"])
    .mockResolvedValueOnce(["read_file"])
    .mockResolvedValueOnce(["wrong_tool"]);

  await expect(
    runSetup(
      manualDestinationSetupOptions(
        setup,
        [
          "4\n",
          "files\n",
          "stdio\n",
          `${process.execPath}\n`,
          `${JSON.stringify([setup.fixture, JSON.stringify(["read_file", "write_file"])])}\n`,
          "API_KEY\n",
          "2,3\n",
          "1\n",
          "2\n",
          "1\n",
          "1\n",
          "1\n",
          "yes\n",
          "1\n",
          "1\n",
          "2\n",
          "1\n",
          "yes\n",
        ],
        capture(),
      ),
    ),
  ).rejects.toThrow("Wrapper verification returned unexpected tools");

  expect(await loadRoutes(setup.home)).toEqual([]);
  for (const path of setup.policyPaths.slice(0, 2)) expect(await exists(path)).toBe(false);
  expect(await readFile(setup.claudePath, "utf8")).toBe('{"mcpServers": {}}\n');
  expect(await readFile(setup.codexPath, "utf8")).toBe("");
  for (const [adapterId, configPath] of [
    ["claude", setup.claudePath],
    ["codex", setup.codexPath],
  ] as const) {
    await expect(
      readRestoreState({ home: setup.home, adapterId, configPath, projectRoot: setup.root }),
    ).resolves.toBeUndefined();
  }
});

test.each(["matched configuration", "adapter result", "duplicate supported"] as const)(
  "rolls back Manual installation when reloading reports conflicting same-name ownership from %s",
  async (ownership) => {
    const root = await temporaryDirectory();
    const home = join(root, "home");
    const configPath = join(root, "shadow.json");
    await writeFile(configPath, "{}\n");
    const adapter = defineClientAdapter({
      apiVersion: 1,
      id: "shadow",
      label: "Shadow",
      async load(context, host) {
        const snapshot = await host.readConfig(configPath);
        if (!snapshot) throw new Error("missing test configuration");
        const installed = snapshot.content === "installed\n";
        const servers = installed
          ? Array.from({ length: ownership === "duplicate supported" ? 2 : 1 }, () => ({
              client: "shadow",
              scope: "project" as const,
              name: "files",
              configPath,
              source: {
                kind: "stdio" as const,
                command: process.execPath,
                args: [],
                envNames: [],
              },
              upstream: { kind: "stdio" as const, command: process.execPath, args: [] },
              wrapperEnvironment: {},
              original: {},
              managedPolicyPath: join(
                context.projectRoot,
                ".mcp-restrictor",
                "policies",
                "shadow",
                "files.yaml",
              ),
            }))
          : [];
        return {
          configurations: [
            {
              config: {
                client: "shadow",
                scope: "project" as const,
                path: configPath,
                source: snapshot.content,
                servers,
                unsupported:
                  installed && ownership === "matched configuration"
                    ? [
                        {
                          client: "shadow",
                          scope: "project" as const,
                          name: "files",
                          configPath,
                          reason: "shadowed after installation",
                        },
                      ]
                    : [],
              },
              snapshot,
            },
          ],
          unsupported:
            installed && ownership === "adapter result"
              ? [
                  {
                    client: "shadow",
                    scope: "project" as const,
                    name: "files",
                    configPath,
                    reason: "shadowed after installation",
                  },
                ]
              : [],
        };
      },
      render(config) {
        return config.source;
      },
      install() {
        return "installed\n";
      },
      installHttp() {
        return "installed\n";
      },
      restore() {
        return "{}\n";
      },
    });
    setupFakes.discover = vi.fn(async () => ["read_file"]);

    await expect(
      runSetup({
        input: Readable.from([
          "2\n",
          "files\n",
          "stdio\n",
          `${process.execPath}\n`,
          "[]\n",
          "\n",
          "2\n",
          "2\n",
          "1\n",
          "1\n",
          "yes\n",
          "all\n",
          "1\n",
          "yes\n",
        ]),
        output: capture(),
        error: capture(),
        interactive: true,
        cwd: root,
        home,
        environment: { PATH: process.env.PATH },
        restrictor: { command: process.execPath, argsPrefix: [] },
        adapters: [adapter],
      }),
    ).rejects.toThrow("Installed client configuration verification failed");

    expect(await readFile(configPath, "utf8")).toBe("{}\n");
    expect(await exists(join(root, ".mcp-restrictor", "policies", "shadow", "files.yaml"))).toBe(
      false,
    );
    expect(await loadRoutes(home)).toEqual([]);
  },
);

test("does not install selected Manual destinations after selected config drift", async () => {
  const setup = await manualDestinationFixture();
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture((value) => {
    if (value.includes("Apply these changes?")) {
      writeFileSync(setup.codexPath, "mcp_oauth_callback_port = 1\n");
    }
  });

  await expect(
    runSetup(manualDestinationSetupOptions(setup, manualDestinationInput(setup.fixture), output)),
  ).rejects.toThrow("Selected destination changed during setup; rerun setup");

  expect(await readFile(setup.codexPath, "utf8")).toBe("mcp_oauth_callback_port = 1\n");
  expect(await readFile(setup.claudePath, "utf8")).toBe('{"mcpServers": {}}\n');
  expect(await readFile(setup.openCodePath, "utf8")).toBe("{}\n");
  for (const path of setup.policyPaths) expect(await exists(path)).toBe(false);
});

test("does not install selected Manual destinations when a target policy appears after Destination", async () => {
  const setup = await manualDestinationFixture();
  const externalPolicy =
    "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: external\n  deny: []\n";
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture((value) => {
    if (value.includes("Apply these changes?")) {
      mkdirSync(dirname(setup.policyPaths[1]!), { recursive: true });
      writeFileSync(setup.policyPaths[1]!, externalPolicy);
    }
  });

  await expect(
    runSetup(manualDestinationSetupOptions(setup, manualDestinationInput(setup.fixture), output)),
  ).rejects.toThrow("Selected destination changed during setup; rerun setup");

  expect(await readFile(setup.policyPaths[1]!, "utf8")).toBe(externalPolicy);
  expect(await exists(setup.policyPaths[0]!)).toBe(false);
  expect(await exists(setup.policyPaths[2]!)).toBe(false);
  expect(await readFile(setup.claudePath, "utf8")).toBe('{"mcpServers": {}}\n');
  expect(await readFile(setup.codexPath, "utf8")).toBe("");
  expect(await readFile(setup.openCodePath, "utf8")).toBe("{}\n");
});

test("rechecks an existing policy selected independently for Manual destinations", async () => {
  const setup = await manualDestinationFixture();
  const activePolicy =
    "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n  deny: []\n";
  for (const path of setup.policyPaths) {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, activePolicy);
  }
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture((value) => {
    if (value.includes("Apply these changes?")) {
      writeFileSync(setup.policyPaths[1]!, activePolicy.replace("read_file", "changed_tool"));
    }
  });

  await expect(
    runSetup(
      manualDestinationSetupOptions(
        setup,
        manualDestinationInput(setup.fixture, { selectedPolicy: true }),
        output,
      ),
    ),
  ).rejects.toThrow("Existing policy changed during setup; rerun setup");

  expect(await readFile(setup.policyPaths[1]!, "utf8")).toContain("changed_tool");
  for (const path of [setup.policyPaths[0]!, setup.policyPaths[2]!]) {
    expect(await readFile(path, "utf8")).toBe(activePolicy);
  }
  expect(await readFile(setup.claudePath, "utf8")).toBe('{"mcpServers": {}}\n');
  expect(await readFile(setup.codexPath, "utf8")).toBe("");
  expect(await readFile(setup.openCodePath, "utf8")).toBe("{}\n");
});

test("preserves independent existing Manual destination policies byte-for-byte", async () => {
  const setup = await manualDestinationFixture();
  const activePolicy =
    "# preserve these bytes\nversion: 1\ndefault: deny\ntools:\n  allow:\n    - { name: read_file }\n  deny: []\n";
  for (const path of setup.policyPaths) {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, activePolicy);
  }
  setupFakes.discover = vi.fn(async () => ["read_file"]);

  await runSetup(
    manualDestinationSetupOptions(
      setup,
      manualDestinationInput(setup.fixture, { selectedPolicy: true }),
      capture(),
    ),
  );

  for (const path of setup.policyPaths) expect(await readFile(path, "utf8")).toBe(activePolicy);
});

test("rechecks a saved policy selected independently for Manual destinations", async () => {
  const setup = await manualDestinationFixture();
  const savedPolicy =
    "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n  deny: []\n";
  const savedPaths = [
    join(setup.root, ".mcp-restrictor", "saved-policies", "claude", "files.d", "read-only.yaml"),
    join(setup.home, ".mcp-restrictor", "saved-policies", "codex", "files.d", "read-only.yaml"),
    join(setup.root, ".mcp-restrictor", "saved-policies", "opencode", "files.d", "read-only.yaml"),
  ];
  for (const path of savedPaths) {
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    await chmod(dirname(path), 0o700);
    await writeFile(path, savedPolicy, { mode: 0o600 });
    await chmod(path, 0o600);
  }
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture((value) => {
    if (value.includes("Apply these changes?")) {
      writeFileSync(savedPaths[1]!, savedPolicy.replace("read_file", "changed_tool"));
    }
  });

  await expect(
    runSetup(
      manualDestinationSetupOptions(
        setup,
        manualDestinationInput(setup.fixture, { selectedPolicy: true }),
        output,
      ),
    ),
  ).rejects.toThrow("Saved Tools & Policy changed during setup");

  expect(await readFile(savedPaths[1]!, "utf8")).toContain("changed_tool");
  for (const path of setup.policyPaths) expect(await exists(path)).toBe(false);
});

test.each([0, 1, 2] as const)(
  "rolls back all Manual destination writes when wrapper verification %s fails",
  async (failedWrapper) => {
    const setup = await manualDestinationFixture();
    const configPaths = [setup.claudePath, setup.codexPath, setup.openCodePath];
    const before = await Promise.all(
      configPaths.map(async (path) => ({
        path,
        content: await readFile(path, "utf8"),
        mode: (await lstat(path)).mode,
      })),
    );
    let wrapperCalls = 0;
    setupFakes.discover = vi.fn(async (configured: UpstreamConfig) => {
      if (configured.kind === "stdio" && configured.args?.[0] === "--policy") {
        const index = wrapperCalls++;
        return index === failedWrapper ? ["wrong_tool"] : ["read_file"];
      }
      return ["read_file"];
    });

    await expect(
      runSetup(
        manualDestinationSetupOptions(setup, manualDestinationInput(setup.fixture), capture()),
      ),
    ).rejects.toThrow("Wrapper verification returned unexpected tools");

    expect(wrapperCalls).toBe(failedWrapper + 1);
    for (const expected of before) {
      expect(await readFile(expected.path, "utf8")).toBe(expected.content);
      expect((await lstat(expected.path)).mode).toBe(expected.mode);
    }
    for (const path of setup.policyPaths) expect(await exists(path)).toBe(false);
    for (const [adapterId, configPath] of [
      ["claude", setup.claudePath],
      ["codex", setup.codexPath],
      ["opencode", setup.openCodePath],
    ] as const) {
      await expect(
        readRestoreState({ home: setup.home, adapterId, configPath, projectRoot: setup.root }),
      ).resolves.toBeUndefined();
    }
  },
);

test("rolls back Manual destination writes when a later client config write fails", async () => {
  const setup = await manualDestinationFixture();
  const configPaths = [setup.claudePath, setup.codexPath, setup.openCodePath];
  const before = await Promise.all(
    configPaths.map(async (path) => ({
      path,
      content: await readFile(path, "utf8"),
      mode: (await lstat(path)).mode,
    })),
  );
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture((value) => {
    if (value.includes("Apply these changes?")) chmodSync(dirname(setup.codexPath), 0o500);
  });

  try {
    await expect(
      runSetup(manualDestinationSetupOptions(setup, manualDestinationInput(setup.fixture), output)),
    ).rejects.toThrow();
  } finally {
    chmodSync(dirname(setup.codexPath), 0o700);
  }

  for (const expected of before) {
    expect(await readFile(expected.path, "utf8")).toBe(expected.content);
    expect((await lstat(expected.path)).mode).toBe(expected.mode);
  }
  for (const path of setup.policyPaths) expect(await exists(path)).toBe(false);
  for (const [adapterId, configPath] of [
    ["claude", setup.claudePath],
    ["codex", setup.codexPath],
    ["opencode", setup.openCodePath],
  ] as const) {
    await expect(
      readRestoreState({ home: setup.home, adapterId, configPath, projectRoot: setup.root }),
    ).resolves.toBeUndefined();
  }
});

test("installs one Manual OAuth profile and UUID across all selected destinations", async () => {
  const setup = await manualDestinationFixture();
  const keyPath = join(setup.root, "master.key");
  const key = randomBytes(32).toString("base64url");
  const serverUrl = "https://resource.example.test/mcp";
  await writeFile(keyPath, key, { mode: 0o600 });
  let profileId = "";
  setupFakes.login = vi.fn(async (options) => {
    profileId = options.input.metadata.profileId;
    return exampleProfile(profileId, serverUrl, {
      metadata: options.input.metadata,
      accessToken: "manual-oauth-token",
    });
  });
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture();

  await runSetup({
    ...manualDestinationSetupOptions(setup, manualDestinationOAuthInput(serverUrl), output),
    environment: {
      PATH: process.env.PATH,
      [MASTER_KEY_FILE_ENV]: keyPath,
    },
  });

  expect(profileId).toMatch(UUID_V4);
  expect(setupFakes.login).toHaveBeenCalledTimes(1);
  const profilePath = oauthProfilePath(setup.home, profileId);
  expect(await readdir(dirname(profilePath))).toEqual([basename(profilePath)]);
  expect(await readFile(profilePath, "utf8")).not.toContain("manual-oauth-token");
  const sources = await Promise.all(
    [setup.claudePath, setup.codexPath, setup.openCodePath].map((path) => readFile(path, "utf8")),
  );
  for (const source of sources) {
    expect(source).toContain(profileId);
    expect(source).toContain(keyPath);
    expect(source).not.toContain("manual-oauth-token");
  }
  expect(output.text().split(`Changed: ${JSON.stringify(profilePath)}`).length - 1).toBe(1);
  expect(output.text()).not.toMatch(/^(command|args|environment):/m);
  expect(output.text()).not.toContain(key);
  expect(output.text()).not.toContain("manual-oauth-token");
});

test("rolls back Manual OAuth profile, saved policy, destinations, and restore state together", async () => {
  const setup = await manualDestinationFixture();
  const keyPath = join(setup.root, "master.key");
  const serverUrl = "https://resource.example.test/mcp";
  await writeFile(keyPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
  let profileId = "";
  setupFakes.login = vi.fn(async (options) => {
    profileId = options.input.metadata.profileId;
    return exampleProfile(profileId, serverUrl, {
      metadata: options.input.metadata,
      accessToken: "manual-oauth-token",
    });
  });
  setupFakes.discover = vi.fn(async (configured: UpstreamConfig) =>
    configured.kind === "stdio" ? ["wrong_tool"] : ["read_file"],
  );

  await expect(
    runSetup({
      ...manualDestinationSetupOptions(
        setup,
        manualDestinationOAuthInput(serverUrl, { savePolicy: true }),
        capture(),
      ),
      environment: { PATH: process.env.PATH, [MASTER_KEY_FILE_ENV]: keyPath },
    }),
  ).rejects.toThrow("Wrapper verification returned unexpected tools");

  expect(profileId).toMatch(UUID_V4);
  expect(await exists(oauthProfilePath(setup.home, profileId))).toBe(false);
  expect(
    await exists(
      join(setup.root, ".mcp-restrictor", "saved-policies", "manual", "oauth.d", "read-only.yaml"),
    ),
  ).toBe(false);
  for (const path of setup.policyPaths) expect(await exists(path)).toBe(false);
  for (const [path, source] of [
    [setup.claudePath, '{"mcpServers": {}}\n'],
    [setup.codexPath, ""],
    [setup.openCodePath, "{}\n"],
  ] as const) {
    expect(await readFile(path, "utf8")).toBe(source);
  }
  for (const [adapterId, configPath] of [
    ["claude", setup.claudePath],
    ["codex", setup.codexPath],
    ["opencode", setup.openCodePath],
  ] as const) {
    await expect(
      readRestoreState({ home: setup.home, adapterId, configPath, projectRoot: setup.root }),
    ).resolves.toBeUndefined();
  }
});

test("rejects an OAuth profile that appears after Manual destination preview", async () => {
  const setup = await manualDestinationFixture();
  const keyPath = join(setup.root, "master.key");
  const serverUrl = "https://resource.example.test/mcp";
  await writeFile(keyPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
  let profileId = "";
  setupFakes.login = vi.fn(async (options) => {
    profileId = options.input.metadata.profileId;
    return exampleProfile(profileId, serverUrl, { metadata: options.input.metadata });
  });
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture((value) => {
    if (value.includes("Apply these changes?")) {
      const profilePath = oauthProfilePath(setup.home, profileId);
      mkdirSync(dirname(profilePath), { recursive: true, mode: 0o700 });
      chmodSync(dirname(profilePath), 0o700);
      writeFileSync(profilePath, "external profile", { mode: 0o600 });
      chmodSync(profilePath, 0o600);
    }
  });

  await expect(
    runSetup({
      ...manualDestinationSetupOptions(setup, manualDestinationOAuthInput(serverUrl), output),
      environment: { PATH: process.env.PATH, [MASTER_KEY_FILE_ENV]: keyPath },
    }),
  ).rejects.toThrow();

  expect(profileId).toMatch(UUID_V4);
  expect(await readFile(oauthProfilePath(setup.home, profileId), "utf8")).toBe("external profile");
  for (const path of setup.policyPaths) expect(await exists(path)).toBe(false);
  expect(await readFile(setup.claudePath, "utf8")).toBe('{"mcpServers": {}}\n');
  expect(await readFile(setup.codexPath, "utf8")).toBe("");
  expect(await readFile(setup.openCodePath, "utf8")).toBe("{}\n");
});

test("prints Manual header and bearer source names under inherit without their values", async () => {
  const root = await temporaryDirectory();
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture();

  await runSetup({
    input: Readable.from([
      "4\n",
      "remote\n",
      "http\n",
      "https://example.test/mcp\n",
      "X-Key=API_KEY\n",
      "\n",
      "bearer\n",
      "TOKEN\n",
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
    home: join(root, "home"),
    environment: {
      PATH: process.env.PATH,
      API_KEY: "manual-header-secret",
      TOKEN: "manual-bearer-secret",
    },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(output.text()).toContain('environment: {"inherit":["API_KEY","TOKEN"],"set":{}}');
  expect(output.text()).not.toContain("manual-header-secret");
  expect(output.text()).not.toContain("manual-bearer-secret");
});

test("rolls back a Manual policy when exact wrapper verification differs", async () => {
  const root = await temporaryDirectory();
  setupFakes.discover = vi
    .fn()
    .mockResolvedValueOnce(["read_file"])
    .mockResolvedValueOnce(["wrong_tool"]);

  await expect(
    runSetup({
      input: Readable.from([
        "4\n",
        "remote\n",
        "http\n",
        "https://example.test/mcp\n",
        "\n",
        "none\n",
        "1\n",
        "1\n",
        "yes\n",
        "all\n",
        "1\n",
        "yes\n",
      ]),
      output: capture(),
      error: capture(),
      interactive: true,
      cwd: root,
      home: join(root, "home"),
      environment: { PATH: process.env.PATH },
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Wrapper verification returned unexpected tools");

  expect(await exists(join(root, ".mcp-restrictor", "policies", "manual", "remote.yaml"))).toBe(
    false,
  );
});

test("rolls back newly saved and active Manual policies when wrapper verification fails", async () => {
  const root = await temporaryDirectory();
  setupFakes.discover = vi
    .fn()
    .mockResolvedValueOnce(["read_file"])
    .mockResolvedValueOnce(["wrong_tool"]);
  const active = join(root, ".mcp-restrictor", "policies", "manual", "remote.yaml");
  const saved = join(
    root,
    ".mcp-restrictor",
    "saved-policies",
    "manual",
    "remote.d",
    "read-only.yaml",
  );
  const output = capture();

  await expect(
    runSetup({
      input: Readable.from([
        "4\n",
        "remote\n",
        "http\n",
        "https://example.test/mcp\n",
        "\n",
        "none\n",
        "1\n",
        "1\n",
        "yes\n",
        "all\n",
        "2\n",
        "read-only\n",
        "yes\n",
      ]),
      output,
      error: capture(),
      interactive: true,
      cwd: root,
      home: join(root, "home"),
      environment: { PATH: process.env.PATH },
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Wrapper verification returned unexpected tools");

  await expect(readFile(active)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(readFile(saved)).rejects.toMatchObject({ code: "ENOENT" });
  expect(output.text()).toContain("Save Tools & Policy?");
});

test("rejects Manual takeover when any restore-state record references its policy", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const policyPath = join(root, ".mcp-restrictor", "policies", "manual", "remote.yaml");
  const policy = "version: 1\ndefault: deny\ntools: { allow: [{ name: read_file }], deny: [] }\n";
  await mkdir(dirname(policyPath), { recursive: true });
  await writeFile(policyPath, policy, { mode: 0o600 });
  const configPath = join(root, "other-config.toml");
  const statePath = restoreStatePath(home, configPath);
  await mkdir(dirname(statePath), { recursive: true, mode: 0o700 });
  await chmod(dirname(statePath), 0o700);
  await writeFile(
    statePath,
    serializeRestoreState({
      version: 1,
      adapterId: "manual",
      configPath,
      servers: [
        {
          name: "remote",
          scope: "project",
          projectRoot: root,
          originalSource: "original",
          installedSource: "installed",
          policy: {
            path: policyPath,
            before: null,
            installed: policyFingerprint(policy, 0o600),
          },
        },
      ],
    }),
    { mode: 0o600 },
  );
  await chmod(statePath, 0o600);
  setupFakes.discover = vi.fn(async () => ["read_file"]);

  await expect(
    runSetup({
      input: Readable.from([
        "4\n",
        "remote\n",
        "http\n",
        "https://example.test/mcp\n",
        "\n",
        "none\n",
        "1\n",
        "1\n",
        "yes\n",
        "yes\n",
      ]),
      output: capture(),
      error: capture(),
      interactive: true,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH },
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Existing policy is referenced by another MCP restore state");

  expect(await readFile(policyPath, "utf8")).toBe(policy);
});

test("rejects Manual policy drift after selecting Existing policy", async () => {
  const root = await temporaryDirectory();
  const policyPath = join(root, ".mcp-restrictor", "policies", "manual", "remote.yaml");
  const policy = "version: 1\ndefault: deny\ntools: { allow: [{ name: read_file }], deny: [] }\n";
  await mkdir(dirname(policyPath), { recursive: true });
  await writeFile(policyPath, policy);
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture((value) => {
    if (value.includes("Apply these changes?")) {
      writeFileSync(policyPath, policy.replace("read_file", "other_tool"));
    }
  });

  await expect(
    runSetup({
      input: Readable.from([
        "4\n",
        "remote\n",
        "http\n",
        "https://example.test/mcp\n",
        "\n",
        "none\n",
        "1\n",
        "1\n",
        "yes\n",
        "yes\n",
      ]),
      output,
      error: capture(),
      interactive: true,
      cwd: root,
      home: join(root, "home"),
      environment: { PATH: process.env.PATH },
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Existing policy changed during setup; rerun setup");
});

test("Manual Configure new accepts an empty allowlist", async () => {
  const root = await temporaryDirectory();
  setupFakes.discover = vi.fn(async () => []);

  await runSetup({
    input: Readable.from([
      "4\n",
      "remote\n",
      "http\n",
      "https://example.test/mcp\n",
      "\n",
      "none\n",
      "1\n",
      "1\n",
      "yes\n",
      "none\n",
      "1\n",
      "yes\n",
    ]),
    output: capture(),
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(
    await readFile(join(root, ".mcp-restrictor", "policies", "manual", "remote.yaml"), "utf8"),
  ).toContain("allow: []");
});

test.each([
  [
    "endpoint no",
    [
      "4\n",
      "remote\n",
      "http\n",
      "https://example.test/mcp\n",
      "\n",
      "none\n",
      "1\n",
      "1\n",
      "no\n",
    ],
  ],
  [
    "final Apply no",
    [
      "4\n",
      "remote\n",
      "http\n",
      "https://example.test/mcp\n",
      "\n",
      "none\n",
      "1\n",
      "1\n",
      "yes\n",
      "all\n",
      "2\n",
      "read-only\n",
      "no\n",
    ],
  ],
  [
    "Tools & Policy EOF",
    ["4\n", "remote\n", "http\n", "https://example.test/mcp\n", "\n", "none\n", "1\n"],
  ],
] as const)("cancels Manual setup on %s without policy or client writes", async (_exit, input) => {
  const root = await temporaryDirectory();
  setupFakes.discover = vi.fn(async () => ["read_file"]);

  await runSetup({
    input: Readable.from(input),
    output: capture(),
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(await exists(join(root, ".mcp-restrictor", "policies", "manual", "remote.yaml"))).toBe(
    false,
  );
  expect(await exists(join(root, ".mcp.json"))).toBe(false);
  expect(await exists(join(root, ".codex", "config.toml"))).toBe(false);
  expect(
    await exists(
      join(root, ".mcp-restrictor", "saved-policies", "manual", "remote.d", "read-only.yaml"),
    ),
  ).toBe(false);
});

test("cancels Manual setup on SIGINT without writes", async () => {
  const root = await temporaryDirectory();
  const before = process.listenerCount("SIGINT");
  const input = Readable.from(
    (async function* () {
      yield "4\n";
      await new Promise<void>((resolveImmediate) => setImmediate(resolveImmediate));
      process.emit("SIGINT", "SIGINT");
    })(),
  );

  await runSetup({
    input,
    output: capture(),
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
  });

  expect(process.listenerCount("SIGINT")).toBe(before);
  expect(await exists(join(root, ".mcp-restrictor"))).toBe(false);
  expect(await exists(join(root, ".mcp.json"))).toBe(false);
  expect(await exists(join(root, ".codex", "config.toml"))).toBe(false);
});

test("rejects an invalid existing Manual policy before Connect", async () => {
  const root = await temporaryDirectory();
  const policyPath = join(root, ".mcp-restrictor", "policies", "manual", "remote.yaml");
  await mkdir(dirname(policyPath), { recursive: true });
  await writeFile(policyPath, "unmanaged");
  setupFakes.discover = vi.fn(async () => ["read_file"]);

  await expect(
    runSetup({
      input: Readable.from([
        "4\n",
        "remote\n",
        "http\n",
        "https://example.test/mcp\n",
        "\n",
        "none\n",
        "1\n",
        "1\n",
      ]),
      output: capture(),
      error: capture(),
      interactive: true,
      cwd: root,
      home: join(root, "home"),
      environment: { PATH: process.env.PATH },
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Saved Tools & Policy is invalid");

  expect(await readFile(policyPath, "utf8")).toBe("unmanaged");
});

test("preserves exact existing Manual policy bytes", async () => {
  const root = await temporaryDirectory();
  const policyPath = join(root, ".mcp-restrictor", "policies", "manual", "remote.yaml");
  const policy =
    "# keep exact\nversion: 1\ndefault: deny\ntools:\n  allow:\n    - { name: read_file }\n  deny: []\n";
  await mkdir(dirname(policyPath), { recursive: true });
  await writeFile(policyPath, policy);
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture();

  await runSetup({
    input: Readable.from([
      "4\n",
      "remote\n",
      "http\n",
      "https://example.test/mcp\n",
      "\n",
      "none\n",
      "1\n",
      "1\n",
      "yes\n",
      "yes\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(await readFile(policyPath, "utf8")).toBe(policy);
  expect(output.text()).not.toContain("Select allowed tools");
});

test("saved-name collision leaves Manual policies unchanged on cancellation", async () => {
  const root = await temporaryDirectory();
  const savedDirectory = join(root, ".mcp-restrictor", "saved-policies", "manual", "remote.d");
  const savedPath = join(savedDirectory, "read-only.yaml");
  const saved = "version: 1\ndefault: deny\ntools: { allow: [{ name: read_file }], deny: [] }\n";
  await mkdir(savedDirectory, { recursive: true, mode: 0o700 });
  await chmod(savedDirectory, 0o700);
  await writeFile(savedPath, saved, { mode: 0o600 });
  await chmod(savedPath, 0o600);
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  const output = capture();

  await runSetup({
    input: Readable.from([
      "4\n",
      "remote\n",
      "http\n",
      "https://example.test/mcp\n",
      "\n",
      "none\n",
      "1\n",
      "2\n",
      "yes\n",
      "all\n",
      "2\n",
      "read-only\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(await readFile(savedPath, "utf8")).toBe(saved);
  expect(await exists(join(root, ".mcp-restrictor", "policies", "manual", "remote.yaml"))).toBe(
    false,
  );
  expect(output.text()).toContain("Saved configuration already exists.");
});

test("transacts a Manual OAuth profile with its policy and prints only the fixed key path", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const keyPath = join(root, "keys", "master.key");
  const keyBytes = randomBytes(32).toString("base64url");
  await mkdir(dirname(keyPath), { recursive: true });
  await writeFile(keyPath, keyBytes, { mode: 0o600 });
  const serverUrl = "https://example.test/mcp";
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  setupFakes.login = vi.fn(async ({ input }: any) =>
    exampleProfile(input.metadata.profileId, serverUrl, {
      metadata: input.metadata,
      accessToken: "manual-access-token",
    }),
  );
  const output = capture();

  await runSetup({
    input: Readable.from([
      "4\n",
      "oauth\n",
      "http\n",
      `${serverUrl}\n`,
      "\n",
      "oauth\n",
      "\n",
      "read write\n",
      "\n",
      "\n",
      "\n",
      "\n",
      "\n",
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
    environment: { PATH: process.env.PATH, [MASTER_KEY_FILE_ENV]: join("keys", "master.key") },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  const profileFiles = await import("node:fs/promises").then(({ readdir }) =>
    readdir(join(home, ".mcp-restrictor", "oauth")),
  );
  expect(profileFiles).toHaveLength(1);
  const profilePath = join(home, ".mcp-restrictor", "oauth", profileFiles[0]!);
  expect(await readFile(profilePath, "utf8")).not.toContain("manual-access-token");
  const text = output.text();
  expect(text).toContain(
    `environment: ${JSON.stringify({ inherit: [], set: { [MASTER_KEY_FILE_ENV]: keyPath } })}`,
  );
  expect(text).not.toContain(keyBytes);
  expect(text).not.toContain("manual-access-token");
  const argsLine = text.split("\n").find((line) => line.startsWith("args: "));
  expect(argsLine).not.toContain(keyPath);
});

test("rolls back Manual OAuth, saved, and active policy writes together", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const keyPath = join(root, "master.key");
  const serverUrl = "https://example.test/mcp";
  await writeFile(keyPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
  setupFakes.discover = vi
    .fn()
    .mockResolvedValueOnce(["read_file"])
    .mockResolvedValueOnce(["wrong_tool"]);
  setupFakes.login = vi.fn(async ({ input }: any) =>
    exampleProfile(input.metadata.profileId, serverUrl, {
      metadata: input.metadata,
      accessToken: "manual-access-token",
    }),
  );

  await expect(
    runSetup({
      input: Readable.from([
        "4\n",
        "oauth\n",
        "http\n",
        `${serverUrl}\n`,
        "\n",
        "oauth\n",
        "\n",
        "\n",
        "\n",
        "\n",
        "\n",
        "\n",
        "\n",
        "1\n",
        "1\n",
        "yes\n",
        "all\n",
        "2\n",
        "read-only\n",
        "yes\n",
      ]),
      output: capture(),
      error: capture(),
      interactive: true,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH, [MASTER_KEY_FILE_ENV]: keyPath },
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Wrapper verification returned unexpected tools");

  expect(await readdir(join(home, ".mcp-restrictor", "oauth"))).toEqual([]);
  expect(await exists(join(root, ".mcp-restrictor", "policies", "manual", "oauth.yaml"))).toBe(
    false,
  );
  expect(
    await exists(
      join(root, ".mcp-restrictor", "saved-policies", "manual", "oauth.d", "read-only.yaml"),
    ),
  ).toBe(false);
});

test("rejects Manual saved-policy drift before installing active or OAuth writes", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const keyPath = join(root, "master.key");
  const serverUrl = "https://example.test/mcp";
  const savedDirectory = join(root, ".mcp-restrictor", "saved-policies", "manual", "oauth.d");
  const savedPath = join(savedDirectory, "read-only.yaml");
  const savedPolicy =
    "version: 1\ndefault: deny\ntools: { allow: [{ name: read_file }], deny: [] }\n";
  const changedPolicy = savedPolicy.replace("read_file", "other_tool");
  await writeFile(keyPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
  await mkdir(savedDirectory, { recursive: true, mode: 0o700 });
  await chmod(savedDirectory, 0o700);
  await writeFile(savedPath, savedPolicy, { mode: 0o600 });
  await chmod(savedPath, 0o600);
  setupFakes.discover = vi.fn(async () => ["read_file"]);
  setupFakes.login = vi.fn(async ({ input }: any) =>
    exampleProfile(input.metadata.profileId, serverUrl, {
      metadata: input.metadata,
      accessToken: "manual-access-token",
    }),
  );
  const output = capture((value) => {
    if (value.includes("Apply these changes?")) writeFileSync(savedPath, changedPolicy);
  });

  await expect(
    runSetup({
      input: Readable.from([
        "4\n",
        "oauth\n",
        "http\n",
        `${serverUrl}\n`,
        "\n",
        "oauth\n",
        "\n",
        "\n",
        "\n",
        "\n",
        "\n",
        "\n",
        "\n",
        "1\n",
        "1\n",
        "yes\n",
        "yes\n",
      ]),
      output,
      error: capture(),
      interactive: true,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH, [MASTER_KEY_FILE_ENV]: keyPath },
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Saved Tools & Policy changed during setup");

  expect(await readFile(savedPath, "utf8")).toBe(changedPolicy);
  expect(await exists(join(root, ".mcp-restrictor", "policies", "manual", "oauth.yaml"))).toBe(
    false,
  );
  await expect(readdir(join(home, ".mcp-restrictor", "oauth"))).rejects.toMatchObject({
    code: "ENOENT",
  });
});

test("cancels Manual OAuth login without profile, policy, or client writes", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const keyPath = join(root, "master.key");
  await writeFile(keyPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
  setupFakes.login = vi.fn(async () => {
    throw new DOMException("Aborted", "AbortError");
  });

  await runSetup({
    input: Readable.from([
      "4\n",
      "oauth\n",
      "http\n",
      "https://example.test/mcp\n",
      "\n",
      "oauth\n",
      "\n",
      "\n",
      "\n",
      "\n",
      "\n",
      "\n",
      "\n",
      "1\n",
      "1\n",
      "yes\n",
    ]),
    output: capture(),
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { PATH: process.env.PATH, [MASTER_KEY_FILE_ENV]: keyPath },
  });

  expect(await exists(join(root, ".mcp-restrictor", "policies", "manual", "oauth.yaml"))).toBe(
    false,
  );
  expect(await exists(join(home, ".mcp-restrictor", "oauth"))).toBe(false);
  expect(await exists(join(root, ".mcp.json"))).toBe(false);
  expect(await exists(join(root, ".codex", "config.toml"))).toBe(false);
});

test("retries invalid selections and accepts an empty tool allowlist", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const output = capture();

  await runSetup({
    ...setupOptions(
      setup,
      ["9\n", "2\n", "0\n", "all\n", "1\n", "yes\n", "9\n", "none\n", "1\n", "yes\n"],
      output,
    ),
    restrictor: {
      command: process.execPath,
      argsPrefix: [setup.fixture, JSON.stringify([])],
    },
  });

  expect(output.text().match(/Invalid selection/g)?.length).toBeGreaterThanOrEqual(3);
  expect(await readFile(setup.policyPath, "utf8")).toContain("allow: []");
});

test("prints all unsupported entries and exits without writes", async () => {
  const root = await temporaryDirectory();
  const configPath = join(root, ".codex", "config.toml");
  const source = `[mcp_servers.disabled]\ncommand = "node"\nenabled = false\n`;
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, source);
  const output = capture();

  await runSetup({
    input: Readable.from(["2\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
  });

  expect(output.text()).toContain("Unsupported");
  expect(output.text()).toContain("Codex / disabled");
  expect(output.text()).toContain(JSON.stringify("disabled server is not supported"));
  expect(output.text()).toContain("No supported MCP servers found");
  expect(await readFile(configPath, "utf8")).toBe(source);
});

test("keeps duplicate user/project identities separate and writes each config once", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const codexHome = join(home, "codex-home");
  const fixture = await writeUpstreamFixture(root);
  const userConfig = join(codexHome, "config.toml");
  const projectConfig = join(root, ".codex", "config.toml");
  await Promise.all([
    mkdir(dirname(userConfig), { recursive: true }),
    mkdir(dirname(projectConfig), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(userConfig, stdioServer("same", fixture, ["read_file"])),
    writeFile(
      projectConfig,
      [
        stdioServer("same", fixture, ["read_file"]),
        stdioServer("second", fixture, ["read_file"]),
      ].join("\n"),
    ),
  ]);
  const output = capture();

  await runSetup({
    input: Readable.from([
      "2\n",
      "all\n",
      "1\n",
      "yes\n",
      "all\n",
      "1\n",
      "1\n",
      "yes\n",
      "all\n",
      "1\n",
      "1\n",
      "yes\n",
      "all\n",
      "1\n",
      "yes\n",
      "all\n",
      "yes\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { CODEX_HOME: codexHome, PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(output.text()).toContain("Codex / same (user, stdio");
  expect(output.text()).toContain("Codex / same (project, stdio");
  expect(
    (await readFile(userConfig, "utf8")).match(new RegExp(escapeRegex(cli), "g")),
  ).toHaveLength(1);
  expect(
    (await readFile(projectConfig, "utf8")).match(new RegExp(escapeRegex(cli), "g")),
  ).toHaveLength(2);
  expect(await exists(join(home, ".mcp-restrictor", "policies", "codex", "same.yaml"))).toBe(true);
  expect(await exists(join(root, ".mcp-restrictor", "policies", "codex", "same.yaml"))).toBe(true);
});

test("aborts a same-length config mutation during tools/list before confirmation", async () => {
  const root = await temporaryDirectory();
  const fixture = await writeUpstreamFixture(root);
  const configPath = join(root, ".codex", "config.toml");
  const source = `${stdioServer("files", fixture, ["read_file"], { mode: "mutate", target: configPath })}\n# marker A\n`;
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, source);
  const output = capture();

  await expect(
    runSetup({
      input: Readable.from(["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n"]),
      output,
      error: capture(),
      interactive: true,
      cwd: root,
      home: join(root, "home"),
      environment: { PATH: process.env.PATH },
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Client configuration changed during setup; rerun setup");

  const changed = await readFile(configPath, "utf8");
  expect(changed).toContain("# marker B");
  expect(changed).toHaveLength(source.length);
  expect(output.text()).not.toContain("Apply these changes");
  expect(await exists(join(root, ".mcp-restrictor", "policies", "codex", "files.yaml"))).toBe(
    false,
  );
});

test("redacts caught upstream errors and control-bearing names", async () => {
  const root = await temporaryDirectory();
  const fixture = await writeUpstreamFixture(root);
  const configPath = join(root, ".codex", "config.toml");
  const name = "bad\u001b\r\nserver";
  const source = stdioServer(name, fixture, [], {
    mode: "error",
    env: { ERROR_SECRET: "upstream-credential-value" },
  });
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, source);
  const output = capture();

  const failure = await runSetup({
    input: Readable.from(["2\n", "all\n", "1\n", "yes\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
  }).catch((error: unknown) => error);

  expect(failure).toBeInstanceOf(Error);
  expect((failure as Error).message).toContain("Tool discovery failed for");
  expect((failure as Error).message).toContain(JSON.stringify(name));
  expect((failure as Error).message).not.toContain("upstream-credential-value");
  expect(output.text()).not.toContain("upstream-credential-value");
  expect(output.text()).not.toContain("\u001b");
  expect(output.text()).not.toContain("\r");
  expect(await readFile(configPath, "utf8")).toBe(source);
});

test("suppresses configured secrets written to upstream stderr", async () => {
  const root = await temporaryDirectory();
  const fixture = await writeUpstreamFixture(root);
  const configPath = join(root, ".codex", "config.toml");
  const source = stdioServer("files", fixture, ["read_file"], {
    mode: "stderr",
    env: { ERROR_SECRET: "stderr-credential-value" },
  });
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, source);
  const output = capture();
  const error = capture();

  await runSetup({
    input: Readable.from(["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"]),
    output,
    error,
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(output.text()).not.toContain("stderr-credential-value");
  expect(error.text()).not.toContain("stderr-credential-value");
  expect(error.text()).toBe("Upstream diagnostics suppressed during setup.\n");
  expect(output.text()).toContain("Setup complete");
});

test("uses an existing unmanaged policy as-is", async () => {
  const setup = await simpleCodexProject(["read_file", "write_file"]);
  const policy =
    "# keep this exact source\nversion: 1\ndefault: allow\ntools:\n  allow: []\n  deny:\n    - name: write_file\n";
  await mkdir(dirname(setup.policyPath), { recursive: true });
  await writeFile(setup.policyPath, policy);
  const output = capture();

  await runSetup({
    ...setupOptions(setup, ["2\n", "all\n", "1\n", "yes\n", "yes\n"], output),
    restrictor: {
      command: process.execPath,
      argsPrefix: [setup.fixture, JSON.stringify(["read_file"])],
    },
  });

  expect(await readFile(setup.policyPath, "utf8")).toBe(policy);
  expect(await readFile(setup.configPath, "utf8")).not.toBe(setup.source);
  expect(output.text()).not.toContain("Select allowed tools");
});

test("rejects an invalid existing policy without leaking its source", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const sentinel = "private-policy-sentinel";
  const policy = `${sentinel}: [`;
  await mkdir(dirname(setup.policyPath), { recursive: true });
  await writeFile(setup.policyPath, policy);
  const output = capture();

  const failure = await runSetup({
    ...setupOptions(setup, ["2\n", "all\n", "1\n"], output),
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  }).catch((error: unknown) => error);

  expect(failure).toBeInstanceOf(Error);
  expect((failure as Error).message).toBe("Saved Tools & Policy is invalid");
  expect((failure as Error).message).not.toContain(sentinel);
  expect(output.text()).not.toContain(sentinel);
  expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
  expect(await readFile(setup.policyPath, "utf8")).toBe(policy);
});

test.each(["1", "2"])(
  "rejects invalid UTF-8 in an existing policy before action %s",
  async (action) => {
    const setup = await simpleCodexProject(["read_file"]);
    const sentinel = "private-policy-sentinel";
    const policy = Buffer.concat([
      Buffer.from(`# ${sentinel} `),
      Buffer.from([0xff]),
      Buffer.from(
        "\nversion: 1\ndefault: deny\ntools: { allow: [{ name: read_file }], deny: [] }\n",
      ),
    ]);
    await mkdir(dirname(setup.policyPath), { recursive: true });
    await writeFile(setup.policyPath, policy);
    const output = capture();

    const failure = await runSetup({
      ...setupOptions(setup, ["2\n", "all\n", "1\n", `${action}\n`], output),
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toBe(
      `Failed to read policy ${JSON.stringify(setup.policyPath)}`,
    );
    expect(output.text()).not.toContain(sentinel);
    expect(output.text()).not.toContain("Existing policy found:");
    expect(output.text()).not.toContain("Apply these changes");
    expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
    expect(await readFile(setup.policyPath)).toEqual(policy);
    expect(await exists(join(setup.home, ".mcp-restrictor", "restore"))).toBe(false);
    expect(await exists(join(setup.home, ".mcp-restrictor", "backups"))).toBe(false);
  },
);

test("replaces an unmanaged policy after backing it up", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const policy = "unmanaged policy";
  await mkdir(dirname(setup.policyPath), { recursive: true });
  await writeFile(setup.policyPath, policy);
  await chmod(setup.policyPath, 0o640);
  const output = capture();

  await runSetup({
    ...setupOptions(setup, ["2\n", "all\n", "2\n", "yes\n", "all\n", "1\n", "yes\n"], output),
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(await readFile(setup.policyPath, "utf8")).toContain("name: read_file");
  const restore = output
    .text()
    .split("\n")
    .find((line) => line.startsWith(`Restore ${JSON.stringify(setup.policyPath)} from `));
  expect(restore).toBeDefined();
  expect(await readFile(JSON.parse(restore!.slice(restore!.indexOf(" from ") + 6)), "utf8")).toBe(
    policy,
  );
  const stored = await readRestoreState({
    home: setup.home,
    adapterId: "codex",
    configPath: setup.configPath,
    projectRoot: setup.root,
  });
  expect(stored?.state.servers[0]?.policy.before).toEqual({ content: policy, mode: 0o640 });
});

test("rolls back an unmanaged policy takeover when wrapper verification fails", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const policy = "old opaque policy bytes";
  await mkdir(dirname(setup.policyPath), { recursive: true });
  await writeFile(setup.policyPath, policy);
  await chmod(setup.policyPath, 0o640);

  await expect(
    runSetup({
      ...setupOptions(setup, ["2\n", "all\n", "2\n", "yes\n", "all\n", "1\n", "yes\n"], capture()),
      restrictor: {
        command: process.execPath,
        argsPrefix: [setup.fixture, JSON.stringify(["wrong_tool"])],
      },
    }),
  ).rejects.toThrow("Wrapper verification returned unexpected tools");

  expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
  expect(await readFile(setup.policyPath, "utf8")).toBe(policy);
  expect((await lstat(setup.policyPath)).mode & 0o7777).toBe(0o640);
  await expect(
    readRestoreState({
      home: setup.home,
      adapterId: "codex",
      configPath: setup.configPath,
      projectRoot: setup.root,
    }),
  ).resolves.toBeUndefined();
});

test("cancels an unmanaged policy decision without writes", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const policy = "unmanaged policy";
  await mkdir(dirname(setup.policyPath), { recursive: true });
  await writeFile(setup.policyPath, policy);
  const output = capture();

  await runSetup({
    ...setupOptions(setup, ["2\n", "all\n"], output),
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
  expect(await readFile(setup.policyPath, "utf8")).toBe(policy);
  expect(await exists(join(setup.home, ".mcp-restrictor", "restore"))).toBe(false);
  expect(await exists(join(setup.home, ".mcp-restrictor", "backups"))).toBe(false);
  expect(output.text()).toContain("Setup cancelled");
  expect(output.text()).not.toContain("Apply these changes");
});

test("rejects unmanaged policy drift after the decision", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const policy = "version: 1\ndefault: deny\ntools: { allow: [{ name: read_file }], deny: [] }\n";
  await mkdir(dirname(setup.policyPath), { recursive: true });
  await writeFile(setup.policyPath, policy);
  const output = capture();
  const mutationOutput = new Writable({
    write(chunk, _encoding, callback) {
      output.write(chunk);
      if (chunk.toString().includes("Apply these changes?")) {
        writeFileSync(setup.policyPath, policy.replace("read_file", "other_tool"));
      }
      callback();
    },
  });

  await expect(
    runSetup({
      ...setupOptions(setup, ["2\n", "all\n", "1\n", "yes\n", "yes\n"], mutationOutput),
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Existing policy changed during setup; rerun setup");

  expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
  expect(output.text()).not.toContain("Setup complete");
});

test("rejects takeover when another restore-state record references the policy", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const policy = "version: 1\ndefault: deny\ntools: { allow: [{ name: read_file }], deny: [] }\n";
  await mkdir(dirname(setup.policyPath), { recursive: true });
  await writeFile(setup.policyPath, policy, { mode: 0o600 });
  const otherConfig = join(setup.root, "other-config.toml");
  const statePath = restoreStatePath(setup.home, otherConfig);
  await mkdir(dirname(statePath), { recursive: true, mode: 0o700 });
  await chmod(dirname(statePath), 0o700);
  await writeFile(
    statePath,
    serializeRestoreState({
      version: 1,
      adapterId: "codex",
      configPath: otherConfig,
      servers: [
        {
          name: "files",
          scope: "project",
          projectRoot: setup.root,
          originalSource: "original",
          installedSource: "installed",
          policy: {
            path: setup.policyPath,
            before: null,
            installed: policyFingerprint(policy, 0o600),
          },
        },
      ],
    }),
    { mode: 0o600 },
  );
  await chmod(statePath, 0o600);

  await expect(
    runSetup({
      ...setupOptions(setup, ["2\n", "all\n", "2\n", "yes\n", "all\n", "1\n", "yes\n"], capture()),
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Existing policy is referenced by another MCP restore state");

  expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
  expect(await readFile(setup.policyPath, "utf8")).toBe(policy);
});

test("allows takeover when the same restore-state record references the policy", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const policy = "version: 1\ndefault: deny\ntools: { allow: [], deny: [] }\n";
  await mkdir(dirname(setup.policyPath), { recursive: true });
  await writeFile(setup.policyPath, policy, { mode: 0o600 });
  const statePath = restoreStatePath(setup.home, setup.configPath);
  await mkdir(dirname(statePath), { recursive: true, mode: 0o700 });
  await chmod(dirname(statePath), 0o700);
  await writeFile(
    statePath,
    serializeRestoreState({
      version: 1,
      adapterId: "codex",
      configPath: setup.configPath,
      servers: [
        {
          name: "files",
          scope: "project",
          projectRoot: setup.root,
          originalSource: "previous original",
          installedSource: "previous installed",
          policy: {
            path: setup.policyPath,
            before: null,
            installed: policyFingerprint(policy, 0o600),
          },
        },
      ],
    }),
    { mode: 0o600 },
  );
  await chmod(statePath, 0o600);

  await runSetup({
    ...setupOptions(setup, ["2\n", "all\n", "2\n", "yes\n", "all\n", "1\n", "yes\n"], capture()),
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(await readFile(setup.policyPath, "utf8")).toContain("name: read_file");
  expect(await readFile(setup.configPath, "utf8")).not.toBe(setup.source);
});

test("quotes a control-bearing policy path when planning cannot snapshot it", async () => {
  const parent = await temporaryDirectory();
  const controlledSegment = "project\u001b\r\npath";
  const root = join(parent, controlledSegment);
  await mkdir(root);
  const setup = await simpleCodexProject(["read_file"], root);
  await mkdir(setup.policyPath, { recursive: true });
  const output = capture();
  const error = capture();

  const failure = await runSetup({
    ...setupOptions(setup, ["2\n", "all\n", "1\n", "yes\n", "1\n", "all\n"], output),
    error,
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  }).catch((caught: unknown) => caught);

  expect(failure).toBeInstanceOf(Error);
  expect((failure as Error).message).toContain(JSON.stringify(setup.policyPath));
  expect((failure as Error).message).not.toContain(controlledSegment);
  expect((failure as Error).message).not.toContain("\u001b");
  expect((failure as Error).message).not.toContain("\r");
  expect((failure as Error).message).not.toContain("\n");
  expect(`${output.text()}${error.text()}`).not.toContain(controlledSegment);
  expect(output.text()).toContain(JSON.stringify(root));
  expect(output.text()).not.toContain("\u001b");
  expect(output.text()).not.toContain("\r");
  expect(output.text()).not.toContain("Apply these changes");
});

test("keeps invalid-UTF-8 Current without reading bytes, connecting, or writing", async () => {
  const root = await temporaryDirectory();
  const fixture = await writeUpstreamFixture(root);
  const configPath = join(root, ".codex", "config.toml");
  const policyPath = join(root, ".mcp-restrictor", "policies", "codex", "files.yaml");
  const policyArgument = ".mcp-restrictor/policies/codex/files.yaml";
  const source = `[mcp_servers.files]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(policyArgument)}, "--", ${JSON.stringify(process.execPath)}, ${JSON.stringify(fixture)}, ${JSON.stringify(JSON.stringify(["read_file"]))}]\ncwd = ${JSON.stringify(root)}\n`;
  const invalidPolicy = Buffer.from([0xff, 0xfe, 0xfd]);
  await Promise.all([
    mkdir(dirname(configPath), { recursive: true }),
    mkdir(dirname(policyPath), { recursive: true }),
  ]);
  await Promise.all([writeFile(configPath, source), writeFile(policyPath, invalidPolicy)]);
  const discover = vi.fn();
  setupFakes.discover = discover;
  const before = await Promise.all([readFile(configPath), readFile(policyPath)]);
  const output = capture();

  await runSetup({
    input: Readable.from(["2\n", "all\n", "1\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
    restrictor: { command: "must-not-resolve", argsPrefix: [] },
  });

  expect(discover).not.toHaveBeenCalled();
  await expect(Promise.all([readFile(configPath), readFile(policyPath)])).resolves.toEqual(before);
  expect(output.text()).not.toMatch(
    /Connect to this upstream|Apply these changes|Backup directory/,
  );
});

test("keeps managed OAuth Current without reading its profile or connecting", async () => {
  const setup = await codexOAuthProject();
  const profileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  setup.source = `[mcp_servers.protected]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(setup.policyPath)}, "--upstream-http", ${JSON.stringify(setup.serverUrl)}, "--upstream-oauth-profile", "${profileId}"]\n\n[mcp_servers.protected.env]\n${MASTER_KEY_FILE_ENV} = ${JSON.stringify(setup.keyPath)}\n`;
  await mkdir(dirname(setup.policyPath), { recursive: true });
  await Promise.all([
    writeFile(setup.configPath, setup.source),
    writeFile(setup.policyPath, "not: [valid"),
  ]);
  let masterKeyReads = 0;
  Object.defineProperty(setup.environment, MASTER_KEY_FILE_ENV, {
    enumerable: true,
    get() {
      masterKeyReads += 1;
      return setup.keyPath;
    },
  });
  const discover = vi.fn();
  const login = vi.fn();
  const readSecret = vi.fn();
  setupFakes.discover = discover;
  setupFakes.login = login;
  const output = capture();
  const before = await Promise.all([
    readFile(setup.configPath, "utf8"),
    readFile(setup.policyPath, "utf8"),
  ]);

  await runSetup({
    ...oauthSetupOptions(setup, ["2\n", "all\n", "1\n"], output),
    restrictor: { command: "must-not-resolve", argsPrefix: [] },
    readSecret,
  });

  expect(masterKeyReads).toBe(0);
  expect(discover).not.toHaveBeenCalled();
  expect(login).not.toHaveBeenCalled();
  expect(readSecret).not.toHaveBeenCalled();
  await expect(
    Promise.all([readFile(setup.configPath, "utf8"), readFile(setup.policyPath, "utf8")]),
  ).resolves.toEqual(before);
  expect(output.text()).not.toMatch(
    /Connect to this upstream|Apply these changes|Backup directory/,
  );
});

test("only transacts changed servers when another selected server keeps Current", async () => {
  const root = await temporaryDirectory();
  const fixture = await writeUpstreamFixture(root);
  const configPath = join(root, ".codex", "config.toml");
  const currentPolicyPath = join(root, ".mcp-restrictor", "policies", "codex", "current.yaml");
  const currentPolicy = "not: [valid";
  const source = `[mcp_servers.current]\ncommand = "mcp-restrictor"\nargs = ["--policy", ".mcp-restrictor/policies/codex/current.yaml", "--", ${JSON.stringify(process.execPath)}, ${JSON.stringify(fixture)}, ${JSON.stringify(JSON.stringify(["read_file"]))}]\ncwd = ${JSON.stringify(root)}\n\n${stdioServer("changed", fixture, ["read_file"])}\n`;
  await Promise.all([
    mkdir(dirname(configPath), { recursive: true }),
    mkdir(dirname(currentPolicyPath), { recursive: true }),
  ]);
  await Promise.all([writeFile(configPath, source), writeFile(currentPolicyPath, currentPolicy)]);
  const output = capture();

  await runSetup({
    input: Readable.from(["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "1\n", "yes\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(output.text()).toContain("Preview:");
  expect(await readFile(currentPolicyPath, "utf8")).toBe(currentPolicy);
  expect(
    await readFile(join(root, ".mcp-restrictor", "policies", "codex", "changed.yaml"), "utf8"),
  ).toContain("name: read_file");
  const preview = output.text().slice(output.text().indexOf("Preview:"));
  expect(preview).not.toContain("Codex / current");
  expect(preview).toContain("Codex / changed");
});

test("selects a saved policy before Connect and copies its exact bytes", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const savedDirectory = join(setup.root, ".mcp-restrictor", "saved-policies", "codex", "files.d");
  const exactPolicy =
    "# preserve these bytes\nversion: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n      conditions:\n        - { argument: path, operator: startsWith, value: /workspace/ }\n  deny: []\n";
  await mkdir(savedDirectory, { recursive: true, mode: 0o700 });
  await chmod(savedDirectory, 0o700);
  await writeFile(join(savedDirectory, "read-only.yaml"), exactPolicy, { mode: 0o600 });
  await chmod(join(savedDirectory, "read-only.yaml"), 0o600);
  const output = capture();

  await runSetup({
    ...setupOptions(setup, ["2\n", "all\n", "1\n", "yes\n", "yes\n"], output),
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  const policyPrompt = output.text().indexOf("Select Tools & Policy");
  const connectPrompt = output.text().indexOf("Connect to this upstream?");
  expect(policyPrompt).toBeGreaterThanOrEqual(0);
  expect(connectPrompt).toBeGreaterThanOrEqual(0);
  expect(policyPrompt).toBeLessThan(connectPrompt);
  expect(await readFile(setup.policyPath, "utf8")).toBe(exactPolicy);
});

test("prints numbered policy-source and optional-save choices without a TTY", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const savedDirectory = join(setup.root, ".mcp-restrictor", "saved-policies", "codex", "files.d");
  await mkdir(savedDirectory, { recursive: true, mode: 0o700 });
  await chmod(savedDirectory, 0o700);
  await writeFile(
    join(savedDirectory, "read-only.yaml"),
    "version: 1\ndefault: deny\ntools: { allow: [{ name: read_file }], deny: [] }\n",
    { mode: 0o600 },
  );
  const output = capture();

  await runSetup({
    ...setupOptions(setup, ["2\n", "all\n", "2\n", "yes\n", "all\n", "1\n", "no\n"], output),
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(output.text()).toContain("1. read-only\n2. Configure new\nSelect Tools & Policy: ");
  expect(output.text()).toContain("1. No\n2. Yes\nSave Tools & Policy? ");
  expect(await exists(setup.policyPath)).toBe(false);
});

test("configures a new policy and optionally saves identical bytes", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const output = capture();

  await runSetup({
    ...setupOptions(
      setup,
      ["2\n", "all\n", "1\n", "yes\n", "all\n", "2\n", "read-only\n", "yes\n"],
      output,
    ),
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(
    await readFile(
      join(setup.root, ".mcp-restrictor", "saved-policies", "codex", "files.d", "read-only.yaml"),
      "utf8",
    ),
  ).toBe(await readFile(setup.policyPath, "utf8"));

  const prompts = [
    "Select Tools & Policy",
    "Upstream:",
    "Connect to this upstream?",
    "Tools for",
    "Save Tools & Policy?",
    "Preview:",
    "Apply these changes?",
  ].map((prompt) => output.text().indexOf(prompt));
  expect(prompts.every((index) => index >= 0)).toBe(true);
  expect(prompts).toEqual([...prompts].sort((left, right) => left - right));
});

test("does not create a saved policy directory before Apply", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const directory = join(setup.root, ".mcp-restrictor", "saved-policies", "codex", "files.d");

  await runSetup({
    ...setupOptions(
      setup,
      ["2\n", "all\n", "1\n", "yes\n", "all\n", "2\n", "read-only\n", "no\n"],
      capture(),
    ),
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  await expect(lstat(directory)).rejects.toMatchObject({ code: "ENOENT" });
});

test("rolls back saved and active policies when verification fails", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const saved = join(
    setup.root,
    ".mcp-restrictor",
    "saved-policies",
    "codex",
    "files.d",
    "read-only.yaml",
  );

  await expect(
    runSetup({
      ...setupOptions(
        setup,
        ["2\n", "all\n", "1\n", "yes\n", "all\n", "2\n", "read-only\n", "yes\n"],
        capture(),
      ),
      restrictor: {
        command: process.execPath,
        argsPrefix: [setup.fixture, JSON.stringify(["wrong_tool"])],
      },
    }),
  ).rejects.toThrow("Wrapper verification returned unexpected tools");

  await expect(readFile(saved)).rejects.toMatchObject({ code: "ENOENT" });
  await expect(readFile(setup.policyPath)).rejects.toMatchObject({ code: "ENOENT" });
  expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
});

test("updates an exactly owned managed policy without nesting another wrapper", async () => {
  const root = await temporaryDirectory();
  const fixture = await writeUpstreamFixture(root);
  const configPath = join(root, ".codex", "config.toml");
  const policyPath = join(root, ".mcp-restrictor", "policies", "codex", "files.yaml");
  const policyArgument = ".mcp-restrictor/policies/codex/files.yaml";
  const source = `[mcp_servers.files]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(policyArgument)}, "--", ${JSON.stringify(process.execPath)}, ${JSON.stringify(fixture)}, ${JSON.stringify(JSON.stringify(["read_file"]))}]\ncwd = ${JSON.stringify(root)}\n`;
  await Promise.all([
    mkdir(dirname(configPath), { recursive: true }),
    mkdir(dirname(policyPath), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(configPath, source),
    writeFile(policyPath, "version: 1\ndefault: deny\ntools:\n  allow: []\n  deny: []\n"),
  ]);

  await runSetup({
    input: Readable.from(["2\n", "all\n", "2\n", "yes\n", "all\n", "1\n", "yes\n"]),
    output: capture(),
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  const rendered = parse(await readFile(configPath, "utf8")) as {
    mcp_servers: { files: { command: string; args: string[] } };
  };
  expect(rendered.mcp_servers.files.command).toBe(process.execPath);
  expect(rendered.mcp_servers.files.args.filter((value) => value === cli)).toHaveLength(1);
  expect(rendered.mcp_servers.files.args.filter((value) => value === "--policy")).toHaveLength(1);
  expect(rendered.mcp_servers.files.args).not.toContain("mcp-restrictor");
  expect(await readFile(policyPath, "utf8")).toContain("name: read_file");
});

test("rejects managed policy drift before replacement", async () => {
  const root = await temporaryDirectory();
  const fixture = await writeUpstreamFixture(root);
  const configPath = join(root, ".codex", "config.toml");
  const policyPath = join(root, ".mcp-restrictor", "policies", "codex", "files.yaml");
  const policy = "version: 1\ndefault: deny\ntools:\n  allow: []\n  deny: []\n";
  const source = `[mcp_servers.files]\ncommand = "mcp-restrictor"\nargs = ["--policy", ".mcp-restrictor/policies/codex/files.yaml", "--", ${JSON.stringify(process.execPath)}, ${JSON.stringify(fixture)}, ${JSON.stringify(JSON.stringify(["read_file"]))}]\ncwd = ${JSON.stringify(root)}\n`;
  await Promise.all([
    mkdir(dirname(configPath), { recursive: true }),
    mkdir(dirname(policyPath), { recursive: true }),
  ]);
  await Promise.all([writeFile(configPath, source), writeFile(policyPath, policy)]);
  const output = capture();
  const mutationOutput = new Writable({
    write(chunk, _encoding, callback) {
      output.write(chunk);
      if (chunk.toString().includes("Apply these changes?")) {
        writeFileSync(policyPath, policy.replace("allow: []", "allow: [{ name: other_tool }]"));
      }
      callback();
    },
  });

  await expect(
    runSetup({
      input: Readable.from(["2\n", "all\n", "2\n", "yes\n", "all\n", "1\n", "yes\n"]),
      output: mutationOutput,
      error: capture(),
      interactive: true,
      cwd: root,
      home: join(root, "home"),
      environment: { PATH: process.env.PATH },
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Managed policy changed during setup; rerun setup");

  expect(await readFile(configPath, "utf8")).toBe(source);
  expect(await readFile(policyPath, "utf8")).not.toBe(policy);
});

test("rejects a managed policy target that appears after source selection", async () => {
  const root = await temporaryDirectory();
  const fixture = await writeUpstreamFixture(root);
  const configPath = join(root, ".codex", "config.toml");
  const policyPath = join(root, ".mcp-restrictor", "policies", "codex", "files.yaml");
  const source = `[mcp_servers.files]\ncommand = "mcp-restrictor"\nargs = ["--policy", ".mcp-restrictor/policies/codex/files.yaml", "--", ${JSON.stringify(process.execPath)}, ${JSON.stringify(fixture)}, ${JSON.stringify(JSON.stringify(["read_file"]))}]\ncwd = ${JSON.stringify(root)}\n`;
  const latePolicy =
    "version: 1\ndefault: deny\ntools: { allow: [{ name: late_tool }], deny: [] }\n";
  await Promise.all([
    mkdir(dirname(configPath), { recursive: true }),
    mkdir(dirname(policyPath), { recursive: true }),
  ]);
  await writeFile(configPath, source);
  const output = capture((value) => {
    if (value.includes("Apply these changes?")) writeFileSync(policyPath, latePolicy);
  });

  await expect(
    runSetup({
      input: Readable.from(["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"]),
      output,
      error: capture(),
      interactive: true,
      cwd: root,
      home: join(root, "home"),
      environment: { PATH: process.env.PATH },
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    }),
  ).rejects.toThrow("Managed policy changed during setup; rerun setup");

  expect(await readFile(configPath, "utf8")).toBe(source);
  expect(await readFile(policyPath, "utf8")).toBe(latePolicy);
});

test("rolls back config and policy when post-install tools differ exactly", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const output = capture();

  await expect(
    runSetup({
      ...setupOptions(setup, ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"], output),
      restrictor: {
        command: process.execPath,
        argsPrefix: [setup.fixture, JSON.stringify(["wrong_tool"])],
      },
    }),
  ).rejects.toThrow("Wrapper verification returned unexpected tools");

  expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
  expect(await exists(setup.policyPath)).toBe(false);
  expect(output.text()).not.toContain("Setup complete");
});

test("accepts an exact empty post-install tool list", async () => {
  const setup = await simpleCodexProject(["read_file"]);

  await runSetup({
    ...setupOptions(setup, ["2\n", "all\n", "1\n", "yes\n", "none\n", "1\n", "yes\n"], capture()),
    restrictor: {
      command: basename(process.execPath),
      argsPrefix: [setup.fixture, JSON.stringify([])],
    },
    environment: {
      PATH: `${dirname(process.execPath)}${delimiter}${process.env.PATH ?? ""}`,
    },
  });

  expect(await readFile(setup.policyPath, "utf8")).toContain("allow: []");
  expect(await readFile(setup.configPath, "utf8")).toContain(basename(process.execPath));
});

test("pins the resolved Restrictor executable against the selected server PATH", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const trustedDirectory = join(setup.root, "trusted-bin");
  const fakeDirectory = join(setup.root, "fake-bin");
  const trustedCommand = join(trustedDirectory, "mcp-restrictor");
  const fakeCommand = join(fakeDirectory, "mcp-restrictor");
  const fakeMarker = join(setup.root, "fake-ran");
  await Promise.all([mkdir(trustedDirectory), mkdir(fakeDirectory)]);
  await Promise.all([
    writeFile(
      trustedCommand,
      `#!${process.execPath}\nimport(${JSON.stringify(pathToFileURL(cli).href)});\n`,
      { mode: 0o755 },
    ),
    writeFile(
      fakeCommand,
      `#!${process.execPath}
const { writeFileSync } = require('node:fs');
const { createInterface } = require('node:readline');
writeFileSync(${JSON.stringify(fakeMarker)}, 'ran');
(async () => {
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (!('id' in request)) continue;
  const result = request.method === 'initialize'
    ? { protocolVersion: request.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'fake', version: '1' } }
    : { tools: [{ name: 'read_file', inputSchema: { type: 'object' } }] };
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }) + '\\n');
}
})();
`,
      { mode: 0o755 },
    ),
  ]);
  await writeFile(
    setup.configPath,
    stdioServer("files", setup.fixture, ["read_file"], {
      env: { PATH: `${fakeDirectory}${delimiter}${dirname(process.execPath)}` },
    }),
  );

  await runSetup({
    ...setupOptions(setup, ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"], capture()),
    environment: {
      PATH: `${trustedDirectory}${delimiter}${process.env.PATH ?? ""}`,
    },
  });

  const rendered = parse(await readFile(setup.configPath, "utf8")) as {
    mcp_servers: { files: { command: string } };
  };
  expect(await exists(fakeMarker)).toBe(false);
  expect(rendered.mcp_servers.files.command).toBe(trustedCommand);
});

test("resolves executables without invoking shell syntax", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const marker = join(setup.root, "shell-marker");
  const command = `missing-command;touch ${marker}`;

  await expect(
    runSetup({
      ...setupOptions(setup, ["2\n", "all\n", "1\n", "yes\n", "all\n"], capture()),
      restrictor: { command, argsPrefix: [] },
    }),
  ).rejects.toThrow("Restrictor executable was not found");

  expect(await exists(marker)).toBe(false);
  expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
});

test("refuses identical resolved user and project configuration paths", async () => {
  const root = await temporaryDirectory();
  const shared = join(root, ".codex", "config.toml");
  await mkdir(dirname(shared), { recursive: true });
  await writeFile(shared, '[mcp_servers.files]\ncommand = "node"\n');

  await expect(
    runSetup({
      input: Readable.from(["2\n"]),
      output: capture(),
      error: capture(),
      interactive: true,
      cwd: root,
      home: join(root, "home"),
      environment: { CODEX_HOME: join(root, ".codex"), PATH: process.env.PATH },
    }),
  ).rejects.toThrow("user and project configuration paths resolve to the same file");

  expect(await readFile(shared, "utf8")).toContain('command = "node"');
});

test("refuses different config paths that hard-link the same file before parsing", async () => {
  const root = await temporaryDirectory();
  const userConfig = join(root, "codex-home", "config.toml");
  const projectConfig = join(root, ".codex", "config.toml");
  await Promise.all([
    mkdir(dirname(userConfig), { recursive: true }),
    mkdir(dirname(projectConfig), { recursive: true }),
  ]);
  await writeFile(userConfig, "[malformed");
  await link(userConfig, projectConfig);

  await expect(
    runSetup({
      input: Readable.from(["2\n"]),
      output: capture(),
      error: capture(),
      interactive: true,
      cwd: root,
      home: join(root, "home"),
      environment: { CODEX_HOME: dirname(userConfig), PATH: process.env.PATH },
    }),
  ).rejects.toThrow("user and project configuration paths resolve to the same file");
});

test.each([
  ["no", ["2\n", "all\n", "1\n", "no\n"]],
  ["EOF", ["2\n", "all\n", "1\n"]],
] as const)(
  "previews a remote OAuth endpoint without secrets and cancels on %s before network or writes",
  async (_exit, answers) => {
    const setup = await codexOAuthProject({
      source: `mcp_oauth_callback_url = "https://callback.example/complete?tenant=secret-tenant"

[mcp_servers.familiar]
url = "https://different.example.test/mcp"
auth = "oauth"
scopes = ["write", "read"]
oauth_resource = "urn:example:resource"
http_headers = { "X-Static" = "literal-header-secret" }
env_http_headers = { "X-Env" = "REMOTE_HEADER" }
`,
      environment: { REMOTE_HEADER: "effective-header-secret" },
    });
    const discover = vi.fn(async () => ["must-not-connect"]);
    const login = vi.fn(async () =>
      exampleProfile("unexpected", "https://different.example.test/mcp"),
    );
    const readSecret = vi.fn(async () => "client-secret");
    setupFakes.discover = discover;
    setupFakes.login = login;
    const output = capture();

    await runSetup({
      ...oauthSetupOptions(setup, answers, output),
      readSecret,
    });

    expect(discover).not.toHaveBeenCalled();
    expect(login).not.toHaveBeenCalled();
    expect(readSecret).not.toHaveBeenCalled();
    expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
    expect(await exists(setup.policyPath)).toBe(false);
    expect(await exists(join(setup.home, ".mcp-restrictor", "oauth"))).toBe(false);
    const text = output.text();
    expect(text).toContain("Connect to this upstream?");
    expect(text).toContain("https://different.example.test/mcp");
    expect(text).toContain("transport=http");
    expect(text).toContain("auth=oauth");
    expect(text).toContain("X-Static");
    expect(text).toContain("X-Env");
    expect(text).toContain("REMOTE_HEADER");
    expect(text).toContain("client literal");
    expect(text).toContain(MASTER_KEY_FILE_ENV);
    expect(text).toContain("resource");
    expect(text).toContain("tenant");
    expect(text).not.toContain("secret-tenant");
    expect(text).not.toContain("literal-header-secret");
    expect(text).not.toContain("effective-header-secret");
    expect(text).not.toContain(setup.keyPath);
  },
);

test("checks explicit OAuth storage before a client-secret prompt or network request", async () => {
  const setup = await claudeOAuthProject({
    oauth: {
      clientId: "pre-registered-client",
      scopes: "read write",
      authServerMetadataUrl: "https://auth.example.test/.well-known/oauth-authorization-server",
    },
    keyContent: "not-a-master-key",
  });
  const discover = vi.fn(async () => ["must-not-connect"]);
  const login = vi.fn(async () => exampleProfile("unexpected", setup.serverUrl));
  const readSecret = vi.fn(async () => "must-not-prompt");
  setupFakes.discover = discover;
  setupFakes.login = login;

  await expect(
    runSetup({
      ...oauthSetupOptions(setup, ["1\n", "all\n", "1\n", "yes\n"], capture()),
      readSecret,
    }),
  ).rejects.toThrow(/master key/i);

  expect(readSecret).not.toHaveBeenCalled();
  expect(login).not.toHaveBeenCalled();
  expect(discover).not.toHaveBeenCalled();
  await expectOAuthSetupUnchanged(setup);
});

test("maps raw Ctrl-C during the default secret prompt to setup cancellation with an external signal", async () => {
  const setup = await claudeOAuthProject({ oauth: { clientId: "pre-registered-client" } });
  const external = new AbortController();
  let enteredRawMode!: () => void;
  const rawMode = new Promise<void>((resolveRawMode) => {
    enteredRawMode = resolveRawMode;
  });
  class SetupTtyInput extends PassThrough {
    readonly isTTY = true;
    isRaw = false;

    setRawMode(mode: boolean): this {
      this.isRaw = mode;
      if (mode) enteredRawMode();
      return this;
    }
  }
  const input = new SetupTtyInput();
  const output = capture();
  const result = runSetup({
    ...oauthSetupOptions(setup, [], output),
    input,
    signal: external.signal,
  });
  input.write("1\nall\n1\nyes\n");
  await rawMode;
  input.write("\x03");

  await expect(result).resolves.toBeUndefined();
  expect(output.text()).toContain("Setup cancelled.");
  expect(external.signal.aborted).toBe(false);
  await expectOAuthSetupUnchanged(setup);
});

class OAuthSetupTtyInput extends PassThrough {
  readonly isTTY = true;
  isRaw = false;
  readonly rawTransitions: boolean[] = [];

  setRawMode(mode: boolean): this {
    this.isRaw = mode;
    this.rawTransitions.push(mode);
    return this;
  }

  ref(): this {
    return this;
  }

  unref(): this {
    return this;
  }
}

const fullTtyOutput = () =>
  Object.assign(capture(), { isTTY: true as const, columns: 80, rows: 24 });
const waitForPrompt = (input: OAuthSetupTtyInput, count: number) =>
  vi.waitFor(() => expect(input.rawTransitions.filter(Boolean)).toHaveLength(count));

test("full-TTY imported OAuth client secret defaults to none without reading a secret", async () => {
  const setup = await claudeOAuthProject({ oauth: { clientId: "client-id" } });
  const input = new OAuthSetupTtyInput();
  const output = fullTtyOutput();
  const readSecret = vi.fn(async () => "must-not-read");
  let loginInput: Parameters<typeof loginOAuthProfile>[0]["input"] | undefined;
  setupFakes.login = vi.fn(async ({ input: captured }) => {
    loginInput = captured;
    throw new Error("stop after OAuth input capture");
  });

  const running = runSetup({
    ...oauthSetupOptions(setup, [], output),
    input,
    readSecret,
  });
  void running.catch(() => {});
  for (let prompt = 1; prompt <= 4; prompt += 1) {
    await waitForPrompt(input, prompt);
    input.write("\r");
  }
  await waitForPrompt(input, 5);
  expect(output.text()).toContain("No client secret");
  input.write("\r");

  await expect(running).rejects.toThrow("stop after OAuth input capture");
  expect(loginInput?.clientInformation).toEqual({ client_id: "client-id" });
  expect(readSecret).not.toHaveBeenCalled();
});

test("full-TTY imported OAuth client secret preserves custom whitespace without revealing it", async () => {
  const setup = await claudeOAuthProject({ oauth: { clientId: "client-id" } });
  const input = new OAuthSetupTtyInput();
  const output = fullTtyOutput();
  const clientSecret = " secret with spaces ";
  let loginInput: Parameters<typeof loginOAuthProfile>[0]["input"] | undefined;
  setupFakes.login = vi.fn(async ({ input: captured }) => {
    loginInput = captured;
    throw new Error("stop after OAuth input capture");
  });

  const running = runSetup({
    ...oauthSetupOptions(setup, [], output),
    input,
  });
  void running.catch(() => {});
  for (let prompt = 1; prompt <= 4; prompt += 1) {
    await waitForPrompt(input, prompt);
    input.write("\r");
  }
  await waitForPrompt(input, 5);
  input.write("\u001B[B\r");
  await waitForPrompt(input, 6);
  input.write(clientSecret);
  await new Promise<void>((resolveTurn) => setImmediate(resolveTurn));
  input.write("\r");

  await expect(running).rejects.toThrow("stop after OAuth input capture");
  expect(loginInput?.clientInformation).toEqual({
    client_id: "client-id",
    client_secret: clientSecret,
  });
  expect(output.text()).not.toContain(clientSecret);
  expect(output.text()).not.toContain("*".repeat(clientSecret.length));
});

test.each([
  ["imported", "", { client_id: "client-id" }],
  [
    "imported",
    " secret with spaces ",
    { client_id: "client-id", client_secret: " secret with spaces " },
  ],
  ["Manual", "", { client_id: "client-id" }],
  [
    "Manual",
    " secret with spaces ",
    { client_id: "client-id", client_secret: " secret with spaces " },
  ],
] as const)(
  "line setup %s OAuth client secret keeps one legacy read for %j",
  async (origin, secret, expected) => {
    const readSecret = vi.fn(async () => secret);
    let loginInput: Parameters<typeof loginOAuthProfile>[0]["input"] | undefined;
    setupFakes.login = vi.fn(async ({ input }) => {
      loginInput = input;
      throw new Error("stop after OAuth input capture");
    });
    const output = capture();

    if (origin === "imported") {
      const setup = await claudeOAuthProject({ oauth: { clientId: "client-id" } });
      await expect(
        runSetup({
          ...oauthSetupOptions(setup, ["1\n", "all\n", "1\n", "yes\n"], output),
          readSecret,
        }),
      ).rejects.toThrow("stop after OAuth input capture");
    } else {
      const setup = await manualDestinationFixture();
      const keyPath = join(setup.root, "master.key");
      await writeFile(keyPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
      await expect(
        runSetup({
          ...manualDestinationSetupOptions(
            setup,
            [
              "4\n",
              "oauth\n",
              "http\n",
              "https://resource.example.test/mcp\n",
              "\n",
              "oauth\n",
              "client-id\n",
              "\n",
              "\n",
              "\n",
              "\n",
              "\n",
              "\n",
              "1\n",
              "1\n",
              "yes\n",
            ],
            output,
          ),
          environment: { PATH: process.env.PATH, [MASTER_KEY_FILE_ENV]: keyPath },
          readSecret,
        }),
      ).rejects.toThrow("stop after OAuth input capture");
    }

    expect(readSecret).toHaveBeenCalledExactlyOnceWith(
      "Optional OAuth client secret (leave empty for none): ",
    );
    expect(loginInput?.clientInformation).toEqual(expected);
    expect(output.text()).not.toContain("No client secret");
    expect(output.text()).not.toContain("Enter client secret");
    expect(output.text()).not.toContain("\u001B[");
  },
);

test("performs only a credential-free challenge probe before checking unavailable storage", async () => {
  const setup = await codexOAuthProject({ keyContent: "not-a-master-key" });
  const challenge = oauthChallenge(
    "https://resource.example.test/.well-known/oauth-protected-resource",
    "read write",
  );
  const discover = vi.fn(async (upstream: UpstreamConfig) => {
    expect(upstream.kind).toBe("http");
    const provider = upstream.kind === "http" ? upstream.authProviderFactory?.() : undefined;
    expect(await provider?.token()).toBeUndefined();
    await provider?.onUnauthorized?.({
      response: new Response(null, {
        status: 401,
        headers: { "WWW-Authenticate": challenge },
      }),
      serverUrl: new URL(setup.serverUrl),
      fetchFn: fetch,
    });
    throw new Error("challenge provider did not stop discovery");
  });
  const login = vi.fn(async () => exampleProfile("unexpected", setup.serverUrl));
  const readSecret = vi.fn(async () => "must-not-prompt");
  setupFakes.discover = discover;
  setupFakes.login = login;

  await expect(
    runSetup({
      ...oauthSetupOptions(setup, ["2\n", "all\n", "1\n", "yes\n"], capture()),
      readSecret,
    }),
  ).rejects.toThrow(/master key/i);

  expect(discover).toHaveBeenCalledOnce();
  expect(login).not.toHaveBeenCalled();
  expect(readSecret).not.toHaveBeenCalled();
  await expectOAuthSetupUnchanged(setup);
});

test("defaults setup OAuth confirmation to Yes on Enter and stores the profile encrypted", async () => {
  const setup = await claudeOAuthProject({
    oauth: {
      clientId: "pre-registered-client",
      scopes: "read write",
      authServerMetadataUrl: "https://auth.example.test/.well-known/oauth-authorization-server",
    },
  });
  const events: string[] = [];
  const clientSecret = "non-echo-client-secret";
  const accessToken = "in-memory-access-token";
  let selectedProfileId = "";
  let oauthConfirmationRequested = false;
  const readSecret = vi.fn(async () => clientSecret);
  setupFakes.login = vi.fn(async (options) => {
    events.push("login");
    const { metadata, clientInformation } = options.input;
    selectedProfileId = metadata.profileId;
    expect(selectedProfileId).toMatch(UUID_V4);
    expect(metadata).toMatchObject({
      version: 1,
      serverUrl: setup.serverUrl,
      requestedScope: "read write",
      authServerMetadataUrl: "https://auth.example.test/.well-known/oauth-authorization-server",
      callback: {
        host: "localhost",
        path: "/callback",
        appendProfileId: false,
      },
      clientMetadata: {
        client_name: "MCP Restrictor",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      },
    });
    expect(metadata.clientMetadata).not.toHaveProperty("scope");
    expect(clientInformation).toEqual({
      client_id: "pre-registered-client",
      client_secret: clientSecret,
    });
    oauthConfirmationRequested = true;
    const confirmed = await options.io.confirmAuthorizationServer({
      authorizationServerUrl: new URL("https://auth.example.test/private/path?client=hidden"),
      callbackUrl: new URL("http://127.0.0.1:41337/callback?code=hidden"),
      scope: "read write",
    });
    expect(confirmed).toBe(true);
    return exampleProfile(selectedProfileId, setup.serverUrl, {
      metadata,
      clientInformation,
      accessToken,
    });
  });
  setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) => {
    if (upstream.kind === "stdio") return ["read_file", "search"];
    events.push("discover");
    expect(upstream.kind).toBe("http");
    expect(await upstream.authProviderFactory?.().token()).toBe(accessToken);
    return ["read_file", "search"];
  });
  const input = new PassThrough();
  const output = capture((value) => {
    if (!value.includes("Continue with OAuth authorization?")) return;
    expect(oauthConfirmationRequested).toBe(true);
    input.end("\nall\n1\nyes\n");
  });
  input.write("1\nall\n1\nyes\n");

  await runSetup({
    ...oauthSetupOptions(setup, [], output),
    input,
    readSecret,
  });

  expect(events).toEqual(["login", "discover"]);
  expect(readSecret).toHaveBeenCalledExactlyOnceWith(
    "Optional OAuth client secret (leave empty for none): ",
  );
  const stored = await readOAuthProfileSnapshot(selectedProfileId, setup.storageOptions);
  expect(stored.profile.credentials.clientInformation.client_secret).toBe(clientSecret);
  expect(stored.profile.credentials.tokens.access_token).toBe(accessToken);
  const config = await readFile(setup.configPath, "utf8");
  expect(config).toContain(selectedProfileId);
  expect(config).not.toContain(clientSecret);
  expect(config).not.toContain(accessToken);
  expect(output.text()).not.toContain(clientSecret);
  expect(output.text()).not.toContain(accessToken);
  expect(output.text()).not.toContain(setup.keyPath);
  expect(output.text()).toContain('OAuth authorization server: "https://auth.example.test"');
  expect(output.text()).not.toContain("private/path");
  expect(output.text()).not.toContain("client=hidden");
});

test("setup OAuth preserves confirmation EOF as the interaction AbortError", async () => {
  const profile = exampleProfile(
    "11111111-1111-4111-8111-111111111111",
    "https://api.example.test/mcp",
  );
  profile.metadata.callback = { url: "https://callback.example/complete", appendProfileId: true };
  profile.credentials.discoveryState.resourceMetadata = {
    resource: profile.metadata.serverUrl,
    authorization_servers: ["https://auth.example.test/"],
  };
  const interaction = new SetupInteraction({
    input: Readable.from([]),
    output: capture(),
    error: capture(),
  });
  const writeAuthorizationUrl = vi.fn();

  try {
    const error = await loginOAuthProfile({
      input: {
        metadata: profile.metadata,
        clientInformation: profile.credentials.clientInformation,
        discoveryState: profile.credentials.discoveryState,
      },
      io: {
        confirmAuthorizationServer: async () =>
          await interaction.confirm("Continue with OAuth authorization?"),
        writeAuthorizationUrl,
        readPastedRedirect: async () => new URL("https://callback.example/complete"),
      },
      signal: interaction.signal,
    }).catch((reason: unknown) => reason);

    expect(error).toBe(interaction.signal.reason);
    expect(error).toMatchObject({ name: "AbortError" });
  } finally {
    interaction.close();
  }

  expect(writeAuthorizationUrl).not.toHaveBeenCalled();
});

test("preserves whitespace in an explicit OAuth client secret", async () => {
  const setup = await claudeOAuthProject({ oauth: { clientId: "client" } });
  setupFakes.login = vi.fn(async (options) => {
    expect(options.input.clientInformation).toEqual({
      client_id: "client",
      client_secret: " secret with spaces ",
    });
    return exampleProfile(options.input.metadata.profileId, setup.serverUrl, {
      metadata: options.input.metadata,
      clientInformation: options.input.clientInformation,
    });
  });
  setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) =>
    upstream.kind === "stdio" ? ["read_file"] : ["read_file"],
  );

  await runSetup({
    ...oauthSetupOptions(
      setup,
      ["1\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "no\n"],
      capture(),
    ),
    readSecret: vi.fn(async () => " secret with spaces "),
  });
});

test("previews STDIO without argument values and names only bearer environment input", async () => {
  const setup = await simpleCodexProject(["read_file"]);
  const argumentSecret = "argument-secret";
  await writeFile(
    setup.configPath,
    stdioServer("files", setup.fixture, ["read_file"], {
      target: argumentSecret,
      env: { SAFE_NAME: "hidden-value" },
    }),
  );
  const output = capture();
  await runSetup({
    ...setupOptions(setup, ["2\n", "all\n", "1\n", "no\n"], output),
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });
  expect(output.text()).toContain('environment=["SAFE_NAME"]');
  expect(output.text()).not.toContain(argumentSecret);
  expect(output.text()).not.toContain("hidden-value");
});

test("previews the effective Claude STDIO command without its raw expression", async () => {
  const root = await temporaryDirectory();
  const configPath = join(root, ".mcp.json");
  await writeFile(
    configPath,
    `${JSON.stringify({
      mcpServers: {
        files: {
          command: "${NODE_BINARY}",
          args: ["argument-secret"],
        },
      },
    })}\n`,
  );
  const output = capture();

  await runSetup({
    input: Readable.from(["1\n", "all\n", "1\n", "no\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { NODE_BINARY: process.execPath, PATH: process.env.PATH },
  });

  expect(output.text()).toContain(`command=${JSON.stringify(process.execPath)}`);
  expect(output.text()).not.toContain("${NODE_BINARY}");
  expect(output.text()).not.toContain("argument-secret");
});

test("maps Codex fallback scope and resource into one dynamic-registration login before discovery", async () => {
  const setup = await codexOAuthProject({
    source: `mcp_oauth_callback_port = 0
mcp_oauth_callback_url = "http://127.0.0.1:4321/callback?tenant=one"

[mcp_servers.protected]
url = "https://resource.example.test/mcp"
auth = "oauth"
scopes = ["write", "read"]
oauth_resource = "urn:example:resource"
`,
  });
  const readSecret = vi.fn(async () => "unexpected");
  const events: string[] = [];
  setupFakes.login = vi.fn(async (options) => {
    events.push("login");
    expect(options.input.clientInformation).toBeUndefined();
    expect(options.input.metadata).toMatchObject({
      serverUrl: setup.serverUrl,
      resource: "urn:example:resource",
      callback: {
        url: "http://127.0.0.1:4321/callback?tenant=one",
        port: 0,
        appendProfileId: true,
      },
      clientMetadata: { scope: "write read" },
    });
    expect(options.input.metadata).not.toHaveProperty("requestedScope");
    return exampleProfile(options.input.metadata.profileId, setup.serverUrl, {
      metadata: options.input.metadata,
      accessToken: "codex-access-token",
    });
  });
  setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) => {
    if (upstream.kind === "stdio") return ["alpha", "zeta"];
    events.push("discover");
    expect(
      await (upstream.kind === "http" ? upstream.authProviderFactory?.().token() : undefined),
    ).toBe("codex-access-token");
    return ["alpha", "zeta"];
  });

  await runSetup({
    ...oauthSetupOptions(
      setup,
      ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"],
      capture(),
    ),
    readSecret,
  });

  expect(events).toEqual(["login", "discover"]);
  expect(readSecret).not.toHaveBeenCalled();
  expect(await readFile(setup.policyPath, "utf8")).toContain("name: alpha");
  expect(await readFile(setup.policyPath, "utf8")).toContain("name: zeta");
});

test.each([
  [
    "401",
    (upstream: Extract<UpstreamConfig, { kind: "http" }>, challenge: string) =>
      upstream.authProviderFactory?.().onUnauthorized?.({
        response: new Response(null, { status: 401, headers: { "WWW-Authenticate": challenge } }),
        serverUrl: new URL(upstream.url),
        fetchFn: fetch,
      }),
  ],
  [
    "403",
    (upstream: Extract<UpstreamConfig, { kind: "http" }>, challenge: string) =>
      Promise.resolve(
        upstream.validateResponse?.(
          new Response(null, { status: 403, headers: { "WWW-Authenticate": challenge } }),
        ),
      ),
  ],
] as const)(
  "turns a validated HTTP %s challenge into one authenticated login and discovery",
  async (_status, trigger) => {
    const setup = await codexOAuthProject();
    const resourceMetadataUrl =
      "https://resource.example.test/.well-known/oauth-protected-resource";
    const challenge = oauthChallenge(resourceMetadataUrl, "read write");
    const events: string[] = [];
    let attempts = 0;
    setupFakes.discover = vi.fn(async (upstream: UpstreamConfig, options) => {
      if (upstream.kind === "stdio") return ["alpha", "zeta"];
      expect(upstream.kind).toBe("http");
      if (upstream.kind !== "http") return [];
      attempts += 1;
      events.push(`discover-${attempts}`);
      if (attempts === 1) {
        expect(options?.preserveError).toEqual(expect.any(Function));
        await trigger(upstream, challenge);
        throw new Error("challenge callback returned");
      }
      expect(await upstream.authProviderFactory?.().token()).toBe("challenge-access-token");
      return ["alpha", "zeta"];
    });
    setupFakes.login = vi.fn(async (options) => {
      events.push("login");
      expect(options.input.metadata).toMatchObject({
        requestedScope: "read write",
        resourceMetadataUrl,
      });
      return exampleProfile(options.input.metadata.profileId, setup.serverUrl, {
        metadata: options.input.metadata,
        accessToken: "challenge-access-token",
      });
    });

    await runSetup({
      ...oauthSetupOptions(
        setup,
        ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"],
        capture(),
      ),
      readSecret: vi.fn(async () => "unexpected"),
    });

    expect(events).toEqual(["discover-1", "login", "discover-2"]);
    expect(await readFile(setup.policyPath, "utf8")).toContain("name: alpha");
  },
);

test.each([
  ["missing metadata", 'Bearer scope="read"'],
  ["wrong scheme", 'Basic resource_metadata="https://resource.example.test/metadata"'],
  ["remote plaintext", 'Bearer resource_metadata="http://resource.example.test/metadata"'],
  ["fragment", 'Bearer resource_metadata="https://resource.example.test/metadata#hidden"'],
  ["userinfo", 'Bearer resource_metadata="https://user@resource.example.test/metadata"'],
  [
    "bad scope",
    'Bearer resource_metadata="https://resource.example.test/metadata", scope="read  write"',
  ],
  [
    "different challenge scheme",
    'Bearer realm="mcp", Basic resource_metadata="https://resource.example.test/metadata"',
  ],
  [
    "RFC token challenge scheme",
    'Bearer realm="mcp", DPoP+v1 resource_metadata="https://resource.example.test/metadata"',
  ],
  [
    "duplicate metadata",
    'Bearer resource_metadata="https://resource.example.test/one", resource_metadata="https://resource.example.test/two"',
  ],
  [
    "duplicate scope",
    'Bearer resource_metadata="https://resource.example.test/metadata", scope="read", scope="write"',
  ],
] as const)("does not start OAuth for an invalid %s challenge", async (_case, challenge) => {
  const setup = await codexOAuthProject();
  const login = vi.fn(async () => exampleProfile("unexpected", setup.serverUrl));
  setupFakes.login = login;
  setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) => {
    if (upstream.kind === "http") {
      await upstream.authProviderFactory?.().onUnauthorized?.({
        response: new Response("challenge-body-secret", {
          status: 401,
          headers: { "WWW-Authenticate": challenge },
        }),
        serverUrl: new URL(upstream.url),
        fetchFn: fetch,
      });
    }
    return [];
  });

  const failure = await runSetup({
    ...oauthSetupOptions(setup, ["2\n", "all\n", "1\n", "1\n", "yes\n"], capture()),
    readSecret: vi.fn(async () => "unexpected"),
  }).catch((error: unknown) => error);

  expect(failure).toBeInstanceOf(Error);
  expect(String(failure)).not.toContain("challenge-body-secret");
  expect(login).not.toHaveBeenCalled();
  await expectOAuthSetupUnchanged(setup);
});

test("reuses a managed OAuth profile ID and exact encrypted bytes when its token works", async () => {
  const setup = await codexOAuthProject();
  const profileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const profile = exampleProfile(profileId, setup.serverUrl, { accessToken: "working-token" });
  await writeOAuthProfile(profile, setup.storageOptions);
  const profilePath = oauthProfilePath(setup.home, profileId);
  const before = await readFile(profilePath, "utf8");
  setup.source = `[mcp_servers.protected]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(setup.policyPath)}, "--upstream-http", ${JSON.stringify(setup.serverUrl)}, "--upstream-oauth-profile", "${profileId}"]\n\n[mcp_servers.protected.env]\n${MASTER_KEY_FILE_ENV} = ${JSON.stringify(setup.keyPath)}\n`;
  const savedDirectory = join(
    setup.root,
    ".mcp-restrictor",
    "saved-policies",
    "codex",
    "protected.d",
  );
  const savedPolicy =
    "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n  deny: []\n";
  await Promise.all([
    mkdir(dirname(setup.policyPath), { recursive: true }),
    mkdir(savedDirectory, { recursive: true, mode: 0o700 }),
  ]);
  await Promise.all([
    writeFile(setup.configPath, setup.source),
    writeFile(setup.policyPath, "version: 1\ndefault: deny\ntools:\n  allow: []\n  deny: []\n"),
    writeFile(join(savedDirectory, "read-only.yaml"), savedPolicy, { mode: 0o600 }),
  ]);
  await Promise.all([
    chmod(savedDirectory, 0o700),
    chmod(join(savedDirectory, "read-only.yaml"), 0o600),
  ]);
  setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) => {
    if (upstream.kind === "http") {
      expect(await upstream.authProviderFactory?.().token()).toBe("working-token");
    }
    return ["read_file"];
  });
  const login = vi.fn();
  setupFakes.login = login;

  await runSetup({
    ...oauthSetupOptions(setup, ["2\n", "all\n", "2\n", "yes\n", "yes\n"], capture()),
    readSecret: vi.fn(async () => "unexpected"),
  });

  expect(login).not.toHaveBeenCalled();
  expect(await readFile(profilePath, "utf8")).toBe(before);
  const configured = await readFile(setup.configPath, "utf8");
  expect(configured).toContain(`"--upstream-oauth-profile", "${profileId}"`);
  expect(await readFile(setup.policyPath, "utf8")).toBe(savedPolicy);
});

test("rejects a managed OAuth profile bound to another URL before discovery", async () => {
  const setup = await codexOAuthProject();
  const profileId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  await writeOAuthProfile(
    exampleProfile(profileId, "https://other.example.test/mcp"),
    setup.storageOptions,
  );
  setup.source = `[mcp_servers.protected]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(setup.policyPath)}, "--upstream-http", ${JSON.stringify(setup.serverUrl)}, "--upstream-oauth-profile", "${profileId}"]\n\n[mcp_servers.protected.env]\n${MASTER_KEY_FILE_ENV} = ${JSON.stringify(setup.keyPath)}\n`;
  await writeFile(setup.configPath, setup.source);
  const discover = vi.fn(async () => []);
  setupFakes.discover = discover;

  await expect(
    runSetup({
      ...oauthSetupOptions(setup, ["2\n", "all\n", "1\n", "1\n", "yes\n"], capture()),
      readSecret: vi.fn(async () => "unexpected"),
    }),
  ).rejects.toThrow(/binding/i);

  expect(discover).not.toHaveBeenCalled();
});

test("re-logs a managed profile in memory after 401 and keeps the same ID", async () => {
  const setup = await codexOAuthProject();
  const profileId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  const baseline = exampleProfile(profileId, setup.serverUrl, { accessToken: "expired-token" });
  await writeOAuthProfile(baseline, setup.storageOptions);
  setup.source = `[mcp_servers.protected]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(setup.policyPath)}, "--upstream-http", ${JSON.stringify(setup.serverUrl)}, "--upstream-oauth-profile", "${profileId}"]\n\n[mcp_servers.protected.env]\n${MASTER_KEY_FILE_ENV} = ${JSON.stringify(setup.keyPath)}\n`;
  await writeFile(setup.configPath, setup.source);
  const events: string[] = [];
  let remoteAttempts = 0;
  setupFakes.discover = vi.fn(async (upstream: UpstreamConfig, options) => {
    if (upstream.kind === "stdio") return ["read_file"];
    remoteAttempts += 1;
    events.push(`discover-${remoteAttempts}`);
    if (remoteAttempts === 1 && upstream.kind === "http") {
      expect(options?.preserveError).toEqual(expect.any(Function));
      await upstream.authProviderFactory?.().onUnauthorized?.({
        response: new Response(null, { status: 401 }),
        serverUrl: new URL(upstream.url),
        fetchFn: fetch,
      });
    }
    expect(
      await (upstream.kind === "http" ? upstream.authProviderFactory?.().token() : undefined),
    ).toBe("replacement-token");
    return ["read_file"];
  });
  setupFakes.login = vi.fn(async (options) => {
    events.push("login");
    expect(options.input.metadata.profileId).toBe(profileId);
    return exampleProfile(profileId, setup.serverUrl, {
      metadata: options.input.metadata,
      clientInformation: options.input.clientInformation,
      accessToken: "replacement-token",
    });
  });

  await runSetup({
    ...oauthSetupOptions(
      setup,
      ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"],
      capture(),
    ),
    readSecret: vi.fn(async () => "unexpected"),
  });

  expect(events).toEqual(["discover-1", "login", "discover-2"]);
  expect(
    (await readOAuthProfileSnapshot(profileId, setup.storageOptions)).profile.credentials.tokens
      .access_token,
  ).toBe("replacement-token");
  expect(await readFile(setup.configPath, "utf8")).toContain(profileId);
});

test("prepares one write for two compatible managed wrappers sharing an OAuth profile", async () => {
  const setup = await codexOAuthProject();
  const profileId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
  const baseline = exampleProfile(profileId, setup.serverUrl, { accessToken: "expired-token" });
  await writeOAuthProfile(baseline, setup.storageOptions);
  const managed = (name: string) => `[mcp_servers.${name}]
command = "mcp-restrictor"
args = ["--policy", ${JSON.stringify(join(setup.root, `${name}.yaml`))}, "--upstream-http", ${JSON.stringify(setup.serverUrl)}, "--upstream-oauth-profile", "${profileId}"]

[mcp_servers.${name}.env]
${MASTER_KEY_FILE_ENV} = ${JSON.stringify(setup.keyPath)}
`;
  setup.source = `${managed("alpha")}\n${managed("beta")}`;
  await writeFile(setup.configPath, setup.source);
  setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) => {
    if (upstream.kind === "stdio") return ["read_file"];
    const provider = upstream.authProviderFactory?.();
    if ((await provider?.token()) === "expired-token") {
      await provider?.onUnauthorized?.({
        response: new Response(null, { status: 401 }),
        serverUrl: new URL(setup.serverUrl),
        fetchFn: fetch,
      });
    }
    return ["read_file"];
  });
  setupFakes.login = vi.fn(async (options) =>
    exampleProfile(profileId, setup.serverUrl, {
      metadata: options.input.metadata,
      clientInformation: options.input.clientInformation,
      accessToken: "replacement-token",
    }),
  );

  await runSetup({
    ...oauthSetupOptions(
      setup,
      ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"],
      capture(),
    ),
    readSecret: vi.fn(async () => "unexpected"),
  });

  expect(setupFakes.login).toHaveBeenCalledTimes(2);
  expect(
    (await readOAuthProfileSnapshot(profileId, setup.storageOptions)).profile.credentials.tokens
      .access_token,
  ).toBe("replacement-token");
  expect((await readFile(setup.configPath, "utf8")).match(new RegExp(profileId, "g"))).toHaveLength(
    2,
  );
});

test("reports wrapper discovery before OAuth profile acceptance when both verification steps fail", async () => {
  const setup = await codexOAuthProject();
  const profileId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
  const baseline = exampleProfile(profileId, setup.serverUrl, { accessToken: "working-token" });
  await writeOAuthProfile(baseline, setup.storageOptions);
  setup.source = `[mcp_servers.protected]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(setup.policyPath)}, "--upstream-http", ${JSON.stringify(setup.serverUrl)}, "--upstream-oauth-profile", "${profileId}"]\n\n[mcp_servers.protected.env]\n${MASTER_KEY_FILE_ENV} = ${JSON.stringify(setup.keyPath)}\n`;
  await writeFile(setup.configPath, setup.source);
  setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) => {
    if (upstream.kind !== "stdio") return ["read_file"];
    const beforeRotation = await readOAuthProfileSnapshot(profileId, setup.storageOptions);
    await writeOAuthProfile(
      {
        ...baseline,
        credentials: {
          ...baseline.credentials,
          clientInformation: {
            ...baseline.credentials.clientInformation,
            client_id: "changed-client",
          },
        },
      },
      { ...setup.storageOptions, before: beforeRotation.snapshot },
    );
    expect(
      (await readOAuthProfileSnapshot(profileId, setup.storageOptions)).profile.credentials
        .clientInformation.client_id,
    ).toBe("changed-client");
    throw new Error("upstream-secret");
  });

  const failure = await runSetup({
    ...oauthSetupOptions(
      setup,
      ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"],
      capture(),
    ),
    readSecret: vi.fn(async () => "unexpected"),
  }).catch((error: unknown) => error);

  expect(failure).toBeInstanceOf(AggregateError);
  const messages = errorMessages(failure);
  const discoveryIndex = messages.findIndex((message) =>
    /wrapper verification failed/i.test(message),
  );
  const acceptanceIndex = messages.findIndex((message) => /outside token rotation/i.test(message));
  expect(discoveryIndex).toBeGreaterThanOrEqual(0);
  expect(acceptanceIndex).toBeGreaterThan(discoveryIndex);
  expect(messages.join(" ")).not.toContain("upstream-secret");
  expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
  expect(
    (await readOAuthProfileSnapshot(profileId, setup.storageOptions)).profile.credentials
      .clientInformation.client_id,
  ).toBe("changed-client");
});

test("accepts exact-wrapper token rotation and keeps the rotated OAuth profile", async () => {
  const setup = await codexOAuthProject();
  const profileId = "ffffffff-ffff-4fff-8fff-ffffffffffff";
  const baseline = exampleProfile(profileId, setup.serverUrl, { accessToken: "working-token" });
  await writeOAuthProfile(baseline, setup.storageOptions);
  setup.source = `[mcp_servers.protected]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(setup.policyPath)}, "--upstream-http", ${JSON.stringify(setup.serverUrl)}, "--upstream-oauth-profile", "${profileId}"]\n\n[mcp_servers.protected.env]\n${MASTER_KEY_FILE_ENV} = ${JSON.stringify(setup.keyPath)}\n`;
  await writeFile(setup.configPath, setup.source);
  setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) => {
    if (upstream.kind !== "stdio") return ["read_file"];
    const current = await readOAuthProfileSnapshot(profileId, setup.storageOptions);
    await writeOAuthProfile(
      {
        ...current.profile,
        credentials: {
          ...current.profile.credentials,
          tokens: {
            ...current.profile.credentials.tokens,
            access_token: "rotated-token",
            refresh_token: "rotated-refresh-token",
          },
        },
      },
      { ...setup.storageOptions, before: current.snapshot },
    );
    return ["read_file"];
  });

  await runSetup({
    ...oauthSetupOptions(
      setup,
      ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"],
      capture(),
    ),
    readSecret: vi.fn(async () => "unexpected"),
  });

  const stored = await readOAuthProfileSnapshot(profileId, setup.storageOptions);
  expect(stored.profile.credentials.tokens).toMatchObject({
    access_token: "rotated-token",
    refresh_token: "rotated-refresh-token",
  });
  expect(stored.profile.metadata).toEqual(baseline.metadata);
  expect(stored.profile.credentials.clientInformation).toEqual(
    baseline.credentials.clientInformation,
  );
  expect(stored.profile.credentials.discoveryState).toEqual(baseline.credentials.discoveryState);
});

test("final Apply=no after OAuth login leaves no profile, policy, or config change", async () => {
  const setup = await codexOAuthProject({
    source: `[mcp_servers.protected]\nurl = "https://resource.example.test/mcp"\nauth = "oauth"\n`,
  });
  let profileId = "";
  setupFakes.login = vi.fn(async (options) => {
    profileId = options.input.metadata.profileId;
    return exampleProfile(profileId, setup.serverUrl, {
      metadata: options.input.metadata,
    });
  });
  setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) =>
    upstream.kind === "stdio" ? ["read_file"] : ["read_file"],
  );

  await runSetup({
    ...oauthSetupOptions(
      setup,
      ["2\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "no\n"],
      capture(),
    ),
    readSecret: vi.fn(async () => "unexpected"),
  });

  expect(profileId).toMatch(UUID_V4);
  await expectOAuthSetupUnchanged(setup);
  expect(await exists(oauthProfilePath(setup.home, profileId))).toBe(false);
});

test.each([401, 403] as const)(
  "parses an initial SSE %s challenge and cancels its body before login",
  async (status) => {
    const setup = await claudeOAuthProject({ type: "sse" });
    const resourceMetadataUrl =
      "https://resource.example.test/.well-known/oauth-protected-resource";
    const cancel = vi.fn(async () => undefined);
    const fetchStub = vi.fn(async (_url: string | URL | Request, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      expect(headers.get("Accept")).toBe("text/event-stream");
      return new Response(new ReadableStream({ cancel }), {
        status,
        headers: { "WWW-Authenticate": oauthChallenge(resourceMetadataUrl, "read") },
      });
    });
    vi.stubGlobal("fetch", fetchStub);
    let remoteDiscoveries = 0;
    setupFakes.discover = vi.fn(async (upstream: UpstreamConfig) => {
      if (upstream.kind === "stdio") return ["read_file"];
      remoteDiscoveries += 1;
      expect(
        await (upstream.kind === "sse" ? upstream.authProviderFactory?.().token() : undefined),
      ).toBe("sse-token");
      return ["read_file"];
    });
    setupFakes.login = vi.fn(async (options) => {
      expect(options.input.metadata).toMatchObject({
        resourceMetadataUrl,
        requestedScope: "read",
      });
      return exampleProfile(options.input.metadata.profileId, setup.serverUrl, {
        metadata: options.input.metadata,
        accessToken: "sse-token",
      });
    });

    await runSetup({
      ...oauthSetupOptions(
        setup,
        ["1\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "yes\n"],
        capture(),
      ),
      readSecret: vi.fn(async () => "unexpected"),
    });

    expect(fetchStub).toHaveBeenCalledOnce();
    expect(cancel).toHaveBeenCalledOnce();
    expect(remoteDiscoveries).toBe(1);
  },
);

test.each([200, 500] as const)(
  "cancels an initial SSE %s response body before continuing or failing",
  async (status) => {
    const setup = await claudeOAuthProject({ type: "sse" });
    const cancel = vi.fn(async () => undefined);
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(new ReadableStream({ cancel }), { status })),
    );
    const discover = vi.fn(async (upstream: UpstreamConfig) =>
      upstream.kind === "stdio" ? ["read_file"] : ["read_file"],
    );
    setupFakes.discover = discover;

    const result = runSetup({
      ...oauthSetupOptions(
        setup,
        status === 200
          ? ["1\n", "all\n", "1\n", "yes\n", "all\n", "1\n", "no\n"]
          : ["1\n", "all\n", "1\n", "1\n", "yes\n"],
        capture(),
      ),
      readSecret: vi.fn(async () => "unexpected"),
    });
    if (status === 200) await expect(result).resolves.toBeUndefined();
    else await expect(result).rejects.toThrow(/status 500/i);

    expect(cancel).toHaveBeenCalledOnce();
    expect(discover).toHaveBeenCalledTimes(status === 200 ? 1 : 0);
  },
);

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-setup-")));
  temporaryDirectories.push(path);
  return path;
}

type ManualDestinationFixture = {
  root: string;
  home: string;
  fixture: string;
  restrictor: string;
  claudePath: string;
  codexPath: string;
  openCodePath: string;
  policyPaths: string[];
};

async function manualDestinationFixture(): Promise<ManualDestinationFixture> {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const fixture = await writeUpstreamFixture(root);
  const restrictor = join(root, "mcp-restrictor");
  const claudePath = join(root, ".mcp.json");
  const codexPath = join(home, ".codex", "config.toml");
  const openCodePath = join(root, "opencode.jsonc");
  await mkdir(dirname(codexPath), { recursive: true });
  await Promise.all([
    writeFile(restrictor, ""),
    writeFile(claudePath, '{"mcpServers": {}}\n'),
    writeFile(codexPath, ""),
    writeFile(openCodePath, "{}\n"),
  ]);
  await chmod(restrictor, 0o755);
  return {
    root,
    home,
    fixture,
    restrictor,
    claudePath,
    codexPath,
    openCodePath,
    policyPaths: [
      join(root, ".mcp-restrictor", "policies", "claude", "files.yaml"),
      join(home, ".mcp-restrictor", "policies", "codex", "files.yaml"),
      join(root, ".mcp-restrictor", "policies", "opencode", "files.yaml"),
    ],
  };
}

function manualDestinationInput(
  fixture: string,
  options: { policyChoice?: string; selectedPolicy?: boolean } = {},
): string[] {
  return [
    "4\n",
    "files\n",
    "stdio\n",
    `${process.execPath}\n`,
    `${JSON.stringify([fixture, JSON.stringify(["read_file"])])}\n`,
    "API_KEY\n",
    "2,3,4\n",
    "1\n",
    "1\n",
    "1\n",
    `${options.policyChoice ?? "1"}\n`,
    `${options.policyChoice ?? "1"}\n`,
    `${options.policyChoice ?? "1"}\n`,
    "yes\n",
    ...(options.selectedPolicy ? [] : ["all\n", "1\n", "all\n", "1\n", "all\n", "1\n"]),
    "yes\n",
  ];
}

function manualTwoHttpInput(setup: ManualDestinationFixture): string[] {
  return [
    "4\n",
    "files\n",
    "stdio\n",
    `${process.execPath}\n`,
    `${JSON.stringify([setup.fixture, JSON.stringify(["read_file", "write_file"])])}\n`,
    "API_KEY\n",
    "2,3\n",
    "2\n",
    "2\n",
    "1\n",
    "1\n",
    "1\n",
    "yes\n",
    "1\n",
    "1\n",
    "2\n",
    "1\n",
    "yes\n",
  ];
}

function manualOneHttpInput(setup: ManualDestinationFixture): string[] {
  return [
    "4\n",
    "files\n",
    "stdio\n",
    `${process.execPath}\n`,
    `${JSON.stringify([setup.fixture, JSON.stringify(["read_file"])])}\n`,
    "API_KEY\n",
    "2\n",
    "2\n",
    "1\n",
    "1\n",
    "yes\n",
    "all\n",
    "1\n",
    "yes\n",
  ];
}

function manualThreeHttpInput(setup: ManualDestinationFixture): string[] {
  return [
    "4\n",
    "files\n",
    "stdio\n",
    `${process.execPath}\n`,
    `${JSON.stringify([setup.fixture, JSON.stringify(["read_file"])])}\n`,
    "API_KEY\n",
    "2,3,4\n",
    "2\n",
    "2\n",
    "2\n",
    "1\n",
    "1\n",
    "1\n",
    "1\n",
    "yes\n",
    "all\n",
    "1\n",
    "all\n",
    "1\n",
    "all\n",
    "1\n",
    "yes\n",
  ];
}

function manualDestinationOAuthInput(
  serverUrl: string,
  options: { savePolicy?: boolean } = {},
): string[] {
  return [
    "4\n",
    "oauth\n",
    "http\n",
    `${serverUrl}\n`,
    "\n",
    "oauth\n",
    "\n",
    "\n",
    "\n",
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
    "all\n",
    ...(options.savePolicy ? ["2\n", "read-only\n"] : ["1\n"]),
    "all\n",
    "1\n",
    "all\n",
    "1\n",
    "yes\n",
  ];
}

function manualHttpOAuthInput(serverUrl: string): string[] {
  return [
    "4\n",
    "oauth\n",
    "http\n",
    `${serverUrl}\n`,
    "\n",
    "oauth\n",
    "\n",
    "\n",
    "\n",
    "\n",
    "\n",
    "\n",
    "\n",
    "2\n",
    "2\n",
    "1\n",
    "1\n",
    "yes\n",
    "all\n",
    "1\n",
    "yes\n",
  ];
}

async function withProcessPlatform<T>(
  value: NodeJS.Platform,
  operation: () => Promise<T>,
): Promise<T> {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  Object.defineProperty(process, "platform", { ...platform, value });
  try {
    return await operation();
  } finally {
    Object.defineProperty(process, "platform", platform);
  }
}

function manualDestinationSetupOptions(
  setup: ManualDestinationFixture,
  input: string[],
  output: Writable,
) {
  return {
    input: Readable.from(input),
    output,
    error: capture(),
    interactive: true,
    cwd: setup.root,
    home: setup.home,
    environment: { PATH: process.env.PATH, API_KEY: "manual-secret" },
    restrictor: { command: setup.restrictor, argsPrefix: [] },
    adapters: [claudeAdapter, codexAdapter, opencodeAdapter],
  };
}

type SimpleSetup = {
  root: string;
  home: string;
  fixture: string;
  configPath: string;
  policyPath: string;
  source: string;
};

async function simpleCodexProject(tools: string[], project?: string): Promise<SimpleSetup> {
  const root = project ?? (await temporaryDirectory());
  const fixture = await writeUpstreamFixture(root);
  const configPath = join(root, ".codex", "config.toml");
  const source = stdioServer("files", fixture, tools);
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, source);
  return {
    root,
    home: join(root, "home"),
    fixture,
    configPath,
    policyPath: join(root, ".mcp-restrictor", "policies", "codex", "files.yaml"),
    source,
  };
}

function setupOptions(setup: SimpleSetup, answers: string[], output: Writable) {
  return {
    input: Readable.from(answers),
    output,
    error: capture(),
    interactive: true,
    cwd: setup.root,
    home: setup.home,
    environment: { PATH: process.env.PATH },
  };
}

type AdapterCandidate = Omit<ServerCandidate, "source" | "upstream"> & {
  source: ServerCandidate["source"] & { kind: "http" };
  upstream: Extract<UpstreamConfig, { kind: "http" }>;
};

function resolvingAdapter(
  configPath: string,
  resolveCandidate: NonNullable<ClientAdapter["resolve"]>,
): ClientAdapter {
  return defineClientAdapter({
    apiVersion: 1,
    id: "fake",
    label: "Fake",
    async load(_context, host) {
      const snapshot = await host.readConfig(configPath);
      if (!snapshot) throw new Error("missing adapter fixture");
      const candidate: AdapterCandidate = {
        client: "fake",
        scope: "project",
        name: "files",
        configPath,
        source: {
          kind: "http",
          url: "https://example.test/mcp",
          headers: [{ name: "X-Key", environmentVariable: "SECRET" }],
        },
        upstream: {
          kind: "http",
          url: "https://example.test/mcp",
          headers: [["X-Key", "unresolved"]],
        },
        alternatives: [
          {
            source: {
              kind: "sse",
              url: "https://example.test/mcp",
              headers: [{ name: "X-Key", environmentVariable: "SECRET" }],
            },
            upstream: {
              kind: "sse",
              url: "https://example.test/mcp",
              headers: [["X-Key", "unresolved"]],
            },
          },
          {
            source: {
              kind: "http",
              url: "https://example.test/other",
              headers: [{ name: "X-Key", environmentVariable: "SECRET" }],
            },
            upstream: {
              kind: "http",
              url: "https://example.test/other",
              headers: [["X-Key", "unresolved"]],
            },
          },
        ],
        wrapperEnvironment: {},
        original: {},
      };
      return {
        configurations: [
          {
            config: {
              client: "fake",
              scope: "project",
              path: configPath,
              source: snapshot.content,
              servers: [candidate],
              unsupported: [],
            },
            snapshot,
          },
        ],
        unsupported: [],
      };
    },
    resolve: resolveCandidate,
    render: (config) => config.source,
  });
}

function alternativeAdapter(configPath: string, oauth = false): ClientAdapter {
  return defineClientAdapter({
    apiVersion: 1,
    id: "opencode",
    label: "OpenCode",
    async load(_context, host) {
      const snapshot = await host.readConfig(configPath);
      if (!snapshot) throw new Error("missing adapter fixture");
      const source = { kind: "http" as const, url: "https://example.test/mcp", headers: [] };
      const upstream: Extract<UpstreamConfig, { kind: "http" }> = {
        kind: "http",
        url: source.url,
      };
      const candidate: ServerCandidate = {
        client: "opencode",
        scope: "project",
        name: "files",
        configPath,
        source,
        upstream,
        alternatives: [
          {
            source: { kind: "sse", url: source.url, headers: [] },
            upstream: { kind: "sse", url: source.url },
          },
        ],
        wrapperEnvironment: {},
        original: {},
        ...(oauth
          ? {
              oauth: {
                mode: "explicit" as const,
                callback: {
                  host: "127.0.0.1" as const,
                  path: "/callback",
                  port: 0,
                  appendProfileId: false,
                },
              },
            }
          : {}),
      };
      return {
        configurations: [
          {
            config: {
              client: "opencode",
              scope: "project",
              path: configPath,
              source: snapshot.content,
              servers: [candidate],
              unsupported: [],
            },
            snapshot,
          },
        ],
        unsupported: [],
      };
    },
    render: (config) => config.source,
  });
}

function adapterSetupOptions(
  root: string,
  environment: NodeJS.ProcessEnv,
  adapter: ClientAdapter,
  answers: string[],
) {
  return {
    input: Readable.from(answers),
    output: capture(),
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment,
    adapters: [adapter],
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  };
}

function stdioServer(
  name: string,
  fixture: string,
  tools: string[],
  options: {
    mode?: "normal" | "mutate" | "error" | "stderr";
    target?: string;
    env?: Record<string, string>;
  } = {},
): string {
  const args = [fixture, JSON.stringify(tools), options.mode ?? "normal", options.target ?? ""];
  const lines = [
    `[mcp_servers.${JSON.stringify(name)}]`,
    `command = ${JSON.stringify(process.execPath)}`,
    `args = ${JSON.stringify(args)}`,
  ];
  if (options.env && Object.keys(options.env).length) {
    lines.push("", `[mcp_servers.${JSON.stringify(name)}.env]`);
    for (const [key, value] of Object.entries(options.env)) {
      lines.push(`${JSON.stringify(key)} = ${JSON.stringify(value)}`);
    }
  }
  return `${lines.join("\n")}\n`;
}

async function writeUpstreamFixture(root: string): Promise<string> {
  const path = join(root, "setup-upstream.mjs");
  await writeFile(
    path,
    `import { readFileSync, rmSync, writeFileSync } from 'node:fs';
	import { dirname } from 'node:path';
	import { createInterface } from 'node:readline';

const tools = JSON.parse(process.argv[2] ?? '[]');
	const mode = process.argv[3] ?? 'normal';
	const target = process.argv[4] ?? '';
	const marker = process.argv[5] ?? '';
	const lines = createInterface({ input: process.stdin });

	if (mode === 'stderr') process.stderr.write(process.env.ERROR_SECRET);

for await (const line of lines) {
  const request = JSON.parse(line);
  if (!('id' in request)) continue;
  if (request.method === 'initialize') {
    respond(request.id, {
      protocolVersion: request.params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: 'setup-fixture', version: '1.0.0' },
    });
	  } else if (request.method === 'tools/list') {
	    if (mode === 'sabotage') {
	      rmSync(dirname(target), { recursive: true, force: true });
	      writeFileSync(dirname(target), 'blocks rollback');
	      writeFileSync(marker, 'ready');
	      continue;
	    }
	    if (mode === 'mutate') {
      const source = readFileSync(target, 'utf8');
      writeFileSync(target, source.replace('# marker A', '# marker B'));
    }
    if (mode === 'error') {
      process.stdout.write(JSON.stringify({
        jsonrpc: '2.0',
        id: request.id,
        error: { code: -32000, message: process.env.ERROR_SECRET },
      }) + '\\n');
    } else {
      respond(request.id, {
        tools: tools.map((name) => ({ name, inputSchema: { type: 'object' } })),
      });
    }
  }
}

function respond(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\\n');
}
`,
  );
  return path;
}

async function exists(path: string): Promise<boolean> {
  try {
    await readFile(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function errorMessages(error: unknown): string[] {
  if (error instanceof AggregateError) {
    return [error.message, ...error.errors.flatMap(errorMessages)];
  }
  return [error instanceof Error ? error.message : String(error)];
}

function capture(onWrite?: (value: string) => void): Writable & { text(): string } {
  const chunks: Buffer[] = [];
  const stream = new Writable({
    write(chunk: Buffer | string, _encoding, callback) {
      const value = Buffer.from(chunk);
      chunks.push(value);
      onWrite?.(value.toString("utf8"));
      callback();
    },
  }) as Writable & { text(): string };
  stream.text = () => Buffer.concat(chunks).toString("utf8");
  return stream;
}

type OAuthSetup = SimpleSetup & {
  keyPath: string;
  serverUrl: string;
  environment: NodeJS.ProcessEnv;
  storageOptions: {
    home: string;
    environment: NodeJS.ProcessEnv;
  };
};

async function codexOAuthProject(
  options: {
    source?: string;
    environment?: NodeJS.ProcessEnv;
    keyContent?: string;
  } = {},
): Promise<OAuthSetup> {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const configPath = join(root, ".codex", "config.toml");
  const serverUrl = "https://resource.example.test/mcp";
  const source = options.source ?? `[mcp_servers.protected]\nurl = ${JSON.stringify(serverUrl)}\n`;
  const keyPath = join(root, "oauth-master.key");
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, source);
  await writeFile(keyPath, options.keyContent ?? randomBytes(32).toString("base64url"));
  await chmod(keyPath, 0o600);
  const environment = {
    PATH: process.env.PATH,
    [MASTER_KEY_FILE_ENV]: keyPath,
    ...options.environment,
  };
  return {
    root,
    home,
    fixture: "",
    configPath,
    policyPath: join(root, ".mcp-restrictor", "policies", "codex", "protected.yaml"),
    source,
    keyPath,
    serverUrl: serverUrlFromCodex(source),
    environment,
    storageOptions: { home, environment },
  };
}

async function claudeOAuthProject(
  options: {
    oauth?: Record<string, unknown>;
    type?: "http" | "sse";
    keyContent?: string;
  } = {},
): Promise<OAuthSetup> {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const configPath = join(root, ".mcp.json");
  const serverUrl =
    options.type === "sse"
      ? "https://resource.example.test/events"
      : "https://resource.example.test/mcp";
  const source = `${JSON.stringify(
    {
      mcpServers: {
        protected: {
          type: options.type ?? "http",
          url: serverUrl,
          ...(options.oauth ? { oauth: options.oauth } : {}),
        },
      },
    },
    null,
    2,
  )}\n`;
  const keyPath = join(root, "oauth-master.key");
  await writeFile(configPath, source);
  await writeFile(keyPath, options.keyContent ?? randomBytes(32).toString("base64url"));
  await chmod(keyPath, 0o600);
  const environment = {
    PATH: process.env.PATH,
    [MASTER_KEY_FILE_ENV]: keyPath,
  };
  return {
    root,
    home,
    fixture: "",
    configPath,
    policyPath: join(root, ".mcp-restrictor", "policies", "claude", "protected.yaml"),
    source,
    keyPath,
    serverUrl,
    environment,
    storageOptions: { home, environment },
  };
}

function oauthSetupOptions(setup: OAuthSetup, answers: readonly string[], output: Writable) {
  return {
    input: Readable.from(answers),
    output,
    error: capture(),
    interactive: true,
    cwd: setup.root,
    home: setup.home,
    environment: setup.environment,
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  };
}

async function expectOAuthSetupUnchanged(setup: OAuthSetup): Promise<void> {
  expect(await readFile(setup.configPath, "utf8")).toBe(setup.source);
  expect(await exists(setup.policyPath)).toBe(false);
  expect(await exists(join(setup.home, ".mcp-restrictor", "oauth"))).toBe(false);
}

function oauthChallenge(resourceMetadataUrl: string, scope?: string): string {
  return [
    `Bearer resource_metadata=${JSON.stringify(resourceMetadataUrl)}`,
    ...(scope ? [`scope=${JSON.stringify(scope)}`] : []),
  ].join(", ");
}

function exampleProfile(
  profileId: string,
  serverUrl: string,
  options: {
    metadata?: OAuthProfile["metadata"];
    clientInformation?: OAuthProfile["credentials"]["clientInformation"];
    accessToken?: string;
  } = {},
): OAuthProfile {
  const issuer = "https://auth.example.test/";
  const metadata = options.metadata ?? {
    version: 1,
    profileId,
    serverUrl,
    callback: {
      host: "127.0.0.1",
      path: "/callback",
      appendProfileId: true,
    },
    clientMetadata: {
      client_name: "MCP Restrictor",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    },
  };
  return {
    metadata,
    credentials: {
      clientInformation: options.clientInformation ?? {
        client_id: "registered-client",
        issuer,
      },
      tokens: {
        access_token: options.accessToken ?? "access-token",
        refresh_token: "refresh-token",
        token_type: "Bearer",
        issuer,
      },
      discoveryState: {
        authorizationServerUrl: issuer,
        authorizationServerMetadata: {
          issuer,
          authorization_endpoint: `${issuer}authorize`,
          token_endpoint: `${issuer}token`,
          response_types_supported: ["code"],
        },
      },
    },
  };
}

async function startOpenCodeNegotiationFixture(httpStatus: 200 | 401 | 404 | 500): Promise<{
  url: string;
  sseMessages(): number;
  close(): Promise<void>;
}> {
  const transport = new NodeStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  transport.onmessage = (message) => {
    if (!("method" in message) || !("id" in message)) return;
    const result =
      message.method === "initialize"
        ? {
            protocolVersion: (message.params as { protocolVersion: string }).protocolVersion,
            capabilities: { tools: {} },
            serverInfo: { name: "opencode-negotiation", version: "1.0.0" },
          }
        : message.method === "tools/list"
          ? { tools: [{ name: "read_file", inputSchema: { type: "object" } }] }
          : {};
    void transport.send(
      { jsonrpc: "2.0", id: message.id, result },
      { relatedRequestId: message.id },
    );
  };
  await transport.start();

  let sseMessageRequests = 0;
  let stream: ServerResponse | undefined;
  const server = createServer(async (request, response) => {
    if (request.method === "POST" && request.url === "/mcp") {
      if (
        httpStatus === 200 ||
        (httpStatus === 401 && request.headers.authorization === "Bearer oauth-token")
      ) {
        await transport.handleRequest(request, response);
        return;
      }
      response
        .writeHead(
          httpStatus,
          httpStatus === 401
            ? {
                "WWW-Authenticate": `Bearer resource_metadata="http://127.0.0.1:${serverAddress(server).port}/metadata"`,
              }
            : undefined,
        )
        .end("HTTP transport unavailable");
      return;
    }
    if (request.method === "GET" && request.url === "/mcp") {
      stream = response;
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write("event: endpoint\ndata: /messages\n\n");
      return;
    }
    if (request.method !== "POST" || request.url !== "/messages") {
      response.writeHead(404).end();
      return;
    }
    sseMessageRequests += 1;
    const message = await readSetupJsonRequest(request);
    const result =
      message.method === "initialize"
        ? {
            protocolVersion: message.params?.protocolVersion ?? "",
            capabilities: { tools: {} },
            serverInfo: { name: "opencode-sse", version: "1.0.0" },
          }
        : { tools: [{ name: "read_file", inputSchema: { type: "object" } }] };
    stream?.write(`data: ${JSON.stringify({ jsonrpc: "2.0", id: message.id, result })}\n\n`);
    response.writeHead(202).end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = serverAddress(server);
  return {
    url: `http://127.0.0.1:${address.port}/mcp`,
    sseMessages: () => sseMessageRequests,
    close: async () => {
      stream?.end();
      await transport.close();
      await new Promise<void>((resolveClose, reject) => {
        server.close((error) => (error ? reject(error) : resolveClose()));
      });
    },
  };
}

function serverAddress(server: Server): { port: number } {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");
  return address;
}

async function readSetupJsonRequest(request: IncomingMessage): Promise<{
  id: string | number;
  method: string;
  params?: { protocolVersion?: string };
}> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function serverUrlFromCodex(source: string): string {
  const parsed = parse(source) as { mcp_servers: Record<string, { url: string }> };
  return Object.values(parsed.mcp_servers)[0]!.url;
}

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
