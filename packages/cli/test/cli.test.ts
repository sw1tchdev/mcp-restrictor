import { spawn } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { once } from "node:events";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { PassThrough, Readable, Writable, type Duplex } from "node:stream";
import { fileURLToPath } from "node:url";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import { runStdioProxy, startHttpProxy } from "@mcp-restrictor/transports";
import { expect, test, vi } from "vitest";
import { main } from "../src/index.ts";
import { resolveProxyRoute, runProxyCommand } from "../src/commands/proxy.ts";
import { defineClientAdapter } from "../src/client-adapter.ts";
import {
  installClientAdapter,
  listClientAdapters,
  loadInstalledClientAdapters,
  removeClientAdapter,
} from "../src/client-plugins.ts";
import { readSecretLine } from "../src/secret-input.ts";
import { loginOAuthProfile } from "../src/oauth/login.ts";
import { createOAuthAuthProvider } from "../src/oauth/provider.ts";
import { CONTAINER_MARKER_ENV } from "../src/setup/constants.ts";
import {
  MASTER_KEY_FILE_ENV,
  oauthProfilePath,
  readOAuthProfile,
  readOAuthProfileSnapshot,
  writeOAuthProfile,
  type OAuthProfile,
} from "../src/oauth/storage.ts";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(testDirectory, "../../..");
const { WebSocketServer } = createRequire(resolve(projectRoot, "packages/transports/package.json"))(
  "ws",
) as typeof import("ws");
const cli = resolve(projectRoot, "packages/cli/dist/index.js");
const policy = resolve(testDirectory, "fixtures/policy.yaml");
const upstream = resolve(testDirectory, "fixtures/upstream.mjs");
const configSensitiveUpstream = resolve(
  projectRoot,
  "packages/transports/test/fixtures/config-sensitive-upstream.mjs",
);
const certificate = resolve(testDirectory, "fixtures/localhost-cert.pem");
const privateKey = resolve(testDirectory, "fixtures/localhost-key.pem");
const oauthProfileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const trustedInstallWarning =
  "This npm package is trusted code and will run with your user permissions. npm lifecycle scripts will be disabled. Install it? [Y/n]: ";

test.each(["http", "sse", "websocket"] as const)(
  "runs a live %s upstream with plain and base64url headers",
  async (kind) => {
    const secrets = {
      plain: `${kind}-plain-secret`,
      encoded: `${kind}-encoded-secret`,
      bearer: `${kind}-bearer-secret`,
    };
    const fixture = await startRemoteFixture(kind, secrets);
    const plainEnvironmentName = kind === "http" ? "__proto__" : "PLAIN_ENV";
    const args = [
      cli,
      "--policy",
      policy,
      `--upstream-${kind}`,
      fixture.url,
      "--upstream-header-env",
      `X-Plain=${plainEnvironmentName}`,
      "--upstream-header-base64url-env",
      "X-Encoded=ENCODED_ENV",
      ...(kind === "websocket" ? [] : ["--upstream-bearer-token-env", "BEARER_ENV"]),
    ];
    const environment = {
      ...process.env,
      ENCODED_ENV: Buffer.from(secrets.encoded).toString("base64url"),
      BEARER_ENV: secrets.bearer,
    };
    Object.defineProperty(environment, plainEnvironmentName, {
      value: secrets.plain,
      enumerable: true,
      configurable: true,
      writable: true,
    });
    const child = spawn(process.execPath, args, {
      cwd: projectRoot,
      env: environment,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

    try {
      child.stdin.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "cli-test", version: "1.0.0" },
          },
        })}\n`,
      );
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" })}\n`);
      child.stdin.end();

      const [code] = await once(child, "exit");
      const diagnostics = Buffer.concat(stderr).toString("utf8");
      expect(code, diagnostics).toBe(0);
      const responses = Buffer.concat(stdout)
        .toString("utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(responses.find((response) => response.id === 2).result.tools).toEqual([
        { name: "read_file", inputSchema: { type: "object" } },
      ]);
      expect(fixture.accepted).toBeGreaterThan(0);
      for (const secret of Object.values(secrets)) {
        expect(child.spawnargs.join(" ")).not.toContain(secret);
        expect(diagnostics).not.toContain(secret);
      }
    } finally {
      if (child.exitCode === null) child.kill();
      await fixture.close();
    }
  },
);

test.each(["http", "sse"] as const)(
  "runs a live %s upstream with an encrypted OAuth profile",
  async (kind) => {
    const secrets = {
      plain: `${kind}-plain-secret`,
      encoded: `${kind}-encoded-secret`,
      bearer: `${kind}-oauth-access-token`,
    };
    const fixture = await startRemoteFixture(kind, secrets);
    const stored = await storedCliProfile(fixture.url, {
      resource: `${fixture.url}/resource`,
      accessToken: secrets.bearer,
    });
    const child = spawn(
      process.execPath,
      [
        cli,
        "--policy",
        policy,
        `--upstream-${kind}`,
        fixture.url,
        "--upstream-header-env",
        "X-Plain=PLAIN_ENV",
        "--upstream-header-base64url-env",
        "X-Encoded=ENCODED_ENV",
        "--upstream-oauth-profile",
        stored.id,
      ],
      {
        cwd: projectRoot,
        env: {
          ...process.env,
          HOME: stored.home,
          [MASTER_KEY_FILE_ENV]: stored.keyPath,
          PLAIN_ENV: secrets.plain,
          ENCODED_ENV: Buffer.from(secrets.encoded).toString("base64url"),
        },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

    try {
      child.stdin.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {
            protocolVersion: "2025-11-25",
            capabilities: {},
            clientInfo: { name: "oauth-cli-test", version: "1.0.0" },
          },
        })}\n`,
      );
      child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" })}\n`);
      child.stdin.end();

      const [code] = await once(child, "exit");
      const diagnostics = Buffer.concat(stderr).toString("utf8");
      expect(code, diagnostics).toBe(0);
      const responses = Buffer.concat(stdout)
        .toString("utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
      expect(responses.find((response) => response.id === 2).result.tools).toEqual([
        { name: "read_file", inputSchema: { type: "object" } },
      ]);
      expect(fixture.accepted).toBeGreaterThan(0);
      expect(child.spawnargs.join(" ")).not.toContain(secrets.bearer);
      expect(diagnostics).not.toContain(secrets.bearer);
    } finally {
      if (child.exitCode === null) child.kill();
      await fixture.close();
      await rm(stored.home, { force: true, recursive: true });
    }
  },
);

test.each([
  [
    "http",
    "different origin",
    (url: string) => {
      const parsed = new URL(url);
      parsed.port = String(Number(parsed.port) + 1);
      return parsed.href;
    },
  ],
  ["http", "different path", (url: string) => `${url}/other`],
  [
    "sse",
    "different origin",
    (url: string) => {
      const parsed = new URL(url);
      parsed.port = String(Number(parsed.port) + 1);
      return parsed.href;
    },
  ],
  ["sse", "different path", (url: string) => `${url}/other`],
] as const)(
  "rejects an OAuth %s profile bound to a %s before connection",
  async (kind, _name, boundUrl) => {
    const fixture = await startCountingServer();
    const stored = await storedCliProfile(boundUrl(fixture.url));

    try {
      const result = await runCli(
        [
          "--policy",
          policy,
          `--upstream-${kind}`,
          fixture.url,
          "--upstream-oauth-profile",
          stored.id,
        ],
        stored,
      );

      expect(result.code).toBe(1);
      expect(result.stderr).toMatch(/OAuth (server binding mismatch|profile)/i);
      expect(fixture.connections).toBe(0);
    } finally {
      await fixture.close();
      await rm(stored.home, { force: true, recursive: true });
    }
  },
);

test.each(["missing", "malformed", "wrong key"] as const)(
  "rejects a %s OAuth profile before connection",
  async (failure) => {
    const fixture = await startCountingServer();
    const stored = await emptyCliStorage();
    try {
      if (failure === "malformed") {
        const directory = dirname(oauthProfilePath(stored.home, stored.id));
        await mkdir(directory, { recursive: true, mode: 0o700 });
        await chmod(directory, 0o700);
        await writeFile(oauthProfilePath(stored.home, stored.id), "{bad json", {
          mode: 0o600,
        });
      } else if (failure === "wrong key") {
        await writeOAuthProfile(exampleCliProfile(stored.id, fixture.url), {
          home: stored.home,
          environment: { [MASTER_KEY_FILE_ENV]: stored.keyPath },
        });
        await writeFile(stored.keyPath, randomBytes(32).toString("base64url"), {
          mode: 0o600,
        });
      }

      const result = await runCli(
        ["--policy", policy, "--upstream-http", fixture.url, "--upstream-oauth-profile", stored.id],
        stored,
      );

      expect(result.code).toBe(1);
      expect(result.stderr).toMatch(/OAuth profile/i);
      expect(fixture.connections).toBe(0);
    } finally {
      await fixture.close();
      await rm(stored.home, { force: true, recursive: true });
    }
  },
);

test.each([
  {
    name: "OAuth on STDIO",
    args: ["--upstream-oauth-profile", "not-a-profile", "--", process.execPath, "-e", ""],
    message: /requires an HTTP or SSE upstream/i,
  },
  {
    name: "OAuth on WebSocket",
    args: [
      "--upstream-websocket",
      "ws://127.0.0.1:1/mcp",
      "--upstream-oauth-profile",
      "not-a-profile",
    ],
    message: /does not support WebSocket/i,
  },
  {
    name: "OAuth with bearer",
    args: [
      "--upstream-http",
      "http://127.0.0.1:1/mcp",
      "--upstream-oauth-profile",
      "not-a-profile",
      "--upstream-bearer-token-env",
      "MISSING",
    ],
    message: /conflicting upstream authentication/i,
  },
  {
    name: "OAuth with an empty bearer selector",
    args: [
      "--upstream-http",
      "http://127.0.0.1:1/mcp",
      "--upstream-oauth-profile",
      "not-a-profile",
      "--upstream-bearer-token-env",
      "",
    ],
    message: /conflicting upstream authentication/i,
  },
  {
    name: "OAuth with Authorization mapping",
    args: [
      "--upstream-http",
      "http://127.0.0.1:1/mcp",
      "--upstream-oauth-profile",
      "not-a-profile",
      "--upstream-header-env",
      "Authorization=MISSING",
    ],
    message: /conflicting upstream authentication/i,
  },
  {
    name: "OAuth with master-key header mapping",
    args: [
      "--upstream-http",
      "http://127.0.0.1:1/mcp",
      "--upstream-oauth-profile",
      "not-a-profile",
      "--upstream-header-env",
      "X-Key=mCp_ReStRiCtOr_MaStEr_KeY_fIlE",
    ],
    message: /master key/i,
  },
  {
    name: "duplicate OAuth profile selector",
    args: [
      "--upstream-http",
      "http://127.0.0.1:1/mcp",
      "--upstream-oauth-profile",
      oauthProfileId,
      "--upstream-oauth-profile",
      oauthProfileId,
    ],
    message: /exactly one OAuth profile/i,
  },
] as const)("rejects $name before secret or profile resolution", async ({ args, message }) => {
  const child = spawn(process.execPath, [cli, "--policy", "/missing-policy.yaml", ...args], {
    cwd: projectRoot,
    env: { ...process.env },
    stdio: ["ignore", "ignore", "pipe"],
  });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

  const [code] = await once(child, "exit");
  const diagnostics = Buffer.concat(stderr).toString("utf8");

  expect(code).toBe(1);
  expect(diagnostics).toMatch(message);
  expect(diagnostics).not.toMatch(/MISSING.*(empty|missing)/);
  expect(diagnostics).not.toMatch(/profile not-a-profile/i);
});

test.each([
  ["missing", "MISSING", undefined],
  ["empty", "EMPTY", ""],
  ["inherited", "__proto__", undefined],
  ["non-canonical base64url", "ENCODED", "c2VjcmV0="],
  ["invalid UTF-8 base64url", "ENCODED", "_w"],
] as const)(
  "rejects a %s remote header environment before connection",
  async (caseName, environmentName, value) => {
    let requests = 0;
    const server = await startHttpServer((_request, response) => {
      requests += 1;
      response.writeHead(500).end();
    });
    const env = { ...process.env };
    delete env[environmentName];
    if (value !== undefined) env[environmentName] = value;
    const flag =
      caseName.includes("base64url") || caseName.includes("UTF-8")
        ? "--upstream-header-base64url-env"
        : "--upstream-header-env";
    const child = spawn(
      process.execPath,
      [cli, "--policy", policy, "--upstream-http", server.url, flag, `X-Key=${environmentName}`],
      { cwd: projectRoot, env, stdio: ["ignore", "ignore", "pipe"] },
    );
    const stderr: Buffer[] = [];
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

    try {
      const [code] = await once(child, "exit");
      expect(code).toBe(1);
      expect(requests).toBe(0);
      if (value) expect(Buffer.concat(stderr).toString("utf8")).not.toContain(value);
    } finally {
      if (child.exitCode === null) child.kill();
      await server.close();
    }
  },
);

test.each([
  [
    "duplicate headers",
    ["--upstream-header-env", "X-Key=ONE", "--upstream-header-base64url-env", "x-key=TWO"],
  ],
  [
    "bearer and Authorization",
    ["--upstream-header-env", "Authorization=ONE", "--upstream-bearer-token-env", "TOKEN"],
  ],
  ["bearer on WebSocket", ["--upstream-bearer-token-env", "TOKEN"]],
] as const)("rejects %s before connection", async (_case, extraArgs) => {
  let requests = 0;
  const server = await startHttpServer((_request, response) => {
    requests += 1;
    response.writeHead(500).end();
  });
  const websocket = _case === "bearer on WebSocket";
  const child = spawn(
    process.execPath,
    [
      cli,
      "--policy",
      policy,
      websocket ? "--upstream-websocket" : "--upstream-http",
      websocket ? server.url.replace("http:", "ws:") : server.url,
      ...extraArgs,
    ],
    {
      cwd: projectRoot,
      env: { ...process.env, ONE: "one", TWO: "dHdv", TOKEN: "token" },
      stdio: ["ignore", "ignore", "pipe"],
    },
  );

  try {
    const [code] = await once(child, "exit");
    expect(code).toBe(1);
    expect(requests).toBe(0);
  } finally {
    if (child.exitCode === null) child.kill();
    await server.close();
  }
});

test.each(["http", "sse", "websocket"] as const)(
  "rejects a repeated %s selector before connection",
  async (kind) => {
    let connections = 0;
    const server = createServer((_request, response) => {
      response.writeHead(500).end();
    });
    server.on("connection", () => {
      connections += 1;
    });
    server.on("upgrade", (_request, socket) => socket.destroy());
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const url =
      kind === "websocket" ? serverUrl(server).replace("http:", "ws:") : serverUrl(server);
    const selector = `--upstream-${kind}`;
    const child = spawn(process.execPath, [cli, "--policy", policy, selector, url, selector, url], {
      cwd: projectRoot,
      stdio: ["pipe", "ignore", "pipe"],
    });

    try {
      child.stdin.end(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })}\n`);
      const [code] = await once(child, "exit");
      expect(code).toBe(1);
      expect(connections).toBe(0);
    } finally {
      if (child.exitCode === null) child.kill();
      await closeHttpServer(server);
    }
  },
);

test("aborts a pending WebSocket open and closes its socket", async () => {
  let socket: Duplex | undefined;
  let markUpgrade!: () => void;
  const upgraded = new Promise<void>((resolveUpgrade) => {
    markUpgrade = resolveUpgrade;
  });
  const server = createServer();
  server.on("upgrade", (_request, upgradedSocket) => {
    socket = upgradedSocket;
    markUpgrade();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");
  const child = spawn(
    process.execPath,
    [cli, "--policy", policy, "--upstream-websocket", `ws://127.0.0.1:${address.port}/mcp`],
    { cwd: projectRoot, stdio: ["pipe", "ignore", "pipe"] },
  );
  const exit = once(child, "exit");

  try {
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })}\n`);
    const opened = await Promise.race([upgraded.then(() => true), exit.then(() => false)]);
    expect(opened).toBe(true);
    const ended = once(socket!, "end");
    child.kill("SIGTERM");
    const outcome = await Promise.race([
      Promise.all([exit, ended]).then(() => "ended" as const),
      new Promise<"timeout">((resolveTimeout) =>
        setTimeout(() => resolveTimeout("timeout"), 1_000),
      ),
    ]);
    expect(outcome, `exitCode=${child.exitCode} readableEnded=${socket!.readableEnded}`).toBe(
      "ended",
    );
    expect(socket!.readableEnded).toBe(true);
  } finally {
    if (child.exitCode === null) child.kill();
    socket?.destroy();
    await closeHttpServer(server);
  }
});

test("dispatches setup and refuses a non-interactive terminal", async () => {
  const child = spawn(process.execPath, [cli, "setup"], {
    cwd: projectRoot,
    stdio: ["ignore", "ignore", "pipe"],
  });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

  const [code] = await once(child, "exit");

  expect(code).toBe(1);
  expect(Buffer.concat(stderr).toString("utf8")).toBe(
    "mcp-restrictor: setup requires an interactive terminal\n",
  );
});

test("rejects extra setup arguments with the setup usage", async () => {
  const child = spawn(process.execPath, [cli, "setup", "extra"], {
    cwd: projectRoot,
    stdio: ["ignore", "ignore", "pipe"],
  });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

  const [code] = await once(child, "exit");

  expect(code).toBe(1);
  expect(Buffer.concat(stderr).toString("utf8")).toBe(
    "mcp-restrictor: Usage: mcp-restrictor setup\n",
  );
});

test.each([["run"], ["run", "--bind", "0.0.0.0"]] as const)(
  "accepts exact managed gateway syntax: %s",
  async (...args) => {
    const home = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-run-syntax-")));
    try {
      await expect(main({ argv: [process.execPath, cli, ...args], home })).rejects.toThrow(
        "No managed HTTP routes; run setup",
      );
    } finally {
      await rm(home, { force: true, recursive: true });
    }
  },
);

test.each([
  ["arbitrary host", ["run", "--bind", "192.0.2.1"]],
  ["duplicate bind flag", ["run", "--bind", "0.0.0.0", "--bind", "0.0.0.0"]],
  ["missing bind value", ["run", "--bind"]],
  ["IPv6 wildcard", ["run", "--bind", "::"]],
  ["extra argument", ["run", "private-argument"]],
  ["extra argument after bind", ["run", "--bind", "0.0.0.0", "private-argument"]],
] as const)(
  "rejects run with $0 before loading routes or starting the gateway",
  async (_name, args) => {
    const startGateway = vi.fn(() => {
      throw new Error("must not start gateway");
    });
    let homeReads = 0;
    const options: Parameters<typeof main>[0] = {
      argv: [process.execPath, cli, ...args],
      startHttpGateway: startGateway,
    };
    Object.defineProperty(options, "home", {
      get() {
        homeReads += 1;
        throw new Error("must not load routes");
      },
    });

    await expect(main(options)).rejects.toThrowError(
      new Error("Usage: mcp-restrictor run [--bind 0.0.0.0]"),
    );
    expect(homeReads).toBe(0);
    expect(startGateway).not.toHaveBeenCalled();
  },
);

test("rejects the managed bind flag in direct proxy mode", async () => {
  const startGateway = vi.fn(() => {
    throw new Error("must not start gateway");
  });

  await expect(
    main({
      argv: [
        process.execPath,
        cli,
        "--bind",
        "0.0.0.0",
        "--policy",
        policy,
        "--",
        process.execPath,
      ],
      startHttpGateway: startGateway,
    }),
  ).rejects.toThrow();
  expect(startGateway).not.toHaveBeenCalled();
});

test("shared proxy resolution preserves the direct remote upstream and policy", async () => {
  const runProxy = vi.fn<typeof runStdioProxy>(async ({ upstream: configured, authorizer }) => {
    expect(configured).toEqual({
      kind: "http",
      url: "https://api.example.test/mcp",
      headers: [["X-Key", "header-secret"]],
      bearerToken: "bearer-secret",
    });
    expect(authorizer.discover("read_file")).toBe(true);
    expect(authorizer.discover("delete_file")).toBe(false);
    return 0;
  });

  await main({
    argv: [
      process.execPath,
      cli,
      "--policy",
      policy,
      "--upstream-http",
      "https://api.example.test/mcp",
      "--upstream-header-env",
      "X-Key=HEADER_ENV",
      "--upstream-bearer-token-env",
      "TOKEN_ENV",
    ],
    environment: { HEADER_ENV: "header-secret", TOKEN_ENV: "bearer-secret" },
    signal: new AbortController().signal,
    runStdioProxy: runProxy,
  });

  expect(runProxy).toHaveBeenCalledOnce();
});

test.each([
  {
    name: "missing subcommand",
    args: ["client"],
    usage: "Usage: mcp-restrictor client (install NPM_SPEC | list | remove PACKAGE_NAME)",
  },
  {
    name: "unknown subcommand",
    args: ["client", "unknown"],
    usage: "Usage: mcp-restrictor client (install NPM_SPEC | list | remove PACKAGE_NAME)",
  },
  {
    name: "missing install spec",
    args: ["client", "install"],
    usage: "Usage: mcp-restrictor client install NPM_SPEC",
  },
  {
    name: "extra install argument",
    args: ["client", "install", "fixture", "secret-extra"],
    usage: "Usage: mcp-restrictor client install NPM_SPEC",
  },
  {
    name: "extra list argument",
    args: ["client", "list", "secret-extra"],
    usage: "Usage: mcp-restrictor client list",
  },
  {
    name: "missing remove name",
    args: ["client", "remove"],
    usage: "Usage: mcp-restrictor client remove PACKAGE_NAME",
  },
  {
    name: "extra remove argument",
    args: ["client", "remove", "fixture", "secret-extra"],
    usage: "Usage: mcp-restrictor client remove PACKAGE_NAME",
  },
] as const)(
  "rejects client command with $name using fixed exact-arity usage",
  async ({ args, usage }) => {
    const clientPlugins = clientPluginDoubles();
    let pluginReads = 0;

    await expect(
      main(
        withClientPluginGetter(
          {
            argv: [process.execPath, cli, ...args],
          },
          clientPlugins,
          () => {
            pluginReads += 1;
          },
        ),
      ),
    ).rejects.toThrowError(new Error(usage));

    expect(pluginReads).toBe(0);
    expectClientPluginsUnused(clientPlugins);
  },
);

test("rejects extra setup arguments before reading client plugin operations", async () => {
  const clientPlugins = clientPluginDoubles();
  let pluginReads = 0;

  await expect(
    main(
      withClientPluginGetter(
        {
          argv: [process.execPath, cli, "setup", "secret-extra"],
        },
        clientPlugins,
        () => {
          pluginReads += 1;
        },
      ),
    ),
  ).rejects.toThrowError(new Error("Usage: mcp-restrictor setup"));

  expect(pluginReads).toBe(0);
  expectClientPluginsUnused(clientPlugins);
});

test.each(["no"])("does not install after selecting %s", async (answer) => {
  const clientPlugins = clientPluginDoubles();
  let pluginReads = 0;
  let installReads = 0;
  observeOperationRead(clientPlugins, "install", () => {
    installReads += 1;
  });
  const input = new PassThrough();
  const output = capturedCliOutput();
  input.end(`${answer}\n`);

  await expect(
    main(
      withClientPluginGetter(
        {
          argv: [process.execPath, cli, "client", "install", "private-source-secret"],
          home: "/home/fixture",
          environment: { PRIVATE_ENV: "environment-secret" },
          input,
          output,
        },
        clientPlugins,
        () => {
          pluginReads += 1;
        },
      ),
    ),
  ).rejects.toThrowError(new Error("Client adapter installation cancelled"));

  expect(output.text()).toBe(trustedInstallWarning);
  expect(pluginReads).toBe(0);
  expect(installReads).toBe(0);
  expectClientPluginsUnused(clientPlugins);
});

test("cancels client installation on EOF before package or filesystem work", async () => {
  const clientPlugins = clientPluginDoubles();
  let pluginReads = 0;
  const input = new PassThrough();
  const output = capturedCliOutput();
  input.end();

  await expect(
    main(
      withClientPluginGetter(
        {
          argv: [process.execPath, cli, "client", "install", "private-source-secret"],
          input,
          output,
        },
        clientPlugins,
        () => {
          pluginReads += 1;
        },
      ),
    ),
  ).rejects.toThrowError(new Error("Client adapter installation cancelled"));

  expect(output.text()).toBe(trustedInstallWarning);
  expect(pluginReads).toBe(0);
  expectClientPluginsUnused(clientPlugins);
});

test("cancels TTY client installation on EOF after its Ink selector renders", async () => {
  const clientPlugins = clientPluginDoubles();
  const input = new TestTtyInput();
  const output = capturedCliOutput(true);
  const running = main(
    withClientPluginGetter(
      {
        argv: [process.execPath, cli, "client", "install", "private-source-secret"],
        input,
        output,
      },
      clientPlugins,
      () => {
        throw new Error("plugin boundary must not be read");
      },
    ),
  );

  await vi.waitFor(() => expect(input.isRaw).toBe(true));
  input.end();
  await expect(running).rejects.toThrow("Client adapter installation cancelled");
  expectClientPluginsUnused(clientPlugins);
  expect(input.isRaw).toBe(false);
});

test("cancels a pending client installation signal before package or filesystem work", async () => {
  const clientPlugins = clientPluginDoubles();
  const input = new PassThrough();
  const output = capturedCliOutput();
  const controller = new AbortController();
  let contextReads = 0;
  let pluginReads = 0;
  const options = {
    argv: [process.execPath, cli, "client", "install", "private-source-secret"],
    input,
    output,
    signal: controller.signal,
  };
  Object.defineProperties(options, {
    home: {
      get: () => {
        contextReads += 1;
        return "/home/fixture";
      },
    },
    environment: {
      get: () => {
        contextReads += 1;
        return {};
      },
    },
    clientPlugins: {
      get: () => {
        pluginReads += 1;
        return clientPlugins;
      },
    },
  });
  const running = main(options);
  const settled = running.then(
    () => ({ error: undefined }),
    (error: unknown) => ({ error }),
  );

  await new Promise<void>((resolveTurn) => setImmediate(resolveTurn));
  expect(output.text()).toBe(trustedInstallWarning);
  expect(contextReads).toBe(0);
  expect(pluginReads).toBe(0);
  expectClientPluginsUnused(clientPlugins);
  controller.abort();

  expect((await settled).error).toBeInstanceOf(Error);
  expect((await settled).error).toHaveProperty("message", expect.stringMatching(/abort|cancel/i));
  expect(contextReads).toBe(0);
  expect(pluginReads).toBe(0);
  expectClientPluginsUnused(clientPlugins);
});

test("maps its SIGINT handler to cancellation before client installation", async () => {
  const clientPlugins = clientPluginDoubles();
  const input = new PassThrough();
  const output = capturedCliOutput();
  let pluginReads = 0;
  const processOnce = vi.spyOn(process, "once");
  const running = main(
    withClientPluginGetter(
      {
        argv: [process.execPath, cli, "client", "install", "private-source-secret"],
        input,
        output,
      },
      clientPlugins,
      () => {
        pluginReads += 1;
      },
    ),
  );
  const settled = running.then(
    () => ({ error: undefined }),
    (error: unknown) => ({ error }),
  );

  try {
    await new Promise<void>((resolveTurn) => setImmediate(resolveTurn));
    const handler = processOnce.mock.calls.find(([event]) => event === "SIGINT")?.[1];
    expect(handler).toBeTypeOf("function");
    (handler as () => void)();

    expect((await settled).error).toHaveProperty(
      "message",
      "Client adapter installation cancelled",
    );
    expect(output.text()).toBe(trustedInstallWarning);
    expect(pluginReads).toBe(0);
    expectClientPluginsUnused(clientPlugins);
  } finally {
    processOnce.mockRestore();
  }
});

test("installs a client adapter when Enter confirms the trust warning", async () => {
  const clientPlugins = clientPluginDoubles();
  let pluginReads = 0;
  let installReads = 0;
  clientPlugins.install.mockResolvedValue({
    plugin: {
      packageName: "@fixture/client-adapter",
      version: "1.2.3",
      requestedSpec: "file:/private/source-secret",
    },
    warnings: ["inactive client adapter files require manual cleanup"],
  });
  observeOperationRead(clientPlugins, "install", () => {
    installReads += 1;
  });
  const input = new PassThrough();
  const output = capturedCliOutput();
  input.end("\n");
  const environment = { PRIVATE_ENV: "environment-secret" };

  await main(
    withClientPluginGetter(
      {
        argv: [process.execPath, cli, "client", "install", "file:/private/source-secret"],
        home: "/home/fixture",
        environment,
        input,
        output,
      },
      clientPlugins,
      () => {
        pluginReads += 1;
      },
    ),
  );

  expect(pluginReads).toBe(1);
  expect(installReads).toBe(1);
  expect(clientPlugins.install).toHaveBeenCalledExactlyOnceWith("file:/private/source-secret", {
    home: "/home/fixture",
    environment,
  });
  expect(output.text()).toBe(
    `${trustedInstallWarning}Installed @fixture/client-adapter@1.2.3.\nWarning: inactive client adapter files require manual cleanup.\n`,
  );
  expect(output.text()).not.toContain("/private/source-secret");
  expect(output.text()).not.toContain("environment-secret");
  expect(clientPlugins.list).not.toHaveBeenCalled();
  expect(clientPlugins.load).not.toHaveBeenCalled();
  expect(clientPlugins.remove).not.toHaveBeenCalled();
});

test("keeps a fixed installation failure free of package source and diagnostics", async () => {
  const clientPlugins = clientPluginDoubles();
  clientPlugins.install.mockRejectedValue(
    new AggregateError(
      [new Error("/private/npm stderr secret"), new Error("manifest and environment secret")],
      "import secret",
    ),
  );
  const input = new PassThrough();
  const output = capturedCliOutput();
  input.end("yes\n");

  await expect(
    main({
      argv: [process.execPath, cli, "client", "install", "file:/private/source-secret"],
      input,
      output,
      clientPlugins,
    }),
  ).rejects.toThrowError(new Error("Client adapter installation failed"));

  expect(output.text()).toBe(trustedInstallWarning);
  expect(output.text()).not.toContain("/private/source-secret");
  expect(output.text()).not.toContain("npm stderr secret");
  expect(output.text()).not.toContain("import secret");
});

test("lists available and unavailable adapters in stable sanitized rows", async () => {
  const clientPlugins = clientPluginDoubles();
  clientPlugins.list.mockResolvedValue([
    {
      packageName: "z-broken",
      version: "2.0.0",
      status: "unavailable",
      reason: "client adapter failed to load",
      requestedSpec: "file:/private/source-secret",
      manifest: "manifest-secret",
    },
    {
      packageName: "@fixture/available",
      version: "1.0.0",
      id: "fixture-adapter",
      label: "Fixture\u001bLabel",
      status: "available",
      requestedSpec: "file:/private/source-secret",
      importedError: "import-secret",
    },
  ] as unknown as Awaited<ReturnType<typeof listClientAdapters>>);
  const output = capturedCliOutput();

  await main({
    argv: [process.execPath, cli, "client", "list"],
    home: "/home/fixture",
    output,
    clientPlugins,
  });

  expect(clientPlugins.list).toHaveBeenCalledExactlyOnceWith({ home: "/home/fixture" });
  expect(output.text()).toBe(
    '@fixture/available@1.0.0 available (id=fixture-adapter, label="Fixture\\u001bLabel")\nz-broken@2.0.0 unavailable (client adapter failed to load)\n',
  );
  for (const secret of ["/private/source-secret", "manifest-secret", "import-secret", "\u001b"]) {
    expect(output.text()).not.toContain(secret);
  }
});

test("escapes bidi controls in installed adapter identities without escaping ZWJ", async () => {
  const clientPlugins = clientPluginDoubles();
  const joiner = "\u200d";
  clientPlugins.list.mockResolvedValue([
    {
      packageName: "safe\u202epackage",
      version: "1\u200e0",
      id: "safe\u2066id",
      label: `Visible\u061cMiddle\u2069Tail${joiner}Join`,
      status: "available",
    },
  ] as Awaited<ReturnType<typeof listClientAdapters>>);
  const output = capturedCliOutput();

  await main({
    argv: [process.execPath, cli, "client", "list"],
    output,
    clientPlugins,
  });

  expect(output.text()).toBe(
    `safe\\u202epackage@1\\u200e0 available (id=safe\\u2066id, label="Visible\\u061cMiddle\\u2069Tail${joiner}Join")\n`,
  );
  expect(output.text()).not.toMatch(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u);
  expect(output.text()).toContain(joiner);
});

test("reports an empty installed client adapter list without touching other operations", async () => {
  const clientPlugins = clientPluginDoubles();
  let pluginReads = 0;
  const output = capturedCliOutput();

  await main(
    withClientPluginGetter(
      {
        argv: [process.execPath, cli, "client", "list"],
        output,
      },
      clientPlugins,
      () => {
        pluginReads += 1;
      },
    ),
  );

  expect(pluginReads).toBe(1);
  expect(output.text()).toBe("No installed client adapters.\n");
  expect(clientPlugins.install).not.toHaveBeenCalled();
  expect(clientPlugins.load).not.toHaveBeenCalled();
  expect(clientPlugins.remove).not.toHaveBeenCalled();
});

test("removes the exact installed package name with fixed confirmation output", async () => {
  const clientPlugins = clientPluginDoubles();
  let pluginReads = 0;
  const output = capturedCliOutput();

  await main(
    withClientPluginGetter(
      {
        argv: [process.execPath, cli, "client", "remove", "@fixture/client-adapter"],
        home: "/home/fixture",
        output,
      },
      clientPlugins,
      () => {
        pluginReads += 1;
      },
    ),
  );

  expect(pluginReads).toBe(1);
  expect(clientPlugins.remove).toHaveBeenCalledExactlyOnceWith("@fixture/client-adapter", {
    home: "/home/fixture",
  });
  expect(output.text()).toBe("Removed @fixture/client-adapter.\n");
});

test("reports inactive-file cleanup as a warning after successful logical removal", async () => {
  const clientPlugins = clientPluginDoubles();
  clientPlugins.remove.mockResolvedValue({
    warnings: ["inactive client adapter files require manual cleanup"],
  });
  const output = capturedCliOutput();

  await main({
    argv: [process.execPath, cli, "client", "remove", "fixture-cleanup"],
    output,
    clientPlugins,
  });

  expect(output.text()).toBe(
    "Removed fixture-cleanup.\nWarning: inactive client adapter files require manual cleanup.\n",
  );
});

test("reports an unknown client adapter without leaking paths or metadata", async () => {
  const clientPlugins = clientPluginDoubles();
  clientPlugins.remove.mockRejectedValue(
    new Error("/private/metadata: client adapter is not installed"),
  );
  const output = capturedCliOutput();

  await expect(
    main({
      argv: [process.execPath, cli, "client", "remove", "missing-adapter"],
      home: "/home/fixture",
      output,
      clientPlugins,
    }),
  ).rejects.toThrowError(new Error("Failed to remove client adapter"));

  expect(output.text()).toBe("");
});

test.each([
  [
    "install rejection",
    "install",
    ["client", "install", "file:/private/source-secret"],
    "Client adapter installation failed",
    true,
    false,
  ],
  [
    "install getter",
    "install",
    ["client", "install", "file:/private/source-secret"],
    "Client adapter installation failed",
    true,
    true,
  ],
  ["list rejection", "list", ["client", "list"], "Failed to list client adapters", false, false],
  ["list getter", "list", ["client", "list"], "Failed to list client adapters", false, true],
  [
    "remove rejection",
    "remove",
    ["client", "remove", "fixture-adapter"],
    "Failed to remove client adapter",
    false,
    false,
  ],
  [
    "remove getter",
    "remove",
    ["client", "remove", "fixture-adapter"],
    "Failed to remove client adapter",
    false,
    true,
  ],
] as const)(
  "maps %s to one fixed command error",
  async (_name, operation, args, publicMessage, confirm, getterFailure) => {
    const secret = "/private/client-plugin manifest env npm stderr import secret";
    const clientPlugins = clientPluginDoubles();
    if (!getterFailure) {
      clientPlugins[operation].mockRejectedValue(new AggregateError([new Error(secret)], secret));
    }
    const input = new PassThrough();
    if (confirm) input.end("yes\n");
    const output = capturedCliOutput();
    const options: Parameters<typeof main>[0] = {
      argv: [process.execPath, cli, ...args],
      input,
      output,
      ...(!getterFailure ? { clientPlugins } : {}),
    };
    if (getterFailure) {
      Object.defineProperty(options, "clientPlugins", {
        get() {
          throw new Error(secret);
        },
      });
    }
    const failure = await main(options).then(
      () => undefined,
      (error: unknown) => error,
    );

    expect(failure).toBeInstanceOf(Error);
    expect(failure).not.toBeInstanceOf(AggregateError);
    expect(failure).toHaveProperty("message", publicMessage);
    expect(String(failure)).not.toContain(secret);
    expect(output.text()).toBe(confirm ? trustedInstallWarning : "");
  },
);

test("keeps a client command after -- in proxy mode", async () => {
  const clientPlugins = clientPluginDoubles();
  const runProxy = vi.fn<typeof runStdioProxy>(async ({ upstream: configured }) => {
    expect(configured).toEqual({ kind: "stdio", command: "client", args: ["list"] });
    return 0;
  });

  await main({
    argv: [process.execPath, cli, "--policy", policy, "--", "client", "list"],
    signal: new AbortController().signal,
    runStdioProxy: runProxy,
    clientPlugins,
  });

  expect(runProxy).toHaveBeenCalledOnce();
  expectClientPluginsUnused(clientPlugins);
});

test("loads external adapters before setup and keeps built-ins plus valid siblings visible", async () => {
  const clientPlugins = clientPluginDoubles();
  const externalLoad = vi.fn().mockResolvedValue({ configurations: [], unsupported: [] });
  const joiner = "\u200d";
  const external = defineClientAdapter({
    apiVersion: 1,
    id: "fixture-external",
    label: `Zed\u202e External${joiner}`,
    load: externalLoad,
    render: (config) => config.source,
  });
  const input = ttyInput("1\n4\n");
  const output = capturedCliOutput(true);
  clientPlugins.load.mockImplementation(async () => {
    expect(output.text()).toBe("");
    return {
      adapters: [{ packageName: "fixture-external", adapter: external }],
      unavailable: [{ packageName: "broken-external", reason: "client adapter failed to load" }],
    };
  });

  await main({
    argv: [process.execPath, cli, "setup"],
    home: "/home/fixture",
    environment: { PATH: process.env.PATH, PRIVATE_ENV: "environment-secret" },
    input,
    output,
    clientPlugins,
  });

  const text = output.text();
  expect(clientPlugins.load).toHaveBeenCalledExactlyOnceWith({ home: "/home/fixture" });
  expect(externalLoad).toHaveBeenCalledOnce();
  expect(text).toContain(
    `1. Claude Code\n2. Codex\n3. OpenCode\n4. Zed\\u202e External${joiner}\n5. Manual upstream\n`,
  );
  expect(text).not.toContain("\u202e");
  expect(text).toContain(joiner);
  expect(text.indexOf("Clients:\n")).toBeLessThan(text.indexOf("Unavailable client adapters:\n"));
  expect(text).toContain("- broken-external: client adapter failed to load\n");
  expect(text).not.toContain("environment-secret");
});

test("keeps built-ins available when installed-adapter loading fails globally", async () => {
  const clientPlugins = clientPluginDoubles();
  clientPlugins.load.mockRejectedValue(new Error("/private/registry import-secret"));
  const output = capturedCliOutput(true);

  await main({
    argv: [process.execPath, cli, "setup"],
    home: "/home/fixture",
    environment: { PATH: process.env.PATH },
    input: ttyInput("1\n"),
    output,
    clientPlugins,
  });

  expect(output.text()).toContain("1. Claude Code\n2. Codex\n3. OpenCode\n4. Manual upstream\n");
  expect(output.text()).toContain("- unknown client adapter: client adapter failed to load\n");
  expect(output.text()).not.toContain("/private/registry");
  expect(output.text()).not.toContain("import-secret");
});

test("keeps built-ins available when the setup client plugin accessor fails", async () => {
  const output = capturedCliOutput(true);
  const options = {
    argv: [process.execPath, cli, "setup"],
    home: "/home/fixture",
    environment: { PATH: process.env.PATH },
    input: ttyInput("1\n"),
    output,
  };
  Object.defineProperty(options, "clientPlugins", {
    get() {
      throw new Error("/private/plugin accessor import-secret");
    },
  });

  await main(options);

  expect(output.text()).toContain("1. Claude Code\n2. Codex\n3. OpenCode\n4. Manual upstream\n");
  expect(output.text()).toContain("- unknown client adapter: client adapter failed to load\n");
  expect(output.text()).not.toContain("/private/plugin");
  expect(output.text()).not.toContain("import-secret");
});

test("routes Restore MCP through setup with one scoped adapter lifetime", async () => {
  const clientPlugins = clientPluginDoubles();
  const output = capturedCliOutput(true);
  const home = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-setup-command-")));
  const withLoaded = vi.fn(async (_options, operation) =>
    operation({ adapters: [], unavailable: [] }),
  );

  try {
    await main({
      argv: [process.execPath, cli, "setup"],
      home,
      environment: { PATH: process.env.PATH },
      input: ttyInput("2\n"),
      output,
      clientPlugins: { ...clientPlugins, withLoaded },
    });
  } finally {
    await rm(home, { force: true, recursive: true });
  }

  expect(withLoaded).toHaveBeenCalledExactlyOnceWith({ home }, expect.any(Function));
  expect(clientPlugins.load).not.toHaveBeenCalled();
  expect(output.text()).toMatch(
    /^Actions:\n1\. Add MCP\n2\. Restore MCP\nSelect action: Managed MCP servers:\nNo managed MCP servers can be restored\.\n$/,
  );
});

test("keeps built-ins available when setup scoped loading fails before its callback", async () => {
  const clientPlugins = clientPluginDoubles();
  const output = capturedCliOutput(true);
  const secret = "/private/scoped-loader-before-callback-secret";
  const withLoaded = vi.fn(async () => {
    throw new Error(secret);
  });

  await main({
    argv: [process.execPath, cli, "setup"],
    home: "/home/fixture",
    environment: { PATH: process.env.PATH },
    input: ttyInput("1\n"),
    output,
    clientPlugins: { ...clientPlugins, withLoaded },
  });

  expect(withLoaded).toHaveBeenCalledExactlyOnceWith(
    { home: "/home/fixture" },
    expect.any(Function),
  );
  expect(clientPlugins.load).not.toHaveBeenCalled();
  expect(output.text()).toContain(
    "Clients:\n1. Claude Code\n2. Codex\n3. OpenCode\n4. Manual upstream\n",
  );
  expect(output.text()).toContain("- unknown client adapter: client adapter failed to load\n");
  expect(output.text()).not.toContain(secret);
});

test("leaves bare restore for proxy parsing before plugin access", async () => {
  const clientPlugins = clientPluginDoubles();
  const options = withClientPluginGetter(
    { argv: [process.execPath, cli, "restore"] },
    clientPlugins,
    () => {
      throw new Error("plugin registry was read");
    },
  );

  await expect(main(options)).rejects.toThrow("Usage: mcp-restrictor --policy FILE");
  expectClientPluginsUnused(clientPlugins);
});

test.each([
  ["missing profile ID", ["oauth", "login"]],
  ["extra argument", ["oauth", "login", oauthProfileId, "extra"]],
] as const)("rejects OAuth login with a $caseName", async (_caseName, args) => {
  const child = spawn(process.execPath, [cli, ...args], {
    cwd: projectRoot,
    stdio: ["ignore", "ignore", "pipe"],
  });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

  const [code] = await once(child, "exit");

  expect(code).toBe(1);
  expect(Buffer.concat(stderr).toString("utf8")).toBe(
    "mcp-restrictor: Usage: mcp-restrictor oauth login PROFILE_ID\n",
  );
});

test("keeps oauth login as an upstream command after --", async () => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-oauth-command-")));
  try {
    await symlink(process.execPath, join(directory, "oauth"));
    await symlink(upstream, join(directory, "login"));
    const child = spawn(
      process.execPath,
      [cli, "--policy", policy, "--", "oauth", "login", oauthProfileId],
      {
        cwd: directory,
        env: {
          ...process.env,
          PATH: `${directory}${delimiter}${process.env.PATH ?? ""}`,
        },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.stdin.end(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })}\n`);

    const [code] = await once(child, "exit");

    expect(code, Buffer.concat(stderr).toString("utf8")).toBe(0);
    expect(JSON.parse(Buffer.concat(stdout).toString("utf8")).result.tools).toHaveLength(2);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("runs the compiled CLI through a symlinked entrypoint", async () => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-entry-")));
  try {
    const linkedCli = join(directory, "mcp-restrictor.js");
    await symlink(cli, linkedCli);
    const child = spawn(
      process.execPath,
      [linkedCli, "--policy", policy, "--", process.execPath, upstream],
      { cwd: projectRoot, stdio: ["pipe", "pipe", "pipe"] },
    );
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.stdin.end(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })}\n`);

    const [code] = await once(child, "exit");

    expect(code, Buffer.concat(stderr).toString("utf8")).toBe(0);
    expect(JSON.parse(Buffer.concat(stdout).toString("utf8")).result.tools).toHaveLength(2);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test.each([
  ["bad profile", undefined, /OAuth profile read failed/i],
  [
    "Authorization conflict",
    "Authorization=MISSING_SECRET",
    /conflicting upstream authentication/i,
  ],
  ["master-key mapping", "X-Key=mCp_ReStRiCtOr_MaStEr_KeY_fIlE", /master key/i],
] as const)("does not start a downstream listener for a %s", async (failure, mapping, message) => {
  const readProfile = vi.fn<typeof readOAuthProfile>();
  const startProxy = vi.fn<typeof startHttpProxy>();
  const args = [
    process.execPath,
    cli,
    "--policy",
    policy,
    "--listen-http",
    "http://127.0.0.1:0/mcp",
    "--upstream-http",
    "http://127.0.0.1:1/mcp",
    "--upstream-oauth-profile",
    failure === "bad profile" ? oauthProfileId : "not-a-profile",
    ...(mapping ? ["--upstream-header-env", mapping] : []),
  ];

  await expect(
    main({
      argv: args,
      home: "/home/test",
      environment: {},
      signal: new AbortController().signal,
      readOAuthProfile:
        failure === "bad profile"
          ? readProfile.mockRejectedValue(new Error("OAuth profile read failed"))
          : readProfile,
      startHttpProxy: startProxy,
    }),
  ).rejects.toThrow(message);

  expect(startProxy).not.toHaveBeenCalled();
  if (failure !== "bad profile") {
    expect(readProfile).not.toHaveBeenCalled();
  }
});

test.each([
  ["uppercase UUID", oauthProfileId.toUpperCase()],
  ["path-like ID", "../oauth-profile"],
  ["empty ID", ""],
] as const)(
  "rejects a direct OAuth selector with an $name before profile IO",
  async (_name, id) => {
    const readProfile = vi.fn<typeof readOAuthProfile>();
    const startProxy = vi.fn<typeof startHttpProxy>();

    await expect(
      main({
        argv: [
          process.execPath,
          cli,
          "--policy",
          policy,
          "--listen-http",
          "http://127.0.0.1:0/mcp",
          "--upstream-http",
          "http://127.0.0.1:1/mcp",
          "--upstream-oauth-profile",
          id,
        ],
        home: "/home/test",
        environment: {},
        signal: new AbortController().signal,
        readOAuthProfile: readProfile,
        startHttpProxy: startProxy,
      }),
    ).rejects.toThrow(/invalid OAuth profile ID/i);

    expect(readProfile).not.toHaveBeenCalled();
    expect(startProxy).not.toHaveBeenCalled();
  },
);

test.each([
  ["uppercase UUID", oauthProfileId.toUpperCase()],
  ["path-like ID", "../oauth-profile"],
] as const)("rejects OAuth re-login with an $name before profile IO", async (_name, id) => {
  const readProfile = vi.fn<typeof readOAuthProfileSnapshot>();

  await expect(
    main({
      argv: [process.execPath, cli, "oauth", "login", id],
      home: "/home/test",
      environment: {},
      signal: new AbortController().signal,
      readOAuthProfileSnapshot: readProfile,
    }),
  ).rejects.toThrow(/invalid OAuth profile ID/i);

  expect(readProfile).not.toHaveBeenCalled();
});

test("re-logs the exact existing OAuth profile and replaces its exact snapshot", async () => {
  const profile = exampleCliProfile(oauthProfileId, "https://api.example.test/mcp");
  const before = fakeSnapshot("/home/test/profile.json", "old-ciphertext");
  const next: OAuthProfile = {
    ...profile,
    credentials: {
      ...profile.credentials,
      tokens: { ...profile.credentials.tokens, access_token: "new-access-token" },
    },
  };
  const readProfile = vi.fn().mockResolvedValue({ profile, snapshot: before });
  const readSecret = vi.fn().mockResolvedValue("https://callback.example/complete?code=hidden");
  const login = vi.fn(async (options: Parameters<typeof loginOAuthProfile>[0]) => {
    expect(options.input).toEqual({
      metadata: profile.metadata,
      clientInformation: profile.credentials.clientInformation,
      discoveryState: profile.credentials.discoveryState,
    });
    await expect(options.io.readPastedRedirect()).resolves.toEqual(
      new URL("https://callback.example/complete?code=hidden"),
    );
    return next;
  });
  const writeProfile = vi.fn().mockResolvedValue(fakeSnapshot(before.path, "new-ciphertext"));
  const environment = { [MASTER_KEY_FILE_ENV]: "/keys/master" };

  await main({
    argv: [process.execPath, cli, "oauth", "login", oauthProfileId],
    home: "/home/test",
    environment,
    signal: new AbortController().signal,
    readOAuthProfileSnapshot: readProfile,
    loginOAuthProfile: login,
    writeOAuthProfile: writeProfile,
    readSecret,
    output: new PassThrough(),
  });

  expect(readProfile).toHaveBeenCalledExactlyOnceWith(oauthProfileId, {
    home: "/home/test",
    environment,
  });
  expect(login).toHaveBeenCalledOnce();
  expect(readSecret).toHaveBeenCalledWith("Paste the final redirect URL: ");
  expect(writeProfile).toHaveBeenCalledExactlyOnceWith(next, {
    home: "/home/test",
    environment,
    before,
  });
  expect(next.metadata.profileId).toBe(oauthProfileId);
});

test("standalone OAuth treats Enter as authorization approval", async () => {
  const profile = exampleCliProfile(oauthProfileId, "https://api.example.test/mcp");
  const before = fakeSnapshot("/home/test/profile.json", "old-ciphertext");
  const writeProfile = vi.fn().mockResolvedValue(fakeSnapshot(before.path, "new-ciphertext"));
  const input = new PassThrough();
  input.end("\n");
  const login = vi.fn(async (options: Parameters<typeof loginOAuthProfile>[0]) => {
    await expect(
      options.io.confirmAuthorizationServer({
        authorizationServerUrl: new URL("https://auth.example.test"),
        callbackUrl: new URL("http://127.0.0.1:49151/callback"),
      }),
    ).resolves.toBe(true);
    return profile;
  });

  await main({
    argv: [process.execPath, cli, "oauth", "login", oauthProfileId],
    home: "/home/test",
    environment: {},
    signal: new AbortController().signal,
    input,
    output: new PassThrough(),
    readOAuthProfileSnapshot: vi.fn().mockResolvedValue({ profile, snapshot: before }),
    loginOAuthProfile: login,
    writeOAuthProfile: writeProfile,
  });

  expect(writeProfile).toHaveBeenCalledOnce();
});

test("standalone OAuth Ink keeps authorization visible and hands every redirect byte to the secret editor", async () => {
  const profile = exampleCliProfile(oauthProfileId, "https://api.example.test/mcp");
  const before = fakeSnapshot("/home/test/profile.json", "old-ciphertext");
  const input = new TestTtyInput();
  const redirect = "https://callback.example/complete?code=redirect-secret";
  const authorizationUrl = new URL("https://auth.example.test/authorize?client_id=public");
  const output = capturedCliOutput(true, (value) => {
    if (value.includes(authorizationUrl.href)) input.write(redirect);
  });
  const writeProfile = vi.fn().mockResolvedValue(fakeSnapshot(before.path, "new-ciphertext"));
  const login = vi.fn(async (options: Parameters<typeof loginOAuthProfile>[0]) => {
    await expect(options.io.selectRedirectDelivery!()).resolves.toBe("paste");
    await expect(
      options.io.confirmAuthorizationServer({
        authorizationServerUrl: new URL("https://auth.example.test"),
        callbackUrl: new URL("http://127.0.0.1:49151/callback"),
      }),
    ).resolves.toBe(true);
    options.io.writeAuthorizationUrl(authorizationUrl);
    await expect(options.io.readPastedRedirect()).resolves.toEqual(new URL(redirect));
    return profile;
  });

  const running = main({
    argv: [process.execPath, cli, "oauth", "login", oauthProfileId],
    home: "/home/test",
    environment: {},
    signal: new AbortController().signal,
    input,
    output,
    readOAuthProfileSnapshot: vi.fn().mockResolvedValue({ profile, snapshot: before }),
    loginOAuthProfile: login,
    writeOAuthProfile: writeProfile,
  });
  await vi.waitFor(() => expect(input.rawTransitions.filter(Boolean)).toHaveLength(1));
  expect(output.text()).toContain("OAuth redirect delivery");
  expect(output.text()).toContain("Loopback listener");
  expect(output.text()).toContain("Paste redirected URL");
  input.write("\u001B[B\r");
  await vi.waitFor(() => expect(input.rawTransitions.filter(Boolean)).toHaveLength(2));
  expect(output.text()).toContain("OAuth authorization server: https://auth.example.test/\n");
  expect(output.text()).toContain("Continue?");
  input.write("\r");
  await vi.waitFor(() => expect(input.rawTransitions.filter(Boolean)).toHaveLength(3));
  input.write("\r");

  await running;
  expect(writeProfile).toHaveBeenCalledOnce();
  expect(output.text()).toContain(authorizationUrl.href);
  expect(output.text()).not.toContain(redirect);
  expect(output.text()).not.toContain("redirect-secret");
  expect(output.text()).not.toContain("*".repeat(redirect.length));
  expect(input.isRaw).toBe(false);
});

test("standalone OAuth Ink defaults redirect delivery to Loopback listener", async () => {
  const profile = exampleCliProfile(oauthProfileId, "https://api.example.test/mcp");
  const before = fakeSnapshot("/home/test/profile.json", "old-ciphertext");
  const input = new TestTtyInput();
  const output = capturedCliOutput(true);
  const writeProfile = vi.fn().mockResolvedValue(fakeSnapshot(before.path, "new-ciphertext"));
  const login = vi.fn(async (options: Parameters<typeof loginOAuthProfile>[0]) => {
    await expect(options.io.selectRedirectDelivery!()).resolves.toBe("listener");
    return profile;
  });

  const running = main({
    argv: [process.execPath, cli, "oauth", "login", oauthProfileId],
    home: "/home/test",
    environment: {},
    signal: new AbortController().signal,
    input,
    output,
    readOAuthProfileSnapshot: vi.fn().mockResolvedValue({ profile, snapshot: before }),
    loginOAuthProfile: login,
    writeOAuthProfile: writeProfile,
  });
  await vi.waitFor(() => expect(input.rawTransitions.filter(Boolean)).toHaveLength(1));
  expect(output.text()).toContain("OAuth redirect delivery");
  expect(output.text()).toContain("Loopback listener");
  expect(output.text()).toContain("Paste redirected URL");
  input.write("\r");

  await running;
  expect(writeProfile).toHaveBeenCalledOnce();
  expect(input.isRaw).toBe(false);
});

test.each([
  ["selector", "Escape"],
  ["selector", "Ctrl-C"],
  ["selector", "EOF"],
  ["selector", "external abort"],
  ["secret editor", "EOF"],
  ["secret editor", "external abort"],
] as const)("standalone OAuth Ink does not publish after %s %s", async (phase, cancellation) => {
  const profile = exampleCliProfile(oauthProfileId, "https://api.example.test/mcp");
  const before = fakeSnapshot("/home/test/profile.json", "old-ciphertext");
  const input = new TestTtyInput();
  const output = capturedCliOutput(true);
  const controller = new AbortController();
  const writeProfile = vi.fn<typeof writeOAuthProfile>();
  const login = vi.fn(async (options: Parameters<typeof loginOAuthProfile>[0]) => {
    await options.io.selectRedirectDelivery!();
    await options.io.confirmAuthorizationServer({
      authorizationServerUrl: new URL("https://auth.example.test"),
      callbackUrl: new URL("http://127.0.0.1:49151/callback"),
    });
    options.io.writeAuthorizationUrl(new URL("https://auth.example.test/authorize"));
    await options.io.readPastedRedirect();
    return profile;
  });
  const running = main({
    argv: [process.execPath, cli, "oauth", "login", oauthProfileId],
    home: "/home/test",
    environment: {},
    signal: controller.signal,
    input,
    output,
    readOAuthProfileSnapshot: vi.fn().mockResolvedValue({ profile, snapshot: before }),
    loginOAuthProfile: login,
    writeOAuthProfile: writeProfile,
  });
  void running.catch(() => {});
  await vi.waitFor(() => expect(input.rawTransitions.filter(Boolean)).toHaveLength(1));
  if (phase === "secret editor") {
    input.write("\u001B[B\r");
    await vi.waitFor(() => expect(input.rawTransitions.filter(Boolean)).toHaveLength(2));
    input.write("\r");
    await vi.waitFor(() => expect(input.rawTransitions.filter(Boolean)).toHaveLength(3));
  }

  if (cancellation === "Escape") input.write("\u001B");
  else if (cancellation === "Ctrl-C") input.write("\u0003");
  else if (cancellation === "EOF") input.end();
  else controller.abort();

  await expect(running).rejects.toThrow();
  expect(writeProfile).not.toHaveBeenCalled();
  expect(output.text()).not.toContain("redirect-secret");
  expect(input.isRaw).toBe(false);
});

test("standalone OAuth login never repairs a missing container key", async () => {
  const stored = await storedCliProfile("https://api.example.test/mcp");
  const login = vi.fn<typeof loginOAuthProfile>();
  const writeProfile = vi.fn<typeof writeOAuthProfile>();
  await rm(stored.keyPath);

  try {
    await expect(
      main({
        argv: [process.execPath, cli, "oauth", "login", stored.id],
        home: stored.home,
        environment: { ...stored.environment, [CONTAINER_MARKER_ENV]: "1" },
        signal: new AbortController().signal,
        input: Readable.from([]),
        output: new PassThrough(),
        loginOAuthProfile: login,
        writeOAuthProfile: writeProfile,
      }),
    ).rejects.toThrow(/OAuth profile .* decrypt failed/i);

    expect(login).not.toHaveBeenCalled();
    expect(writeProfile).not.toHaveBeenCalled();
    await expect(readFile(stored.keyPath)).rejects.toMatchObject({ code: "ENOENT" });
  } finally {
    await rm(stored.home, { force: true, recursive: true });
  }
});

test("standalone OAuth Ink rejects loopback success after EOF without opening the secret editor", async () => {
  const profile = exampleCliProfile(oauthProfileId, "https://api.example.test/mcp");
  const before = fakeSnapshot("/home/test/profile.json", "old-ciphertext");
  const input = new TestTtyInput();
  const output = capturedCliOutput(true);
  const listenersBefore = listenerCounts(input);
  const writeProfile = vi.fn<typeof writeOAuthProfile>();
  let resolveLogin!: () => void;
  const loginPending = new Promise<void>((resolve) => {
    resolveLogin = resolve;
  });
  const login = vi.fn(async (options: Parameters<typeof loginOAuthProfile>[0]) => {
    await options.io.confirmAuthorizationServer({
      authorizationServerUrl: new URL("https://auth.example.test"),
      callbackUrl: new URL("http://127.0.0.1:49151/callback"),
    });
    options.io.writeAuthorizationUrl(new URL("https://auth.example.test/authorize"));
    await loginPending;
    return profile;
  });
  const running = main({
    argv: [process.execPath, cli, "oauth", "login", oauthProfileId],
    home: "/home/test",
    environment: {},
    signal: new AbortController().signal,
    input,
    output,
    readOAuthProfileSnapshot: vi.fn().mockResolvedValue({ profile, snapshot: before }),
    loginOAuthProfile: login,
    writeOAuthProfile: writeProfile,
  });
  void running.catch(() => {});
  await vi.waitFor(() => expect(input.rawTransitions.filter(Boolean)).toHaveLength(1));
  input.write("\r");
  await vi.waitFor(() => expect(output.text()).toContain("Open this URL to authorize:"));
  input.end();
  resolveLogin();

  await expect(running).rejects.toThrow();
  expect(writeProfile).not.toHaveBeenCalled();
  expect(input.isRaw).toBe(false);
  expect(listenerCounts(input)).toEqual(listenersBefore);
});

test("standalone OAuth redirected output keeps the raw no-echo fallback without Ink ANSI", async () => {
  const profile = exampleCliProfile(oauthProfileId, "https://api.example.test/mcp");
  const before = fakeSnapshot("/home/test/profile.json", "old-ciphertext");
  const input = new TestTtyInput();
  const output = capturedCliOutput();
  const redirect = "https://callback.example/complete?code=mixed-stream-secret";
  const writeProfile = vi.fn().mockResolvedValue(fakeSnapshot(before.path, "new-ciphertext"));
  const login = vi.fn(async (options: Parameters<typeof loginOAuthProfile>[0]) => {
    await expect(
      options.io.confirmAuthorizationServer({
        authorizationServerUrl: new URL("https://auth.example.test"),
        callbackUrl: new URL("http://127.0.0.1:49151/callback"),
      }),
    ).resolves.toBe(true);
    options.io.writeAuthorizationUrl(new URL("https://auth.example.test/authorize"));
    await expect(options.io.readPastedRedirect()).resolves.toEqual(new URL(redirect));
    return profile;
  });
  const running = main({
    argv: [process.execPath, cli, "oauth", "login", oauthProfileId],
    home: "/home/test",
    environment: {},
    signal: new AbortController().signal,
    input,
    output,
    readOAuthProfileSnapshot: vi.fn().mockResolvedValue({ profile, snapshot: before }),
    loginOAuthProfile: login,
    writeOAuthProfile: writeProfile,
  });
  await vi.waitFor(() => expect(output.text()).toContain("Continue? [Y/n]: "));
  input.write("\n");
  await vi.waitFor(() => expect(input.isRaw).toBe(true));
  input.write(`${redirect}\r`);

  await running;
  expect(writeProfile).toHaveBeenCalledOnce();
  expect(input.rawTransitions).toEqual([true, false]);
  expect(output.text()).not.toContain("\u001B[");
  expect(output.text()).not.toContain(redirect);
  expect(output.text()).not.toContain("mixed-stream-secret");
});

test("standalone OAuth preserves confirmation EOF as AbortError through the real login wrapper", async () => {
  const profile = exampleCliProfile(oauthProfileId, "https://api.example.test/mcp");
  profile.metadata.callback = { url: "https://callback.example/complete", appendProfileId: true };
  profile.credentials.discoveryState = {
    authorizationServerUrl: "https://auth.example.test/",
    authorizationServerMetadata: {
      issuer: "https://auth.example.test/",
      authorization_endpoint: "https://auth.example.test/authorize",
      token_endpoint: "https://auth.example.test/token",
      response_types_supported: ["code"],
    },
    resourceMetadata: {
      resource: profile.metadata.serverUrl,
      authorization_servers: ["https://auth.example.test/"],
    },
  };
  const writeProfile = vi.fn();

  await expect(
    main({
      argv: [process.execPath, cli, "oauth", "login", oauthProfileId],
      home: "/home/test",
      environment: {},
      signal: new AbortController().signal,
      input: Readable.from([]),
      output: new PassThrough(),
      readOAuthProfileSnapshot: vi.fn().mockResolvedValue({
        profile,
        snapshot: fakeSnapshot("/home/test/profile.json", "old-ciphertext"),
      }),
      writeOAuthProfile: writeProfile,
    }),
  ).rejects.toMatchObject({ name: "AbortError" });

  expect(writeProfile).not.toHaveBeenCalled();
});

test("leaves the existing OAuth profile unchanged when re-login is cancelled", async () => {
  const profile = exampleCliProfile(oauthProfileId, "https://api.example.test/mcp");
  const writeProfile = vi.fn();

  await expect(
    main({
      argv: [process.execPath, cli, "oauth", "login", oauthProfileId],
      home: "/home/test",
      environment: {},
      signal: new AbortController().signal,
      readOAuthProfileSnapshot: vi.fn().mockResolvedValue({
        profile,
        snapshot: fakeSnapshot("/home/test/profile.json", "old-ciphertext"),
      }),
      loginOAuthProfile: vi.fn().mockRejectedValue(new Error("OAuth login cancelled")),
      writeOAuthProfile: writeProfile,
    }),
  ).rejects.toThrow("OAuth login cancelled");
  expect(writeProfile).not.toHaveBeenCalled();
});

test("does not write a re-login result returned after cancellation", async () => {
  const profile = exampleCliProfile(oauthProfileId, "https://api.example.test/mcp");
  const controller = new AbortController();
  const writeProfile = vi.fn<typeof writeOAuthProfile>();

  await expect(
    main({
      argv: [process.execPath, cli, "oauth", "login", oauthProfileId],
      home: "/home/test",
      environment: {},
      signal: controller.signal,
      output: new PassThrough(),
      readOAuthProfileSnapshot: vi.fn().mockResolvedValue({
        profile,
        snapshot: fakeSnapshot("/home/test/profile.json", "old-ciphertext"),
      }),
      loginOAuthProfile: vi.fn(async () => {
        controller.abort();
        return profile;
      }),
      writeOAuthProfile: writeProfile,
    }),
  ).rejects.toThrow(/abort/i);

  expect(writeProfile).not.toHaveBeenCalled();
});

test("rejects a re-login result with a different profile ID without writing it", async () => {
  const profile = exampleCliProfile(oauthProfileId, "https://api.example.test/mcp");
  const writeProfile = vi.fn<typeof writeOAuthProfile>();
  const replacement = exampleCliProfile(
    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    profile.metadata.serverUrl,
  );

  await expect(
    main({
      argv: [process.execPath, cli, "oauth", "login", oauthProfileId],
      home: "/home/test",
      environment: {},
      signal: new AbortController().signal,
      output: new PassThrough(),
      readOAuthProfileSnapshot: vi.fn().mockResolvedValue({
        profile,
        snapshot: fakeSnapshot("/home/test/profile.json", "old-ciphertext"),
      }),
      loginOAuthProfile: vi.fn().mockResolvedValue(replacement),
      writeOAuthProfile: writeProfile,
    }),
  ).rejects.toThrow(/different profile ID/i);

  expect(writeProfile).not.toHaveBeenCalled();
});

test("preserves a concurrently refreshed OAuth profile on stale re-login", async () => {
  const stored = await storedCliProfile("https://api.example.test/mcp");
  let rotatedBytes = "";
  try {
    const login = vi.fn(async () => {
      const current = await readOAuthProfileSnapshot(stored.id, stored.options);
      const rotated: OAuthProfile = {
        ...current.profile,
        credentials: {
          ...current.profile.credentials,
          tokens: {
            ...current.profile.credentials.tokens,
            access_token: "rotated-by-runtime",
          },
        },
      };
      await writeOAuthProfile(rotated, { ...stored.options, before: current.snapshot });
      rotatedBytes = await readFile(oauthProfilePath(stored.home, stored.id), "utf8");
      return {
        ...current.profile,
        credentials: {
          ...current.profile.credentials,
          tokens: {
            ...current.profile.credentials.tokens,
            access_token: "interactive-login-token",
          },
        },
      };
    });

    await expect(
      main({
        argv: [process.execPath, cli, "oauth", "login", stored.id],
        home: stored.home,
        environment: stored.environment,
        signal: new AbortController().signal,
        loginOAuthProfile: login,
      }),
    ).rejects.toThrow(/OAuth profile.*write failed/i);

    expect(login).toHaveBeenCalledOnce();
    expect(await readFile(oauthProfilePath(stored.home, stored.id), "utf8")).toBe(rotatedBytes);
  } finally {
    await rm(stored.home, { force: true, recursive: true });
  }
});

test.each(["http", "sse"] as const)(
  "builds a fresh bound OAuth provider for each %s transport signal",
  async (kind) => {
    const stored = await storedCliProfile("https://api.example.test/mcp", {
      resource: "https://resource.example.test/mcp",
    });
    const root = new AbortController();
    const transports = [new AbortController(), new AbortController()];
    const providers = [{ token: async () => "one" }, { token: async () => "two" }];
    let providerIndex = 0;
    const createProvider = vi.fn<typeof createOAuthAuthProvider>((_id, _binding, options) => {
      if (!options) throw new Error("expected OAuth runtime options");
      const provider = providers[providerIndex++];
      expect(provider).toBeDefined();
      expect(options.signal?.aborted).toBe(false);
      return provider!;
    });
    const runProxy = vi.fn<typeof runStdioProxy>(async ({ upstream: configured }) => {
      if (configured.kind !== kind || !configured.authProviderFactory) {
        throw new Error(`expected OAuth ${kind} upstream`);
      }
      const first = configured.authProviderFactory(transports[0]!.signal);
      const second = configured.authProviderFactory(transports[1]!.signal);
      expect(first).toBe(providers[0]);
      expect(second).toBe(providers[1]);
      expect(first).not.toBe(second);
      transports[0]!.abort();
      expect(createProvider.mock.calls[0]?.[2]?.signal?.aborted).toBe(true);
      expect(createProvider.mock.calls[1]?.[2]?.signal?.aborted).toBe(false);
      root.abort();
      expect(createProvider.mock.calls[1]?.[2]?.signal?.aborted).toBe(true);
      return 0;
    });

    try {
      await main({
        argv: [
          process.execPath,
          cli,
          "--policy",
          policy,
          `--upstream-${kind}`,
          "https://api.example.test/mcp",
          "--upstream-oauth-profile",
          stored.id,
        ],
        home: stored.home,
        environment: stored.environment,
        signal: root.signal,
        createOAuthAuthProvider: createProvider,
        runStdioProxy: runProxy,
      });

      expect(createProvider).toHaveBeenCalledTimes(2);
      for (const call of createProvider.mock.calls) {
        expect(call[0]).toBe(stored.id);
        expect(call[1]).toEqual({
          serverUrl: "https://api.example.test/mcp",
          resource: "https://resource.example.test/mcp",
        });
        expect(call[2]).toMatchObject({
          home: stored.home,
          environment: stored.environment,
        });
      }
    } finally {
      await rm(stored.home, { force: true, recursive: true });
    }
  },
);

test("binds an OAuth provider to the discovered protected resource", async () => {
  const stored = await emptyCliStorage();
  const serverUrl = "https://api.example.test/mcp";
  const resource = "https://discovered-resource.example.test/mcp";
  const profile = exampleCliProfile(stored.id, serverUrl);
  profile.credentials.discoveryState.resourceMetadata = {
    resource,
    authorization_servers: ["https://auth.example.test"],
  };
  await writeOAuthProfile(profile, stored.options);
  const createProvider = vi.fn<typeof createOAuthAuthProvider>(() => ({
    token: async () => "access-token",
  }));
  const runProxy = vi.fn<typeof runStdioProxy>(async ({ upstream: configured }) => {
    if (configured.kind !== "http" || !configured.authProviderFactory) {
      throw new Error("expected OAuth HTTP upstream");
    }
    configured.authProviderFactory();
    return 0;
  });

  try {
    await main({
      argv: [
        process.execPath,
        cli,
        "--policy",
        policy,
        "--upstream-http",
        serverUrl,
        "--upstream-oauth-profile",
        stored.id,
      ],
      home: stored.home,
      environment: stored.environment,
      signal: new AbortController().signal,
      createOAuthAuthProvider: createProvider,
      runStdioProxy: runProxy,
    });

    expect(createProvider).toHaveBeenCalledExactlyOnceWith(
      stored.id,
      { serverUrl, resource },
      expect.objectContaining({
        home: stored.home,
        environment: stored.environment,
      }),
    );
  } finally {
    await rm(stored.home, { force: true, recursive: true });
  }
});

test("reads one non-echo secret line and restores raw and paused state", async () => {
  const fixture = secretInputFixture();
  fixture.readline.pause();
  const listeners = fixture.input.listenerCount("data");
  const result = readSecretLine({ ...fixture, signal: new AbortController().signal });

  fixture.input.write("hidden value\r\n");

  await expect(result).resolves.toBe("hidden value");
  expect(fixture.input.rawTransitions).toEqual([true, false]);
  expect(fixture.input.isRaw).toBe(false);
  expect(fixture.input.isPaused()).toBe(true);
  expect(fixture.input.listenerCount("data")).toBe(listeners);
  fixture.readline.close();
});

test("restores a terminal that was already in raw mode", async () => {
  const fixture = secretInputFixture();
  fixture.input.isRaw = true;
  const result = readSecretLine({ ...fixture, signal: new AbortController().signal });

  fixture.input.write("secret\n");

  await expect(result).resolves.toBe("secret");
  expect(fixture.input.rawTransitions).toEqual([true, true]);
  expect(fixture.input.isRaw).toBe(true);
  fixture.readline.close();
});

test("does not leave the secret queued for the next readline answer", async () => {
  const fixture = secretInputFixture();
  const secret = readSecretLine({ ...fixture, signal: new AbortController().signal });
  fixture.input.write("hidden\nvisible\n");
  await expect(secret).resolves.toBe("hidden");

  const ordinary = fixture.answers.next();
  await expect(ordinary).resolves.toEqual({ done: false, value: "visible" });
  fixture.readline.close();
});

test.each(["abort", "ctrl-c"] as const)(
  "cancels reusable secret input on %s and restores terminal state",
  async (exit) => {
    const fixture = secretInputFixture();
    fixture.input.isRaw = true;
    fixture.readline.pause();
    const controller = new AbortController();
    const listeners = listenerCounts(fixture.input);
    const result = readSecretLine({ ...fixture, signal: controller.signal });

    if (exit === "abort") controller.abort();
    else fixture.input.write("\x03");

    await expect(result).rejects.toThrow(/cancelled/i);
    expect(fixture.input.rawTransitions).toEqual([true, true]);
    expect(fixture.input.isRaw).toBe(true);
    expect(fixture.input.isPaused()).toBe(true);
    expect(listenerCounts(fixture.input)).toEqual(listeners);

    fixture.readline.resume();
    const ordinary = fixture.answers.next();
    fixture.input.write("visible\n");
    await expect(ordinary).resolves.toEqual({ done: false, value: "visible" });
    fixture.readline.close();
  },
);

test("cancels secret input on EOF and restores raw mode", async () => {
  const fixture = secretInputFixture();
  const result = readSecretLine({
    ...fixture,
    signal: new AbortController().signal,
  });

  fixture.input.end();

  await expect(result).rejects.toThrow(/cancelled/i);
  expect(fixture.input.rawTransitions).toEqual([true, false]);
  expect(fixture.input.isRaw).toBe(false);
  fixture.readline.close();
});

test("refuses to read a secret without a TTY", async () => {
  const input = new PassThrough();
  const readline = createInterface({ input, crlfDelay: Infinity });
  try {
    await expect(
      readSecretLine({
        input,
        readline,
        signal: new AbortController().signal,
      }),
    ).rejects.toThrow(/interactive terminal/i);
  } finally {
    readline.close();
  }
});

test("restores readline state when raw mode cannot be enabled", async () => {
  const fixture = secretInputFixture();
  fixture.readline.pause();
  const listeners = listenerCounts(fixture.input);
  const setRawMode = fixture.input.setRawMode.bind(fixture.input);
  let calls = 0;
  fixture.input.setRawMode = (mode) => {
    calls += 1;
    if (calls === 1) throw new Error("raw mode unavailable");
    return setRawMode(mode);
  };

  await expect(
    readSecretLine({
      ...fixture,
      signal: new AbortController().signal,
    }),
  ).rejects.toThrow("raw mode unavailable");

  expect(listenerCounts(fixture.input)).toEqual(listeners);
  expect(fixture.input.isPaused()).toBe(true);
  expect(fixture.input.isRaw).toBe(false);
  fixture.readline.close();
});

test("keeps an upstream command named setup in proxy mode after --", async () => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-setup-command-")));
  try {
    await symlink(process.execPath, join(directory, "setup"));
    const child = spawn(process.execPath, [cli, "--policy", policy, "--", "setup", upstream], {
      cwd: projectRoot,
      env: {
        ...process.env,
        PATH: `${directory}${delimiter}${process.env.PATH ?? ""}`,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" })}\n`);
    child.stdin.end();

    const [code] = await once(child, "exit");

    expect(code, Buffer.concat(stderr).toString("utf8")).toBe(0);
    expect(JSON.parse(Buffer.concat(stdout).toString("utf8")).result.tools).toHaveLength(2);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("filters discovery and blocks denied calls before they reach upstream", async () => {
  const child = spawn(
    process.execPath,
    [cli, "--policy", policy, "--", process.execPath, upstream],
    { cwd: projectRoot, stdio: ["pipe", "pipe", "pipe"] },
  );
  child.stdin.on("error", () => {});
  const exit = once(child, "exit");
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

  for (const message of [
    { jsonrpc: "2.0", id: 1, method: "tools/list" },
    {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "delete_file", arguments: { path: "/workspace/a.txt" } },
    },
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "write_file", arguments: { path: "/etc/passwd" } },
    },
    {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "read_file", arguments: { path: "/workspace/a.txt" } },
    },
  ]) {
    child.stdin.write(`${JSON.stringify(message)}\n`);
  }
  child.stdin.end();

  const [code] = await exit;
  expect(code, Buffer.concat(stderr).toString("utf8")).toBe(0);

  const responses = Buffer.concat(stdout)
    .toString("utf8")
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  expect(responses).toHaveLength(4);

  const byId = new Map(responses.map((response) => [response.id, response]));
  expect(byId.get(1).result.tools.map((tool: { name: string }) => tool.name)).toEqual([
    "read_file",
    "write_file",
  ]);
  expect(byId.get(2).error.code).toBe(-32001);
  expect(byId.get(3).error.code).toBe(-32001);
  expect(byId.get(4).result.content).toEqual([
    { type: "text", text: expect.stringMatching(/^upstream:read_file:/) },
  ]);
});

test("exits when upstream stops while client stdin is still open", async () => {
  const child = spawn(
    process.execPath,
    [cli, "--policy", policy, "--", process.execPath, "-e", ""],
    { cwd: projectRoot, stdio: ["pipe", "pipe", "pipe"] },
  );
  child.stdin.on("error", () => {});
  const exit = once(child, "exit");

  const outcome = await Promise.race([
    exit.then(([code]) => ({ exited: true as const, code })),
    new Promise<{ exited: false }>((resolveTimeout) =>
      setTimeout(() => resolveTimeout({ exited: false }), 3_000),
    ),
  ]);

  if (!outcome.exited) {
    child.stdin.destroy();
    child.kill();
    await exit;
  }

  expect(outcome).toEqual({ exited: true, code: 0 });
});

test("preserves a nonzero stdio upstream exit status", async () => {
  const child = spawn(
    process.execPath,
    [cli, "--policy", policy, "--", process.execPath, "-e", "process.exit(42)"],
    { cwd: projectRoot, stdio: ["pipe", "pipe", "pipe"] },
  );
  const [code] = await once(child, "exit");
  expect(code).toBe(42);
});

test("passes selected environment and cwd to a stdio upstream", async () => {
  const tempDirectory = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-")));
  try {
    const child = spawn(
      process.execPath,
      [
        cli,
        "--policy",
        policy,
        "--upstream-env",
        "API_KEY",
        "--upstream-cwd",
        tempDirectory,
        "--",
        process.execPath,
        configSensitiveUpstream,
        tempDirectory,
      ],
      {
        cwd: projectRoot,
        env: { ...process.env, API_KEY: "secret" },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    child.stdin.on("error", () => {});
    const exit = once(child, "exit");
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

    for (const message of [
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-11-25",
          capabilities: {},
          clientInfo: { name: "test", version: "1.0.0" },
        },
      },
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
    ]) {
      child.stdin.write(`${JSON.stringify(message)}\n`);
    }
    child.stdin.end();

    const [code] = await exit;
    expect(code, Buffer.concat(stderr).toString("utf8")).toBe(0);

    const responses = Buffer.concat(stdout)
      .toString("utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    const byId = new Map(responses.map((response) => [response.id, response]));
    expect(byId.get(1).result.serverInfo.name).toBe("config-sensitive-fixture");
    expect(byId.get(2).result.tools.map((tool: { name: string }) => tool.name)).toEqual([
      "read_file",
    ]);
  } finally {
    await rm(tempDirectory, { force: true, recursive: true });
  }
});

test.each([
  [
    "STDIO inherited env",
    ["--upstream-env", "MCP_RESTRICTOR_CONTAINER", "--", process.execPath, "-e", ""],
  ],
  [
    "header env mapping",
    [
      "--upstream-http",
      "http://127.0.0.1:1/mcp",
      "--upstream-header-env",
      "X-Key=MCP_RESTRICTOR_CONTAINER",
    ],
  ],
  [
    "bearer env name",
    [
      "--upstream-http",
      "http://127.0.0.1:1/mcp",
      "--upstream-bearer-token-env",
      "MCP_RESTRICTOR_CONTAINER",
    ],
  ],
] as const)(
  "rejects reserved upstream environment for the container marker: %s",
  async (_case, args) => {
    await expect(
      resolveProxyRoute(
        ["--policy", policy, ...args],
        {},
        {
          home: projectRoot,
          environment: { ["MCP_RESTRICTOR_CONTAINER"]: "1" },
        },
      ),
    ).rejects.toThrow(/reserved upstream environment/i);
  },
);

test.each([
  {
    args: ["--upstream-env", "API_KEY"],
    message: "--upstream-env requires a STDIO upstream",
  },
  {
    args: ["--upstream-cwd", "/tmp"],
    message: "--upstream-cwd requires a STDIO upstream",
  },
])("rejects $args with an HTTP upstream", async ({ args, message }) => {
  const child = spawn(
    process.execPath,
    [cli, "--policy", policy, "--upstream-http", "http://127.0.0.1:1/mcp", ...args],
    { cwd: projectRoot, stdio: ["ignore", "ignore", "pipe"] },
  );
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

  const [code] = await once(child, "exit");

  expect(code).toBe(1);
  expect(Buffer.concat(stderr).toString("utf8")).toContain(message);
});

type CliOAuthStorage = {
  id: string;
  home: string;
  keyPath: string;
  environment: NodeJS.ProcessEnv;
  options: { home: string; environment: NodeJS.ProcessEnv };
};

async function emptyCliStorage(): Promise<CliOAuthStorage> {
  const home = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-cli-oauth-")));
  const keyPath = join(home, "master.key");
  await writeFile(keyPath, randomBytes(32).toString("base64url"), { mode: 0o600 });
  await chmod(keyPath, 0o600);
  const environment = { [MASTER_KEY_FILE_ENV]: keyPath };
  return {
    id: randomUUID(),
    home,
    keyPath,
    environment,
    options: { home, environment },
  };
}

async function storedCliProfile(
  serverUrl: string,
  options: { resource?: string; accessToken?: string } = {},
): Promise<CliOAuthStorage> {
  const stored = await emptyCliStorage();
  await writeOAuthProfile(exampleCliProfile(stored.id, serverUrl, options), stored.options);
  return stored;
}

function exampleCliProfile(
  id: string,
  serverUrl: string,
  options: { resource?: string; accessToken?: string } = {},
): OAuthProfile {
  const issuer = "https://auth.example.test";
  return {
    metadata: {
      version: 1,
      profileId: id,
      serverUrl,
      ...(options.resource ? { resource: options.resource } : {}),
      callback: {
        host: "127.0.0.1",
        path: "/callback",
        appendProfileId: true,
      },
      clientMetadata: {},
    },
    credentials: {
      clientInformation: {
        client_id: "client-id",
        client_secret: "client-secret",
        issuer,
      },
      tokens: {
        access_token: options.accessToken ?? "oauth-access-token",
        refresh_token: "refresh-token",
        token_type: "Bearer",
        issuer,
      },
      discoveryState: {
        authorizationServerUrl: issuer,
        authorizationServerMetadata: {
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          response_types_supported: ["code"],
        },
      },
    },
  };
}

async function runCli(
  args: readonly string[],
  stored: Pick<CliOAuthStorage, "home" | "keyPath">,
): Promise<{ code: number | null; stderr: string }> {
  const child = spawn(process.execPath, [cli, ...args], {
    cwd: projectRoot,
    env: {
      ...process.env,
      HOME: stored.home,
      [MASTER_KEY_FILE_ENV]: stored.keyPath,
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
  const [code] = await once(child, "exit");
  return { code: code as number | null, stderr: Buffer.concat(stderr).toString("utf8") };
}

async function startCountingServer(): Promise<{
  url: string;
  readonly connections: number;
  close(): Promise<void>;
}> {
  let connections = 0;
  const server = createServer((_request, response) => response.writeHead(500).end());
  server.on("connection", () => {
    connections += 1;
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return {
    url: serverUrl(server),
    get connections() {
      return connections;
    },
    close: () => closeHttpServer(server),
  };
}

function fakeSnapshot(path: string, content: string) {
  return {
    path,
    content,
    mode: 0o600,
    size: Buffer.byteLength(content),
    mtimeMs: 1,
    dev: 1,
    ino: 1,
  };
}

function clientPluginDoubles() {
  return {
    install: vi.fn<typeof installClientAdapter>(),
    list: vi.fn<typeof listClientAdapters>().mockResolvedValue([]),
    load: vi.fn<typeof loadInstalledClientAdapters>().mockResolvedValue({
      adapters: [],
      unavailable: [],
    }),
    remove: vi.fn<typeof removeClientAdapter>().mockResolvedValue({ warnings: [] }),
  };
}

function withClientPluginGetter(
  options: Omit<Parameters<typeof main>[0], "clientPlugins">,
  clientPlugins: ReturnType<typeof clientPluginDoubles>,
  onRead: () => void,
): Parameters<typeof main>[0] {
  return Object.defineProperty(options, "clientPlugins", {
    get() {
      onRead();
      return clientPlugins;
    },
  });
}

function observeOperationRead(
  clientPlugins: ReturnType<typeof clientPluginDoubles>,
  operation: keyof ReturnType<typeof clientPluginDoubles>,
  onRead: () => void,
): void {
  const value = clientPlugins[operation];
  Object.defineProperty(clientPlugins, operation, {
    configurable: true,
    get() {
      onRead();
      return value;
    },
  });
}

function expectClientPluginsUnused(clientPlugins: ReturnType<typeof clientPluginDoubles>): void {
  expect(clientPlugins.install).not.toHaveBeenCalled();
  expect(clientPlugins.list).not.toHaveBeenCalled();
  expect(clientPlugins.load).not.toHaveBeenCalled();
  expect(clientPlugins.remove).not.toHaveBeenCalled();
}

function capturedCliOutput(
  tty = false,
  onWrite?: (value: string) => void,
): Writable & { isTTY?: boolean; text(): string } {
  const chunks: Buffer[] = [];
  const output = new Writable({
    write(chunk, _encoding, callback) {
      const value = Buffer.from(chunk);
      chunks.push(value);
      onWrite?.(value.toString("utf8"));
      callback();
    },
  }) as Writable & { isTTY?: boolean; text(): string };
  if (tty) output.isTTY = true;
  output.text = () => Buffer.concat(chunks).toString("utf8");
  return output;
}

function ttyInput(content: string): PassThrough & { isTTY: true } {
  const input = Object.assign(new PassThrough(), { isTTY: true as const });
  input.end(content);
  return input;
}

class TestTtyInput extends PassThrough {
  readonly isTTY = true;
  isRaw = false;
  readonly rawTransitions: boolean[] = [];

  setRawMode(mode: boolean): this {
    this.rawTransitions.push(mode);
    this.isRaw = mode;
    return this;
  }

  ref(): this {
    return this;
  }

  unref(): this {
    return this;
  }
}

function secretInputFixture() {
  const input = new TestTtyInput();
  const readline = createInterface({ input, crlfDelay: Infinity });
  return {
    input,
    readline,
    answers: readline[Symbol.asyncIterator](),
  };
}

function listenerCounts(input: TestTtyInput): Record<string, number> {
  return Object.fromEntries(
    ["data", "readable", "end", "error"].map((event) => [event, input.listenerCount(event)]),
  );
}

type RemoteFixture = {
  url: string;
  accepted: number;
  close(): Promise<void>;
};

async function startRemoteFixture(
  kind: "http" | "sse" | "websocket",
  secrets: { plain: string; encoded: string; bearer: string },
): Promise<RemoteFixture> {
  if (kind === "websocket") return startWebSocketFixture(secrets);
  if (kind === "sse") return startSseFixture(secrets);

  const transport = new NodeStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  transport.onmessage = (message) => {
    if (!("method" in message) || !("id" in message)) return;
    void transport.send(responseFor(message as RpcRequest), { relatedRequestId: message.id });
  };
  await transport.start();
  const fixture = { accepted: 0 };
  const server = createServer((request, response) => {
    if (!validFixtureHeaders(request, secrets, true)) {
      response.writeHead(401).end();
      return;
    }
    fixture.accepted += 1;
    void transport.handleRequest(request, response);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return {
    ...fixture,
    get accepted() {
      return fixture.accepted;
    },
    url: serverUrl(server),
    close: async () => {
      await transport.close();
      await closeHttpServer(server);
    },
  };
}

async function startSseFixture(secrets: {
  plain: string;
  encoded: string;
  bearer: string;
}): Promise<RemoteFixture> {
  let stream: ServerResponse | undefined;
  const fixture = { accepted: 0 };
  const server = createServer(async (request, response) => {
    if (!validFixtureHeaders(request, secrets, true)) {
      response.writeHead(401).end();
      return;
    }
    fixture.accepted += 1;
    if (request.method === "GET") {
      stream = response;
      response.writeHead(200, {
        "cache-control": "no-cache",
        "content-type": "text/event-stream",
      });
      response.write("event: endpoint\ndata: /messages\n\n");
      return;
    }
    if (request.method !== "POST" || request.url !== "/messages") {
      response.writeHead(404).end();
      return;
    }
    const message = await readJsonRequest(request);
    stream?.write(`data: ${JSON.stringify(responseFor(message))}\n\n`);
    response.writeHead(202).end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return {
    get accepted() {
      return fixture.accepted;
    },
    url: serverUrl(server),
    close: async () => {
      stream?.end();
      await closeHttpServer(server);
    },
  };
}

async function startWebSocketFixture(secrets: {
  plain: string;
  encoded: string;
  bearer: string;
}): Promise<RemoteFixture> {
  const fixture = { accepted: 0 };
  const server = new WebSocketServer({
    host: "127.0.0.1",
    port: 0,
    perMessageDeflate: false,
    handleProtocols: (protocols) => (protocols.has("mcp") ? "mcp" : false),
  });
  server.on("connection", (socket, request) => {
    if (!validFixtureHeaders(request, secrets, false)) {
      socket.terminate();
      return;
    }
    fixture.accepted += 1;
    socket.on("message", (data, isBinary) => {
      if (isBinary) return;
      const message = JSON.parse(data.toString()) as RpcRequest;
      if (message.id !== undefined) socket.send(JSON.stringify(responseFor(message)));
    });
  });
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");
  return {
    get accepted() {
      return fixture.accepted;
    },
    url: `ws://127.0.0.1:${address.port}/mcp`,
    close: async () => {
      for (const client of server.clients) client.terminate();
      await new Promise<void>((resolveClose, reject) =>
        server.close((error) => (error ? reject(error) : resolveClose())),
      );
    },
  };
}

type RpcRequest = {
  jsonrpc: "2.0";
  id: string | number;
  method: string;
  params?: { protocolVersion?: string };
};

function responseFor(message: RpcRequest) {
  const result =
    message.method === "initialize"
      ? {
          protocolVersion: message.params?.protocolVersion ?? "",
          capabilities: { tools: {} },
          serverInfo: { name: "cli-remote-fixture", version: "1.0.0" },
        }
      : message.method === "tools/list"
        ? { tools: [{ name: "read_file", inputSchema: { type: "object" } }] }
        : {};
  return { jsonrpc: "2.0" as const, id: message.id, result };
}

function validFixtureHeaders(
  request: IncomingMessage,
  secrets: { plain: string; encoded: string; bearer: string },
  bearer: boolean,
): boolean {
  return (
    request.headers["x-plain"] === secrets.plain &&
    request.headers["x-encoded"] === secrets.encoded &&
    (!bearer || request.headers.authorization === `Bearer ${secrets.bearer}`)
  );
}

async function readJsonRequest(request: IncomingMessage): Promise<RpcRequest> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

async function startHttpServer(
  listener: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<{ url: string; close(): Promise<void> }> {
  const server = createServer(listener);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return { url: serverUrl(server), close: () => closeHttpServer(server) };
}

function serverUrl(server: Server): string {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");
  return `http://127.0.0.1:${address.port}/mcp`;
}

function closeHttpServer(server: Server): Promise<void> {
  if (!server.listening) return Promise.resolve();
  server.closeAllConnections();
  return new Promise((resolveClose, reject) =>
    server.close((error) => (error ? reject(error) : resolveClose())),
  );
}

test("rejects a missing selected environment before spawning the upstream", async () => {
  const env = { ...process.env };
  delete env.MISSING;
  const child = spawn(
    process.execPath,
    [
      cli,
      "--policy",
      policy,
      "--upstream-env",
      "MISSING",
      "--",
      process.execPath,
      "-e",
      "process.exit(42)",
    ],
    { cwd: projectRoot, env, stdio: ["ignore", "ignore", "pipe"] },
  );
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

  const [code] = await once(child, "exit");

  expect(code).toBe(1);
  expect(Buffer.concat(stderr).toString("utf8")).toContain(
    "Environment variable MISSING is missing",
  );
});

test("rejects an upstream bearer environment without an HTTP upstream", async () => {
  const child = spawn(
    process.execPath,
    [
      cli,
      "--policy",
      policy,
      "--upstream-bearer-token-env",
      "MCP_TOKEN",
      "--",
      process.execPath,
      "-e",
      "",
    ],
    { cwd: projectRoot, stdio: ["ignore", "ignore", "pipe"] },
  );
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

  const [code] = await once(child, "exit");

  expect(code).toBe(1);
  expect(Buffer.concat(stderr).toString("utf8")).toContain(
    "--upstream-bearer-token-env requires --upstream-http",
  );
});

test("rejects a missing upstream bearer environment value", async () => {
  const child = spawn(
    process.execPath,
    [
      cli,
      "--policy",
      policy,
      "--upstream-http",
      "http://127.0.0.1:1/mcp",
      "--upstream-bearer-token-env",
      "MISSING_TOKEN",
    ],
    {
      cwd: projectRoot,
      env: { ...process.env, MISSING_TOKEN: "" },
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

  const [code] = await once(child, "exit");

  expect(code).toBe(1);
  expect(Buffer.concat(stderr).toString("utf8")).toContain(
    "Environment variable MISSING_TOKEN is empty or missing",
  );
});

test("rejects an inherited upstream bearer environment value before network", async () => {
  const env = { ...process.env };
  delete env["__proto__"];
  const child = spawn(
    process.execPath,
    [
      cli,
      "--policy",
      policy,
      "--upstream-http",
      "http://127.0.0.1:1/mcp",
      "--upstream-bearer-token-env",
      "__proto__",
    ],
    {
      cwd: projectRoot,
      env,
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

  const [code] = await once(child, "exit");
  const message = Buffer.concat(stderr).toString("utf8");

  expect(code).toBe(1);
  expect(message).toBe("mcp-restrictor: Environment variable __proto__ is empty or missing\n");
  expect(message).not.toContain("[object Object]");
});

test.each([
  {
    name: "both listener schemes",
    args: [
      "--listen-http",
      "http://127.0.0.1:0/mcp",
      "--listen-https",
      "https://127.0.0.1:0/mcp",
      "--tls-cert",
      certificate,
      "--tls-key",
      privateKey,
    ],
    message: "--listen-http and --listen-https are mutually exclusive",
  },
  {
    name: "HTTPS without a certificate",
    args: ["--listen-https", "https://127.0.0.1:0/mcp", "--tls-key", privateKey],
    message: "--listen-https requires --tls-cert and --tls-key",
  },
  {
    name: "HTTPS without a private key",
    args: ["--listen-https", "https://127.0.0.1:0/mcp", "--tls-cert", certificate],
    message: "--listen-https requires --tls-cert and --tls-key",
  },
  {
    name: "a certificate without HTTPS",
    args: ["--tls-cert", certificate],
    message: "--tls-cert and --tls-key require --listen-https",
  },
  {
    name: "a private key without HTTPS",
    args: ["--tls-key", privateKey],
    message: "--tls-cert and --tls-key require --listen-https",
  },
])("rejects $name", async ({ args, message }) => {
  const child = spawn(
    process.execPath,
    [cli, "--policy", policy, ...args, "--", process.execPath, "-e", ""],
    { cwd: projectRoot, stdio: ["ignore", "ignore", "pipe"] },
  );
  const stderr: Buffer[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

  const [code] = await once(child, "exit");

  expect(code).toBe(1);
  expect(Buffer.concat(stderr).toString("utf8")).toContain(message);
});

test("reads direct HTTPS credentials before loading the policy", async () => {
  const missingPolicy = resolve(testDirectory, "fixtures/review-missing-policy.yaml");
  const missingCertificate = resolve(testDirectory, "fixtures/review-missing-certificate.pem");

  await expect(
    runProxyCommand(
      {},
      {
        argv: [
          process.execPath,
          cli,
          "--policy",
          missingPolicy,
          "--listen-https",
          "https://127.0.0.1:0/mcp",
          "--tls-cert",
          missingCertificate,
          "--tls-key",
          privateKey,
          "--upstream-http",
          "https://upstream.example/mcp",
        ],
        home: projectRoot,
        environment: {},
        input: Readable.from([]),
        output: new PassThrough(),
      },
    ),
  ).rejects.toThrow(missingCertificate);
});
