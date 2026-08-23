import { spawn } from "node:child_process";
import { once } from "node:events";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { afterEach, expect, test, vi } from "vitest";
import { runRoutesCommand } from "../src/commands/run.ts";
import { resolveProxyRoute } from "../src/commands/proxy.ts";
import { MASTER_KEY_FILE_ENV, writeOAuthProfile, type OAuthProfile } from "../src/oauth/storage.ts";
import {
  routePath,
  routeUrl,
  serializeRoute,
  type RouteDefinitionV1,
  type RouteOwner,
} from "../src/routes.ts";
import { closeServer, startHttpFixture } from "./helpers.ts";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(testDirectory, "../../..");
const cli = resolve(projectRoot, "packages/cli/dist/index.js");
const homes: string[] = [];

afterEach(async () => {
  process.exitCode = undefined;
  await Promise.all(homes.splice(0).map((home) => rm(home, { recursive: true, force: true })));
});

test("run rejects an empty route directory before binding", async () => {
  const home = await temporaryHome();
  const startGateway = vi.fn(() => {
    throw new Error("must not bind");
  });

  await expect(
    runRoutesCommand({ home, environment: {}, startHttpGateway: startGateway }),
  ).rejects.toThrow("No managed HTTP routes; run setup");
  expect(startGateway).not.toHaveBeenCalled();
});

test("run passes wildcard bind while advertising stored loopback route URLs", async () => {
  const home = await temporaryHome();
  const policy = await writePolicy(home, "wildcard-bind", "read_file");
  const route = await writeRoute(home, "wildcard-bind", 7319, [
    "--policy",
    policy,
    "--",
    process.execPath,
  ]);
  const controller = new AbortController();
  const error = new CapturedOutput();
  const startGateway = vi.fn<
    NonNullable<Parameters<typeof runRoutesCommand>[0]["startHttpGateway"]>
  >(async ({ signal }) => {
    let finish!: () => void;
    const closed = new Promise<void>((resolve) => {
      finish = resolve;
    });
    signal?.addEventListener("abort", finish, { once: true });
    return {
      origin: "http://127.0.0.1:7319",
      closed,
      close: async () => finish(),
    };
  });

  const running = runRoutesCommand({
    home,
    environment: {},
    bindHostname: "0.0.0.0",
    signal: controller.signal,
    error,
    startHttpGateway: startGateway,
  });
  try {
    await error.waitFor(route.listenUrl);
    expect(startGateway).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ listen: "http://127.0.0.1:7319", bindHostname: "0.0.0.0" }),
    );
    expect(error.text()).toContain(`mcp-restrictor listening ${route.listenUrl} `);
    expect(error.text()).not.toContain("0.0.0.0");
  } finally {
    controller.abort();
    await running;
  }
});

test("run escapes bidi controls in route identity diagnostics", async () => {
  const home = await temporaryHome();
  const port = await reservePort();
  const serverName = "safe\u202ehidden";
  const policy = await writePolicy(home, "bidi", "read_file");
  await writeFile(policy, "not: [valid", "utf8");
  await writeDefinition(
    home,
    routeDefinition(routeOwner(home, serverName), port, [
      "--policy",
      policy,
      "--upstream-http",
      "https://upstream.example/mcp",
    ]),
  );

  const failure = await runRoutesCommand({ home, environment: {} }).catch(
    (error: unknown) => error,
  );

  expect(failure).toBeInstanceOf(Error);
  expect((failure as Error).message).toContain("safe\\\\u202ehidden");
  expect((failure as Error).message).not.toContain("\u202e");
});

test("run escapes bidi controls in denied client tool audit fields", async () => {
  const home = await temporaryHome();
  const port = await reservePort();
  const upstream = await startHttpFixture();
  const policy = await writePolicy(home, "audit-bidi", "read_file");
  const route = await writeRoute(home, "audit-bidi", port, [
    "--policy",
    policy,
    "--upstream-http",
    upstream.url,
  ]);
  const controller = new AbortController();
  const error = new CapturedOutput();
  const client = new Client({ name: "run-audit-test", version: "1.0.0" });

  try {
    const running = runRoutesCommand({
      home,
      environment: {},
      signal: controller.signal,
      error,
    });
    await error.waitFor(route.listenUrl);
    await client.connect(new StreamableHTTPClientTransport(new URL(route.listenUrl)));

    const tool = "safe\u202ehidden";
    await expect(client.callTool({ name: tool, arguments: {} })).rejects.toMatchObject({
      code: -32001,
    });
    expect(error.text()).toContain('"tool":"safe\\\\u202ehidden"');
    expect(error.text()).not.toContain(tool);

    controller.abort();
    await running;
  } finally {
    controller.abort();
    await client.close().catch(() => {});
    await upstream.close();
  }
});

test("shared proxy resolution rejects noncanonical route argument order", async () => {
  const home = await temporaryHome();
  const policy = await writePolicy(home, "policy", "read_file");

  await expect(
    resolveProxyRoute(
      ["--upstream-http", "https://upstream.example/mcp", "--policy", policy],
      {},
      { home, environment: {} },
    ),
  ).rejects.toThrow();
});

test("run serves two isolated routes and injected abort closes every route", async () => {
  const home = await temporaryHome();
  const port = await reservePort();
  const upstreamA = await startHttpFixture({ instanceId: "upstream-alpha" });
  const upstreamB = await startHttpFixture({ instanceId: "upstream-beta" });
  const policyA = await writePolicy(home, "alpha", "read_file");
  const policyB = await writePolicy(home, "beta", "write_file");
  const routeA = await writeRoute(home, "alpha", port, [
    "--policy",
    policyA,
    "--upstream-http",
    upstreamA.url,
  ]);
  const routeB = await writeRoute(home, "beta", port, [
    "--policy",
    policyB,
    "--upstream-http",
    upstreamB.url,
  ]);
  const controller = new AbortController();
  const error = new CapturedOutput();

  try {
    const running = runRoutesCommand({
      home,
      environment: {},
      signal: controller.signal,
      error,
    });
    await error.waitFor(routeB.listenUrl);

    expect(await toolsAndCall(routeA.listenUrl, "read_file")).toEqual({
      tools: ["read_file"],
      text: "upstream:read_file:upstream-alpha",
    });
    expect(await toolsAndCall(routeB.listenUrl, "write_file")).toEqual({
      tools: ["write_file"],
      text: "upstream:write_file:upstream-beta",
    });
    expect(error.text()).toContain('"adapterId":"codex"');
    expect(error.text()).toContain('"serverName":"alpha"');
    expect(error.text()).toContain('"serverName":"beta"');
    for (const privateValue of [policyA, policyB, upstreamA.url, upstreamB.url]) {
      expect(error.text()).not.toContain(privateValue);
    }

    controller.abort();
    await running;
    await expectPortAvailable(port);
    expect(process.exitCode).toBe(0);
  } finally {
    controller.abort();
    await Promise.all([upstreamA.close(), upstreamB.close()]);
  }
});

test("run preflights every route failure before opening the shared port", async () => {
  for (const kind of [
    "malformed policy",
    "missing environment",
    "invalid OAuth binding",
    "bad route",
  ] as const) {
    const home = await temporaryHome();
    const port = await reservePort();
    const policy = await writePolicy(home, kind.replaceAll(" ", "-"), "read_file");
    const owner = routeOwner(home, kind.replaceAll(" ", "-"));
    const options: Parameters<typeof runRoutesCommand>[0] = { home, environment: {} };

    if (kind === "malformed policy") {
      await writeFile(policy, "not: [valid", "utf8");
      await writeDefinition(
        home,
        routeDefinition(owner, port, [
          "--policy",
          policy,
          "--upstream-http",
          "https://upstream.example/mcp",
        ]),
      );
    } else if (kind === "missing environment") {
      await writeDefinition(
        home,
        routeDefinition(owner, port, [
          "--policy",
          policy,
          "--upstream-http",
          "https://upstream.example/mcp",
          "--upstream-header-env",
          "X-Key=MISSING_HEADER",
        ]),
      );
    } else if (kind === "invalid OAuth binding") {
      const profileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
      const keyPath = join(home, "master.key");
      await writeDefinition(
        home,
        routeDefinition(
          owner,
          port,
          [
            "--policy",
            policy,
            "--upstream-http",
            "https://upstream.example/mcp",
            "--upstream-oauth-profile",
            profileId,
          ],
          { [MASTER_KEY_FILE_ENV]: keyPath },
        ),
      );
      options.readOAuthProfile = async () =>
        exampleOAuthProfile(profileId, "https://other.example/mcp");
    } else {
      await writeRawRoute(home, owner, "{}\n");
    }

    await expect(runRoutesCommand(options)).rejects.toThrow();
    await expectPortAvailable(port);
    process.exitCode = undefined;
  }
});

test.each(["missing", "invalid"] as const)(
  "run rejects a %s stored OAuth key before starting the gateway",
  async (failure) => {
    const home = await temporaryHome();
    const profileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const upstreamUrl = "https://upstream.example/mcp";
    const keyPath = join(home, "master.key");
    const policy = await writePolicy(home, `oauth-${failure}-key`, "read_file");
    await writeFile(keyPath, Buffer.alloc(32, 23).toString("base64url"), { mode: 0o600 });
    await chmod(keyPath, 0o600);
    await writeOAuthProfile(exampleOAuthProfile(profileId, upstreamUrl), {
      home,
      environment: { [MASTER_KEY_FILE_ENV]: keyPath },
    });
    await writeDefinition(
      home,
      routeDefinition(
        routeOwner(home, `oauth-${failure}-key`),
        7319,
        ["--policy", policy, "--upstream-http", upstreamUrl, "--upstream-oauth-profile", profileId],
        { [MASTER_KEY_FILE_ENV]: keyPath },
      ),
    );
    if (failure === "missing") await rm(keyPath);
    else await writeFile(keyPath, "not-a-master-key", { mode: 0o600 });
    const startGateway = vi.fn(() => {
      throw new Error("must not bind");
    });

    await expect(
      runRoutesCommand({ home, environment: {}, startHttpGateway: startGateway }),
    ).rejects.toThrow(/Managed HTTP route preflight failed/);

    expect(startGateway).not.toHaveBeenCalled();
    if (failure === "missing") {
      await expect(realpath(keyPath)).rejects.toMatchObject({ code: "ENOENT" });
    } else {
      expect(await readFile(keyPath, "utf8")).toBe("not-a-master-key");
    }
  },
);

test("run aborts the lifetime signal passed to an OAuth provider", async () => {
  const home = await temporaryHome();
  const profileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const upstreamUrl = "https://upstream.example/mcp";
  const policy = await writePolicy(home, "oauth-lifetime", "read_file");
  await writeDefinition(
    home,
    routeDefinition(
      routeOwner(home, "oauth-lifetime"),
      7319,
      ["--policy", policy, "--upstream-http", upstreamUrl, "--upstream-oauth-profile", profileId],
      { [MASTER_KEY_FILE_ENV]: join(home, "master.key") },
    ),
  );
  const controller = new AbortController();
  const transport = new AbortController();
  let providerSignal: AbortSignal | undefined;

  const running = runRoutesCommand({
    home,
    environment: {},
    error: new CapturedOutput(),
    signal: controller.signal,
    readOAuthProfile: async () => exampleOAuthProfile(profileId, upstreamUrl),
    createOAuthAuthProvider: (_id, _binding, options = {}) => {
      providerSignal = options.signal;
      return { token: async () => "oauth-token" };
    },
    startHttpGateway: async ({ routes, signal }) => {
      const upstream = routes[0]?.upstream;
      if (upstream?.kind !== "http" || !upstream.authProviderFactory) {
        throw new Error("Missing OAuth upstream provider factory");
      }
      upstream.authProviderFactory(transport.signal);
      let finish!: () => void;
      const closed = new Promise<void>((resolve) => {
        finish = resolve;
      });
      signal?.addEventListener("abort", finish, { once: true });
      return {
        origin: "http://127.0.0.1:7319",
        closed,
        close: async () => finish(),
      };
    },
  });

  await vi.waitFor(() => expect(providerSignal).toBeDefined());
  expect(providerSignal!.aborted).toBe(false);
  controller.abort();
  await running;
  expect(providerSignal!.aborted).toBe(true);
  expect(transport.signal.aborted).toBe(false);
});

test("a second run reports the occupied shared port without configured values", async () => {
  const home = await temporaryHome();
  const port = await reservePort();
  const upstream = await startHttpFixture();
  const policy = await writePolicy(home, "occupied", "read_file");
  const route = await writeRoute(home, "occupied", port, [
    "--policy",
    policy,
    "--upstream-http",
    upstream.url,
  ]);
  const controller = new AbortController();
  const firstError = new CapturedOutput();
  const first = runRoutesCommand({
    home,
    environment: {},
    signal: controller.signal,
    error: firstError,
  });

  try {
    await firstError.waitFor(route.listenUrl);
    await expect(runRoutesCommand({ home, environment: {} })).rejects.toThrow(
      "Managed HTTP route listener is already in use",
    );
  } finally {
    controller.abort();
    await first;
    await upstream.close();
  }
});

test.each(["SIGINT", "SIGTERM"] as const)(
  "run exits cleanly on %s with empty stdout and secret-free stderr",
  async (signal) => {
    const home = await temporaryHome();
    const port = await reservePort();
    const upstream = await startHttpFixture();
    const policy = await writePolicy(home, signal.toLowerCase(), "read_file");
    const secret = `${signal}-configured-secret`;
    const route = await writeRoute(home, signal.toLowerCase(), port, [
      "--policy",
      policy,
      "--upstream-http",
      upstream.url,
      "--upstream-bearer-token-env",
      "RUN_BEARER_TOKEN",
    ]);
    const child = spawn(process.execPath, [cli, "run"], {
      cwd: projectRoot,
      env: { ...process.env, HOME: home, RUN_BEARER_TOKEN: secret },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));

    try {
      await waitForText(stderr, route.listenUrl);
      child.kill(signal);
      const [code] = await once(child, "exit");
      const diagnostics = Buffer.concat(stderr).toString("utf8");
      expect(code, diagnostics).toBe(0);
      expect(Buffer.concat(stdout).toString("utf8")).toBe("");
      expect(diagnostics).toContain('"adapterId":"codex"');
      expect(diagnostics).toContain(`"serverName":"${signal.toLowerCase()}"`);
      for (const privateValue of [secret, policy, upstream.url, route.owner.configPath]) {
        expect(diagnostics).not.toContain(privateValue);
      }
    } finally {
      if (child.exitCode === null) child.kill("SIGKILL");
      await upstream.close();
    }
  },
);

test("run keeps its startup route snapshot until restart", async () => {
  const home = await temporaryHome();
  const port = await reservePort();
  const upstreamA = await startHttpFixture({ instanceId: "snapshot-alpha" });
  const upstreamB = await startHttpFixture({ instanceId: "snapshot-beta" });
  const policyA = await writePolicy(home, "snapshot-alpha", "read_file");
  const policyB = await writePolicy(home, "snapshot-beta", "write_file");
  const routeA = await writeRoute(home, "snapshot", port, [
    "--policy",
    policyA,
    "--upstream-http",
    upstreamA.url,
  ]);
  const routeB = routeDefinition(routeA.owner, port, [
    "--policy",
    policyB,
    "--upstream-http",
    upstreamB.url,
  ]);

  try {
    const firstController = new AbortController();
    const firstError = new CapturedOutput();
    const first = runRoutesCommand({
      home,
      environment: {},
      signal: firstController.signal,
      error: firstError,
    });
    await firstError.waitFor(routeA.listenUrl);
    await writeDefinition(home, routeB);
    expect(await toolsAndCall(routeA.listenUrl, "read_file")).toEqual({
      tools: ["read_file"],
      text: "upstream:read_file:snapshot-alpha",
    });
    firstController.abort();
    await first;

    const secondController = new AbortController();
    const secondError = new CapturedOutput();
    const second = runRoutesCommand({
      home,
      environment: {},
      signal: secondController.signal,
      error: secondError,
    });
    await secondError.waitFor(routeB.listenUrl);
    expect(await toolsAndCall(routeB.listenUrl, "write_file")).toEqual({
      tools: ["write_file"],
      text: "upstream:write_file:snapshot-beta",
    });
    secondController.abort();
    await second;
  } finally {
    await Promise.all([upstreamA.close(), upstreamB.close()]);
  }
});

class CapturedOutput extends Writable {
  readonly #chunks: Buffer[] = [];

  override _write(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    this.#chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding));
    callback();
  }

  text(): string {
    return Buffer.concat(this.#chunks).toString("utf8");
  }

  async waitFor(value: string): Promise<void> {
    await vi.waitFor(() => expect(this.text()).toContain(value));
  }
}

async function temporaryHome(): Promise<string> {
  const home = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-run-")));
  homes.push(home);
  return home;
}

async function reservePort(): Promise<number> {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing reserved port");
  await closeServer(server);
  return address.port;
}

async function expectPortAvailable(port: number): Promise<void> {
  const server = createServer();
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
  await closeServer(server);
}

async function writePolicy(home: string, name: string, tool: string): Promise<string> {
  const path = join(home, `${name}.policy.json`);
  await writeFile(
    path,
    JSON.stringify({
      version: 1,
      default: "deny",
      tools: { allow: [{ name: tool }], deny: [] },
    }),
    "utf8",
  );
  return path;
}

function routeOwner(home: string, serverName: string): RouteOwner {
  return {
    adapterId: "codex",
    scope: "project",
    configPath: join(home, `${serverName}.config.json`),
    projectRoot: home,
    serverName,
  };
}

function routeDefinition(
  owner: RouteOwner,
  port: number,
  proxyArgs: string[],
  set: Record<string, string> = {},
): RouteDefinitionV1 {
  return { version: 1, owner, listenUrl: routeUrl(port, owner), proxyArgs, environment: { set } };
}

async function writeRoute(
  home: string,
  serverName: string,
  port: number,
  proxyArgs: string[],
): Promise<RouteDefinitionV1> {
  const route = routeDefinition(routeOwner(home, serverName), port, proxyArgs);
  await writeDefinition(home, route);
  return route;
}

async function writeDefinition(home: string, route: RouteDefinitionV1): Promise<void> {
  await writeRawRoute(home, route.owner, serializeRoute(route));
}

async function writeRawRoute(home: string, owner: RouteOwner, content: string): Promise<void> {
  const path = routePath(home, owner);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await chmod(dirname(dirname(path)), 0o700);
  await chmod(dirname(path), 0o700);
  await writeFile(path, content, { mode: 0o600 });
  await chmod(path, 0o600);
}

async function toolsAndCall(url: string, tool: string): Promise<{ tools: string[]; text: string }> {
  const client = new Client({ name: "run-route-test", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(url)));
  try {
    const tools = (await client.listTools()).tools.map(({ name }) => name);
    const result = await client.callTool({ name: tool, arguments: {} });
    const content = result.content[0];
    if (content?.type !== "text") throw new Error("Missing text tool result");
    return { tools, text: content.text };
  } finally {
    await client.close();
  }
}

async function waitForText(chunks: readonly Buffer[], value: string): Promise<void> {
  await vi.waitFor(() => expect(Buffer.concat(chunks).toString("utf8")).toContain(value));
}

function exampleOAuthProfile(id: string, serverUrl: string): OAuthProfile {
  const issuer = "https://auth.example.test";
  return {
    metadata: {
      version: 1,
      profileId: id,
      serverUrl,
      callback: { host: "127.0.0.1", path: "/callback", appendProfileId: true },
      clientMetadata: {},
    },
    credentials: {
      clientInformation: { client_id: "client-id", issuer },
      tokens: { access_token: "access-token", token_type: "Bearer", issuer },
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
