import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { afterEach, expect, test, vi } from "vitest";
import { MASTER_KEY_FILE_ENV } from "../src/oauth/storage.ts";
import { routePath, routeUrl, serializeRoute, type RouteOwner } from "../src/routes.ts";
import { runSetup } from "../src/setup/index.ts";
import { defineClientAdapter, type ClientAdapter } from "../src/client-adapter.ts";
import { installAdapterHttpConfig } from "../src/setup/adapter-boundary.ts";
import { claudeAdapter } from "../src/setup/claude.ts";
import { codexAdapter } from "../src/setup/codex.ts";
import {
  generatedConfigPath,
  generatedPolicyLocation,
  generatedPresetConfig,
  isGeneratedConfigPath,
  type GeneratedPresetKind,
} from "../src/setup/generated.ts";
import {
  planManualWrapper,
  promptManualCandidate,
  resolveManualUpstream,
  type ManualCandidate,
} from "../src/setup/manual.ts";
import { discoverManualDestinations } from "../src/setup/manual/destinations.ts";
import {
  planManualDestinationHttpRoute,
  planManualDestinationWrapper,
} from "../src/setup/manual/planning.ts";
import { opencodeAdapter } from "../src/setup/opencode.ts";
import { CONTAINER_MARKER_ENV } from "../src/setup/constants.ts";
import { SetupCancelled } from "../src/setup/interaction.ts";

const setupManualFakes = vi.hoisted(() => ({
  discover: undefined as undefined | ((server: unknown, options: unknown) => Promise<unknown>),
}));

vi.mock("../src/setup/discovery.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/setup/discovery.ts")>();
  return {
    ...actual,
    discoverSetupServer: (...args: Parameters<typeof actual.discoverSetupServer>) =>
      setupManualFakes.discover
        ? setupManualFakes.discover(args[0], args[1])
        : actual.discoverSetupServer(...args),
  };
});

const temporaryDirectories: string[] = [];
const testDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(testDirectory, "../../..");
const cli = resolve(projectRoot, "packages/cli/dist/index.js");
const upstream = resolve(
  projectRoot,
  "packages/transports/test/fixtures/config-sensitive-upstream.mjs",
);
const simpleUpstream = resolve(projectRoot, "packages/cli/test/fixtures/upstream.mjs");

afterEach(async () => {
  setupManualFakes.discover = undefined;
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { force: true, recursive: true })),
  );
});

test("generated preset paths, baselines, and native HTTP fragments are deterministic", () => {
  const home = "/home/restrictor";
  const url = "http://127.0.0.1:17319/mcp/claude/route-id";
  const rows: Array<{
    kind: GeneratedPresetKind;
    adapter: ClientAdapter;
    path: string;
    baseline: string;
    fragment: string;
  }> = [
    {
      kind: "claude",
      adapter: claudeAdapter,
      path: "/home/restrictor/.mcp-restrictor/generated/claude.json",
      baseline: "{}\n",
      fragment:
        '{\n  "mcpServers": {\n    "github": {\n      "type": "http",\n      "url": "http://127.0.0.1:17319/mcp/claude/route-id"\n    }\n  }\n}\n',
    },
    {
      kind: "codex",
      adapter: codexAdapter,
      path: "/home/restrictor/.mcp-restrictor/generated/codex.toml",
      baseline: "",
      fragment: '[mcp_servers.github]\nurl = "http://127.0.0.1:17319/mcp/claude/route-id"\n',
    },
    {
      kind: "opencode-v2",
      adapter: opencodeAdapter,
      path: "/home/restrictor/.mcp-restrictor/generated/opencode-v2.jsonc",
      baseline: '{\n  "mcp": {\n    "servers": {}\n  }\n}\n',
      fragment:
        '{\n  "mcp": {\n    "servers": {\n      "github": {\n        "type": "remote",\n        "url": "http://127.0.0.1:17319/mcp/claude/route-id",\n        "oauth": false\n      }\n    }\n  }\n}\n',
    },
    {
      kind: "opencode-v1",
      adapter: opencodeAdapter,
      path: "/home/restrictor/.mcp-restrictor/generated/opencode-v1.jsonc",
      baseline: "{}\n",
      fragment:
        '{\n  "mcp": {\n    "github": {\n      "type": "remote",\n      "url": "http://127.0.0.1:17319/mcp/claude/route-id",\n      "oauth": false\n    }\n  }\n}\n',
    },
  ];

  for (const row of rows) {
    expect(generatedConfigPath(home, row.kind)).toBe(row.path);
    const config = generatedPresetConfig({ home, kind: row.kind, environment: {} });
    expect(config).toMatchObject({ scope: "user", path: row.path, source: row.baseline });
    expect(installAdapterHttpConfig(row.adapter, config, { name: "github", url })).toBe(
      row.fragment,
    );
    expect(isGeneratedConfigPath(home, row.adapter.id, row.path)).toBe(true);
  }

  expect(isGeneratedConfigPath(home, "claude", rows[1]!.path)).toBe(false);
  expect(isGeneratedConfigPath(home, "external", rows[0]!.path)).toBe(false);
  expect(isGeneratedConfigPath(home, "claude", `${rows[0]!.path}.bak`)).toBe(false);
  expect(
    generatedPolicyLocation({ home, adapterId: "opencode", serverName: "github repo" }),
  ).toEqual({
    diskPath: "/home/restrictor/.mcp-restrictor/generated/policies/opencode/github%20repo.yaml",
    argument: "/home/restrictor/.mcp-restrictor/generated/policies/opencode/github%20repo.yaml",
    relativePath: ".mcp-restrictor/generated/policies/opencode/github%20repo.yaml",
  });
  for (const serverName of ["../github", "github/control", "github\\control", "github\ncontrol"])
    expect(() => generatedPolicyLocation({ home, adapterId: "claude", serverName })).toThrow(
      "Invalid generated preset path",
    );
});

test.each([
  ["V2 path with a V1 shape", "opencode-v2", "{}\n"],
  ["V1 path with a V2 shape", "opencode-v1", '{"mcp":{"servers":{}}}\n'],
] as const)("generated OpenCode rejects %s", (_case, kind, source) => {
  expect(() =>
    generatedPresetConfig({ home: "/home/restrictor", kind, environment: {}, source }),
  ).toThrow("Invalid generated preset path");
});

test("Manual container OAuth keeps the marker only in reduced storage state", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const output = capture();
  const keyPath = "/home/restrictor/.mcp-restrictor-key/oauth-master-key-v1";
  const keyBytes = Buffer.alloc(32, 17).toString("base64url");
  let observedStorage: NodeJS.ProcessEnv | undefined;
  let observedWrapper: { env?: Record<string, string> } | undefined;
  setupManualFakes.discover = async (server, options) => {
    observedStorage = (options as { environment: NodeJS.ProcessEnv }).environment;
    observedWrapper = (server as { wrapperEnvironment: { env?: Record<string, string> } })
      .wrapperEnvironment;
    throw new SetupCancelled();
  };

  await runSetup({
    input: Readable.from([
      "4\n",
      "oauth\n",
      "sse\n",
      "https://example.test/events\n",
      "\n",
      "oauth\n",
      "\n",
      "\n",
      "\n",
      "\n",
      "\n",
      "\n",
      "\n",
      "\n",
      "1\n",
      "\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: {
      PATH: process.env.PATH,
      [CONTAINER_MARKER_ENV]: "1",
      [MASTER_KEY_FILE_ENV]: keyPath,
      UNUSED_KEY_BYTES: keyBytes,
    },
  });

  expect(observedStorage).toEqual({
    [MASTER_KEY_FILE_ENV]: keyPath,
    [CONTAINER_MARKER_ENV]: "1",
  });
  expect(observedWrapper).toEqual({ env: { [MASTER_KEY_FILE_ENV]: keyPath } });
  expect(output.text()).toContain("Setup cancelled.");
  expect(output.text()).not.toContain(CONTAINER_MARKER_ENV);
  expect(output.text()).not.toContain(keyBytes);
});

test("offers Manual upstream before reading either client configuration", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const paths = [
    join(home, ".claude.json"),
    join(root, ".mcp.json"),
    join(home, ".codex", "config.toml"),
    join(root, ".codex", "config.toml"),
  ];
  for (const path of paths) {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, "malformed client sentinel");
  }
  const output = capture();
  await runSetup({
    input: Readable.from(["4\n"]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { PATH: process.env.PATH },
  });

  expect(output.text()).toContain(
    "Clients:\n1. Claude Code\n2. Codex\n3. OpenCode\n4. Manual upstream\n",
  );
  expect(output.text()).toContain("Setup cancelled.");
  for (const path of paths) {
    expect(await readFile(path, "utf8")).toBe("malformed client sentinel");
  }
});

test("discovers exact capable Manual destinations and reports unsafe targets", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const projectPath = join(root, "project.json");
  const userPath = join(home, "user.json");
  const duplicatePath = join(root, "duplicate.json");
  await mkdir(dirname(userPath), { recursive: true });
  await Promise.all([projectPath, userPath, duplicatePath].map((path) => writeFile(path, "{}")));
  const adapter = destinationAdapter("capable", "Capable", [
    { path: userPath, scope: "user" as const },
    { path: projectPath, scope: "project" as const },
  ]);
  const collision = destinationAdapter("collision", "Collision", [
    { path: duplicatePath, scope: "project" as const, servers: [{ name: "files" }] },
  ]);
  const { restore: _restore, ...incomplete } = destinationAdapter(
    "incomplete",
    "Incomplete",
    [],
  ).adapter;
  const noRestore = defineClientAdapter(incomplete);

  const result = await discoverManualDestinations({
    adapters: [collision.adapter, noRestore, adapter.adapter],
    context: { home, projectRoot: root, cwd: root, environment: {} },
    serverName: "files",
    restrictorHome: join(home, ".mcp-restrictor"),
  });

  expect(
    result.available.map(({ adapter: available, config }) => [
      available.label,
      config.scope,
      config.path,
    ]),
  ).toEqual([
    ["Capable", "project", projectPath],
    ["Capable", "user", userPath],
  ]);
  expect(result.unavailable).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ adapterLabel: "Collision", reason: "server name already exists" }),
    ]),
  );
});

test("keeps a manual-ID adapter unavailable so the legacy policy path is not selected or written", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const configPath = join(root, "external.json");
  const legacyPolicyPath = join(root, ".mcp-restrictor", "policies", "manual", "files.yaml");
  await writeFile(configPath, "{}\n");

  const result = await discoverManualDestinations({
    adapters: [
      destinationAdapter("manual", "External Manual", [{ path: configPath, scope: "project" }])
        .adapter,
    ],
    context: { home, projectRoot: root, cwd: root, environment: {} },
    serverName: "files",
    restrictorHome: join(home, ".mcp-restrictor"),
  });

  expect(result.available).toEqual([]);
  expect(result.unavailable).toContainEqual(
    expect.objectContaining({
      adapterLabel: "External Manual",
      reason: "client ID is reserved for Manual configuration",
    }),
  );
  await expect(readFile(legacyPolicyPath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
});

test("isolates a hostile destination adapter capability getter", async () => {
  const root = await temporaryDirectory();
  const path = join(root, "config.json");
  await writeFile(path, "{}");
  const capable = destinationAdapter("capable", "Capable", [{ path, scope: "project" }]).adapter;
  const hostile = Object.create(capable) as ClientAdapter;
  Object.defineProperty(hostile, "install", {
    get() {
      throw new Error("hostile");
    },
  });

  const result = await discoverManualDestinations({
    adapters: [hostile, capable],
    context: { home: join(root, "home"), projectRoot: root, cwd: root, environment: {} },
    serverName: "files",
    restrictorHome: join(root, "home", ".mcp-restrictor"),
  });

  expect(result.available).toHaveLength(1);
  expect(result.unavailable).toContainEqual(
    expect.objectContaining({
      adapterLabel: "Capable",
      reason: "client configuration could not be loaded",
    }),
  );
});

test("rejects cross-adapter aliases and carries pre-existing destination policies", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const path = join(root, "config.json");
  const aliasPath = join(root, "alias.json");
  const otherPath = join(root, "other.json");
  await Promise.all([writeFile(path, "{}"), writeFile(otherPath, "{}")]);
  await link(path, aliasPath);
  const policy = join(home, ".mcp-restrictor", "policies", "taken", "files.yaml");
  await mkdir(dirname(policy), { recursive: true });
  await writeFile(policy, "occupied");
  const result = await discoverManualDestinations({
    adapters: [
      destinationAdapter("first", "First", [{ path, scope: "project" }]).adapter,
      destinationAdapter("second", "Second", [{ path: aliasPath, scope: "project" }]).adapter,
      destinationAdapter("taken", "Taken", [{ path: otherPath, scope: "user" }]).adapter,
    ],
    context: { home, projectRoot: root, cwd: root, environment: {} },
    serverName: "files",
    restrictorHome: join(home, ".mcp-restrictor"),
  });

  expect(result.available).toEqual([
    expect.objectContaining({
      adapter: expect.objectContaining({ id: "taken" }),
      policyBaseline: expect.objectContaining({ content: "occupied" }),
    }),
  ]);
  expect(result.unavailable).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        adapterLabel: "First",
        reason: "client configuration aliases another destination",
      }),
      expect.objectContaining({
        adapterLabel: "Second",
        reason: "client configuration aliases another destination",
      }),
    ]),
  );
});

test("classifies aliases before per-destination eligibility", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const path = join(root, "config.json");
  const aliasPath = join(root, "alias.json");
  await writeFile(path, "{}");
  await link(path, aliasPath);

  const result = await discoverManualDestinations({
    adapters: [
      destinationAdapter("conflict", "Conflict", [
        { path, scope: "project", servers: [{ name: "files" }] },
      ]).adapter,
      destinationAdapter("alias", "Alias", [{ path: aliasPath, scope: "project" }]).adapter,
    ],
    context: { home, projectRoot: root, cwd: root, environment: {} },
    serverName: "files",
    restrictorHome: join(home, ".mcp-restrictor"),
  });

  expect(result.available).toEqual([]);
  expect(result.unavailable).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        adapterLabel: "Conflict",
        reason: "client configuration aliases another destination",
      }),
      expect.objectContaining({
        adapterLabel: "Alias",
        reason: "client configuration aliases another destination",
      }),
    ]),
  );
});

test("treats config and OpenCode-shadow adapter ownership as destination collisions", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const configUnsupportedPath = join(root, "config-unsupported.json");
  const adapterUnsupportedPath = join(root, "adapter-unsupported.json");
  await Promise.all([
    writeFile(configUnsupportedPath, "{}"),
    writeFile(adapterUnsupportedPath, "{}"),
  ]);
  const result = await discoverManualDestinations({
    adapters: [
      destinationAdapter("config-unsupported", "Config unsupported", [
        { path: configUnsupportedPath, scope: "project", unsupported: [{ name: "files" }] },
      ]).adapter,
      destinationAdapter(
        "opencode-shadow",
        "OpenCode shadow",
        [{ path: adapterUnsupportedPath, scope: "project" }],
        [{ name: "files", scope: "project", configPath: adapterUnsupportedPath }],
      ).adapter,
    ],
    context: { home, projectRoot: root, cwd: root, environment: {} },
    serverName: "files",
    restrictorHome: join(home, ".mcp-restrictor"),
  });

  expect(result.available).toEqual([]);
  expect(result.unavailable).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        adapterLabel: "Config unsupported",
        reason: "server name already exists",
      }),
      expect.objectContaining({
        adapterLabel: "OpenCode shadow",
        reason: "server name already exists",
      }),
    ]),
  );
});

test("treats an inline OpenCode owner as a destination collision", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  await writeFile(
    join(root, "opencode.jsonc"),
    JSON.stringify({ mcp: { files: { type: "local", command: ["node", "project.mjs"] } } }),
  );
  const result = await discoverManualDestinations({
    adapters: [opencodeAdapter],
    context: {
      home,
      projectRoot: root,
      cwd: root,
      environment: {
        OPENCODE_CONFIG_CONTENT: JSON.stringify({
          mcp: { files: { type: "local", command: ["node", "inline.mjs"] } },
        }),
      },
    },
    serverName: "files",
    restrictorHome: join(home, ".mcp-restrictor"),
  });

  expect(result.available).toEqual([]);
  expect(result.unavailable).toContainEqual(
    expect.objectContaining({ adapterLabel: "OpenCode", reason: "server name already exists" }),
  );
});

test("line-mode Manual destinations keep copy-only default and validate selected scopes", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const projectFirst = join(root, "first.json");
  const projectSecond = join(root, "second.json");
  const user = join(home, "user.json");
  await mkdir(dirname(user), { recursive: true });
  await Promise.all([projectFirst, projectSecond, user].map((path) => writeFile(path, "{}")));
  const adapter = destinationAdapter("fixture", "Fixture", [
    { path: projectFirst, scope: "project" },
    { path: projectSecond, scope: "project" },
    { path: user, scope: "user" },
  ]).adapter;
  const copyOnly = capture();
  await runSetup({
    input: Readable.from([
      "2\n",
      "files\n",
      "stdio\n",
      "node\n",
      "[]\n",
      "\n",
      "\n",
      "1\n",
      "no\n",
    ]),
    output: copyOnly,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { PATH: process.env.PATH },
    adapters: [adapter],
  });
  expect(copyOnly.text().indexOf("Destination:")).toBeLessThan(
    copyOnly.text().indexOf("Select Tools & Policy"),
  );
  expect(copyOnly.text()).toContain("1. Show configuration only");

  const selected = capture();
  await runSetup({
    input: Readable.from([
      "2\n",
      "files\n",
      "stdio\n",
      "node\n",
      "[]\n",
      "\n",
      "2,3\n",
      "2,4\n",
      "1\n",
      "1\n",
      "1\n",
      "1\n",
      "no\n",
    ]),
    output: selected,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { PATH: process.env.PATH },
    adapters: [adapter],
  });
  expect(selected.text()).toContain("Select at most one destination per client and scope.");
  expect(selected.text()).toContain("Select Tools & Policy");
});

test("generated preset selection forces HTTP on 17319 and rejoins the shared Manual flow", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const output = capture();

  await runSetup({
    input: Readable.from([
      "4\n",
      "files\n",
      "stdio\n",
      "node\n",
      "[]\n",
      "\n",
      "2\n",
      "1,2,3\n",
      "1\n",
      "1\n",
      "1\n",
      "1\n",
      "1\n",
      "no\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { PATH: process.env.PATH },
  });

  const text = output.text();
  const ordered = [
    "Destination:",
    "Generate client presets",
    "Generated client presets:",
    "OpenCode format:",
    "17319 (default)",
    "Tools & Policy — Claude Code / user",
    "Tools & Policy — Codex / user",
    "Tools & Policy — OpenCode / user",
    "Connect to this upstream?",
  ].map((label) => text.indexOf(label));
  expect(ordered).not.toContain(-1);
  expect(ordered).toEqual([...ordered].sort((left, right) => left - right));
  expect(text).toContain("Generated client presets:\n1. Claude Code\n2. Codex\n3. OpenCode\n");
  expect(text).toContain("OpenCode format:\n1. Current (V2)\n2. Legacy (V1)\n");
  expect(text).not.toContain("Client connection —");
  expect(text).toContain("Setup cancelled.");
  await expect(readFile(join(home, ".mcp-restrictor"), "utf8")).rejects.toMatchObject({
    code: "ENOENT",
  });
});

test("generated preset Apply creates private managed artifacts and an installer-rendered fragment", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const output = capture();
  const source = {
    kind: "stdio" as const,
    command: process.execPath,
    args: [simpleUpstream],
    envNames: [],
  };
  setupManualFakes.discover = async () => ({
    tools: ["read_file", "write_file"],
    source,
    upstream: { kind: "stdio", command: process.execPath, args: [simpleUpstream] },
  });

  await runSetup({
    input: Readable.from([
      "4\n",
      "files\n",
      "stdio\n",
      `${process.execPath}\n`,
      `${JSON.stringify([simpleUpstream])}\n`,
      "\n",
      "2\n",
      "1\n",
      "1\n",
      "1\n",
      "yes\n",
      "1\n",
      "1\n",
      "yes\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { PATH: process.env.PATH, SECRET_SENTINEL: "must-not-leak" },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  const configPath = generatedConfigPath(home, "claude");
  const policyPath = generatedPolicyLocation({
    home,
    adapterId: "claude",
    serverName: "files",
  }).diskPath;
  const config = await readFile(configPath, "utf8");
  expect(JSON.parse(config).mcpServers.files).toEqual({
    type: "http",
    url: expect.stringMatching(/^http:\/\/127\.0\.0\.1:17319\/mcp\/claude\/[0-9a-f]{64}$/),
  });
  expect(output.text()).toContain('Client preset fragment — Claude Code / "files":');
  expect(output.text()).toContain(config);
  expect(output.text()).toContain("Merge this entry into the host client configuration");
  for (const path of [dirname(configPath), dirname(policyPath)]) {
    expect((await stat(path)).mode & 0o7777).toBe(0o700);
  }
  for (const path of [configPath, policyPath]) {
    expect((await stat(path)).mode & 0o7777).toBe(0o600);
  }
  const artifacts = `${output.text()}\n${config}\n${await readFile(policyPath, "utf8")}`;
  expect(artifacts).not.toContain("must-not-leak");
});

test("generated presets exclude external adapters and built-ins with a real destination", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const claudePath = join(root, ".mcp.json");
  await writeFile(claudePath, '{"mcpServers": {}}\n');
  const external = destinationAdapter("external", "External", []).adapter;

  const result = await discoverManualDestinations({
    adapters: [external, claudeAdapter, codexAdapter, opencodeAdapter],
    context: { home, projectRoot: root, cwd: root, environment: {} },
    serverName: "files",
    restrictorHome: join(home, ".mcp-restrictor"),
  });

  expect(result.generated.map(({ adapter }) => adapter.id)).toEqual(["codex", "opencode"]);
  expect(result.available.map(({ adapter }) => adapter.id)).toEqual(["claude"]);
});

test("orders client connection, one HTTP gateway choice, and independent policy choices before Connect", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const alphaPath = join(root, "alpha.json");
  const betaPath = join(home, "beta.json");
  await mkdir(home, { recursive: true });
  await Promise.all([alphaPath, betaPath].map((path) => writeFile(path, "{}\n")));
  const alpha = destinationAdapter(
    "alpha",
    "Alpha",
    [{ path: alphaPath, scope: "project" }],
    [],
    true,
  ).adapter;
  const beta = destinationAdapter(
    "beta",
    "Beta",
    [{ path: betaPath, scope: "user" }],
    [],
    true,
  ).adapter;
  const output = capture();

  await runSetup({
    input: Readable.from([
      "3\n",
      "files\n",
      "stdio\n",
      "node\n",
      "[]\n",
      "\n",
      "2,3\n",
      "1\n",
      "2\n",
      "1\n",
      "1\n",
      "1\n",
      "no\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { PATH: process.env.PATH },
    adapters: [alpha, beta],
  });

  const text = output.text();
  const ordered = [
    "Destination:",
    "Client connection — Alpha / project",
    "Client connection — Beta / user",
    "HTTP gateway port",
    "Tools & Policy — Alpha / project",
    "Tools & Policy — Beta / user",
    "Connect to this upstream?",
  ].map((label) => text.indexOf(label));
  expect(ordered).not.toContain(-1);
  expect(ordered).toEqual([...ordered].sort((left, right) => left - right));
  expect(text.match(/HTTP gateway port:\n/g)).toHaveLength(1);
  expect(await readFile(alphaPath, "utf8")).toBe("{}\n");
  expect(await readFile(betaPath, "utf8")).toBe("{}\n");
  await expect(readFile(join(home, ".mcp-restrictor", "routes"), "utf8")).rejects.toThrow();
});

test("reuses the existing HTTP gateway origin without a port prompt", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const configPath = join(root, "client.json");
  await writeFile(configPath, "{}\n");
  const adapter = destinationAdapter(
    "fixture",
    "Fixture",
    [{ path: configPath, scope: "project" }],
    [],
    true,
  ).adapter;
  const owner = {
    adapterId: "fixture",
    scope: "user" as const,
    configPath: resolve(join(home, "other.json")),
    projectRoot: resolve(root),
    serverName: "other",
  };
  const path = routePath(home, owner);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await chmod(dirname(path), 0o700);
  await writeFile(
    path,
    serializeRoute({
      version: 1,
      owner,
      listenUrl: routeUrl(8123, owner),
      proxyArgs: [
        "--policy",
        resolve(join(root, "other.yaml")),
        "--upstream-http",
        "https://example.test/mcp",
      ],
      environment: { set: {} },
    }),
    { mode: 0o600 },
  );
  await chmod(path, 0o600);
  const output = capture();

  await runSetup({
    input: Readable.from([
      "2\n",
      "files\n",
      "stdio\n",
      "node\n",
      "[]\n",
      "\n",
      "2\n",
      "2\n",
      "1\n",
      "no\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home,
    environment: { PATH: process.env.PATH },
    adapters: [adapter],
  });

  expect(output.text()).not.toContain("HTTP gateway port:\n");
  expect(output.text()).toContain("Connect to this upstream?");
  expect(await readFile(path, "utf8")).toContain("127.0.0.1:8123");
});

test("offers only STDIO when a destination adapter has no HTTP install hook", async () => {
  const root = await temporaryDirectory();
  const configPath = join(root, "client.json");
  await writeFile(configPath, "{}\n");
  const adapter = destinationAdapter("fixture", "Fixture", [
    { path: configPath, scope: "project" },
  ]).adapter;
  const output = capture();

  await runSetup({
    input: Readable.from([
      "2\n",
      "files\n",
      "stdio\n",
      "node\n",
      "[]\n",
      "\n",
      "2\n",
      "1\n",
      "1\n",
      "no\n",
    ]),
    output,
    error: capture(),
    interactive: true,
    cwd: root,
    home: join(root, "home"),
    environment: { PATH: process.env.PATH },
    adapters: [adapter],
  });

  expect(output.text()).toContain("1. STDIO — client starts Restrictor");
  expect(output.text()).not.toContain("HTTP — connects through mcp-restrictor run");
  expect(output.text()).not.toContain("HTTP gateway port:");
});

test("rejects mismatched managed route origins before Connect", async () => {
  const root = await temporaryDirectory();
  const home = join(root, "home");
  const configPath = join(root, "client.json");
  await writeFile(configPath, "{}\n");
  const adapter = destinationAdapter(
    "fixture",
    "Fixture",
    [{ path: configPath, scope: "project" }],
    [],
    true,
  ).adapter;
  for (const [index, port] of [7319, 8123].entries()) {
    const owner = {
      adapterId: "fixture",
      scope: "user" as const,
      configPath: resolve(join(home, `other-${index}.json`)),
      projectRoot: resolve(root),
      serverName: `other-${index}`,
    };
    const path = routePath(home, owner);
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    await chmod(dirname(path), 0o700);
    await writeFile(
      path,
      serializeRoute({
        version: 1,
        owner,
        listenUrl: routeUrl(port, owner),
        proxyArgs: [
          "--policy",
          resolve(join(root, `other-${index}.yaml`)),
          "--upstream-http",
          "https://example.test/mcp",
        ],
        environment: { set: {} },
      }),
      { mode: 0o600 },
    );
    await chmod(path, 0o600);
  }
  const output = capture();

  await expect(
    runSetup({
      input: Readable.from(["2\n", "files\n", "stdio\n", "node\n", "[]\n", "\n", "2\n", "2\n"]),
      output,
      error: capture(),
      interactive: true,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH },
      adapters: [adapter],
    }),
  ).rejects.toThrow("Invalid managed HTTP route");

  expect(output.text()).not.toContain("Connect to this upstream?");
});

test("Manual chooses saved Tools & Policy before Connect", async () => {
  const root = await temporaryDirectory();
  const savedDirectory = join(root, ".mcp-restrictor", "saved-policies", "manual", "files.d");
  const savedPath = join(savedDirectory, "read-only.yaml");
  const policyPath = join(root, ".mcp-restrictor", "policies", "manual", "files.yaml");
  const exactPolicy =
    "# preserve these bytes\nversion: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n  deny: []\n";
  await mkdir(savedDirectory, { recursive: true, mode: 0o700 });
  await chmod(savedDirectory, 0o700);
  await writeFile(savedPath, exactPolicy, { mode: 0o600 });
  await chmod(savedPath, 0o600);
  const output = capture();

  await runSetup({
    input: Readable.from([
      "4\n",
      "files\n",
      "stdio\n",
      `${process.execPath}\n`,
      `${JSON.stringify([upstream, projectRoot])}\n`,
      "API_KEY\n",
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
    environment: { PATH: process.env.PATH, API_KEY: "secret" },
    restrictor: { command: process.execPath, argsPrefix: [cli] },
  });

  expect(output.text().indexOf("Select Tools & Policy")).toBeLessThan(
    output.text().indexOf("Connect to this upstream?"),
  );
  expect(await readFile(policyPath, "utf8")).toBe(exactPolicy);
});

function inkManual(values: readonly string[], selections: readonly number[]) {
  const remainingValues = [...values];
  const remainingSelections = [...selections];
  const validationErrors: string[] = [];
  const interaction = {
    usesTui: true,
    ask: vi.fn(async () => {
      throw new Error("Ink Manual must not use ask");
    }),
    readText: vi.fn(
      async (
        _message: string,
        options: {
          trim?: boolean;
          validate?: (value: string) => string | undefined;
        } = {},
      ) => {
        for (;;) {
          const value = remainingValues.shift();
          if (value === undefined) throw new Error("missing Ink Manual text value");
          const normalized = options.trim === false ? value : value.trim();
          const validationError = options.validate?.(normalized);
          if (!validationError) return normalized;
          validationErrors.push(validationError);
        }
      },
    ),
    selectIndexes: vi.fn(
      async (
        _message: string,
        _choices: readonly string[],
        _options: { allowNone: boolean; single?: boolean },
      ) => {
        const index = remainingSelections.shift();
        if (index === undefined) throw new Error("missing Ink Manual selection");
        return [index];
      },
    ),
    write: vi.fn(),
  };
  return { interaction, remainingSelections, remainingValues, validationErrors };
}

function lineManual(...values: string[]) {
  const ask = answers(...values);
  return {
    usesTui: false,
    ask,
    readText: (question: string) => ask(question),
    selectIndexes: async () => {
      throw new Error("line Manual candidate collection must not select indexes");
    },
    write: () => {},
  };
}

test("Ink Manual preserves exact STDIO arguments and repeated environment names", async () => {
  const { interaction, remainingSelections, remainingValues } = inkManual(
    ["files", process.execPath, "", "  spaced  ", "API_KEY", "PATH", "API_KEY"],
    [0, 1, 1, 0, 1, 1, 1, 0],
  );

  const candidate = await promptManualCandidate({ interaction });

  expect(candidate).toEqual({
    name: "files",
    source: {
      kind: "stdio",
      command: process.execPath,
      args: ["", "  spaced  "],
      envNames: ["API_KEY", "PATH", "API_KEY"],
    },
  });
  expect(interaction.ask).not.toHaveBeenCalled();
  expect(interaction.readText.mock.calls.filter(([message]) => message === "Argument")).toEqual([
    ["Argument", { trim: false }],
    ["Argument", { trim: false }],
  ]);
  expect(remainingValues).toEqual([]);
  expect(remainingSelections).toEqual([]);
});

test("Ink Manual collects HTTP headers on separate screens and selects None authentication", async () => {
  const { interaction } = inkManual(
    ["remote", "https://example.test/mcp", "X-Key", "API_KEY", "X-Tenant", "TENANT"],
    [1, 1, 1, 0, 0],
  );

  await expect(promptManualCandidate({ interaction })).resolves.toEqual({
    name: "remote",
    source: {
      kind: "http",
      url: "https://example.test/mcp",
      headers: [
        { name: "X-Key", environmentVariable: "API_KEY" },
        { name: "X-Tenant", environmentVariable: "TENANT" },
      ],
    },
  });
  expect(interaction.readText.mock.calls.map(([message]) => message)).toEqual([
    "Server name",
    "Upstream URL",
    "Header name",
    "Environment variable",
    "Header name",
    "Environment variable",
  ]);
});

test("Ink Manual retries an invalid upstream URL on the same screen", async () => {
  const { interaction, validationErrors } = inkManual(
    ["remote", "not a URL", "https://example.test/mcp"],
    [1, 0, 0],
  );

  await expect(promptManualCandidate({ interaction })).resolves.toEqual({
    name: "remote",
    source: { kind: "http", url: "https://example.test/mcp", headers: [] },
  });
  expect(validationErrors).toEqual(["Enter a valid upstream URL."]);
  expect(validationErrors.join("\n")).not.toContain("not a URL");
  expect(interaction.write).not.toHaveBeenCalled();
});

test.each([
  {
    name: "HTTP header",
    values: [
      "header",
      "http://example.test/mcp",
      "X-Key",
      "API_KEY",
      "http://example.test/mcp",
      "https://example.test/mcp",
    ],
    selections: [1, 1, 0, 0],
    expected: {
      name: "header",
      source: {
        kind: "http",
        url: "https://example.test/mcp",
        headers: [{ name: "X-Key", environmentVariable: "API_KEY" }],
      },
    },
    lastPrompt: "Upstream URL",
  },
  {
    name: "HTTP Bearer",
    values: [
      "bearer",
      "http://example.test/mcp",
      "http://example.test/mcp",
      "https://example.test/mcp",
      "TOKEN",
    ],
    selections: [1, 0, 1],
    expected: {
      name: "bearer",
      source: {
        kind: "http",
        url: "https://example.test/mcp",
        headers: [],
        bearerTokenEnvVar: "TOKEN",
      },
    },
    lastPrompt: "Bearer token environment variable",
  },
  {
    name: "WebSocket header",
    values: [
      "socket",
      "ws://example.test/mcp",
      "X-Key",
      "API_KEY",
      "ws://example.test/mcp",
      "wss://example.test/mcp",
    ],
    selections: [3, 1, 0],
    expected: {
      name: "socket",
      source: {
        kind: "websocket",
        url: "wss://example.test/mcp",
        headers: [{ name: "X-Key", environmentVariable: "API_KEY" }],
      },
    },
    lastPrompt: "Upstream URL",
  },
] as const)("Ink Manual revisits an insecure $name URL after cross-field choices", async (row) => {
  const { interaction, validationErrors } = inkManual(row.values, row.selections);

  await expect(promptManualCandidate({ interaction })).resolves.toEqual(row.expected);
  const prompts = interaction.readText.mock.calls.map(([message]) => message);
  expect(prompts.filter((message) => message === "Upstream URL")).toHaveLength(2);
  expect(prompts.at(-1)).toBe(row.lastPrompt);
  expect(validationErrors).toEqual(["Enter a valid upstream URL."]);
  expect(validationErrors.join("\n")).not.toMatch(/example\.test|X-Key|API_KEY/);
});

test.each([
  {
    name: "resource",
    optionalIndex: 2,
    invalid: "relative",
    valid: "urn:example:resource",
    error: "Enter a valid absolute URL.",
    expected: { resource: "urn:example:resource" },
  },
  {
    name: "resource metadata",
    optionalIndex: 3,
    invalid: "http://metadata.example.test/resource",
    valid: "https://metadata.example.test/resource",
    error: "Enter a secure OAuth URL.",
    expected: { resourceMetadataUrl: "https://metadata.example.test/resource" },
  },
  {
    name: "authorization metadata",
    optionalIndex: 4,
    invalid: "http://auth.example.test/metadata",
    valid: "https://auth.example.test/metadata",
    error: "Enter a secure OAuth URL.",
    expected: { authServerMetadataUrl: "https://auth.example.test/metadata" },
  },
  {
    name: "callback base",
    optionalIndex: 6,
    invalid: "http://127.0.0.1:43123/callback?state=fixed",
    valid: "http://127.0.0.1:43123/callback?tenant=one",
    error: "Enter a valid OAuth callback URL.",
    expected: {
      callback: {
        url: "http://127.0.0.1:43123/callback?tenant=one",
        appendProfileId: true,
      },
    },
  },
] as const)("Ink Manual retries an invalid custom OAuth $name URL", async (row) => {
  const selections = [2, 0, 2, 0, 0, 0, 0, 0, 0, 0];
  selections[3 + row.optionalIndex] = 1;
  const { interaction, validationErrors } = inkManual(
    ["oauth", "https://example.test/events", row.invalid, row.valid],
    selections,
  );

  const candidate = await promptManualCandidate({ interaction });

  expect(candidate.oauth).toMatchObject(row.expected);
  expect(validationErrors).toEqual([row.error]);
  expect(validationErrors.join("\n")).not.toContain(row.invalid);
});

test("Ink Manual collects custom SSE OAuth values and retries an invalid callback port", async () => {
  const { interaction } = inkManual(
    [
      "oauth",
      "https://example.test/events",
      "client-id",
      "read write",
      "https://resource.example.test/",
      "https://resource.example.test/.well-known/oauth-protected-resource",
      "https://auth.example.test/.well-known/oauth-authorization-server",
      "not-a-port",
      "43123",
      "http://127.0.0.1:43123/callback",
    ],
    [2, 0, 2, 1, 1, 1, 1, 1, 1, 1],
  );

  const candidate = await promptManualCandidate({ interaction });

  expect(candidate).toEqual({
    name: "oauth",
    source: { kind: "sse", url: "https://example.test/events", headers: [] },
    oauth: {
      mode: "explicit",
      clientId: "client-id",
      requestedScope: "read write",
      resource: "https://resource.example.test/",
      resourceMetadataUrl: "https://resource.example.test/.well-known/oauth-protected-resource",
      authServerMetadataUrl: "https://auth.example.test/.well-known/oauth-authorization-server",
      callback: {
        url: "http://127.0.0.1:43123/callback",
        port: 43123,
        appendProfileId: true,
      },
    },
  });
  expect(
    interaction.readText.mock.calls.filter(([message]) => message === "OAuth callback port"),
  ).toHaveLength(1);
});

test("Ink Manual defaults omit optional OAuth values", async () => {
  const { interaction } = inkManual(
    ["oauth", "https://example.test/events"],
    [2, 0, 2, 0, 0, 0, 0, 0, 0, 0],
  );

  await expect(promptManualCandidate({ interaction })).resolves.toEqual({
    name: "oauth",
    source: { kind: "sse", url: "https://example.test/events", headers: [] },
    oauth: {
      mode: "explicit",
      callback: {
        host: "127.0.0.1",
        path: "/callback",
        appendProfileId: true,
      },
    },
  });
});

test("Ink Manual WebSocket maps Authorization without asking for authentication", async () => {
  const { interaction } = inkManual(
    ["socket", "wss://example.test/mcp", "Authorization", "AUTHORIZATION"],
    [3, 1, 0],
  );

  await expect(promptManualCandidate({ interaction })).resolves.toEqual({
    name: "socket",
    source: {
      kind: "websocket",
      url: "wss://example.test/mcp",
      headers: [{ name: "Authorization", environmentVariable: "AUTHORIZATION" }],
    },
  });
  expect(interaction.selectIndexes.mock.calls.map(([message]) => message)).not.toContain(
    "Authentication",
  );
});

test.each([
  {
    name: "Authorization",
    header: "Authorization",
    environmentVariable: "AUTH_SECRET_ENV",
    choices: ["None"],
    explanation: "An Authorization header mapping is already configured; only None is available.\n",
  },
  {
    name: "master key",
    header: "X-Key",
    environmentVariable: MASTER_KEY_FILE_ENV.toLowerCase(),
    choices: ["None", "Bearer"],
    explanation: "A master-key header mapping is already configured; OAuth is unavailable.\n",
  },
] as const)("Ink Manual filters $name authentication conflicts before render", async (row) => {
  const { interaction } = inkManual(
    ["remote", "https://example.test/mcp", row.header, row.environmentVariable],
    [1, 1, 0, 0],
  );

  await promptManualCandidate({ interaction });

  const authenticationCall = interaction.selectIndexes.mock.calls.findIndex(
    ([message]) => message === "Authentication",
  );
  expect(interaction.selectIndexes.mock.calls[authenticationCall]?.[1]).toEqual(row.choices);
  expect(interaction.write).toHaveBeenCalledWith(row.explanation);
  expect(interaction.write.mock.invocationCallOrder[0]).toBeLessThan(
    interaction.selectIndexes.mock.invocationCallOrder[authenticationCall]!,
  );
  expect(interaction.write.mock.calls.flat().join("\n")).not.toContain(row.environmentVariable);
});

test("builds a pure STDIO candidate from a JSON argument array", async () => {
  const candidate = await promptManualCandidate({
    interaction: lineManual(
      "files",
      "stdio",
      process.execPath,
      '["fixture.mjs","two words"]',
      "API_KEY,PATH,API_KEY",
    ),
  });

  expect(candidate).toEqual({
    name: "files",
    source: {
      kind: "stdio",
      command: process.execPath,
      args: ["fixture.mjs", "two words"],
      envNames: ["API_KEY", "PATH", "API_KEY"],
    },
  });
  expect(resolveManualUpstream(candidate, { API_KEY: "secret", PATH: "/bin" })).toMatchObject({
    env: { API_KEY: "secret", PATH: "/bin" },
  });
});

test.each([
  ["http", "https://example.test/mcp"],
  ["sse", "https://example.test/events"],
  ["websocket", "wss://example.test/mcp"],
] as const)("builds a pure %s candidate with repeatable header selectors", async (kind, url) => {
  const candidate = await promptManualCandidate({
    interaction: lineManual("remote", kind, url, "X-Key=API_KEY", "X-Tenant=TENANT", "", "none"),
  });

  expect(candidate).toEqual({
    name: "remote",
    source: {
      kind,
      url,
      headers: [
        { name: "X-Key", environmentVariable: "API_KEY" },
        { name: "X-Tenant", environmentVariable: "TENANT" },
      ],
    },
  });
});

test("collects bearer and OAuth selectors without reading their values", async () => {
  const bearer = await promptManualCandidate({
    interaction: lineManual("bearer", "http", "https://example.test/mcp", "", "bearer", "TOKEN"),
  });
  const oauth = await promptManualCandidate({
    interaction: lineManual(
      "oauth",
      "sse",
      "https://example.test/events",
      "",
      "oauth",
      "client-id",
      "read write",
      "https://resource.example.test/",
      "https://resource.example.test/.well-known/oauth-protected-resource",
      "https://auth.example.test/.well-known/oauth-authorization-server",
      "43123",
      "http://127.0.0.1:43123/callback",
    ),
  });

  expect(bearer.source).toMatchObject({ bearerTokenEnvVar: "TOKEN" });
  expect(oauth.oauth).toEqual({
    mode: "explicit",
    clientId: "client-id",
    requestedScope: "read write",
    resource: "https://resource.example.test/",
    resourceMetadataUrl: "https://resource.example.test/.well-known/oauth-protected-resource",
    authServerMetadataUrl: "https://auth.example.test/.well-known/oauth-authorization-server",
    callback: {
      url: "http://127.0.0.1:43123/callback",
      port: 43123,
      appendProfileId: true,
    },
  });
});

test.each([
  ["malformed JSON args", ["name", "stdio", "node", "not-json", ""], /JSON array/i],
  ["non-string JSON args", ["name", "stdio", "node", "[1]", ""], /JSON array/i],
  [
    "unsafe remote URL",
    ["name", "http", "https://example.test/mcp?secret=x", "", "none"],
    /upstream/i,
  ],
  [
    "literal header value",
    ["name", "http", "https://example.test/mcp", "X-Key=literal-value", "", "none"],
    /header/i,
  ],
  [
    "duplicate header",
    ["name", "http", "https://example.test/mcp", "X-Key=ONE", "x-key=TWO", "", "none"],
    /duplicate/i,
  ],
  ["bearer WebSocket", ["name", "websocket", "wss://example.test/mcp", "", "bearer"], /WebSocket/i],
  ["OAuth WebSocket", ["name", "websocket", "wss://example.test/mcp", "", "oauth"], /WebSocket/i],
  [
    "mixed Authorization and bearer",
    ["name", "http", "https://example.test/mcp", "Authorization=AUTH", "", "bearer", "TOKEN"],
    /conflicting/i,
  ],
  [
    "OAuth master-key header selector",
    [
      "name",
      "http",
      "https://example.test/mcp",
      `X-Key=${MASTER_KEY_FILE_ENV.toLowerCase()}`,
      "",
      "oauth",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
    ],
    /master key/i,
  ],
] as const)("rejects pure manual input: %s", async (_case, values, message) => {
  await expect(
    promptManualCandidate({
      interaction: lineManual(...values),
    }),
  ).rejects.toThrow(message);
});

test("uses Authorization as an ordinary WebSocket header selector", async () => {
  const candidate = await promptManualCandidate({
    interaction: lineManual(
      "socket",
      "websocket",
      "wss://example.test/mcp",
      "Authorization=AUTHORIZATION",
      "",
      "none",
    ),
  });
  const upstream = resolveManualUpstream(candidate, {
    AUTHORIZATION: "Basic complete-credential",
  });

  expect(upstream).toEqual({
    kind: "websocket",
    url: "wss://example.test/mcp",
    headers: [["Authorization", "Basic complete-credential"]],
  });
});

test("resolves selected environment values only at the explicit resolution boundary", async () => {
  const candidate = await promptManualCandidate({
    interaction: lineManual(
      "remote",
      "http",
      "https://example.test/mcp",
      "X-Key=API_KEY",
      "",
      "bearer",
      "TOKEN",
    ),
  });
  let reads = 0;
  const environment = new Proxy(Object.create(null) as NodeJS.ProcessEnv, {
    getOwnPropertyDescriptor(_target, property) {
      reads += 1;
      if (property === "API_KEY") return descriptor("header-secret");
      if (property === "TOKEN") return descriptor("bearer-secret");
      return undefined;
    },
    get(_target, property) {
      reads += 1;
      if (property === "API_KEY") return "header-secret";
      if (property === "TOKEN") return "bearer-secret";
      return undefined;
    },
  });

  expect(reads).toBe(0);
  expect(resolveManualUpstream(candidate, environment)).toEqual({
    kind: "http",
    url: "https://example.test/mcp",
    headers: [["X-Key", "header-secret"]],
    bearerToken: "bearer-secret",
  });
  expect(reads).toBeGreaterThan(0);
  expect(() => resolveManualUpstream(candidate, {})).toThrow(/API_KEY|TOKEN/);
});

test.each([
  [
    "STDIO inherited env",
    () =>
      ({
        name: "files",
        source: {
          kind: "stdio",
          command: "node",
          args: ["server.mjs"],
          envNames: ["MCP_RESTRICTOR_CONTAINER"],
        },
      }) satisfies ManualCandidate,
  ],
  [
    "header env mapping",
    () =>
      ({
        name: "remote",
        source: {
          kind: "http",
          url: "https://example.test/mcp",
          headers: [{ name: "X-Key", environmentVariable: "MCP_RESTRICTOR_CONTAINER" }],
        },
      }) satisfies ManualCandidate,
  ],
  [
    "bearer env name",
    () =>
      ({
        name: "remote",
        source: {
          kind: "http",
          url: "https://example.test/mcp",
          headers: [],
          bearerTokenEnvVar: "MCP_RESTRICTOR_CONTAINER",
        },
      }) satisfies ManualCandidate,
  ],
] as const)(
  "rejects the reserved container marker before Manual resolution: %s",
  (_case, candidate) => {
    let reads = 0;
    const environment = new Proxy(Object.create(null) as NodeJS.ProcessEnv, {
      getOwnPropertyDescriptor() {
        reads += 1;
        return descriptor("marker-value");
      },
      get() {
        reads += 1;
        return "marker-value";
      },
    });

    expect(() => resolveManualUpstream(candidate(), environment)).toThrow(
      /reserved upstream environment/i,
    );
    expect(reads).toBe(0);
  },
);

test("plans the exact manual policy and JSON-safe wrapper without secret values", async () => {
  const root = "/project";
  const candidate: ManualCandidate = {
    name: "spaces/and ? marks",
    source: {
      kind: "sse",
      url: "https://example.test/events",
      headers: [{ name: "X-Key", environmentVariable: "API_KEY" }],
      bearerTokenEnvVar: "TOKEN",
    },
  };
  const planned = planManualWrapper({
    candidate,
    allowedTools: ["read_file"],
    projectRoot: root,
    restrictor: { command: "/absolute/mcp-restrictor", argsPrefix: [] },
    upstream: {
      kind: "sse",
      url: "https://example.test/events",
      headers: [["X-Key", "header-secret"]],
      bearerToken: "bearer-secret",
    },
  });

  expect(planned.policyPath).toBe(
    join(root, ".mcp-restrictor", "policies", "manual", "spaces%2Fand%20%3F%20marks.yaml"),
  );
  expect(planned.command).toBe("/absolute/mcp-restrictor");
  expect(planned.args).toEqual([
    "--policy",
    planned.policyPath,
    "--upstream-sse",
    "https://example.test/events",
    "--upstream-header-env",
    "X-Key=API_KEY",
    "--upstream-bearer-token-env",
    "TOKEN",
  ]);
  expect(planned.policySource).toContain("name: read_file");
  expect(JSON.stringify({ args: planned.args, policy: planned.policySource })).not.toContain(
    "header-secret",
  );
  expect(JSON.stringify({ args: planned.args, policy: planned.policySource })).not.toContain(
    "bearer-secret",
  );
  expect(planned.verificationUpstream).toMatchObject({
    kind: "stdio",
    env: { API_KEY: "header-secret", TOKEN: "bearer-secret" },
  });
});

test("plans one installed Manual destination with names-only client environment", () => {
  const policySource =
    "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n  deny: []\n";
  const planned = planManualDestinationWrapper({
    candidate: {
      name: "files",
      source: {
        kind: "sse",
        url: "https://example.test/events",
        headers: [{ name: "X-Key", environmentVariable: "API_KEY" }],
      },
    },
    client: "codex",
    scope: "project",
    configPath: "/project/.codex/config.toml",
    allowedTools: ["read_file"],
    policy: {
      diskPath: "/project/.mcp-restrictor/policies/codex/files.yaml",
      argument: ".mcp-restrictor/policies/codex/files.yaml",
    },
    restrictor: { command: "/absolute/mcp-restrictor", argsPrefix: [] },
    upstream: {
      kind: "sse",
      url: "https://example.test/events",
      headers: [["X-Key", "header-secret"]],
    },
    oauthProfileId: "00000000-0000-4000-8000-000000000000",
    fixedEnvironment: { [MASTER_KEY_FILE_ENV]: "/keys/master" },
    inheritedEnvironment: ["API_KEY"],
    wrapperCwd: "/project",
    policySource,
  });

  expect(planned.entry).toEqual({
    name: "files",
    command: "/absolute/mcp-restrictor",
    args: [
      "--policy",
      ".mcp-restrictor/policies/codex/files.yaml",
      "--upstream-sse",
      "https://example.test/events",
      "--upstream-header-env",
      "X-Key=API_KEY",
      "--upstream-oauth-profile",
      "00000000-0000-4000-8000-000000000000",
    ],
    cwd: "/project",
    environment: {
      inherit: ["API_KEY"],
      set: { [MASTER_KEY_FILE_ENV]: "/keys/master" },
    },
  });
  expect(planned.policySource).toBe(policySource);
  expect(planned.server).toMatchObject({
    client: "codex",
    scope: "project",
    configPath: "/project/.codex/config.toml",
    source: { kind: "sse", oauthProfileId: "00000000-0000-4000-8000-000000000000" },
  });
  expect(planned.verificationUpstream).toEqual({
    kind: "stdio",
    command: "/absolute/mcp-restrictor",
    args: [
      "--policy",
      "/project/.mcp-restrictor/policies/codex/files.yaml",
      "--upstream-sse",
      "https://example.test/events",
      "--upstream-header-env",
      "X-Key=API_KEY",
      "--upstream-oauth-profile",
      "00000000-0000-4000-8000-000000000000",
    ],
    env: {
      [MASTER_KEY_FILE_ENV]: "/keys/master",
      API_KEY: "header-secret",
    },
    cwd: "/project",
  });
  expect(JSON.stringify(planned.entry)).not.toContain("header-secret");
});

test("plans an HTTP gateway client connection with an independent policy and canonical route", () => {
  const planned = planManualDestinationHttpRoute({
    candidate: {
      name: "files",
      source: {
        kind: "stdio",
        command: "/usr/bin/node",
        args: ["server.mjs"],
        envNames: ["API_KEY"],
      },
    },
    client: "codex",
    scope: "project",
    configPath: "/project/.codex/config.toml",
    projectRoot: "/project",
    allowedTools: ["read_file"],
    policy: { diskPath: "/project/.mcp-restrictor/policies/codex/files.yaml" },
    restrictor: { command: "/absolute/mcp-restrictor", argsPrefix: [] },
    upstream: {
      kind: "stdio",
      command: "/usr/bin/node",
      args: ["server.mjs"],
      env: { API_KEY: "resolved-secret" },
    },
    inheritedEnvironment: ["API_KEY"],
    port: 7319,
    home: "/home/tester",
    policySource:
      "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n  deny: []\n",
  });

  const routeId = "510948d0823176b35557592f5a4ea07ec55d1940290e44ce22b0f3ca66be7b7d";
  const url = `http://127.0.0.1:7319/mcp/codex/${routeId}`;
  expect(planned.entry).toEqual({ name: "files", url });
  expect(planned.routePath).toBe(`/home/tester/.mcp-restrictor/routes/${routeId}.json`);
  expect(JSON.parse(planned.routeSource)).toEqual({
    version: 1,
    owner: {
      adapterId: "codex",
      scope: "project",
      configPath: "/project/.codex/config.toml",
      projectRoot: "/project",
      serverName: "files",
    },
    listenUrl: url,
    proxyArgs: [
      "--policy",
      "/project/.mcp-restrictor/policies/codex/files.yaml",
      "--upstream-env",
      "API_KEY",
      "--upstream-cwd",
      "/project",
      "--",
      "/usr/bin/node",
      "server.mjs",
    ],
    environment: { set: {} },
  });
  expect(JSON.stringify({ entry: planned.entry, routeSource: planned.routeSource })).not.toContain(
    "resolved-secret",
  );
});

test("generated HTTP ownership stays home-scoped while relative STDIO uses the setup root", () => {
  const home = "/home/tester";
  const projectRoot = "/workspace";
  const configPath = generatedConfigPath(home, "codex");
  const owner: RouteOwner = {
    adapterId: "codex",
    scope: "user",
    configPath,
    projectRoot: home,
    serverName: "files",
  };
  const planned = planManualDestinationHttpRoute({
    candidate: {
      name: "files",
      source: { kind: "stdio", command: "node", args: ["server.mjs"], envNames: [] },
    },
    client: "codex",
    scope: "user",
    configPath,
    projectRoot,
    ownerProjectRoot: home,
    allowedTools: ["read_file"],
    policy: {
      diskPath: generatedPolicyLocation({ home, adapterId: "codex", serverName: "files" }).diskPath,
    },
    restrictor: { command: "/absolute/mcp-restrictor", argsPrefix: [] },
    upstream: { kind: "stdio", command: "node", args: ["server.mjs"] },
    inheritedEnvironment: [],
    port: 17319,
    home,
  });

  expect(planned.entry.url).toBe(routeUrl(17319, owner));
  expect(JSON.parse(planned.routeSource)).toMatchObject({
    owner,
    proxyArgs: expect.arrayContaining(["--upstream-cwd", projectRoot]),
  });
});

test("validates Manual destinations through the shared wrapper planner", () => {
  expect(() =>
    planManualDestinationWrapper({
      candidate: {
        name: "files",
        source: { kind: "sse", url: "https://example.test/events", headers: [] },
      },
      client: "codex",
      scope: "project",
      configPath: "/project/.codex/config.toml",
      allowedTools: ["read_file"],
      policy: {
        diskPath: "/project/.mcp-restrictor/policies/codex/files.yaml",
        argument: ".mcp-restrictor/policies/codex/files.yaml",
      },
      restrictor: { command: "/absolute/mcp-restrictor", argsPrefix: [] },
      upstream: { kind: "sse", url: "https://example.test/events?untrusted=1" },
      inheritedEnvironment: [],
    }),
  ).toThrow("unsafe upstream URL");
});

test.each([
  ["HTTP", "http", "https://example.test/mcp", "--upstream-http"],
  ["SSE", "sse", "https://example.test/events", "--upstream-sse"],
  ["WebSocket", "websocket", "wss://example.test/mcp", "--upstream-websocket"],
] as const)("plans an exact %s wrapper selector", (_label, kind, url, option) => {
  const candidate: ManualCandidate = {
    name: "remote",
    source: { kind, url, headers: [] },
  };
  const planned = planManualWrapper({
    candidate,
    allowedTools: [],
    projectRoot: "/project",
    restrictor: { command: "/absolute/mcp-restrictor", argsPrefix: [] },
    upstream: { kind, url },
  });

  expect(planned.args).toEqual([
    "--policy",
    "/project/.mcp-restrictor/policies/manual/remote.yaml",
    option,
    url,
  ]);
});

function answers(...values: readonly string[]): (question: string) => Promise<string> {
  let index = 0;
  return async () => values[index++] ?? "";
}

function descriptor(value: string): PropertyDescriptor {
  return { value, enumerable: true, configurable: true, writable: true };
}

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-manual-")));
  temporaryDirectories.push(path);
  return path;
}

function capture(): Writable & { text(): string } {
  let contents = "";
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      contents += chunk.toString();
      callback();
    },
  });
  return Object.assign(stream, { text: () => contents });
}

function destinationAdapter(
  id: string,
  label: string,
  configurations: Array<{
    path: string;
    scope: "user" | "project";
    servers?: Array<{ name: string }>;
    unsupported?: Array<{ name: string }>;
  }>,
  adapterUnsupported: Array<{ name: string; scope: "user" | "project"; configPath: string }> = [],
  http = false,
): { adapter: ClientAdapter } {
  return {
    adapter: defineClientAdapter({
      apiVersion: 1,
      id,
      label,
      async load(_context, host) {
        const loaded = await Promise.all(
          configurations.map(async ({ path, scope, servers = [], unsupported = [] }) => {
            const snapshot = await host.readConfig(path);
            if (!snapshot) throw new Error("missing test config");
            return {
              snapshot,
              config: {
                client: id,
                scope,
                path: snapshot.path,
                source: snapshot.content,
                servers: servers.map((server) => ({
                  client: id,
                  scope,
                  name: server.name,
                  configPath: snapshot.path,
                  source: { kind: "stdio" as const, command: "node", args: [], envNames: [] },
                  upstream: { kind: "stdio" as const, command: "node", args: [] },
                  wrapperEnvironment: {},
                  original: {},
                })),
                unsupported: unsupported.map(({ name }) => ({
                  client: id,
                  scope,
                  name,
                  configPath: snapshot.path,
                  reason: "unsupported",
                })),
              },
            };
          }),
        );
        return {
          configurations: loaded,
          unsupported: adapterUnsupported.map(({ name, scope, configPath }) => ({
            client: id,
            scope,
            name,
            configPath,
            reason: "unsupported",
          })),
        };
      },
      render: (config) => config.source,
      install: (config) => `${config.source}\ninstalled`,
      ...(http ? { installHttp: (config) => `${config.source}\ninstalled-http` } : {}),
      restore: (config) => config.source,
    }),
  };
}
