import { mkdtemp, mkdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { expect, test, vi } from "vitest";
import { MASTER_KEY_FILE_ENV } from "../src/oauth/storage.ts";
import {
  claudeConfigPaths,
  claudeAdapter,
  installClaudeConfig,
  installClaudeHttpConfig,
  parseClaudeConfig,
  renderClaudeConfig,
  restoreClaudeConfig,
} from "../src/setup/claude.ts";
import { readSnapshot } from "../src/setup/transaction.ts";
import { planManagedWrapper } from "../src/setup/wrapper.ts";

const options = {
  path: "/home/me/.claude.json",
  scope: "user" as const,
  projectRoot: "/repo",
  environment: {
    NODE: "/usr/bin/node",
    SCRIPT: "server.mjs",
    EMPTY: "",
    TOKEN: "process-secret",
    OTHER: "explicit-secret",
    URL: "https://example.test/mcp",
  },
};

const oauthProfileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const nativeHttpUrl =
  "http://127.0.0.1:7319/mcp/claude/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function manualClaudeEntry(overrides: Record<string, unknown> = {}) {
  return {
    name: "manual",
    command: "mcp-restrictor",
    args: [
      "--policy",
      ".mcp-restrictor/policies/claude/manual.yaml",
      "--upstream-env",
      "TOKEN",
      "--",
      "node",
      "server.mjs",
    ],
    environment: { inherit: ["TOKEN"], set: { FIXED: "fixed-value" } },
    ...overrides,
  };
}

test("parses a Claude configuration without mcpServers as empty", () => {
  expect(
    parseClaudeConfig({ ...options, source: '{"projects":{"/repo":{"trusted":true}}}' }),
  ).toMatchObject({
    servers: [],
    unsupported: [],
  });
});

test.each([
  [
    "absent mcpServers",
    '{"projects":{"/repo":{"trusted":true}}}',
    '{\n  "projects": {\n    "/repo": {\n      "trusted": true\n    }\n  },\n  "mcpServers": {\n    "manual": {\n      "type": "stdio",\n      "command": "mcp-restrictor",\n      "args": [\n        "--policy",\n        ".mcp-restrictor/policies/claude/manual.yaml",\n        "--upstream-env",\n        "TOKEN",\n        "--",\n        "node",\n        "server.mjs"\n      ],\n      "env": {\n        "TOKEN": "${TOKEN}",\n        "FIXED": "fixed-value"\n      }\n    }\n  }\n}\n',
  ],
  [
    "existing mcpServers",
    '{"mcpServers":{"existing":{"command":"node","args":["existing.mjs"]}}}',
    '{\n  "mcpServers": {\n    "existing": {\n      "command": "node",\n      "args": [\n        "existing.mjs"\n      ]\n    },\n    "manual": {\n      "type": "stdio",\n      "command": "mcp-restrictor",\n      "args": [\n        "--policy",\n        ".mcp-restrictor/policies/claude/manual.yaml",\n        "--upstream-env",\n        "TOKEN",\n        "--",\n        "node",\n        "server.mjs"\n      ],\n      "env": {\n        "TOKEN": "${TOKEN}",\n        "FIXED": "fixed-value"\n      }\n    }\n  }\n}\n',
  ],
] as const)("installs a manual Claude wrapper into %s", (_name, source, expected) => {
  const rendered = installClaudeConfig(
    parseClaudeConfig({ ...options, source }),
    manualClaudeEntry(),
  );

  expect(rendered).toBe(expected);
  expect(rendered).not.toContain("process-secret");
  const reparsed = parseClaudeConfig({ ...options, source: rendered });
  expect(reparsed.unsupported).toEqual([]);
  expect(reparsed.servers).toHaveLength(source.includes("existing") ? 2 : 1);
  expect(reparsed.servers.find(({ name }) => name === "manual")).toMatchObject({
    managedPolicyPath: "/repo/.mcp-restrictor/policies/claude/manual.yaml",
    wrapperEnvironment: { env: { TOKEN: "${TOKEN}", FIXED: "fixed-value" } },
  });
});

test("omits a Claude wrapper env when it has no inherited or fixed values", () => {
  const rendered = installClaudeConfig(
    parseClaudeConfig({ ...options, source: "{}" }),
    manualClaudeEntry({
      args: ["--policy", ".mcp-restrictor/policies/claude/manual.yaml", "--", "node"],
      environment: { inherit: [], set: {} },
    }),
  );

  expect(JSON.parse(rendered).mcpServers.manual).toEqual({
    type: "stdio",
    command: "mcp-restrictor",
    args: ["--policy", ".mcp-restrictor/policies/claude/manual.yaml", "--", "node"],
  });
});

test("rejects Claude installation cwd and occupied server names", () => {
  const empty = parseClaudeConfig({ ...options, source: "{}" });
  expect(() => installClaudeConfig(empty, manualClaudeEntry({ cwd: "/repo" }))).toThrow();

  for (const source of [
    '{"mcpServers":{"manual":{"command":"node","args":[]}}}',
    '{"mcpServers":{"manual":{"disabled":true}}}',
  ]) {
    expect(() =>
      installClaudeConfig(parseClaudeConfig({ ...options, source }), manualClaudeEntry()),
    ).toThrow();
  }
});

test("keeps __proto__ Claude server and environment names as own properties", () => {
  const rendered = installClaudeConfig(
    parseClaudeConfig({ ...options, source: "{}" }),
    manualClaudeEntry({
      name: "__proto__",
      args: [
        "--policy",
        ".mcp-restrictor/policies/claude/proto.yaml",
        "--upstream-env",
        "__proto__",
        "--",
        "node",
      ],
      environment: { inherit: ["__proto__"], set: {} },
    }),
  );
  const parsed = JSON.parse(rendered);

  expect(Object.hasOwn(parsed.mcpServers, "__proto__")).toBe(true);
  expect(Object.hasOwn(parsed.mcpServers.__proto__.env, "__proto__")).toBe(true);
  expect(parsed.mcpServers.__proto__.env.__proto__).toBe("${__proto__}");
});

test("exposes manual Claude installation through the adapter", () => {
  expect(claudeAdapter.install).toBe(installClaudeConfig);
});

test.each([
  ["absent container", '{"projects":{"/repo":{"trusted":true}}}'],
  ["existing container", '{"mcpServers":{"existing":{"command":"node","args":[]}}}'],
] as const)("native HTTP install writes the exact Claude entry into an %s", (_name, source) => {
  const rendered = installClaudeHttpConfig(parseClaudeConfig({ ...options, source }), {
    name: "gateway",
    url: nativeHttpUrl,
  });
  const entry = JSON.parse(rendered).mcpServers.gateway;
  const reparsed = parseClaudeConfig({ ...options, source: rendered });
  const candidate = reparsed.servers.find(({ name }) => name === "gateway");

  expect(entry).toEqual({ type: "http", url: nativeHttpUrl });
  expect(candidate?.source).toEqual({ kind: "http", url: nativeHttpUrl, headers: [] });
  expect(candidate).not.toHaveProperty("managedPolicyPath");
  expect(reparsed.unsupported).toEqual([]);
  expect(reparsed.servers).toHaveLength(source.includes("existing") ? 2 : 1);
  expect(JSON.stringify(entry)).not.toMatch(
    /command|policy|env|oauth|profile|upstream|header|authorization/i,
  );
});

test("native HTTP install handles Claude collisions and prototype-like names", () => {
  for (const source of [
    '{"mcpServers":{"gateway":{"type":"http","url":"https://example.test/mcp"}}}',
    '{"mcpServers":{"gateway":{"disabled":true}}}',
  ]) {
    expect(() =>
      installClaudeHttpConfig(parseClaudeConfig({ ...options, source }), {
        name: "gateway",
        url: nativeHttpUrl,
      }),
    ).toThrow("Claude server name already exists");
  }

  const rendered = installClaudeHttpConfig(parseClaudeConfig({ ...options, source: "{}" }), {
    name: "__proto__",
    url: nativeHttpUrl,
  });
  expect(Object.hasOwn(JSON.parse(rendered).mcpServers, "__proto__")).toBe(true);
});

test("native HTTP install is removed by exact created-entry Claude Restore", () => {
  const source = '{"keep":{"value":1},"mcpServers":{"existing":{"command":"node","args":[]}}}';
  const installed = installClaudeHttpConfig(parseClaudeConfig({ ...options, source }), {
    name: "gateway",
    url: nativeHttpUrl,
  });
  const restored = restoreClaudeConfig(
    parseClaudeConfig({ ...options, source: installed }),
    [{ name: "gateway", originalSource: source, installedSource: installed, created: true }],
    { home: "/home/me", projectRoot: "/repo", cwd: "/repo", environment: options.environment },
  );

  expect(restored).toBe(`{
  "keep": {
    "value": 1
  },
  "mcpServers": {
    "existing": {
      "command": "node",
      "args": []
    }
  }
}\n`);
});

test("delegates Claude configuration loading, rendering, and completion to the existing parser", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-claude-adapter-")));
  const home = join(root, "home");
  const projectRoot = join(root, "project");
  const path = join(home, ".claude.json");
  const source = JSON.stringify({
    mcpServers: { files: { command: "node", args: ["server.mjs"] } },
  });
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, source);
  const host = {
    readConfig: vi.fn((configPath: string) => readSnapshot(configPath)),
    readSecretFile: vi.fn(),
  };

  try {
    const result = await claudeAdapter.load(
      { home, projectRoot, cwd: projectRoot, environment: {} },
      host,
    );
    const config = result.configurations[0]!.config;
    const replacements = new Map([
      ["files", { command: "mcp-restrictor", args: ["--policy", "/policy.yaml"] }],
    ]);

    expect(result.configurations.map(({ config }) => config.client)).toEqual(["claude"]);
    expect(host.readConfig).toHaveBeenCalledWith(path);
    expect(claudeAdapter.render(config, replacements)).toBe(
      renderClaudeConfig(config, replacements),
    );
    expect(claudeAdapter.completionMessage?.({ projectRoot })).toContain(
      "Restart Claude Code and approve the project .mcp.json change when prompted.",
    );
    expect(
      claudeAdapter.projectWrapper?.({
        projectRoot,
        relativePolicyPath: ".mcp-restrictor/policies/claude/files.yaml",
        diskPolicyPath: join(projectRoot, ".mcp-restrictor/policies/claude/files.yaml"),
      }),
    ).toEqual({
      policyArgument: "${CLAUDE_PROJECT_DIR:-.}/.mcp-restrictor/policies/claude/files.yaml",
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test.each([
  [
    "server property",
    '{"mcpServers":{"files":{"command":"node","args":["shadowed.mjs"]},"files":{"command":"node","args":["effective.mjs"]}}}',
  ],
  [
    "mcpServers property",
    '{"mcpServers":{"files":{"command":"node","args":["shadowed.mjs"]}},"mcpServers":{"files":{"command":"node","args":["effective.mjs"]}}}',
  ],
] as const)("rejects a duplicate Claude %s before setup", (_name, source) => {
  expect(() => parseClaudeConfig({ ...options, source })).toThrow("Invalid Claude JSON");
});

test("imports HTTP and SSE headers with raw wrapper expressions and expanded preflight values", () => {
  const source = JSON.stringify({
    mcpServers: {
      http: {
        type: "streamable-http",
        url: "${MCP_RESTRICTOR_UPSTREAM_HEADER_1:-https://http.example.test/mcp}",
        headers: {
          "X-Http": "${MCP_RESTRICTOR_UPSTREAM_HEADER_2:-header-fallback}",
          "X-One-Pass": "${OUTER}",
          "X-Default": "${MISSING:-fallback-value}",
        },
      },
      sse: {
        type: "sse",
        url: "${SSE_URL}",
        headers: { "X-Sse": "${SSE_TOKEN}" },
      },
    },
  });

  const environment = Object.assign(Object.create({ MISSING: "inherited-secret" }), {
    ...options.environment,
    MCP_RESTRICTOR_UPSTREAM_HEADER_0: "occupied-by-process",
    OUTER: "${INNER}",
    INNER: "recursive-secret",
    SSE_URL: "https://sse.example.test/events",
    SSE_TOKEN: "sse-effective-secret",
  }) as NodeJS.ProcessEnv;
  const parsed = parseClaudeConfig({
    ...options,
    source,
    environment,
  });

  expect(parsed.unsupported).toEqual([]);
  expect(
    parsed.servers.map(({ name, source: raw, upstream, wrapperEnvironment, oauth }) => ({
      name,
      raw,
      upstream,
      wrapperEnvironment,
      oauth,
    })),
  ).toEqual([
    {
      name: "http",
      raw: {
        kind: "http",
        url: "${MCP_RESTRICTOR_UPSTREAM_HEADER_1:-https://http.example.test/mcp}",
        headers: [
          { name: "X-Http", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_3" },
          { name: "X-One-Pass", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_4" },
          { name: "X-Default", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_5" },
        ],
      },
      upstream: {
        kind: "http",
        url: "https://http.example.test/mcp",
        headers: [
          ["X-Http", "header-fallback"],
          ["X-One-Pass", "${INNER}"],
          ["X-Default", "fallback-value"],
        ],
      },
      wrapperEnvironment: {
        env: {
          MCP_RESTRICTOR_UPSTREAM_HEADER_3: "${MCP_RESTRICTOR_UPSTREAM_HEADER_2:-header-fallback}",
          MCP_RESTRICTOR_UPSTREAM_HEADER_4: "${OUTER}",
          MCP_RESTRICTOR_UPSTREAM_HEADER_5: "${MISSING:-fallback-value}",
        },
      },
      oauth: {
        mode: "challenge",
        callback: { host: "localhost", path: "/callback", appendProfileId: false },
      },
    },
    {
      name: "sse",
      raw: {
        kind: "sse",
        url: "${SSE_URL}",
        headers: [{ name: "X-Sse", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_1" }],
      },
      upstream: {
        kind: "sse",
        url: "https://sse.example.test/events",
        headers: [["X-Sse", "sse-effective-secret"]],
      },
      wrapperEnvironment: {
        env: { MCP_RESTRICTOR_UPSTREAM_HEADER_1: "${SSE_TOKEN}" },
      },
      oauth: {
        mode: "challenge",
        callback: { host: "localhost", path: "/callback", appendProfileId: false },
      },
    },
  ]);
  expect(
    JSON.stringify(
      parsed.servers.map(({ source: raw, wrapperEnvironment }) => ({ raw, wrapperEnvironment })),
    ),
  ).not.toContain("effective-secret");
});

test("imports ws and wss with literal base64url-backed headers", () => {
  const source = JSON.stringify({
    mcpServers: {
      secure: {
        type: "ws",
        url: "wss://socket.example.test/mcp",
        headers: {
          "X-Literal": "${TOKEN}",
          Authorization: "Bearer ${TOKEN}",
        },
      },
      loopback: { type: "ws", url: "ws://127.0.0.1:4321/mcp" },
      inventedAlias: { type: "websocket", url: "wss://socket.example.test/mcp" },
      invalidScheme: { type: "ws", url: "https://socket.example.test/mcp" },
      oauth: { type: "ws", url: "wss://socket.example.test/mcp", oauth: {} },
      helper: {
        type: "ws",
        url: "wss://socket.example.test/mcp",
        headersHelper: "secret-command",
      },
    },
  });

  const parsed = parseClaudeConfig({ ...options, source, environment: { TOKEN: "other" } });

  expect(
    parsed.servers.map(({ name, source: raw, upstream, wrapperEnvironment, oauth }) => ({
      name,
      raw,
      upstream,
      wrapperEnvironment,
      oauth,
    })),
  ).toEqual([
    {
      name: "secure",
      raw: {
        kind: "websocket",
        url: "wss://socket.example.test/mcp",
        headers: [
          {
            name: "X-Literal",
            environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_0",
            encoding: "base64url",
          },
          {
            name: "Authorization",
            environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_1",
            encoding: "base64url",
          },
        ],
      },
      upstream: {
        kind: "websocket",
        url: "wss://socket.example.test/mcp",
        headers: [
          ["X-Literal", "${TOKEN}"],
          ["Authorization", "Bearer ${TOKEN}"],
        ],
      },
      wrapperEnvironment: {
        env: {
          MCP_RESTRICTOR_UPSTREAM_HEADER_0: "JHtUT0tFTn0",
          MCP_RESTRICTOR_UPSTREAM_HEADER_1: "QmVhcmVyICR7VE9LRU59",
        },
      },
      oauth: undefined,
    },
    {
      name: "loopback",
      raw: { kind: "websocket", url: "ws://127.0.0.1:4321/mcp", headers: [] },
      upstream: { kind: "websocket", url: "ws://127.0.0.1:4321/mcp" },
      wrapperEnvironment: {},
      oauth: undefined,
    },
  ]);
  expect(parsed.unsupported.map(({ name, reason }) => ({ name, reason }))).toEqual([
    { name: "inventedAlias", reason: "unsupported transport" },
    { name: "invalidScheme", reason: "unsupported WebSocket URL" },
    { name: "oauth", reason: "OAuth is not supported for WebSocket" },
    { name: "helper", reason: "unsupported field: headersHelper" },
  ]);
  expect(renderClaudeConfig(parsed, new Map())).toBe(
    `${JSON.stringify(JSON.parse(source), null, 2)}\n`,
  );
});

test("rejects interpolated native and managed WebSocket URLs without reading their values", () => {
  let tokenReads = 0;
  const environment: NodeJS.ProcessEnv = {};
  Object.defineProperty(environment, "TOKEN", {
    enumerable: true,
    get() {
      tokenReads += 1;
      return "expanded-secret";
    },
  });
  const source = `${JSON.stringify(
    {
      mcpServers: {
        native: { type: "ws", url: "wss://socket.example.test/${TOKEN}" },
        managed: {
          command: "mcp-restrictor",
          args: [
            "--policy",
            "/policies/ws.yaml",
            "--upstream-websocket",
            "wss://socket.example.test/${TOKEN}",
          ],
        },
      },
    },
    null,
    2,
  )}\n`;

  const parsed = parseClaudeConfig({ ...options, source, environment });

  expect(tokenReads).toBe(0);
  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ name, reason }) => ({ name, reason }))).toEqual([
    { name: "native", reason: "unsupported WebSocket URL" },
    { name: "managed", reason: "unsupported WebSocket URL" },
  ]);
  expect(renderClaudeConfig(parsed, new Map())).toBe(source);
});

test("maps explicit and challenge OAuth hints without reading a Claude session", () => {
  let sessionReads = 0;
  const keyPath = resolve("keys/oauth-master.key");
  const environment: NodeJS.ProcessEnv = {
    HEADER_TOKEN: "effective-header",
    TOKEN: "bearer-token",
    [MASTER_KEY_FILE_ENV]: "keys/oauth-master.key",
  };
  Object.defineProperty(environment, "CLAUDE_CODE_OAUTH_TOKEN", {
    enumerable: true,
    get() {
      sessionReads += 1;
      throw new Error("Claude session must not be read");
    },
  });
  const source = JSON.stringify({
    mcpServers: {
      explicitHttp: {
        type: "http",
        url: "https://http.example.test/mcp",
        headers: { "X-Tenant": "${HEADER_TOKEN}" },
        oauth: {
          clientId: "registered-client",
          authServerMetadataUrl: "https://auth.example.test/.well-known/openid-configuration",
          scopes: "read write",
          callbackPort: 41337,
        },
      },
      explicitSse: {
        type: "sse",
        url: "https://sse.example.test/events",
        oauth: { callbackPort: 0 },
      },
      challenge: { type: "http", url: "https://challenge.example.test/mcp" },
      bearer: {
        type: "sse",
        url: "https://bearer.example.test/events",
        headers: { Authorization: "Bearer ${TOKEN}" },
      },
      authorization: {
        type: "http",
        url: "https://basic.example.test/mcp",
        headers: { aUtHoRiZaTiOn: "Basic ${TOKEN}" },
      },
    },
  });

  const parsed = parseClaudeConfig({ ...options, source, environment });

  expect(sessionReads).toBe(0);
  expect(parsed.unsupported).toEqual([]);
  expect(parsed.servers.map(({ name, oauth }) => [name, oauth])).toEqual([
    [
      "explicitHttp",
      {
        mode: "explicit",
        clientId: "registered-client",
        requestedScope: "read write",
        authServerMetadataUrl: "https://auth.example.test/.well-known/openid-configuration",
        callback: {
          host: "localhost",
          path: "/callback",
          port: 41337,
          appendProfileId: false,
        },
      },
    ],
    [
      "explicitSse",
      {
        mode: "explicit",
        callback: { host: "localhost", path: "/callback", port: 0, appendProfileId: false },
      },
    ],
    [
      "challenge",
      {
        mode: "challenge",
        callback: { host: "localhost", path: "/callback", appendProfileId: false },
      },
    ],
    ["bearer", undefined],
    ["authorization", undefined],
  ]);
  const explicit = parsed.servers[0]!;
  expect(explicit.wrapperEnvironment).toEqual({
    env: {
      MCP_RESTRICTOR_UPSTREAM_HEADER_0: "${HEADER_TOKEN}",
      [MASTER_KEY_FILE_ENV]: keyPath,
    },
  });
  expect(explicit.source).toEqual({
    kind: "http",
    url: "https://http.example.test/mcp",
    headers: [{ name: "X-Tenant", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_0" }],
  });
  expect(explicit.upstream).toEqual({
    kind: "http",
    url: "https://http.example.test/mcp",
    headers: [["X-Tenant", "effective-header"]],
  });
  expect(parsed.servers[1]!.wrapperEnvironment).toEqual({
    env: { [MASTER_KEY_FILE_ENV]: keyPath },
  });
  expect(parsed.servers[2]!.wrapperEnvironment).toEqual({
    env: { [MASTER_KEY_FILE_ENV]: keyPath },
  });
  expect(parsed.servers[3]!.wrapperEnvironment.env).not.toHaveProperty(MASTER_KEY_FILE_ENV);
  expect(parsed.servers[4]!.wrapperEnvironment.env).not.toHaveProperty(MASTER_KEY_FILE_ENV);
  expect(JSON.stringify(parsed.servers)).not.toContain("CLAUDE_CODE_OAUTH_TOKEN");
  expect(
    JSON.stringify(
      parsed.servers.map(({ source: raw, wrapperEnvironment }) => ({
        raw,
        wrapperEnvironment,
      })),
    ),
  ).not.toContain("bearer-token");
  expect(JSON.stringify(explicit.source)).not.toContain(keyPath);
});

test("rejects malformed or conflicting OAuth metadata before expanding secrets", () => {
  let secretReads = 0;
  const environment: NodeJS.ProcessEnv = {};
  Object.defineProperty(environment, "UNREAD_SECRET", {
    enumerable: true,
    get() {
      secretReads += 1;
      throw new Error("invalid entries must not expand secrets");
    },
  });
  const source = JSON.stringify({
    mcpServers: {
      insecureMetadata: {
        type: "http",
        url: "${UNREAD_SECRET}",
        oauth: { authServerMetadataUrl: "http://localhost:4321/metadata" },
      },
      malformedScopes: {
        type: "http",
        url: "${UNREAD_SECRET}",
        oauth: { scopes: "read\twrite" },
      },
      malformedPort: {
        type: "sse",
        url: "${UNREAD_SECRET}",
        oauth: { callbackPort: -1 },
      },
      clientCredential: {
        type: "http",
        url: "${UNREAD_SECRET}",
        oauth: { clientId: "client", accessToken: "client-token-secret" },
      },
      authorizationConflict: {
        type: "http",
        url: "${UNREAD_SECRET}",
        headers: { Authorization: "${UNREAD_SECRET}" },
        oauth: {},
      },
      bearerConflict: {
        type: "sse",
        url: "${UNREAD_SECRET}",
        headers: { Authorization: "Bearer ${UNREAD_SECRET}" },
        oauth: {},
      },
      masterKeyConflict: {
        command: "mcp-restrictor",
        args: [
          "--policy",
          "/policy.yaml",
          "--upstream-http",
          "${UNREAD_SECRET}",
          "--upstream-header-env",
          "X-Key=mCp_ReStRiCtOr_MaStEr_KeY_fIlE",
        ],
      },
    },
  });

  const parsed = parseClaudeConfig({ ...options, source, environment });

  expect(secretReads).toBe(0);
  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ name, reason }) => ({ name, reason }))).toEqual([
    { name: "insecureMetadata", reason: "invalid OAuth metadata" },
    { name: "malformedScopes", reason: "invalid OAuth metadata" },
    { name: "malformedPort", reason: "invalid OAuth metadata" },
    { name: "clientCredential", reason: "invalid OAuth metadata" },
    { name: "authorizationConflict", reason: "conflicting remote authentication" },
    { name: "bearerConflict", reason: "conflicting remote authentication" },
    {
      name: "masterKeyConflict",
      reason: "OAuth header mapping conflicts with the master key selector",
    },
  ]);
  expect(JSON.stringify(parsed.unsupported)).not.toContain("client-token-secret");
});

test("rejects an empty expanded bearer token before discovery", () => {
  const source = JSON.stringify({
    mcpServers: {
      emptyBearer: {
        type: "http",
        url: "https://bearer.example.test/mcp",
        headers: { Authorization: "Bearer ${TOKEN}" },
      },
    },
  });

  const parsed = parseClaudeConfig({ ...options, source, environment: { TOKEN: "" } });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ name, reason }) => ({ name, reason }))).toEqual([
    { name: "emptyBearer", reason: "missing HTTP bearer environment variable" },
  ]);
});

test.each([
  ["leading scope separator", { scopes: " read" }],
  ["double scope separator", { scopes: "read  write" }],
  ["trailing scope separator", { scopes: "read " }],
  ["fractional callback port", { callbackPort: 1.5 }],
  ["callback port above 65535", { callbackPort: 65_536 }],
  ["string callback port", { callbackPort: "41337" }],
  [
    "metadata URL credentials",
    { authServerMetadataUrl: "https://user:pass@auth.example.test/metadata" },
  ],
  [
    "metadata URL fragment",
    { authServerMetadataUrl: "https://auth.example.test/metadata#fragment" },
  ],
])("rejects malformed OAuth metadata: %s", (_case, oauth) => {
  const parsed = parseClaudeConfig({
    ...options,
    source: JSON.stringify({
      mcpServers: {
        invalid: { type: "http", url: "https://example.test/mcp", oauth },
      },
    }),
  });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ reason }) => reason)).toEqual(["invalid OAuth metadata"]);
});

test("applies shared TLS rules to explicit OAuth and arbitrary headers only", () => {
  const source = JSON.stringify({
    mcpServers: {
      challenge: { type: "http", url: "http://example.test/mcp" },
      explicit: { type: "http", url: "http://example.test/mcp", oauth: {} },
      header: {
        type: "sse",
        url: "http://example.test/events",
        headers: { "X-Key": "configured-value" },
      },
    },
  });

  const parsed = parseClaudeConfig({ ...options, source });

  expect(parsed.servers.map(({ name, oauth }) => ({ name, oauth }))).toEqual([
    {
      name: "challenge",
      oauth: {
        mode: "challenge",
        callback: { host: "localhost", path: "/callback", appendProfileId: false },
      },
    },
  ]);
  expect(parsed.unsupported.map(({ name, reason }) => ({ name, reason }))).toEqual([
    { name: "explicit", reason: "invalid remote configuration" },
    { name: "header", reason: "invalid remote configuration" },
  ]);
});

test.each([
  [
    "reserved header",
    "HEADER_SECRET",
    {
      type: "http",
      url: "https://example.test/mcp",
      headers: { Host: "${HEADER_SECRET}" },
    },
  ],
  [
    "plaintext bearer",
    "TOKEN",
    {
      type: "http",
      url: "http://example.test/mcp",
      headers: { Authorization: "Bearer ${TOKEN}" },
    },
  ],
  [
    "plaintext explicit OAuth",
    MASTER_KEY_FILE_ENV,
    { type: "http", url: "http://example.test/mcp", oauth: {} },
  ],
] as const)("rejects %s before reading %s", (_case, environmentName, entry) => {
  let reads = 0;
  const environment: NodeJS.ProcessEnv = {};
  Object.defineProperty(environment, environmentName, {
    enumerable: true,
    get() {
      reads += 1;
      return "unread-value";
    },
  });

  const parsed = parseClaudeConfig({
    ...options,
    source: JSON.stringify({ mcpServers: { invalid: entry } }),
    environment,
  });

  expect(reads).toBe(0);
  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ reason }) => reason)).toEqual(["invalid remote configuration"]);
});

test.each([
  ["header", "HEADER_SECRET", ["--upstream-header-env", "X-Key=HEADER_SECRET"]],
  ["bearer", "TOKEN", ["--upstream-bearer-token-env", "TOKEN"]],
  ["OAuth storage", MASTER_KEY_FILE_ENV, ["--upstream-oauth-profile", oauthProfileId]],
] as const)(
  "rejects a plaintext managed %s before reading %s",
  (_case, environmentName, authArgs) => {
    let reads = 0;
    const environment: NodeJS.ProcessEnv = { URL: "http://example.test/mcp" };
    Object.defineProperty(environment, environmentName, {
      enumerable: true,
      get() {
        reads += 1;
        return "unread-value";
      },
    });
    const source = JSON.stringify({
      mcpServers: {
        invalid: {
          command: "mcp-restrictor",
          args: ["--policy", "/policy.yaml", "--upstream-http", "${URL}", ...authArgs],
        },
      },
    });

    const parsed = parseClaudeConfig({ ...options, source, environment });

    expect(reads).toBe(0);
    expect(parsed.servers).toEqual([]);
    expect(parsed.unsupported.map(({ reason }) => reason)).toEqual([
      "invalid remote configuration",
    ]);
  },
);

test("unwraps managed Claude remote sources and keeps their fixed storage environment", () => {
  const websocketHeader = Buffer.from("${TOKEN}").toString("base64url");
  const source = JSON.stringify({
    mcpServers: {
      http: {
        command: "mcp-restrictor",
        args: [
          "--policy",
          "/policies/http.yaml",
          "--upstream-http",
          "https://http.example.test/mcp",
          "--upstream-header-env",
          "X-Http=HTTP_HEADER",
          "--upstream-oauth-profile",
          oauthProfileId,
        ],
        env: {
          HTTP_HEADER: "${TOKEN}",
          [MASTER_KEY_FILE_ENV]: "/fixed/oauth-master.key",
          UNRELATED: "preserve-me",
        },
        timeout: 1000,
      },
      sse: {
        command: "/trusted/bin/mcp-restrictor",
        args: [
          "--policy",
          "/policies/sse.yaml",
          "--upstream-sse",
          "https://sse.example.test/events",
          "--upstream-header-env",
          "X-Sse=SSE_HEADER",
          "--upstream-oauth-profile",
          oauthProfileId,
        ],
        env: { SSE_HEADER: "${SSE_TOKEN}", [MASTER_KEY_FILE_ENV]: "/fixed/oauth-master.key" },
      },
      websocket: {
        command: "C:\\trusted\\mcp-restrictor.exe",
        args: [
          "--policy",
          "/policies/ws.yaml",
          "--upstream-websocket",
          "wss://socket.example.test/mcp",
          "--upstream-header-base64url-env",
          "X-Literal=WS_HEADER",
        ],
        env: { WS_HEADER: websocketHeader },
      },
    },
  });

  const parsed = parseClaudeConfig({
    ...options,
    source,
    environment: { TOKEN: "http-effective", SSE_TOKEN: "sse-effective" },
  });

  expect(parsed.unsupported).toEqual([]);
  expect(
    parsed.servers.map(
      ({ name, source: raw, upstream, wrapperEnvironment, oauth, managedPolicyPath }) => ({
        name,
        raw,
        upstream,
        wrapperEnvironment,
        oauth,
        managedPolicyPath,
      }),
    ),
  ).toEqual([
    {
      name: "http",
      raw: {
        kind: "http",
        url: "https://http.example.test/mcp",
        headers: [{ name: "X-Http", environmentVariable: "HTTP_HEADER" }],
        oauthProfileId,
      },
      upstream: {
        kind: "http",
        url: "https://http.example.test/mcp",
        headers: [["X-Http", "http-effective"]],
      },
      wrapperEnvironment: {
        env: {
          HTTP_HEADER: "${TOKEN}",
          [MASTER_KEY_FILE_ENV]: "/fixed/oauth-master.key",
          UNRELATED: "preserve-me",
        },
      },
      oauth: undefined,
      managedPolicyPath: "/policies/http.yaml",
    },
    {
      name: "sse",
      raw: {
        kind: "sse",
        url: "https://sse.example.test/events",
        headers: [{ name: "X-Sse", environmentVariable: "SSE_HEADER" }],
        oauthProfileId,
      },
      upstream: {
        kind: "sse",
        url: "https://sse.example.test/events",
        headers: [["X-Sse", "sse-effective"]],
      },
      wrapperEnvironment: {
        env: { SSE_HEADER: "${SSE_TOKEN}", [MASTER_KEY_FILE_ENV]: "/fixed/oauth-master.key" },
      },
      oauth: undefined,
      managedPolicyPath: "/policies/sse.yaml",
    },
    {
      name: "websocket",
      raw: {
        kind: "websocket",
        url: "wss://socket.example.test/mcp",
        headers: [{ name: "X-Literal", environmentVariable: "WS_HEADER", encoding: "base64url" }],
      },
      upstream: {
        kind: "websocket",
        url: "wss://socket.example.test/mcp",
        headers: [["X-Literal", "${TOKEN}"]],
      },
      wrapperEnvironment: { env: { WS_HEADER: websocketHeader } },
      oauth: undefined,
      managedPolicyPath: "/policies/ws.yaml",
    },
  ]);

  const planned = planManagedWrapper({
    server: parsed.servers[0]!,
    allowedTools: [],
    policy: { diskPath: "/policies/http.yaml", argument: "/policies/http.yaml" },
    restrictor: { command: "mcp-restrictor", argsPrefix: [] },
    projectRoot: "/repo",
  });
  expect(planned.replacement.env).toEqual(parsed.servers[0]!.wrapperEnvironment.env);
  expect(planned.replacement.args).not.toContain("/fixed/oauth-master.key");
  expect(planned.verificationUpstream).toMatchObject({
    kind: "stdio",
    env: {
      HTTP_HEADER: "http-effective",
      [MASTER_KEY_FILE_ENV]: "/fixed/oauth-master.key",
    },
  });
});

test("renders a selected remote entry as only the managed STDIO fields", () => {
  const source = JSON.stringify({
    mcpServers: {
      selected: {
        type: "sse",
        url: "https://sse.example.test/events",
        headers: { "X-Key": "${TOKEN}" },
        oauth: { scopes: "read" },
        timeout: 500,
        alwaysLoad: true,
      },
      untouched: { type: "ws", url: "wss://socket.example.test/mcp" },
    },
  });
  const parsed = parseClaudeConfig({ ...options, source });

  const rendered = JSON.parse(
    renderClaudeConfig(
      parsed,
      new Map([
        [
          "selected",
          {
            command: "/trusted/bin/mcp-restrictor",
            args: ["--policy", "/policy.yaml", "--upstream-sse", "https://sse.example.test/events"],
            env: { MCP_RESTRICTOR_UPSTREAM_HEADER_0: "${TOKEN}" },
          },
        ],
      ]),
    ),
  );

  expect(rendered.mcpServers.selected).toEqual({
    type: "stdio",
    command: "/trusted/bin/mcp-restrictor",
    args: ["--policy", "/policy.yaml", "--upstream-sse", "https://sse.example.test/events"],
    env: { MCP_RESTRICTOR_UPSTREAM_HEADER_0: "${TOKEN}" },
    timeout: 500,
    alwaysLoad: true,
  });
  expect(rendered.mcpServers.selected).not.toHaveProperty("url");
  expect(rendered.mcpServers.selected).not.toHaveProperty("headers");
  expect(rendered.mcpServers.selected).not.toHaveProperty("oauth");
  expect(rendered.mcpServers.untouched).toEqual({
    type: "ws",
    url: "wss://socket.example.test/mcp",
  });
});

test("uses the documented user and project Claude configuration paths", () => {
  expect(
    claudeConfigPaths({
      home: "/home/me",
      projectRoot: "/repo",
      environment: {},
    }),
  ).toEqual({ user: "/home/me/.claude.json", project: "/repo/.mcp.json" });
  expect(
    claudeConfigPaths({
      home: "/home/me",
      projectRoot: "/repo",
      environment: { CLAUDE_CONFIG_DIR: "/config" },
    }),
  ).toEqual({ user: "/config/.claude.json", project: "/repo/.mcp.json" });
});

test("uses an expanded managed wrapper environment value for HTTP bearer preflight", () => {
  const source = JSON.stringify({
    mcpServers: {
      managed: {
        command: "C:\\trusted\\mcp-restrictor.cmd",
        args: [
          "--policy",
          "/repo/policy.yaml",
          "--upstream-http",
          "https://example.test/mcp",
          "--upstream-bearer-token-env",
          "TOKEN",
        ],
        env: { TOKEN: "${OTHER}" },
      },
    },
  });

  const [candidate] = parseClaudeConfig({ ...options, source }).servers;

  expect(candidate).toEqual({
    client: "claude",
    scope: "user",
    name: "managed",
    configPath: "/home/me/.claude.json",
    source: {
      kind: "http",
      url: "https://example.test/mcp",
      headers: [],
      bearerTokenEnvVar: "TOKEN",
    },
    upstream: {
      kind: "http",
      url: "https://example.test/mcp",
      bearerToken: "explicit-secret",
    },
    wrapperEnvironment: { env: { TOKEN: "${OTHER}" } },
    original: {
      command: "C:\\trusted\\mcp-restrictor.cmd",
      args: [
        "--policy",
        "/repo/policy.yaml",
        "--upstream-http",
        "https://example.test/mcp",
        "--upstream-bearer-token-env",
        "TOKEN",
      ],
      env: { TOKEN: "${OTHER}" },
    },
    managedPolicyPath: "/repo/policy.yaml",
  });
  expect(
    JSON.stringify({ source: candidate?.source, wrapper: candidate?.wrapperEnvironment }),
  ).not.toContain("explicit-secret");
});

test("rejects a malformed absolute Claude managed wrapper", () => {
  const source = JSON.stringify({
    mcpServers: {
      managed: {
        command: "/trusted/bin/mcp-restrictor",
        args: ["--", "node"],
      },
    },
  });

  const parsed = parseClaudeConfig({ ...options, source });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ reason }) => reason)).toEqual([
    "malformed mcp-restrictor wrapper",
  ]);
});

test("preserves an own __proto__ STDIO environment value", () => {
  const source = '{"mcpServers":{"proto":{"command":"node","env":{"__proto__":"own-value"}}}}';

  const [candidate] = parseClaudeConfig({ ...options, source }).servers;

  expect(candidate?.source).toEqual({
    kind: "stdio",
    command: "node",
    args: [],
    envNames: ["__proto__"],
  });
  expect(candidate?.upstream.kind).toBe("stdio");
  if (candidate?.upstream.kind !== "stdio") throw new Error("expected STDIO candidate");
  expect(Object.hasOwn(candidate.upstream.env!, "__proto__")).toBe(true);
  expect(candidate.upstream.env!.__proto__).toBe("own-value");
  expect(Object.hasOwn(candidate.wrapperEnvironment.env!, "__proto__")).toBe(true);
  expect(candidate.wrapperEnvironment.env!.__proto__).toBe("own-value");
});

test("forwards only env names declared by a managed STDIO wrapper", () => {
  const source = JSON.stringify({
    mcpServers: {
      managed: {
        command: "mcp-restrictor",
        args: [
          "--policy",
          "/repo/policy.yaml",
          "--upstream-env",
          "PUBLIC",
          "--",
          "node",
          "server.mjs",
        ],
        env: {
          PUBLIC: "${OTHER}",
          WRAPPER_ONLY_SECRET: "do-not-forward",
        },
      },
    },
  });

  const parsed = parseClaudeConfig({ ...options, source });
  const [managed] = parsed.servers;

  expect(managed?.source).toEqual({
    kind: "stdio",
    command: "node",
    args: ["server.mjs"],
    envNames: ["PUBLIC"],
  });
  expect(managed?.upstream.kind).toBe("stdio");
  if (managed?.upstream.kind !== "stdio") throw new Error("expected STDIO candidate");
  expect(managed.upstream.env).toEqual(expect.objectContaining({ PUBLIC: "explicit-secret" }));
  expect(Object.hasOwn(managed.upstream.env!, "WRAPPER_ONLY_SECRET")).toBe(false);
  expect(managed.wrapperEnvironment).toEqual({
    env: { PUBLIC: "${OTHER}", WRAPPER_ONLY_SECRET: "do-not-forward" },
  });
});

test("rejects a missing managed STDIO env name without exposing it", () => {
  const source = JSON.stringify({
    mcpServers: {
      missing: {
        command: "mcp-restrictor",
        args: [
          "--policy",
          "/repo/missing.yaml",
          "--upstream-env",
          "MISSING_SECRET_NAME",
          "--",
          "node",
          "server.mjs",
        ],
        env: { WRAPPER_ONLY_SECRET: "do-not-forward" },
      },
    },
  });

  const parsed = parseClaudeConfig({ ...options, source });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported).toEqual([
    {
      client: "claude",
      scope: "user",
      name: "missing",
      configPath: "/home/me/.claude.json",
      reason: "missing STDIO environment variable",
    },
  ]);
  expect(JSON.stringify(parsed.unsupported)).not.toContain("MISSING_SECRET_NAME");
  expect(JSON.stringify(parsed.unsupported)).not.toContain("do-not-forward");
});

test("rejects expanded HTTP query and fragment values without exposing them", () => {
  const source = JSON.stringify({
    mcpServers: {
      rawQuery: {
        type: "http",
        url: "https://example.test/mcp?access_token=${TOKEN}",
      },
      expandedQuery: { type: "http", url: "${MCP_URL}" },
      plain: { type: "http", url: "${PLAIN_URL}" },
    },
  });

  const parsed = parseClaudeConfig({
    ...options,
    source,
    environment: {
      ...options.environment,
      MCP_URL: "https://example.test/mcp?session=resolved-secret#state",
      PLAIN_URL: "https://example.test/plain",
    },
  });

  expect(parsed.servers).toEqual([
    {
      client: "claude",
      scope: "user",
      name: "plain",
      configPath: "/home/me/.claude.json",
      source: { kind: "http", url: "${PLAIN_URL}", headers: [] },
      upstream: { kind: "http", url: "https://example.test/plain" },
      wrapperEnvironment: {},
      oauth: {
        mode: "challenge",
        callback: { host: "localhost", path: "/callback", appendProfileId: false },
      },
      original: { type: "http", url: "${PLAIN_URL}" },
    },
  ]);
  expect(parsed.unsupported).toEqual([
    {
      client: "claude",
      scope: "user",
      name: "rawQuery",
      configPath: "/home/me/.claude.json",
      reason: "HTTP URL must not contain query or fragment",
    },
    {
      client: "claude",
      scope: "user",
      name: "expandedQuery",
      configPath: "/home/me/.claude.json",
      reason: "HTTP URL must not contain query or fragment",
    },
  ]);
  expect(JSON.stringify(parsed.unsupported)).not.toContain("process-secret");
  expect(JSON.stringify(parsed.unsupported)).not.toContain("resolved-secret");
  expect(JSON.stringify(parsed.unsupported)).not.toContain("https://example.test/mcp");
});

test("discovers supported entries with raw client expressions and expanded preflight values", () => {
  const source = JSON.stringify({
    projects: { "/repo": { trusted: true } },
    cache: { lastUpdated: 1 },
    mcpServers: {
      stdio: {
        command: "${NODE}",
        args: [
          "${SCRIPT}",
          "${EMPTY}",
          "${EMPTY:-empty-fallback}",
          "${MISSING:-fallback}",
          "${MISSING}",
        ],
        env: {
          TOKEN: "${TOKEN}",
          PROJECT: "${CLAUDE_PROJECT_DIR:-.}",
          PATH: "/configured/path",
        },
        timeout: 2000,
        alwaysLoad: true,
      },
      http: { type: "http", url: "${URL}" },
      bearer: {
        type: "streamable-http",
        url: "https://example.test/${MISSING:-fallback}",
        headers: { Authorization: "Bearer ${TOKEN}" },
      },
      managed: {
        command: "mcp-restrictor",
        args: [
          "--policy",
          "${CLAUDE_PROJECT_DIR:-.}/.mcp-restrictor/policies/claude/managed.yaml",
          "--upstream-env",
          "TOKEN",
          "--",
          "${NODE}",
          "${SCRIPT}",
        ],
        env: { TOKEN: "${TOKEN}" },
      },
      managedHttp: {
        command: "mcp-restrictor",
        args: [
          "--policy",
          "/repo/.mcp-restrictor/policies/claude/managed-http.yaml",
          "--upstream-http",
          "https://example.test/managed",
          "--upstream-bearer-token-env",
          "TOKEN",
        ],
        env: { TOKEN: "${OTHER}" },
      },
      invalidOauth: {
        type: "http",
        url: "https://example.test/mcp",
        oauth: { accessToken: "client-session-secret" },
      },
      invalidHeader: {
        type: "http",
        url: "https://example.test/mcp",
        headers: { Host: "secret" },
      },
      helper: {
        type: "http",
        url: "https://example.test/mcp",
        headersHelper: "secret-command",
      },
      invalidSse: { type: "sse-legacy", url: "https://example.test/sse" },
      websocket: { type: "websocket", url: "wss://example.test/mcp" },
      unknown: { command: "node", runOnStartup: true },
    },
  });

  const parsed = parseClaudeConfig({ ...options, source });

  expect(parsed.servers).toHaveLength(5);
  expect(parsed.servers[0]).toEqual({
    client: "claude",
    scope: "user",
    name: "stdio",
    configPath: "/home/me/.claude.json",
    source: {
      kind: "stdio",
      command: "${NODE}",
      args: [
        "${SCRIPT}",
        "${EMPTY}",
        "${EMPTY:-empty-fallback}",
        "${MISSING:-fallback}",
        "${MISSING}",
      ],
      envNames: ["PATH", "PROJECT", "TOKEN"],
    },
    upstream: {
      kind: "stdio",
      command: "/usr/bin/node",
      args: ["server.mjs", "", "empty-fallback", "fallback", "${MISSING}"],
      env: expect.objectContaining({
        TOKEN: "process-secret",
        PROJECT: "/repo",
        PATH: "/configured/path",
      }),
    },
    wrapperEnvironment: {
      env: {
        TOKEN: "${TOKEN}",
        PROJECT: "${CLAUDE_PROJECT_DIR:-.}",
        PATH: "/configured/path",
      },
    },
    original: {
      command: "${NODE}",
      args: [
        "${SCRIPT}",
        "${EMPTY}",
        "${EMPTY:-empty-fallback}",
        "${MISSING:-fallback}",
        "${MISSING}",
      ],
      env: {
        TOKEN: "${TOKEN}",
        PROJECT: "${CLAUDE_PROJECT_DIR:-.}",
        PATH: "/configured/path",
      },
      timeout: 2000,
      alwaysLoad: true,
    },
  });
  expect(parsed.servers[1]).toEqual({
    client: "claude",
    scope: "user",
    name: "http",
    configPath: "/home/me/.claude.json",
    source: { kind: "http", url: "${URL}", headers: [] },
    upstream: { kind: "http", url: "https://example.test/mcp" },
    wrapperEnvironment: {},
    oauth: {
      mode: "challenge",
      callback: { host: "localhost", path: "/callback", appendProfileId: false },
    },
    original: { type: "http", url: "${URL}" },
  });
  expect(parsed.servers[2]).toEqual({
    client: "claude",
    scope: "user",
    name: "bearer",
    configPath: "/home/me/.claude.json",
    source: {
      kind: "http",
      url: "https://example.test/${MISSING:-fallback}",
      headers: [],
      bearerTokenEnvVar: "TOKEN",
    },
    upstream: {
      kind: "http",
      url: "https://example.test/fallback",
      bearerToken: "process-secret",
    },
    wrapperEnvironment: { env: { TOKEN: "${TOKEN}" } },
    original: {
      type: "streamable-http",
      url: "https://example.test/${MISSING:-fallback}",
      headers: { Authorization: "Bearer ${TOKEN}" },
    },
  });
  expect(parsed.servers[3]).toEqual({
    client: "claude",
    scope: "user",
    name: "managed",
    configPath: "/home/me/.claude.json",
    source: {
      kind: "stdio",
      command: "${NODE}",
      args: ["${SCRIPT}"],
      envNames: ["TOKEN"],
    },
    upstream: {
      kind: "stdio",
      command: "/usr/bin/node",
      args: ["server.mjs"],
      env: expect.objectContaining({ TOKEN: "process-secret" }),
    },
    wrapperEnvironment: { env: { TOKEN: "${TOKEN}" } },
    original: {
      command: "mcp-restrictor",
      args: [
        "--policy",
        "${CLAUDE_PROJECT_DIR:-.}/.mcp-restrictor/policies/claude/managed.yaml",
        "--upstream-env",
        "TOKEN",
        "--",
        "${NODE}",
        "${SCRIPT}",
      ],
      env: { TOKEN: "${TOKEN}" },
    },
    managedPolicyPath: "/repo/.mcp-restrictor/policies/claude/managed.yaml",
  });
  expect(parsed.servers[4]).toEqual({
    client: "claude",
    scope: "user",
    name: "managedHttp",
    configPath: "/home/me/.claude.json",
    source: {
      kind: "http",
      url: "https://example.test/managed",
      headers: [],
      bearerTokenEnvVar: "TOKEN",
    },
    upstream: {
      kind: "http",
      url: "https://example.test/managed",
      bearerToken: "explicit-secret",
    },
    wrapperEnvironment: { env: { TOKEN: "${OTHER}" } },
    original: {
      command: "mcp-restrictor",
      args: [
        "--policy",
        "/repo/.mcp-restrictor/policies/claude/managed-http.yaml",
        "--upstream-http",
        "https://example.test/managed",
        "--upstream-bearer-token-env",
        "TOKEN",
      ],
      env: { TOKEN: "${OTHER}" },
    },
    managedPolicyPath: "/repo/.mcp-restrictor/policies/claude/managed-http.yaml",
  });
  const rawCandidates = parsed.servers.map(({ source: rawSource, wrapperEnvironment }) => ({
    source: rawSource,
    wrapperEnvironment,
  }));
  expect(JSON.stringify(rawCandidates)).not.toContain("process-secret");
  expect(JSON.stringify(rawCandidates)).not.toContain("explicit-secret");
  expect(parsed.unsupported).toEqual([
    {
      client: "claude",
      scope: "user",
      name: "invalidOauth",
      configPath: "/home/me/.claude.json",
      reason: "invalid OAuth metadata",
    },
    {
      client: "claude",
      scope: "user",
      name: "invalidHeader",
      configPath: "/home/me/.claude.json",
      reason: "invalid remote configuration",
    },
    {
      client: "claude",
      scope: "user",
      name: "helper",
      configPath: "/home/me/.claude.json",
      reason: "unsupported field: headersHelper",
    },
    {
      client: "claude",
      scope: "user",
      name: "invalidSse",
      configPath: "/home/me/.claude.json",
      reason: "unsupported transport",
    },
    {
      client: "claude",
      scope: "user",
      name: "websocket",
      configPath: "/home/me/.claude.json",
      reason: "unsupported transport",
    },
    {
      client: "claude",
      scope: "user",
      name: "unknown",
      configPath: "/home/me/.claude.json",
      reason: "unsupported field: runOnStartup",
    },
  ]);
});

test("rejects malformed wrappers and invalid remote configuration without exposing values", () => {
  const parsed = parseClaudeConfig({
    ...options,
    source: JSON.stringify({
      mcpServers: {
        nested: { command: "mcp-restrictor", args: ["--policy", "x", "--", "mcp-restrictor"] },
        disabled: { command: "node", disabled: false },
        credentials: { type: "http", url: "https://user:password@example.test/mcp" },
        badUrl: { type: "http", url: "file:///tmp/mcp" },
        headers: { type: "http", url: "https://example.test/mcp", headers: { Host: "secret" } },
      },
    }),
  });

  expect(parsed.unsupported.map(({ name, reason }) => ({ name, reason }))).toEqual([
    { name: "nested", reason: "malformed mcp-restrictor wrapper" },
    { name: "disabled", reason: "unsupported field: disabled" },
    { name: "credentials", reason: "HTTP URL must not contain credentials" },
    { name: "badUrl", reason: "unsupported HTTP URL" },
    { name: "headers", reason: "invalid remote configuration" },
  ]);
  expect(JSON.stringify(parsed.unsupported)).not.toContain("password");
  expect(JSON.stringify(parsed.unsupported)).not.toContain("secret");
});

test("renders selected entries while preserving unrelated Claude configuration state", () => {
  const source =
    '{"projects":{"/repo":{"trusted":true}},"cache":{"token":"leave-alone"},"mcpServers":{"selected":{"command":"node","args":["old.mjs"],"env":{"OLD":"old"},"timeout":500,"alwaysLoad":true},"untouched":{"command":"node","args":["stay.mjs"],"env":{"KEEP":"yes"}},"__proto__":{"command":"node","args":["ordinary-name.mjs"]}}}';
  const parsed = parseClaudeConfig({ ...options, source });
  const rendered = JSON.parse(
    renderClaudeConfig(
      parsed,
      new Map([
        [
          "selected",
          {
            command: "mcp-restrictor",
            args: ["--policy", "/tmp/policy.yaml"],
            env: { TOKEN: "${TOKEN}" },
          },
        ],
      ]),
    ),
  );

  expect(rendered.projects).toEqual({ "/repo": { trusted: true } });
  expect(rendered.cache).toEqual({ token: "leave-alone" });
  expect(rendered.mcpServers.selected).toEqual({
    type: "stdio",
    command: "mcp-restrictor",
    args: ["--policy", "/tmp/policy.yaml"],
    env: { TOKEN: "${TOKEN}" },
    timeout: 500,
    alwaysLoad: true,
  });
  expect(rendered.mcpServers.untouched).toEqual({
    command: "node",
    args: ["stay.mjs"],
    env: { KEEP: "yes" },
  });
  expect(Object.hasOwn(rendered.mcpServers, "__proto__")).toBe(true);
  expect(rendered.mcpServers.__proto__).toEqual({ command: "node", args: ["ordinary-name.mjs"] });
  expect(renderClaudeConfig(parsed, new Map())).toBe(
    `${JSON.stringify(JSON.parse(source), null, 2)}\n`,
  );
});
