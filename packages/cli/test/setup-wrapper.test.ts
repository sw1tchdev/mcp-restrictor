import { expect, test } from "vitest";
import { discoverToolNames } from "@mcp-restrictor/transports";
import { MASTER_KEY_FILE_ENV } from "../src/oauth/storage.ts";
import {
  parseManagedWrapper,
  planManagedWrapper,
  policyLocation,
  reserveWrapperEnvironmentName,
  type ServerCandidate,
} from "../src/setup/wrapper.ts";

const oauthProfileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

test("reserves deterministic wrapper header environment names", () => {
  const occupied = new Set(["MCP_RESTRICTOR_UPSTREAM_HEADER_0"]);

  expect(reserveWrapperEnvironmentName(occupied)).toBe("MCP_RESTRICTOR_UPSTREAM_HEADER_1");
  expect(reserveWrapperEnvironmentName(occupied)).toBe("MCP_RESTRICTOR_UPSTREAM_HEADER_2");
  expect([...occupied]).toEqual([
    "MCP_RESTRICTOR_UPSTREAM_HEADER_0",
    "MCP_RESTRICTOR_UPSTREAM_HEADER_1",
    "MCP_RESTRICTOR_UPSTREAM_HEADER_2",
  ]);
});

test("reserves wrapper environment names case-insensitively for Windows", () => {
  const occupied = new Set(["mcp_restrictor_upstream_header_0"]);

  expect(reserveWrapperEnvironmentName(occupied)).toBe("MCP_RESTRICTOR_UPSTREAM_HEADER_1");
});

test.each([
  ["http", "mcp-restrictor"],
  ["http", "/trusted/bin/mcp-restrictor"],
  ["sse", "mcp-restrictor"],
  ["sse", "C:\\trusted\\mcp-restrictor.exe"],
  ["websocket", "mcp-restrictor"],
  ["websocket", "/trusted/bin/mcp-restrictor"],
] as const)("round trips a generated %s wrapper pinned to %s", (kind, command) => {
  const server = remoteServer(kind);
  const planned = planManagedWrapper({
    server,
    allowedTools: [],
    policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
    restrictor: { command, argsPrefix: [] },
    projectRoot: "/repo",
  });

  expect(parseManagedWrapper(planned.replacement.command, planned.replacement.args)).toEqual({
    policyArgument: "/policy.yaml",
    source: server.source,
  });
  expect(planned.replacement.args).toEqual([
    "--policy",
    "/policy.yaml",
    `--upstream-${kind}`,
    server.source.kind === "stdio" ? "" : server.source.url,
    "--upstream-header-env",
    "X-Plain=PLAIN_ENV",
    "--upstream-header-base64url-env",
    "X-Encoded=ENCODED_ENV",
    ...(kind === "websocket" ? [] : ["--upstream-bearer-token-env", "BEARER_ENV"]),
  ]);
  expect(JSON.stringify(planned.replacement.args)).not.toContain("plain-secret");
  expect(JSON.stringify(planned.replacement.args)).not.toContain("encoded-secret");
  expect(JSON.stringify(planned.replacement.args)).not.toContain("bearer-secret");
  expect(planned.verificationUpstream).toMatchObject({
    kind: "stdio",
    env: {
      PLAIN_ENV: "plain-secret",
      ENCODED_ENV: "ZW5jb2RlZC1zZWNyZXQ",
      ...(kind === "websocket" ? {} : { BEARER_ENV: "bearer-secret" }),
    },
  });
});

test("preserves the Node custom CA only in the actual verification child environment", async () => {
  const verificationServer = `import { createInterface } from 'node:readline';
if (process.env.NODE_EXTRA_CA_CERTS !== '/certificates/local-ca.pem' || process.env.PLAIN_ENV !== 'plain-secret' || process.env.UNRELATED_RUNTIME_SECRET !== undefined) { process.stderr.write('verification environment mismatch\\n'); process.exit(42); }
for await (const line of createInterface({ input: process.stdin })) {
  const request = JSON.parse(line);
  if (request.id === undefined) continue;
  const result = request.method === 'initialize'
    ? { protocolVersion: request.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: 'verification-env', version: '1.0.0' } }
    : request.method === 'tools/list'
      ? { tools: [{ name: 'read_file', inputSchema: { type: 'object' } }] }
      : {};
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }) + '\\n');
}`;
  const planned = planManagedWrapper({
    server: remoteServer("http"),
    allowedTools: ["read_file"],
    policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
    restrictor: {
      command: process.execPath,
      argsPrefix: ["--input-type=module", "--eval", verificationServer, "--"],
    },
    verificationEnvironment: {
      NODE_EXTRA_CA_CERTS: "/certificates/local-ca.pem",
      UNRELATED_RUNTIME_SECRET: "must-not-be-inherited",
    },
  });

  await expect(discoverToolNames(planned.verificationUpstream)).resolves.toEqual(["read_file"]);
  expect(planned.replacement.env).not.toHaveProperty("NODE_EXTRA_CA_CERTS");
  expect(planned.replacement.env).not.toHaveProperty("UNRELATED_RUNTIME_SECRET");
});

test.each([
  ["http", "mcp-restrictor"],
  ["http", "/trusted/bin/mcp-restrictor"],
  ["sse", "mcp-restrictor"],
  ["sse", "C:\\trusted\\mcp-restrictor.exe"],
] as const)("round trips a generated OAuth %s wrapper pinned to %s", (kind, command) => {
  const server = oauthRemoteServer(kind);
  const planned = planManagedWrapper({
    server,
    allowedTools: [],
    policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
    restrictor: { command, argsPrefix: [] },
    projectRoot: "/repo",
  });

  expect(parseManagedWrapper(planned.replacement.command, planned.replacement.args)).toEqual({
    policyArgument: "/policy.yaml",
    source: server.source,
  });
  expect(planned.replacement.args).toEqual([
    "--policy",
    "/policy.yaml",
    `--upstream-${kind}`,
    `https://example.test/${kind}`,
    "--upstream-header-env",
    "X-Plain=PLAIN_ENV",
    "--upstream-oauth-profile",
    oauthProfileId,
  ]);
  expect(planned.replacement.env).toEqual({
    PLAIN_ENV: "plain-secret",
    [MASTER_KEY_FILE_ENV]: "/keys/oauth-master.key",
    UNRELATED_ENV: "wrapper-only",
  });
  expect(planned.verificationUpstream).toMatchObject({
    kind: "stdio",
    env: {
      PLAIN_ENV: "plain-secret",
      [MASTER_KEY_FILE_ENV]: "/keys/oauth-master.key",
    },
  });
  if (planned.verificationUpstream.kind !== "stdio") throw new Error();
  expect(planned.verificationUpstream.env).not.toHaveProperty("UNRELATED_ENV");
});

test.each([
  [
    "mixed remote selectors",
    [
      "--policy",
      "a",
      "--upstream-http",
      "https://example.test/mcp",
      "--upstream-sse",
      "https://example.test/sse",
    ],
  ],
  [
    "duplicate remote selector",
    [
      "--policy",
      "a",
      "--upstream-http",
      "https://example.test/one",
      "--upstream-http",
      "https://example.test/two",
    ],
  ],
  [
    "duplicate header names across encodings",
    [
      "--policy",
      "a",
      "--upstream-http",
      "https://example.test/mcp",
      "--upstream-header-env",
      "X-Key=PLAIN",
      "--upstream-header-base64url-env",
      "x-key=ENCODED",
    ],
  ],
  [
    "malformed header mapping",
    [
      "--policy",
      "a",
      "--upstream-http",
      "https://example.test/mcp",
      "--upstream-header-env",
      "X-Key",
    ],
  ],
  [
    "bearer on WebSocket",
    [
      "--policy",
      "a",
      "--upstream-websocket",
      "wss://example.test/mcp",
      "--upstream-bearer-token-env",
      "TOKEN",
    ],
  ],
  [
    "bearer conflicts with Authorization",
    [
      "--policy",
      "a",
      "--upstream-http",
      "https://example.test/mcp",
      "--upstream-header-env",
      "Authorization=AUTH",
      "--upstream-bearer-token-env",
      "TOKEN",
    ],
  ],
  [
    "remote header on STDIO",
    ["--policy", "a", "--upstream-header-env", "X-Key=TOKEN", "--", "node"],
  ],
  [
    "remote bearer on STDIO",
    ["--policy", "a", "--upstream-bearer-token-env", "TOKEN", "--", "node"],
  ],
  [
    "STDIO environment on remote",
    ["--policy", "a", "--upstream-env", "TOKEN", "--upstream-sse", "https://example.test/sse"],
  ],
  ["missing remote option value", ["--policy", "a", "--upstream-sse"]],
  [
    "missing header option value",
    ["--policy", "a", "--upstream-http", "https://example.test/mcp", "--upstream-header-env"],
  ],
  [
    "unknown option",
    ["--policy", "a", "--upstream-http", "https://example.test/mcp", "--future-option", "x"],
  ],
  [
    "duplicate OAuth selector",
    [
      "--policy",
      "a",
      "--upstream-http",
      "https://example.test/mcp",
      "--upstream-oauth-profile",
      oauthProfileId,
      "--upstream-oauth-profile",
      oauthProfileId,
    ],
  ],
  ["OAuth on STDIO", ["--policy", "a", "--upstream-oauth-profile", oauthProfileId, "--", "node"]],
  [
    "OAuth on WebSocket",
    [
      "--policy",
      "a",
      "--upstream-websocket",
      "wss://example.test/mcp",
      "--upstream-oauth-profile",
      oauthProfileId,
    ],
  ],
  [
    "OAuth conflicts with bearer",
    [
      "--policy",
      "a",
      "--upstream-http",
      "https://example.test/mcp",
      "--upstream-oauth-profile",
      oauthProfileId,
      "--upstream-bearer-token-env",
      "TOKEN",
    ],
  ],
  [
    "OAuth conflicts with Authorization",
    [
      "--policy",
      "a",
      "--upstream-http",
      "https://example.test/mcp",
      "--upstream-oauth-profile",
      oauthProfileId,
      "--upstream-header-env",
      "Authorization=AUTH",
    ],
  ],
  [
    "OAuth maps the master-key selector",
    [
      "--policy",
      "a",
      "--upstream-http",
      "https://example.test/mcp",
      "--upstream-oauth-profile",
      oauthProfileId,
      "--upstream-header-env",
      "X-Key=mCp_ReStRiCtOr_MaStEr_KeY_fIlE",
    ],
  ],
  [
    "missing OAuth option value",
    ["--policy", "a", "--upstream-http", "https://example.test/mcp", "--upstream-oauth-profile"],
  ],
  [
    "non-canonical OAuth profile ID",
    [
      "--policy",
      "a",
      "--upstream-http",
      "https://example.test/mcp",
      "--upstream-oauth-profile",
      oauthProfileId.toUpperCase(),
    ],
  ],
] as const)("rejects malformed managed wrapper codec input: %s", (_reason, args) => {
  expect(parseManagedWrapper("mcp-restrictor", args)).toBeUndefined();
});

test("rejects a planned non-canonical OAuth profile ID", () => {
  const server = oauthRemoteServer("http");
  if (server.source.kind === "stdio" || server.source.kind === "websocket") throw new Error();
  server.source.oauthProfileId = oauthProfileId.toUpperCase();

  expect(() => plan(server)).toThrow(/invalid OAuth profile ID/i);
});

test.each([
  ["stdio", stdioServer()],
  ["websocket", remoteServer("websocket")],
] as const)("rejects OAuth on a planned %s source", (_kind, server) => {
  Object.assign(server.source, { oauthProfileId });

  expect(() => plan(server)).toThrow();
});

test.each([
  [
    "bearer",
    /conflicting upstream authentication/i,
    (server: ServerCandidate) => {
      if (server.source.kind === "stdio" || server.source.kind === "websocket") throw new Error();
      server.source.bearerTokenEnvVar = "TOKEN";
    },
  ],
  [
    "Authorization",
    /conflicting upstream authentication/i,
    (server: ServerCandidate) => {
      if (server.source.kind === "stdio") throw new Error();
      server.source.headers = [{ name: "Authorization", environmentVariable: "AUTH" }];
      if (server.upstream.kind === "stdio") throw new Error();
      server.upstream.headers = [["Authorization", "hidden"]];
    },
  ],
  [
    "master-key selector",
    /master key/i,
    (server: ServerCandidate) => {
      if (server.source.kind === "stdio") throw new Error();
      server.source.headers = [
        {
          name: "X-Key",
          environmentVariable: MASTER_KEY_FILE_ENV.toLowerCase(),
        },
      ];
      if (server.upstream.kind === "stdio") throw new Error();
      server.upstream.headers = [["X-Key", "hidden"]];
    },
  ],
] as const)("rejects planned OAuth conflict with %s", (_kind, message, mutate) => {
  const server = oauthRemoteServer("http");
  mutate(server);

  expect(() => plan(server)).toThrow(message);
});

test.each(["c2VjcmV0=", "_w"])(
  "rejects invalid base64url header environment value before planning: %s",
  (value) => {
    const server = remoteServer("http");
    server.wrapperEnvironment = {
      env: {
        PLAIN_ENV: "plain-secret",
        ENCODED_ENV: value,
        BEARER_ENV: "bearer-secret",
      },
    };

    expect(() =>
      planManagedWrapper({
        server,
        allowedTools: [],
        policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
        restrictor: { command: "mcp-restrictor", argsPrefix: [] },
        projectRoot: "/repo",
      }),
    ).toThrow("invalid upstream header value for X-Encoded");
  },
);

test.each([
  ["unsafe URL", { url: "https://example.test/mcp?secret=value" }],
  [
    "duplicate headers",
    {
      headers: [
        ["X-Plain", "plain-secret"],
        ["x-plain", "other"],
      ],
    },
  ],
] as const)(
  "rejects invalid effective remote configuration before planning: %s",
  (_case, override) => {
    const server = remoteServer("http");
    Object.assign(server.upstream, override);

    expect(() =>
      planManagedWrapper({
        server,
        allowedTools: [],
        policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
        restrictor: { command: "mcp-restrictor", argsPrefix: [] },
        projectRoot: "/repo",
      }),
    ).toThrow();
  },
);

test("parses a managed STDIO wrapper exactly", () => {
  expect(
    parseManagedWrapper("mcp-restrictor", [
      "--policy",
      "/tmp/read.yaml",
      "--upstream-env",
      "TOKEN",
      "--upstream-cwd",
      "/workspace",
      "--",
      "node",
      "server.mjs",
    ]),
  ).toEqual({
    policyArgument: "/tmp/read.yaml",
    source: {
      kind: "stdio",
      command: "node",
      args: ["server.mjs"],
      envNames: ["TOKEN"],
      cwd: "/workspace",
    },
  });
});

test.each([
  "/trusted/bin/mcp-restrictor",
  "C:\\trusted\\mcp-restrictor.CMD",
  "C:\\trusted\\mcp-restrictor.exe",
  "C:\\trusted\\mcp-restrictor.bat",
  "C:\\trusted\\mcp-restrictor.com",
])("round trips a generated wrapper pinned to %s", (command) => {
  const planned = planManagedWrapper({
    server: stdioServer(),
    allowedTools: [],
    policy: {
      diskPath: "/repo/.mcp-restrictor/policies/codex/files.yaml",
      argument: ".mcp-restrictor/policies/codex/files.yaml",
    },
    restrictor: { command, argsPrefix: [] },
    projectRoot: "/repo",
  });

  expect(parseManagedWrapper(planned.replacement.command, planned.replacement.args)).toEqual({
    policyArgument: ".mcp-restrictor/policies/codex/files.yaml",
    source: {
      kind: "stdio",
      command: "${NODE}",
      args: ["${SERVER_FILE}"],
      envNames: ["TOKEN"],
      cwd: "${SERVER_CWD}",
    },
  });
});

test.each(["/trusted/bin/mcp-restrictor", "C:\\trusted\\mcp-restrictor.exe"])(
  "rejects an absolute nested managed wrapper: %s",
  (nestedCommand) => {
    expect(
      parseManagedWrapper("mcp-restrictor", [
        "--policy",
        "/tmp/policy.yaml",
        "--",
        nestedCommand,
        "--policy",
        "/tmp/nested.yaml",
        "--",
        "node",
      ]),
    ).toBeUndefined();
  },
);

test.each(["/trusted/bin/not-mcp-restrictor", "C:\\trusted\\mcp-restrictor.ps1"])(
  "does not recognize an arbitrary executable basename: %s",
  (command) => {
    expect(
      parseManagedWrapper(command, ["--policy", "/tmp/policy.yaml", "--", "node"]),
    ).toBeUndefined();
  },
);

test("parses an HTTP bearer wrapper without exposing a token", () => {
  expect(
    parseManagedWrapper("mcp-restrictor", [
      "--policy",
      "/tmp/read.yaml",
      "--upstream-http",
      "https://example.test/mcp",
      "--upstream-bearer-token-env",
      "MCP_TOKEN",
    ]),
  ).toEqual({
    policyArgument: "/tmp/read.yaml",
    source: {
      kind: "http",
      url: "https://example.test/mcp",
      headers: [],
      bearerTokenEnvVar: "MCP_TOKEN",
    },
  });
});

test.each([
  ["another command", "node", ["--policy", "/tmp/policy.yaml", "--", "node"]],
  ["absolute missing policy", "/trusted/bin/mcp-restrictor", ["--", "node"]],
  ["missing policy", "mcp-restrictor", ["--", "node"]],
  ["empty policy", "mcp-restrictor", ["--policy", "", "--", "node"]],
  ["duplicate policy", "mcp-restrictor", ["--policy", "a", "--policy", "b", "--", "node"]],
  ["missing value", "mcp-restrictor", ["--policy", "--", "node"]],
  [
    "HTTP with STDIO environment",
    "mcp-restrictor",
    ["--policy", "a", "--upstream-http", "https://example.test", "--upstream-env", "TOKEN"],
  ],
  [
    "STDIO with HTTP bearer",
    "mcp-restrictor",
    ["--policy", "a", "--upstream-bearer-token-env", "TOKEN", "--", "node"],
  ],
  [
    "nested restrictor",
    "mcp-restrictor",
    ["--policy", "a", "--", "mcp-restrictor", "--policy", "b", "--", "node"],
  ],
] as const)("rejects malformed managed wrapper: %s", (_reason, command, args) => {
  expect(parseManagedWrapper(command, args)).toBeUndefined();
});

test("returns client-neutral project policy paths and absolute safe arguments", () => {
  expect(
    policyLocation({
      client: "claude",
      scope: "project",
      serverName: "a/b",
      projectRoot: "/repo",
      restrictorHome: "/home/me/.mcp-restrictor",
    }),
  ).toEqual({
    diskPath: "/repo/.mcp-restrictor/policies/claude/a%2Fb.yaml",
    relativePath: ".mcp-restrictor/policies/claude/a%2Fb.yaml",
    argument: "/repo/.mcp-restrictor/policies/claude/a%2Fb.yaml",
  });
  expect(
    policyLocation({
      client: "codex",
      scope: "project",
      serverName: "a/b",
      projectRoot: "/repo",
      restrictorHome: "/home/me/.mcp-restrictor",
    }),
  ).toEqual({
    diskPath: "/repo/.mcp-restrictor/policies/codex/a%2Fb.yaml",
    relativePath: ".mcp-restrictor/policies/codex/a%2Fb.yaml",
    argument: "/repo/.mcp-restrictor/policies/codex/a%2Fb.yaml",
  });
  expect(
    policyLocation({
      client: "codex",
      scope: "user",
      serverName: "a b",
      projectRoot: "/repo",
      restrictorHome: "/home/me/.mcp-restrictor",
    }),
  ).toEqual({
    diskPath: "/home/me/.mcp-restrictor/policies/codex/a%20b.yaml",
    relativePath: ".mcp-restrictor/policies/codex/a%20b.yaml",
    argument: "/home/me/.mcp-restrictor/policies/codex/a%20b.yaml",
  });
});

test("plans a project Codex STDIO wrapper and verifies its expanded upstream", () => {
  const server = stdioServer();
  const planned = planManagedWrapper({
    server,
    allowedTools: ["read_file"],
    policy: {
      diskPath: "/repo/.mcp-restrictor/policies/codex/files.yaml",
      argument: ".mcp-restrictor/policies/codex/files.yaml",
    },
    restrictor: { command: "node", argsPrefix: ["/tool/mcp-restrictor.js"] },
    projectRoot: "/repo",
    wrapperCwd: "/repo",
  });

  expect(planned).toEqual({
    replacement: {
      command: "node",
      args: [
        "/tool/mcp-restrictor.js",
        "--policy",
        ".mcp-restrictor/policies/codex/files.yaml",
        "--upstream-env",
        "TOKEN",
        "--upstream-cwd",
        "${SERVER_CWD}",
        "--",
        "${NODE}",
        "${SERVER_FILE}",
      ],
      env: { EXPLICIT: "configured" },
      envVars: ["TOKEN"],
      cwd: "/repo",
    },
    policySource:
      "version: 1\ndefault: deny\ntools:\n  allow:\n    - name: read_file\n  deny: []\n",
    verificationUpstream: {
      kind: "stdio",
      command: "node",
      args: [
        "/tool/mcp-restrictor.js",
        "--policy",
        "/repo/.mcp-restrictor/policies/codex/files.yaml",
        "--upstream-env",
        "TOKEN",
        "--upstream-cwd",
        "/expanded/server",
        "--",
        "/usr/local/bin/node",
        "/expanded/server.mjs",
      ],
      env: { EXPLICIT: "configured", TOKEN: "secret" },
      cwd: "/repo",
    },
  });
});

test("keeps a user Codex upstream cwd only in the child arguments", () => {
  const planned = planManagedWrapper({
    server: {
      ...stdioServer(),
      scope: "user",
      configPath: "/home/me/.codex/config.toml",
    },
    allowedTools: [],
    policy: {
      diskPath: "/home/me/.mcp-restrictor/policies/codex/files.yaml",
      argument: "/home/me/.mcp-restrictor/policies/codex/files.yaml",
    },
    restrictor: { command: "mcp-restrictor", argsPrefix: [] },
    projectRoot: "/repo",
  });

  expect(planned.replacement).not.toHaveProperty("cwd");
  expect(planned.replacement.args).toEqual([
    "--policy",
    "/home/me/.mcp-restrictor/policies/codex/files.yaml",
    "--upstream-env",
    "TOKEN",
    "--upstream-cwd",
    "${SERVER_CWD}",
    "--",
    "${NODE}",
    "${SERVER_FILE}",
  ]);
  expect(planned.verificationUpstream).toEqual({
    kind: "stdio",
    command: "mcp-restrictor",
    args: [
      "--policy",
      "/home/me/.mcp-restrictor/policies/codex/files.yaml",
      "--upstream-env",
      "TOKEN",
      "--upstream-cwd",
      "/expanded/server",
      "--",
      "/usr/local/bin/node",
      "/expanded/server.mjs",
    ],
    env: { EXPLICIT: "configured", TOKEN: "secret" },
  });
});

test("keeps OpenCode substitution values out of argv and separates wrapper and upstream cwd", () => {
  const secret = "wrapper-secret-value";
  const planned = planManagedWrapper({
    server: {
      client: "opencode",
      scope: "project",
      name: "files",
      configPath: "/repo/opencode.jsonc",
      source: {
        kind: "stdio",
        command: "node",
        args: ["server.mjs"],
        envNames: ["API_KEY"],
        cwd: "/upstream",
      },
      upstream: {
        kind: "stdio",
        command: "node",
        args: ["server.mjs"],
        env: { API_KEY: secret },
        cwd: "/upstream",
      },
      wrapperEnvironment: { env: { API_KEY: "{file:secrets/key}" } },
      original: {},
    },
    allowedTools: [],
    policy: {
      diskPath: "/repo/.mcp-restrictor/policies/opencode/files.yaml",
      argument: ".mcp-restrictor/policies/opencode/files.yaml",
    },
    restrictor: { command: "mcp-restrictor", argsPrefix: [] },
    wrapperCwd: "/repo",
  });

  expect(planned.replacement).toMatchObject({
    cwd: "/repo",
    env: { API_KEY: "{file:secrets/key}" },
  });
  expect(planned.replacement.args).toEqual([
    "--policy",
    ".mcp-restrictor/policies/opencode/files.yaml",
    "--upstream-env",
    "API_KEY",
    "--upstream-cwd",
    "/upstream",
    "--",
    "node",
    "server.mjs",
  ]);
  expect(JSON.stringify(planned.replacement.args)).not.toContain(secret);
  expect(planned.verificationUpstream).toMatchObject({ cwd: "/repo" });
});

test.each([
  ["empty", ""],
  ["leading-dash", "-TOKEN"],
])("rejects an invalid upstream environment variable name (%s) before planning", (_case, name) => {
  const server = stdioServer();
  if (server.source.kind !== "stdio") throw new Error("expected STDIO source");
  server.source.envNames = [name];

  expect(() =>
    planManagedWrapper({
      server,
      allowedTools: [],
      policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
      restrictor: { command: "mcp-restrictor", argsPrefix: [] },
      projectRoot: "/repo",
    }),
  ).toThrowError(new Error("invalid upstream environment variable name"));
});

test.each([
  [
    "STDIO inherited env",
    () => {
      const server = stdioServer();
      if (server.source.kind !== "stdio") throw new Error();
      server.source.envNames = ["MCP_RESTRICTOR_CONTAINER"];
      return server;
    },
  ],
  [
    "header env mapping",
    () => {
      const server = remoteServer("http");
      if (server.source.kind === "stdio") throw new Error();
      server.source.headers[0] = {
        name: "X-Plain",
        environmentVariable: "MCP_RESTRICTOR_CONTAINER",
      };
      return server;
    },
  ],
  [
    "bearer env name",
    () => {
      const server = remoteServer("http");
      if (server.source.kind === "stdio" || server.source.kind === "websocket") throw new Error();
      server.source.bearerTokenEnvVar = "MCP_RESTRICTOR_CONTAINER";
      return server;
    },
  ],
] as const)(
  "rejects reserved upstream environment before wrapper planning: %s",
  (_case, server) => {
    expect(() => plan(server())).toThrow(/reserved upstream environment/i);
  },
);

test("rejects a resolved STDIO container marker omitted from the source selectors", () => {
  const server = stdioServer();
  if (server.source.kind !== "stdio" || server.upstream.kind !== "stdio") throw new Error();
  server.source.envNames = [];
  server.upstream.env = { MCP_RESTRICTOR_CONTAINER: "marker-value" };

  expect(() => plan(server)).toThrow(/invalid STDIO upstream/i);
});

test("keeps the container marker out of wrapper route args and gives it to OAuth verification", () => {
  const server = oauthRemoteServer("http");
  server.wrapperEnvironment.env!.MCP_RESTRICTOR_CONTAINER = "must-not-persist";
  const planned = planManagedWrapper({
    server,
    allowedTools: [],
    policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
    restrictor: { command: "mcp-restrictor", argsPrefix: [] },
    projectRoot: "/repo",
    verificationEnvironment: { MCP_RESTRICTOR_CONTAINER: "1" },
  });

  expect(planned.replacement.args).not.toContain("MCP_RESTRICTOR_CONTAINER");
  expect(planned.replacement.env).not.toHaveProperty("MCP_RESTRICTOR_CONTAINER");
  expect(JSON.stringify(planned.replacement)).not.toContain("must-not-persist");
  expect(planned.verificationUpstream).toMatchObject({
    kind: "stdio",
    env: { MCP_RESTRICTOR_CONTAINER: "1" },
  });
  if (planned.verificationUpstream.kind !== "stdio") throw new Error();
  expect(planned.verificationUpstream.args).not.toContain("MCP_RESTRICTOR_CONTAINER");
});

test.each([
  ["empty", ""],
  ["leading-dash", "-TOKEN"],
])(
  "rejects an invalid HTTP bearer environment variable name (%s) before planning",
  (_case, name) => {
    const server: ServerCandidate = {
      client: "codex",
      scope: "user",
      name: "remote",
      configPath: "/home/me/.codex/config.toml",
      source: {
        kind: "http",
        url: "https://example.test/mcp",
        headers: [],
        bearerTokenEnvVar: name,
      },
      upstream: {
        kind: "http",
        url: "https://example.test/mcp",
        bearerToken: "secret",
      },
      wrapperEnvironment: { envVars: [name] },
      original: {},
    };

    expect(() =>
      planManagedWrapper({
        server,
        allowedTools: [],
        policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
        restrictor: { command: "mcp-restrictor", argsPrefix: [] },
        projectRoot: "/repo",
      }),
    ).toThrowError(new Error("invalid upstream environment variable name"));
  },
);

test.each([
  ["empty", ""],
  ["leading-dash", "--sandbox"],
])("rejects an invalid upstream cwd (%s) before planning", (_case, cwd) => {
  const server = stdioServer();
  if (server.source.kind !== "stdio") throw new Error("expected STDIO source");
  server.source.cwd = cwd;

  expect(() =>
    planManagedWrapper({
      server,
      allowedTools: [],
      policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
      restrictor: { command: "mcp-restrictor", argsPrefix: [] },
      projectRoot: "/repo",
    }),
  ).toThrowError(new Error("invalid upstream working directory"));
});

test("keeps HTTP bearer tokens out of the rendered wrapper and permits no tools", () => {
  const server: ServerCandidate = {
    client: "claude",
    scope: "user",
    name: "remote",
    configPath: "/home/me/.claude.json",
    source: {
      kind: "http",
      url: "${MCP_URL}",
      headers: [],
      bearerTokenEnvVar: "MCP_TOKEN",
    },
    upstream: {
      kind: "http",
      url: "https://example.test/mcp",
      bearerToken: "secret",
    },
    wrapperEnvironment: { env: { MCP_TOKEN: "${MCP_TOKEN}" } },
    original: {},
  };

  const planned = planManagedWrapper({
    server,
    allowedTools: [],
    policy: {
      diskPath: "/home/me/.mcp-restrictor/policies/claude/remote.yaml",
      argument: "/home/me/.mcp-restrictor/policies/claude/remote.yaml",
    },
    restrictor: { command: "mcp-restrictor", argsPrefix: [] },
    projectRoot: "/repo",
  });
  expect(planned).toEqual({
    replacement: {
      command: "mcp-restrictor",
      args: [
        "--policy",
        "/home/me/.mcp-restrictor/policies/claude/remote.yaml",
        "--upstream-http",
        "${MCP_URL}",
        "--upstream-bearer-token-env",
        "MCP_TOKEN",
      ],
      env: { MCP_TOKEN: "${MCP_TOKEN}" },
    },
    policySource: "version: 1\ndefault: deny\ntools:\n  allow: []\n  deny: []\n",
    verificationUpstream: {
      kind: "stdio",
      command: "mcp-restrictor",
      args: [
        "--policy",
        "/home/me/.mcp-restrictor/policies/claude/remote.yaml",
        "--upstream-http",
        "https://example.test/mcp",
        "--upstream-bearer-token-env",
        "MCP_TOKEN",
      ],
      env: { MCP_TOKEN: "secret" },
    },
  });
  expect(JSON.stringify(planned.replacement)).not.toContain("secret");
  expect(planned.policySource).not.toContain("secret");
});

function stdioServer(): ServerCandidate {
  return {
    client: "codex",
    scope: "project",
    name: "files",
    configPath: "/repo/.codex/config.toml",
    source: {
      kind: "stdio",
      command: "${NODE}",
      args: ["${SERVER_FILE}"],
      envNames: ["TOKEN"],
      cwd: "${SERVER_CWD}",
    },
    upstream: {
      kind: "stdio",
      command: "/usr/local/bin/node",
      args: ["/expanded/server.mjs"],
      env: { EXPLICIT: "configured", TOKEN: "secret" },
      cwd: "/expanded/server",
    },
    wrapperEnvironment: { env: { EXPLICIT: "configured" }, envVars: ["TOKEN"] },
    original: {},
  };
}

function remoteServer(kind: "http" | "sse" | "websocket"): ServerCandidate {
  const url = kind === "websocket" ? "wss://example.test/mcp" : `https://example.test/${kind}`;
  const headers = [
    { name: "X-Plain", environmentVariable: "PLAIN_ENV" },
    {
      name: "X-Encoded",
      environmentVariable: "ENCODED_ENV",
      encoding: "base64url" as const,
    },
  ];
  const source =
    kind === "websocket"
      ? { kind, url, headers }
      : { kind, url, headers, bearerTokenEnvVar: "BEARER_ENV" };
  const upstream =
    kind === "websocket"
      ? {
          kind,
          url,
          headers: [
            ["X-Plain", "plain-secret"],
            ["X-Encoded", "encoded-secret"],
          ] as const,
        }
      : {
          kind,
          url,
          headers: [
            ["X-Plain", "plain-secret"],
            ["X-Encoded", "encoded-secret"],
          ] as const,
          bearerToken: "bearer-secret",
        };
  return {
    client: "claude",
    scope: "user",
    name: "remote",
    configPath: "/home/me/.claude.json",
    source,
    upstream,
    wrapperEnvironment: {
      env: {
        PLAIN_ENV: "plain-secret",
        ENCODED_ENV: "ZW5jb2RlZC1zZWNyZXQ",
        ...(kind === "websocket" ? {} : { BEARER_ENV: "bearer-secret" }),
      },
    },
    original: {},
  } as ServerCandidate;
}

function oauthRemoteServer(kind: "http" | "sse"): ServerCandidate {
  return {
    client: "claude",
    scope: "user",
    name: "oauth",
    configPath: "/home/me/.claude.json",
    source: {
      kind,
      url: `https://example.test/${kind}`,
      headers: [{ name: "X-Plain", environmentVariable: "PLAIN_ENV" }],
      oauthProfileId,
    },
    upstream: {
      kind,
      url: `https://example.test/${kind}`,
      headers: [["X-Plain", "plain-secret"]],
    },
    wrapperEnvironment: {
      env: {
        PLAIN_ENV: "plain-secret",
        [MASTER_KEY_FILE_ENV]: "/keys/oauth-master.key",
        UNRELATED_ENV: "wrapper-only",
      },
    },
    oauth: {
      mode: "explicit",
      requestedScope: "read",
      callback: {
        host: "localhost",
        path: "/callback",
        port: 41_337,
        appendProfileId: false,
      },
    },
    original: {},
  };
}

function plan(server: ServerCandidate) {
  return planManagedWrapper({
    server,
    allowedTools: [],
    policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
    restrictor: { command: "mcp-restrictor", argsPrefix: [] },
    projectRoot: "/repo",
  });
}
