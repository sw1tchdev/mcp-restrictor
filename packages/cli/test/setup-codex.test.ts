import { mkdtemp, mkdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parse } from "smol-toml";
import { expect, test, vi } from "vitest";
import { MASTER_KEY_FILE_ENV } from "../src/oauth/storage.ts";
import {
  codexConfigPaths,
  codexAdapter,
  installCodexConfig,
  installCodexHttpConfig,
  parseCodexConfig,
  renderCodexConfig,
  restoreCodexConfig,
} from "../src/setup/codex.ts";
import { readSnapshot } from "../src/setup/transaction.ts";
import { planManagedWrapper } from "../src/setup/wrapper.ts";

const options = {
  path: "/home/me/.codex/config.toml",
  scope: "user" as const,
  environment: {
    TOKEN: "forwarded-secret",
    DOCS_TOKEN: "bearer-secret",
    REMOTE: "must-not-leak",
  },
};

const oauthProfileId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const nativeHttpUrl =
  "http://127.0.0.1:7319/mcp/codex/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function manualCodexEntry(overrides: Record<string, unknown> = {}) {
  return {
    name: "manual",
    command: "mcp-restrictor",
    args: ["--policy", ".mcp-restrictor/policies/codex/manual.yaml", "--", "node", "server.mjs"],
    environment: { inherit: ["TOKEN"], set: { FIXED: "fixed-value" } },
    ...overrides,
  };
}

test.each([
  ["empty TOML", ""],
  [
    "root-only CRLF TOML",
    '# keep this comment\r\nmodel  =  "gpt-5" # preserve spacing\r\n[projects.local]\r\ntrusted = true\r\n',
  ],
] as const)(
  "appends a manual Codex wrapper to %s without rewriting its prefix",
  (_name, source) => {
    const config = parseCodexConfig({ ...options, source });
    const rendered = installCodexConfig(config, manualCodexEntry({ cwd: "/repo" }));

    expect(rendered.startsWith(source)).toBe(true);
    expect(rendered.slice(0, source.length)).toBe(source);
    expect(rendered.slice(source.length)).toMatch(
      source ? /^\n\[mcp_servers\.manual\]\n/ : /^\[mcp_servers\.manual\]\n/,
    );
    const parsed = parse(rendered) as Record<string, unknown>;
    expect(parsed).toMatchObject({
      mcp_servers: {
        manual: {
          command: "mcp-restrictor",
          args: [
            "--policy",
            ".mcp-restrictor/policies/codex/manual.yaml",
            "--",
            "node",
            "server.mjs",
          ],
          env_vars: ["TOKEN"],
          cwd: "/repo",
          env: { FIXED: "fixed-value" },
        },
      },
    });
    expect(
      ((parsed.mcp_servers as Record<string, unknown>).manual as Record<string, unknown>).env,
    ).toEqual({
      FIXED: "fixed-value",
    });
    expect(
      parseCodexConfig({ ...options, source: rendered }).servers.find(
        ({ name }) => name === "manual",
      ),
    ).toMatchObject({ managedPolicyPath: "/repo/.mcp-restrictor/policies/codex/manual.yaml" });
  },
);

test("encodes dotted Codex names and preserves prototype-like names as own properties", () => {
  const rendered = installCodexConfig(
    parseCodexConfig({ ...options, source: "" }),
    manualCodexEntry({
      name: "manual.dot",
      args: ["--policy", "/policy.yaml", "--upstream-env", "__proto__", "--", "node"],
      environment: { inherit: ["__proto__"], set: { constructor: "fixed-value" } },
    }),
  );
  const parsed = parse(rendered) as Record<string, unknown>;
  const servers = parsed.mcp_servers as Record<string, unknown>;
  const manual = servers["manual.dot"] as Record<string, unknown>;
  const env = manual.env as Record<string, unknown>;

  expect(rendered).toContain('[mcp_servers."manual.dot"]');
  expect(Object.hasOwn(servers, "manual.dot")).toBe(true);
  expect(Object.hasOwn(env, "constructor")).toBe(true);
  expect(manual.env_vars).toEqual(["__proto__"]);
  expect(manual).not.toHaveProperty("cwd");

  const prototype = parse(
    installCodexConfig(
      parseCodexConfig({ ...options, source: "" }),
      manualCodexEntry({ name: "__proto__", args: ["--policy", "/policy.yaml", "--", "node"] }),
    ),
  ) as Record<string, unknown>;
  expect(Object.hasOwn(prototype.mcp_servers as Record<string, unknown>, "__proto__")).toBe(true);
});

test.each([
  '[mcp_servers.manual]\ncommand = "node"\nargs = []\n',
  "[mcp_servers.manual]\nenabled = false\n",
] as const)("refuses manual Codex installation when an existing server owns the name", (source) => {
  expect(() =>
    installCodexConfig(parseCodexConfig({ ...options, source }), manualCodexEntry()),
  ).toThrow("Codex server name already exists");
});

test("exposes manual Codex installation through the adapter", () => {
  expect(codexAdapter.install).toBe(installCodexConfig);
});

test.each([
  ["absent container", ""],
  [
    "existing container",
    '# keep exact bytes\r\nmodel  =  "gpt-5"\r\n[mcp_servers.existing]\r\ncommand = "node"\r\nargs = []\r\n',
  ],
] as const)("native HTTP install appends the exact Codex table to an %s", (_name, source) => {
  const rendered = installCodexHttpConfig(parseCodexConfig({ ...options, source }), {
    name: "gateway",
    url: nativeHttpUrl,
  });
  const parsed = parse(rendered) as Record<string, any>;
  const reparsed = parseCodexConfig({ ...options, source: rendered });
  const candidate = reparsed.servers.find(({ name }) => name === "gateway");

  expect(rendered.slice(0, source.length)).toBe(source);
  expect(parsed.mcp_servers.gateway).toEqual({ url: nativeHttpUrl });
  expect(candidate?.source).toEqual({ kind: "http", url: nativeHttpUrl, headers: [] });
  expect(candidate).not.toHaveProperty("managedPolicyPath");
  expect(reparsed.unsupported).toEqual([]);
  expect(reparsed.servers).toHaveLength(source ? 2 : 1);
  expect(JSON.stringify(parsed.mcp_servers.gateway)).not.toMatch(
    /command|policy|env|oauth|profile|upstream|header|authorization/i,
  );
});

test("native HTTP install handles Codex collisions and prototype-like names", () => {
  for (const source of [
    '[mcp_servers.gateway]\nurl = "https://example.test/mcp"\n',
    "[mcp_servers.gateway]\nenabled = false\n",
  ]) {
    expect(() =>
      installCodexHttpConfig(parseCodexConfig({ ...options, source }), {
        name: "gateway",
        url: nativeHttpUrl,
      }),
    ).toThrow("Codex server name already exists");
  }

  const rendered = installCodexHttpConfig(parseCodexConfig({ ...options, source: "" }), {
    name: "__proto__",
    url: nativeHttpUrl,
  });
  expect(Object.hasOwn((parse(rendered) as any).mcp_servers, "__proto__")).toBe(true);
});

test("native HTTP install is removed by exact created-entry Codex Restore", () => {
  const source = '# unrelated bytes stay\nmodel = "gpt-5"\n';
  const installed = installCodexHttpConfig(parseCodexConfig({ ...options, source }), {
    name: "gateway",
    url: nativeHttpUrl,
  });
  const restored = restoreCodexConfig(
    parseCodexConfig({ ...options, source: installed }),
    [{ name: "gateway", originalSource: source, installedSource: installed, created: true }],
    { home: "/home/me", projectRoot: "/repo", cwd: "/repo", environment: options.environment },
  );

  expect(restored).toBe(source);
});

test("native HTTP Codex Restore removes its separator after a no-final-newline source", () => {
  const source = '# exact prefix\nmodel = "gpt-5"';
  const installed = installCodexHttpConfig(parseCodexConfig({ ...options, source }), {
    name: "gateway",
    url: nativeHttpUrl,
  });
  const restored = restoreCodexConfig(
    parseCodexConfig({ ...options, source: installed }),
    [{ name: "gateway", originalSource: source, installedSource: installed, created: true }],
    { home: "/home/me", projectRoot: "/repo", cwd: "/repo", environment: options.environment },
  );

  expect(installed.slice(0, source.length)).toBe(source);
  expect(restored).toBe(source);
});

test.each([
  ["changed prefix", "# keep before gateway\n"],
  ["unchanged prefix", ""],
] as const)(
  "native HTTP Codex Restore keeps its separator with a %s and trailing user table",
  (_name, beforeGateway) => {
    const source = '# exact prefix\nmodel = "gpt-5"';
    const installed = installCodexHttpConfig(parseCodexConfig({ ...options, source }), {
      name: "gateway",
      url: nativeHttpUrl,
    });
    const userTable = '[user_settings]\nvalue = "keep"\n';
    const current = `${installed.replace(
      "\n[mcp_servers.gateway]",
      `\n${beforeGateway}[mcp_servers.gateway]`,
    )}${userTable}`;
    const restored = restoreCodexConfig(
      parseCodexConfig({ ...options, source: current }),
      [{ name: "gateway", originalSource: source, installedSource: installed, created: true }],
      { home: "/home/me", projectRoot: "/repo", cwd: "/repo", environment: options.environment },
    );

    expect(restored).toBe(`${source}\n${beforeGateway}${userTable}`);
    expect((parse(restored) as any).user_settings).toEqual({ value: "keep" });
  },
);

test("delegates Codex configuration loading, rendering, and completion to the existing parser", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-codex-adapter-")));
  const home = join(root, "home");
  const projectRoot = join(root, "project");
  const path = join(home, ".codex", "config.toml");
  const source = '[mcp_servers.files]\ncommand = "node"\nargs = ["server.mjs"]\n';
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, source);
  const host = {
    readConfig: vi.fn((configPath: string) => readSnapshot(configPath)),
    readSecretFile: vi.fn(),
  };

  try {
    const result = await codexAdapter.load(
      { home, projectRoot, cwd: projectRoot, environment: {} },
      host,
    );
    const config = result.configurations[0]!.config;
    const replacements = new Map([
      ["files", { command: "mcp-restrictor", args: ["--policy", "/policy.yaml"] }],
    ]);

    expect(result.configurations.map(({ config }) => config.client)).toEqual(["codex"]);
    expect(host.readConfig).toHaveBeenCalledWith(path);
    expect(codexAdapter.render(config, replacements)).toBe(renderCodexConfig(config, replacements));
    expect(codexAdapter.completionMessage?.({ projectRoot })).toContain(
      "Restart Codex in a trusted project.",
    );
    expect(
      codexAdapter.projectWrapper?.({
        projectRoot,
        relativePolicyPath: ".mcp-restrictor/policies/codex/files.yaml",
        diskPolicyPath: join(projectRoot, ".mcp-restrictor/policies/codex/files.yaml"),
      }),
    ).toEqual({
      policyArgument: ".mcp-restrictor/policies/codex/files.yaml",
      cwd: projectRoot,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("uses the documented user and project Codex configuration paths", () => {
  expect(codexConfigPaths({ home: "/home/me", projectRoot: "/repo", environment: {} })).toEqual({
    user: "/home/me/.codex/config.toml",
    project: "/repo/.codex/config.toml",
  });
  expect(
    codexConfigPaths({
      home: "/home/me",
      projectRoot: "/repo",
      environment: { CODEX_HOME: "/config" },
    }),
  ).toEqual({ user: "/config/config.toml", project: "/repo/.codex/config.toml" });
});

test("imports static and environment HTTP headers with exact Codex OAuth metadata", () => {
  const keyPath = resolve("keys/codex-master.key");
  const environment: NodeJS.ProcessEnv = {
    ...options.environment,
    MCP_RESTRICTOR_UPSTREAM_HEADER_0: "occupied-by-process",
    MCP_RESTRICTOR_UPSTREAM_HEADER_1: "environment-header-secret",
    [MASTER_KEY_FILE_ENV]: "keys/codex-master.key",
  };
  Object.defineProperty(environment, "__proto__", {
    value: "own-prototype-secret",
    enumerable: true,
    configurable: true,
  });
  const source = `# keep root bytes
mcp_oauth_callback_port = 0
mcp_oauth_callback_url = "https://callback.example/base?tenant=one"
mcp_oauth_credentials_store = "keyring"
experimental_use_rmcp_client = true

[mcp_servers.remote]
url = "https://example.test/mcp"
auth = "oauth"
scopes = ["write", "read"]
oauth_resource = "urn:example:resource"
http_headers = { "X-Static" = "static-secret", "X-Other" = "other-literal" }
env_http_headers = { "X-Env" = "MCP_RESTRICTOR_UPSTREAM_HEADER_1", "X-Reused" = "MCP_RESTRICTOR_UPSTREAM_HEADER_1", "X-Proto" = "__proto__" }
enabled_tools = ["search", "read"]
disabled_tools = ["delete", "write"]
`;

  const parsed = parseCodexConfig({ ...options, source, environment });
  const [candidate] = parsed.servers;

  expect(parsed.unsupported).toEqual([]);
  expect(candidate).toEqual({
    client: "codex",
    scope: "user",
    name: "remote",
    configPath: "/home/me/.codex/config.toml",
    source: {
      kind: "http",
      url: "https://example.test/mcp",
      headers: [
        { name: "X-Static", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_2" },
        { name: "X-Other", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_3" },
        { name: "X-Env", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_1" },
        { name: "X-Reused", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_1" },
        { name: "X-Proto", environmentVariable: "__proto__" },
      ],
    },
    upstream: {
      kind: "http",
      url: "https://example.test/mcp",
      headers: [
        ["X-Static", "static-secret"],
        ["X-Other", "other-literal"],
        ["X-Env", "environment-header-secret"],
        ["X-Reused", "environment-header-secret"],
        ["X-Proto", "own-prototype-secret"],
      ],
    },
    wrapperEnvironment: {
      env: {
        MCP_RESTRICTOR_UPSTREAM_HEADER_2: "static-secret",
        MCP_RESTRICTOR_UPSTREAM_HEADER_3: "other-literal",
        [MASTER_KEY_FILE_ENV]: keyPath,
      },
      envVars: ["MCP_RESTRICTOR_UPSTREAM_HEADER_1", "__proto__"],
    },
    oauth: {
      mode: "explicit",
      fallbackScope: "write read",
      resource: "urn:example:resource",
      callback: {
        url: "https://callback.example/base?tenant=one",
        port: 0,
        appendProfileId: true,
      },
    },
    original: {
      url: "https://example.test/mcp",
      auth: "oauth",
      scopes: ["write", "read"],
      oauth_resource: "urn:example:resource",
      http_headers: { "X-Static": "static-secret", "X-Other": "other-literal" },
      env_http_headers: {
        "X-Env": "MCP_RESTRICTOR_UPSTREAM_HEADER_1",
        "X-Reused": "MCP_RESTRICTOR_UPSTREAM_HEADER_1",
        "X-Proto": "__proto__",
      },
      enabled_tools: ["search", "read"],
      disabled_tools: ["delete", "write"],
    },
  });
  expect(candidate?.oauth).not.toHaveProperty("requestedScope");
  expect(
    JSON.stringify({ source: candidate?.source, wrapper: candidate?.wrapperEnvironment }),
  ).not.toContain("environment-header-secret");
  expect(
    JSON.stringify({ source: candidate?.source, wrapper: candidate?.wrapperEnvironment }),
  ).not.toContain("own-prototype-secret");
  expect(renderCodexConfig(parsed, new Map())).toBe(source);

  const planned = planManagedWrapper({
    server: candidate!,
    allowedTools: [],
    policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
    restrictor: { command: "mcp-restrictor", argsPrefix: [] },
    projectRoot: "/repo",
  });
  expect(planned.replacement.env).toEqual(candidate?.wrapperEnvironment.env);
  expect(planned.replacement.envVars).toEqual(candidate?.wrapperEnvironment.envVars);
  expect(planned.policySource).toBe("version: 1\ndefault: deny\ntools:\n  allow: []\n  deny: []\n");
  expect(JSON.stringify(planned.replacement.args)).not.toMatch(
    /static-secret|environment-header-secret|own-prototype-secret|codex-master\.key/,
  );
});

test("targets challenge storage without changing bearer or literal Authorization ownership", () => {
  const keyPath = resolve("keys/codex-master.key");
  const source = `mcp_oauth_callback_url = "http://127.0.0.1:4321/callback?tenant=one"

[mcp_servers.challenge]
url = "http://example.test/mcp"
scopes = []

[mcp_servers.header_challenge]
url = "https://header.example.test/mcp"
http_headers = { "X-Tenant" = "tenant-one" }

[mcp_servers.bearer]
url = "https://bearer.example.test/mcp"
bearer_token_env_var = "MCP_RESTRICTOR_UPSTREAM_HEADER_1"
http_headers = { "X-Static" = "bearer-literal" }

[mcp_servers.authorization]
url = "https://authorization.example.test/mcp"
http_headers = { "aUtHoRiZaTiOn" = "Bearer \${TOKEN}" }
`;

  const parsed = parseCodexConfig({
    ...options,
    source,
    environment: {
      TOKEN: "must-not-expand",
      MCP_RESTRICTOR_UPSTREAM_HEADER_0: "occupied-by-process",
      MCP_RESTRICTOR_UPSTREAM_HEADER_1: "effective-bearer",
      [MASTER_KEY_FILE_ENV]: "keys/codex-master.key",
    },
  });

  expect(parsed.unsupported).toEqual([]);
  expect(
    parsed.servers.map(({ name, oauth, upstream, wrapperEnvironment }) => ({
      name,
      oauth,
      upstream,
      wrapperEnvironment,
    })),
  ).toEqual([
    {
      name: "challenge",
      oauth: {
        mode: "challenge",
        callback: {
          url: "http://127.0.0.1:4321/callback?tenant=one",
          appendProfileId: true,
        },
      },
      upstream: { kind: "http", url: "http://example.test/mcp" },
      wrapperEnvironment: { env: { [MASTER_KEY_FILE_ENV]: keyPath } },
    },
    {
      name: "header_challenge",
      oauth: {
        mode: "challenge",
        callback: {
          url: "http://127.0.0.1:4321/callback?tenant=one",
          appendProfileId: true,
        },
      },
      upstream: {
        kind: "http",
        url: "https://header.example.test/mcp",
        headers: [["X-Tenant", "tenant-one"]],
      },
      wrapperEnvironment: {
        env: {
          MCP_RESTRICTOR_UPSTREAM_HEADER_2: "tenant-one",
          [MASTER_KEY_FILE_ENV]: keyPath,
        },
      },
    },
    {
      name: "bearer",
      oauth: undefined,
      upstream: {
        kind: "http",
        url: "https://bearer.example.test/mcp",
        headers: [["X-Static", "bearer-literal"]],
        bearerToken: "effective-bearer",
      },
      wrapperEnvironment: {
        env: { MCP_RESTRICTOR_UPSTREAM_HEADER_2: "bearer-literal" },
        envVars: ["MCP_RESTRICTOR_UPSTREAM_HEADER_1"],
      },
    },
    {
      name: "authorization",
      oauth: undefined,
      upstream: {
        kind: "http",
        url: "https://authorization.example.test/mcp",
        headers: [["aUtHoRiZaTiOn", "Bearer ${TOKEN}"]],
      },
      wrapperEnvironment: {
        env: { MCP_RESTRICTOR_UPSTREAM_HEADER_2: "Bearer ${TOKEN}" },
      },
    },
  ]);
  expect(parsed.servers[2]?.wrapperEnvironment.env).not.toHaveProperty(MASTER_KEY_FILE_ENV);
  expect(parsed.servers[3]?.wrapperEnvironment.env).not.toHaveProperty(MASTER_KEY_FILE_ENV);
});

test("rejects structural header and authentication conflicts before reading environment values", () => {
  let reads = 0;
  const environment: NodeJS.ProcessEnv = {};
  for (const name of [
    "UNREAD_SECRET",
    "TOKEN",
    MASTER_KEY_FILE_ENV,
    "mCp_ReStRiCtOr_MaStEr_KeY_fIlE",
  ]) {
    Object.defineProperty(environment, name, {
      enumerable: true,
      configurable: true,
      get() {
        reads += 1;
        return name === MASTER_KEY_FILE_ENV ? "keys/unread.key" : "unread-secret";
      },
    });
  }
  const source = `mcp_oauth_callback_url = "https://callback.example/base"

[mcp_servers.duplicate]
url = "https://example.test/mcp"
http_headers = { "X-Key" = "static" }
env_http_headers = { "x-key" = "UNREAD_SECRET" }

[mcp_servers.reserved]
url = "https://example.test/mcp"
env_http_headers = { "Host" = "UNREAD_SECRET" }

[mcp_servers.invalid_header_name]
url = "https://example.test/mcp"
http_headers = { "Bad Header" = "static" }

[mcp_servers.bearer_oauth]
url = "https://example.test/mcp"
bearer_token_env_var = "TOKEN"
auth = "oauth"

[mcp_servers.bearer_authorization]
url = "https://example.test/mcp"
bearer_token_env_var = "TOKEN"
http_headers = { "authorization" = "Basic static" }

[mcp_servers.oauth_authorization]
url = "https://example.test/mcp"
auth = "oauth"
http_headers = { "AUTHORIZATION" = "Basic static" }

[mcp_servers.challenge_master_key]
url = "https://example.test/mcp"
env_http_headers = { "X-Key" = "mCp_ReStRiCtOr_MaStEr_KeY_fIlE" }

[mcp_servers.explicit_master_key]
url = "https://example.test/mcp"
auth = "oauth"
env_http_headers = { "X-Key" = "mCp_ReStRiCtOr_MaStEr_KeY_fIlE" }

[mcp_servers.plaintext_bearer]
url = "http://example.test/mcp"
bearer_token_env_var = "TOKEN"

[mcp_servers.plaintext_header]
url = "http://example.test/mcp"
env_http_headers = { "X-Key" = "UNREAD_SECRET" }

[mcp_servers.plaintext_oauth]
url = "http://example.test/mcp"
auth = "oauth"

[mcp_servers.query]
url = "https://example.test/mcp?token=hidden"
env_http_headers = { "X-Key" = "UNREAD_SECRET" }

[mcp_servers.fragment]
url = "https://example.test/mcp#hidden"
bearer_token_env_var = "TOKEN"

[mcp_servers.bearer_scope]
url = "https://example.test/mcp"
bearer_token_env_var = "TOKEN"
scopes = ["read"]

[mcp_servers.authorization_resource]
url = "https://example.test/mcp"
http_headers = { "Authorization" = "Basic static" }
oauth_resource = "https://resource.example/mcp"

[mcp_servers.server_store]
url = "https://example.test/mcp"
mcp_oauth_credentials_store = "keyring"
`;

  const parsed = parseCodexConfig({ ...options, source, environment });

  expect(reads).toBe(0);
  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ name }) => name)).toEqual([
    "duplicate",
    "reserved",
    "invalid_header_name",
    "bearer_oauth",
    "bearer_authorization",
    "oauth_authorization",
    "challenge_master_key",
    "explicit_master_key",
    "plaintext_bearer",
    "plaintext_header",
    "plaintext_oauth",
    "query",
    "fragment",
    "bearer_scope",
    "authorization_resource",
    "server_store",
  ]);
  expect(JSON.stringify(parsed.unsupported)).not.toMatch(/unread-secret|hidden|keys\/unread/);
});

test("rejects missing, inherited, empty, and malformed effective HTTP header values", () => {
  const source = String.raw`
[mcp_servers.missing]
url = "https://example.test/mcp"
env_http_headers = { "X-Key" = "MISSING" }

[mcp_servers.inherited]
url = "https://example.test/mcp"
env_http_headers = { "X-Key" = "INHERITED" }

[mcp_servers.empty]
url = "https://example.test/mcp"
env_http_headers = { "X-Key" = "EMPTY" }

[mcp_servers.invalid_env_name]
url = "https://example.test/mcp"
env_http_headers = { "X-Key" = "BAD-NAME" }

[mcp_servers.static_crlf]
url = "https://example.test/mcp"
http_headers = { "X-Key" = "hidden\r\nInjected: yes" }

[mcp_servers.environment_crlf]
url = "https://example.test/mcp"
env_http_headers = { "X-Key" = "CRLF" }

[mcp_servers.empty_bearer]
url = "https://example.test/mcp"
bearer_token_env_var = "EMPTY"

[mcp_servers.bad_static_map]
url = "https://example.test/mcp"
http_headers = { "X-Key" = 1 }

[mcp_servers.bad_environment_map]
url = "https://example.test/mcp"
env_http_headers = { "X-Key" = 1 }
`;
  const environment = Object.assign(Object.create({ INHERITED: "inherited-secret" }), {
    EMPTY: "",
    CRLF: "hidden\r\nInjected: yes",
  }) as NodeJS.ProcessEnv;

  const parsed = parseCodexConfig({ ...options, source, environment });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ name, reason }) => ({ name, reason }))).toEqual([
    { name: "missing", reason: "invalid remote configuration" },
    { name: "inherited", reason: "invalid remote configuration" },
    { name: "empty", reason: "invalid remote configuration" },
    { name: "invalid_env_name", reason: "invalid remote configuration" },
    { name: "static_crlf", reason: "invalid remote configuration" },
    { name: "environment_crlf", reason: "invalid remote configuration" },
    { name: "empty_bearer", reason: "required environment variable is missing" },
    { name: "bad_static_map", reason: "invalid HTTP headers" },
    { name: "bad_environment_map", reason: "invalid HTTP headers" },
  ]);
  expect(JSON.stringify(parsed.unsupported)).not.toMatch(/inherited-secret|hidden|Injected/);
});

test("fails on the first invalid header and memoizes reused remote environment values", () => {
  let invalidStaticLaterReads = 0;
  let invalidDynamicReads = 0;
  let invalidDynamicLaterReads = 0;
  let sharedReads = 0;
  const environment: NodeJS.ProcessEnv = {};
  for (const [name, read] of [
    [
      "INVALID_STATIC_LATER",
      () => {
        invalidStaticLaterReads += 1;
        return "must-not-read";
      },
    ],
    [
      "INVALID_DYNAMIC",
      () => {
        invalidDynamicReads += 1;
        return "hidden\r\nInjected: yes";
      },
    ],
    [
      "INVALID_DYNAMIC_LATER",
      () => {
        invalidDynamicLaterReads += 1;
        return "must-not-read";
      },
    ],
    [
      "SHARED",
      () => {
        sharedReads += 1;
        return `shared-${sharedReads}`;
      },
    ],
  ] as const) {
    Object.defineProperty(environment, name, {
      enumerable: true,
      configurable: true,
      get: read,
    });
  }
  const source = String.raw`
[mcp_servers.invalid_static]
url = "https://example.test/mcp"
http_headers = { "X-Bad" = "hidden\r\nInjected: yes" }
env_http_headers = { "X-Later" = "INVALID_STATIC_LATER" }

[mcp_servers.invalid_dynamic]
url = "https://example.test/mcp"
env_http_headers = { "X-Bad" = "INVALID_DYNAMIC", "X-Later" = "INVALID_DYNAMIC_LATER" }

[mcp_servers.reused]
url = "https://example.test/mcp"
env_http_headers = { "X-One" = "SHARED", "X-Two" = "SHARED" }
bearer_token_env_var = "SHARED"
`;

  const parsed = parseCodexConfig({ ...options, source, environment });

  expect(parsed.unsupported.map(({ name, reason }) => ({ name, reason }))).toEqual([
    { name: "invalid_static", reason: "invalid remote configuration" },
    { name: "invalid_dynamic", reason: "invalid remote configuration" },
  ]);
  expect(parsed.servers.map(({ name, upstream }) => ({ name, upstream }))).toEqual([
    {
      name: "reused",
      upstream: {
        kind: "http",
        url: "https://example.test/mcp",
        headers: [
          ["X-One", "shared-1"],
          ["X-Two", "shared-1"],
        ],
        bearerToken: "shared-1",
      },
    },
  ]);
  expect({
    invalidStaticLaterReads,
    invalidDynamicReads,
    invalidDynamicLaterReads,
    sharedReads,
  }).toEqual({
    invalidStaticLaterReads: 0,
    invalidDynamicReads: 1,
    invalidDynamicLaterReads: 0,
    sharedReads: 1,
  });
});

test("keeps Codex scopes and resource as challenge OAuth fallback metadata", () => {
  const source = `[mcp_servers.challenge]
url = "https://example.test/mcp"
scopes = ["write", "read"]
oauth_resource = "urn:example:challenge"
`;

  const parsed = parseCodexConfig({ ...options, source, environment: {} });

  expect(parsed.unsupported).toEqual([]);
  expect(parsed.servers[0]?.oauth).toEqual({
    mode: "challenge",
    fallbackScope: "write read",
    resource: "urn:example:challenge",
    callback: {
      host: "127.0.0.1",
      path: "/callback",
      appendProfileId: true,
    },
  });
});

test.each([
  ["scope string", 'scopes = "read"', "invalid OAuth metadata"],
  ["scope non-string", "scopes = [1]", "invalid OAuth metadata"],
  ["scope containing a separator", 'scopes = ["read write"]', "invalid OAuth metadata"],
  ["empty scope token", 'scopes = [""]', "invalid OAuth metadata"],
  ["relative resource", 'oauth_resource = "relative"', "invalid OAuth metadata"],
  [
    "fragment resource",
    'oauth_resource = "https://resource.example/mcp#fragment"',
    "invalid OAuth metadata",
  ],
  ["non-string resource", "oauth_resource = 1", "invalid OAuth metadata"],
  ["ChatGPT auth", 'auth = "chatgpt"', "unsupported Codex authentication"],
  ["unknown auth", 'auth = "future"', "unsupported Codex authentication"],
  ["non-string auth", "auth = 1", "invalid OAuth metadata"],
  ["invalid enabled tools", 'enabled_tools = ["read", 1]', "invalid enabled_tools option"],
  ["invalid disabled tools", 'disabled_tools = "read"', "invalid disabled_tools option"],
] as const)("rejects malformed Codex OAuth/client metadata: %s", (_case, field, reason) => {
  const source = `[mcp_servers.invalid]
url = "https://example.test/mcp"
${field}
`;

  const parsed = parseCodexConfig({ ...options, source });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ name, reason: actual }) => ({ name, reason: actual }))).toEqual([
    { name: "invalid", reason },
  ]);
});

test.each([
  ["negative port", "mcp_oauth_callback_port = -1"],
  ["port above 65535", "mcp_oauth_callback_port = 65536"],
  ["fractional port", "mcp_oauth_callback_port = 1.5"],
  ["string port", 'mcp_oauth_callback_port = "41337"'],
  ["relative URL", 'mcp_oauth_callback_url = "relative"'],
  ["remote plaintext URL", 'mcp_oauth_callback_url = "http://callback.example/base"'],
  ["URL credentials", 'mcp_oauth_callback_url = "https://user:pass@callback.example/base"'],
  ["URL fragment", 'mcp_oauth_callback_url = "https://callback.example/base#fragment"'],
  ["non-string URL", "mcp_oauth_callback_url = 1"],
] as const)(
  "rejects malformed top-level callback metadata for an OAuth candidate: %s",
  (_case, field) => {
    let storageReads = 0;
    const environment: NodeJS.ProcessEnv = {};
    Object.defineProperty(environment, MASTER_KEY_FILE_ENV, {
      enumerable: true,
      get() {
        storageReads += 1;
        return "keys/unread.key";
      },
    });
    const source = `${field}

[mcp_servers.invalid]
url = "https://example.test/mcp"
auth = "oauth"
`;

    const parsed = parseCodexConfig({ ...options, source, environment });

    expect(storageReads).toBe(0);
    expect(parsed.servers).toEqual([]);
    expect(parsed.unsupported.map(({ name, reason }) => ({ name, reason }))).toEqual([
      { name: "invalid", reason: "invalid OAuth metadata" },
    ]);
  },
);

test("does not apply malformed global OAuth settings to a bearer-only server", () => {
  const source = `mcp_oauth_callback_port = -1
mcp_oauth_callback_url = "not a URL"
mcp_oauth_credentials_store = "file"

[mcp_servers.bearer]
url = "https://example.test/mcp"
bearer_token_env_var = "TOKEN"
`;

  const parsed = parseCodexConfig({
    ...options,
    source,
    environment: { TOKEN: "bearer-secret" },
  });

  expect(parsed.unsupported).toEqual([]);
  expect(
    parsed.servers.map(({ name, oauth, upstream, wrapperEnvironment }) => ({
      name,
      oauth,
      upstream,
      wrapperEnvironment,
    })),
  ).toEqual([
    {
      name: "bearer",
      oauth: undefined,
      upstream: {
        kind: "http",
        url: "https://example.test/mcp",
        bearerToken: "bearer-secret",
      },
      wrapperEnvironment: { envVars: ["TOKEN"] },
    },
  ]);
  expect(renderCodexConfig(parsed, new Map())).toBe(source);
});

test("discovers supported Codex servers without exposing effective secrets", () => {
  const source = `# keep this comment
model = "gpt-5"

[mcp_servers.files]
command = "node"
args = ["server.mjs"]
cwd = "/workspace"
env_vars = ["TOKEN", "TOKEN"]

[mcp_servers.files.env]
API_KEY = "configured-secret"

[mcp_servers."remote docs"]
url = "https://example.test/mcp"
bearer_token_env_var = "DOCS_TOKEN"

[mcp_servers.files.tools.read_file]
approval_mode = "approve"

[mcp_servers.remote_exec]
command = "remote-node"
env_vars = [{ name = "REMOTE", source = "remote" }]
`;

  const parsed = parseCodexConfig({ ...options, source });

  expect(parsed.servers).toHaveLength(2);
  expect(parsed.servers[0]).toEqual({
    client: "codex",
    scope: "user",
    name: "files",
    configPath: "/home/me/.codex/config.toml",
    source: {
      kind: "stdio",
      command: "node",
      args: ["server.mjs"],
      envNames: ["API_KEY", "TOKEN"],
      cwd: "/workspace",
    },
    upstream: {
      kind: "stdio",
      command: "node",
      args: ["server.mjs"],
      cwd: "/workspace",
      env: expect.objectContaining({
        API_KEY: "configured-secret",
        TOKEN: "forwarded-secret",
      }),
    },
    wrapperEnvironment: {
      env: { API_KEY: "configured-secret" },
      envVars: ["TOKEN", "TOKEN"],
    },
    original: {
      command: "node",
      args: ["server.mjs"],
      cwd: "/workspace",
      env_vars: ["TOKEN", "TOKEN"],
      env: { API_KEY: "configured-secret" },
      tools: { read_file: { approval_mode: "approve" } },
    },
  });
  expect(parsed.servers[1]).toEqual({
    client: "codex",
    scope: "user",
    name: "remote docs",
    configPath: "/home/me/.codex/config.toml",
    source: {
      kind: "http",
      url: "https://example.test/mcp",
      headers: [],
      bearerTokenEnvVar: "DOCS_TOKEN",
    },
    upstream: {
      kind: "http",
      url: "https://example.test/mcp",
      bearerToken: "bearer-secret",
    },
    wrapperEnvironment: { envVars: ["DOCS_TOKEN"] },
    original: {
      url: "https://example.test/mcp",
      bearer_token_env_var: "DOCS_TOKEN",
    },
  });
  expect(parsed.unsupported).toEqual([
    {
      client: "codex",
      scope: "user",
      name: "remote_exec",
      configPath: "/home/me/.codex/config.toml",
      reason: "remote STDIO executor is not supported",
    },
  ]);
  expect(
    JSON.stringify({
      source: parsed.servers.map((server) => server.source),
      wrappers: parsed.servers.map((server) => server.wrapperEnvironment),
      unsupported: parsed.unsupported,
    }),
  ).not.toContain("forwarded-secret");
  expect(JSON.stringify(parsed.unsupported)).not.toContain("must-not-leak");
});

test("rejects disabled, nested OAuth, mixed, unknown, and malformed entries", () => {
  const source = `
[mcp_servers.disabled]
command = "node"
enabled = false

[mcp_servers.oauth]
url = "https://example.test/mcp"
oauth = { client_id = "secret-id" }

[mcp_servers.mixed]
command = "node"
url = "https://example.test/mcp"

[mcp_servers.unknown]
command = "node"
executor = "future"

[mcp_servers.bad_args]
command = "node"
args = [1]

[mcp_servers.bad_env]
command = "node"
env = { TOKEN = 1 }

[mcp_servers.bad_url]
url = "ssh://user:password@example.test/mcp"
`;

  const parsed = parseCodexConfig({ ...options, source });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ name, reason }) => ({ name, reason }))).toEqual([
    { name: "disabled", reason: "disabled server is not supported" },
    { name: "oauth", reason: "unsupported field: oauth" },
    { name: "mixed", reason: "mixed MCP transports are not supported" },
    { name: "unknown", reason: "unsupported server field" },
    { name: "bad_args", reason: "invalid STDIO arguments" },
    { name: "bad_env", reason: "invalid STDIO environment" },
    { name: "bad_url", reason: "unsupported HTTP URL" },
  ]);
  expect(JSON.stringify(parsed.unsupported)).not.toMatch(/secret-id|secret-value|password/);
});

test("unwraps a managed Codex server using outer environment and cwd", () => {
  const source = `
[mcp_servers.managed]
command = "/trusted/bin/mcp-restrictor"
args = ["--policy", ".mcp-restrictor/policies/codex/managed.yaml", "--upstream-env", "TOKEN", "--upstream-cwd", "/original", "--", "node", "server.mjs"]
cwd = "/repo"
env_vars = ["TOKEN"]

[mcp_servers.managed.env]
EXPLICIT = "configured"
`;

  const [candidate] = parseCodexConfig({ ...options, source }).servers;

  expect(candidate).toEqual({
    client: "codex",
    scope: "user",
    name: "managed",
    configPath: "/home/me/.codex/config.toml",
    source: {
      kind: "stdio",
      command: "node",
      args: ["server.mjs"],
      envNames: ["TOKEN"],
      cwd: "/original",
    },
    upstream: {
      kind: "stdio",
      command: "node",
      args: ["server.mjs"],
      cwd: "/original",
      env: expect.objectContaining({ TOKEN: "forwarded-secret" }),
    },
    wrapperEnvironment: {
      env: { EXPLICIT: "configured" },
      envVars: ["TOKEN"],
    },
    original: {
      command: "/trusted/bin/mcp-restrictor",
      args: [
        "--policy",
        ".mcp-restrictor/policies/codex/managed.yaml",
        "--upstream-env",
        "TOKEN",
        "--upstream-cwd",
        "/original",
        "--",
        "node",
        "server.mjs",
      ],
      cwd: "/repo",
      env_vars: ["TOKEN"],
      env: { EXPLICIT: "configured" },
    },
    managedPolicyPath: "/repo/.mcp-restrictor/policies/codex/managed.yaml",
  });
});

test("rejects a malformed absolute Codex managed wrapper", () => {
  const source = `
[mcp_servers.managed]
command = "/trusted/bin/mcp-restrictor.exe"
args = ["--", "node"]
`;

  const parsed = parseCodexConfig({ ...options, source });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ reason }) => reason)).toEqual([
    "malformed mcp-restrictor wrapper",
  ]);
});

test("rejects a managed wrapper assigned to a remote STDIO executor", () => {
  const source = `
[mcp_servers.managed]
command = "mcp-restrictor"
args = ["--policy", "/policy.yaml", "--", "node", "server.mjs"]
env_vars = [{ name = "REMOTE", source = "remote" }]
`;

  const parsed = parseCodexConfig({ ...options, source });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ reason }) => reason)).toEqual([
    "remote STDIO executor is not supported",
  ]);
});

test("uses a managed HTTP wrapper explicit environment value for bearer preflight", () => {
  const source = `
[mcp_servers.managed]
command = "mcp-restrictor"
args = ["--policy", "/policy.yaml", "--upstream-http", "https://example.test/mcp", "--upstream-bearer-token-env", "DOCS_TOKEN"]

[mcp_servers.managed.env]
DOCS_TOKEN = "explicit-bearer"
`;

  const [candidate] = parseCodexConfig({ ...options, source }).servers;

  expect(candidate?.upstream).toEqual({
    kind: "http",
    url: "https://example.test/mcp",
    bearerToken: "explicit-bearer",
  });
  expect(candidate?.wrapperEnvironment).toEqual({
    env: { DOCS_TOKEN: "explicit-bearer" },
  });
});

test("scans only real table headers outside comments and multiline strings", () => {
  const source = `description = """
[mcp_servers.phantom]
command = "bad"
"""
literal = '''
[mcp_servers.also_phantom]
'''
# [mcp_servers.comment]
[mcp_servers.real]
command = "node" # [mcp_servers.inline_comment]
`;

  expect(parseCodexConfig({ ...options, source }).servers.map(({ name }) => name)).toEqual([
    "real",
  ]);
});

test("decodes quoted dotted and literal server names with descendant tables", () => {
  const source = `
[mcp_servers."a.b"]
command = "node"

[mcp_servers."a.b".env]
TOKEN = "explicit"

[mcp_servers.'literal.name']
command = "python"

[mcp_servers.'literal.name'.tools.read]
approval_mode = "approve"
`;

  const parsed = parseCodexConfig({ ...options, source });

  expect(parsed.servers.map(({ name }) => name)).toEqual(["a.b", "literal.name"]);
  expect(parsed.servers[0]?.source).toEqual({
    kind: "stdio",
    command: "node",
    args: [],
    envNames: ["TOKEN"],
  });
  expect(parsed.servers[1]?.original).toEqual({
    command: "python",
    tools: { read: { approval_mode: "approve" } },
  });
});

test("explicit Codex env wins over the same forwarded name while raw wrapper fields remain intact", () => {
  const source = `
[mcp_servers.files]
command = "node"
env_vars = ["TOKEN"]

[mcp_servers.files.env]
TOKEN = "explicit-secret"
`;

  const [candidate] = parseCodexConfig({ ...options, source }).servers;

  expect(candidate?.upstream).toEqual({
    kind: "stdio",
    command: "node",
    args: [],
    env: expect.objectContaining({ TOKEN: "explicit-secret" }),
  });
  expect(candidate?.wrapperEnvironment).toEqual({
    env: { TOKEN: "explicit-secret" },
    envVars: ["TOKEN"],
  });
});

test("requires normal STDIO and HTTP named environment values before discovery", () => {
  const source = `
[mcp_servers.stdio]
command = "node"
env_vars = ["MISSING"]

[mcp_servers.http]
url = "https://example.test/mcp"
bearer_token_env_var = "MISSING"
`;

  const parsed = parseCodexConfig({ ...options, source });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ name, reason }) => ({ name, reason }))).toEqual([
    { name: "stdio", reason: "required environment variable is missing" },
    { name: "http", reason: "required environment variable is missing" },
  ]);
});

test("does not treat inherited process-environment properties as named values", () => {
  const source = `
[mcp_servers.stdio]
command = "node"
env_vars = ["constructor"]

[mcp_servers.http]
url = "https://example.test/mcp"
bearer_token_env_var = "__proto__"
`;

  const parsed = parseCodexConfig({ ...options, environment: {}, source });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ name, reason }) => ({ name, reason }))).toEqual([
    { name: "stdio", reason: "required environment variable is missing" },
    { name: "http", reason: "required environment variable is missing" },
  ]);
});

test("accepts an own explicit prototype-like environment name", () => {
  const source = `
[mcp_servers.files]
command = "node"
env_vars = ["constructor"]

[mcp_servers.files.env]
constructor = "explicit-value"
`;

  const [candidate] = parseCodexConfig({ ...options, environment: {}, source }).servers;

  expect(candidate?.upstream).toEqual({
    kind: "stdio",
    command: "node",
    args: [],
    env: expect.objectContaining({ constructor: "explicit-value" }),
  });
});

test("installs explicit __proto__ values as own STDIO environment properties", () => {
  const source = `
[mcp_servers.normal]
command = "node"

[mcp_servers.normal.env]
"__proto__" = "normal-value"

[mcp_servers.managed]
command = "mcp-restrictor"
args = ["--policy", "/policy.yaml", "--upstream-env", "__proto__", "--", "node"]

[mcp_servers.managed.env]
"__proto__" = "managed-value"
`;

  const parsed = parseCodexConfig({ ...options, environment: {}, source });
  const normal = parsed.servers.find(({ name }) => name === "normal");
  const managed = parsed.servers.find(({ name }) => name === "managed");
  const normalEnv = normal?.upstream.kind === "stdio" ? normal.upstream.env : undefined;
  const managedEnv = managed?.upstream.kind === "stdio" ? managed.upstream.env : undefined;

  expect(Object.hasOwn(normalEnv ?? {}, "__proto__")).toBe(true);
  expect(normalEnv?.__proto__).toBe("normal-value");
  expect(Object.hasOwn(managedEnv ?? {}, "__proto__")).toBe(true);
  expect(managedEnv?.__proto__).toBe("managed-value");
});

test("allows explicit STDIO env to satisfy a forwarded name missing from the process", () => {
  const source = `
[mcp_servers.files]
command = "node"
env_vars = ["MISSING"]

[mcp_servers.files.env]
MISSING = "explicit-value"
`;

  const [candidate] = parseCodexConfig({ ...options, source }).servers;

  expect(candidate?.upstream).toEqual({
    kind: "stdio",
    command: "node",
    args: [],
    env: expect.objectContaining({ MISSING: "explicit-value" }),
  });
  expect(candidate?.wrapperEnvironment).toEqual({
    env: { MISSING: "explicit-value" },
    envVars: ["MISSING"],
  });
});

test("managed STDIO preflight forwards only names declared by embedded Restrictor arguments", () => {
  const source = `
[mcp_servers.managed]
command = "mcp-restrictor"
args = ["--policy", "/policy.yaml", "--upstream-env", "TOKEN", "--", "node", "server.mjs"]
env_vars = ["TOKEN"]

[mcp_servers.managed.env]
TOKEN = "explicit-token"
EXTRA = "must-not-reach-child"
`;

  const [candidate] = parseCodexConfig({ ...options, source }).servers;
  const upstream = candidate?.upstream;

  expect(upstream).toEqual({
    kind: "stdio",
    command: "node",
    args: ["server.mjs"],
    env: expect.objectContaining({ TOKEN: "explicit-token" }),
  });
  expect(upstream?.kind === "stdio" ? upstream.env?.EXTRA : undefined).toBeUndefined();
  expect(candidate?.wrapperEnvironment).toEqual({
    env: { TOKEN: "explicit-token", EXTRA: "must-not-reach-child" },
    envVars: ["TOKEN"],
  });
});

test("managed STDIO process values require matching outer local env_vars declarations", () => {
  const source = `
[mcp_servers.managed]
command = "mcp-restrictor"
args = ["--policy", "/policy.yaml", "--upstream-env", "TOKEN", "--", "node"]
`;

  const parsed = parseCodexConfig({ ...options, source });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ reason }) => reason)).toEqual([
    "required environment variable is missing",
  ]);
});

test("managed HTTP bearer process values require matching outer local env_vars declarations", () => {
  const source = `
[mcp_servers.managed]
command = "mcp-restrictor"
args = ["--policy", "/policy.yaml", "--upstream-http", "https://example.test/mcp", "--upstream-bearer-token-env", "DOCS_TOKEN"]
`;

  const parsed = parseCodexConfig({ ...options, source });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported.map(({ reason }) => reason)).toEqual([
    "required environment variable is missing",
  ]);
});

test("unwraps managed SSE and WebSocket without inventing native Codex transports", () => {
  const websocketHeader = Buffer.from("${TOKEN}").toString("base64url");
  const source = `experimental_use_rmcp_client = true

[mcp_servers.sse]
command = "/trusted/bin/mcp-restrictor"
args = ["--policy", "/policy/sse.yaml", "--upstream-sse", "https://example.test/events", "--upstream-header-env", "X-Sse=SSE_HEADER", "--upstream-oauth-profile", "${oauthProfileId}"]
env_vars = ["SSE_HEADER"]
enabled_tools = ["read", "search"]

[mcp_servers.sse.env]
${MASTER_KEY_FILE_ENV} = "/fixed/codex-master.key"

[mcp_servers.websocket]
command = "mcp-restrictor"
args = ["--policy", "/policy/ws.yaml", "--upstream-websocket", "wss://example.test/mcp", "--upstream-header-base64url-env", "X-Literal=WS_HEADER"]

[mcp_servers.websocket.env]
WS_HEADER = "${websocketHeader}"

[mcp_servers.native]
url = "https://example.test/native"
`;

  const parsed = parseCodexConfig({
    ...options,
    source,
    environment: { SSE_HEADER: "sse-secret", TOKEN: "other" },
  });

  expect(parsed.unsupported).toEqual([]);
  expect(
    parsed.servers.map((candidate) => ({
      name: candidate.name,
      source: candidate.source,
      upstream: candidate.upstream,
      wrapperEnvironment: candidate.wrapperEnvironment,
      oauth: candidate.oauth,
      managedPolicyPath: candidate.managedPolicyPath,
    })),
  ).toEqual([
    {
      name: "sse",
      source: {
        kind: "sse",
        url: "https://example.test/events",
        headers: [{ name: "X-Sse", environmentVariable: "SSE_HEADER" }],
        oauthProfileId,
      },
      upstream: {
        kind: "sse",
        url: "https://example.test/events",
        headers: [["X-Sse", "sse-secret"]],
      },
      wrapperEnvironment: {
        env: { [MASTER_KEY_FILE_ENV]: "/fixed/codex-master.key" },
        envVars: ["SSE_HEADER"],
      },
      oauth: undefined,
      managedPolicyPath: "/policy/sse.yaml",
    },
    {
      name: "websocket",
      source: {
        kind: "websocket",
        url: "wss://example.test/mcp",
        headers: [
          {
            name: "X-Literal",
            environmentVariable: "WS_HEADER",
            encoding: "base64url",
          },
        ],
      },
      upstream: {
        kind: "websocket",
        url: "wss://example.test/mcp",
        headers: [["X-Literal", "${TOKEN}"]],
      },
      wrapperEnvironment: { env: { WS_HEADER: websocketHeader } },
      oauth: undefined,
      managedPolicyPath: "/policy/ws.yaml",
    },
    {
      name: "native",
      source: { kind: "http", url: "https://example.test/native", headers: [] },
      upstream: { kind: "http", url: "https://example.test/native" },
      wrapperEnvironment: {},
      oauth: {
        mode: "challenge",
        callback: {
          host: "127.0.0.1",
          path: "/callback",
          appendProfileId: true,
        },
      },
      managedPolicyPath: undefined,
    },
  ]);
  expect(renderCodexConfig(parsed, new Map())).toBe(source);

  const plannedSse = planManagedWrapper({
    server: parsed.servers[0]!,
    allowedTools: [],
    policy: { diskPath: "/policy/sse.yaml", argument: "/policy/sse.yaml" },
    restrictor: { command: "mcp-restrictor", argsPrefix: [] },
    projectRoot: "/repo",
  });
  expect(plannedSse.replacement.env).toEqual({
    [MASTER_KEY_FILE_ENV]: "/fixed/codex-master.key",
  });
  expect(plannedSse.replacement.envVars).toEqual(["SSE_HEADER"]);
  expect(plannedSse.replacement.args.filter((value) => value === oauthProfileId)).toEqual([
    oauthProfileId,
  ]);
  expect(plannedSse.verificationUpstream).toMatchObject({
    kind: "stdio",
    env: {
      SSE_HEADER: "sse-secret",
      [MASTER_KEY_FILE_ENV]: "/fixed/codex-master.key",
    },
  });

  const plannedWebSocket = planManagedWrapper({
    server: parsed.servers[1]!,
    allowedTools: [],
    policy: { diskPath: "/policy/ws.yaml", argument: "/policy/ws.yaml" },
    restrictor: { command: "mcp-restrictor", argsPrefix: [] },
    projectRoot: "/repo",
  });
  expect(plannedWebSocket.replacement.env).toEqual({ WS_HEADER: websocketHeader });
  expect(plannedWebSocket.replacement.args).not.toContain("--upstream-oauth-profile");
  expect(plannedWebSocket.verificationUpstream).toMatchObject({
    kind: "stdio",
    env: { WS_HEADER: websocketHeader },
  });
});

test("keeps intervening unselected root and descendant bytes when one server owns later ranges", () => {
  const source = `[mcp_servers.files]
command = "node"

[mcp_servers.unselected]
command   =   "python" # exact root bytes

[mcp_servers.unselected.env]
TOKEN = "keep" # exact descendant bytes

[mcp_servers.files.env]
OLD = "remove"
`;
  const rendered = renderCodexConfig(
    parseCodexConfig({ ...options, source }),
    new Map([["files", { command: "mcp-restrictor", args: ["--policy", "/files.yaml"] }]]),
  );

  expect(rendered).toContain(`[mcp_servers.unselected]
command   =   "python" # exact root bytes

[mcp_servers.unselected.env]
TOKEN = "keep" # exact descendant bytes
`);
  expect(rendered).not.toContain('OLD = "remove"');
});

test("treats prototype-like server names as own keys without changing unselected bytes", () => {
  const source = `[mcp_servers.__proto__]
command = "node"

[mcp_servers.constructor]
command   =   "python" # preserve constructor bytes
`;
  const config = parseCodexConfig({ ...options, source });
  const rendered = renderCodexConfig(
    config,
    new Map([["__proto__", { command: "mcp-restrictor", args: ["--policy", "/p.yaml"] }]]),
  );
  const servers = (parse(rendered) as { mcp_servers: Record<string, unknown> }).mcp_servers;

  expect(config.servers.map(({ name }) => name)).toEqual(["__proto__", "constructor"]);
  expect(Object.hasOwn(servers, "__proto__")).toBe(true);
  expect(Object.hasOwn(servers, "constructor")).toBe(true);
  expect(rendered).toContain(
    '[mcp_servers.constructor]\ncommand   =   "python" # preserve constructor bytes\n',
  );
});

test("decodes smol-toml basic-quoted key escapes consistently with semantic parsing", () => {
  const source = String.raw`
[mcp_servers."face\U0001F600"]
command = "node"

[mcp_servers."esc\e"]
command = "node"

[mcp_servers."hex\x41"]
command = "node"
`;

  expect(parseCodexConfig({ ...options, source }).servers.map(({ name }) => name)).toEqual([
    "face😀",
    "esc\u001b",
    "hexA",
  ]);
});

test("surgically replaces selected bare and quoted servers and preserves unrelated bytes", () => {
  const source = `# keep this comment\r
model = "gpt-5"\r
mcp_oauth_callback_port = 41337\r
mcp_oauth_callback_url = "https://callback.example/base?tenant=one"\r
mcp_oauth_credentials_store = "keyring"\r
\r
[mcp_servers.files]\r
command = "node"\r
enabled = true\r
required = true\r
startup_timeout_sec = 5\r
tool_timeout_sec = 9\r
default_tools_approval_mode = "prompt"\r
enabled_tools = ["read_file", "list_files"]\r
disabled_tools = ["delete_file", "write_file"]\r
\r
[mcp_servers.unselected]\r
command   =   "python" # preserve spacing\r
args = ["server.py"]\r
\r
[mcp_servers.files.env]\r
# remove old env comment\r
OLD = "value"\r
\r
[mcp_servers."remote docs"]\r
url = "https://old.example.test/mcp"\r
auth = "oauth"\r
scopes = ["search", "read"]\r
oauth_resource = "https://old.example.test/resource"\r
http_headers = { "X-Static" = "configured-static" }\r
env_http_headers = { "X-Env" = "TOKEN" }\r
required = false\r
enabled_tools = ["search", "fetch"]\r
disabled_tools = ["delete", "update"]\r
\r
[mcp_servers.files.tools.read_file]\r
# remove old tool comment\r
approval_mode = "approve"\r
\r
[mcp_servers."remote docs".tools.search]\r
approval_mode = "reject"\r
`;
  const config = parseCodexConfig({ ...options, source });
  const rendered = renderCodexConfig(
    config,
    new Map([
      [
        "files",
        {
          command: "mcp-restrictor",
          args: ["--policy", "/policies/files.yaml", "--", "node", "server.mjs"],
          env: { NEW: "configured" },
          envVars: ["TOKEN"] as const,
          cwd: "/wrapper",
        },
      ],
      [
        "remote docs",
        {
          command: "mcp-restrictor",
          args: [
            "--policy",
            "/policies/remote.yaml",
            "--upstream-http",
            "https://old.example.test/mcp",
          ],
          env: { MCP_RESTRICTOR_UPSTREAM_HEADER_0: "configured-static" },
          envVars: ["TOKEN"] as const,
        },
      ],
    ]),
  );

  expect(rendered).toContain('# keep this comment\r\nmodel = "gpt-5"\r\n');
  expect(rendered).toContain(
    "mcp_oauth_callback_port = 41337\r\n" +
      'mcp_oauth_callback_url = "https://callback.example/base?tenant=one"\r\n' +
      'mcp_oauth_credentials_store = "keyring"\r\n',
  );
  expect(rendered).toContain(
    '[mcp_servers.unselected]\r\ncommand   =   "python" # preserve spacing\r\nargs = ["server.py"]\r\n',
  );
  expect(rendered).not.toContain("remove old env comment");
  expect(rendered).not.toContain("remove old tool comment");
  expect(rendered).not.toMatch(/http_headers|env_http_headers|oauth_resource|auth =|scopes =/);
  const parsed = parse(rendered) as Record<string, unknown>;
  expect(parsed).toEqual({
    model: "gpt-5",
    mcp_oauth_callback_port: 41337,
    mcp_oauth_callback_url: "https://callback.example/base?tenant=one",
    mcp_oauth_credentials_store: "keyring",
    mcp_servers: {
      files: {
        command: "mcp-restrictor",
        args: ["--policy", "/policies/files.yaml", "--", "node", "server.mjs"],
        env_vars: ["TOKEN"],
        cwd: "/wrapper",
        enabled: true,
        required: true,
        startup_timeout_sec: 5,
        tool_timeout_sec: 9,
        default_tools_approval_mode: "prompt",
        enabled_tools: ["read_file", "list_files"],
        disabled_tools: ["delete_file", "write_file"],
        env: { NEW: "configured" },
        tools: { read_file: { approval_mode: "approve" } },
      },
      unselected: { command: "python", args: ["server.py"] },
      "remote docs": {
        command: "mcp-restrictor",
        args: [
          "--policy",
          "/policies/remote.yaml",
          "--upstream-http",
          "https://old.example.test/mcp",
        ],
        env_vars: ["TOKEN"],
        required: false,
        enabled_tools: ["search", "fetch"],
        disabled_tools: ["delete", "update"],
        env: { MCP_RESTRICTOR_UPSTREAM_HEADER_0: "configured-static" },
        tools: { search: { approval_mode: "reject" } },
      },
    },
  });
});

test.each([
  [
    "duplicate table ownership",
    '[mcp_servers.files]\ncommand="node"\n[mcp_servers.files]\nargs=[]\n',
  ],
  ["inline ownership", 'mcp_servers = { files = { command = "node" } }\n'],
  ["array table ownership", '[[mcp_servers.files]]\ncommand = "node"\n'],
  ["dotted assignment ownership", 'mcp_servers.files.command = "node"\n'],
  ["quoted dotted assignment ownership", 'mcp_servers."a.b".command = "node"\n'],
] as const)("refuses ambiguous or unscannable %s", (_name, source) => {
  expect(() => parseCodexConfig({ ...options, source })).toThrow();
});

test("rejects malformed env_vars grammar without leaking values", () => {
  const source = `[mcp_servers.files]
command = "node"
env_vars = [{ name = "TOKEN", source = "local", value = "secret-value" }]
`;

  const parsed = parseCodexConfig({ ...options, source });

  expect(parsed.unsupported.map(({ reason }) => reason)).toEqual([
    "invalid STDIO environment variables",
  ]);
  expect(JSON.stringify(parsed.unsupported)).not.toContain("secret-value");
});

test("does not interpolate attacker-controlled unknown field names into reasons", () => {
  const source = String.raw`
[mcp_servers.attack]
command = "node"
"secret-like\e[31mTOKEN" = "value"
`;

  const parsed = parseCodexConfig({ ...options, source });

  expect(parsed.unsupported.map(({ reason }) => reason)).toEqual(["unsupported server field"]);
  expect(JSON.stringify(parsed.unsupported)).not.toMatch(/secret-like|TOKEN|\u001b/);
});
