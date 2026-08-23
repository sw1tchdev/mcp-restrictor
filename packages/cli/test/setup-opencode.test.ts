import {
  link,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parse as parseJsonc } from "jsonc-parser";
import { expect, test, vi } from "vitest";
import type {
  ClientAdapterHost,
  ClientLoadContext,
  ClientResolveContext,
} from "../src/client-adapter.ts";
import { UpstreamProtocolIncompatibleError } from "../src/client-adapter.ts";
import { MASTER_KEY_FILE_ENV } from "../src/oauth/storage.ts";
import {
  installOpenCodeConfig,
  installOpenCodeHttpConfig,
  opencodeAdapter,
  parseOpenCodeConfig,
  renderOpenCodeConfig,
  restoreOpenCodeConfig,
} from "../src/setup/opencode.ts";
import { readSnapshot, type FileSnapshot } from "../src/setup/transaction.ts";
import { planManagedWrapper, type Replacement } from "../src/setup/wrapper.ts";

const unsupportedEntryReason = "OpenCode MCP entry is not supported yet";
const shadowedReason = "shadowed by a higher-precedence OpenCode configuration";
const nativeHttpUrl =
  "http://127.0.0.1:7319/mcp/opencode/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

function snapshot(path: string, content: string, identity: number): FileSnapshot {
  return {
    path,
    content,
    mode: 0o600,
    size: content.length,
    mtimeMs: identity,
    dev: 1,
    ino: identity,
  };
}

function context(options: Partial<ClientLoadContext> = {}): ClientLoadContext {
  return {
    home: "/home/me",
    projectRoot: "/workspace/project",
    cwd: "/workspace/project/packages/app",
    environment: {},
    ...options,
  };
}

function memoryHost(files: ReadonlyMap<string, FileSnapshot>) {
  return {
    readConfig: vi.fn(async (path: string) => files.get(resolve(path))),
    readSecretFile: vi.fn(async (_path: string): Promise<FileSnapshot> => {
      throw new Error("unexpected secret read");
    }),
  } satisfies ClientAdapterHost;
}

function rows(result: Awaited<ReturnType<typeof opencodeAdapter.load>>) {
  return [
    ...result.configurations.flatMap(({ config }) => [...config.servers, ...config.unsupported]),
    ...result.unsupported,
  ];
}

function parseLocal(
  schema: "v1" | "v2",
  entry: Record<string, unknown>,
  path = "/workspace/project/opencode.jsonc",
) {
  const mcp = schema === "v1" ? { files: entry } : { servers: { files: entry } };
  return parseOpenCodeConfig({ path, scope: "project", source: JSON.stringify({ mcp }) });
}

function parseRemote(
  schema: "v1" | "v2",
  entry: Record<string, unknown>,
  path = "/workspace/project/opencode.jsonc",
  environment: NodeJS.ProcessEnv = {},
) {
  const mcp = schema === "v1" ? { files: entry } : { servers: { files: entry } };
  return parseOpenCodeConfig({
    path,
    scope: "project",
    source: JSON.stringify({ mcp }),
    environment,
  });
}

function parseRemoteWithControl(schema: "v1" | "v2", entry: Record<string, unknown>) {
  const servers = {
    files: entry,
    control: { type: "remote", url: "https://control.example/mcp", oauth: false },
  };
  const mcp = schema === "v1" ? servers : { servers };
  return parseOpenCodeConfig({
    path: "/workspace/project/opencode.jsonc",
    scope: "project",
    source: JSON.stringify({ mcp }),
  });
}

function manualOpenCodeEntry(overrides: Record<string, unknown> = {}) {
  return {
    name: "manual",
    command: "mcp-restrictor",
    args: ["--policy", ".mcp-restrictor/policies/opencode/manual.yaml", "--", "node", "server.mjs"],
    environment: { inherit: ["TOKEN"], set: { FIXED: "fixed-value" } },
    ...overrides,
  };
}

function resolveContext(environment: NodeJS.ProcessEnv = {}): ClientResolveContext {
  return {
    home: "/home/me",
    projectRoot: "/workspace/project",
    cwd: "/workspace/project",
    environment,
  };
}

test("runs the project wrapper from the project root while keeping a relative policy argument", () => {
  expect(
    opencodeAdapter.projectWrapper?.({
      projectRoot: "/workspace/project",
      relativePolicyPath: ".mcp-restrictor/policies/opencode/files.yaml",
      diskPolicyPath: "/workspace/project/.mcp-restrictor/policies/opencode/files.yaml",
    }),
  ).toEqual({
    policyArgument: ".mcp-restrictor/policies/opencode/files.yaml",
    cwd: "/workspace/project",
  });
});

test.each([
  { file: "opencode.json", source: '{"mcp":{"files":{"type":"local"}}}', schema: "v1" },
  {
    file: "opencode.jsonc",
    source: '{ // retained\n "mcp": {"servers": {"files": {"type":"local"},},},\n}',
    schema: "v2",
  },
] as const)("strictly parses $schema ownership from $file", ({ file, source }) => {
  const parsed = parseOpenCodeConfig({
    path: `/workspace/${file}`,
    scope: "project",
    source,
  });

  expect(parsed).toMatchObject({ client: "opencode", path: `/workspace/${file}`, source });
  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported).toEqual([
    {
      client: "opencode",
      scope: "project",
      name: "files",
      configPath: `/workspace/${file}`,
      reason: unsupportedEntryReason,
    },
  ]);
  expect(renderOpenCodeConfig(parsed, new Map())).toBe(source);
});

test("accepts comments, trailing commas, and an own __proto__ server without prototype pollution", () => {
  const source = `{
    // JSONC remains source-owned
    "mcp": {
      "__proto__": { "type": "local" },
    },
  }`;
  const parsed = parseOpenCodeConfig({
    path: "/workspace/opencode.jsonc",
    scope: "project",
    source,
  });

  expect(parsed.unsupported.map(({ name }) => name)).toEqual(["__proto__"]);
  expect(({} as Record<string, unknown>).type).toBeUndefined();
});

test.each([
  {
    name: "a configuration without mcp as V1",
    source: `{
  // root comment stays put
  "unrelated": "keep",
}`,
    path: ["mcp", "manual"],
  },
  {
    name: "an existing V1 configuration",
    source: `{
  "mcp": {
    // existing V1 comment
    "existing": { "type": "local", "command": ["node", "existing.mjs"], },
  },
  "unrelated": "keep",
}`,
    path: ["mcp", "manual"],
    trailingCommaBytes: '"unrelated": "keep",\n}',
  },
  {
    name: "an existing V2 configuration",
    source: `{
  "mcp": {
    "servers": {
      // existing V2 comment
      "existing": { "type": "local", "command": ["node", "existing.mjs"], },
    },
  },
  "unrelated": "keep",
}`,
    path: ["mcp", "servers", "manual"],
    trailingCommaBytes: '"unrelated": "keep",\n}',
  },
] as const)(
  "installs a manual OpenCode wrapper into %s",
  ({ source, path, trailingCommaBytes }) => {
    const rendered = installOpenCodeConfig(
      parseOpenCodeConfig({ path: "/workspace/project/opencode.jsonc", scope: "project", source }),
      manualOpenCodeEntry({ cwd: "/repo" }),
    );

    if (source.includes("root comment")) expect(rendered).toContain("// root comment stays put");
    const unrelated = source.slice(
      source.indexOf('"unrelated"'),
      source.indexOf("\n", source.indexOf('"unrelated"')),
    );
    expect(
      rendered.slice(rendered.indexOf(unrelated), rendered.indexOf(unrelated) + unrelated.length),
    ).toBe(unrelated);
    if (trailingCommaBytes) expect(rendered).toContain(trailingCommaBytes);
    expect(rendered).not.toContain("effective-token-secret");
    expect(parseJsonc(rendered)).toHaveProperty([...path], {
      type: "local",
      command: [
        "mcp-restrictor",
        "--policy",
        ".mcp-restrictor/policies/opencode/manual.yaml",
        "--",
        "node",
        "server.mjs",
      ],
      environment: { TOKEN: "{env:TOKEN}", FIXED: "fixed-value" },
      cwd: "/repo",
    });
    if (source.includes("existing")) {
      expect(rendered).toContain(
        source.includes("V1") ? "// existing V1 comment" : "// existing V2 comment",
      );
    }
    const reparsed = parseOpenCodeConfig({
      path: "/workspace/project/opencode.jsonc",
      scope: "project",
      source: rendered,
      projectRoot: "/repo",
      environment: { TOKEN: "effective-token-secret" },
    });
    expect(reparsed.unsupported).toEqual([]);
    expect(reparsed.servers.find(({ name }) => name === "manual")).toMatchObject({
      managedPolicyPath: "/repo/.mcp-restrictor/policies/opencode/manual.yaml",
      wrapperEnvironment: { env: { TOKEN: "{env:TOKEN}", FIXED: "fixed-value" } },
    });
  },
);

test("keeps OpenCode prototype-like names as own properties", () => {
  const rendered = installOpenCodeConfig(
    parseOpenCodeConfig({
      path: "/workspace/project/opencode.jsonc",
      scope: "project",
      source: "{}",
    }),
    manualOpenCodeEntry({
      name: "__proto__",
      args: ["--policy", "/policy.yaml", "--", "node"],
      environment: { inherit: ["__proto__"], set: { constructor: "fixed-value" } },
    }),
  );

  const entry = parseOpenCodeConfig({
    path: "/workspace/project/opencode.jsonc",
    scope: "project",
    source: rendered,
    environment: { __proto__: "inherited" },
  }).servers[0]!;
  expect(Object.hasOwn(entry.original, "environment")).toBe(true);
  expect(Object.hasOwn(entry.wrapperEnvironment.env!, "__proto__")).toBe(true);
  expect(entry.wrapperEnvironment.env?.__proto__).toBe("{env:__proto__}");
  expect(entry.wrapperEnvironment.env?.constructor).toBe("fixed-value");
});

test.each([
  '{"mcp":{"manual":{"type":"local","command":["node"]}}}',
  '{"mcp":{"manual":{"disabled":true}}}',
  '{"mcp":{"servers":{"manual":{"type":"local","command":["node"]}}}}',
] as const)("refuses OpenCode installation when an existing server owns the name", (source) => {
  expect(() =>
    installOpenCodeConfig(
      parseOpenCodeConfig({ path: "/workspace/project/opencode.jsonc", scope: "project", source }),
      manualOpenCodeEntry(),
    ),
  ).toThrow();
});

test("refuses V2 insertion when a V1 entry already owns the name", () => {
  const source = '{"mcp":{"manual":{"type":"local","command":["node"]},"servers":{}}}';

  expect(() =>
    installOpenCodeConfig(
      parseOpenCodeConfig({ path: "/workspace/project/opencode.jsonc", scope: "project", source }),
      manualOpenCodeEntry(),
    ),
  ).toThrow("OpenCode server name already exists");
});

test("exposes manual OpenCode installation through the adapter", () => {
  expect(opencodeAdapter.install).toBe(installOpenCodeConfig);
});

test.each([
  {
    name: "absent container as V1",
    source: '{\n  // root comment stays\n  "unrelated": "keep",\n}',
    path: ["mcp", "gateway"],
  },
  {
    name: "existing V1 container",
    source:
      '{\n  "mcp": {\n    // V1 comment stays\n    "existing": { "type": "local", "command": ["node"], },\n  },\n  "unrelated": "keep",\n}',
    path: ["mcp", "gateway"],
  },
  {
    name: "existing V2 container",
    source:
      '{\n  "mcp": {\n    "servers": {\n      // V2 comment stays\n      "existing": { "type": "local", "command": ["node"], },\n    },\n  },\n  "unrelated": "keep",\n}',
    path: ["mcp", "servers", "gateway"],
  },
] as const)(
  "native HTTP install writes the exact OpenCode entry into $name",
  ({ source, path }) => {
    const rendered = installOpenCodeHttpConfig(
      parseOpenCodeConfig({ path: "/workspace/project/opencode.jsonc", scope: "project", source }),
      { name: "gateway", url: nativeHttpUrl },
    );
    const entry = path.reduce<any>((value, name) => value[name], parseJsonc(rendered));
    const reparsed = parseOpenCodeConfig({
      path: "/workspace/project/opencode.jsonc",
      scope: "project",
      source: rendered,
    });
    const candidate = reparsed.servers.find(({ name }) => name === "gateway");

    expect(entry).toEqual({ type: "remote", url: nativeHttpUrl, oauth: false });
    expect(candidate?.source).toEqual({ kind: "http", url: nativeHttpUrl, headers: [] });
    expect(candidate).not.toHaveProperty("managedPolicyPath");
    expect(reparsed.unsupported).toEqual([]);
    expect(reparsed.servers).toHaveLength(source.includes("existing") ? 2 : 1);
    expect(rendered).toContain('"unrelated": "keep",');
    if (source.includes("root comment")) expect(rendered).toContain("// root comment stays");
    if (source.includes("V1 comment")) expect(rendered).toContain("// V1 comment stays");
    if (source.includes("V2 comment")) expect(rendered).toContain("// V2 comment stays");
    expect(JSON.stringify(entry)).not.toMatch(
      /command|policy|env|profile|upstream|header|authorization/i,
    );
  },
);

test("native HTTP install and Restore preserve compact OpenCode sibling bytes", () => {
  const source = `{
  "mcp": {
    "compact":{"type":"local","command":["node"]}
  },
  "keep":true
}\n`;
  const config = parseOpenCodeConfig({
    path: "/workspace/project/opencode.jsonc",
    scope: "project",
    source,
  });
  const installed = installOpenCodeHttpConfig(config, {
    name: "gateway",
    url: nativeHttpUrl,
  });
  const restored = restoreOpenCodeConfig(
    parseOpenCodeConfig({ ...config, source: installed }),
    [{ name: "gateway", originalSource: source, installedSource: installed, created: true }],
    {
      home: "/home/me",
      projectRoot: "/workspace/project",
      cwd: "/workspace/project",
      environment: {},
    },
  );

  expect(installed).toContain('"compact":{"type":"local","command":["node"]}');
  expect(restored).toBe(source);
});

test("native HTTP install handles OpenCode collisions and prototype-like names", () => {
  for (const source of [
    '{"mcp":{"gateway":{"type":"remote","url":"https://example.test/mcp","oauth":false}}}',
    '{"mcp":{"gateway":{"disabled":true}}}',
    '{"mcp":{"gateway":{"type":"local","command":["node"]},"servers":{}}}',
  ]) {
    expect(() =>
      installOpenCodeHttpConfig(
        parseOpenCodeConfig({
          path: "/workspace/project/opencode.jsonc",
          scope: "project",
          source,
        }),
        { name: "gateway", url: nativeHttpUrl },
      ),
    ).toThrow("OpenCode server name already exists");
  }

  const rendered = installOpenCodeHttpConfig(
    parseOpenCodeConfig({
      path: "/workspace/project/opencode.jsonc",
      scope: "project",
      source: "{}",
    }),
    { name: "__proto__", url: nativeHttpUrl },
  );
  const prototype = parseOpenCodeConfig({
    path: "/workspace/project/opencode.jsonc",
    scope: "project",
    source: rendered,
  }).servers[0]!;
  expect(prototype.name).toBe("__proto__");
  expect(Object.hasOwn(prototype.original, "type")).toBe(true);
});

test.each([
  [
    "V1",
    '{\n  "mcp": {\n    // unrelated V1 range\n    "existing": { "type": "local", "command": ["node"], },\n  },\n  "keep": true,\n}',
  ],
  [
    "V2",
    '{\n  "mcp": {\n    "servers": {\n      // unrelated V2 range\n      "existing": { "type": "local", "command": ["node"], },\n    },\n  },\n  "keep": true,\n}',
  ],
] as const)(
  "native HTTP install is removed by exact created-entry OpenCode %s Restore",
  (_schema, source) => {
    const config = parseOpenCodeConfig({
      path: "/workspace/project/opencode.jsonc",
      scope: "project",
      source,
    });
    const installed = installOpenCodeHttpConfig(config, { name: "gateway", url: nativeHttpUrl });
    const restored = restoreOpenCodeConfig(
      parseOpenCodeConfig({ ...config, source: installed }),
      [{ name: "gateway", originalSource: source, installedSource: installed, created: true }],
      {
        home: "/home/me",
        projectRoot: "/workspace/project",
        cwd: "/workspace/project",
        environment: {},
      },
    );

    expect(restored).toBe(source);
    expect(
      parseOpenCodeConfig({ ...config, source: restored }).servers.map(({ name }) => name),
    ).toEqual(["existing"]);
  },
);

test.each([
  ["duplicate server", '{"mcp":{"files":{},"files":{}}}'],
  ["duplicate root path", '{"mcp":{},"mcp":{"servers":{}}}'],
  ["malformed JSONC", '{"mcp":{"files":,}}'],
] as const)("rejects a %s document", (_label, source) => {
  expect(() =>
    parseOpenCodeConfig({
      path: "/workspace/opencode.jsonc",
      scope: "project",
      source,
    }),
  ).toThrow("Invalid OpenCode configuration");
});

test("discovers global, custom, direct ancestor, and .opencode files using documented precedence", async () => {
  const options = context();
  const paths = [
    join(options.home, ".config/opencode/opencode.json"),
    "/custom/settings.jsonc",
    join(options.projectRoot, "opencode.json"),
    join(options.projectRoot, "packages/opencode.jsonc"),
    join(options.cwd, "opencode.json"),
    join(options.projectRoot, ".opencode/opencode.jsonc"),
    join(options.projectRoot, "packages/.opencode/opencode.json"),
    join(options.cwd, ".opencode/opencode.jsonc"),
  ].map((path) => resolve(path));
  const files = new Map(
    paths.map((path, index) => [
      path,
      snapshot(
        path,
        index % 2 === 0
          ? `{"mcp":{"shared":{},"only${index}":{}}}`
          : `{"mcp":{"servers":{"shared":{},"only${index}":{}}}}`,
        index + 1,
      ),
    ]),
  );
  const host = memoryHost(files);

  const result = await opencodeAdapter.load(
    {
      ...options,
      environment: { OPENCODE_CONFIG: "/custom/settings.jsonc" },
    },
    host,
  );
  const allRows = rows(result);
  const shared = allRows.filter(({ name }) => name === "shared");

  expect(host.readConfig.mock.calls.map(([path]) => resolve(path))).toEqual([
    resolve(join(options.home, ".config/opencode/opencode.json")),
    resolve(join(options.home, ".config/opencode/opencode.jsonc")),
    resolve("/custom/settings.jsonc"),
    resolve(join(options.projectRoot, "opencode.json")),
    resolve(join(options.projectRoot, "opencode.jsonc")),
    resolve(join(options.projectRoot, "packages/opencode.json")),
    resolve(join(options.projectRoot, "packages/opencode.jsonc")),
    resolve(join(options.cwd, "opencode.json")),
    resolve(join(options.cwd, "opencode.jsonc")),
    resolve(join(options.projectRoot, ".opencode/opencode.json")),
    resolve(join(options.projectRoot, ".opencode/opencode.jsonc")),
    resolve(join(options.projectRoot, "packages/.opencode/opencode.json")),
    resolve(join(options.projectRoot, "packages/.opencode/opencode.jsonc")),
    resolve(join(options.cwd, ".opencode/opencode.json")),
    resolve(join(options.cwd, ".opencode/opencode.jsonc")),
  ]);
  expect(shared).toHaveLength(paths.length);
  expect(shared.slice(0, -1).every((row) => "reason" in row && row.reason === shadowedReason)).toBe(
    true,
  );
  expect(shared.at(-1)).toMatchObject({ configPath: paths.at(-1), reason: unsupportedEntryReason });
  expect(result.configurations.map(({ config }) => config.path)).toEqual(paths);
});

test("gives V2 ownership precedence over V1 in the same document", () => {
  const parsed = parseOpenCodeConfig({
    path: "/workspace/opencode.jsonc",
    scope: "project",
    source:
      '{"mcp":{"files":{"type":"local"},"timeout":{"startup":30000},"servers":{"files":{"type":"local"}}}}',
  });

  expect(parsed.unsupported).toEqual([
    expect.objectContaining({ name: "files", reason: shadowedReason }),
    expect.objectContaining({ name: "files", reason: unsupportedEntryReason }),
  ]);
});

test("treats a valid V1 server named servers as one direct owner", () => {
  const parsed = parseOpenCodeConfig({
    path: "/workspace/opencode.json",
    scope: "project",
    source: '{"mcp":{"servers":{"type":"local","command":["node","server.mjs"]}}}',
  });

  expect(parsed.unsupported).toEqual([]);
  expect(parsed.servers).toEqual([
    expect.objectContaining({
      name: "servers",
      source: expect.objectContaining({ command: "node" }),
    }),
  ]);
});

test("excludes documented V2 timeout metadata from server ownership", () => {
  const parsed = parseOpenCodeConfig({
    path: "/workspace/opencode.jsonc",
    scope: "project",
    source: '{"mcp":{"timeout":{"startup":30000},"servers":{"files":{"type":"local"}}}}',
  });

  expect(parsed.unsupported).toEqual([
    expect.objectContaining({ name: "files", reason: unsupportedEntryReason }),
  ]);
});

test("does not select either JSON sibling when a location is ambiguous", async () => {
  const options = context({ cwd: "/workspace/project" });
  const json = resolve(options.projectRoot, "opencode.json");
  const jsonc = resolve(options.projectRoot, "opencode.jsonc");
  const secret = "AMBIGUOUS_HEADER_SECRET";
  const host = memoryHost(
    new Map([
      [json, snapshot(json, `{"mcp":{"json":{"headers":{"X-Key":"${secret}"}}}}`, 1)],
      [jsonc, snapshot(jsonc, `{"mcp":{"jsonc":{"headers":{"X-Key":"${secret}"}}}}`, 2)],
    ]),
  );

  const result = await opencodeAdapter.load(options, host);

  expect(result.configurations).toEqual([]);
  expect(result.unsupported).toEqual([
    expect.objectContaining({
      name: "(configuration)",
      configPath: resolve(options.projectRoot),
      reason: "ambiguous OpenCode configuration location",
    }),
  ]);
  expect(JSON.stringify(result)).not.toContain(secret);
});

test("preserves sibling ambiguity when OPENCODE_CONFIG names one global sibling", async () => {
  const options = context({ cwd: "/workspace/project" });
  const json = resolve(options.home, ".config/opencode/opencode.json");
  const jsonc = resolve(options.home, ".config/opencode/opencode.jsonc");
  const host = memoryHost(
    new Map([
      [json, snapshot(json, '{"mcp":{"json":{"type":"local"}}}', 1)],
      [jsonc, snapshot(jsonc, '{"mcp":{"servers":{"jsonc":{"type":"local"}}}}', 2)],
    ]),
  );

  const result = await opencodeAdapter.load(
    {
      ...options,
      environment: { OPENCODE_CONFIG: json },
    },
    host,
  );

  expect(result.configurations).toEqual([]);
  expect(result.unsupported).toEqual([
    expect.objectContaining({
      name: "(configuration)",
      configPath: resolve(options.home, ".config/opencode"),
      reason: "ambiguous OpenCode configuration location",
    }),
  ]);
  expect(host.readConfig.mock.calls.filter(([path]) => resolve(path) === json)).toHaveLength(1);
  expect(host.readConfig.mock.calls.filter(([path]) => resolve(path) === jsonc)).toHaveLength(1);
});

test("ambiguous higher siblings suppress matching lower ownership without exposing either file", async () => {
  const options = context({ cwd: "/workspace/project" });
  const global = resolve(options.home, ".config/opencode/opencode.json");
  const json = resolve(options.projectRoot, "opencode.json");
  const jsonc = resolve(options.projectRoot, "opencode.jsonc");
  const secret = "AMBIGUOUS_PROJECT_SECRET";
  const host = memoryHost(
    new Map([
      [
        global,
        snapshot(
          global,
          '{"mcp":{"files":{"type":"local"},"search":{"type":"local"},"global":{}}}',
          1,
        ),
      ],
      [json, snapshot(json, `{"mcp":{"files":{"headers":{"X-Key":"${secret}"}}}}`, 2)],
      [
        jsonc,
        snapshot(jsonc, `{"mcp":{"servers":{"search":{"headers":{"X-Key":"${secret}"}}}}}`, 3),
      ],
    ]),
  );

  const result = await opencodeAdapter.load(options, host);

  expect(result.configurations).toHaveLength(1);
  expect(result.configurations[0]!.config.unsupported).toEqual([
    expect.objectContaining({ name: "files", reason: shadowedReason }),
    expect.objectContaining({ name: "search", reason: shadowedReason }),
    expect.objectContaining({ name: "global", reason: unsupportedEntryReason }),
  ]);
  expect(result.unsupported).toEqual([
    expect.objectContaining({
      name: "(configuration)",
      configPath: resolve(options.projectRoot),
      reason: "ambiguous OpenCode configuration location",
    }),
  ]);
  expect(JSON.stringify(result)).not.toContain(secret);
});

test("a malformed ambiguous sibling contributes no ownership and leaks no content", async () => {
  const options = context({ cwd: "/workspace/project" });
  const global = resolve(options.home, ".config/opencode/opencode.json");
  const json = resolve(options.projectRoot, "opencode.json");
  const jsonc = resolve(options.projectRoot, "opencode.jsonc");
  const secret = "MALFORMED_AMBIGUOUS_SECRET";
  const host = memoryHost(
    new Map([
      [global, snapshot(global, '{"mcp":{"files":{},"malformedOnly":{},"global":{}}}', 1)],
      [json, snapshot(json, '{"mcp":{"files":{}}}', 2)],
      [jsonc, snapshot(jsonc, `{"mcp":{"malformedOnly":{"headers":{"X-Key":"${secret}"}}`, 3)],
    ]),
  );

  const result = await opencodeAdapter.load(options, host);

  expect(result.configurations).toHaveLength(1);
  expect(result.configurations[0]!.config.unsupported).toEqual([
    expect.objectContaining({ name: "files", reason: shadowedReason }),
    expect.objectContaining({ name: "malformedOnly", reason: unsupportedEntryReason }),
    expect.objectContaining({ name: "global", reason: unsupportedEntryReason }),
  ]);
  expect(result.unsupported).toEqual([
    expect.objectContaining({
      name: "(configuration)",
      configPath: resolve(options.projectRoot),
      reason: "ambiguous OpenCode configuration location",
    }),
  ]);
  expect(JSON.stringify(result)).not.toContain(secret);
});

test("inline config content suppresses lower writable ownership without leaking content", async () => {
  const options = context({ cwd: "/workspace/project" });
  const path = resolve(options.home, ".config/opencode/opencode.json");
  const sourceSecret = "INLINE_HEADER_SECRET";
  const localSecret = "LOCAL_HEADER_SECRET";
  const host = memoryHost(
    new Map([
      [
        path,
        snapshot(path, `{"mcp":{"files":{"headers":{"X-Key":"${localSecret}"}},"local":{}}}`, 1),
      ],
    ]),
  );
  const result = await opencodeAdapter.load(
    {
      ...options,
      environment: {
        OPENCODE_CONFIG_CONTENT: `{"mcp":{"files":{"headers":{"X-Key":"${sourceSecret}"}}}}`,
      },
    },
    host,
  );
  const allRows = rows(result);

  expect(allRows.filter(({ name }) => name === "files")).toEqual([
    expect.objectContaining({ configPath: path, reason: shadowedReason }),
    expect.objectContaining({
      configPath: "OPENCODE_CONFIG_CONTENT",
      reason: "inline OpenCode configuration is not writable",
    }),
  ]);
  expect(result.configurations).toHaveLength(1);
  expect(result.configurations[0]!.config.unsupported).toEqual([
    expect.objectContaining({ name: "files", reason: shadowedReason }),
    expect.objectContaining({ name: "local", reason: unsupportedEntryReason }),
  ]);
  expect(JSON.stringify(result.unsupported)).not.toContain(sourceSecret);
  expect(JSON.stringify(result.unsupported)).not.toContain(localSecret);
});

test("reduces a valid inline remote owner to a minimal secret-free unsupported row", async () => {
  const headerSecret = "INLINE_LITERAL_HEADER_SECRET";
  const clientSecret = "INLINE_OAUTH_CLIENT_SECRET";

  const result = await opencodeAdapter.load(
    context({
      cwd: "/workspace/project",
      environment: {
        OPENCODE_CONFIG_CONTENT: JSON.stringify({
          mcp: {
            servers: {
              protected: {
                type: "remote",
                url: "https://example.test/mcp",
                headers: { "X-Key": headerSecret },
                oauth: { client_id: "inline-client", client_secret: clientSecret },
              },
            },
          },
        }),
      },
    }),
    memoryHost(new Map()),
  );

  expect(result.unsupported).toEqual([
    {
      client: "opencode",
      scope: "user",
      name: "protected",
      configPath: "OPENCODE_CONFIG_CONTENT",
      reason: "inline OpenCode configuration is not writable",
    },
  ]);
  expect(JSON.stringify(result.unsupported)).not.toMatch(
    /INLINE_LITERAL_HEADER_SECRET|INLINE_OAUTH_CLIENT_SECRET/,
  );
});

test("reads selectors once, never reads unrelated getter-backed secrets, and keeps errors sanitized", async () => {
  const options = context({ cwd: "/workspace/project" });
  const customPath = resolve("/custom/opencode.jsonc");
  const environment: NodeJS.ProcessEnv = {};
  let configReads = 0;
  let contentReads = 0;
  let secretReads = 0;
  Object.defineProperties(environment, {
    OPENCODE_CONFIG: {
      enumerable: true,
      get() {
        configReads += 1;
        return customPath;
      },
    },
    OPENCODE_CONFIG_CONTENT: {
      enumerable: true,
      get() {
        contentReads += 1;
        return '{"mcp":{"inline":{}}}';
      },
    },
    HEADER_SECRET: {
      enumerable: true,
      get() {
        secretReads += 1;
        return "GETTER_SECRET_VALUE";
      },
    },
  });
  const host = memoryHost(
    new Map([
      [
        customPath,
        snapshot(customPath, '{"mcp":{"broken":{"headers":{"X-Key":"{env:HEADER_SECRET}"}}}}', 1),
      ],
    ]),
  );

  const result = await opencodeAdapter.load({ ...options, environment }, host);

  expect({ configReads, contentReads, secretReads }).toEqual({
    configReads: 1,
    contentReads: 1,
    secretReads: 0,
  });
  expect(JSON.stringify(result)).not.toContain("GETTER_SECRET_VALUE");
});

test.each(["symlink", "hardlink"] as const)(
  "rejects %s aliases by snapshot identity",
  async (kind) => {
    const root = await realpath(await mkdtemp(join(tmpdir(), `mcp-restrictor-opencode-${kind}-`)));
    const home = join(root, "home");
    const projectRoot = join(root, "project");
    const global = join(home, ".config/opencode/opencode.json");
    const project = join(projectRoot, "opencode.json");
    await mkdir(dirname(global), { recursive: true });
    await mkdir(projectRoot, { recursive: true });
    await writeFile(global, '{"mcp":{"files":{}}}');
    if (kind === "symlink") await symlink(global, project);
    else await link(global, project);

    const host: ClientAdapterHost = {
      async readConfig(path) {
        try {
          const [content, metadata] = await Promise.all([readFile(path, "utf8"), stat(path)]);
          return {
            path,
            content,
            mode: metadata.mode & 0o7777,
            size: metadata.size,
            mtimeMs: metadata.mtimeMs,
            dev: metadata.dev,
            ino: metadata.ino,
          };
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
          throw error;
        }
      },
      readSecretFile: vi.fn(),
    };

    try {
      await expect(
        opencodeAdapter.load({ home, projectRoot, cwd: projectRoot, environment: {} }, host),
      ).rejects.toThrow("OpenCode configuration paths resolve to the same file");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  },
);

test("deduplicates equivalent resolved paths at their highest-precedence location", async () => {
  const options = context({ cwd: "/workspace/project" });
  const direct = resolve(options.projectRoot, "opencode.json");
  const customAlias = join(options.projectRoot, "nested", "..", "opencode.json");
  const host = memoryHost(new Map([[direct, snapshot(direct, '{"mcp":{"files":{}}}', 1)]]));

  const result = await opencodeAdapter.load(
    {
      ...options,
      environment: { OPENCODE_CONFIG: customAlias },
    },
    host,
  );

  expect(result.configurations).toHaveLength(1);
  expect(result.configurations[0]!.config).toMatchObject({
    path: direct,
    scope: "project",
  });
  expect(result.configurations[0]!.config.unsupported).toEqual([
    expect.objectContaining({ name: "files", scope: "project" }),
  ]);
  expect(host.readConfig.mock.calls.filter(([path]) => resolve(path) === direct)).toHaveLength(1);
});

test("turns malformed documents into sanitized non-writable rows while retaining valid files", async () => {
  const options = context({ cwd: "/workspace/project" });
  const global = resolve(options.home, ".config/opencode/opencode.json");
  const project = resolve(options.projectRoot, "opencode.json");
  const secret = "MALFORMED_SECRET";
  const host = memoryHost(
    new Map([
      [global, snapshot(global, `{"mcp":{"bad":{"headers":{"X-Key":"${secret}"}},"bad":{}}}`, 1)],
      [project, snapshot(project, '{"mcp":{"good":{}}}', 2)],
    ]),
  );

  const result = await opencodeAdapter.load(options, host);

  expect(result.configurations.map(({ config }) => config.path)).toEqual([project]);
  expect(result.unsupported).toEqual([
    expect.objectContaining({
      name: "(configuration)",
      configPath: global,
      reason: "Invalid OpenCode configuration",
    }),
  ]);
  expect(JSON.stringify(result.unsupported)).not.toContain(secret);
});

test.each([
  ["v1", { enabled: true, timeout: 5_000 }],
  [
    "v2",
    {
      disabled: false,
      codemode: false,
      timeout: { startup: 1, catalog: 2, execution: 3 },
    },
  ],
] as const)("parses a supported %s local command and documented controls", (schema, controls) => {
  const original = {
    type: "local",
    command: ["node", "server.mjs"],
    cwd: "/workspace",
    environment: { MODE: "literal" },
    ...controls,
  };

  const parsed = parseLocal(schema, original);

  expect(parsed.unsupported).toEqual([]);
  expect(parsed.servers).toEqual([
    expect.objectContaining({
      client: "opencode",
      scope: "project",
      name: "files",
      configPath: "/workspace/project/opencode.jsonc",
      source: {
        kind: "stdio",
        command: "node",
        args: ["server.mjs"],
        envNames: ["MODE"],
        cwd: "/workspace",
      },
      upstream: {
        kind: "stdio",
        command: "node",
        args: ["server.mjs"],
        cwd: "/workspace",
      },
      wrapperEnvironment: { env: { MODE: "literal" } },
      original,
    }),
  ]);
});

test.each([
  ["v1", { enabled: false }],
  ["v2", { disabled: true }],
] as const)("keeps a disabled %s local row visible but unselectable", (schema, control) => {
  const parsed = parseLocal(schema, {
    type: "local",
    command: ["node"],
    ...control,
  });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported).toEqual([
    expect.objectContaining({ name: "files", reason: "disabled server is not supported" }),
  ]);
});

test.each([
  ["empty command", "v1", { type: "local", command: [] }],
  ["non-string command member", "v2", { type: "local", command: ["node", 1] }],
  ["invalid cwd", "v1", { type: "local", command: ["node"], cwd: 42 }],
  ["invalid environment", "v2", { type: "local", command: ["node"], environment: { KEY: 42 } }],
  ["invalid V1 enablement", "v1", { type: "local", command: ["node"], enabled: "yes" }],
  ["invalid V1 timeout", "v1", { type: "local", command: ["node"], timeout: 0 }],
  ["invalid V2 disablement", "v2", { type: "local", command: ["node"], disabled: "yes" }],
  ["invalid V2 codemode", "v2", { type: "local", command: ["node"], codemode: "no" }],
  [
    "invalid V2 timeout member",
    "v2",
    { type: "local", command: ["node"], timeout: { catalog: 0 } },
  ],
  ["V1-only field on V2", "v2", { type: "local", command: ["node"], enabled: true }],
  ["V2-only field on V1", "v1", { type: "local", command: ["node"], codemode: true }],
  ["unknown behavior field", "v1", { type: "local", command: ["node"], reconnect: true }],
] as const)("fails closed for a malformed local entry: %s", (_case, schema, entry) => {
  const parsed = parseLocal(schema, entry as Record<string, unknown>);

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported).toEqual([expect.objectContaining({ name: "files" })]);
});

test("preserves local substitutions structurally without reading them before resolve", async () => {
  const environment: NodeJS.ProcessEnv = {};
  let rootReads = 0;
  Object.defineProperty(environment, "ROOT", {
    enumerable: true,
    get() {
      rootReads += 1;
      return "/resolved/root";
    },
  });
  const path = "/workspace/project/opencode.jsonc";
  const entry = {
    type: "local",
    command: ["node", "server.mjs", "--root", "{env:ROOT}"],
    cwd: "/workspace",
    environment: {
      API_KEY: "{file:secrets/key}",
      MODE: "literal",
    },
  };
  const host = memoryHost(
    new Map([[path, snapshot(path, JSON.stringify({ mcp: { servers: { files: entry } } }), 1)]]),
  );

  const loaded = await opencodeAdapter.load(
    context({
      cwd: "/workspace/project",
      environment,
    }),
    host,
  );
  const parsed = loaded.configurations[0]!.config;

  expect(rootReads).toBe(0);
  expect(host.readSecretFile).not.toHaveBeenCalled();
  expect(parsed.servers[0]).toMatchObject({
    source: {
      command: "node",
      args: ["server.mjs", "--root", "{env:ROOT}"],
      envNames: ["API_KEY", "MODE"],
      cwd: "/workspace",
    },
    wrapperEnvironment: {
      env: { API_KEY: "{file:secrets/key}", MODE: "literal" },
    },
  });
});

test("resolves env, config-relative file, and literal substitutions once per candidate", async () => {
  const environment: NodeJS.ProcessEnv = {};
  let rootReads = 0;
  Object.defineProperty(environment, "ROOT", {
    enumerable: true,
    get() {
      rootReads += 1;
      return "/resolved/root";
    },
  });
  const path = "/workspace/project/config/opencode.jsonc";
  const keyPath = "/workspace/project/config/secrets/key";
  const keySnapshot = snapshot(keyPath, "file-secret", 99);
  const host = memoryHost(new Map());
  host.readSecretFile.mockResolvedValue(keySnapshot);
  const candidate = parseLocal(
    "v1",
    {
      type: "local",
      command: ["{env:ROOT}", "server.mjs", "{env:ROOT}"],
      environment: {
        FIRST: "{file:secrets/key}",
        SECOND: "{file:secrets/key}",
        MODE: "literal",
      },
    },
    path,
  ).servers[0]!;

  const resolved = await opencodeAdapter.resolve!(candidate, resolveContext(environment), host);

  expect(rootReads).toBe(1);
  expect(host.readSecretFile).toHaveBeenCalledTimes(1);
  expect(host.readSecretFile).toHaveBeenCalledWith(keyPath);
  expect(resolved.dependencies).toEqual([
    { kind: "environment", name: "ROOT", value: "/resolved/root" },
    { kind: "file", snapshot: keySnapshot },
  ]);
  expect(resolved.candidate).toMatchObject({
    source: {
      kind: "stdio",
      command: "{env:ROOT}",
      args: ["server.mjs", "{env:ROOT}"],
      envNames: ["FIRST", "MODE", "SECOND"],
    },
    upstream: {
      kind: "stdio",
      command: "/resolved/root",
      args: ["server.mjs", "/resolved/root"],
      env: expect.objectContaining({
        FIRST: "file-secret",
        SECOND: "file-secret",
        MODE: "literal",
      }),
    },
    wrapperEnvironment: {
      env: {
        FIRST: "{file:secrets/key}",
        SECOND: "{file:secrets/key}",
        MODE: "literal",
      },
    },
  });
});

test("requires substitutions to be exact and environment values to be own strings", async () => {
  const malformed = parseLocal("v1", {
    type: "local",
    command: ["node", "prefix-{env:ROOT}"],
  });
  expect(malformed.servers).toEqual([]);

  const inherited = Object.create({ ROOT: "/inherited" }) as NodeJS.ProcessEnv;
  const candidate = parseLocal("v1", {
    type: "local",
    command: ["node", "{env:ROOT}"],
  }).servers[0]!;
  await expect(
    opencodeAdapter.resolve!(candidate, resolveContext(inherited), memoryHost(new Map())),
  ).rejects.toThrow();
});

test.each([
  ["bare", "mcp-restrictor"],
  ["absolute", "/trusted/bin/mcp-restrictor"],
] as const)("unwraps a managed %s OpenCode command exactly once", (_case, command) => {
  const parsed = parseLocal("v2", {
    type: "local",
    command: [
      command,
      "--policy",
      ".mcp-restrictor/policies/opencode/files.yaml",
      "--upstream-env",
      "TOKEN",
      "--upstream-cwd",
      "/upstream",
      "--",
      "node",
      "server.mjs",
    ],
    cwd: "/workspace/project",
    environment: { TOKEN: "{env:TOKEN}" },
  });

  expect(parsed.unsupported).toEqual([]);
  expect(parsed.servers[0]).toMatchObject({
    source: {
      kind: "stdio",
      command: "node",
      args: ["server.mjs"],
      envNames: ["TOKEN"],
      cwd: "/upstream",
    },
    managedPolicyPath: "/workspace/project/.mcp-restrictor/policies/opencode/files.yaml",
  });
  expect(parsed.servers[0]!.source).not.toMatchObject({ command });
});

test.each([
  ["bare nested", "mcp-restrictor"],
  ["absolute nested", "/trusted/bin/mcp-restrictor"],
] as const)("rejects a managed OpenCode wrapper that would remain nested: %s", (_case, nested) => {
  const parsed = parseLocal("v1", {
    type: "local",
    command: [
      "mcp-restrictor",
      "--policy",
      "/outer.yaml",
      "--",
      nested,
      "--policy",
      "/inner.yaml",
      "--",
      "node",
    ],
  });

  expect(parsed.servers).toEqual([]);
  expect(parsed.unsupported).toHaveLength(1);
});

test.each([
  ["bare", "mcp-restrictor"],
  ["absolute", "/trusted/bin/mcp-restrictor"],
] as const)(
  "resolves a managed %s OpenCode WebSocket header without nesting",
  async (_case, command) => {
    const environment: NodeJS.ProcessEnv = {};
    let reads = 0;
    Object.defineProperty(environment, "WS_SECRET", {
      enumerable: true,
      get() {
        reads += 1;
        return "websocket-secret";
      },
    });
    const candidate = parseLocal("v2", {
      type: "local",
      command: [
        command,
        "--policy",
        ".mcp-restrictor/policies/opencode/socket.yaml",
        "--upstream-websocket",
        "wss://example.test/mcp",
        "--upstream-header-env",
        "X-Auth=WS_AUTH",
      ],
      environment: { WS_AUTH: "{env:WS_SECRET}" },
    }).servers[0]!;
    const source = {
      kind: "websocket" as const,
      url: "wss://example.test/mcp",
      headers: [{ name: "X-Auth", environmentVariable: "WS_AUTH" }],
    };

    expect(candidate.source).toEqual(source);
    const resolved = await opencodeAdapter.resolve!(
      candidate,
      resolveContext(environment),
      memoryHost(new Map()),
    );

    expect(reads).toBe(1);
    expect(resolved.dependencies).toEqual([
      { kind: "environment", name: "WS_SECRET", value: "websocket-secret" },
    ]);
    expect(resolved.candidate.source).toEqual(source);
    expect(resolved.candidate.upstream).toEqual({
      kind: "websocket",
      url: "wss://example.test/mcp",
      headers: [["X-Auth", "websocket-secret"]],
    });
    const planned = planManagedWrapper({
      server: resolved.candidate,
      allowedTools: ["read_file"],
      policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
      restrictor: { command: "mcp-restrictor", argsPrefix: [] },
    });
    expect(planned.replacement.args).toEqual([
      "--policy",
      "/policy.yaml",
      "--upstream-websocket",
      "wss://example.test/mcp",
      "--upstream-header-env",
      "X-Auth=WS_AUTH",
    ]);
    expect(planned.replacement.args).not.toContain(command);
    expect(JSON.stringify(planned.replacement)).not.toContain("websocket-secret");
  },
);

test("maps literal, environment, and file headers to collision-free wrapper names without values in argv", async () => {
  const environment = {
    mcp_restrictor_upstream_header_0: "occupied",
    HEADER_ENV: "environment-secret",
  };
  const path = "/workspace/project/config/opencode.jsonc";
  const keyPath = "/workspace/project/config/secrets/key";
  const keySnapshot = snapshot(keyPath, "file-secret", 91);
  const host = memoryHost(new Map());
  host.readSecretFile.mockResolvedValue(keySnapshot);
  const candidate = parseRemote(
    "v2",
    {
      type: "remote",
      url: "https://example.test/mcp",
      oauth: false,
      disabled: false,
      codemode: true,
      timeout: { startup: 1, catalog: 2, execution: 3 },
      headers: {
        "X-Literal": "literal-secret",
        "X-Env": "{env:HEADER_ENV}",
        "X-File": "{file:secrets/key}",
      },
    },
    path,
    environment,
  ).servers[0]!;

  expect(candidate).toMatchObject({
    source: {
      kind: "http",
      url: "https://example.test/mcp",
      headers: [
        { name: "X-Literal", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_1" },
        { name: "X-Env", environmentVariable: "HEADER_ENV" },
        { name: "X-File", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_2" },
      ],
    },
    wrapperEnvironment: {
      env: {
        MCP_RESTRICTOR_UPSTREAM_HEADER_1: "literal-secret",
        HEADER_ENV: "{env:HEADER_ENV}",
        MCP_RESTRICTOR_UPSTREAM_HEADER_2: "{file:secrets/key}",
      },
    },
  });
  expect(candidate.upstream).toEqual({
    kind: "http",
    url: "https://example.test/mcp",
    headers: [
      ["X-Literal", "configured"],
      ["X-Env", "configured"],
      ["X-File", "configured"],
    ],
  });

  const resolved = await opencodeAdapter.resolve!(candidate, resolveContext(environment), host);
  expect(host.readSecretFile).toHaveBeenCalledExactlyOnceWith(keyPath);
  expect(resolved.dependencies).toEqual([
    { kind: "environment", name: "HEADER_ENV", value: "environment-secret" },
    { kind: "file", snapshot: keySnapshot },
  ]);
  expect(resolved.candidate.upstream).toEqual({
    kind: "http",
    url: "https://example.test/mcp",
    headers: [
      ["X-Literal", "literal-secret"],
      ["X-Env", "environment-secret"],
      ["X-File", "file-secret"],
    ],
  });

  const planned = planManagedWrapper({
    server: resolved.candidate,
    allowedTools: ["read_file"],
    policy: { diskPath: "/policy.yaml", argument: "/policy.yaml" },
    restrictor: { command: "mcp-restrictor", argsPrefix: [] },
  });
  expect(planned.replacement.args).toEqual([
    "--policy",
    "/policy.yaml",
    "--upstream-http",
    "https://example.test/mcp",
    "--upstream-header-env",
    "X-Literal=MCP_RESTRICTOR_UPSTREAM_HEADER_1",
    "--upstream-header-env",
    "X-Env=HEADER_ENV",
    "--upstream-header-env",
    "X-File=MCP_RESTRICTOR_UPSTREAM_HEADER_2",
  ]);
  expect(JSON.stringify(planned.replacement.args)).not.toMatch(
    /literal-secret|environment-secret|file-secret/,
  );
});

test.each([
  {
    name: "exact Bearer authorization",
    authorization: "Bearer bearer-secret",
    source: {
      kind: "http",
      url: "https://example.test/mcp",
      headers: [],
      bearerTokenEnvVar: "MCP_RESTRICTOR_UPSTREAM_HEADER_0",
    },
    upstream: { kind: "http", url: "https://example.test/mcp", bearerToken: "bearer-secret" },
  },
  {
    name: "generic authorization",
    authorization: "Basic generic-secret",
    source: {
      kind: "http",
      url: "https://example.test/mcp",
      headers: [{ name: "Authorization", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_0" }],
    },
    upstream: {
      kind: "http",
      url: "https://example.test/mcp",
      headers: [["Authorization", "Basic generic-secret"]],
    },
  },
] as const)("preserves $name under oauth:false", async ({ authorization, source, upstream }) => {
  const candidate = parseRemote("v1", {
    type: "remote",
    url: "https://example.test/mcp",
    oauth: false,
    enabled: true,
    timeout: 5_000,
    headers: { Authorization: authorization },
  }).servers[0]!;

  expect(candidate.source).toEqual(source);
  expect(candidate.oauth).toBeUndefined();
  const resolved = await opencodeAdapter.resolve!(
    candidate,
    resolveContext(),
    memoryHost(new Map()),
  );
  expect(resolved.candidate.upstream).toEqual(upstream);
});

test("maps omitted OAuth to challenge mode with the V1 callback default", () => {
  const candidate = parseRemote("v1", {
    type: "remote",
    url: "https://example.test/mcp",
  }).servers[0]!;

  expect(candidate.oauth).toEqual({
    mode: "challenge",
    callback: {
      url: "http://127.0.0.1:19876/mcp/oauth/callback",
      appendProfileId: false,
    },
  });
});

test("gives only V1 remote entries one ordered SSE protocol alternative", () => {
  const v1 = parseRemote("v1", {
    type: "remote",
    url: "https://example.test/mcp",
    oauth: false,
    headers: { "X-Key": "secret" },
  }).servers[0]!;
  const v2 = parseRemote("v2", {
    type: "remote",
    url: "https://example.test/mcp",
    oauth: false,
    headers: { "X-Key": "secret" },
  }).servers[0]!;

  expect(v1.alternatives).toEqual([
    {
      source: {
        kind: "sse",
        url: "https://example.test/mcp",
        headers: [{ name: "X-Key", environmentVariable: "MCP_RESTRICTOR_UPSTREAM_HEADER_0" }],
      },
      upstream: {
        kind: "sse",
        url: "https://example.test/mcp",
        headers: [["X-Key", "configured"]],
      },
    },
  ]);
  expect(v2.alternatives).toBeUndefined();
  const error = new UpstreamProtocolIncompatibleError();
  expect(error.message).toBe("Upstream transport protocol is incompatible");
  expect(error).not.toHaveProperty("response");
});

test("resolves V1 HTTP and SSE alternatives from the same header and bearer values", async () => {
  const candidate = parseRemote("v1", {
    type: "remote",
    url: "https://example.test/mcp",
    oauth: false,
    headers: {
      Authorization: "Bearer {env:TOKEN}",
      "X-Key": "{env:HEADER}",
    },
  }).servers[0]!;

  const resolved = await opencodeAdapter.resolve!(
    candidate,
    resolveContext({ TOKEN: "token-secret", HEADER: "header-secret" }),
    memoryHost(new Map()),
  );

  expect(resolved.candidate.upstream).toMatchObject({
    kind: "http",
    headers: [["X-Key", "header-secret"]],
    bearerToken: "token-secret",
  });
  expect(resolved.candidate.alternatives).toEqual([
    {
      source: expect.objectContaining({ kind: "sse" }),
      upstream: expect.objectContaining({
        kind: "sse",
        headers: [["X-Key", "header-secret"]],
        bearerToken: "token-secret",
      }),
    },
  ]);
});

test.each([
  {
    schema: "v1",
    oauth: {
      clientId: "v1-client",
      clientSecret: "{env:V1_SECRET}",
      scope: "read write",
      callbackPort: 3101,
    },
    environment: { V1_SECRET: "v1-secret" },
    secretPath: undefined,
    expected: {
      mode: "explicit",
      clientId: "v1-client",
      clientSecret: "v1-secret",
      requestedScope: "read write",
      callback: {
        host: "127.0.0.1",
        path: "/mcp/oauth/callback",
        port: 3101,
        appendProfileId: false,
      },
    },
    dependencies: [{ kind: "environment", name: "V1_SECRET", value: "v1-secret" }],
  },
  {
    schema: "v2",
    oauth: {
      client_id: "{env:V2_CLIENT}",
      client_secret: "{file:secrets/client}",
      scope: "catalog",
      redirect_uri: "https://callback.example/finish?tenant=one",
    },
    environment: { V2_CLIENT: "v2-client" },
    secretPath: "/workspace/project/secrets/client",
    expected: {
      mode: "explicit",
      clientId: "v2-client",
      clientSecret: "v2-secret",
      requestedScope: "catalog",
      callback: {
        url: "https://callback.example/finish?tenant=one",
        appendProfileId: false,
      },
    },
    dependencies: [
      { kind: "environment", name: "V2_CLIENT", value: "v2-client" },
      { kind: "file", snapshot: snapshot("/workspace/project/secrets/client", "v2-secret", 92) },
    ],
  },
] as const)("maps and resolves $schema OAuth names without prompting inputs early", async (row) => {
  const host = memoryHost(new Map());
  if (row.secretPath) {
    host.readSecretFile.mockResolvedValue(snapshot(row.secretPath, "v2-secret", 92));
  }
  const candidate = parseRemote(row.schema, {
    type: "remote",
    url: "https://example.test/mcp",
    oauth: row.oauth,
  }).servers[0]!;

  expect(candidate.oauth).not.toHaveProperty("clientSecret");
  const resolved = await opencodeAdapter.resolve!(candidate, resolveContext(row.environment), host);
  expect(resolved.candidate.oauth).toEqual(row.expected);
  expect(resolved.dependencies).toEqual(row.dependencies);
});

test.each([
  [
    "V1 fixed default",
    "v1",
    {},
    {
      url: "http://127.0.0.1:19876/mcp/oauth/callback",
      appendProfileId: false,
    },
  ],
  [
    "V1 exact redirect",
    "v1",
    { redirectUri: "https://callback.example/finish" },
    {
      url: "https://callback.example/finish",
      appendProfileId: false,
    },
  ],
  [
    "V2 callback port",
    "v2",
    { callback_port: 4202 },
    {
      host: "127.0.0.1",
      path: "/mcp/oauth/callback",
      port: 4202,
      appendProfileId: false,
    },
  ],
  [
    "V2 ephemeral default",
    "v2",
    {},
    {
      host: "127.0.0.1",
      path: "/mcp/oauth/callback",
      port: 0,
      appendProfileId: false,
    },
  ],
  [
    "V1 redirect precedence",
    "v1",
    {
      redirectUri: "https://callback.example/v1",
      callbackPort: 4101,
    },
    {
      url: "https://callback.example/v1",
      appendProfileId: false,
    },
  ],
  [
    "V2 redirect precedence",
    "v2",
    {
      redirect_uri: "https://callback.example/v2",
      callback_port: 4102,
    },
    {
      url: "https://callback.example/v2",
      appendProfileId: false,
    },
  ],
] as const)("maps the $schema callback strategy for %s", (_name, schema, oauth, callback) => {
  expect(
    parseRemote(schema, {
      type: "remote",
      url: "https://example.test/mcp",
      oauth,
    }).servers[0]!.oauth?.callback,
  ).toEqual(callback);
});

test.each([
  [
    "V1 lower",
    "v1",
    1,
    {
      host: "127.0.0.1",
      path: "/mcp/oauth/callback",
      port: 1,
      appendProfileId: false,
    },
  ],
  [
    "V1 upper",
    "v1",
    65_535,
    {
      host: "127.0.0.1",
      path: "/mcp/oauth/callback",
      port: 65_535,
      appendProfileId: false,
    },
  ],
  [
    "V2 lower",
    "v2",
    1,
    {
      host: "127.0.0.1",
      path: "/mcp/oauth/callback",
      port: 1,
      appendProfileId: false,
    },
  ],
  [
    "V2 upper",
    "v2",
    65_535,
    {
      host: "127.0.0.1",
      path: "/mcp/oauth/callback",
      port: 65_535,
      appendProfileId: false,
    },
  ],
] as const)(
  "accepts the explicit callback-port boundary for %s without early reads",
  async (_name, schema, port, callback) => {
    const path = "/workspace/project/opencode.jsonc";
    const environment: NodeJS.ProcessEnv = {};
    let reads = 0;
    Object.defineProperty(environment, "OAUTH_CLIENT", {
      enumerable: true,
      get() {
        reads += 1;
        return "client";
      },
    });
    const oauth =
      schema === "v1"
        ? {
            clientId: "{env:OAUTH_CLIENT}",
            clientSecret: "{file:secrets/client}",
            callbackPort: port,
          }
        : {
            client_id: "{env:OAUTH_CLIENT}",
            client_secret: "{file:secrets/client}",
            callback_port: port,
          };
    const entry = { type: "remote", url: "https://example.test/mcp", oauth };
    const mcp = schema === "v1" ? { boundary: entry } : { servers: { boundary: entry } };
    const host = memoryHost(new Map([[path, snapshot(path, JSON.stringify({ mcp }), 95)]]));

    const result = await opencodeAdapter.load(
      context({
        projectRoot: "/workspace/project",
        cwd: "/workspace/project",
        environment,
      }),
      host,
    );

    expect(result.configurations[0]!.config.servers).toEqual([
      expect.objectContaining({ name: "boundary", oauth: expect.objectContaining({ callback }) }),
    ]);
    expect(reads).toBe(0);
    expect(host.readSecretFile).not.toHaveBeenCalled();
  },
);

test.each([
  ["OAuth Authorization conflict", "v1", { oauth: {}, headers: { Authorization: "Basic secret" } }],
  ["challenge Authorization conflict", "v2", { headers: { authorization: "Basic secret" } }],
  ["reserved header", "v1", { oauth: false, headers: { Accept: "secret" } }],
  ["CRLF header", "v2", { oauth: false, headers: { "X-Key": "secret\r\nattack" } }],
  [
    "case-insensitive duplicate headers",
    "v1",
    { oauth: false, headers: { "X-Key": "one", "x-key": "two" } },
  ],
  ["URL credentials", "v2", { oauth: false, url: "https://user:pass@example.test/mcp" }],
  ["URL query", "v1", { oauth: false, url: "https://example.test/mcp?secret=one" }],
  ["URL fragment", "v2", { oauth: false, url: "https://example.test/mcp#fragment" }],
  ["malformed scope", "v1", { oauth: { scope: "read  write" } }],
  ["explicit V1 callback port zero", "v1", { oauth: { callbackPort: 0 } }],
  ["explicit V2 callback port zero", "v2", { oauth: { callback_port: 0 } }],
  ["malformed callback port", "v1", { oauth: { callbackPort: 65_536 } }],
  ["malformed callback URL", "v2", { oauth: { redirect_uri: "http://remote.example/finish" } }],
  [
    "reserved callback query",
    "v1",
    { oauth: { redirectUri: "https://callback.example/finish?code=one" } },
  ],
  [
    "duplicate callback query",
    "v2",
    { oauth: { redirect_uri: "https://callback.example/finish?tenant=one&tenant=two" } },
  ],
  ["client secret without client ID", "v1", { oauth: { clientSecret: "secret" } }],
  ["wrong OAuth schema names", "v2", { oauth: { clientId: "client" } }],
  [
    "master-key environment alias",
    "v1",
    { headers: { "X-Key": `{env:${MASTER_KEY_FILE_ENV.toLowerCase()}}` } },
  ],
  ["unknown behavior field", "v2", { oauth: false, reconnect: true }],
] as const)("fails closed structurally for remote input with %s", (_name, schema, partial) => {
  const parsed = parseRemoteWithControl(schema, {
    type: "remote",
    url: "https://example.test/mcp",
    ...partial,
  });

  expect(parsed.servers).toEqual([expect.objectContaining({ name: "control" })]);
  expect(parsed.unsupported).toEqual([expect.objectContaining({ name: "files" })]);
});

test("rejects structural remote failures before environment getters or secret files", async () => {
  const path = "/workspace/project/opencode.json";
  const environment: NodeJS.ProcessEnv = {};
  let reads = 0;
  Object.defineProperty(environment, "HEADER_SECRET", {
    enumerable: true,
    get() {
      reads += 1;
      return "getter-secret";
    },
  });
  const host = memoryHost(
    new Map([
      [
        path,
        snapshot(
          path,
          JSON.stringify({
            mcp: {
              files: {
                type: "remote",
                url: "https://example.test/mcp",
                oauth: false,
                headers: {
                  Accept: "{env:HEADER_SECRET}",
                  "X-File": "{file:secrets/key}",
                },
              },
              control: {
                type: "remote",
                url: "https://control.example/mcp",
                oauth: false,
              },
            },
          }),
          93,
        ),
      ],
    ]),
  );

  const result = await opencodeAdapter.load(
    context({
      projectRoot: "/workspace/project",
      cwd: "/workspace/project",
      environment,
    }),
    host,
  );

  expect(result.configurations[0]!.config.servers).toEqual([
    expect.objectContaining({ name: "control" }),
  ]);
  expect(reads).toBe(0);
  expect(host.readSecretFile).not.toHaveBeenCalled();
});

test("rejects an explicit zero callback port before OAuth substitution reads", async () => {
  const path = "/workspace/project/opencode.jsonc";
  const environment: NodeJS.ProcessEnv = {};
  let reads = 0;
  Object.defineProperty(environment, "OAUTH_CLIENT", {
    enumerable: true,
    get() {
      reads += 1;
      return "client";
    },
  });
  const host = memoryHost(
    new Map([
      [
        path,
        snapshot(
          path,
          JSON.stringify({
            mcp: {
              servers: {
                invalid: {
                  type: "remote",
                  url: "https://example.test/mcp",
                  oauth: {
                    client_id: "{env:OAUTH_CLIENT}",
                    client_secret: "{file:secrets/client}",
                    callback_port: 0,
                  },
                },
                control: {
                  type: "remote",
                  url: "https://control.example/mcp",
                  oauth: false,
                },
              },
            },
          }),
          94,
        ),
      ],
    ]),
  );

  const result = await opencodeAdapter.load(
    context({
      projectRoot: "/workspace/project",
      cwd: "/workspace/project",
      environment,
    }),
    host,
  );

  expect(result.configurations[0]!.config.servers).toEqual([
    expect.objectContaining({ name: "control" }),
  ]);
  expect(result.configurations[0]!.config.unsupported).toEqual([
    expect.objectContaining({ name: "invalid" }),
  ]);
  expect(reads).toBe(0);
  expect(host.readSecretFile).not.toHaveBeenCalled();
});

test("the hardened production snapshot reader rejects symlink config reads", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-opencode-host-")));
  const target = join(root, "target.json");
  const alias = join(root, "alias.json");
  await writeFile(target, "{}");
  await symlink(target, alias);
  try {
    await expect(readSnapshot(alias)).rejects.toThrow("not a regular file");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("surgically renders selected V1 and V2 entries without changing either schema or unselected bytes", () => {
  const source = `{
  // before selected V1
  "mcp": {
    "selectedV1": {
      // selected V1 internal comment may be regenerated
      "type": "remote",
      "url": "https://v1.example/mcp",
      "headers": { "X-Key": "secret-v1" },
      "oauth": false,
      "enabled": true,
      "timeout": 9000
    },
    // unselected-start
    "unselected": {
      "type": "future",
      "nested": { "unknown": [1, { "keep": true }] }
    },
    // unselected-end
    "servers": {
      "selectedV2": {
        // selected V2 internal comment may be regenerated
        "type": "remote",
        "url": "https://v2.example/mcp",
        "headers": { "X-Key": "secret-v2" },
        "oauth": false,
        "disabled": false,
        "codemode": true,
        "timeout": { "startup": 1, "catalog": 2, "execution": 3 }
      },
      "unselectedV2": {
        "type": "future",
        "nested": { "preserve": "exactly" }
      }
    }
  }
  // after selected V2
}\n`;
  const config = parseOpenCodeConfig({
    path: "/workspace/project/opencode.jsonc",
    scope: "project",
    source,
  });
  const replacement = (marker: string): Replacement => ({
    command: "/usr/bin/node",
    args: ["restrictor.mjs", "--policy", `${marker}.yaml`],
    env: { SECRET: "{env:SECRET}" },
    cwd: "/workspace/project",
  });
  const selectedStart = source.indexOf("{", source.indexOf('"selectedV1"'));
  const unselectedStart = source.indexOf("    // unselected-start");
  const unselectedEnd = source.indexOf("    // unselected-end") + "    // unselected-end\n".length;
  const suffix = source.slice(source.indexOf("  // after selected V2"));

  const rendered = renderOpenCodeConfig(
    config,
    new Map([
      ["selectedV1", replacement("v1")],
      ["selectedV2", replacement("v2")],
    ]),
  );
  const parsed = parseJsonc(rendered) as {
    mcp: Record<string, any> & { servers: Record<string, any> };
  };

  expect(rendered.slice(0, selectedStart)).toBe(source.slice(0, selectedStart));
  expect(
    rendered.slice(
      rendered.indexOf("    // unselected-start"),
      rendered.indexOf("    // unselected-end") + "    // unselected-end\n".length,
    ),
  ).toBe(source.slice(unselectedStart, unselectedEnd));
  expect(rendered.endsWith(suffix)).toBe(true);
  expect(parsed.mcp.unselected).toEqual({
    type: "future",
    nested: { unknown: [1, { keep: true }] },
  });
  expect(parsed.mcp.servers.unselectedV2).toEqual({
    type: "future",
    nested: { preserve: "exactly" },
  });
  expect(parsed.mcp.selectedV1).toEqual({
    type: "local",
    command: ["/usr/bin/node", "restrictor.mjs", "--policy", "v1.yaml"],
    environment: { SECRET: "{env:SECRET}" },
    cwd: "/workspace/project",
    enabled: true,
    timeout: 9000,
  });
  expect(parsed.mcp.servers.selectedV2).toEqual({
    type: "local",
    command: ["/usr/bin/node", "restrictor.mjs", "--policy", "v2.yaml"],
    environment: { SECRET: "{env:SECRET}" },
    cwd: "/workspace/project",
    disabled: false,
    codemode: true,
    timeout: { startup: 1, catalog: 2, execution: 3 },
  });
  for (const selected of [parsed.mcp.selectedV1, parsed.mcp.servers.selectedV2]) {
    expect(selected).not.toHaveProperty("url");
    expect(selected).not.toHaveProperty("headers");
    expect(selected).not.toHaveProperty("oauth");
  }
});

test("the inverse JSON.stringify renderer fails the JSONC byte-preservation lock", () => {
  const source =
    '{\n  // keep this byte range\n  "mcp": {"files": {"type": "local", "command": ["node"]}}\n}\n';
  const selectedStart = source.indexOf("{", source.indexOf('"files"'));
  const inverse = `${JSON.stringify(parseJsonc(source), null, 2)}\n`;

  expect(inverse.slice(0, selectedStart)).not.toBe(source.slice(0, selectedStart));
  expect(inverse).not.toContain("// keep this byte range");
});
