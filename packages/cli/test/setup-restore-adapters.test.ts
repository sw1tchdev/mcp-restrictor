import { expect, test } from "vitest";
import type { ClientAdapter, ClientLoadContext } from "../src/client-adapter.ts";
import { restoreAdapterConfig } from "../src/setup/adapter-boundary.ts";
import { claudeAdapter, parseClaudeConfig } from "../src/setup/claude.ts";
import { codexAdapter, parseCodexConfig } from "../src/setup/codex.ts";
import { opencodeAdapter, parseOpenCodeConfig } from "../src/setup/opencode.ts";

const context: ClientLoadContext = {
  home: "/home/me",
  projectRoot: "/workspace/project",
  cwd: "/workspace/project",
  environment: {},
};

const managedArgs = ["--policy", "/policy.yaml", "--", "node", "first.mjs"];

type Row = {
  name: string;
  adapter: ClientAdapter;
  current: string;
  installed: string;
  original: string;
  expected: string;
  parse(source: string): ReturnType<typeof parseClaudeConfig>;
};

const rows: Row[] = [
  {
    name: "Claude JSON",
    adapter: claudeAdapter,
    current:
      '{"prefix":true,"mcpServers":{"first":{"command":"mcp-restrictor","args":["--policy","/policy.yaml","--","node","first.mjs"]},"second":{"command":"node","args":["second.mjs"]}},"suffix":true}\n',
    installed:
      '{\n  "mcpServers": { "first": { "args": ["--policy", "/policy.yaml", "--", "node", "first.mjs"], "command": "mcp-restrictor" } }\n}\n',
    original: '{"mcpServers":{"first":{\n  "command": "node",\n  "args": ["original.mjs"]\n}}}\n',
    expected:
      '{"prefix":true,"mcpServers":{"first":{\n  "command": "node",\n  "args": ["original.mjs"]\n},"second":{"command":"node","args":["second.mjs"]}},"suffix":true}\n',
    parse: (source) =>
      parseClaudeConfig({
        path: "/home/me/.claude.json",
        scope: "user",
        source,
        projectRoot: context.projectRoot,
        environment: context.environment,
      }),
  },
  {
    name: "Codex TOML",
    adapter: codexAdapter,
    current: `prefix = true
[mcp_servers.first]
command = "mcp-restrictor"
args = ["--policy", "/policy.yaml", "--", "node", "first.mjs"]
[mcp_servers.second]
command = "node"
args = ["second.mjs"]
suffix = true
`,
    installed: `[mcp_servers.first]
args=["--policy", "/policy.yaml", "--", "node", "first.mjs"]
command="mcp-restrictor"
`,
    original: `[mcp_servers.first]
# native bytes stay exact
command = "node"
args = ["original.mjs"]
`,
    expected: `prefix = true
[mcp_servers.first]
# native bytes stay exact
command = "node"
args = ["original.mjs"]
[mcp_servers.second]
command = "node"
args = ["second.mjs"]
suffix = true
`,
    parse: (source) =>
      parseCodexConfig({
        path: "/home/me/.codex/config.toml",
        scope: "user",
        source,
        environment: context.environment,
      }),
  },
  ...(["v1", "v2"] as const).map((schema) => {
    const wrapper = JSON.stringify({ type: "local", command: ["mcp-restrictor", ...managedArgs] });
    const native = '{ /* native bytes */ "type": "local", "command": ["node", "original.mjs"] }';
    const second = '{ "type": "local", "command": ["node", "second.mjs"] }';
    const firstPath = schema === "v1" ? `"first": ${wrapper}` : `"servers": { "first": ${wrapper}`;
    const secondPath = schema === "v1" ? `"second": ${second}` : `"second": ${second} }`;
    const current = `{\n  "prefix": true,\n  "mcp": { ${firstPath}, ${secondPath} },\n  "suffix": true\n}\n`;
    const installed =
      schema === "v1"
        ? '{"mcp":{"first":{"command":["mcp-restrictor","--policy","/policy.yaml","--","node","first.mjs"],"type":"local"}}}\n'
        : '{"mcp":{"servers":{"first":{"command":["mcp-restrictor","--policy","/policy.yaml","--","node","first.mjs"],"type":"local"}}}}\n';
    const original =
      schema === "v1"
        ? `{"mcp":{"first":${native}}}\n`
        : `{"mcp":{"servers":{"first":${native}}}}\n`;
    const expected =
      schema === "v1"
        ? `{\n  "prefix": true,\n  "mcp": { "first": ${native}, "second": ${second} },\n  "suffix": true\n}\n`
        : `{\n  "prefix": true,\n  "mcp": { "servers": { "first": ${native}, "second": ${second} } },\n  "suffix": true\n}\n`;
    return {
      name: `OpenCode ${schema.toUpperCase()} JSONC`,
      adapter: opencodeAdapter,
      current,
      installed,
      original,
      expected,
      parse: (source: string) =>
        parseOpenCodeConfig({
          path: "/workspace/project/opencode.jsonc",
          scope: "project",
          source,
          projectRoot: context.projectRoot,
          environment: context.environment,
        }),
    };
  }),
];

test.each(rows)("restores only the selected native $name entry", (row) => {
  expect(
    restoreAdapterConfig(
      row.adapter,
      row.parse(row.current),
      [{ name: "first", installedSource: row.installed, originalSource: row.original }],
      context,
    ),
  ).toBe(row.expected);
});

const addedRows: Row[] = [
  {
    name: "Claude JSON",
    adapter: claudeAdapter,
    current:
      '{"prefix":true,"mcpServers":{"first":{"command":"mcp-restrictor","args":["--policy","/policy.yaml","--","node","first.mjs"]},"second":{"command":"node","args":["second.mjs"]}},"suffix":true}\n',
    installed:
      '{"mcpServers":{"first":{"args":["--policy","/policy.yaml","--","node","first.mjs"],"command":"mcp-restrictor"}}}\n',
    original:
      '{"prefix":true,"mcpServers":{"second":{"command":"node","args":["second.mjs"]}},"suffix":true}\n',
    expected: `{
  "prefix": true,
  "mcpServers": {
    "second": {
      "command": "node",
      "args": [
        "second.mjs"
      ]
    }
  },
  "suffix": true
}
`,
    parse: (source) =>
      parseClaudeConfig({
        path: "/home/me/.claude.json",
        scope: "user",
        source,
        projectRoot: context.projectRoot,
        environment: context.environment,
      }),
  },
  {
    name: "Codex TOML",
    adapter: codexAdapter,
    current: `# prefix stays
[mcp_servers.first]
command = "mcp-restrictor"
args = ["--policy", "/policy.yaml", "--", "node", "first.mjs"]
[mcp_servers.second]
command = "node"
args = ["second.mjs"]
`,
    installed: `[mcp_servers.first]
args=["--policy", "/policy.yaml", "--", "node", "first.mjs"]
command="mcp-restrictor"
`,
    original: `# prefix stays
[mcp_servers.second]
command = "node"
args = ["second.mjs"]
`,
    expected: `# prefix stays
[mcp_servers.second]
command = "node"
args = ["second.mjs"]
`,
    parse: (source) =>
      parseCodexConfig({
        path: "/home/me/.codex/config.toml",
        scope: "user",
        source,
        environment: context.environment,
      }),
  },
  ...(["v1", "v2"] as const).map((schema) => {
    const wrapper = JSON.stringify({ type: "local", command: ["mcp-restrictor", ...managedArgs] });
    const first = schema === "v1" ? `"first": ${wrapper}` : `"servers": { "first": ${wrapper}`;
    const second =
      schema === "v1"
        ? `"second": { "type": "local", "command": ["node", "second.mjs"] }`
        : `"second": { "type": "local", "command": ["node", "second.mjs"] } }`;
    const originalMcp = schema === "v1" ? second : `"servers": { ${second}`;
    return {
      name: `OpenCode ${schema.toUpperCase()} JSONC`,
      adapter: opencodeAdapter,
      current: `{
  // prefix stays
  "mcp": { ${first}, ${second} }
}\n`,
      installed:
        schema === "v1"
          ? `{"mcp":{"first":${wrapper}}}\n`
          : `{"mcp":{"servers":{"first":${wrapper}}}}\n`,
      original: `{
  // prefix stays
  "mcp": { ${originalMcp} }
}\n`,
      expected:
        schema === "v1"
          ? `{
  // prefix stays
  "mcp": {
    "second": {
      "type": "local",
      "command": [
        "node",
        "second.mjs"
      ]
    }
  }
}\n`
          : `{
  // prefix stays
  "mcp": {
    "servers": {
      "second": {
        "type": "local",
        "command": [
          "node",
          "second.mjs"
        ]
      }
    }
  }
}\n`,
      parse: (source: string) =>
        parseOpenCodeConfig({
          path: "/workspace/project/opencode.jsonc",
          scope: "project",
          source,
          projectRoot: context.projectRoot,
          environment: context.environment,
        }),
    };
  }),
  {
    name: "OpenCode JSONC without mcp",
    adapter: opencodeAdapter,
    current: `{
  // prefix stays
  "mcp": { "first": { "type": "local", "command": ["mcp-restrictor", "--policy", "/policy.yaml", "--", "node", "first.mjs"] } },
  "suffix": true
}\n`,
    installed:
      '{"mcp":{"first":{"command":["mcp-restrictor","--policy","/policy.yaml","--","node","first.mjs"],"type":"local"}}}\n',
    original: `{
  // prefix stays
  "suffix": true
}\n`,
    expected: `{
  // prefix stays
  "mcp": {},
  "suffix": true
}\n`,
    parse: (source) =>
      parseOpenCodeConfig({
        path: "/workspace/project/opencode.jsonc",
        scope: "project",
        source,
        projectRoot: context.projectRoot,
        environment: context.environment,
      }),
  },
];

test.each(addedRows)("removes only an unchanged added $name entry", (row) => {
  const restored = restoreAdapterConfig(
    row.adapter,
    row.parse(row.current),
    [
      {
        name: "first",
        installedSource: row.installed,
        originalSource: row.original,
        created: true,
      },
    ],
    context,
  );

  expect(restored).toBe(row.expected);
});

test("removes only an exactly installed created native HTTP entry", () => {
  const url = "http://127.0.0.1:7319/mcp/codex/route";
  const original =
    '# prefix stays\n[mcp_servers.sibling]\ncommand = "node"\nargs = ["sibling.mjs"]\n';
  const installed = `[mcp_servers.route]\nurl = ${JSON.stringify(url)}\n`;
  const current = `# prefix stays\n${installed}[mcp_servers.sibling]\ncommand = "node"\nargs = ["sibling.mjs"]\n`;
  const parsed = parseCodexConfig({
    path: "/workspace/project/.codex/config.toml",
    scope: "project",
    source: current,
    environment: {},
  });
  const entry = {
    name: "route",
    originalSource: original,
    installedSource: installed,
    created: true as const,
  };

  expect(restoreAdapterConfig(codexAdapter, parsed, [entry], context)).toBe(original);
  expect(() =>
    restoreAdapterConfig(
      codexAdapter,
      parsed,
      [{ ...entry, installedSource: installed.replace("/route", "/other") }],
      context,
    ),
  ).toThrow("Client configuration restore failed");
});

test("restores mixed replaced and added JSON entries sequentially", () => {
  const original =
    '{"mcpServers":{"first":{"command":"node","args":["first.mjs"]},"third":{"command":"node","args":["third.mjs"]}}}\n';
  const current =
    '{"mcpServers":{"first":{"command":"mcp-restrictor","args":["--policy","/policy.yaml","--","node","first.mjs"]},"second":{"command":"mcp-restrictor","args":["--policy","/policy.yaml","--","node","second.mjs"]},"third":{"command":"node","args":["third.mjs"]}}}\n';
  const installed =
    '{"mcpServers":{"first":{"command":"mcp-restrictor","args":["--policy","/policy.yaml","--","node","first.mjs"]},"second":{"command":"mcp-restrictor","args":["--policy","/policy.yaml","--","node","second.mjs"]}}}\n';
  const parsed = parseClaudeConfig({
    path: "/home/me/.claude.json",
    scope: "user",
    source: current,
    projectRoot: context.projectRoot,
    environment: context.environment,
  });

  const restored = restoreAdapterConfig(
    claudeAdapter,
    parsed,
    [
      { name: "first", originalSource: original },
      { name: "second", originalSource: original, installedSource: installed, created: true },
    ],
    context,
  );

  expect(
    parseClaudeConfig({
      path: "/home/me/.claude.json",
      scope: "user",
      source: restored,
      projectRoot: context.projectRoot,
      environment: context.environment,
    }).servers,
  ).toEqual(
    parseClaudeConfig({
      path: "/home/me/.claude.json",
      scope: "user",
      source: original,
      projectRoot: context.projectRoot,
      environment: context.environment,
    }).servers,
  );
});

test.each(["v1", "v2"] as const)(
  "restores mixed replaced and added OpenCode %s entries with exact sibling bytes",
  (schema) => {
    const wrapped = (name: string) =>
      `{\n      "type": "local",\n      "command": ["mcp-restrictor", "--policy", "/policy.yaml", "--", "node", "${name}.mjs"]\n    }`;
    const native = (name: string) =>
      `{\n      "type": "local",\n      "command": ["node", "${name}.mjs"]\n    }`;
    const body = (replaced: string, added = "") =>
      schema === "v1"
        ? `{\n  // comment survives\n  "mcp": {\n    "replaced": ${replaced}${added},\n    "sibling": ${native("sibling")}\n  }\n}\n`
        : `{\n  // comment survives\n  "mcp": {\n    "servers": {\n      "replaced": ${replaced}${added},\n      "sibling": ${native("sibling")}\n    }\n  }\n}\n`;
    const original = body(native("replaced"));
    const current = body(wrapped("replaced"), `,\n    "added": ${wrapped("added")}`);
    const parsed = parseOpenCodeConfig({
      path: "/workspace/project/opencode.jsonc",
      scope: "project",
      source: current,
      projectRoot: context.projectRoot,
      environment: context.environment,
    });

    expect(
      restoreAdapterConfig(
        opencodeAdapter,
        parsed,
        [
          { name: "replaced", originalSource: original },
          { name: "added", originalSource: original, installedSource: current, created: true },
        ],
        context,
      ),
    ).toBe(original);
  },
);

test("restores mixed Codex entries and deletes every owned range of an added entry", () => {
  const original =
    '# prefix and sibling bytes stay\n[mcp_servers.replaced]\ncommand = "node"\nargs = ["replaced.mjs"]\n[mcp_servers.sibling]\ncommand = "node"\nargs = ["sibling.mjs"]\n';
  const current =
    '# prefix and sibling bytes stay\n[mcp_servers.replaced]\ncommand = "mcp-restrictor"\nargs = ["--policy", "/policy.yaml", "--", "node", "replaced.mjs"]\n[mcp_servers.added]\ncommand = "mcp-restrictor"\nargs = ["--policy", "/policy.yaml", "--", "node", "added.mjs"]\n[mcp_servers.added.env]\nTOKEN = "fixed"\n[mcp_servers.sibling]\ncommand = "node"\nargs = ["sibling.mjs"]\n';
  const parsed = parseCodexConfig({
    path: "/home/me/.codex/config.toml",
    scope: "user",
    source: current,
    environment: {},
  });

  expect(
    restoreAdapterConfig(
      codexAdapter,
      parsed,
      [
        { name: "replaced", originalSource: original },
        { name: "added", originalSource: original, installedSource: current, created: true },
      ],
      context,
    ),
  ).toBe(original);
});

const addedFailureRows = addedRows.flatMap((row) => [
  {
    name: `${row.name}: edited`,
    row,
    source: row.current.replace("mcp-restrictor", "other"),
    created: true as const,
  },
  { name: `${row.name}: removed`, row, source: row.expected, created: true as const },
  {
    name: `${row.name}: replaced`,
    row,
    source: row.current.replace("mcp-restrictor", "node"),
    created: true as const,
  },
  { name: `${row.name}: malformed`, row, source: "{", created: true as const },
  { name: `${row.name}: no marker`, row, source: row.current },
]);

test.each(addedFailureRows)("rejects unsafe added restore: $name", ({ row, source, created }) => {
  const parsed = row.parse(source === "{" ? row.current : source);
  const entry = {
    name: "first",
    originalSource: row.original,
    installedSource: row.installed,
    ...(created ? { created } : {}),
  };

  expect(() => restoreAdapterConfig(row.adapter, { ...parsed, source }, [entry], context)).toThrow(
    "Client configuration restore failed",
  );
});

test.each(["null", "[]", '{"mcpServers":null}', '{"mcpServers":[]}', '{"mcpServers":"bad"}'])(
  "rejects a tracked Claude addition with non-Claude original source %j",
  (originalSource) => {
    const row = addedRows[0]!;

    expect(() =>
      restoreAdapterConfig(
        claudeAdapter,
        row.parse(row.current),
        [{ name: "first", originalSource, installedSource: row.installed, created: true }],
        context,
      ),
    ).toThrow("Client configuration restore failed");
  },
);

test.each([
  [
    "current entry changed after installation",
    '{"mcpServers":{"first":{"command":"other","args":[]}}}',
    '{"mcpServers":{"first":{"command":"mcp-restrictor","args":[]}}}',
    '{"mcpServers":{"first":{"command":"node","args":[]}}}',
    [{ name: "first" }],
  ],
  [
    "original entry is missing",
    '{"mcpServers":{"first":{"command":"mcp-restrictor","args":["--policy","/policy.yaml","--","node","first.mjs"]}}}',
    '{"mcpServers":{"first":{"command":"mcp-restrictor","args":["--policy","/policy.yaml","--","node","first.mjs"]}}}',
    '{"mcpServers":{"second":{"command":"node","args":[]}}}',
    [{ name: "first" }],
  ],
  [
    "source is malformed",
    '{"mcpServers":{"first":{"command":"mcp-restrictor","args":["--policy","/policy.yaml","--","node","first.mjs"]}}}',
    '{"mcpServers":{"first":{"command":"mcp-restrictor","args":["--policy","/policy.yaml","--","node","first.mjs"]}}}',
    "{",
    [{ name: "first" }],
  ],
  [
    "legacy normalized source differs",
    '{"mcpServers":{"first":{"command":"mcp-restrictor","args":["--policy","/policy.yaml","--","node","first.mjs"]}}}',
    undefined,
    '{"mcpServers":{"first":{"command":"node","args":["changed.mjs"]}}}',
    [{ name: "first" }],
  ],
] as const)("rejects restore when %s", (_name, current, installed, original, entries) => {
  const parsed = parseClaudeConfig({
    path: "/home/me/.claude.json",
    scope: "user",
    source: current,
    projectRoot: context.projectRoot,
    environment: context.environment,
  });
  const restoreEntries = entries.map((entry) => ({
    ...entry,
    originalSource: original,
    ...(installed === undefined ? {} : { installedSource: installed }),
  }));

  expect(() => restoreAdapterConfig(claudeAdapter, parsed, restoreEntries, context)).toThrow(
    "Client configuration restore failed",
  );
});

test("rejects duplicate restore names before calling an adapter", () => {
  const config = parseClaudeConfig({
    path: "/home/me/.claude.json",
    scope: "user",
    source: '{"mcpServers":{}}',
    projectRoot: context.projectRoot,
    environment: context.environment,
  });

  expect(() =>
    restoreAdapterConfig(
      claudeAdapter,
      config,
      [
        { name: "first", originalSource: "{}" },
        { name: "first", originalSource: "{}" },
      ],
      context,
    ),
  ).toThrow("Client configuration restore failed");
});

test.each([
  [
    "server property",
    '{"mcpServers":{"first":{"command":"node","args":["shadowed.mjs"]},"first":{"command":"node","args":["effective.mjs"]}}}',
  ],
  [
    "mcpServers property",
    '{"mcpServers":{"first":{"command":"node","args":["shadowed.mjs"]}},"mcpServers":{"first":{"command":"node","args":["effective.mjs"]}}}',
  ],
] as const)("rejects a duplicate Claude %s during tracked restore", (_name, originalSource) => {
  const current =
    '{"mcpServers":{"first":{"command":"mcp-restrictor","args":["--policy","/policy.yaml","--","node","effective.mjs"]}}}';
  const parsed = parseClaudeConfig({
    path: "/home/me/.claude.json",
    scope: "user",
    source: current,
    projectRoot: context.projectRoot,
    environment: context.environment,
  });

  expect(() =>
    restoreAdapterConfig(
      claudeAdapter,
      parsed,
      [{ name: "first", installedSource: current, originalSource }],
      context,
    ),
  ).toThrow("Client configuration restore failed");
});
