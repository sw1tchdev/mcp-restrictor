import { chmod, link, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { Readable, Writable } from "node:stream";
import { expect, test } from "vitest";
import {
  defineClientAdapter,
  type ClientAdapter,
  type ClientHttpInstallEntry,
  type ClientInstallEntry,
  type ClientLoadResult,
} from "../src/client-adapter.ts";
import {
  createAdapterLoader,
  installAdapterConfig,
  installAdapterHttpConfig,
  restoreAdapterConfig,
} from "../src/setup/adapter-boundary.ts";
import { createAdapterRegistry } from "../src/setup/adapters.ts";
import { codexAdapter } from "../src/setup/codex.ts";
import { runSetup } from "../src/setup/index.ts";
import {
  policyFingerprint,
  restoreStatePath,
  serializeRestoreState,
} from "../src/setup/restore/state.ts";
import { routePath, routeUrl, serializeRoute, type RouteOwner } from "../src/routes.ts";
import {
  generatedConfigPath,
  generatedPolicyLocation,
  generatedPresetConfig,
} from "../src/setup/generated.ts";
import { discoverManualDestinations } from "../src/setup/manual/destinations.ts";

const adapter = (id: string, label = id) =>
  defineClientAdapter({
    apiVersion: 1,
    id,
    label,
    load: async () => ({ configurations: [], unsupported: [] }),
    render: (config) => config.source,
  });

test("validates the versioned public adapter shape", () => {
  expect(adapter("valid-adapter").id).toBe("valid-adapter");
  expect(() => adapter("Invalid")).toThrow("Invalid client adapter ID");
  expect(() => defineClientAdapter({ ...adapter("x"), apiVersion: 2 as 1 })).toThrow(
    "Unsupported client adapter API version",
  );
});

test("normalizes host-issued adapter snapshots idempotently", () => {
  const first = adapter("idempotent");
  expect(defineClientAdapter(first)).toBe(first);
  expect(createAdapterRegistry(createAdapterRegistry([first]).available).available[0]).toBe(first);
});

test.each([
  ["load", undefined],
  ["load", 1],
  ["resolve", 1],
  ["projectWrapper", 1],
  ["render", undefined],
  ["render", 1],
  ["install", 1],
  ["installHttp", 1],
  ["restore", 1],
  ["completionMessage", 1],
] as const)("rejects a non-callable public adapter %s member", (member, value) => {
  const candidate: Record<string, unknown> = {
    apiVersion: 1,
    id: "contract-test",
    label: "Contract test",
    load: async () => ({ configurations: [], unsupported: [] }),
    render: (config: { source: string }) => config.source,
  };
  candidate[member] = value;

  expect(() => defineClientAdapter(candidate as ClientAdapter)).toThrow(
    `Invalid client adapter ${member}`,
  );
});

test("reads the complete public adapter contract once into a frozen plain snapshot", () => {
  const first = {
    apiVersion: 1,
    id: "snapshot",
    label: "Snapshot",
    load: async () => ({ configurations: [], unsupported: [] }),
    resolve: async (candidate: never) => ({ candidate, dependencies: [] }),
    projectWrapper: () => ({ policyArgument: "policy.json" }),
    render: (config: { source: string }) => config.source,
    install: (config: { source: string }) => config.source,
    installHttp: (config: { source: string }) => config.source,
    restore: (config: { source: string }) => config.source,
    completionMessage: () => ["complete"],
  } as const;
  const reads = new Map<string, number>();
  const hostile = Object.create(null) as Record<string, unknown>;
  for (const [key, value] of Object.entries(first)) {
    Object.defineProperty(hostile, key, {
      enumerable: true,
      get() {
        const count = (reads.get(key) ?? 0) + 1;
        reads.set(key, count);
        return count === 1 ? value : key === "id" ? "mutated" : 1;
      },
    });
  }
  hostile.extra = "must not cross the contract boundary";

  const snapshot = defineClientAdapter(hostile as ClientAdapter);

  expect(reads).toEqual(new Map(Object.keys(first).map((key) => [key, 1])));
  expect(Object.getPrototypeOf(snapshot)).toBe(Object.prototype);
  expect(Object.isFrozen(snapshot)).toBe(true);
  expect(snapshot).toEqual(first);
  expect(Object.hasOwn(snapshot, "extra")).toBe(false);
});

test("preserves an optional HTTP install hook without changing old API-v1 adapters", () => {
  const oldAdapter = adapter("old-external");
  const installHttp = () => "installed";
  const capable = defineClientAdapter({ ...adapter("http-capable"), installHttp });

  expect(Object.hasOwn(oldAdapter, "installHttp")).toBe(false);
  expect(capable.installHttp).toBe(installHttp);
  expect(Object.isFrozen(capable)).toBe(true);
});

test("isolates a valid install hook from adapters without installation support", () => {
  const config = installConfig();
  const entry = installEntry();
  const installing = defineClientAdapter({
    ...adapter("installing"),
    install(receivedConfig, receivedEntry) {
      receivedConfig.source = "mutated";
      (receivedEntry.args as string[])[0] = "mutated";
      (receivedEntry.environment.inherit as string[])[0] = "MUTATED";
      (receivedEntry.environment.set as Record<string, string>).TOKEN = "mutated";
      return "installed";
    },
  });

  expect(installAdapterConfig(installing, config, entry)).toBe("installed");
  expect({ config, entry }).toEqual({ config: installConfig(), entry: installEntry() });
  expect(() => installAdapterConfig(adapter("setup-only"), config, entry)).toThrow(
    "Client adapter does not support installation",
  );
});

test.each([
  ["empty name", { ...installEntry(), name: "" }],
  ["empty command", { ...installEntry(), command: "" }],
  ["non-string argument", { ...installEntry(), args: ["ok", 1] }],
  ["empty cwd", { ...installEntry(), cwd: "" }],
  [
    "invalid inherited environment name",
    { ...installEntry(), environment: { inherit: ["NO-DASH"], set: {} } },
  ],
  [
    "duplicate inherited environment name",
    { ...installEntry(), environment: { inherit: ["TOKEN", "TOKEN"], set: {} } },
  ],
  [
    "invalid fixed environment name",
    { ...installEntry(), environment: { inherit: [], set: { "NO-DASH": "value" } } },
  ],
  ["array fixed environment values", { ...installEntry(), environment: { inherit: [], set: [] } }],
  [
    "non-string fixed environment value",
    { ...installEntry(), environment: { inherit: [], set: { TOKEN: 1 } } },
  ],
  [
    "inherited and fixed environment overlap",
    { ...installEntry(), environment: { inherit: ["TOKEN"], set: { TOKEN: "value" } } },
  ],
] as const)("rejects a malformed install entry: %s", (_name, entry) => {
  const installing = defineClientAdapter({ ...adapter("validation"), install: () => "installed" });

  expect(() =>
    installAdapterConfig(installing, installConfig(), entry as ClientInstallEntry),
  ).toThrow("Client configuration installation failed");
});

test("rejects install collisions and hostile install hook results", () => {
  const installing = defineClientAdapter({
    ...adapter("hostile-install"),
    install: () => "installed",
  });
  const collisions = [
    { ...installConfig(), servers: [{ name: "installed" }] as never[] },
    { ...installConfig(), unsupported: [{ name: "installed" }] as never[] },
  ];

  for (const config of collisions) {
    expect(() => installAdapterConfig(installing, config, installEntry())).toThrow(
      "Client configuration installation failed",
    );
  }
  for (const hostile of [
    defineClientAdapter({
      ...adapter("throws-install"),
      install: () => {
        throw new Error("secret");
      },
    }),
    defineClientAdapter({
      ...adapter("non-string-install"),
      install: () => 1 as unknown as string,
    }),
    defineClientAdapter({ ...adapter("same-source-install"), install: (config) => config.source }),
  ]) {
    expect(() => installAdapterConfig(hostile, installConfig(), installEntry())).toThrow(
      "Client configuration installation failed",
    );
  }
});

test.each(["client", "scope", "path"] as const)(
  "rejects an install hook that changes cloned config %s identity",
  (field) => {
    const hostile = defineClientAdapter({
      ...adapter(`mutates-${field}`),
      install(config) {
        if (field === "client") config.client = "changed";
        if (field === "scope") config.scope = "user";
        if (field === "path") config.path = "/changed";
        return "installed";
      },
    });

    expect(() => installAdapterConfig(hostile, installConfig(), installEntry())).toThrow(
      "Client configuration installation failed",
    );
  },
);

test("sanitizes install getter and clone failures", () => {
  const getter = { ...adapter("install-getter") };
  Object.defineProperty(getter, "install", {
    get() {
      throw new Error("secret");
    },
  });
  const installing = defineClientAdapter({
    ...adapter("clone-failure"),
    install: () => "installed",
  });
  const uncloneable = {
    ...installEntry(),
    args: [() => undefined],
  } as unknown as ClientInstallEntry;

  for (const [candidate, entry] of [
    [getter as ClientAdapter, installEntry()],
    [installing, uncloneable],
  ] as const) {
    expect(() => installAdapterConfig(candidate, installConfig(), entry)).toThrow(
      "Client configuration installation failed",
    );
  }
});

function installConfig() {
  return {
    client: "install-test",
    scope: "project" as const,
    path: "/config",
    source: "current",
    servers: [],
    unsupported: [],
  };
}

function installEntry(): ClientInstallEntry {
  return {
    name: "installed",
    command: "mcp-restrictor",
    args: ["upstream"],
    cwd: "/project",
    environment: { inherit: ["PATH"], set: { TOKEN: "value" } },
  };
}

test("isolates a valid HTTP install hook from adapters without HTTP support", () => {
  const config = installConfig();
  const entry = httpInstallEntry();
  const installing = defineClientAdapter({
    ...adapter("http-installing"),
    installHttp(receivedConfig, receivedEntry) {
      receivedConfig.source = "mutated";
      receivedEntry.name = "mutated";
      receivedEntry.url = "http://127.0.0.1:1/mutated";
      return "installed";
    },
  });

  expect(installAdapterHttpConfig(installing, config, entry)).toBe("installed");
  expect(
    installAdapterHttpConfig(installing, config, {
      ...entry,
      url: "http://127.0.0.1:80/mcp/test/id",
    }),
  ).toBe("installed");
  expect(
    installAdapterHttpConfig(installing, config, {
      ...entry,
      url: "http://127.0.0.1:7319/mcp/test/valid%20segment",
    }),
  ).toBe("installed");
  expect({ config, entry }).toEqual({ config: installConfig(), entry: httpInstallEntry() });
  expect(() => installAdapterHttpConfig(adapter("http-unsupported"), config, entry)).toThrow(
    "Client adapter does not support HTTP installation",
  );
});

test.each([
  ["empty name", { ...httpInstallEntry(), name: "" }],
  ["non-string name", { ...httpInstallEntry(), name: 1 }],
  ["non-string URL", { ...httpInstallEntry(), url: 1 }],
  ["malformed URL", { ...httpInstallEntry(), url: "not a URL" }],
  ["HTTPS", { ...httpInstallEntry(), url: "https://127.0.0.1:7319/mcp/test/id" }],
  ["localhost", { ...httpInstallEntry(), url: "http://localhost:7319/mcp/test/id" }],
  ["IPv6 loopback", { ...httpInstallEntry(), url: "http://[::1]:7319/mcp/test/id" }],
  ["missing port", { ...httpInstallEntry(), url: "http://127.0.0.1/mcp/test/id" }],
  ["port zero", { ...httpInstallEntry(), url: "http://127.0.0.1:0/mcp/test/id" }],
  ["port overflow", { ...httpInstallEntry(), url: "http://127.0.0.1:65536/mcp/test/id" }],
  ["credentials", { ...httpInstallEntry(), url: "http://user:secret@127.0.0.1:7319/mcp/test/id" }],
  ["query", { ...httpInstallEntry(), url: "http://127.0.0.1:7319/mcp/test/id?secret=value" }],
  ["fragment", { ...httpInstallEntry(), url: "http://127.0.0.1:7319/mcp/test/id#secret" }],
  ["bare percent escape", { ...httpInstallEntry(), url: "http://127.0.0.1:7319/mcp/test/%" }],
  ["short percent escape", { ...httpInstallEntry(), url: "http://127.0.0.1:7319/mcp/test/%2" }],
  ["non-hex percent escape", { ...httpInstallEntry(), url: "http://127.0.0.1:7319/mcp/test/%zz" }],
  ["non-canonical host", { ...httpInstallEntry(), url: "http://127.000.000.001:7319/mcp/test/id" }],
] as const)("rejects a malformed HTTP install entry: %s", (_name, entry) => {
  const installing = defineClientAdapter({
    ...adapter("http-entry-validation"),
    installHttp: () => "installed",
  });

  expect(() =>
    installAdapterHttpConfig(installing, installConfig(), entry as ClientHttpInstallEntry),
  ).toThrow("Client configuration HTTP installation failed");
});

test("rejects HTTP install collisions and hostile hook results with a sanitized error", () => {
  const secretName = "secret-name";
  const secretUrl = "http://127.0.0.1:7319/secret-url";
  const secretSource = "secret-config";
  const config = { ...installConfig(), source: secretSource };
  const entry = { name: secretName, url: secretUrl };
  const installing = defineClientAdapter({
    ...adapter("http-collision"),
    installHttp: () => "installed",
  });
  const cases: Array<[ClientAdapter, ReturnType<typeof installConfig>, ClientHttpInstallEntry]> = [
    [installing, { ...config, servers: [{ name: secretName }] as never[] }, entry],
    [installing, { ...config, unsupported: [{ name: secretName }] as never[] }, entry],
    [
      defineClientAdapter({
        ...adapter("http-throws"),
        installHttp: () => {
          throw new Error(`${secretName} ${secretUrl} ${secretSource}`);
        },
      }),
      config,
      entry,
    ],
    [
      defineClientAdapter({
        ...adapter("http-non-string"),
        installHttp: () => 1 as unknown as string,
      }),
      config,
      entry,
    ],
    [
      defineClientAdapter({
        ...adapter("http-unchanged"),
        installHttp: (received) => received.source,
      }),
      config,
      entry,
    ],
  ];

  for (const [candidate, receivedConfig, receivedEntry] of cases) {
    let error: unknown;
    try {
      installAdapterHttpConfig(candidate, receivedConfig, receivedEntry);
    } catch (caught) {
      error = caught;
    }
    expect(error).toEqual(new Error("Client configuration HTTP installation failed"));
    expect(String(error)).not.toContain(secretName);
    expect(String(error)).not.toContain(secretUrl);
    expect(String(error)).not.toContain(secretSource);
  }
});

test.each(["client", "scope", "path"] as const)(
  "rejects an HTTP install hook that changes cloned config %s identity",
  (field) => {
    const hostile = defineClientAdapter({
      ...adapter(`http-mutates-${field}`),
      installHttp(config) {
        if (field === "client") config.client = "changed";
        if (field === "scope") config.scope = "user";
        if (field === "path") config.path = "/changed";
        return "installed";
      },
    });

    expect(() => installAdapterHttpConfig(hostile, installConfig(), httpInstallEntry())).toThrow(
      "Client configuration HTTP installation failed",
    );
  },
);

test("sanitizes HTTP install getter and clone failures", () => {
  const getter = { ...adapter("http-install-getter") };
  Object.defineProperty(getter, "installHttp", {
    get() {
      throw new Error("secret");
    },
  });
  const installing = defineClientAdapter({
    ...adapter("http-clone-failure"),
    installHttp: () => "installed",
  });
  const uncloneable = {
    ...httpInstallEntry(),
    extra: () => undefined,
  } as ClientHttpInstallEntry;

  for (const [candidate, entry] of [
    [getter as ClientAdapter, httpInstallEntry()],
    [installing, uncloneable],
  ] as const) {
    expect(() => installAdapterHttpConfig(candidate, installConfig(), entry)).toThrow(
      "Client configuration HTTP installation failed",
    );
  }
});

function httpInstallEntry(): ClientHttpInstallEntry {
  return { name: "installed", url: "http://127.0.0.1:7319/mcp/test/id" };
}

test("keeps an optional restore hook isolated from setup-only adapters", () => {
  const setupOnly = adapter("setup-only");
  const restoring = defineClientAdapter({
    ...adapter("restoring"),
    restore: (config) => config.source,
  });
  const config = {
    client: "restoring",
    scope: "project" as const,
    path: "/config",
    source: "current",
    servers: [],
    unsupported: [],
  };

  expect(
    createAdapterRegistry([], [{ packageName: "setup-only", adapter: setupOnly }]).available,
  ).toEqual([setupOnly]);
  expect(
    restoreAdapterConfig(restoring, config, [], {
      home: "/home",
      projectRoot: "/project",
      cwd: "/project",
      environment: {},
    }),
  ).toBe("current");
  expect(() =>
    restoreAdapterConfig(setupOnly, config, [], {
      home: "/home",
      projectRoot: "/project",
      cwd: "/project",
      environment: {},
    }),
  ).toThrow("Client adapter does not support restore");
});

test("classifies an owned user route from another project as unavailable for Add", async () => {
  const fixture = await managedUserRouteFixture();

  try {
    const first = await createAdapterLoader().load(codexAdapter, fixture.context);
    expect(first.configurations[0]!.config.servers.map(({ name }) => name)).toEqual(["arbitrary"]);
    expect(first.configurations[0]!.config.unsupported).toEqual([
      {
        client: "codex",
        scope: "user",
        name: "managed",
        configPath: fixture.configPath,
        reason: "Managed local HTTP route; Restore it before adding.",
      },
    ]);
    expect(JSON.stringify(first)).not.toContain("state-secret");

    await writeFile(fixture.routePath, "{}", { mode: 0o600 });
    const drifted = await createAdapterLoader().load(codexAdapter, fixture.context);
    expect(drifted.configurations[0]!.config.servers.map(({ name }) => name)).toEqual([
      "arbitrary",
    ]);
    expect(drifted.configurations[0]!.config.unsupported).toEqual([
      expect.objectContaining({
        name: "managed",
        reason: "Managed local HTTP route ownership could not be verified; Restore is unavailable.",
      }),
    ]);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test.each([
  ["the same project root", true, ["arbitrary"], ["managed"]],
  ["a different project root", false, ["arbitrary", "managed"], []],
] as const)(
  "classifies a project-scope route owned from %s",
  async (_name, sameProject, expectedServers, expectedUnsupported) => {
    const fixture = await managedProjectRouteFixture(sameProject);

    try {
      const loaded = await createAdapterLoader().load(codexAdapter, fixture.context);
      expect(loaded.configurations[0]!.config.servers.map(({ name }) => name)).toEqual(
        expectedServers,
      );
      expect(loaded.configurations[0]!.config.unsupported.map(({ name }) => name)).toEqual(
        expectedUnsupported,
      );
      if (sameProject) {
        expect(loaded.configurations[0]!.config.unsupported[0]).toMatchObject({
          scope: "project",
          reason: "Managed local HTTP route; Restore it before adding.",
        });
      }
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);

test("fails closed when an unrelated restore-state file makes route ownership untrustworthy", async () => {
  const fixture = await managedUserRouteFixture();
  const corruptPath = join(dirname(fixture.statePath), "unrelated.json");
  await privateAdapterFile(corruptPath, '{"state-secret":"unterminated');
  const paths = [
    fixture.configPath,
    fixture.policyPath,
    fixture.routePath,
    fixture.statePath,
    corruptPath,
  ];
  const before = await Promise.all(paths.map((path) => readFile(path, "utf8")));

  try {
    await expect(createAdapterLoader().load(codexAdapter, fixture.context)).rejects.toThrow(
      /^Failed to load client configuration$/,
    );
    expect(await Promise.all(paths.map((path) => readFile(path, "utf8")))).toEqual(before);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test.each(["missing", "corrupt"] as const)(
  "loader fails closed for a matching state with %s route proof",
  async (condition) => {
    const fixture = await managedUserRouteFixture();
    if (condition === "missing") {
      await rm(fixture.routePath);
    } else {
      await writeFile(fixture.routePath, "{}", { mode: 0o600 });
    }

    try {
      const loaded = await createAdapterLoader().load(codexAdapter, fixture.context);
      const config = loaded.configurations[0]!.config;
      expect(config.servers.map(({ name }) => name)).not.toContain("managed");
      expect(config.unsupported).toContainEqual(
        expect.objectContaining({
          name: "managed",
          reason:
            "Managed local HTTP route ownership could not be verified; Restore is unavailable.",
        }),
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  },
);

test("classifies a generated managed route Restore-first while another server name stays eligible", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-generated-route-")));
  const home = join(root, "home");
  const configPath = generatedConfigPath(home, "codex");
  const policyPath = generatedPolicyLocation({
    home,
    adapterId: "codex",
    serverName: "managed",
  }).diskPath;
  const owner: RouteOwner = {
    adapterId: "codex",
    scope: "user",
    configPath,
    projectRoot: resolve(home),
    serverName: "managed",
  };
  const url = routeUrl(17319, owner);
  const originalSource = "";
  const installedSource = installAdapterHttpConfig(
    codexAdapter,
    generatedPresetConfig({ home, kind: "codex", environment: {} }),
    { name: "managed", url },
  );
  const routePathValue = routePath(home, owner);
  const routeSource = serializeRoute({
    version: 1,
    owner,
    listenUrl: url,
    proxyArgs: ["--policy", policyPath, "--", "node", "managed.mjs"],
    environment: { set: {} },
  });
  const statePath = restoreStatePath(home, configPath);
  const stateSource = serializeRestoreState({
    version: 2,
    adapterId: "codex",
    configPath,
    servers: [
      {
        name: "managed",
        scope: "user",
        projectRoot: resolve(home),
        originalSource,
        installedSource,
        created: true,
        policy: {
          path: policyPath,
          before: null,
          installed: policyFingerprint("policy", 0o600),
        },
        route: { path: routePathValue, installed: policyFingerprint(routeSource, 0o600) },
      },
    ],
  });
  const context = { home, projectRoot: root, cwd: root, environment: {} };
  await privateAdapterFile(configPath, installedSource);
  await privateAdapterFile(policyPath, "policy");
  await privateAdapterFile(routePathValue, routeSource);
  await privateAdapterFile(statePath, stateSource);

  try {
    const loaded = await createAdapterLoader().load(codexAdapter, context);
    expect(loaded.configurations).toEqual([
      expect.objectContaining({
        config: expect.objectContaining({
          path: configPath,
          servers: [],
          unsupported: [
            expect.objectContaining({
              name: "managed",
              reason: "Managed local HTTP route; Restore it before adding.",
            }),
          ],
        }),
      }),
    ]);
    const destinations = await discoverManualDestinations({
      adapters: [codexAdapter],
      context,
      serverName: "different",
      restrictorHome: join(home, ".mcp-restrictor"),
    });
    expect(destinations.available).toEqual([
      expect.objectContaining({
        generated: "codex",
        config: expect.objectContaining({ path: configPath }),
      }),
    ]);
    expect(destinations.generated).toEqual([]);

    await writeFile(routePathValue, "{}", { mode: 0o600 });
    const failedClosed = await discoverManualDestinations({
      adapters: [codexAdapter],
      context,
      serverName: "managed",
      restrictorHome: join(home, ".mcp-restrictor"),
    });
    expect(failedClosed.available).toEqual([]);
    expect(failedClosed.unavailable).toContainEqual(
      expect.objectContaining({ reason: "server name already exists" }),
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

async function managedUserRouteFixture() {
  return managedRouteFixture("user", false);
}

async function managedProjectRouteFixture(sameProject: boolean) {
  return managedRouteFixture("project", sameProject);
}

async function managedRouteFixture(scope: "user" | "project", sameProject: boolean) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-managed-route-")));
  const home = join(root, "home");
  const projectA = join(root, "project-a");
  const projectB = join(root, "project-b");
  const contextProject = sameProject ? projectA : projectB;
  const configPath = join(scope === "user" ? home : contextProject, ".codex", "config.toml");
  const policyPath = join(
    scope === "user" ? home : projectA,
    ".mcp-restrictor",
    "policies",
    "codex",
    "managed.yaml",
  );
  const owner: RouteOwner = {
    adapterId: "codex",
    scope,
    configPath,
    projectRoot: projectA,
    serverName: "managed",
  };
  const routePathValue = routePath(home, owner);
  const url = routeUrl(7319, owner);
  const originalSource =
    '[mcp_servers.arbitrary]\nurl = "http://127.0.0.1:7319/mcp/codex/not-owned"\n';
  const installedSource = `${originalSource}[mcp_servers.managed]\nurl = ${JSON.stringify(url)}\n`;
  const routeSource = serializeRoute({
    version: 1,
    owner,
    listenUrl: url,
    proxyArgs: ["--policy", policyPath, "--", "node", "managed.mjs"],
    environment: { set: {} },
  });
  const statePath = restoreStatePath(home, configPath);
  const stateSource = serializeRestoreState({
    version: 2,
    adapterId: "codex",
    configPath,
    servers: [
      {
        name: "managed",
        scope,
        projectRoot: projectA,
        originalSource: `# state-secret\n${originalSource}`,
        installedSource,
        created: true,
        policy: {
          path: policyPath,
          before: null,
          installed: policyFingerprint("policy", 0o600),
        },
        route: { path: routePathValue, installed: policyFingerprint(routeSource, 0o600) },
      },
    ],
  });
  await mkdir(contextProject, { recursive: true });
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, installedSource);
  await privateAdapterFile(policyPath, "policy");
  await privateAdapterFile(routePathValue, routeSource);
  await privateAdapterFile(statePath, stateSource);
  return {
    root,
    configPath,
    policyPath,
    routePath: routePathValue,
    statePath,
    context: {
      home,
      projectRoot: contextProject,
      cwd: contextProject,
      environment: {},
    },
  };
}

async function privateAdapterFile(path: string, content: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await chmod(dirname(path), 0o700);
  await writeFile(path, content, { mode: 0o600 });
  await chmod(path, 0o600);
}

test("sanitizes hostile restore hooks and snapshots their inputs", () => {
  const config = {
    client: "restore-test",
    scope: "project" as const,
    path: "/config",
    source: "current",
    servers: [],
    unsupported: [],
  };
  const entries = [{ name: "first", originalSource: "original" }];
  const restore = defineClientAdapter({
    ...adapter("restore-test"),
    restore: (received, receivedEntries, receivedContext) => {
      received.source = "changed";
      receivedEntries[0]!.name = "changed";
      receivedContext.environment.CHANGED = "yes";
      return "restored";
    },
  });
  const restoreContext = {
    home: "/home",
    projectRoot: "/project",
    cwd: "/project",
    environment: {},
  };

  expect(restoreAdapterConfig(restore, config, entries, restoreContext)).toBe("restored");
  expect({ config, entries, restoreContext }).toEqual({
    config: { ...config, source: "current" },
    entries: [{ name: "first", originalSource: "original" }],
    restoreContext: { home: "/home", projectRoot: "/project", cwd: "/project", environment: {} },
  });

  const hostile = { ...adapter("getter") };
  Object.defineProperty(hostile, "restore", {
    get() {
      throw new Error("secret");
    },
  });
  const hostileThrown = new Proxy(
    {},
    {
      getPrototypeOf() {
        throw new Error("secret-prototype");
      },
    },
  );

  for (const candidate of [
    defineClientAdapter({
      ...adapter("throws"),
      restore: () => {
        throw new Error("secret");
      },
    }),
    defineClientAdapter({ ...adapter("non-string"), restore: () => 1 as unknown as string }),
    defineClientAdapter({
      ...adapter("hostile-throw"),
      restore: () => {
        throw hostileThrown;
      },
    }),
    hostile as ClientAdapter,
  ]) {
    expect(() => restoreAdapterConfig(candidate, config, entries, restoreContext)).toThrow(
      "Client configuration restore failed",
    );
  }
});

test.each([false, "true", 1, null])("rejects a non-literal created restore marker", (created) => {
  const config = {
    client: "restore-marker",
    scope: "project" as const,
    path: "/config",
    source: "current",
    servers: [],
    unsupported: [],
  };
  const restore = defineClientAdapter({
    ...adapter("restore-marker"),
    restore: (received) => received.source,
  });

  expect(() =>
    restoreAdapterConfig(
      restore,
      config,
      [{ name: "first", originalSource: "original", created } as any],
      { home: "/home", projectRoot: "/project", cwd: "/project", environment: {} },
    ),
  ).toThrow("Client configuration restore failed");
});

test("imports the built public client adapter contract", async () => {
  const { defineClientAdapter: defineBuiltClientAdapter } =
    await import("../dist/client-adapter.js");
  const builtAdapter = defineBuiltClientAdapter({
    apiVersion: 1,
    id: "built-adapter",
    label: "Built adapter",
    load: async () => ({ configurations: [], unsupported: [] }),
    render: (config) => config.source,
  });

  expect(builtAdapter.id).toBe("built-adapter");
  expect(() => defineBuiltClientAdapter({ ...builtAdapter, id: "Invalid" })).toThrow(
    "Invalid client adapter ID",
  );
});

test("lists OpenCode as the third built-in and Manual upstream fourth", async () => {
  const output = capturedOutput();

  await runSetup({
    input: Readable.from([]),
    output,
    interactive: true,
  });

  expect(output.text()).toBe(`Clients:
1. Claude Code
2. Codex
3. OpenCode
4. Manual upstream
Select clients: Setup cancelled.
`);
});

test("protects built-in IDs and keeps an invalid external isolated", () => {
  const result = createAdapterRegistry(
    [adapter("claude", "Claude Code"), adapter("codex", "Codex")],
    [
      { packageName: "override", adapter: adapter("claude", "Override") },
      { packageName: "broken", error: new Error("secret") },
    ],
  );
  expect(result.available.map(({ id }) => id)).toEqual(["claude", "codex"]);
  expect(result.unavailable).toEqual([
    { packageName: "override", reason: "client adapter ID conflicts with a built-in" },
    { packageName: "broken", reason: "client adapter failed to load" },
  ]);
});

test("isolates an external adapter that bypasses validation", () => {
  const rawAdapter = { ...adapter("external"), id: "Invalid" };
  const result = createAdapterRegistry(
    [adapter("claude", "Claude Code")],
    [{ packageName: "raw", adapter: rawAdapter }],
  );

  expect(result.available.map(({ id }) => id)).toEqual(["claude"]);
  expect(result.unavailable).toEqual([
    { packageName: "raw", reason: "client adapter failed to load" },
  ]);
});

test("rejects Claude user and project paths that alias the same hard-linked file", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-adapter-links-")));
  const home = join(root, "home");
  const userPath = join(home, ".claude.json");
  const projectPath = join(root, ".mcp.json");
  await mkdir(dirname(userPath), { recursive: true });
  await writeFile(userPath, JSON.stringify({ mcpServers: {} }));
  await link(userPath, projectPath);

  try {
    await expect(
      runSetup({
        input: Readable.from(["1\n"]),
        output: new Writable({
          write(_chunk, _encoding, callback) {
            callback();
          },
        }),
        interactive: true,
        cwd: root,
        home,
        environment: { PATH: process.env.PATH },
      }),
    ).rejects.toThrow("user and project configuration paths resolve to the same file");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects an adapter snapshot that was not issued by the setup host before display", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-adapter-snapshot-")));
  const path = join(root, "client.conf");
  await writeFile(path, "source");
  const adapter: ClientAdapter = defineClientAdapter({
    apiVersion: 1,
    id: "fake",
    label: "Fake",
    load: async (_context, host) => {
      const snapshot = await host.readConfig(path);
      if (!snapshot) throw new Error("missing fixture");
      return {
        configurations: [
          {
            config: {
              client: "fake",
              scope: "project",
              path,
              source: snapshot.content,
              servers: [],
              unsupported: [],
            },
            snapshot: { ...snapshot },
          },
        ],
        unsupported: [],
      };
    },
    render: (config) => config.source,
  });
  const output: Buffer[] = [];

  try {
    await expect(
      runSetup({
        input: Readable.from(["1\n"]),
        output: new Writable({
          write(chunk, _encoding, callback) {
            output.push(Buffer.from(chunk));
            callback();
          },
        }),
        interactive: true,
        cwd: root,
        home: join(root, "home"),
        environment: { PATH: process.env.PATH },
        adapters: [adapter],
      }),
    ).rejects.toThrow("Invalid client configuration returned by adapter");
    expect(Buffer.concat(output).toString("utf8")).not.toContain("Supported MCP servers:");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects a malformed STDIO candidate before display", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-adapter-stdio-")));
  const path = join(root, "client.conf");
  await writeFile(path, "source");
  const malformedAdapter = defineClientAdapter({
    apiVersion: 1,
    id: "fake",
    label: "Fake",
    async load(_context, host) {
      const snapshot = await host.readConfig(path);
      if (!snapshot) throw new Error("missing fixture");
      return {
        configurations: [
          {
            config: {
              client: "fake",
              scope: "project",
              path,
              source: snapshot.content,
              servers: [
                {
                  client: "fake",
                  scope: "project",
                  name: "broken",
                  configPath: path,
                  source: { kind: "stdio", command: "", args: [], envNames: [] },
                  upstream: { kind: "stdio", command: "", args: [] },
                  wrapperEnvironment: {},
                  original: {},
                },
              ],
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
  const output = capturedOutput();

  try {
    await expect(
      runSetup({
        input: Readable.from(["1\n"]),
        output,
        interactive: true,
        cwd: root,
        home: join(root, "home"),
        environment: { PATH: process.env.PATH },
        adapters: [malformedAdapter],
      }),
    ).rejects.toThrow("Invalid client configuration returned by adapter");
    expect(output.text()).not.toContain("Supported MCP servers:");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects a config snapshot issued only for a secret file", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-adapter-secret-")));
  const path = join(root, "secret.conf");
  await writeFile(path, "source");
  await chmod(path, 0o600);
  const adapter: ClientAdapter = defineClientAdapter({
    apiVersion: 1,
    id: "fake",
    label: "Fake",
    load: async (_context, host) => {
      const snapshot = await host.readSecretFile(path);
      return {
        configurations: [
          {
            config: {
              client: "fake",
              scope: "project",
              path,
              source: snapshot.content,
              servers: [],
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

  try {
    await expect(
      runSetup({
        input: Readable.from(["1\n"]),
        output: new Writable({
          write(_chunk, _encoding, callback) {
            callback();
          },
        }),
        interactive: true,
        cwd: root,
        home: join(root, "home"),
        environment: { PATH: process.env.PATH },
        adapters: [adapter],
      }),
    ).rejects.toThrow("Invalid client configuration returned by adapter");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects an issued snapshot mutated by an adapter after the host returns it", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-adapter-mutation-")));
  const path = join(root, "client.conf");
  await writeFile(path, "source");
  const adapter: ClientAdapter = defineClientAdapter({
    apiVersion: 1,
    id: "fake",
    label: "Fake",
    load: async (_context, host) => {
      const snapshot = await host.readConfig(path);
      if (!snapshot) throw new Error("missing fixture");
      snapshot.path = join(root, "redirected.conf");
      snapshot.content = "adapter-controlled";
      snapshot.mode = 0o777;
      snapshot.size = 0;
      snapshot.mtimeMs = 0;
      snapshot.dev = 0;
      snapshot.ino = 0;
      return {
        configurations: [
          {
            config: {
              client: "fake",
              scope: "project",
              path: snapshot.path,
              source: snapshot.content,
              servers: [],
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
  const output: Buffer[] = [];

  try {
    await expect(
      runSetup({
        input: Readable.from(["1\n"]),
        output: new Writable({
          write(chunk, _encoding, callback) {
            output.push(Buffer.from(chunk));
            callback();
          },
        }),
        interactive: true,
        cwd: root,
        home: join(root, "home"),
        environment: { PATH: process.env.PATH },
        adapters: [adapter],
      }),
    ).rejects.toThrow("Invalid client configuration returned by adapter");
    expect(Buffer.concat(output).toString("utf8")).not.toContain("No supported MCP servers found.");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("retains the core-owned cloned configuration after adapter load", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-adapter-clone-")));
  const path = join(root, "client.conf");
  const config = {
    client: "fake",
    scope: "project" as const,
    path,
    source: "source",
    servers: [
      {
        client: "fake",
        scope: "project" as const,
        name: "files",
        configPath: path,
        source: { kind: "stdio" as const, command: "original-command", args: [], envNames: [] },
        upstream: { kind: "stdio" as const, command: "original-command", args: [] },
        wrapperEnvironment: {},
        original: {},
      },
    ],
    unsupported: [],
  };
  await writeFile(path, config.source);
  const adapter: ClientAdapter = defineClientAdapter({
    apiVersion: 1,
    id: "fake",
    label: "Fake",
    load: (_context, host) =>
      new Promise((resolveLoad) => {
        void host.readConfig(path).then((snapshot) => {
          if (!snapshot) throw new Error("missing fixture");
          resolveLoad({ configurations: [{ config, snapshot }], unsupported: [] });
          queueMicrotask(() => {
            config.servers[0]!.source.command = "adapter-mutated-command";
            (config.servers[0]!.upstream as { command: string }).command =
              "adapter-mutated-command";
          });
        });
      }),
    render: (loaded) => loaded.source,
  });
  const output: Buffer[] = [];

  try {
    await runSetup({
      input: Readable.from(["1\n", "1\n", "1\n", "no\n"]),
      output: new Writable({
        write(chunk, _encoding, callback) {
          output.push(Buffer.from(chunk));
          callback();
        },
      }),
      interactive: true,
      cwd: root,
      home: join(root, "home"),
      environment: { PATH: process.env.PATH },
      adapters: [adapter],
    });
    const rendered = Buffer.concat(output).toString("utf8");
    expect(config.servers[0]!.source.command).toBe("adapter-mutated-command");
    expect(rendered).toContain('command="original-command"');
    expect(rendered).not.toContain("adapter-mutated-command");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("clones adapter-owned unsupported entries before the generated-config await", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-unsupported-clone-")));
  const path = join(root, "client.conf");
  await writeFile(path, "source");
  const unsupported = [
    {
      client: "fake",
      scope: "project" as const,
      name: "original-name",
      configPath: path,
      reason: "original reason",
    },
  ];
  const fake = defineClientAdapter({
    apiVersion: 1,
    id: "fake",
    label: "Fake",
    load: (_context, host) =>
      new Promise((resolveLoad) => {
        void host.readConfig(path).then(() => {
          resolveLoad({ configurations: [], unsupported });
          queueMicrotask(() => {
            unsupported[0]!.name = "adapter-mutated-name";
            unsupported[0]!.reason = "adapter-mutated reason";
          });
        });
      }),
    render: (config) => config.source,
  });

  try {
    const result = await createAdapterLoader().load(fake, {
      home: join(root, "home"),
      projectRoot: root,
      cwd: root,
      environment: {},
    });
    expect(unsupported[0]).toMatchObject({
      name: "adapter-mutated-name",
      reason: "adapter-mutated reason",
    });
    expect(result.unsupported).toEqual([
      expect.objectContaining({ name: "original-name", reason: "original reason" }),
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test.each([
  [
    "result getter",
    () => ({
      get configurations() {
        throw new Error("secret-load-detail");
      },
      unsupported: [],
    }),
  ],
  [
    "result iterator",
    () => ({
      configurations: {
        [Symbol.iterator]() {
          throw new Error("secret-load-detail");
        },
      },
      unsupported: [],
    }),
  ],
  [
    "entry getter",
    () => ({
      configurations: [
        {
          snapshot: {} as never,
          get config() {
            throw new Error("secret-load-detail");
          },
        },
      ],
      unsupported: [],
    }),
  ],
  [
    "clone failure",
    () => ({
      configurations: [
        {
          snapshot: {} as never,
          config: { uncloneable: () => undefined },
        },
      ],
      unsupported: [],
    }),
  ],
] as const)("sanitizes adapter load $stage failures", async (_stage, result) => {
  const adapter: ClientAdapter = defineClientAdapter({
    apiVersion: 1,
    id: "fake",
    label: "Fake",
    load: async () => result() as unknown as ClientLoadResult,
    render: (config) => config.source,
  });
  const output: Buffer[] = [];
  const error: Buffer[] = [];
  const failure = await runSetup({
    input: Readable.from(["1\n"]),
    output: new Writable({
      write(chunk, _encoding, callback) {
        output.push(Buffer.from(chunk));
        callback();
      },
    }),
    error: new Writable({
      write(chunk, _encoding, callback) {
        error.push(Buffer.from(chunk));
        callback();
      },
    }),
    interactive: true,
    adapters: [adapter],
  }).catch((reason: unknown) => reason);

  expect(failure).toBeInstanceOf(Error);
  expect((failure as Error).message).toBe("Failed to load client configuration");
  expect(Buffer.concat([...output, ...error]).toString("utf8")).not.toContain("secret-load-detail");
});

test("rejects an injected adapter with an invalid ID before rendering the menu", async () => {
  const invalidAdapter = { ...adapter("fake"), id: "Invalid" } as ClientAdapter;
  const output: Buffer[] = [];

  await expect(
    runSetup({
      input: Readable.from(["1\n"]),
      output: new Writable({
        write(chunk, _encoding, callback) {
          output.push(Buffer.from(chunk));
          callback();
        },
      }),
      interactive: true,
      adapters: [invalidAdapter],
    }),
  ).rejects.toThrow("Invalid client adapter ID");
  expect(Buffer.concat(output).toString("utf8")).toBe("");
});

test("escapes control characters in injected adapter labels", async () => {
  const output: Buffer[] = [];
  const adapter: ClientAdapter = defineClientAdapter({
    apiVersion: 1,
    id: "fake",
    label: "Fake\u001bLabel",
    load: async () => ({ configurations: [], unsupported: [] }),
    render: (config) => config.source,
  });

  await runSetup({
    input: Readable.from(["1\n"]),
    output: new Writable({
      write(chunk, _encoding, callback) {
        output.push(Buffer.from(chunk));
        callback();
      },
    }),
    interactive: true,
    adapters: [adapter],
  });
  expect(Buffer.concat(output).toString("utf8")).toContain("1. Fake\\u001bLabel\n");
  expect(Buffer.concat(output).toString("utf8")).not.toContain("Fake\u001bLabel");
});

test.each(["all", "1,2"])("selects several adapters with %s", async (selection) => {
  const loads: string[] = [];
  const adapters = [
    menuAdapter("alpha", "Alpha", () => loads.push("alpha")),
    menuAdapter("beta", "Beta", () => loads.push("beta")),
  ];

  await runSetup({
    input: Readable.from([`${selection}\n`]),
    output: quietOutput(),
    interactive: true,
    adapters,
  });

  expect(loads).toEqual(["alpha", "beta"]);
});

test("rejects duplicate client numbers and reprompts", async () => {
  const loads: string[] = [];
  const output = capturedOutput();

  await runSetup({
    input: Readable.from(["1,1\n", "1\n"]),
    output,
    interactive: true,
    adapters: [
      menuAdapter("alpha", "Alpha", () => loads.push("alpha")),
      menuAdapter("beta", "Beta", () => loads.push("beta")),
    ],
  });

  expect(output.text()).toContain("Invalid selection.");
  expect(loads).toEqual(["alpha"]);
});

test("reprompts a Manual and adapter mix before configuration IO", async () => {
  const output = capturedOutput();
  const loads: string[] = [];

  await runSetup({
    input: Readable.from(["1,3\n", "1\n"]),
    output,
    interactive: true,
    adapters: [
      menuAdapter("alpha", "Alpha", () => {
        expect(output.text()).toContain("Manual upstream must be selected by itself.");
        loads.push("alpha");
      }),
      menuAdapter("beta", "Beta", () => loads.push("beta")),
    ],
  });

  expect(loads).toEqual(["alpha"]);
});

test("uses one host instance for every selected adapter", async () => {
  const hosts: unknown[] = [];
  const adapters = ["alpha", "beta"].map((id) =>
    defineClientAdapter({
      apiVersion: 1,
      id,
      label: id,
      load: async (_context, host) => {
        hosts.push(host);
        return { configurations: [], unsupported: [] };
      },
      render: (config) => config.source,
    }),
  );

  await runSetup({
    input: Readable.from(["1,2\n"]),
    output: quietOutput(),
    interactive: true,
    adapters,
  });

  expect(hosts).toHaveLength(2);
  expect(hosts[0]).toBe(hosts[1]);
});

test("displays adapter-level unsupported servers", async () => {
  const output = capturedOutput();
  const unsupportedAdapter = defineClientAdapter({
    apiVersion: 1,
    id: "fake",
    label: "Fake",
    load: async () => ({
      configurations: [],
      unsupported: [
        {
          client: "fake",
          scope: "project",
          name: "managed",
          configPath: "/managed/config",
          reason: "not writable",
        },
      ],
    }),
    render: (config) => config.source,
  });

  await runSetup({
    input: Readable.from(["1\n"]),
    output,
    interactive: true,
    adapters: [unsupportedAdapter],
  });

  expect(output.text()).toContain("Fake / managed");
  expect(output.text()).toContain("not writable");
});

function menuAdapter(id: string, label: string, onLoad: () => void): ClientAdapter {
  return defineClientAdapter({
    apiVersion: 1,
    id,
    label,
    load: async () => {
      onLoad();
      return { configurations: [], unsupported: [] };
    },
    render: (config) => config.source,
  });
}

function quietOutput(): Writable {
  return new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
}

function capturedOutput(): Writable & { text(): string } {
  const chunks: Buffer[] = [];
  const output = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(Buffer.from(chunk));
      callback();
    },
  }) as Writable & { text(): string };
  output.text = () => Buffer.concat(chunks).toString("utf8");
  return output;
}
