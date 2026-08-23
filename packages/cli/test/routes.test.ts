import { link, chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, expect, test } from "vitest";
import { MASTER_KEY_FILE_ENV } from "../src/oauth/storage.ts";
import {
  loadRoutes,
  parseRoute,
  routeId,
  routePath,
  routeUrl,
  serializeRoute,
  type RouteDefinitionV1,
  type RouteOwner,
} from "../src/routes.ts";

const fixture =
  process.platform === "win32"
    ? {
        expectedRouteId: "ba725bad5c0f45a309604e1b90401e958d4b70245e3a56635c50fa94f543bbe0",
        configPath: "C:\\project\\.codex\\config.toml",
        projectRoot: "C:\\project",
        policy: "C:\\project\\policy.yaml",
        managedPolicy: "C:\\project\\.mcp-restrictor\\policies\\codex\\github.yaml",
        otherPolicy: "C:\\project\\other.yaml",
        home: "C:\\Users\\alice",
        keyPath: "C:\\Users\\alice\\.mcp-restrictor\\master.key",
        routePath:
          "C:\\Users\\alice\\.mcp-restrictor\\routes\\ba725bad5c0f45a309604e1b90401e958d4b70245e3a56635c50fa94f543bbe0.json",
        wrongRoutePath: "C:\\routes\\not-the-route-id.json",
      }
    : {
        expectedRouteId: "a2a210e0c010d834f39e237837771d5fe8fcb7fe9fb6bb82ecea2294731f9340",
        configPath: "/project/.codex/config.toml",
        projectRoot: "/project",
        policy: "/project/policy.yaml",
        managedPolicy: "/project/.mcp-restrictor/policies/codex/github.yaml",
        otherPolicy: "/other.yaml",
        home: "/home/alice",
        keyPath: "/home/alice/.mcp-restrictor/master.key",
        routePath:
          "/home/alice/.mcp-restrictor/routes/a2a210e0c010d834f39e237837771d5fe8fcb7fe9fb6bb82ecea2294731f9340.json",
        wrongRoutePath: "/routes/not-the-route-id.json",
      };
const expectedRouteId = fixture.expectedRouteId;
const owner: RouteOwner = {
  adapterId: "codex",
  scope: "project",
  configPath: fixture.configPath,
  projectRoot: fixture.projectRoot,
  serverName: "github",
};
const validRoute: RouteDefinitionV1 = {
  version: 1,
  owner,
  listenUrl: `http://127.0.0.1:7319/mcp/codex/${expectedRouteId}`,
  proxyArgs: ["--policy", fixture.managedPolicy, "--upstream-http", "https://upstream.example/mcp"],
  environment: { set: {} },
};

const temporaryHomes: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryHomes.splice(0).map((home) => rm(home, { recursive: true, force: true })),
  );
});

test("derives the literal stable Codex project route identity", () => {
  expect(routeId(owner)).toBe(expectedRouteId);
  expect(routeId(owner)).toMatch(/^[0-9a-f]{64}$/);
  expect(routePath(fixture.home, owner)).toBe(fixture.routePath);
  expect(routeUrl(7319, owner)).toBe(`http://127.0.0.1:7319/mcp/codex/${expectedRouteId}`);
});

test("serializes only selectors and a fixed absolute OAuth key path in canonical JSON", () => {
  const route: RouteDefinitionV1 = {
    ...validRoute,
    proxyArgs: [
      "--policy",
      fixture.policy,
      "--upstream-http",
      "https://upstream.example/mcp",
      "--upstream-header-env",
      "X-Key=HEADER_ENV",
      "--upstream-oauth-profile",
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    ],
    environment: { set: { [MASTER_KEY_FILE_ENV]: fixture.keyPath } },
  };

  const serialized = serializeRoute(route);

  expect(serialized).toBe(`${JSON.stringify(route, null, 2)}\n`);
  expect(parseRoute(serialized)).toEqual(route);
  expect(serialized).not.toContain("header-secret");
  expect(serialized).not.toContain("access-token");
});

test.each([
  ["top-level", (route: any): void => void (route.extra = true)],
  ["owner", (route: any): void => void (route.owner.extra = true)],
  ["environment", (route: any): void => void (route.environment.extra = true)],
  ["environment set", (route: any): void => void (route.environment.set.UNKNOWN = "/secret")],
] as const)("rejects an unknown %s key", (_name, mutate) => {
  const route = structuredClone(validRoute);
  mutate(route);
  expect(() => parseRoute(JSON.stringify(route))).toThrow();
});

test.each([
  ["version", (route: any) => delete route.version],
  ["owner", (route: any) => delete route.owner],
  ["environment set", (route: any) => delete route.environment.set],
] as const)("rejects a missing %s key", (_name, mutate) => {
  const route = structuredClone(validRoute);
  mutate(route);
  expect(() => parseRoute(JSON.stringify(route))).toThrow();
});

test.each([
  ["wrong version", (route: any): void => void (route.version = 2)],
  ["invalid adapter", (route: any): void => void (route.owner.adapterId = "Codex")],
  ["invalid scope", (route: any): void => void (route.owner.scope = "global")],
  ["empty server name", (route: any): void => void (route.owner.serverName = "")],
  ["ambiguous server name", (route: any): void => void (route.owner.serverName = "github\0other")],
  ["relative config path", (route: any): void => void (route.owner.configPath = "config.toml")],
  ["relative project root", (route: any): void => void (route.owner.projectRoot = "project")],
] as const)("rejects %s", (_name, mutate) => {
  const route = structuredClone(validRoute);
  mutate(route);
  expect(() => parseRoute(JSON.stringify(route))).toThrow();
});

test("rejects a filename that does not match the recomputed owner ID", () => {
  expect(() => parseRoute(JSON.stringify(validRoute), fixture.wrongRoutePath)).toThrow();
});

test.each([
  ["wrong derived path", "http://127.0.0.1:7319/mcp/codex/wrong"],
  ["non-loopback host", `http://localhost:7319/mcp/codex/${expectedRouteId}`],
  ["HTTPS", `https://127.0.0.1:7319/mcp/codex/${expectedRouteId}`],
  ["port zero", `http://127.0.0.1:0/mcp/codex/${expectedRouteId}`],
  ["missing port", `http://127.0.0.1/mcp/codex/${expectedRouteId}`],
  ["credentials", `http://user:password@127.0.0.1:7319/mcp/codex/${expectedRouteId}`],
  ["query", `http://127.0.0.1:7319/mcp/codex/${expectedRouteId}?secret=value`],
  ["fragment", `http://127.0.0.1:7319/mcp/codex/${expectedRouteId}#fragment`],
] as const)("rejects a listen URL with %s", (_name, listenUrl) => {
  expect(() => parseRoute(JSON.stringify({ ...validRoute, listenUrl }))).toThrow();
});

test.each([
  [
    "listener flags",
    [
      "--policy",
      fixture.policy,
      "--listen-http",
      "http://127.0.0.1:7319/mcp",
      "--upstream-http",
      "https://upstream.example/mcp",
    ],
  ],
  ["malformed arguments", ["--policy", fixture.policy]],
  [
    "nested Restrictor",
    ["--policy", fixture.policy, "--", "mcp-restrictor", "--policy", fixture.otherPolicy],
  ],
  [
    "relative policy",
    ["--policy", "policy.yaml", "--upstream-http", "https://upstream.example/mcp"],
  ],
  [
    "noncanonical policy order",
    ["--upstream-http", "https://upstream.example/mcp", "--policy", fixture.policy],
  ],
  [
    "noncanonical authentication order",
    [
      "--policy",
      fixture.policy,
      "--upstream-bearer-token-env",
      "TOKEN_ENV",
      "--upstream-http",
      "https://upstream.example/mcp",
    ],
  ],
  ["empty STDIO command", ["--policy", fixture.policy, "--", ""]],
  ["NUL-bearing STDIO command", ["--policy", fixture.policy, "--", "node\0x"]],
  ["NUL-bearing STDIO argument", ["--policy", fixture.policy, "--", "node", "arg\0x"]],
  [
    "NUL-bearing STDIO environment name",
    ["--policy", fixture.policy, "--upstream-env", "API\0KEY", "--", "node"],
  ],
  [
    "relative STDIO cwd",
    ["--policy", fixture.policy, "--upstream-cwd", "project", "--", "node", "upstream.mjs"],
  ],
] as const)("rejects proxyArgs with %s", (_name, proxyArgs) => {
  expect(() => parseRoute(JSON.stringify({ ...validRoute, proxyArgs }))).toThrow();
});

test("preserves an empty STDIO argument in a canonical route", () => {
  const route: RouteDefinitionV1 = {
    ...validRoute,
    proxyArgs: [
      "--policy",
      fixture.policy,
      "--upstream-cwd",
      fixture.projectRoot,
      "--",
      "node",
      "",
    ],
  };

  expect(parseRoute(JSON.stringify(route))).toEqual(route);
});

test("rejects a relative OAuth master-key file path", () => {
  const route = {
    ...validRoute,
    environment: { set: { [MASTER_KEY_FILE_ENV]: ".mcp-restrictor/master.key" } },
  };
  expect(() => parseRoute(JSON.stringify(route))).toThrow();
});

test("returns no routes when the private route directory is absent", async () => {
  expect(await loadRoutes(await temporaryHome())).toEqual([]);
});

test("loads private route files in sorted order with one common origin", async () => {
  const home = await temporaryHome();
  const secondOwner = { ...owner, serverName: "zeta" };
  const firstOwner = { ...owner, serverName: "alpha" };
  const routes = [routeFor(secondOwner), routeFor(firstOwner)];
  for (const route of routes) await writeRoute(home, route);

  const loaded = await loadRoutes(home);

  expect(loaded.map(({ snapshot }) => snapshot.path)).toEqual(
    routes.map((route) => routePath(home, route.owner)).sort(),
  );
  expect(loaded.map(({ definition }) => definition).sort(byServerName)).toEqual(
    routes.sort(byServerName),
  );
});

test("rejects duplicate owner route files under another filename", async () => {
  const home = await temporaryHome();
  const original = await writeRoute(home, validRoute);
  await link(original, join(dirname(original), `${"f".repeat(64)}.json`));

  await expect(loadRoutes(home)).rejects.toThrow();
});

test("rejects routes with mixed listener origins", async () => {
  const home = await temporaryHome();
  const secondOwner = { ...owner, serverName: "second" };
  await writeRoute(home, validRoute);
  await writeRoute(home, routeFor(secondOwner, 7320));

  await expect(loadRoutes(home)).rejects.toThrow();
});

test("rejects a symlinked private route file", async () => {
  const home = await temporaryHome();
  const path = routePath(home, owner);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await chmod(dirname(dirname(path)), 0o700);
  await chmod(dirname(path), 0o700);
  const target = join(home, "route-target.json");
  await writeFile(target, serializeRoute(validRoute), { mode: 0o600 });
  await symlink(target, path);

  await expect(loadRoutes(home)).rejects.toThrow();
});

test.skipIf(process.platform === "win32")("rejects a non-private route file", async () => {
  const home = await temporaryHome();
  const path = await writeRoute(home, validRoute);
  await chmod(path, 0o644);

  await expect(loadRoutes(home)).rejects.toThrow();
});

test.each([
  ["invalid UTF-8", Buffer.from([0xff])],
  ["invalid JSON", Buffer.from("{not-json", "utf8")],
] as const)("rejects a route file with %s", async (_name, content) => {
  const home = await temporaryHome();
  const path = routePath(home, owner);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await chmod(dirname(dirname(path)), 0o700);
  await chmod(dirname(path), 0o700);
  await writeFile(path, content, { mode: 0o600 });

  await expect(loadRoutes(home)).rejects.toThrow();
});

function routeFor(routeOwner: RouteOwner, port = 7319): RouteDefinitionV1 {
  return { ...validRoute, owner: routeOwner, listenUrl: routeUrl(port, routeOwner) };
}

function byServerName(left: RouteDefinitionV1, right: RouteDefinitionV1): number {
  return left.owner.serverName.localeCompare(right.owner.serverName);
}

async function temporaryHome(): Promise<string> {
  const home = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-routes-")));
  temporaryHomes.push(home);
  return home;
}

async function writeRoute(home: string, route: RouteDefinitionV1): Promise<string> {
  const path = routePath(home, route.owner);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await chmod(dirname(dirname(path)), 0o700);
  await chmod(dirname(path), 0o700);
  await writeFile(path, serializeRoute(route), { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}
