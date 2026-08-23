import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { describe, expect, test } from "vitest";

const root = resolve(import.meta.dirname, "..");

function ignored(path: string): boolean {
  return (
    spawnSync("git", ["check-ignore", "--no-index", "-q", path], {
      cwd: root,
      stdio: "ignore",
    }).status === 0
  );
}

function documentationRange(source: string, startMarker: string, endMarker: string): string {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  if (start < 0 || end < 0) throw new Error(`documentation range ${startMarker} not found`);
  return source.slice(start, end);
}

function fencedBashBlocks(source: string): string[] {
  return [...source.matchAll(/```bash\n([\s\S]*?)\n```/g)].map((match) => match[1]!.trim());
}

function fencedBashBlock(source: string, marker: string): string {
  const matches = fencedBashBlocks(source).filter((block) => block.includes(marker));
  if (matches.length !== 1) throw new Error(`bash block ${marker} is not unique`);
  return matches[0]!;
}

function workflowJob(workflow: string, name: string): string {
  const match = workflow.match(
    new RegExp(`(?:^|\\n)  ${name}:\\n[\\s\\S]*?(?=\\n  [a-zA-Z0-9_-]+:\\n|$)`),
  );
  if (!match) throw new Error(`workflow job ${name} not found`);
  return match[0];
}

function workflowStep(job: string, name: string): string {
  const marker = `      - name: ${name}\n`;
  const start = job.indexOf(marker);
  if (start < 0) throw new Error(`workflow step ${name} not found`);
  const rest = job.slice(start + marker.length);
  const end = rest.indexOf("\n      - ");
  return marker + (end < 0 ? rest : rest.slice(0, end));
}

function workflowScript(job: string, name: string): string {
  const step = workflowStep(job, name);
  const match = step.match(/        run: \|\n([\s\S]*)/);
  if (!match?.[1]) throw new Error(`workflow step ${name} has no block script`);
  return match[1].replace(/^ {10}/gm, "");
}

async function tagRules(script: string, version: string): Promise<string[]> {
  const directory = await mkdtemp(resolve(tmpdir(), "mcp-restrictor-tags-"));
  const output = resolve(directory, "github-output");
  try {
    const result = spawnSync("bash", ["-eu", "-c", script], {
      encoding: "utf8",
      env: { ...process.env, GITHUB_OUTPUT: output, VERSION: version },
    });
    expect(result.status, result.stderr).toBe(0);
    const lines = (await readFile(output, "utf8")).trimEnd().split("\n");
    expect(lines[0]).toBe("value<<EOF");
    expect(lines.at(-1)).toBe("EOF");
    return lines.slice(1, -1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

describe("public repository contract", () => {
  test("defines the hardened container image contract", async () => {
    const [dockerfile, dockerignore, entrypoint, smoke] = await Promise.all(
      ["Dockerfile", ".dockerignore", "docker-entrypoint.sh", "test/container-smoke.mjs"].map(
        (path) => readFile(resolve(root, path), "utf8"),
      ),
    );
    const manifest = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));
    const base =
      "node:24.19.0-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03";

    expect(dockerfile.split("\n").filter((line) => line.startsWith("FROM "))).toEqual([
      `FROM ${base} AS build`,
      `FROM ${base}`,
    ]);
    expect(dockerfile).toContain("pnpm install --frozen-lockfile");
    expect(dockerfile).toContain(
      "pnpm --filter @mcp-restrictor/cli deploy --prod --no-optional /opt/mcp-restrictor",
    );
    expect(dockerfile).toMatch(/find \/opt\/mcp-restrictor -type f -name ['"]\*\.map['"] -delete/);
    expect(dockerfile).not.toMatch(/COPY[^\n]*--from=build[^\n]*node_modules/);
    expect(dockerfile.match(/apt-get install/g)).toHaveLength(1);
    expect(dockerfile).toMatch(/apt-get install --no-install-recommends -y util-linux/);
    expect(dockerfile).toContain('test "$(id -u node)" = "1000"');
    expect(dockerfile).toContain('test "$(id -g node)" = "1000"');
    expect(dockerfile).toContain("USER 1000:1000");
    expect(dockerfile).toContain("HOME=/home/restrictor");
    expect(dockerfile).toContain("WORKDIR /workspace");
    expect(dockerfile).toContain("NPM_CONFIG_CACHE=/tmp/npm-cache");
    expect(dockerfile).toContain(
      "MCP_RESTRICTOR_MASTER_KEY_FILE=/home/restrictor/.mcp-restrictor-key/oauth-master-key-v1",
    );
    expect(dockerfile).toContain("EXPOSE 17319");
    expect(dockerfile).toContain('ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]');
    expect(dockerfile).toContain('CMD ["run","--bind","0.0.0.0"]');
    expect(dockerfile).not.toContain("MCP_RESTRICTOR_CONTAINER");
    expect(dockerfile).not.toMatch(/(?:TOKEN|PASSWORD|SECRET|PRIVATE_KEY)=/);

    const ignored = new Set(
      dockerignore
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#")),
    );
    for (const pattern of [
      ".git",
      ".worktrees",
      "node_modules",
      "**/node_modules",
      "dist",
      "**/dist",
      "test",
      "**/test",
      ".superpowers",
      "docs/superpowers",
      ".env",
      ".env.*",
      ".npmrc",
      "*.pem",
      "*.key",
      "*.p12",
      "*.pfx",
    ])
      expect(ignored.has(pattern), pattern).toBe(true);

    expect(entrypoint.startsWith("#!/bin/sh\n")).toBe(true);
    const ordered = [
      "umask 077",
      'prepare_private_directory "$HOME/.mcp-restrictor"',
      'prepare_private_directory "$HOME/.mcp-restrictor-key"',
      'lock="$HOME/.mcp-restrictor/.container.lock"',
      'validate_private_lock "$lock"',
      'exec 9<>"$lock"',
      "flock -n 9",
      "export MCP_RESTRICTOR_CONTAINER=1",
      'exec mcp-restrictor "$@"',
    ];
    const positions = ordered.map((value) => {
      const position = entrypoint.indexOf(value);
      expect(position, value).toBeGreaterThanOrEqual(0);
      return position;
    });
    for (let index = 1; index < positions.length; index++)
      expect(positions[index - 1]).toBeLessThan(positions[index]!);
    expect(entrypoint).toContain('test ! -L "$path"');
    expect(entrypoint).toContain('test -f "$path"');
    expect(entrypoint).toContain('test "$(stat -c %u "$path")" = "$uid"');
    expect(entrypoint).toContain('test "$(stat -c %a "$path")" = "600"');
    expect(entrypoint).not.toMatch(/\brm\b|\bchmod\b|\bchown\b/);
    expect(entrypoint).toContain("stop the other container");

    expect(manifest.scripts.test).toBe("vitest run");
    expect(manifest.scripts["test:container"]).toBe("node test/container-smoke.mjs");
    expect(smoke).toContain("MCP_RESTRICTOR_TEST_IMAGE");
    expect(smoke).toContain('"build", "--platform", "linux/amd64"');
  });

  test("drives generated container E2E through the hardened official entrypoint", async () => {
    const smoke = await readFile(resolve(root, "test/container-smoke.mjs"), "utf8");
    const setup = smoke.slice(
      smoke.indexOf("async function runSetupContainer"),
      smoke.indexOf("async function assertFixtureReachable"),
    );
    const generated = smoke.slice(
      smoke.indexOf("async function assertGeneratedRoutesAndGlobalLock"),
      smoke.indexOf("async function assertLiveChildLockOwner"),
    );

    expect(smoke).toContain("const hardenedRuntime = [");
    for (const option of [
      '"--read-only"',
      '"/tmp:rw,noexec,nosuid,size=16m"',
      '"--cap-drop"',
      '"ALL"',
      '"no-new-privileges=true"',
    ])
      expect(smoke, option).toContain(option);
    expect(generated.match(/runSetupContainer\(/g)).toHaveLength(2);
    expect(generated.match(/\.\.\.hardenedRuntime/g)).toHaveLength(2);
    expect(setup).toContain('"create"');
    expect(setup).toContain('"--interactive"');
    expect(setup).toContain('"--tty"');
    expect(setup).toContain("...hardenedRuntime");
    expect(setup).not.toContain('"--entrypoint"');
    expect(smoke).not.toContain("setupProgram");
  });

  test("recursively excludes secret-bearing files from the image build context", async () => {
    const dockerignore = new Set(
      (await readFile(resolve(root, ".dockerignore"), "utf8"))
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#")),
    );

    for (const pattern of [
      "**/.env*",
      "**/.npmrc",
      "**/.mcp-restrictor",
      "**/.mcp-restrictor/**",
      "**/*.pem",
      "**/*.key",
      "**/*.p12",
      "**/*.pfx",
    ])
      expect(dockerignore.has(pattern), pattern).toBe(true);
  });

  test("reports container-smoke success only after checked resource cleanup", async () => {
    const smoke = await readFile(resolve(root, "test/container-smoke.mjs"), "utf8");
    const cleanup = smoke.indexOf("await cleanupResources()");
    const passed = smoke.indexOf("container smoke passed");

    expect(cleanup).toBeGreaterThanOrEqual(0);
    expect(passed).toBeGreaterThan(cleanup);
    expect(smoke).not.toContain(".catch(() => {})");
    expect(smoke).not.toContain("function cleanupDocker");
  });

  test("uses a native HTTP fixture without host certificate tooling", async () => {
    const smoke = await readFile(resolve(root, "test/container-smoke.mjs"), "utf8");

    expect(smoke).toContain('from "node:http"');
    expect(smoke).not.toContain('from "node:https"');
    expect(smoke).not.toContain("openssl");
    expect(smoke).not.toContain("NODE_EXTRA_CA_CERTS");
  });

  test("threads a runtime secret through setup and both gateways without argv values", async () => {
    const smoke = await readFile(resolve(root, "test/container-smoke.mjs"), "utf8");
    const generated = smoke.slice(
      smoke.indexOf("async function assertGeneratedRoutesAndGlobalLock"),
      smoke.indexOf("async function assertLiveChildLockOwner"),
    );
    const setup = smoke.slice(
      smoke.indexOf("async function runSetupContainer"),
      smoke.indexOf("async function assertFixtureReachable"),
    );
    const reachability = smoke.slice(
      smoke.indexOf("async function assertFixtureReachable"),
      smoke.indexOf("function snapshotVolume"),
    );
    const fixture = smoke.slice(
      smoke.indexOf("async function startFixture"),
      smoke.indexOf("async function waitForContainerLogs"),
    );
    const firstGateway = generated.slice(
      generated.indexOf("const gateway ="),
      generated.indexOf("await waitForContainerLogs(gateway"),
    );
    const restartedGateway = generated.slice(
      generated.indexOf("const restarted ="),
      generated.indexOf("await waitForContainerLogs(restarted"),
    );

    expect(smoke).toContain("process.env.SMOKE_SECRET = secret;");
    expect(smoke).not.toContain("SMOKE_SECRET: secret");
    for (const launch of [setup, firstGateway, restartedGateway]) {
      expect(launch).toMatch(/"--env",\s*"SMOKE_SECRET"/);
      expect(launch).not.toContain("SMOKE_SECRET=");
    }
    expect(generated).toContain('{ waitFor: "Header name", input: ["X-Smoke-Secret", "\\r"] }');
    expect(generated).toContain(
      '{ waitFor: "Environment variable", input: ["SMOKE_SECRET", "\\r"] }',
    );
    expect(reachability).toContain('"x-smoke-secret": process.env.SMOKE_SECRET');
    expect(reachability).toContain("missing.status !== 401");
    expect(fixture).toContain('request.headers["x-smoke-secret"] === secret');
    expect(fixture).toContain("response.writeHead(401)");
  });

  test("ignores local state and excludes internal Superpowers files", () => {
    for (const path of [
      ".pnpm-store/index.json",
      ".superpowers/private.md",
      "docs/superpowers/private.md",
      "docs/releasing.md",
      ".env",
      ".env.local",
      ".npmrc",
      ".mcp-restrictor/oauth/profile.json",
      "private.key",
      "private.pem",
      "private.p12",
      "private.pfx",
    ])
      expect(ignored(path), path).toBe(true);

    expect(ignored(".env.example")).toBe(false);
    expect(ignored("packages/cli/test/fixtures/localhost-cert.pem")).toBe(false);
    expect(ignored("packages/cli/test/fixtures/localhost-key.pem")).toBe(false);

    const tracked = spawnSync(
      "git",
      ["ls-files", ".superpowers/**", "docs/superpowers/**", "docs/releasing.md"],
      { cwd: root, encoding: "utf8" },
    );
    expect(tracked.status).toBe(0);
    expect(tracked.stdout).toBe("");
  });

  test("contains complete metadata for public npm packages", async () => {
    const repository = {
      type: "git",
      url: "git+https://github.com/sw1tchdev/mcp-restrictor.git",
    };
    const rootManifest = JSON.parse(await readFile(resolve(root, "package.json"), "utf8"));

    expect(rootManifest.version).toBe("0.0.1");
    expect(rootManifest.private).toBe(true);
    expect(rootManifest.license).toBe("MIT");
    expect(rootManifest.repository).toEqual(repository);
    expect(rootManifest.homepage).toBe("https://github.com/sw1tchdev/mcp-restrictor#readme");
    expect(rootManifest.bugs).toEqual({
      url: "https://github.com/sw1tchdev/mcp-restrictor/issues",
    });
    expect(rootManifest.scripts.lint).toBe("oxlint packages test --deny-warnings");
    expect(rootManifest.scripts.format).toBe("oxfmt");
    expect(rootManifest.scripts["format:check"]).toBe("oxfmt --check");
    expect(JSON.parse(await readFile(resolve(root, ".oxlintrc.json"), "utf8"))).toEqual({
      $schema: "./node_modules/oxlint/configuration_schema.json",
      categories: { correctness: "error" },
      rules: {
        "no-control-regex": "off",
        "no-unsafe-finally": "off",
      },
    });

    expect(await readFile(resolve(root, "README.md"), "utf8")).toContain(
      "MCP Restrictor implements",
    );
    const security = await readFile(resolve(root, "SECURITY.md"), "utf8");
    expect(security).toContain(
      "https://github.com/sw1tchdev/mcp-restrictor/security/advisories/new",
    );
    expect(security).not.toContain("should be added before public release");

    for (const directory of ["core", "policy", "transports", "cli"]) {
      const manifest = JSON.parse(
        await readFile(resolve(root, `packages/${directory}/package.json`), "utf8"),
      );

      expect(manifest.name).toBe(`@mcp-restrictor/${directory}`);
      expect(manifest.version).toBe("0.0.1");
      expect(manifest.license).toBe("MIT");
      expect(manifest.engines).toEqual({ node: ">=22" });
      expect(manifest.publishConfig).toEqual({ access: "public" });
      expect(manifest.repository).toEqual({ ...repository, directory: `packages/${directory}` });
      expect(manifest.homepage).toBe("https://github.com/sw1tchdev/mcp-restrictor#readme");
      expect(manifest.bugs).toEqual({
        url: "https://github.com/sw1tchdev/mcp-restrictor/issues",
      });
      expect(await readFile(resolve(root, `packages/${directory}/LICENSE`), "utf8")).toBe(
        await readFile(resolve(root, "LICENSE"), "utf8"),
      );
      expect(await readFile(resolve(root, `packages/${directory}/README.md`), "utf8")).toContain(
        `@mcp-restrictor/${directory}`,
      );
    }
  });

  test("publishes the managed HTTP gateway contract", async () => {
    const [readme, setup, cli, architecture, security] = await Promise.all(
      ["README.md", "docs/setup.md", "docs/cli.md", "docs/architecture.md", "SECURITY.md"].map(
        (path) => readFile(resolve(root, path), "utf8"),
      ),
    );

    expect(readme).toContain("mcp-restrictor run");
    expect(cli).toContain("Agent --HTTP loopback--> Restrictor --HTTPS--> upstream");
    expect(cli).toMatch(/there is no partial\s+bind/);
    expect(cli).toContain("startup snapshot with no hot reload");
    expect(cli).toContain("NODE_EXTRA_CA_CERTS");
    expect(architecture).toContain("session namespace");
    expect(setup).toContain("$HOME/.mcp-restrictor/routes/<route-id>.json");
    expect(setup).toContain('"type": "http", "url": "<url>"');
    expect(setup).toContain('[mcp_servers.files]\nurl = "<url>"');
    expect(setup).toContain('"type": "remote", "url": "<url>", "oauth": false');
    expect(setup).not.toContain("destination policy path already exists");
    expect(setup).not.toContain("destination policy path is owned by another managed entry");
    expect(setup).toMatch(
      /A readable existing destination policy remains selectable as that\s+destination's exact baseline\./,
    );
    expect(setup).toMatch(
      /Before Apply writes anything, ownership preflight\s+rejects a policy referenced by another restore state, and setup rechecks\s+snapshots, paths, identities, and bytes for drift\./,
    );
    expect(security).toContain("Route paths are identifiers, not credentials");
    expect(security).toContain("They are not encrypted");
    expect(security).toMatch(/Direct `--listen-https` remains\s+available/);
  });

  test("publishes the canonical container operations and security contract", async () => {
    const paths = [
      "README.md",
      "docs/container.md",
      "docs/setup.md",
      "docs/cli.md",
      "docs/oauth.md",
      "docs/architecture.md",
      "SECURITY.md",
    ] as const;
    const sources = Object.fromEntries(
      await Promise.all(
        paths.map(async (path) => [path, await readFile(resolve(root, path), "utf8")] as const),
      ),
    ) as Record<(typeof paths)[number], string>;
    const guide = sources["docs/container.md"];

    expect(sources["README.md"]).toContain("./docs/container.md");
    for (const path of [
      "docs/setup.md",
      "docs/cli.md",
      "docs/oauth.md",
      "docs/architecture.md",
    ] as const)
      expect(sources[path], path).toContain("./container.md");
    expect(sources["SECURITY.md"]).toContain("./docs/container.md");
    expect(guide).toContain("../SECURITY.md");

    for (const value of [
      "docker pull ghcr.io/sw1tchdev/mcp-restrictor:latest",
      "-v mcp-restrictor-state:/home/restrictor/.mcp-restrictor",
      "-v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key",
      "--init",
      "--restart unless-stopped",
      "-p 127.0.0.1:17319:17319",
      "run --bind 0.0.0.0",
      "--read-only",
      "--tmpfs /tmp:rw,noexec,nosuid,size=16m",
      "--cap-drop ALL",
      "--security-opt no-new-privileges=true",
      "docker stop mcp-restrictor",
      "docker rm mcp-restrictor",
      "docker volume rm mcp-restrictor-state mcp-restrictor-key",
    ])
      expect(guide, value).toContain(value);

    expect(guide).toMatch(/services:\s*\n\s+mcp-restrictor:/);
    expect(guide).toContain("UID/GID `1000`");
    expect(guide).toContain("Paste redirected URL");
    expect(guide).toContain("oauth login");
    expect(guide).toMatch(/cannot recover|cannot decrypt/);
    expect(guide).toContain("no hot reload");
    expect(guide).toContain("NFS");
    expect(guide).toContain("downstream authentication");
    expect(guide).toContain("HTTPS termination");
    expect(guide).toContain("docker exec");

    const publicDocs = paths.map((path) => sources[path]).join("\n");
    expect(publicDocs).not.toContain("GITHUB_TOKEN");
    expect(publicDocs).not.toMatch(/^(?:\s*\\?\s*)?-p\s+17319:17319(?:\s*\\)?\s*$/m);

    const composeFiles = spawnSync(
      "git",
      ["ls-files", "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"],
      { cwd: root, encoding: "utf8" },
    );
    expect(composeFiles.status).toBe(0);
    expect(composeFiles.stdout).toBe("");
  });

  test("documents lock-safe container maintenance and recovery commands", async () => {
    const guide = await readFile(resolve(root, "docs/container.md"), "utf8");
    const customPort = documentationRange(guide, "### Custom port", "## Generated client presets");
    const reconfigure = documentationRange(
      guide,
      "## Reconfigure or Restore",
      "## OAuth in containers",
    );
    const oauth = documentationRange(
      guide,
      "## OAuth in containers",
      "## Filesystem and process contract",
    );
    const compose = documentationRange(
      guide,
      "## Inline Compose equivalent",
      "## Backup and upgrade",
    );
    const reconfigureSetup = fencedBashBlock(reconfigure, "docker run --rm -it");
    const reconfigureStart = fencedBashBlock(reconfigure, "docker start mcp-restrictor");
    const reconfigureRecreate = fencedBashBlock(reconfigure, "docker run -d");
    const oauthLogin = fencedBashBlock(oauth, "oauth login PROFILE_ID");
    const oauthStart = fencedBashBlock(oauth, "docker start mcp-restrictor");
    const oauthRemove = fencedBashBlocks(oauth).find(
      (block) => block === "docker rm mcp-restrictor",
    );
    const composeRecovery = fencedBashBlock(compose, "docker compose down --volumes");
    const officialImage = "ghcr.io/sw1tchdev/mcp-restrictor:latest";

    expect(customPort).toMatch(
      /docker stop mcp-restrictor[\s\S]*docker rm mcp-restrictor[\s\S]*-p 127\.0\.0\.1:18080:18080/,
    );
    expect(reconfigure).toMatch(
      /state-only[\s\S]*same image[\s\S]*environment[\s\S]*mount[\s\S]*published port/i,
    );
    expect(reconfigureSetup).toMatch(
      /docker stop mcp-restrictor[\s\S]*docker run --rm -it[\s\S]*\n  setup$/,
    );
    expect(reconfigureStart).toBe("docker start mcp-restrictor");
    expect(reconfigureRecreate).toMatch(/docker rm mcp-restrictor[\s\S]*docker run -d/);
    expect(reconfigureRecreate).toContain("-p 127.0.0.1:17319:17319");
    expect(reconfigureRecreate).toMatch(/run --bind 0\.0\.0\.0$/);
    expect(reconfigure).toMatch(/Do not use `docker exec`[\s\S]*setup[\s\S]*oauth login/i);

    expect(reconfigureSetup).toContain(`${officialImage} \\\n  setup`);
    expect(reconfigureRecreate).toContain(`${officialImage} \\\n  run --bind 0.0.0.0`);
    expect(oauthLogin).toContain(`${officialImage} \\\n  oauth login PROFILE_ID`);

    for (const command of [reconfigureSetup, reconfigureRecreate, oauthLogin]) {
      expect(command).toContain("-v mcp-restrictor-state:/home/restrictor/.mcp-restrictor");
      expect(command).toContain("-v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key");
      expect(command).toContain("--env ACME_MCP_BEARER");
      expect(command).toContain("--env NODE_EXTRA_CA_CERTS=/run/secrets/acme-ca.pem");
      expect(command).toContain("-v /absolute/path/to/acme-ca.pem:/run/secrets/acme-ca.pem:ro");
    }

    expect(oauthLogin).toMatch(
      /docker stop mcp-restrictor[\s\S]*docker run --rm -it[\s\S]*oauth login PROFILE_ID/,
    );
    expect(oauthStart).toBe("docker start mcp-restrictor");
    expect(oauthRemove).toBe("docker rm mcp-restrictor");

    const oauthOrder = [
      oauth.indexOf(oauthLogin),
      oauth.indexOf("If the stopped service still has the exact required image"),
      oauth.indexOf(oauthStart),
      oauth.indexOf("If any option changed"),
      oauth.indexOf(oauthRemove!),
      oauth.indexOf("These are alternative final steps"),
    ];
    expect(oauthOrder).not.toContain(-1);
    expect(oauthOrder).toEqual([...oauthOrder].sort((left, right) => left - right));
    const oauthAlternatives = documentationRange(
      oauth,
      "These are alternative final steps",
      "Always mount the same key file",
    );
    expect(oauthAlternatives).toMatch(/alternative final steps/i);
    expect(oauthAlternatives).toMatch(/not commands to run in sequence/i);

    expect(composeRecovery.split("\n")).toEqual([
      "docker compose down --volumes",
      "docker compose run --rm mcp-restrictor setup",
      "docker compose up -d",
    ]);
    const composeWarning = compose.slice(
      compose.indexOf("\n```\n", compose.indexOf("docker compose down --volumes")) + 5,
    );
    expect(composeWarning).toMatch(/destructive/i);
    expect(composeWarning).toMatch(/current Compose\s+project/i);
    expect(composeWarning).toMatch(/(?:all|every) affected (?:project )?resource/i);
  });

  test("documents both OpenCode formats and the generated HTTP-only flow", async () => {
    const setup = await readFile(resolve(root, "docs/setup.md"), "utf8");

    expect(setup).toMatch(/For every selected existing destination/);
    expect(setup).toMatch(
      /Generated presets[\s\S]*managed HTTP[\s\S]*skip[\s\S]*Client connection/i,
    );
    expect(setup).toMatch(/OpenCode Current \(V2\)[\s\S]*"mcp": \{ "servers": \{ "files":/);
    expect(setup).toMatch(/OpenCode Legacy \(V1\)[\s\S]*"mcp": \{ "files":/);
    expect(setup).toMatch(/fragment printed\s+by setup is authoritative/i);
  });

  test("defines independent releases and OIDC publication", async () => {
    const manifest = JSON.parse(
      await readFile(resolve(root, ".release-please-manifest.json"), "utf8"),
    );
    const config = JSON.parse(await readFile(resolve(root, "release-please-config.json"), "utf8"));
    const release = await readFile(resolve(root, ".github/workflows/release.yml"), "utf8");

    expect(manifest).toEqual({
      "packages/core": "0.0.1",
      "packages/policy": "0.0.1",
      "packages/transports": "0.0.1",
      "packages/cli": "0.0.1",
    });
    expect(config.plugins).toEqual(["node-workspace"]);
    expect(Object.keys(config.packages)).toEqual([
      "packages/core",
      "packages/policy",
      "packages/transports",
      "packages/cli",
    ]);
    expect(config).not.toHaveProperty("bootstrap-sha");

    expect(release).not.toContain("NPM_TOKEN");
    expect(release).toContain("id-token: write");
    expect(release).toContain(
      "googleapis/release-please-action@5c625bfb5d1ff62eadeeb3772007f7f66fdcf071",
    );
    expect(release).toContain("pnpm install --frozen-lockfile");
    expect(release).toContain("npm install --global npm@11.18.0");
    expect(release).toContain("npm view");
    expect(release).toContain("npm publish");
    for (const path of [
      "packages/core",
      "packages/policy",
      "packages/transports",
      "packages/cli",
    ]) {
      expect(release).toContain(`${path}--release_created`);
      expect(release).toContain(`${path}--version`);
    }
    expect(release.indexOf("Publish core")).toBeLessThan(release.indexOf("Publish policy"));
    expect(release.indexOf("Publish policy")).toBeLessThan(release.indexOf("Publish transports"));
    expect(release.indexOf("Publish transports")).toBeLessThan(release.indexOf("Publish CLI"));
  });

  test("publishes only a verified CLI image to GHCR with supply-chain evidence", async () => {
    const release = await readFile(resolve(root, ".github/workflows/release.yml"), "utf8");
    const image = workflowJob(release, "publish_image");
    const metadata = workflowStep(image, "Generate container metadata");
    const build = workflowStep(image, "Build and push container image");

    expect(image).toContain("needs: release");
    expect(image).toContain("if: needs.release.outputs.cli_release_created == 'true'");
    expect(image).toContain("VERSION: ${{ needs.release.outputs.cli_version }}");

    const permissions = image.match(/    permissions:\n((?:      [a-z-]+: [a-z]+\n)+)/)?.[1];
    expect(
      Object.fromEntries(
        (permissions ?? "")
          .trim()
          .split("\n")
          .map((line) => line.trim().split(": ")),
      ),
    ).toEqual({
      contents: "read",
      packages: "write",
      "id-token": "write",
      attestations: "write",
    });

    expect(image).toContain("images: ghcr.io/sw1tchdev/mcp-restrictor");
    expect(image).toContain("registry: ghcr.io");
    expect(image).toContain("username: ${{ github.actor }}");
    expect(image).toContain("password: ${{ secrets.GITHUB_TOKEN }}");
    expect(image).toContain("platforms: linux/amd64,linux/arm64");
    expect(image).toContain("push: true");
    expect(metadata).toContain(
      "        env:\n          DOCKER_METADATA_ANNOTATIONS_LEVELS: manifest,index",
    );
    for (const input of ["labels", "annotations"]) {
      const values =
        metadata.match(
          new RegExp(`          ${input}: \\|\\n((?:            [^\\n]+\\n?)*)`),
        )?.[1] ?? "";
      for (const key of [
        "title",
        "description",
        "source",
        "revision",
        "version",
        "created",
        "licenses",
      ])
        expect(values).toContain(`org.opencontainers.image.${key}=`);
      expect(values).toContain(
        "org.opencontainers.image.created={{date 'YYYY-MM-DDTHH:mm:ss.SSS[Z]' tz='UTC'}}",
      );
    }
    expect(build).toContain("tags: ${{ steps.meta.outputs.tags }}");
    expect(build).toContain("labels: ${{ steps.meta.outputs.labels }}");
    expect(build).toContain("annotations: ${{ steps.meta.outputs.annotations }}");
    expect(image).toContain("sbom: true");
    expect(image).toContain("provenance: mode=max");
    expect(image).toContain("subject-name: ghcr.io/sw1tchdev/mcp-restrictor");
    expect(image).toContain("subject-digest: ${{ steps.push.outputs.digest }}");
    expect(image).toContain("push-to-registry: true");
    expect(image).toContain("create-storage-record: false");
    expect(image).not.toMatch(/docker\.io|dockerhub/i);
    expect(image).not.toMatch(/\bPAT\b/);
    expect(image).not.toMatch(/^\s+(?:build-args|secrets|secret-envs|secret-files):/m);
  });

  test("derives stable and prerelease GHCR tags without a broad major tag", async () => {
    const release = await readFile(resolve(root, ".github/workflows/release.yml"), "utf8");
    const script = workflowScript(workflowJob(release, "publish_image"), "Resolve container tags");

    expect(await tagRules(script, "0.2.3")).toEqual([
      "type=raw,value=0.2.3",
      "type=raw,value=0.2",
      "type=raw,value=latest",
    ]);
    expect(await tagRules(script, "0.3.0-rc.1")).toEqual(["type=raw,value=0.3.0-rc.1"]);
  });

  test("pins every workflow action with its release comment", async () => {
    const workflows = await Promise.all(
      [".github/workflows/ci.yml", ".github/workflows/release.yml"].map((path) =>
        readFile(resolve(root, path), "utf8"),
      ),
    );
    const actions = workflows
      .flatMap((workflow) => workflow.split("\n"))
      .filter((line) => line.includes("uses:"));

    expect(actions.length).toBeGreaterThan(2);
    for (const action of actions)
      expect(action).toMatch(/uses: [a-zA-Z0-9_./-]+@[0-9a-f]{40} # v\d+\.\d+\.\d+$/);
    for (const name of [
      "actions/checkout",
      "actions/setup-node",
      "googleapis/release-please-action",
      "docker/setup-qemu-action",
      "docker/setup-buildx-action",
      "docker/login-action",
      "docker/metadata-action",
      "docker/build-push-action",
      "actions/attest",
    ])
      expect(workflows.join("\n"), name).toContain(`uses: ${name}@`);
  });

  test("builds the amd64 CI image once and smokes that exact local tag", async () => {
    const ci = await readFile(resolve(root, ".github/workflows/ci.yml"), "utf8");
    const verify = workflowJob(ci, "verify");
    const buildStep = workflowStep(verify, "Build container image");
    const smokeStep = workflowStep(verify, "Smoke container image");
    const builds = [...ci.matchAll(/\bdocker (?:build|buildx build)\b/g)];
    const build = ci.indexOf(
      'docker build --platform linux/amd64 --tag "$MCP_RESTRICTOR_TEST_IMAGE" .',
    );
    const smoke = ci.indexOf("pnpm run test:container");
    const expectedEnv =
      "        env:\n          MCP_RESTRICTOR_TEST_IMAGE: mcp-restrictor-ci:${{ github.sha }}";

    expect(builds).toHaveLength(1);
    for (const step of [buildStep, smokeStep]) {
      const env = step.match(/(?:^|\n)(        env:\n(?:          [A-Z0-9_]+: [^\n]+\n?)*)/)?.[1];
      expect(env?.trimEnd()).toBe(expectedEnv);
    }
    expect(build).toBeGreaterThanOrEqual(0);
    expect(smoke).toBeGreaterThan(build);
    expect(ci).not.toMatch(/docker (?:build|buildx build)[^\n]*--push/);
  });

  test("keeps pinned workflow and base-image updates automated", async () => {
    const dependabot = await readFile(resolve(root, ".github/dependabot.yml"), "utf8");

    expect(
      [...dependabot.matchAll(/package-ecosystem: "([^"]+)"/g)].map((match) => match[1]),
    ).toEqual(["github-actions", "docker"]);
    expect(dependabot.match(/directory: "\/"/g)).toHaveLength(2);
    expect(dependabot.match(/interval: "weekly"/g)).toHaveLength(2);
  });

  test("runs least-privilege CI before publishing packages", async () => {
    const ci = await readFile(resolve(root, ".github/workflows/ci.yml"), "utf8");

    expect(ci).toContain("permissions:\n  contents: read");
    expect(ci).toContain("pull_request:");
    expect(ci).toContain("branches: [main]");
    for (const command of [
      "pnpm install --frozen-lockfile",
      "pnpm lint",
      "pnpm format:check",
      "pnpm typecheck",
      "pnpm test",
      "pnpm build",
    ])
      expect(ci).toContain(command);
    expect(ci).toContain(
      "for package in packages/core packages/policy packages/transports packages/cli; do",
    );
    expect(ci).toContain('pnpm pack --pack-destination "$RUNNER_TEMP/npm-packages"');
    expect(ci).not.toContain("pnpm -r --filter './packages/**' pack");
    expect(ci).not.toContain("NPM_TOKEN");
    expect(ci).not.toContain("id-token: write");
    expect([...ci.matchAll(/uses: [^@\s]+@([0-9a-f]{40})/g)]).toHaveLength(2);
  });
});
