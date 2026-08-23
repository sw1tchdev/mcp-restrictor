import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { afterAll, beforeAll, describe, it } from "vitest";
import { exercise, startHttpFixture } from "./helpers.js";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(testDirectory, "../../..");
const cli = resolve(projectRoot, "packages/cli/dist/index.js");
const policy = resolve(testDirectory, "fixtures/policy.yaml");
const upstreamFixture = resolve(testDirectory, "fixtures/upstream.mjs");
const certificatePath = resolve(testDirectory, "fixtures/localhost-cert.pem");
const privateKeyPath = resolve(testDirectory, "fixtures/localhost-key.pem");

let httpFixture: Awaited<ReturnType<typeof startHttpFixture>>;
let httpsFixture: Awaited<ReturnType<typeof startHttpFixture>>;

beforeAll(async () => {
  httpFixture = await startHttpFixture();
  httpsFixture = await startHttpFixture({
    tls: {
      cert: await readFile(certificatePath),
      key: await readFile(privateKeyPath),
    },
    expectedAuthorization: "Bearer upstream-secret",
  });
});

afterAll(async () => {
  await Promise.all([httpFixture.close(), httpsFixture.close()]);
});

describe("stdio input transport matrix", () => {
  const routes: Array<{
    route: string;
    args: string[] | (() => string[]);
    env?: Record<string, string>;
  }> = [
    {
      route: "stdio -> stdio",
      args: ["--", process.execPath, upstreamFixture],
    },
    {
      route: "stdio -> HTTP",
      args: () => ["--upstream-http", httpFixture.url],
    },
    {
      route: "stdio -> HTTPS with bearer",
      args: () => ["--upstream-http", httpsFixture.url, "--upstream-bearer-token-env", "MCP_TOKEN"],
      env: {
        ...getDefaultEnvironment(),
        MCP_TOKEN: "upstream-secret",
        NODE_EXTRA_CA_CERTS: certificatePath,
      },
    },
  ];

  it.each(routes)("$route", async ({ args, env }) => {
    await exercise(
      new StdioClientTransport({
        command: process.execPath,
        args: [cli, "--policy", policy, ...(typeof args === "function" ? args() : args)],
        stderr: "pipe",
        ...(env ? { env } : {}),
      }),
    );
  });
});
