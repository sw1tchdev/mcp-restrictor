import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { chmod, lstat, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { createServer as createHttpsServer, request as httpsRequest } from "node:https";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Client, type FetchLike, type Transport } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { NodeStreamableHTTPServerTransport, toNodeHandler } from "@modelcontextprotocol/node";
import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { expect } from "vitest";

const testDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(testDirectory, "../../..");
const cli = resolve(projectRoot, "packages/cli/dist/index.js");
const policy = resolve(testDirectory, "fixtures/policy.yaml");
export const certificatePath = resolve(testDirectory, "fixtures/localhost-cert.pem");
export const privateKeyPath = resolve(testDirectory, "fixtures/localhost-key.pem");

export async function exercise(
  transport: Transport,
  era: "legacy" | "modern" = "legacy",
): Promise<{
  sessionId: string | undefined;
  instanceId: string;
  protocolVersion: string | undefined;
}> {
  const client = new Client(
    { name: "matrix-test", version: "1.0.0" },
    era === "modern" ? { versionNegotiation: { mode: { pin: "2026-07-28" } } } : undefined,
  );
  await client.connect(transport);

  try {
    const { tools } = await client.listTools();
    expect(tools.map(({ name }) => name)).toEqual(["read_file", "write_file"]);
    await expect(
      client.callTool({ name: "delete_file", arguments: { path: "/tmp/a" } }),
    ).rejects.toMatchObject({ code: -32001 });
    const result = await client.callTool({
      name: "read_file",
      arguments: { path: "/workspace/a" },
    });
    const content = result.content[0];
    if (content?.type !== "text" || !content.text.startsWith("upstream:read_file:")) {
      throw new Error("Fixture did not return its upstream instance ID");
    }
    return {
      sessionId: transport.sessionId,
      instanceId: content.text.slice("upstream:read_file:".length),
      protocolVersion: client.getNegotiatedProtocolVersion(),
    };
  } finally {
    await client.close();
  }
}

export type GeneratedWrapper = {
  command: string;
  args: string[];
  env?: Record<string, string>;
  cwd?: string;
};

export async function writeNodeLauncher(directory: string, entry: string): Promise<string> {
  await mkdir(directory, { recursive: true });
  if (process.platform === "win32") {
    const path = join(directory, "mcp-restrictor.cmd");
    await writeFile(path, `@echo off\r\n${cmdQuote(process.execPath)} ${cmdQuote(entry)} %*\r\n`);
    return path;
  }
  const path = join(directory, "mcp-restrictor");
  await writeFile(
    path,
    `#!/usr/bin/env node\nvoid import(${JSON.stringify(pathToFileURL(entry).href)}).catch(() => { process.stderr.write('mcp-restrictor launcher failed\\n'); process.exitCode = 1; });\n`,
    { mode: 0o700 },
  );
  await chmod(path, 0o700);
  return path;
}

export async function snapshotTree(
  root: string,
  { exact = false }: { exact?: boolean } = {},
): Promise<string[]> {
  const snapshot: string[] = [];
  async function visit(path: string, relativePath: string): Promise<void> {
    const stat = await lstat(path);
    const metadata = exact
      ? `mode=${stat.mode} size=${stat.size} mtimeMs=${stat.mtimeMs} dev=${stat.dev} ino=${stat.ino}`
      : `${stat.mode & 0o7777}`;
    if (stat.isDirectory()) {
      if (relativePath || exact)
        snapshot.push(`directory ${relativePath || "."} ${metadata}${exact ? " bytes=" : ""}`);
      for (const name of (await readdir(path)).sort()) {
        await visit(join(path, name), relativePath ? `${relativePath}/${name}` : name);
      }
    } else {
      const bytes = (await readFile(path)).toString("base64");
      snapshot.push(`file ${relativePath} ${metadata}${exact ? " bytes=" : " "}${bytes}`);
    }
  }
  await visit(root, "");
  return snapshot;
}

function cmdQuote(value: string): string {
  return `"${value.replaceAll('"', '""')}"`;
}

export async function exerciseGeneratedWrapper(
  entry: GeneratedWrapper,
  options: {
    expectedTools: string[];
    allowedTool: string;
    deniedTool: string;
  },
): Promise<{ stderr: string }> {
  const transport = new StdioClientTransport({
    command: entry.command,
    args: entry.args,
    ...(entry.env ? { env: entry.env } : {}),
    ...(entry.cwd ? { cwd: entry.cwd } : {}),
    stderr: "pipe",
  });
  const stderr: Buffer[] = [];
  transport.stderr?.on("data", (chunk: Buffer) => stderr.push(chunk));
  const client = new Client({ name: "setup-e2e", version: "1.0.0" });

  try {
    await client.connect(transport);
    expect((await client.listTools()).tools.map(({ name }) => name)).toEqual(options.expectedTools);
    await expect(
      client.callTool({ name: options.allowedTool, arguments: {} }),
    ).resolves.toMatchObject({
      content: [
        {
          type: "text",
          text: `configured upstream:${options.allowedTool}`,
        },
      ],
    });
    await expect(
      client.callTool({ name: options.deniedTool, arguments: {} }),
    ).rejects.toMatchObject({ code: -32001 });
  } finally {
    try {
      await client.close();
    } finally {
      await transport.close();
    }
  }
  return { stderr: Buffer.concat(stderr).toString("utf8") };
}

export async function startDualEraHttpFixture(
  options: {
    tls?: { cert: Buffer; key: Buffer };
    expectedAuthorization?: string;
    tools?: readonly string[];
  } = {},
): Promise<{
  url: string;
  close(): Promise<void>;
}> {
  const handler = createMcpHandler(() => createFixtureServer(options.tools));
  const nodeHandler = toNodeHandler(handler);
  const requestListener = (request: IncomingMessage, response: ServerResponse) => {
    if (!request.method || !request.url) {
      response.writeHead(400).end("Missing HTTP request target");
      return;
    }
    if (
      options.expectedAuthorization !== undefined &&
      request.headers.authorization !== options.expectedAuthorization
    ) {
      response.writeHead(401).end("Unauthorized");
      return;
    }
    void nodeHandler(request as IncomingMessage & { method: string; url: string }, response);
  };
  const server = options.tls
    ? createHttpsServer(options.tls, requestListener)
    : createHttpServer(requestListener);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Missing dual-era fixture port");
  }

  return {
    url: `${options.tls ? "https" : "http"}://127.0.0.1:${address.port}/mcp`,
    close: async () => {
      await handler.close();
      await closeServer(server);
    },
  };
}

export async function startHttpFixture(options: HttpFixtureOptions = {}): Promise<{
  url: string;
  close(): Promise<void>;
}> {
  const instanceId = options.instanceId ?? randomUUID();
  const transport = new NodeStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  transport.onmessage = (message) => {
    if (!("method" in message) || !("id" in message)) return;
    const result = fixtureResult(message.method, message, instanceId);
    void transport.send(
      { jsonrpc: "2.0", id: message.id, result },
      { relatedRequestId: message.id },
    );
  };
  await transport.start();

  const handle = (request: IncomingMessage, response: ServerResponse) => {
    if (
      options.expectedAuthorization !== undefined &&
      request.headers.authorization !== options.expectedAuthorization
    ) {
      response.writeHead(401).end("Unauthorized");
      return;
    }
    void transport.handleRequest(request, response);
  };
  const server = options.tls ? createHttpsServer(options.tls, handle) : createHttpServer(handle);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing fixture port");

  return {
    url: `${options.tls ? "https" : "http"}://127.0.0.1:${address.port}/mcp`,
    close: async () => {
      await transport.close();
      await closeServer(server);
    },
  };
}

export async function startCli(
  upstream: string[],
  listener: "http" | "https" = "http",
  options: { env?: Record<string, string> } = {},
): Promise<{
  url: string;
  child: ChildProcessWithoutNullStreams;
  stderr(): string;
  close(): Promise<void>;
}> {
  const listenerArgs =
    listener === "https"
      ? [
          "--listen-https",
          "https://127.0.0.1:0/mcp",
          "--tls-cert",
          certificatePath,
          "--tls-key",
          privateKeyPath,
        ]
      : ["--listen-http", "http://127.0.0.1:0/mcp"];
  const child = spawn(process.execPath, [cli, "--policy", policy, ...listenerArgs, ...upstream], {
    cwd: projectRoot,
    env: { ...process.env, ...options.env },
    stdio: "pipe",
  });
  let stderr = "";
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString("utf8");
  });
  const url = await listeningUrl(child);

  return {
    url,
    child,
    stderr: () => stderr,
    close: async () => {
      if (child.exitCode !== null) return;
      const exit = once(child, "exit");
      child.kill("SIGTERM");
      await exit;
    },
  };
}

export function fetchWithCa(ca: Buffer): FetchLike {
  return async (input, init) => {
    const request = new Request(input, init);
    const body = request.body ? Buffer.from(await request.arrayBuffer()) : undefined;
    return new Promise<Response>((resolveResponse, reject) => {
      const outgoing = httpsRequest(
        request.url,
        {
          method: request.method,
          headers: Object.fromEntries(request.headers),
          ca,
          signal: request.signal,
        },
        (incoming) => {
          if (
            request.redirect === "error" &&
            incoming.statusCode !== undefined &&
            incoming.statusCode >= 300 &&
            incoming.statusCode < 400
          ) {
            incoming.resume();
            reject(new TypeError("fetch failed"));
            return;
          }
          const chunks: Buffer[] = [];
          incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
          incoming.on("end", () => {
            const headers = new Headers();
            for (const [name, value] of Object.entries(incoming.headers)) {
              if (Array.isArray(value)) {
                for (const item of value) headers.append(name, item);
              } else if (value !== undefined) {
                headers.set(name, value);
              }
            }
            const status = incoming.statusCode ?? 500;
            resolveResponse(
              new Response([204, 205, 304].includes(status) ? null : Buffer.concat(chunks), {
                status,
                headers,
              }),
            );
          });
        },
      );
      outgoing.on("error", reject);
      if (body) outgoing.write(body);
      outgoing.end();
    });
  };
}

type HttpFixtureOptions = {
  tls?: { cert: Buffer; key: Buffer };
  expectedAuthorization?: string;
  instanceId?: string;
};

function fixtureResult(
  method: string,
  message: Record<string, unknown>,
  instanceId: string,
): Record<string, unknown> {
  if (method === "initialize") {
    const params = message.params as { protocolVersion: string };
    return {
      protocolVersion: params.protocolVersion,
      capabilities: { tools: {} },
      serverInfo: { name: "http-fixture", version: "1.0.0" },
    };
  }
  if (method === "tools/list") {
    return {
      tools: ["read_file", "write_file", "delete_file"].map((name) => ({
        name,
        inputSchema: { type: "object" },
      })),
    };
  }
  if (method === "tools/call") {
    const params = message.params as { name: string };
    return {
      content: [{ type: "text", text: `upstream:${params.name}:${instanceId}` }],
    };
  }
  return {};
}

function createFixtureServer(
  tools: readonly string[] = ["read_file", "write_file", "delete_file"],
): McpServer {
  const instanceId = randomUUID();
  const server = new McpServer({
    name: "dual-era-http-fixture",
    version: "1.0.0",
  });
  for (const name of tools) {
    server.registerTool(name, {}, async () => ({
      content: [{ type: "text", text: `upstream:${name}:${instanceId}` }],
    }));
  }
  return server;
}

export function closeServer(server: Server): Promise<void> {
  return new Promise((resolveClose, reject) => {
    server.close((error) => (error ? reject(error) : resolveClose()));
  });
}

function listeningUrl(child: ChildProcessWithoutNullStreams): Promise<string> {
  return new Promise((resolveUrl, reject) => {
    let pending = "";
    const cleanup = () => {
      child.stderr.off("data", onData);
      child.off("exit", onExit);
    };
    const onData = (chunk: Buffer) => {
      pending += chunk.toString("utf8");
      const match = /(?:^|\n)mcp-restrictor listening (https?:\/\/\S+)\n/.exec(pending);
      if (!match?.[1]) return;
      cleanup();
      resolveUrl(match[1]);
    };
    const onExit = (code: number | null) => {
      cleanup();
      reject(new Error(`CLI exited before listening (code ${code})`));
    };
    child.stderr.on("data", onData);
    child.once("exit", onExit);
  });
}
