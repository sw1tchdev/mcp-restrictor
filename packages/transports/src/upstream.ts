import {
  SSEClientTransport,
  StreamableHTTPClientTransport,
  type AuthProvider,
} from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import type { Transport } from "@modelcontextprotocol/server";
import type { ChildProcess } from "node:child_process";
import type { Writable } from "node:stream";
import { fetchWithoutRedirects, validateRemoteUpstream, type UpstreamHeader } from "./remote.js";
import { CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE } from "./utils.js";
import { WebSocketClientTransport } from "./websocket.js";

export type UpstreamConfig =
  | {
      kind: "stdio";
      command: string;
      args?: string[];
      env?: Record<string, string>;
      cwd?: string;
    }
  | {
      kind: "http";
      url: string;
      headers?: readonly UpstreamHeader[];
      bearerToken?: string;
      authProviderFactory?: (signal?: AbortSignal) => AuthProvider;
      validateResponse?: (response: Response) => void | Promise<void>;
    }
  | {
      kind: "sse";
      url: string;
      headers?: readonly UpstreamHeader[];
      bearerToken?: string;
      authProviderFactory?: (signal?: AbortSignal) => AuthProvider;
      validateResponse?: (response: Response) => void | Promise<void>;
    }
  | {
      kind: "websocket";
      url: string;
      headers?: readonly UpstreamHeader[];
      bearerToken?: never;
      authProviderFactory?: never;
    };

export type UpstreamTransport = Transport & { exitCode?: Promise<number> };

export function createStdioEnvironment(
  names: readonly string[],
  source: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const env = getDefaultEnvironment();
  for (const name of new Set(names)) {
    const value = Object.hasOwn(source, name) ? source[name] : undefined;
    if (typeof value !== "string") {
      throw new Error(`Environment variable ${name} is missing`);
    }
    Object.defineProperty(env, name, {
      value,
      enumerable: true,
      configurable: true,
      writable: true,
    });
  }
  return env;
}

export function createUpstreamTransport(
  config: UpstreamConfig,
  error?: Writable,
  signal?: AbortSignal,
): UpstreamTransport {
  if (config.kind === "websocket") {
    const { url, headers } = validateRemoteUpstream(config);
    return new WebSocketClientTransport(url, headers, signal);
  }
  if (config.kind === "http" || config.kind === "sse") {
    if (config.bearerToken && config.authProviderFactory) {
      throw new Error(CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE);
    }
    const authProviderFactory =
      config.authProviderFactory ??
      (config.bearerToken ? () => ({ token: async () => config.bearerToken }) : undefined);
    const { url, headers } = validateRemoteUpstream({
      kind: config.kind,
      url: config.url,
      ...(config.headers ? { headers: config.headers } : {}),
      ...(authProviderFactory ? { auth: "bearer" } : {}),
    });
    const lifetime = new AbortController();
    const authProvider = authProviderFactory?.(
      signal ? AbortSignal.any([signal, lifetime.signal]) : lifetime.signal,
    );
    const remoteFetch = fetchWithoutRedirects(undefined, config.validateResponse);
    const options = {
      requestInit: { headers },
      fetch: remoteFetch,
      ...(authProvider ? { authProvider } : {}),
    };
    // The pinned SDK does not await or consistently cancel its background SSE pipelines.
    const activeStreams = new Set<{ stream: Promise<void>; pipe?: AbortController }>();
    const trackedFetch: typeof remoteFetch = async (input, init) => {
      lifetime.signal.throwIfAborted();
      const requestSignal = init?.signal ?? undefined;
      requestSignal?.throwIfAborted();
      const combinedSignal = requestSignal
        ? AbortSignal.any([requestSignal, lifetime.signal])
        : lifetime.signal;
      let finish!: () => void;
      const stream = new Promise<void>((resolve) => {
        finish = resolve;
      });
      const active: { stream: Promise<void>; pipe?: AbortController } = { stream };
      activeStreams.add(active);
      void stream.then(() => activeStreams.delete(active));
      try {
        const response = await remoteFetch(input, {
          ...init,
          signal: combinedSignal,
        });
        if (combinedSignal.aborted) {
          await response.body?.cancel().catch(() => {});
          combinedSignal.throwIfAborted();
        }
        if (
          response.ok &&
          response.body &&
          response.headers.get("content-type")?.toLowerCase().startsWith("text/event-stream")
        ) {
          const passthrough = new TransformStream<Uint8Array, Uint8Array>();
          active.pipe = new AbortController();
          void response.body
            .pipeTo(passthrough.writable, { signal: active.pipe.signal })
            .then(finish, finish);
          return new Response(passthrough.readable, response);
        }
        finish();
        return response;
      } catch (error) {
        finish();
        throw error;
      }
    };
    const transport =
      config.kind === "sse"
        ? new SSEClientTransport(url, { ...options, fetch: trackedFetch })
        : new StreamableHTTPClientTransport(url, { ...options, fetch: trackedFetch });
    const close = transport.close.bind(transport);
    let closing: Promise<void> | undefined;
    transport.close = () => {
      closing ??= (async () => {
        for (const active of activeStreams) active.pipe?.abort();
        lifetime.abort();
        try {
          await close();
        } finally {
          await Promise.allSettled([...activeStreams].map(({ stream }) => stream));
        }
      })();
      return closing;
    };
    return transport;
  }

  const transport = new ObservableStdioClientTransport({
    command: config.command,
    ...(config.args ? { args: config.args } : {}),
    ...(config.env ? { env: config.env } : {}),
    ...(config.cwd !== undefined ? { cwd: config.cwd } : {}),
    stderr: error ? "pipe" : "inherit",
  });
  if (error) transport.stderr?.pipe(error, { end: false });
  return transport;
}

class ObservableStdioClientTransport extends StdioClientTransport {
  readonly exitCode: Promise<number>;
  readonly #resolveExitCode: (code: number) => void;

  constructor(options: ConstructorParameters<typeof StdioClientTransport>[0]) {
    super(options);
    let resolve!: (code: number) => void;
    this.exitCode = new Promise((resolvePromise) => {
      resolve = resolvePromise;
    });
    this.#resolveExitCode = resolve;
  }

  override async start(): Promise<void> {
    await super.start();
    // ponytail: the pinned SDK exposes pid but not exit status; remove this
    // private-field adapter when its public transport API exposes completion.
    const child = (this as unknown as { _process?: ChildProcess })._process;
    if (!child) {
      this.#resolveExitCode(1);
      return;
    }
    child.once("close", (code) =>
      this.#resolveExitCode(code !== null && code >= 0 && code <= 255 ? code : 1),
    );
  }
}
