import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, expect, it, vi } from "vitest";
import {
  parseHeaderEnvironmentMapping,
  resolveHeaderEnvironment,
  validateRemoteUpstream,
} from "../src/remote.js";
import {
  createStdioEnvironment,
  createUpstreamTransport,
  type UpstreamConfig,
} from "../src/upstream.js";

const execFileAsync = promisify(execFile);

describe("createStdioEnvironment", () => {
  it("adds only named values to the SDK safe environment", () => {
    const result = createStdioEnvironment(["API_KEY", "EMPTY"], {
      API_KEY: "secret",
      EMPTY: "",
      UNSELECTED: "hidden",
    });
    expect(result.API_KEY).toBe("secret");
    expect(result.EMPTY).toBe("");
    expect(result.UNSELECTED).toBeUndefined();
    expect(result.PATH).toBeTypeOf("string");
  });

  it("rejects a missing named value", () => {
    expect(() => createStdioEnvironment(["MISSING"], {})).toThrow(
      "Environment variable MISSING is missing",
    );
  });

  it("rejects an inherited named value", () => {
    expect(() => createStdioEnvironment(["__proto__"], {})).toThrowError(
      /^Environment variable __proto__ is missing$/,
    );
  });

  it("installs __proto__ as an own enumerable environment value", () => {
    const result = createStdioEnvironment(
      ["__proto__"],
      environmentWithPrototype("prototype-value"),
    );

    expect(Object.hasOwn(result, "__proto__")).toBe(true);
    expect(Object.prototype.propertyIsEnumerable.call(result, "__proto__")).toBe(true);
    expect(result.__proto__).toBe("prototype-value");
  });

  it("passes an explicitly selected __proto__ value to a child process", async () => {
    const env = createStdioEnvironment(["__proto__"], environmentWithPrototype("child-value"));

    const { stdout } = await execFileAsync(
      process.execPath,
      [
        "-e",
        "process.stdout.write(Object.hasOwn(process.env, '__proto__') ? process.env.__proto__ : 'missing')",
      ],
      { env },
    );

    expect(stdout).toBe("child-value");
  });
});

describe("remote upstream validation", () => {
  it("creates WebSocket upstreams with validation and the caller signal", async () => {
    const controller = new AbortController();
    controller.abort();
    const transport = createUpstreamTransport(
      {
        kind: "websocket",
        url: "ws://127.0.0.1:1/mcp",
        headers: [["X-Upstream-Key", "fixture-key"]],
      },
      undefined,
      controller.signal,
    );

    await expect(transport.start()).rejects.toMatchObject({ name: "AbortError" });
    expect(() =>
      createUpstreamTransport({ kind: "websocket", url: "https://example.test/mcp" }),
    ).toThrow("unsupported upstream URL scheme");

    const bearer: UpstreamConfig = {
      kind: "websocket",
      url: "wss://example.test/mcp",
      // @ts-expect-error WebSocket upstreams do not support bearer authentication.
      bearerToken: "hidden",
    };
    const oauth: UpstreamConfig = {
      kind: "websocket",
      url: "wss://example.test/mcp",
      // @ts-expect-error WebSocket upstreams do not support OAuth providers.
      authProviderFactory: () => ({ token: async () => "hidden" }),
    };
    expect([bearer.kind, oauth.kind]).toEqual(["websocket", "websocket"]);
  });

  it("parses a header mapping at the first equals sign", () => {
    expect(parseHeaderEnvironmentMapping("X-Api-Key=UPSTREAM_KEY")).toEqual({
      name: "X-Api-Key",
      environmentVariable: "UPSTREAM_KEY",
    });
  });

  it.each([
    "",
    "X-Api-Key",
    "=UPSTREAM_KEY",
    "X-Api-Key=",
    "X-Api-Key=UPSTREAM-KEY",
    "X-Api-Key=UPSTREAM_KEY=OTHER",
    "X-Api-Key=1UPSTREAM_KEY",
  ])("rejects an invalid header environment mapping without echoing it", (value) => {
    expect(() => parseHeaderEnvironmentMapping(value)).toThrow(
      "invalid upstream header environment mapping",
    );
  });

  it("resolves only own non-empty environment values, including __proto__", () => {
    const environment = Object.defineProperty({}, "__proto__", {
      value: "secret",
      enumerable: true,
    });

    expect(
      resolveHeaderEnvironment([parseHeaderEnvironmentMapping("X-Api-Key=__proto__")], environment),
    ).toEqual([["X-Api-Key", "secret"]]);
    expect(() =>
      resolveHeaderEnvironment([parseHeaderEnvironmentMapping("X-Api-Key=MISSING")], environment),
    ).toThrow("Environment variable MISSING is missing");
    expect(() =>
      resolveHeaderEnvironment([parseHeaderEnvironmentMapping("X-Api-Key=EMPTY")], { EMPTY: "" }),
    ).toThrow("Environment variable EMPTY is missing");
  });

  it("decodes only canonical base64url UTF-8 environment header values", () => {
    expect(
      resolveHeaderEnvironment([parseHeaderEnvironmentMapping("X-Api-Key=ENCODED", "base64url")], {
        ENCODED: "c2VjcmV0",
      }),
    ).toEqual([["X-Api-Key", "secret"]]);

    for (const value of ["c2VjcmV0=", "_w"]) {
      expect(() =>
        resolveHeaderEnvironment(
          [parseHeaderEnvironmentMapping("X-Api-Key=ENCODED", "base64url")],
          { ENCODED: value },
        ),
      ).toThrow("invalid upstream header value for X-Api-Key");
    }
  });

  it("does not expose malformed plain or decoded header values", () => {
    const plain = "plain-header-sentinel\r\nattack";
    const encoded = Buffer.from(plain).toString("base64url");

    for (const mapping of [
      parseHeaderEnvironmentMapping("X-Api-Key=PLAIN"),
      parseHeaderEnvironmentMapping("X-Api-Key=ENCODED", "base64url"),
    ]) {
      const error = capturedError(() =>
        resolveHeaderEnvironment([mapping], {
          PLAIN: plain,
          ENCODED: encoded,
        }),
      );
      expect(error.message).toContain("invalid upstream header value for X-Api-Key");
      expect(error.message).not.toContain(plain);
      expect(error.message).not.toContain(encoded);
    }
  });

  it("rejects invalid, duplicate, and transport-owned upstream headers", () => {
    const invalidValue = "header-value-sentinel\r\nattack";
    const invalidValueError = capturedError(() =>
      validateRemoteUpstream({
        kind: "http",
        url: "https://example.test/mcp",
        headers: [["X-Api-Key", invalidValue]],
      }),
    );
    expect(invalidValueError.message).toContain("X-Api-Key");
    expect(invalidValueError.message).not.toContain(invalidValue);

    expect(() =>
      validateRemoteUpstream({
        kind: "http",
        url: "https://example.test/mcp",
        headers: [["X Bad", "header-value-sentinel"]],
      }),
    ).toThrow("invalid upstream header X Bad");

    expect(() =>
      validateRemoteUpstream({
        kind: "http",
        url: "https://example.test/mcp",
        headers: [
          ["X-Api-Key", "one"],
          ["x-api-key", "two"],
        ],
      }),
    ).toThrow("duplicate upstream header X-Api-Key");

    for (const name of [
      "Host",
      "Content-Length",
      "Connection",
      "Upgrade",
      "Transfer-Encoding",
      "Trailer",
      "TE",
      "Keep-Alive",
      "Proxy-Connection",
      "Proxy-Authorization",
      "Accept",
      "Content-Type",
      "Last-Event-ID",
      "Mcp-Session-Id",
      "Mcp-Future-Header",
      "Sec-WebSocket-Key",
      "Sec-WebSocket-Future",
    ]) {
      expect(() =>
        validateRemoteUpstream({
          kind: "http",
          url: "https://example.test/mcp",
          headers: [[name, "attacker"]],
        }),
      ).toThrow("transport-owned upstream header");
    }
  });

  it("rejects unsafe URLs and insecure remote credentials before transport construction", () => {
    for (const url of [
      "https://user:password@example.test/mcp",
      "https://example.test/mcp?token=secret",
      "https://example.test/mcp#secret",
    ]) {
      expect(() => validateRemoteUpstream({ kind: "http", url })).toThrow("unsafe upstream URL");
    }
    expect(() => validateRemoteUpstream({ kind: "http", url: "ws://example.test/mcp" })).toThrow(
      "unsupported upstream URL scheme",
    );
    expect(() =>
      validateRemoteUpstream({ kind: "websocket", url: "https://example.test/mcp" }),
    ).toThrow("unsupported upstream URL scheme");
    expect(() =>
      validateRemoteUpstream({
        kind: "http",
        url: "http://example.test/mcp",
        headers: [["X-Api-Key", "secret"]],
      }),
    ).toThrow("secure upstream URL is required");
    expect(() =>
      validateRemoteUpstream({
        kind: "http",
        url: "http://127.0.0.2/mcp",
        headers: [["X-Api-Key", "secret"]],
      }),
    ).not.toThrow();
    expect(() =>
      validateRemoteUpstream({
        kind: "http",
        url: "http://example.test/mcp",
        auth: "bearer",
      }),
    ).toThrow("secure upstream URL is required");
  });

  it("rejects a configured authorization header when transport auth is configured", () => {
    expect(() =>
      validateRemoteUpstream({
        kind: "http",
        url: "https://example.test/mcp",
        headers: [["Authorization", "Basic hidden"]],
        auth: "bearer",
      }),
    ).toThrow("conflicting upstream authentication");
  });

  it.each(["http", "sse"] as const)(
    "rejects conflicting configured and transport authentication for %s upstreams",
    (kind) => {
      for (const config of [
        {
          headers: [["Authorization", "Basic hidden"]] as const,
          bearerToken: "hidden",
        },
        {
          headers: [["Authorization", "Basic hidden"]] as const,
          authProviderFactory: () => ({ token: async () => "hidden" }),
        },
        {
          bearerToken: "hidden",
          authProviderFactory: () => ({ token: async () => "hidden" }),
        },
      ]) {
        const remote = { url: "https://example.test/mcp", ...config };
        expect(() =>
          createUpstreamTransport(
            kind === "http" ? { kind: "http", ...remote } : { kind: "sse", ...remote },
          ),
        ).toThrow("conflicting upstream authentication");
      }
    },
  );

  it.each(["http", "sse"] as const)(
    "aborts the %s auth provider when the transport closes",
    async (kind) => {
      const caller = new AbortController();
      let providerSignal: AbortSignal | undefined;
      const transport = createUpstreamTransport(
        {
          kind,
          url: "https://example.test/mcp",
          authProviderFactory: (signal) => {
            providerSignal = signal;
            return { token: async () => "token" };
          },
        },
        undefined,
        caller.signal,
      );

      expect(providerSignal?.aborted).toBe(false);
      await transport.close();
      expect(providerSignal?.aborted).toBe(true);
      expect(caller.signal.aborted).toBe(false);
    },
  );

  it("creates one HTTP auth provider per transport without changing caller headers", () => {
    const headers = [["X-Upstream-Key", "caller-owned"]] as const;
    const first = new AbortController();
    const second = new AbortController();
    const receivedSignals: Array<AbortSignal | undefined> = [];
    const providers: object[] = [];
    const authProviderFactory = (signal?: AbortSignal) => {
      receivedSignals.push(signal);
      const provider = { token: async () => "token" };
      providers.push(provider);
      return provider;
    };

    createUpstreamTransport(
      {
        kind: "http",
        url: "https://example.test/mcp",
        headers,
        authProviderFactory,
      },
      undefined,
      first.signal,
    );
    createUpstreamTransport(
      {
        kind: "http",
        url: "https://example.test/mcp",
        headers,
        authProviderFactory,
      },
      undefined,
      second.signal,
    );

    expect(receivedSignals).toHaveLength(2);
    expect(receivedSignals[0]).not.toBe(first.signal);
    expect(receivedSignals[1]).not.toBe(second.signal);
    expect(receivedSignals[0]).not.toBe(receivedSignals[1]);
    first.abort();
    expect(receivedSignals.map((received) => received?.aborted)).toEqual([true, false]);
    second.abort();
    expect(receivedSignals.map((received) => received?.aborted)).toEqual([true, true]);
    expect(providers).toHaveLength(2);
    expect(providers[0]).not.toBe(providers[1]);
    expect(headers).toEqual([["X-Upstream-Key", "caller-owned"]]);
  });

  it.each(["http", "sse"] as const)(
    "waits for an active %s event stream to finish closing",
    async (kind) => {
      let streamController!: ReadableStreamDefaultController<Uint8Array>;
      let markStreamRead!: () => void;
      const streamRead = new Promise<void>((resolve) => {
        markStreamRead = resolve;
      });
      let markAborted!: () => void;
      const aborted = new Promise<void>((resolve) => {
        markAborted = resolve;
      });
      let releaseStream!: () => void;
      const streamReleased = new Promise<void>((resolve) => {
        releaseStream = resolve;
      });
      let primed = false;
      vi.stubGlobal(
        "fetch",
        vi.fn(async (_input: URL | RequestInfo, init?: RequestInit) => {
          if (init?.method === "POST") return new Response(null, { status: 202 });
          const body = new ReadableStream<Uint8Array>({
            start(controller) {
              streamController = controller;
            },
            pull(controller) {
              markStreamRead();
              if (!primed) {
                primed = true;
                controller.enqueue(
                  new TextEncoder().encode(
                    kind === "sse" ? "event: endpoint\ndata: /messages\n\n" : ": ready\n\n",
                  ),
                );
              }
            },
          });
          init?.signal?.addEventListener(
            "abort",
            () => {
              markAborted();
              void streamReleased.then(() =>
                streamController.error(new DOMException("Aborted", "AbortError")),
              );
            },
            { once: true },
          );
          return new Response(body, {
            headers: { "content-type": "text/event-stream" },
          });
        }),
      );
      const transport = createUpstreamTransport({ kind, url: "https://example.test/mcp" });

      try {
        await transport.start();
        if (kind === "http") {
          await transport.send({ jsonrpc: "2.0", method: "notifications/initialized" });
        }
        await streamRead;

        const closing = transport.close();
        expect(transport.close()).toBe(closing);
        let closed = false;
        void closing.then(() => {
          closed = true;
        });
        await aborted;
        await Promise.resolve();
        expect(closed).toBe(false);

        releaseStream();
        await closing;
        expect(closed).toBe(true);
      } finally {
        releaseStream();
        await transport.close();
        vi.unstubAllGlobals();
      }
    },
  );

  it.each(["http", "sse"] as const)(
    "waits for cancellation of a %s response completed after close",
    async (kind) => {
      let releaseValidation!: () => void;
      const validationReleased = new Promise<void>((resolve) => {
        releaseValidation = resolve;
      });
      let markValidationPending!: () => void;
      const validationPending = new Promise<void>((resolve) => {
        markValidationPending = resolve;
      });
      let releaseCancellation!: () => void;
      const cancellationReleased = new Promise<void>((resolve) => {
        releaseCancellation = resolve;
      });
      let markCancelled!: () => void;
      const cancelled = new Promise<"cancelled">((resolve) => {
        markCancelled = () => resolve("cancelled");
      });
      let markPiped!: () => void;
      const piped = new Promise<"piped">((resolve) => {
        markPiped = () => resolve("piped");
      });
      let streamController!: ReadableStreamDefaultController<Uint8Array>;
      let cancellationFinished = false;
      let wasPiped = false;
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          streamController = controller;
        },
        cancel: async () => {
          markCancelled();
          await cancellationReleased;
          cancellationFinished = true;
        },
      });
      const pipeTo = body.pipeTo.bind(body);
      body.pipeTo = ((...args: Parameters<typeof pipeTo>) => {
        wasPiped = true;
        markPiped();
        return pipeTo(...args);
      }) as typeof body.pipeTo;
      vi.stubGlobal(
        "fetch",
        vi.fn(async () => new Response(body, { headers: { "content-type": "text/event-stream" } })),
      );
      const transport = createUpstreamTransport({
        kind,
        url: "https://example.test/mcp",
        validateResponse: async () => {
          markValidationPending();
          await validationReleased;
        },
      });
      let closing: Promise<void> | undefined;

      try {
        const request =
          kind === "http"
            ? transport
                .start()
                .then(() => transport.send({ jsonrpc: "2.0", method: "notifications/initialized" }))
            : transport.start();
        void request.catch(() => {});
        await validationPending;

        closing = transport.close();
        releaseValidation();

        await expect(Promise.race([cancelled, piped])).resolves.toBe("cancelled");
        expect(wasPiped).toBe(false);
        let closed = false;
        void closing.then(() => {
          closed = true;
        });
        await new Promise((resolve) => setImmediate(resolve));
        expect(closed).toBe(false);

        releaseCancellation();
        await closing;
        expect(cancellationFinished).toBe(true);
      } finally {
        releaseValidation();
        releaseCancellation();
        try {
          streamController.close();
        } catch {}
        await (closing ?? transport.close());
        vi.unstubAllGlobals();
      }
    },
  );

  it("does not start an authentication fetch after close", async () => {
    let releaseAuthentication!: () => void;
    const authenticationReleased = new Promise<void>((resolve) => {
      releaseAuthentication = resolve;
    });
    let markAuthenticationPending!: () => void;
    const authenticationPending = new Promise<void>((resolve) => {
      markAuthenticationPending = resolve;
    });
    const fetchMock = vi.fn(async (_input: URL | RequestInfo, init?: RequestInit) =>
      init?.method === "POST"
        ? new Response(null, {
            status: 401,
            headers: { "www-authenticate": "Bearer" },
          })
        : new Response(null, { status: 204 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const transport = createUpstreamTransport({
      kind: "http",
      url: "https://example.test/mcp",
      authProviderFactory: () => ({
        token: async () => "expired",
        onUnauthorized: async ({ fetchFn }) => {
          markAuthenticationPending();
          await authenticationReleased;
          await fetchFn(new URL("https://auth.example.test/token"), { method: "GET" });
        },
      }),
    });
    let sending: Promise<void> | undefined;

    try {
      await transport.start();
      sending = transport
        .send({ jsonrpc: "2.0", method: "notifications/initialized" })
        .catch(() => {});
      await authenticationPending;

      await transport.close();
      releaseAuthentication();
      await sending;
      await new Promise((resolve) => setImmediate(resolve));

      expect(fetchMock.mock.calls.map(([, init]) => init?.method)).toEqual(["POST"]);
    } finally {
      releaseAuthentication();
      await sending;
      await transport.close();
      vi.unstubAllGlobals();
    }
  });

  it("constructs SSE with validated headers and a fresh auth provider", () => {
    const headers = [["X-Upstream-Key", "caller-owned"]] as const;
    const first = new AbortController();
    const second = new AbortController();
    const receivedSignals: Array<AbortSignal | undefined> = [];
    const providers: object[] = [];
    const authProviderFactory = (signal?: AbortSignal) => {
      receivedSignals.push(signal);
      const provider = { token: async () => "token" };
      providers.push(provider);
      return provider;
    };

    const firstTransport = createUpstreamTransport(
      {
        kind: "sse",
        url: "https://example.test/mcp",
        headers,
        authProviderFactory,
      },
      undefined,
      first.signal,
    ) as unknown as SseTransportInternals;
    const secondTransport = createUpstreamTransport(
      {
        kind: "sse",
        url: "https://example.test/mcp",
        headers,
        authProviderFactory,
      },
      undefined,
      second.signal,
    ) as unknown as SseTransportInternals;

    expect(Array.from(new Headers(firstTransport._requestInit?.headers).entries())).toEqual([
      ["x-upstream-key", "caller-owned"],
    ]);
    expect(receivedSignals).toHaveLength(2);
    expect(receivedSignals[0]).not.toBe(first.signal);
    expect(receivedSignals[1]).not.toBe(second.signal);
    expect(receivedSignals[0]).not.toBe(receivedSignals[1]);
    first.abort();
    expect(receivedSignals.map((received) => received?.aborted)).toEqual([true, false]);
    second.abort();
    expect(receivedSignals.map((received) => received?.aborted)).toEqual([true, true]);
    expect(providers).toHaveLength(2);
    expect(firstTransport._authProvider).toBe(providers[0]);
    expect(secondTransport._authProvider).toBe(providers[1]);
    expect(firstTransport._authProvider).not.toBe(secondTransport._authProvider);
    expect(headers).toEqual([["X-Upstream-Key", "caller-owned"]]);
  });
});

type SseTransportInternals = {
  _requestInit?: RequestInit;
  _authProvider?: object;
};

function environmentWithPrototype(value: string): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  Object.defineProperty(environment, "__proto__", {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
  return environment;
}

function capturedError(action: () => unknown): Error {
  try {
    action();
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
  throw new Error("Expected action to throw");
}
