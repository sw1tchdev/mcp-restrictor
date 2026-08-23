import { describe, expect, it, vi } from "vitest";
import {
  InMemoryTransport,
  type JSONRPCMessage,
  type RequestId,
  type Transport,
} from "@modelcontextprotocol/server";
import { bridgeTransports } from "../src/bridge.js";

describe("bridgeTransports", () => {
  it("filters discovery and denies calls before they reach upstream", async () => {
    const [client, downstream] = InMemoryTransport.createLinkedPair();
    const [upstream, server] = InMemoryTransport.createLinkedPair();
    const responses = responseQueue(client);
    let upstreamCalls = 0;

    server.onmessage = async (message) => {
      if (!("method" in message) || !("id" in message)) return;

      if (message.method === "tools/list") {
        await server.send({
          jsonrpc: "2.0",
          id: message.id,
          result: {
            tools: [
              { name: "read_file", inputSchema: { type: "object" } },
              { name: "delete_file", inputSchema: { type: "object" } },
            ],
          },
        });
      } else if (message.method === "tools/call") {
        upstreamCalls += 1;
      }
    };

    await client.start();
    await server.start();
    const bridge = await bridgeTransports({
      downstream,
      upstream,
      authorizer: {
        discover: (name) => name === "read_file",
        authorize: (name) => ({ allowed: name === "read_file" }),
      },
    });

    try {
      const listed = responses.take(1);
      await client.send({ jsonrpc: "2.0", id: 1, method: "tools/list" });
      await expect(listed).resolves.toMatchObject({
        result: { tools: [{ name: "read_file" }] },
      });

      const denied = responses.take(2);
      await client.send({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "delete_file", arguments: { path: "/tmp/file" } },
      });
      await expect(denied).resolves.toMatchObject({
        error: { code: -32001 },
      });
      expect(upstreamCalls).toBe(0);
    } finally {
      await bridge.close();
      await Promise.all([client.close(), server.close()]);
    }
  });

  it("closes both sides when a transport reports an error", async () => {
    const [client, downstream] = InMemoryTransport.createLinkedPair();
    const [upstream, server] = InMemoryTransport.createLinkedPair();
    await client.start();
    await server.start();
    const bridge = await bridgeTransports({
      downstream,
      upstream,
      authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
      onerror: () => {},
    });

    try {
      upstream.onerror?.(new Error("broken transport"));
      const closed = await Promise.race([
        bridge.closed.then(() => true),
        new Promise<false>((resolve) => setTimeout(() => resolve(false), 20)),
      ]);
      expect(closed).toBe(true);
    } finally {
      await bridge.close();
      await Promise.all([client.close(), server.close()]);
    }
  });

  it("redacts upstream failures before reporting them", async () => {
    const [client, downstream] = InMemoryTransport.createLinkedPair();
    const [upstream, server] = InMemoryTransport.createLinkedPair();
    const errors: Error[] = [];
    await client.start();
    await server.start();
    const bridge = await bridgeTransports({
      downstream,
      upstream,
      authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
      onerror: (error) => errors.push(error),
    });

    try {
      const secret = "bridge-resource-body-sentinel";
      const error = Object.assign(new Error(secret), {
        data: { status: 502, text: secret },
      });
      upstream.onerror?.(error);
      await bridge.closed;

      expect(errors).toHaveLength(1);
      expect(errors[0]?.message).toBe("request failed (status 502)");
      expect(errors[0]?.message).not.toContain(secret);
    } finally {
      await bridge.close();
      await Promise.all([client.close(), server.close()]);
    }
  });

  it("preserves downstream startup failures and sanitizes upstream startup failures", async () => {
    const downstreamError = new Error("downstream-start-sentinel");
    await expect(
      bridgeTransports({
        downstream: failingStartTransport(downstreamError),
        upstream: noOpTransport(),
        authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
      }),
    ).rejects.toBe(downstreamError);

    const upstreamError = Object.assign(new Error("upstream-start-sentinel"), {
      data: { status: 502, text: "upstream-start-sentinel" },
    });
    await expect(
      bridgeTransports({
        downstream: noOpTransport(),
        upstream: failingStartTransport(upstreamError),
        authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
      }),
    ).rejects.toMatchObject({ message: "connect failed (status 502)" });
  });

  it("preserves downstream send failures and sanitizes upstream send failures", async () => {
    const downstreamError = new Error("downstream-send-sentinel");
    const downstream = failingTransport(downstreamError);
    const upstream = noOpTransport();
    const downstreamErrors: Error[] = [];
    const downstreamBridge = await bridgeTransports({
      downstream,
      upstream,
      authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
      onerror: (error) => downstreamErrors.push(error),
    });
    upstream.onmessage?.({
      jsonrpc: "2.0",
      method: "notifications/message",
      params: {},
    });
    await downstreamBridge.closed;
    expect(downstreamErrors).toEqual([downstreamError]);

    const upstreamError = Object.assign(new Error("upstream-send-sentinel"), {
      data: { status: 502, text: "upstream-send-sentinel" },
    });
    const upstreamErrors: Error[] = [];
    const upstreamTransport = failingTransport(upstreamError);
    const upstreamDownstream = noOpTransport();
    const upstreamBridge = await bridgeTransports({
      downstream: upstreamDownstream,
      upstream: upstreamTransport,
      authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
      onerror: (error) => upstreamErrors.push(error),
    });
    upstreamDownstream.onmessage?.({
      jsonrpc: "2.0",
      method: "ping",
    });
    await upstreamBridge.closed;
    expect(upstreamErrors).toMatchObject([{ message: "request failed (status 502)" }]);
    expect(upstreamErrors[0]?.message).not.toContain("upstream-send-sentinel");
  });

  it("preserves a downstream protocol-version failure", async () => {
    const downstreamError = new Error("downstream-protocol-version-sentinel");
    const downstream = noOpTransport();
    downstream.setProtocolVersion = () => {
      throw downstreamError;
    };
    const upstream = noOpTransport();
    upstream.send = async (message) => {
      if (
        !("method" in message) ||
        message.method !== "initialize" ||
        !("id" in message) ||
        message.id === undefined
      ) {
        return;
      }
      upstream.onmessage?.({
        jsonrpc: "2.0",
        id: message.id,
        result: { protocolVersion: "2025-06-18" },
      });
    };
    const errors: Error[] = [];
    const bridge = await bridgeTransports({
      downstream,
      upstream,
      authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
      onerror: (error) => errors.push(error),
    });

    downstream.onmessage?.({
      jsonrpc: "2.0",
      id: "initialize-1",
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: {} },
    });
    await bridge.closed;

    expect(errors).toEqual([downstreamError]);
  });

  it("closes a never-settling upstream start when aborted", async () => {
    const controller = new AbortController();
    const upstream = neverStartingTransport();
    const downstream = noOpTransport();
    const bridge = bridgeTransports({
      downstream,
      upstream: upstream.transport,
      authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
      signal: controller.signal,
    });

    await upstream.started;
    controller.abort();

    await expect(bridge).rejects.toThrow("AbortError");
    expect(upstream.close).toHaveBeenCalledOnce();
    expect(downstream.close).toHaveBeenCalledOnce();
  });

  it("closes once when transports synchronously report their close", async () => {
    let closes = 0;
    const createTransport = (): Transport => {
      const transport: Transport = {
        start: async () => {},
        send: async () => {},
        close: async () => {
          closes += 1;
          transport.onclose?.();
        },
      };
      return transport;
    };
    const bridge = await bridgeTransports({
      downstream: createTransport(),
      upstream: createTransport(),
      authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
    });

    await bridge.close();

    expect(closes).toBe(2);
  });

  it("relates upstream notifications to the sole pending request", async () => {
    const sent: Array<{
      message: JSONRPCMessage;
      relatedRequestId: RequestId | undefined;
    }> = [];
    const downstream: Transport = {
      start: async () => {},
      close: async () => {},
      send: async (message, options) => {
        sent.push({ message, relatedRequestId: options?.relatedRequestId });
      },
    };
    const upstream: Transport = {
      start: async () => {},
      close: async () => {},
      send: async (message) => {
        if (!("id" in message) || message.id === undefined) return;
        upstream.onmessage?.({
          jsonrpc: "2.0",
          method: "notifications/message",
          params: { data: "working" },
        });
        upstream.onmessage?.({ jsonrpc: "2.0", id: message.id, result: {} });
      },
    };
    const bridge = await bridgeTransports({
      downstream,
      upstream,
      authorizer: { discover: () => true, authorize: () => ({ allowed: true }) },
    });

    downstream.onmessage?.({
      jsonrpc: "2.0",
      id: "request-1",
      method: "ping",
    });
    await bridge.drain();

    expect(sent[0]).toMatchObject({ relatedRequestId: "request-1" });
    await bridge.close();
  });
});

function responseQueue(transport: InMemoryTransport): {
  take: (id: RequestId) => Promise<JSONRPCMessage>;
} {
  const waiting = new Map<RequestId, (message: JSONRPCMessage) => void>();
  transport.onmessage = (message) => {
    if ("id" in message && message.id !== undefined) {
      waiting.get(message.id)?.(message);
    }
  };

  return {
    take: (id) =>
      new Promise((resolve) => {
        waiting.set(id, resolve);
      }),
  };
}

function noOpTransport(): Transport & { close: ReturnType<typeof vi.fn> } {
  const close = vi.fn(async () => {});
  return { start: async () => {}, send: async () => {}, close };
}

function failingTransport(error: Error): Transport & { close: ReturnType<typeof vi.fn> } {
  const close = vi.fn(async () => {});
  return {
    start: async () => {},
    send: async () => {
      throw error;
    },
    close,
  };
}

function failingStartTransport(error: Error): Transport & { close: ReturnType<typeof vi.fn> } {
  const close = vi.fn(async () => {});
  return {
    start: async () => {
      throw error;
    },
    send: async () => {},
    close,
  };
}

function neverStartingTransport(): {
  transport: Transport;
  started: Promise<void>;
  close: ReturnType<typeof vi.fn>;
} {
  let started!: () => void;
  const close = vi.fn(async () => {});
  return {
    transport: {
      start: async () => {
        started();
        await new Promise<void>(() => {});
      },
      send: async () => {},
      close,
    },
    started: new Promise((resolve) => {
      started = resolve;
    }),
    close,
  };
}
