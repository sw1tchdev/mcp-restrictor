import { describe, expect, test } from "vitest";
import { MessageFilter, type ToolAuthorizer } from "../src/index.ts";

const authorizer: ToolAuthorizer = {
  discover: (name) => name !== "delete_file",
  authorize: (name) =>
    name === "read_file"
      ? { allowed: true }
      : { allowed: false, reason: "not allowed by test policy" },
};

describe("MessageFilter", () => {
  test("filters tools/list responses using the matching request ID", async () => {
    const filter = new MessageFilter(authorizer);
    const request = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}';

    expect(await filter.handleClientLine(request)).toEqual({ forward: request });

    const result = await filter.handleUpstreamLine(
      '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"safe"},{"name":"delete_file","description":"unsafe"}],"nextCursor":"page-2"}}',
    );

    expect(JSON.parse(result)).toEqual({
      jsonrpc: "2.0",
      id: 1,
      result: {
        tools: [{ name: "read_file", description: "safe" }],
        nextCursor: "page-2",
      },
    });
  });

  test("keeps numeric and string request IDs distinct", async () => {
    const filter = new MessageFilter(authorizer);
    await filter.handleClientLine('{"jsonrpc":"2.0","id":1,"method":"tools/list"}');
    await filter.handleClientLine('{"jsonrpc":"2.0","id":"1","method":"tools/list"}');

    const stringResult = JSON.parse(
      await filter.handleUpstreamLine(
        '{"jsonrpc":"2.0","id":"1","result":{"tools":[{"name":"delete_file"}]}}',
      ),
    );
    const numberResult = JSON.parse(
      await filter.handleUpstreamLine(
        '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_file"}]}}',
      ),
    );

    expect(stringResult.result.tools).toEqual([]);
    expect(numberResult.result.tools).toEqual([]);
  });

  test("rejects duplicate outstanding IDs across methods", async () => {
    const filter = new MessageFilter(authorizer);
    await filter.handleClientLine('{"jsonrpc":"2.0","id":1,"method":"tools/list"}');
    const duplicate = await filter.handleClientLine('{"jsonrpc":"2.0","id":1,"method":"ping"}');

    expect(duplicate.forward).toBeUndefined();
    expect(JSON.parse(duplicate.response ?? "")).toMatchObject({
      id: 1,
      error: { code: -32600 },
    });
    const result = JSON.parse(
      await filter.handleUpstreamLine(
        '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_file"}]}}',
      ),
    );

    expect(result.result.tools).toEqual([]);
  });

  test("reserves a tools/call ID while authorization is pending", async () => {
    let allow!: () => void;
    const gate = new Promise<void>((resolve) => {
      allow = resolve;
    });
    const filter = new MessageFilter({
      discover: () => true,
      authorize: async () => {
        await gate;
        return { allowed: true };
      },
    });
    const first = filter.handleClientLine(
      '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}',
    );

    const duplicate = await filter.handleClientLine('{"jsonrpc":"2.0","id":1,"method":"ping"}');
    allow();

    expect(JSON.parse(duplicate.response ?? "")).toMatchObject({
      error: { code: -32600 },
    });
    await expect(first).resolves.toHaveProperty("forward");
  });

  test("preserves MCP 2026 list metadata while filtering tools", async () => {
    const filter = new MessageFilter(authorizer);
    await filter.handleClientLine(
      JSON.stringify({
        jsonrpc: "2.0",
        id: "modern-list",
        method: "tools/list",
        params: { _meta: { protocolVersion: "2026-07-28" } },
      }),
    );

    const result = JSON.parse(
      await filter.handleUpstreamLine(
        JSON.stringify({
          jsonrpc: "2.0",
          id: "modern-list",
          result: {
            resultType: "complete",
            tools: [{ name: "read_file" }, { name: "delete_file" }],
            ttlMs: 5000,
            cacheScope: "private",
          },
        }),
      ),
    );

    expect(result.result).toEqual({
      resultType: "complete",
      tools: [{ name: "read_file" }],
      ttlMs: 5000,
      cacheScope: "private",
    });
  });

  test("does not confuse an upstream request ID with a tools/list response ID", async () => {
    const filter = new MessageFilter(authorizer);
    await filter.handleClientLine('{"jsonrpc":"2.0","id":1,"method":"tools/list"}');
    const upstreamRequest =
      '{"jsonrpc":"2.0","id":1,"method":"sampling/createMessage","params":{}}';

    expect(await filter.handleUpstreamLine(upstreamRequest)).toBe(upstreamRequest);
    const response = JSON.parse(
      await filter.handleUpstreamLine(
        '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"delete_file"}]}}',
      ),
    );
    expect(response.result.tools).toEqual([]);
  });

  test("blocks a direct unauthorized tools/call with its original ID", async () => {
    const filter = new MessageFilter(authorizer);
    const result = await filter.handleClientLine(
      '{"jsonrpc":"2.0","id":"blocked","method":"tools/call","params":{"name":"delete_file","arguments":{}}}',
    );

    expect(result.forward).toBeUndefined();
    expect(JSON.parse(result.response ?? "")).toEqual({
      jsonrpc: "2.0",
      id: "blocked",
      error: {
        code: -32001,
        message: "MCP tool call denied",
        data: { reason: "not allowed by test policy" },
      },
    });
  });

  test("preserves an authorized tools/call byte for byte", async () => {
    const filter = new MessageFilter(authorizer);
    const line =
      '{"jsonrpc":"2.0", "id":2, "method":"tools/call", "params":{"name":"read_file","arguments":{"path":"/workspace/a.txt"}}}';

    expect(await filter.handleClientLine(line)).toEqual({ forward: line });
  });

  test("returns invalid params without forwarding a malformed tools/call", async () => {
    const filter = new MessageFilter(authorizer);
    const result = await filter.handleClientLine(
      '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":42}}',
    );

    expect(result.forward).toBeUndefined();
    expect(JSON.parse(result.response ?? "")).toMatchObject({
      id: 3,
      error: { code: -32602 },
    });
  });

  test("rejects malformed or non-object JSON-RPC messages", async () => {
    const filter = new MessageFilter(authorizer);

    await expect(filter.handleClientLine("{")).rejects.toThrow("Invalid JSON-RPC message");
    await expect(filter.handleUpstreamLine("[]")).rejects.toThrow("Invalid JSON-RPC message");
  });
});
