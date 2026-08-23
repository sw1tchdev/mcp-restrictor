export type Decision = { allowed: boolean; reason?: string };

export interface ToolAuthorizer {
  discover(name: string): boolean;
  authorize(name: string, arguments_: Record<string, unknown>): Decision | Promise<Decision>;
}

export type AuditEvent = {
  action: "tool.call";
  tool: string;
  decision: "ALLOW" | "DENY";
  reason?: string;
};

export type ClientLineResult = { forward?: string; response?: string };

type JsonRpcMessage = Record<string, unknown> & { jsonrpc: "2.0" };

export class MessageFilter {
  readonly #pendingRequests = new Map<string, string>();

  constructor(
    private readonly authorizer: ToolAuthorizer,
    private readonly audit: (event: AuditEvent) => void = () => {},
  ) {}

  async handleClientLine(line: string): Promise<ClientLineResult> {
    const message = parseMessage(line);
    const method = typeof message.method === "string" ? message.method : undefined;
    const key = method === undefined ? undefined : idKey(message.id);
    if (key && this.#pendingRequests.has(key)) {
      return {
        response: errorResponse(message.id, -32600, "Duplicate request id"),
      };
    }
    if (key && method !== undefined) this.#pendingRequests.set(key, method);

    if (method === "tools/list") return { forward: line };

    if (method !== "tools/call") return { forward: line };

    const request = toolCall(message);
    if (!request) {
      if (key) this.#pendingRequests.delete(key);
      return hasRequestId(message)
        ? { response: errorResponse(message.id, -32602, "Invalid tools/call params") }
        : {};
    }

    let decision: Decision;
    try {
      decision = await this.authorizer.authorize(request.name, request.arguments);
    } catch (error) {
      if (key) this.#pendingRequests.delete(key);
      throw error;
    }
    this.audit(
      decision.reason
        ? {
            action: "tool.call",
            tool: request.name,
            decision: decision.allowed ? "ALLOW" : "DENY",
            reason: decision.reason,
          }
        : {
            action: "tool.call",
            tool: request.name,
            decision: decision.allowed ? "ALLOW" : "DENY",
          },
    );

    if (decision.allowed) return { forward: line };
    if (key) this.#pendingRequests.delete(key);
    if (!hasRequestId(message)) return {};

    return {
      response: errorResponse(
        message.id,
        -32001,
        "MCP tool call denied",
        decision.reason ?? "policy denied the call",
      ),
    };
  }

  async handleUpstreamLine(line: string): Promise<string> {
    const message = parseMessage(line);
    if (typeof message.method === "string") return line;
    const key = idKey(message.id);
    const method = key ? this.#pendingRequests.get(key) : undefined;
    if (!key || !method) return line;
    this.#pendingRequests.delete(key);
    if (method !== "tools/list" || "error" in message) return line;

    if (!isRecord(message.result) || !Array.isArray(message.result.tools)) {
      throw new Error("Invalid tools/list response");
    }

    return JSON.stringify({
      ...message,
      result: {
        ...message.result,
        tools: message.result.tools.filter(
          (tool) =>
            isRecord(tool) && typeof tool.name === "string" && this.authorizer.discover(tool.name),
        ),
      },
    });
  }
}

function parseMessage(line: string): JsonRpcMessage {
  try {
    const message: unknown = JSON.parse(line);
    if (!isRecord(message) || message.jsonrpc !== "2.0") throw new Error();
    return message as JsonRpcMessage;
  } catch {
    throw new Error("Invalid JSON-RPC message");
  }
}

function toolCall(
  message: JsonRpcMessage,
): { name: string; arguments: Record<string, unknown> } | undefined {
  if (!isRecord(message.params) || typeof message.params.name !== "string") {
    return undefined;
  }

  const arguments_ = message.params.arguments;
  if (arguments_ !== undefined && !isRecord(arguments_)) return undefined;

  return {
    name: message.params.name,
    arguments: arguments_ ?? {},
  };
}

function errorResponse(id: unknown, code: number, message: string, reason?: string): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: isJsonRpcId(id) ? id : null,
    error: reason ? { code, message, data: { reason } } : { code, message },
  });
}

function hasRequestId(message: JsonRpcMessage): boolean {
  return Object.hasOwn(message, "id") && isJsonRpcId(message.id);
}

function idKey(id: unknown): string | undefined {
  return isJsonRpcId(id) ? `${typeof id}:${String(id)}` : undefined;
}

function isJsonRpcId(value: unknown): value is string | number {
  return typeof value === "string" || typeof value === "number";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
