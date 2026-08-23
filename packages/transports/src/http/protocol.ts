import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import {
  isInitializeRequest,
  type InboundLadderRejection,
  type InboundModernRoute,
  type JSONRPCMessage,
} from "@modelcontextprotocol/server";
import { isRecord, MAX_MCP_MESSAGE_BYTES } from "../utils.js";

export const noBody = Symbol("no body");

export async function readJsonBody(
  request: IncomingMessage,
  response: ServerResponse,
): Promise<unknown | typeof noBody> {
  const chunks: Buffer[] = [];
  let size = 0;
  let tooLarge = false;
  for await (const value of request) {
    const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value as string);
    size += chunk.length;
    if (size > MAX_MCP_MESSAGE_BYTES) tooLarge = true;
    else chunks.push(chunk);
  }
  if (tooLarge) {
    response.writeHead(413).end("Request body is too large");
    return noBody;
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
  } catch {
    response.writeHead(400).end("Invalid JSON body");
    return noBody;
  }
}

export function isInitializationBody(body: unknown): boolean {
  const message = Array.isArray(body) ? (body.length === 1 ? body[0] : undefined) : body;
  return isRecord(message) && isInitializeRequest(message as JSONRPCMessage);
}

export function singleHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value.join(",") : value;
}

export function validateStandardHeaders(
  route: InboundModernRoute,
  methodHeader: string | undefined,
  nameHeader: string | undefined,
): InboundLadderRejection | undefined {
  // ponytail: the pinned SDK keeps this gate private; delete this copy when public.
  if (route.messageKind !== "request") return;
  const method = route.message.method;
  if (methodHeader === undefined) {
    return headerMismatch(
      "method-header-missing",
      "(missing)",
      `the body names method ${method} but the required Mcp-Method header is absent`,
    );
  }
  const sourceField =
    method === "tools/call" || method === "prompts/get"
      ? "name"
      : method === "resources/read"
        ? "uri"
        : undefined;
  if (!sourceField) return;
  const params = isRecord(route.message.params) ? route.message.params : undefined;
  const sourceValue = params?.[sourceField];
  const bodyValue = typeof sourceValue === "string" ? sourceValue : undefined;
  if (nameHeader === undefined) {
    return bodyValue === undefined
      ? undefined
      : headerMismatch(
          "name-header-missing",
          "(missing)",
          `the body carries params.${sourceField}="${bodyValue}" but the required Mcp-Name header is absent`,
        );
  }
  const normalized = nameHeader.replace(/^[ \t]+|[ \t]+$/g, "");
  const decoded = decodeMcpHeader(normalized);
  if (decoded === undefined) {
    return headerMismatch(
      "name-header-invalid-encoding",
      normalized,
      "the Mcp-Name header carries an invalid Base64 sentinel value",
    );
  }
  return bodyValue !== undefined && decoded !== bodyValue
    ? headerMismatch(
        "name-header-mismatch",
        normalized,
        `the body carries params.${sourceField}="${bodyValue}" but the Mcp-Name header names "${decoded}"`,
      )
    : undefined;
}

export function writeClassificationError(
  response: ServerResponse,
  rejection: InboundLadderRejection,
  body: unknown,
): void {
  writeJsonRpcError(
    response,
    rejection.httpStatus,
    rejection.code,
    rejection.message,
    requestId(body),
    rejection.data,
  );
}

export function writeJsonRpcError(
  response: ServerResponse,
  status: number,
  code: number,
  message: string,
  id: string | number | null,
  data?: unknown,
): void {
  response.writeHead(status, { "content-type": "application/json" }).end(
    JSON.stringify({
      jsonrpc: "2.0",
      id,
      error: { code, message, ...(data === undefined ? {} : { data }) },
    }),
  );
}

export function requestId(body: unknown): string | number | null {
  if (!isRecord(body) || typeof body.method !== "string") return null;
  return typeof body.id === "string" || typeof body.id === "number" ? body.id : null;
}

export async function writeWebResponse(
  webResponse: Response,
  response: ServerResponse,
): Promise<void> {
  response.writeHead(webResponse.status, Object.fromEntries(webResponse.headers.entries()));
  if (!webResponse.body) {
    response.end();
    return;
  }
  await pipeline(
    Readable.fromWeb(webResponse.body as import("node:stream/web").ReadableStream),
    response,
  );
}

function decodeMcpHeader(value: string): string | undefined {
  if (!value.startsWith("=?base64?") || !value.endsWith("?=")) return value;
  const base64 = value.slice(9, -2);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64)) {
    return;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(base64, "base64"));
  } catch {
    return;
  }
}

function headerMismatch(cell: string, header: string, body: string): InboundLadderRejection {
  return {
    kind: "reject",
    rung: "standard-header-validation",
    cell,
    httpStatus: 400,
    code: -32020,
    message: `Bad Request: the request headers and body disagree: ${body}`,
    data: { mismatch: { header, body } },
    settled: true,
  };
}
