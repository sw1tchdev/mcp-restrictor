import type { IncomingMessage, ServerResponse } from "node:http";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import type { JSONRPCMessage } from "@modelcontextprotocol/server";

// The SDK rejects reuse of a stateless transport, so serve each request with a fresh one.
export async function handleStatelessRequest(
  request: IncomingMessage,
  response: ServerResponse,
  onmessage: (message: JSONRPCMessage, transport: NodeStreamableHTTPServerTransport) => void,
): Promise<void> {
  const transport = new NodeStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });
  transport.onmessage = (message) => onmessage(message, transport);
  await transport.start();
  response.once("close", () => void transport.close());
  await transport.handleRequest(request, response);
}
