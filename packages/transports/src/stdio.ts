import type { Readable, Writable } from "node:stream";
import type { AuditEvent, ToolAuthorizer } from "@mcp-restrictor/core";
import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { bridgeTransports } from "./bridge.js";
import { createUpstreamTransport, type UpstreamConfig } from "./upstream.js";

export type StdioProxyOptions = {
  upstream: UpstreamConfig;
  authorizer: ToolAuthorizer;
  audit?: (event: AuditEvent) => void;
  input?: Readable;
  output?: Writable;
  error?: Writable;
  signal?: AbortSignal;
};

export async function runStdioProxy(options: StdioProxyOptions): Promise<number> {
  const input = options.input ?? process.stdin;
  const upstream = createUpstreamTransport(options.upstream, options.error, options.signal);
  let rejectFailure!: (error: Error) => void;
  const failure = new Promise<never>((_, reject) => {
    rejectFailure = reject;
  });
  const bridge = await bridgeTransports({
    downstream: new StdioServerTransport(input, options.output),
    upstream,
    authorizer: options.authorizer,
    ...(options.audit ? { audit: options.audit } : {}),
    onerror: rejectFailure,
    ...(options.signal ? { signal: options.signal } : {}),
  });
  const abort = () => void bridge.close();
  const end = () => void bridge.drain().then(bridge.close, rejectFailure);
  options.signal?.addEventListener("abort", abort, { once: true });
  input.once("end", end);

  try {
    if (options.signal?.aborted) await bridge.close();
    else if (input.readableEnded) await bridge.drain().then(bridge.close);
    await Promise.race([bridge.closed, failure]);
  } finally {
    options.signal?.removeEventListener("abort", abort);
    input.removeListener("end", end);
    await bridge.close();
  }
  return upstream.exitCode ? await upstream.exitCode : 0;
}
