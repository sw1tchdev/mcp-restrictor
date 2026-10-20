import { PassThrough, type Readable, type Writable } from "node:stream";
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
  // StdioServerTransport closes on input EOF and drops in-flight requests. Hold EOF back from it
  // until the bridge has drained, so piped clients still receive their responses.
  const downstreamInput = new PassThrough();
  const forwardError = (error: Error) => downstreamInput.destroy(error);
  const forwardClose = () => {
    if (!input.readableEnded) downstreamInput.destroy();
  };
  const upstream = createUpstreamTransport(options.upstream, options.error, options.signal);
  let rejectFailure!: (error: Error) => void;
  const failure = new Promise<never>((_, reject) => {
    rejectFailure = reject;
  });
  const bridge = await bridgeTransports({
    downstream: new StdioServerTransport(downstreamInput, options.output),
    upstream,
    authorizer: options.authorizer,
    ...(options.audit ? { audit: options.audit } : {}),
    onerror: rejectFailure,
    ...(options.signal ? { signal: options.signal } : {}),
  });
  input.pipe(downstreamInput, { end: false });
  input.on("error", forwardError);
  input.once("close", forwardClose);
  const abort = () => void bridge.close();
  const end = () =>
    void delivered(downstreamInput)
      .then(() => bridge.drain())
      .then(bridge.close, rejectFailure);
  options.signal?.addEventListener("abort", abort, { once: true });
  input.once("end", end);

  try {
    if (options.signal?.aborted) await bridge.close();
    else if (input.readableEnded) {
      await delivered(downstreamInput);
      await bridge.drain().then(bridge.close);
    }
    await Promise.race([bridge.closed, failure]);
  } finally {
    options.signal?.removeEventListener("abort", abort);
    input.removeListener("end", end);
    input.removeListener("error", forwardError);
    input.removeListener("close", forwardClose);
    input.unpipe(downstreamInput);
    await bridge.close();
  }
  return upstream.exitCode ? await upstream.exitCode : 0;
}

// Resolves once everything written to the stream so far has reached its 'data' listeners.
function delivered(stream: PassThrough): Promise<void> {
  return new Promise((resolve, reject) => {
    stream.write(Buffer.alloc(0), (error) => {
      if (error) reject(error);
      else setImmediate(resolve);
    });
  });
}
