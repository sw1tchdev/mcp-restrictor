import { Client } from "@modelcontextprotocol/client";
import { createRequire } from "node:module";
import type { Writable } from "node:stream";
import { redactUpstreamError } from "./remote.js";
import { createUpstreamTransport, type UpstreamConfig } from "./upstream.js";
import { abortError, isAbortError, raceWithAbort } from "./utils.js";

const packageVersion = (createRequire(import.meta.url)("../package.json") as { version: string })
  .version;

export async function discoverToolNames(
  upstream: UpstreamConfig,
  options: {
    signal?: AbortSignal;
    stderr?: Writable;
    preserveError?: (error: unknown) => boolean;
  } = {},
): Promise<string[]> {
  const client = new Client({ name: "mcp-restrictor-setup", version: packageVersion });
  const transport = createUpstreamTransport(upstream, options.stderr, options.signal);
  const requestOptions = options.signal ? { signal: options.signal } : undefined;
  const localErrors = new WeakSet<Error>();
  const preserveError =
    options.preserveError ?? ((error: unknown) => error instanceof Error && localErrors.has(error));
  const abort = () => void transport.close().catch(() => {});
  options.signal?.addEventListener("abort", abort, { once: true });
  let failed = false;
  let failure: unknown;
  let result: string[] = [];

  try {
    if (options.signal?.aborted) throw abortError();
    await raceWithAbort(client.connect(transport, requestOptions), options.signal);
    const { tools } = await raceWithAbort(
      client.listTools(undefined, requestOptions),
      options.signal,
    );
    const names = new Set<string>();
    for (const { name } of tools) {
      if (names.has(name)) {
        const duplicate = new Error(`Duplicate tool name ${name}`);
        localErrors.add(duplicate);
        throw duplicate;
      }
      names.add(name);
    }
    result = [...names].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  } catch (error) {
    failed = true;
    failure =
      isAbortError(error) || preserveError(error) ? error : redactUpstreamError("discovery", error);
  } finally {
    options.signal?.removeEventListener("abort", abort);
  }

  try {
    await client.close();
  } catch (closeError) {
    if (failed) {
      throw new AggregateError([failure, closeError], "Tool discovery and cleanup failed", {
        cause: failure,
      });
    }
    throw closeError;
  }
  if (failed) throw failure;
  return result;
}
