import { MessageFilter, type AuditEvent, type ToolAuthorizer } from "@mcp-restrictor/core";
import type { JSONRPCMessage, RequestId, Transport } from "@modelcontextprotocol/server";
import { redactUpstreamError } from "./remote.js";
import { asError, isAbortError, isRecord, raceWithAbort } from "./utils.js";

export type TransportBridgeOptions = {
  downstream: Transport;
  upstream: Transport;
  authorizer: ToolAuthorizer;
  audit?: (event: AuditEvent) => void;
  onerror?: (error: Error) => void;
  signal?: AbortSignal;
};

export type TransportBridge = {
  close(): Promise<void>;
  drain(): Promise<void>;
  readonly closed: Promise<void>;
};

export async function bridgeTransports(options: TransportBridgeOptions): Promise<TransportBridge> {
  const { downstream, upstream } = options;
  const filter = new MessageFilter(options.authorizer, options.audit);
  const initializeRequests = new Set<string>();
  const jobs = new Set<Promise<void>>();
  const pendingResponses = new Map<string, Deferred>();
  let closing: Promise<void> | undefined;
  let failure: Error | undefined;
  let resolveClosed!: () => void;
  const closed = new Promise<void>((resolve) => {
    resolveClosed = resolve;
  });
  const close = (): Promise<void> => {
    if (!closing) {
      closing = closed;
      void Promise.allSettled([downstream.close(), upstream.close()]).then(() => resolveClosed());
    }
    return closing;
  };
  const fail = (error: Error): void => {
    failure ??= error;
    options.onerror?.(error);
    void close();
  };
  const upstreamFail = (cause: unknown): void => fail(redactUpstreamError("request", cause));
  const downstreamFail = (cause: unknown): void => fail(asError(cause));
  const run = (work: () => Promise<void>, onFailure: (cause: unknown) => void): void => {
    const job = work()
      .catch(onFailure)
      .finally(() => jobs.delete(job));
    jobs.add(job);
  };
  const drain = async (): Promise<void> => {
    while (!closing && (jobs.size > 0 || pendingResponses.size > 0)) {
      await Promise.race([
        closed,
        Promise.allSettled([
          ...jobs,
          ...[...pendingResponses.values()].map(({ promise }) => promise),
        ]),
      ]);
    }
    if (failure) throw failure;
  };

  downstream.onmessage = (message) => {
    run(async () => {
      const result = await filter.handleClientLine(JSON.stringify(message));
      const id = requestId(message);
      if (result.forward) {
        if (id !== undefined) {
          pendingResponses.set(idKey(id), deferred(id));
          if (messageMethod(message) === "initialize") {
            initializeRequests.add(idKey(id));
          }
        }
        try {
          await upstream.send(JSON.parse(result.forward) as JSONRPCMessage);
        } catch (error) {
          upstreamFail(error);
          return;
        }
      }
      if (result.response) {
        await downstream.send(JSON.parse(result.response) as JSONRPCMessage, {
          relatedRequestId: id,
        });
      }
    }, downstreamFail);
  };

  upstream.onmessage = (message) => {
    run(async () => {
      const id = responseId(message);
      if (id !== undefined && initializeRequests.delete(idKey(id))) {
        const version = protocolVersion(message);
        if (version) {
          upstream.setProtocolVersion?.(version);
          try {
            downstream.setProtocolVersion?.(version);
          } catch (error) {
            downstreamFail(error);
            return;
          }
        }
      }
      const filtered = await filter.handleUpstreamLine(JSON.stringify(message));
      const relatedRequestId = id ?? solePendingRequestId(pendingResponses);
      try {
        await downstream.send(JSON.parse(filtered) as JSONRPCMessage, {
          relatedRequestId,
        });
      } catch (error) {
        downstreamFail(error);
        return;
      }
      if (id !== undefined) {
        const pending = pendingResponses.get(idKey(id));
        pendingResponses.delete(idKey(id));
        pending?.resolve();
      }
    }, upstreamFail);
  };

  downstream.onerror = downstreamFail;
  upstream.onerror = upstreamFail;
  downstream.onclose = () => void close();
  upstream.onclose = () => void close();
  const abort = () => void close();
  options.signal?.addEventListener("abort", abort, { once: true });
  void closed.then(() => options.signal?.removeEventListener("abort", abort));

  try {
    await raceWithAbort(upstream.start(), options.signal);
  } catch (error) {
    await close();
    throw isAbortError(error) ? error : redactUpstreamError("connect", error);
  }
  try {
    await raceWithAbort(downstream.start(), options.signal);
  } catch (error) {
    await close();
    throw isAbortError(error) ? error : asError(error);
  }

  return { close, drain, closed };
}

function requestId(message: JSONRPCMessage): RequestId | undefined {
  return "method" in message && "id" in message ? message.id : undefined;
}

function responseId(message: JSONRPCMessage): RequestId | undefined {
  return !("method" in message) && "id" in message ? message.id : undefined;
}

function messageMethod(message: JSONRPCMessage): string | undefined {
  return "method" in message ? message.method : undefined;
}

function protocolVersion(message: JSONRPCMessage): string | undefined {
  if (!("result" in message) || !isRecord(message.result)) return undefined;
  return typeof message.result.protocolVersion === "string"
    ? message.result.protocolVersion
    : undefined;
}

function idKey(id: RequestId): string {
  return `${typeof id}:${String(id)}`;
}

type Deferred = {
  id: RequestId;
  promise: Promise<void>;
  resolve: () => void;
};

function deferred(id: RequestId): Deferred {
  let resolve!: () => void;
  const promise = new Promise<void>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { id, promise, resolve };
}

function solePendingRequestId(pending: Map<string, Deferred>): RequestId | undefined {
  return pending.size === 1 ? pending.values().next().value?.id : undefined;
}
