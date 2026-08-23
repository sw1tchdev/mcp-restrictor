import type { Writable } from "node:stream";
import {
  startHttpGateway,
  type HttpGatewayHandle,
  type HttpGatewayRoute,
} from "@mcp-restrictor/transports";
import { loadRoutes, type RouteOwner } from "../routes.js";
import { TERMINATION_SIGNALS } from "../utils/async.js";
import { escapeControls } from "../utils/terminal.js";
import { resolveProxyRoute, type ProxyRuntimeOptions } from "./proxy.js";

export type RunRoutesOptions = ProxyRuntimeOptions & {
  home: string;
  environment: NodeJS.ProcessEnv;
  bindHostname?: "0.0.0.0";
  error?: Writable;
  startHttpGateway?: typeof startHttpGateway;
};

export async function runRoutesCommand(options: RunRoutesOptions): Promise<void> {
  const error = options.error ?? process.stderr;
  const lifetime = new AbortController();
  let operatorShutdown = false;
  let gateway: HttpGatewayHandle | undefined;
  let listenerFailure: Error | undefined;
  let bound = false;
  const shutdown = () => {
    operatorShutdown = true;
    lifetime.abort();
  };
  for (const signal of TERMINATION_SIGNALS) process.once(signal, shutdown);
  options.signal?.addEventListener("abort", shutdown, { once: true });
  if (options.signal?.aborted) shutdown();

  try {
    const stored = await loadRoutes(options.home);
    if (stored.length === 0) throw new RunRoutesError("No managed HTTP routes; run setup");
    const routes: HttpGatewayRoute[] = [];
    for (const { definition } of stored) {
      let resolved;
      try {
        const environment = Object.assign(
          Object.create(null) as NodeJS.ProcessEnv,
          options.environment,
          definition.environment.set,
        );
        resolved = await resolveProxyRoute(
          definition.proxyArgs,
          {
            signal: lifetime.signal,
            ...(options.readOAuthProfile ? { readOAuthProfile: options.readOAuthProfile } : {}),
            ...(options.createOAuthAuthProvider
              ? { createOAuthAuthProvider: options.createOAuthAuthProvider }
              : {}),
          },
          { home: options.home, environment },
        );
      } catch {
        throw new RunRoutesError(
          `Managed HTTP route preflight failed ${JSON.stringify(routeIdentity(definition.owner))}`,
        );
      }
      const route = routeIdentity(definition.owner);
      routes.push({
        path: new URL(definition.listenUrl).pathname,
        ...resolved,
        audit: (event) =>
          error.write(
            `${JSON.stringify({
              time: new Date().toISOString(),
              route,
              ...event,
              tool: escapeControls(event.tool),
            })}\n`,
          ),
        onerror: () => error.write(`${JSON.stringify({ route, error: "route request failed" })}\n`),
      });
    }
    if (lifetime.signal.aborted) {
      process.exitCode = 0;
      return;
    }

    const first = stored[0]!.definition;
    const firstUrl = new URL(first.listenUrl);
    const listen = first.listenUrl.slice(0, first.listenUrl.length - firstUrl.pathname.length);
    const startGateway = options.startHttpGateway ?? startHttpGateway;
    try {
      gateway = await startGateway({
        listen,
        ...(options.bindHostname ? { bindHostname: options.bindHostname } : {}),
        routes,
        signal: lifetime.signal,
        onerror: (failure) => {
          listenerFailure ??= failure;
          lifetime.abort();
        },
      });
      bound = true;
    } catch (failure) {
      listenerFailure ??= asError(failure);
      throw listenerError(listenerFailure);
    }

    for (const { definition } of stored) {
      error.write(
        `mcp-restrictor listening ${definition.listenUrl} ${JSON.stringify({ route: routeIdentity(definition.owner) })}\n`,
      );
    }
    await gateway.closed;
    if (listenerFailure) throw listenerError(listenerFailure);
    process.exitCode = 0;
  } catch (failure) {
    if (operatorShutdown && !listenerFailure) {
      process.exitCode = 0;
      return;
    }
    process.exitCode = 1;
    if (failure instanceof RunRoutesError) throw failure;
    throw new RunRoutesError(
      bound ? "Managed HTTP route listener failed" : "Managed HTTP route preflight failed",
    );
  } finally {
    for (const signal of TERMINATION_SIGNALS) process.removeListener(signal, shutdown);
    options.signal?.removeEventListener("abort", shutdown);
    lifetime.abort();
    if (gateway) {
      try {
        await gateway.close();
        await gateway.closed;
      } catch {
        process.exitCode = 1;
        throw new RunRoutesError("Managed HTTP route shutdown failed");
      }
    }
  }
}

function routeIdentity(owner: RouteOwner): Pick<RouteOwner, "adapterId" | "scope" | "serverName"> {
  return {
    adapterId: owner.adapterId,
    scope: owner.scope,
    serverName: escapeControls(owner.serverName),
  };
}

function listenerError(failure: Error): RunRoutesError {
  return new RunRoutesError(
    (failure as NodeJS.ErrnoException).code === "EADDRINUSE"
      ? "Managed HTTP route listener is already in use"
      : "Managed HTTP route listener failed",
  );
}

function asError(value: unknown): Error {
  return value instanceof Error ? value : new Error(String(value));
}

class RunRoutesError extends Error {}
