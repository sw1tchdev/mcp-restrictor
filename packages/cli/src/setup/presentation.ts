import { basename, join } from "node:path";
import type { UpstreamConfig } from "@mcp-restrictor/transports";
import type { ClientAdapter } from "../client-adapter.js";
import { MASTER_KEY_FILE_ENV } from "../oauth/storage.js";
import { escapeControls } from "../utils/terminal.js";
import type { ServerCandidate, SourceSpec, UnsupportedServer } from "./wrapper.js";

export { escapeControls };

type CandidateEntry = { adapter: ClientAdapter; server: ServerCandidate };
type UnsupportedEntry = { adapter: ClientAdapter; server: UnsupportedServer };
type PreviewTarget = {
  source: SourceSpec;
  upstream: UpstreamConfig;
  oauth?: ServerCandidate["oauth"];
  wrapperEnvironment: { env?: Record<string, string> };
};

export function previewEndpoint(server: PreviewTarget, write: (value: string) => void): void {
  const { source } = server;
  if (source.kind === "stdio") {
    const command = server.upstream.kind === "stdio" ? server.upstream.command : source.command;
    write(
      `Upstream: transport=stdio command=${quoted(command)} environment=${JSON.stringify(source.envNames)}\n`,
    );
    return;
  }
  const auth =
    source.kind !== "websocket" && source.oauthProfileId
      ? "oauth (managed)"
      : server.oauth
        ? `oauth (${server.oauth.mode})`
        : source.kind !== "websocket" && source.bearerTokenEnvVar
          ? "bearer"
          : source.headers.some(({ name }) => name.toLowerCase() === "authorization")
            ? "header"
            : "none";
  write(
    `Upstream: transport=${source.kind} endpoint=${quoted(redactedUrl(server.upstream.kind === source.kind ? server.upstream.url : source.url))} auth=${auth}\n`,
  );
  if (source.kind !== "websocket" && source.bearerTokenEnvVar) {
    write(`Bearer token from ${quoted(source.bearerTokenEnvVar)}\n`);
  }
  for (const mapping of source.headers) {
    const literal =
      server.wrapperEnvironment.env &&
      Object.hasOwn(server.wrapperEnvironment.env, mapping.environmentVariable);
    write(
      `Header: ${quoted(mapping.name)} from ${literal ? "client literal" : quoted(mapping.environmentVariable)}\n`,
    );
  }
  if (
    (server.oauth || (source.kind !== "websocket" && source.oauthProfileId)) &&
    server.wrapperEnvironment.env &&
    Object.hasOwn(server.wrapperEnvironment.env, MASTER_KEY_FILE_ENV)
  ) {
    write(`OAuth master key file from ${quoted(MASTER_KEY_FILE_ENV)}\n`);
  }
  if (server.oauth) {
    for (const [label, value] of [
      ["resource", server.oauth.resource],
      ["resource metadata", server.oauth.resourceMetadataUrl],
      ["authorization metadata", server.oauth.authServerMetadataUrl],
      ["callback", server.oauth.callback.url],
    ] as const) {
      if (value) write(`${label}: ${quoted(redactedUrl(value))}\n`);
    }
    if (!server.oauth.callback.url) {
      write(
        `callback strategy: ${server.oauth.callback.host}${server.oauth.callback.path}${server.oauth.callback.port === undefined ? "" : ` port=${server.oauth.callback.port}`}\n`,
      );
    }
  }
}

export function compareCandidates(left: CandidateEntry, right: CandidateEntry): number {
  return (
    compareStrings(left.adapter.label, right.adapter.label) ||
    compareScopeAndName(left.server, right.server)
  );
}

export function compareUnsupported(left: UnsupportedEntry, right: UnsupportedEntry): number {
  return (
    compareStrings(left.adapter.label, right.adapter.label) ||
    compareScopeAndName(left.server, right.server)
  );
}

function compareScopeAndName(
  left: { scope: "user" | "project"; name: string; configPath: string },
  right: { scope: "user" | "project"; name: string; configPath: string },
): number {
  const scope = Number(left.scope === "project") - Number(right.scope === "project");
  if (scope) return scope;
  const name = compareStrings(left.name, right.name);
  return name || compareStrings(left.configPath, right.configPath);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function quoted(value: string): string {
  return JSON.stringify(value);
}

export function displayServerName(value: string): string {
  return /^[A-Za-z0-9._ -]+$/.test(value) ? value : quoted(value);
}

export function terminalSafeError(error: unknown): Error {
  if (error instanceof AggregateError) {
    return new AggregateError(error.errors.map(terminalSafeError), escapeControls(error.message));
  }
  if (!(error instanceof Error)) return new Error("Setup failed");
  const safe = new Error(escapeControls(error.message));
  safe.name = error.name;
  return safe;
}

export function redactedUrl(value: string): string {
  try {
    const url = new URL(value);
    for (const name of new Set(url.searchParams.keys())) {
      url.searchParams.set(name, "REDACTED");
    }
    return url.href;
  } catch {
    return value;
  }
}

export function renderSetupCompletion(options: {
  write(value: string): void;
  visibleWrites: readonly { path: string; before?: unknown; backupKey: string }[];
  writes: readonly { backupKey: string }[];
  backupDirectories: readonly string[];
  adapters: readonly ClientAdapter[];
  projectRoot: string;
  hasHttpRoutes?: boolean;
}): void {
  options.write("Setup complete.\n");
  for (const { path } of options.visibleWrites) options.write(`Changed: ${quoted(path)}\n`);
  const backupKeys = [...new Set(options.writes.map(({ backupKey }) => backupKey))];
  for (const [index, directory] of options.backupDirectories.entries()) {
    options.write(`Backup directory: ${quoted(directory)}\n`);
    const backupKey = backupKeys[index];
    for (const write of options.visibleWrites) {
      if (write.backupKey !== backupKey) continue;
      if (!write.before) {
        options.write(`Remove newly created file ${quoted(write.path)}\n`);
        continue;
      }
      options.write(
        `Restore ${quoted(write.path)} from ${quoted(join(directory, basename(write.path)))}\n`,
      );
    }
  }
  for (const adapter of options.adapters) {
    for (const message of adapter.completionMessage?.({ projectRoot: options.projectRoot }) ?? []) {
      options.write(`${message}\n`);
    }
  }
  if (options.hasHttpRoutes) {
    options.write("Start HTTP routes: mcp-restrictor run\n");
    options.write("Restart mcp-restrictor run after Setup or Restore changes.\n");
  }
}
