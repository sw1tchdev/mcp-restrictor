import { dirname, isAbsolute, resolve } from "node:path";
import {
  createStdioEnvironment,
  resolveHeaderEnvironment,
  type UpstreamConfig,
} from "@mcp-restrictor/transports";
import type {
  ClientAdapterHost,
  ClientResolutionDependency,
  ClientResolveContext,
  ClientResolveResult,
} from "../../client-adapter.js";
import { MASTER_KEY_FILE_ENV } from "../../oauth/storage.js";
import { defineOwn, isRecord } from "../../utils/values.js";
import type { FileSnapshot } from "../transaction.js";
import type { ParsedConfig, Scope, ServerCandidate, UnsupportedServer } from "../wrapper.js";
import { parseLocalEntry } from "./local.js";
import { parseRemoteEntry } from "./remote.js";
import { parseDeferred, stringRecord, stringValue, type DeferredValue } from "./values.js";

export const openCodeShadowed = "shadowed by a higher-precedence OpenCode configuration";

const unsupportedEntry = "OpenCode MCP entry is not supported yet";
const disabled = "disabled server is not supported";

export type OpenCodeSchema = "v1" | "v2";

export type EntryOptions = {
  path: string;
  scope: Scope;
  projectRoot?: string;
  environment?: NodeJS.ProcessEnv;
};

export async function resolveOpenCodeCandidate(
  candidate: ServerCandidate,
  context: ClientResolveContext,
  host: ClientAdapterHost,
): Promise<ClientResolveResult> {
  const environmentValues = new Map<string, string>();
  const fileValues = new Map<string, Promise<FileSnapshot>>();
  const dependencies: ClientResolutionDependency[] = [];
  const read = async (deferred: DeferredValue): Promise<string> => {
    if (deferred.kind === "literal") return deferred.value;
    if (deferred.kind === "environment") {
      if (!environmentValues.has(deferred.name)) {
        if (!Object.hasOwn(context.environment, deferred.name)) {
          throw new Error("OpenCode environment substitution is missing");
        }
        const value = context.environment[deferred.name];
        if (typeof value !== "string") {
          throw new Error("OpenCode environment substitution is missing");
        }
        environmentValues.set(deferred.name, value);
        dependencies.push({ kind: "environment", name: deferred.name, value });
      }
      return environmentValues.get(deferred.name)!;
    }
    const path = resolve(dirname(candidate.configPath), deferred.path);
    if (!fileValues.has(path)) {
      fileValues.set(
        path,
        host.readSecretFile(path).then((snapshot) => {
          dependencies.push({ kind: "file", snapshot });
          return snapshot;
        }),
      );
    }
    return (await fileValues.get(path)!).content;
  };
  if (candidate.source.kind !== "stdio" || candidate.upstream.kind !== "stdio") {
    if (candidate.source.kind === "stdio" || candidate.upstream.kind !== candidate.source.kind)
      return { candidate, dependencies: [] };
    const configured = candidate.wrapperEnvironment.env ?? {};
    const effectiveEnvironment: Record<string, string> = {};
    for (const mapping of candidate.source.headers) {
      if (!Object.hasOwn(configured, mapping.environmentVariable)) {
        throw new Error("OpenCode header substitution is missing");
      }
      defineOwn(
        effectiveEnvironment,
        mapping.environmentVariable,
        await read(parseDeferred(configured[mapping.environmentVariable]!)),
      );
    }
    const headers = resolveHeaderEnvironment(candidate.source.headers, effectiveEnvironment);
    if (candidate.source.kind === "websocket") {
      return {
        candidate: {
          ...candidate,
          upstream: {
            kind: "websocket",
            url: candidate.source.url,
            ...(headers.length ? { headers } : {}),
          },
        },
        dependencies,
      };
    }
    const bearerToken =
      candidate.source.bearerTokenEnvVar === undefined
        ? undefined
        : await read(parseDeferred(configured[candidate.source.bearerTokenEnvVar]!));
    if (candidate.source.bearerTokenEnvVar !== undefined && !bearerToken) {
      throw new Error("OpenCode bearer token is missing");
    }
    let oauth = candidate.oauth;
    if (oauth) {
      const raw = isRecord(candidate.original.oauth) ? candidate.original.oauth : {};
      const rawClientId = oauth.clientId;
      const rawClientSecret = stringValue(raw, "clientSecret") ?? stringValue(raw, "client_secret");
      const clientId =
        rawClientId === undefined ? undefined : await read(parseDeferred(rawClientId));
      const clientSecret =
        rawClientSecret === undefined ? undefined : await read(parseDeferred(rawClientSecret));
      if (clientId !== undefined && !clientId) throw new Error("Invalid OAuth client ID");
      if (clientSecret !== undefined && !clientSecret)
        throw new Error("Invalid OAuth client secret");
      oauth = {
        ...oauth,
        ...(clientId === undefined ? {} : { clientId }),
        ...(clientSecret === undefined ? {} : { clientSecret }),
      };
    }
    let wrapperEnvironment = candidate.wrapperEnvironment;
    if (oauth && Object.hasOwn(configured, MASTER_KEY_FILE_ENV)) {
      wrapperEnvironment = {
        env: {
          ...configured,
          [MASTER_KEY_FILE_ENV]: await read(parseDeferred(configured[MASTER_KEY_FILE_ENV]!)),
        },
      };
    }
    return {
      candidate: {
        ...candidate,
        upstream: {
          kind: candidate.source.kind,
          url: candidate.source.url,
          ...(headers.length ? { headers } : {}),
          ...(bearerToken === undefined ? {} : { bearerToken }),
        },
        ...(candidate.alternatives
          ? {
              alternatives: candidate.alternatives.map((alternative) => {
                const source = alternative.source;
                if (source.kind !== "http" && source.kind !== "sse") return alternative;
                return {
                  source,
                  upstream: {
                    kind: source.kind,
                    url: source.url,
                    ...(headers.length ? { headers } : {}),
                    ...(bearerToken === undefined ? {} : { bearerToken }),
                  },
                };
              }),
            }
          : {}),
        wrapperEnvironment,
        ...(oauth ? { oauth } : {}),
      },
      dependencies,
    };
  }
  const resolveValue = async (value: string) => read(parseDeferred(value));
  const command = await resolveValue(candidate.source.command);
  const args = await Promise.all(candidate.source.args.map(resolveValue));
  const rawCwd =
    candidate.source.cwd === undefined ? undefined : await resolveValue(candidate.source.cwd);
  const cwd =
    rawCwd === undefined || isAbsolute(rawCwd) ? rawCwd : resolve(context.projectRoot, rawCwd);
  const configured = stringRecord(candidate.original.environment) ?? {};
  const env = createStdioEnvironment([], context.environment);
  for (const name of candidate.source.envNames) {
    const value = await read(
      Object.hasOwn(configured, name)
        ? parseDeferred(configured[name]!)
        : { kind: "environment", name },
    );
    defineOwn(env, name, value);
  }
  const upstream: UpstreamConfig = {
    kind: "stdio",
    command,
    args,
    env,
    ...(cwd !== undefined ? { cwd } : {}),
  };
  return { candidate: { ...candidate, upstream }, dependencies };
}

export function addOpenCodeEntry(
  config: ParsedConfig,
  options: EntryOptions,
  schema: OpenCodeSchema,
  name: string,
  entry: unknown,
): void {
  const candidate =
    parseLocalEntry(options, schema, name, entry) ?? parseRemoteEntry(options, schema, name, entry);
  if (candidate) config.servers.push(candidate);
  else
    config.unsupported.push(
      entryRow(
        options,
        name,
        isRecord(entry) &&
          ((schema === "v1" && entry.enabled === false) ||
            (schema === "v2" && entry.disabled === true))
          ? disabled
          : unsupportedEntry,
      ),
    );
}

export function shadowOpenCodeLocalOwner(config: ParsedConfig, name: string): void {
  const candidate = [...config.servers].reverse().find((row) => row.name === name);
  if (candidate) {
    config.servers.splice(config.servers.indexOf(candidate), 1);
    config.unsupported.push(entryRow(config, name, openCodeShadowed));
  }
  const unsupported = [...config.unsupported]
    .reverse()
    .find((row) => row.name === name && row.reason !== openCodeShadowed);
  if (unsupported) unsupported.reason = openCodeShadowed;
}

function entryRow(
  options: { path: string; scope: Scope },
  name: string,
  reason: string,
): UnsupportedServer {
  return { client: "opencode", scope: options.scope, name, configPath: options.path, reason };
}
