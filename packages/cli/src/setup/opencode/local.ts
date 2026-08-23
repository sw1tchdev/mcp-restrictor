import { dirname, resolve } from "node:path";
import type { UpstreamConfig } from "@mcp-restrictor/transports";
import { isRecord } from "../../utils/values.js";
import { CONFIGURED_CREDENTIAL_PLACEHOLDER } from "../constants.js";
import {
  isManagedWrapperCommand,
  parseManagedWrapper,
  type Scope,
  type ServerCandidate,
  type SourceSpec,
} from "../wrapper.js";
import type { OpenCodeSchema } from "./candidate.js";
import { validatedOpenCodeCandidate, validOpenCodeEntryState } from "./entry.js";
import { parseDeferred, stringArray, stringRecord, validDeferredValues } from "./values.js";

const v1LocalFields = new Set(["type", "command", "cwd", "environment", "enabled", "timeout"]);
const v2LocalFields = new Set([
  "type",
  "command",
  "cwd",
  "environment",
  "disabled",
  "codemode",
  "timeout",
]);

export function parseLocalEntry(
  options: { path: string; scope: Scope; projectRoot?: string },
  schema: OpenCodeSchema,
  name: string,
  entry: unknown,
): ServerCandidate | undefined {
  if (!isRecord(entry) || entry.type !== "local") return undefined;
  const fields = schema === "v1" ? v1LocalFields : v2LocalFields;
  if (Object.keys(entry).some((field) => !fields.has(field))) return undefined;
  if (!validOpenCodeEntryState(entry, schema)) return undefined;
  const command = stringArray(entry.command);
  const environment = stringRecord(entry.environment);
  if (
    !command?.length ||
    (entry.cwd !== undefined && typeof entry.cwd !== "string") ||
    !environment ||
    !validDeferredValues([
      ...command,
      ...(typeof entry.cwd === "string" ? [entry.cwd] : []),
      ...Object.values(environment),
    ])
  )
    return undefined;

  const [rawCommand, ...rawArgs] = command;
  if (!rawCommand) return undefined;
  const managed = parseManagedWrapper(rawCommand, rawArgs);
  if (isManagedWrapperCommand(rawCommand) && !managed) return undefined;
  if (
    managed &&
    ((typeof entry.cwd === "string" && parseDeferred(entry.cwd).kind !== "literal") ||
      parseDeferred(managed.policyArgument).kind !== "literal")
  )
    return undefined;
  const source: SourceSpec = managed?.source ?? {
    kind: "stdio",
    command: rawCommand,
    args: rawArgs,
    envNames: Object.keys(environment).sort(),
    ...(typeof entry.cwd === "string" ? { cwd: entry.cwd } : {}),
  };
  const wrapperEnvironment = Object.keys(environment).length ? { env: environment } : {};
  const candidate: ServerCandidate = {
    client: "opencode",
    scope: options.scope,
    name,
    configPath: options.path,
    source,
    upstream: structuralUpstream(source),
    wrapperEnvironment,
    original: entry,
    ...(managed
      ? {
          managedPolicyPath: resolve(
            typeof entry.cwd === "string"
              ? resolve(options.projectRoot ?? dirname(options.path), entry.cwd)
              : (options.projectRoot ?? dirname(options.path)),
            managed.policyArgument,
          ),
        }
      : {}),
  };
  return validatedOpenCodeCandidate(candidate);
}

function structuralUpstream(source: SourceSpec): UpstreamConfig {
  if (source.kind === "stdio") {
    return {
      kind: "stdio",
      command: source.command,
      args: source.args,
      ...(source.cwd !== undefined ? { cwd: source.cwd } : {}),
    };
  }
  const headers = source.headers.map(
    ({ name }) => [name, CONFIGURED_CREDENTIAL_PLACEHOLDER] as const,
  );
  if (source.kind === "websocket") {
    return { kind: "websocket", url: source.url, ...(headers.length ? { headers } : {}) };
  }
  return {
    kind: source.kind,
    url: source.url,
    ...(headers.length ? { headers } : {}),
    ...(source.bearerTokenEnvVar ? { bearerToken: CONFIGURED_CREDENTIAL_PLACEHOLDER } : {}),
  };
}
