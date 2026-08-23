import {
  parseHeaderEnvironmentMapping,
  validateRemoteUpstream,
  type HeaderEnvironmentMapping,
} from "@mcp-restrictor/transports";
import { secureOAuthUrl } from "../../oauth/login/discovery.js";
import {
  isReservedOAuthCallbackParameter,
  MAX_TCP_PORT,
  OAUTH_IPV4_LOOPBACK_HOST,
} from "../../oauth/urls.js";
import { MASTER_KEY_FILE_ENV } from "../../oauth/storage.js";
import { asciiLower, defineOwn, isRecord } from "../../utils/values.js";
import { CONFIGURED_CREDENTIAL_PLACEHOLDER } from "../constants.js";
import {
  hasMasterKeyHeaderMapping,
  reserveWrapperEnvironmentName,
  type Scope,
  type ServerCandidate,
  type SourceSpec,
} from "../wrapper.js";
import type { OpenCodeSchema } from "./candidate.js";
import { validatedOpenCodeCandidate, validOpenCodeEntryState } from "./entry.js";
import { parseDeferred, stringRecord, stringValue, validDeferredValues } from "./values.js";

const v1RemoteFields = new Set(["type", "url", "headers", "oauth", "enabled", "timeout"]);
const v2RemoteFields = new Set([
  "type",
  "url",
  "headers",
  "oauth",
  "disabled",
  "codemode",
  "timeout",
]);
const v1OAuthFields = new Set(["clientId", "clientSecret", "scope", "callbackPort", "redirectUri"]);
const v2OAuthFields = new Set([
  "client_id",
  "client_secret",
  "scope",
  "callback_port",
  "redirect_uri",
]);
const bearer = /^Bearer (.+)$/;
const scopeToken = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
export function parseRemoteEntry(
  options: { path: string; scope: Scope; environment?: NodeJS.ProcessEnv },
  schema: OpenCodeSchema,
  name: string,
  entry: unknown,
): ServerCandidate | undefined {
  if (!isRecord(entry) || entry.type !== "remote") return undefined;
  const fields = schema === "v1" ? v1RemoteFields : v2RemoteFields;
  if (Object.keys(entry).some((field) => !fields.has(field))) return undefined;
  if (typeof entry.url !== "string" || !validOpenCodeEntryState(entry, schema)) return undefined;

  const headerValues = stringRecord(entry.headers);
  if (!headerValues) return undefined;
  const oauthValue = Object.hasOwn(entry, "oauth") ? entry.oauth : undefined;
  if (oauthValue !== undefined && oauthValue !== false && !isRecord(oauthValue)) return undefined;
  const oauth = oauthValue === false ? undefined : oauthHint(schema, oauthValue);
  if (oauthValue !== false && !oauth) return undefined;

  const authorization = Object.entries(headerValues).filter(
    ([header]) => asciiLower(header) === "authorization",
  );
  if (oauth && authorization.length > 0) return undefined;
  const bearerAuthorization =
    oauthValue === false && authorization.length === 1
      ? bearer.exec(authorization[0]![1])
      : undefined;
  const deferredHeaderValues = Object.entries(headerValues).map(([header, value]) =>
    bearerAuthorization && header === authorization[0]![0] ? bearerAuthorization[1]! : value,
  );
  if (!validDeferredValues(deferredHeaderValues)) return undefined;
  const rawOAuth = isRecord(oauthValue) ? oauthValue : {};
  const rawClientId = stringValue(rawOAuth, schema === "v1" ? "clientId" : "client_id");
  const rawClientSecret = stringValue(rawOAuth, schema === "v1" ? "clientSecret" : "client_secret");
  const occupied = new Set(Object.keys(options.environment ?? {}));
  for (const value of [...deferredHeaderValues, rawClientId, rawClientSecret]) {
    if (value === undefined) continue;
    const deferred = parseDeferred(value);
    if (deferred.kind === "environment") occupied.add(deferred.name);
  }
  const headers: HeaderEnvironmentMapping[] = [];
  const wrapperValues: Record<string, string> = {};
  let bearerTokenEnvVar: string | undefined;
  for (const [header, raw] of Object.entries(headerValues)) {
    if (bearerAuthorization && header === authorization[0]![0]) {
      bearerTokenEnvVar = reserveWrapperEnvironmentName(occupied);
      defineOwn(wrapperValues, bearerTokenEnvVar, bearerAuthorization[1]!);
      continue;
    }
    const deferred = parseDeferred(raw);
    const environmentVariable =
      deferred.kind === "environment" ? deferred.name : reserveWrapperEnvironmentName(occupied);
    let mapping: HeaderEnvironmentMapping;
    try {
      mapping = parseHeaderEnvironmentMapping(`${header}=${environmentVariable}`);
    } catch {
      return undefined;
    }
    headers.push(mapping);
    defineOwn(wrapperValues, environmentVariable, raw);
  }
  if (oauth && hasMasterKeyHeaderMapping(headers)) return undefined;
  if (oauth && Object.hasOwn(options.environment ?? {}, MASTER_KEY_FILE_ENV)) {
    defineOwn(wrapperValues, MASTER_KEY_FILE_ENV, `{env:${MASTER_KEY_FILE_ENV}}`);
  }

  const structuralHeaders = headers.map(
    ({ name: header }) => [header, CONFIGURED_CREDENTIAL_PLACEHOLDER] as const,
  );
  try {
    validateRemoteUpstream({
      kind: "http",
      url: entry.url,
      ...(structuralHeaders.length ? { headers: structuralHeaders } : {}),
      ...(bearerTokenEnvVar ? { auth: "bearer" } : oauth ? { auth: "oauth" } : {}),
    });
  } catch {
    return undefined;
  }
  const source: SourceSpec = {
    kind: "http",
    url: entry.url,
    headers,
    ...(bearerTokenEnvVar ? { bearerTokenEnvVar } : {}),
  };
  const alternative =
    schema === "v1"
      ? {
          source: { ...source, kind: "sse" as const },
          upstream: {
            kind: "sse" as const,
            url: entry.url,
            ...(structuralHeaders.length ? { headers: structuralHeaders } : {}),
            ...(bearerTokenEnvVar ? { bearerToken: CONFIGURED_CREDENTIAL_PLACEHOLDER } : {}),
          },
        }
      : undefined;
  const candidate: ServerCandidate = {
    client: "opencode",
    scope: options.scope,
    name,
    configPath: options.path,
    source,
    upstream: {
      kind: "http",
      url: entry.url,
      ...(structuralHeaders.length ? { headers: structuralHeaders } : {}),
      ...(bearerTokenEnvVar ? { bearerToken: CONFIGURED_CREDENTIAL_PLACEHOLDER } : {}),
    },
    ...(alternative ? { alternatives: [alternative] } : {}),
    wrapperEnvironment: Object.keys(wrapperValues).length ? { env: wrapperValues } : {},
    original: entry,
    ...(oauth ? { oauth } : {}),
  };
  return validatedOpenCodeCandidate(candidate);
}

function oauthHint(
  schema: OpenCodeSchema,
  value: Record<string, unknown> | undefined,
): ServerCandidate["oauth"] | undefined {
  const fields = schema === "v1" ? v1OAuthFields : v2OAuthFields;
  if (value && Object.keys(value).some((field) => !fields.has(field))) return undefined;
  const clientId = value && stringValue(value, schema === "v1" ? "clientId" : "client_id");
  const clientSecret =
    value && stringValue(value, schema === "v1" ? "clientSecret" : "client_secret");
  if (
    (value &&
      Object.hasOwn(value, schema === "v1" ? "clientId" : "client_id") &&
      !validDeferredCredential(clientId)) ||
    (value &&
      Object.hasOwn(value, schema === "v1" ? "clientSecret" : "client_secret") &&
      !validDeferredCredential(clientSecret)) ||
    (clientSecret !== undefined && clientId === undefined)
  )
    return undefined;
  const scope = value?.scope;
  if (
    scope !== undefined &&
    (typeof scope !== "string" ||
      !scope ||
      !scope.split(" ").every((token) => scopeToken.test(token)))
  )
    return undefined;
  const portName = schema === "v1" ? "callbackPort" : "callback_port";
  const redirectName = schema === "v1" ? "redirectUri" : "redirect_uri";
  const port = value?.[portName];
  const redirect = value?.[redirectName];
  if (
    (port !== undefined &&
      (!Number.isInteger(port) || (port as number) < 1 || (port as number) > MAX_TCP_PORT)) ||
    (redirect !== undefined && (typeof redirect !== "string" || !validCallbackUrl(redirect)))
  )
    return undefined;
  const callback: NonNullable<ServerCandidate["oauth"]>["callback"] =
    redirect !== undefined
      ? { url: redirect as string, appendProfileId: false }
      : port !== undefined
        ? {
            host: OAUTH_IPV4_LOOPBACK_HOST,
            path: "/mcp/oauth/callback",
            port: port as number,
            appendProfileId: false,
          }
        : schema === "v1"
          ? {
              url: `http://${OAUTH_IPV4_LOOPBACK_HOST}:19876/mcp/oauth/callback`,
              appendProfileId: false,
            }
          : {
              host: OAUTH_IPV4_LOOPBACK_HOST,
              path: "/mcp/oauth/callback",
              port: 0,
              appendProfileId: false,
            };
  return {
    mode: value === undefined ? "challenge" : "explicit",
    ...(clientId === undefined ? {} : { clientId }),
    ...(scope === undefined ? {} : { requestedScope: scope as string }),
    callback,
  };
}

function validDeferredCredential(value: string | undefined): boolean {
  if (value === undefined) return false;
  try {
    const deferred = parseDeferred(value);
    return deferred.kind !== "literal" || deferred.value.length > 0;
  } catch {
    return false;
  }
}

function validCallbackUrl(value: string): boolean {
  try {
    const url = secureOAuthUrl(value);
    const seen = new Set<string>();
    for (const [name] of url.searchParams) {
      if (seen.has(name) || isReservedOAuthCallbackParameter(name)) return false;
      seen.add(name);
    }
    return true;
  } catch {
    return false;
  }
}
