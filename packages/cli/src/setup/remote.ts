import { validateRemoteUpstream } from "@mcp-restrictor/transports";
import { configuredMasterKeyFile, MASTER_KEY_FILE_ENV } from "../oauth/storage.js";
import { asciiLower, defineOwn } from "../utils/values.js";
import {
  CONFIGURED_CREDENTIAL_PLACEHOLDER,
  INVALID_REMOTE_CONFIGURATION_MESSAGE,
  OAUTH_HEADER_MAPPING_CONFLICT_MESSAGE,
  OAUTH_UPSTREAM_REQUIRED_MESSAGE,
} from "./constants.js";
import { hasMasterKeyHeaderMapping } from "./wrapper/managed.js";
import type { OAuthSetupHint, SourceSpec, WrapperEnvironment } from "./wrapper/model.js";

type RemoteSource = Extract<SourceSpec, { kind: "http" | "sse" | "websocket" }>;
type RemoteAuth = "bearer" | "oauth" | undefined;
export type RemoteStructure = {
  auth: RemoteAuth;
  headers: readonly (readonly [string, string])[];
};

export function withStorageEnvironment(
  wrapper: WrapperEnvironment,
  environment: NodeJS.ProcessEnv,
  needed: boolean,
): WrapperEnvironment {
  if (!needed || (wrapper.env && Object.hasOwn(wrapper.env, MASTER_KEY_FILE_ENV))) return wrapper;
  const path = configuredMasterKeyFile(environment);
  if (!path) return wrapper;
  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(wrapper.env ?? {})) defineOwn(env, name, value);
  defineOwn(env, MASTER_KEY_FILE_ENV, path);
  return { ...wrapper, env };
}

export function withOAuthProfile(source: SourceSpec, profileId: string): SourceSpec {
  if (source.kind !== "http" && source.kind !== "sse") {
    throw new Error(OAUTH_UPSTREAM_REQUIRED_MESSAGE);
  }
  return { ...source, oauthProfileId: profileId };
}

export function supportsOAuthChallenge(source: SourceSpec): boolean {
  return (
    (source.kind === "http" || source.kind === "sse") &&
    source.oauthProfileId === undefined &&
    source.bearerTokenEnvVar === undefined &&
    !source.headers.some(({ name }) => asciiLower(name) === "authorization")
  );
}

export function remoteStructure(
  source: RemoteSource,
  oauth: OAuthSetupHint | undefined,
): RemoteStructure | { reason: string } {
  if (
    (oauth || (source.kind !== "websocket" && source.oauthProfileId)) &&
    hasMasterKeyHeaderMapping(source.headers)
  ) {
    return { reason: OAUTH_HEADER_MAPPING_CONFLICT_MESSAGE };
  }
  const auth =
    source.kind === "websocket"
      ? undefined
      : source.bearerTokenEnvVar
        ? ("bearer" as const)
        : source.oauthProfileId || oauth?.mode === "explicit"
          ? ("oauth" as const)
          : undefined;
  const headers = source.headers.map(
    ({ name }) => [name, CONFIGURED_CREDENTIAL_PLACEHOLDER] as const,
  );
  const placeholder =
    source.kind === "websocket" ? "wss://example.invalid" : "https://example.invalid";
  return validRemoteConfiguration(source.kind, placeholder, headers, auth)
    ? { auth, headers }
    : { reason: INVALID_REMOTE_CONFIGURATION_MESSAGE };
}

export function remoteEndpointReason(
  source: RemoteSource,
  url: string,
  structure: RemoteStructure,
): string | undefined {
  const label = source.kind === "websocket" ? "WebSocket" : "HTTP";
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return `invalid ${label} URL`;
  }
  const schemes = source.kind === "websocket" ? ["ws:", "wss:"] : ["http:", "https:"];
  if (!schemes.includes(parsed.protocol)) return `unsupported ${label} URL`;
  if (parsed.username || parsed.password) return `${label} URL must not contain credentials`;
  if (parsed.search || parsed.hash) return `${label} URL must not contain query or fragment`;
  return validRemoteConfiguration(source.kind, url, structure.headers, structure.auth)
    ? undefined
    : INVALID_REMOTE_CONFIGURATION_MESSAGE;
}

export function validRemoteConfiguration(
  kind: RemoteSource["kind"],
  url: string,
  headers: readonly (readonly [string, string])[],
  auth: RemoteAuth,
): boolean {
  try {
    validateRemoteUpstream({
      kind,
      url,
      ...(headers.length ? { headers } : {}),
      ...(auth ? { auth } : {}),
    });
    return true;
  } catch {
    return false;
  }
}
