import type {
  OAuthClientMetadata,
  OAuthDiscoveryState,
  StoredOAuthClientInformation,
  StoredOAuthTokens,
} from "@modelcontextprotocol/client";
import { AES_256_GCM_ALGORITHM, INVALID_CALLBACK_STRATEGY_MESSAGE } from "../constants.js";
import {
  DEFAULT_OAUTH_CALLBACK_PATH,
  isExactLoopbackHost,
  MAX_TCP_PORT,
  OAUTH_IPV4_LOOPBACK_HOST,
  OAUTH_IPV6_LOOPBACK_HOST,
  OAUTH_LOCALHOST,
} from "../urls.js";

export type OAuthCallbackStrategy = {
  url?: string;
  host?: typeof OAUTH_LOCALHOST | typeof OAUTH_IPV4_LOOPBACK_HOST | typeof OAUTH_IPV6_LOOPBACK_HOST;
  path?: string;
  port?: number;
  appendProfileId: boolean;
};

export type OAuthProfileMetadata = {
  version: 1;
  profileId: string;
  serverUrl: string;
  requestedScope?: string;
  resource?: string;
  resourceMetadataUrl?: string;
  authServerMetadataUrl?: string;
  callback: OAuthCallbackStrategy;
  callbackUrl?: string;
  clientMetadata: Omit<OAuthClientMetadata, "redirect_uris">;
};

export type OAuthCredentialState = {
  clientInformation: StoredOAuthClientInformation;
  tokens: StoredOAuthTokens;
  discoveryState: OAuthDiscoveryState;
};

export type OAuthProfile = {
  metadata: OAuthProfileMetadata;
  credentials: OAuthCredentialState;
};

export type EncryptionEnvelope = {
  algorithm: typeof AES_256_GCM_ALGORITHM;
  nonce: string;
  ciphertext: string;
  tag: string;
};

type LegacyOAuthCallback = {
  kind: "claude" | "codex" | "manual";
  port?: number;
  baseUrl?: string;
};

type StoredOAuthProfileMetadata = Omit<OAuthProfileMetadata, "callback"> & {
  callback: OAuthCallbackStrategy | LegacyOAuthCallback;
};

const PROFILE_KEYS = [
  "version",
  "profileId",
  "serverUrl",
  "requestedScope",
  "resource",
  "resourceMetadataUrl",
  "authServerMetadataUrl",
  "callback",
  "callbackUrl",
  "clientMetadata",
] as const;
const CLIENT_METADATA_KEYS = [
  "token_endpoint_auth_method",
  "grant_types",
  "response_types",
  "application_type",
  "client_name",
  "client_uri",
  "logo_uri",
  "scope",
  "contacts",
  "tos_uri",
  "policy_uri",
  "jwks_uri",
  "jwks",
  "software_id",
  "software_version",
  "software_statement",
] as const;
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function parseProfileMetadata(value: unknown): OAuthProfileMetadata {
  return parseMetadata(value);
}

export function parseStoredProfile(value: unknown): {
  metadata: StoredOAuthProfileMetadata;
  encryption: EncryptionEnvelope;
} {
  const envelope = record(value);
  assertExactKeys(envelope, [...PROFILE_KEYS, "encryption"]);
  return {
    metadata: parseMetadata(envelope, ["encryption"], true),
    encryption: parseEncryption(envelope.encryption),
  };
}

export function normalizeStoredProfileMetadata(
  metadata: StoredOAuthProfileMetadata,
): OAuthProfileMetadata {
  return { ...metadata, callback: normalizeCallback(metadata.callback) };
}

export function parseCredentialState(value: unknown): OAuthCredentialState {
  const input = record(value);
  assertExactKeys(input, ["clientInformation", "tokens", "discoveryState"]);
  const clientInformation = record(input.clientInformation);
  assertExactKeys(clientInformation, [
    ...CLIENT_METADATA_KEYS,
    "redirect_uris",
    "client_id",
    "client_secret",
    "client_id_issued_at",
    "client_secret_expires_at",
    "issuer",
  ]);
  requiredString(clientInformation.client_id);
  optionalString(clientInformation.client_secret);
  optionalNumber(clientInformation.client_id_issued_at);
  optionalNumber(clientInformation.client_secret_expires_at);
  optionalString(clientInformation.issuer);
  if (clientInformation.redirect_uris !== undefined) {
    stringArray(clientInformation.redirect_uris);
  }

  const tokens = record(input.tokens);
  assertExactKeys(tokens, [
    "access_token",
    "id_token",
    "token_type",
    "expires_in",
    "scope",
    "refresh_token",
    "issuer",
  ]);
  requiredString(tokens.access_token);
  requiredString(tokens.token_type);
  optionalString(tokens.id_token);
  optionalNumber(tokens.expires_in);
  optionalString(tokens.scope);
  optionalString(tokens.refresh_token);
  optionalString(tokens.issuer);

  const discoveryState = record(input.discoveryState);
  assertExactKeys(discoveryState, [
    "authorizationServerUrl",
    "authorizationServerMetadata",
    "resourceMetadata",
    "resourceMetadataUrl",
  ]);
  requiredString(discoveryState.authorizationServerUrl);
  optionalString(discoveryState.resourceMetadataUrl);
  if (discoveryState.authorizationServerMetadata !== undefined) {
    record(discoveryState.authorizationServerMetadata);
  }
  if (discoveryState.resourceMetadata !== undefined) {
    record(discoveryState.resourceMetadata);
  }
  return input as OAuthCredentialState;
}

export function jsonCopy(value: unknown): unknown {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) throw new Error("Expected JSON value");
  return JSON.parse(serialized) as unknown;
}

export function assertProfileId(profileId: string): void {
  if (!UUID_V4.test(profileId)) throw new Error("Invalid OAuth profile ID");
}

export function safeProfileId(value: unknown): string {
  return typeof value === "string" && UUID_V4.test(value) ? value : "invalid";
}

function parseMetadata(value: unknown, allowedExtraKeys?: readonly string[]): OAuthProfileMetadata;
function parseMetadata(
  value: unknown,
  allowedExtraKeys: readonly string[],
  stored: true,
): StoredOAuthProfileMetadata;
function parseMetadata(
  value: unknown,
  allowedExtraKeys: readonly string[] = [],
  stored = false,
): OAuthProfileMetadata | StoredOAuthProfileMetadata {
  const input = record(value);
  assertExactKeys(input, [...PROFILE_KEYS, ...allowedExtraKeys]);
  if (input.version !== 1) throw new Error("Invalid metadata version");
  const profileId = requiredString(input.profileId);
  assertProfileId(profileId);
  const requestedScope = optionalString(input.requestedScope);
  const resource = optionalString(input.resource);
  const resourceMetadataUrl = optionalString(input.resourceMetadataUrl);
  const authServerMetadataUrl = optionalString(input.authServerMetadataUrl);
  const callbackUrl = optionalString(input.callbackUrl);
  return {
    version: 1,
    profileId,
    serverUrl: requiredString(input.serverUrl),
    ...(requestedScope === undefined ? {} : { requestedScope }),
    ...(resource === undefined ? {} : { resource }),
    ...(resourceMetadataUrl === undefined ? {} : { resourceMetadataUrl }),
    ...(authServerMetadataUrl === undefined ? {} : { authServerMetadataUrl }),
    callback: stored ? parseStoredCallback(input.callback) : parseCallback(input.callback),
    ...(callbackUrl === undefined ? {} : { callbackUrl }),
    clientMetadata: parseClientMetadata(input.clientMetadata),
  };
}

function parseCallback(value: unknown): OAuthProfileMetadata["callback"] {
  const input = record(value);
  assertExactKeys(input, ["url", "host", "path", "port", "appendProfileId"]);
  const port = callbackPort(input.port);
  if (typeof input.appendProfileId !== "boolean") {
    throw new Error("Invalid callback profile suffix");
  }
  if (input.url !== undefined) {
    if (input.host !== undefined || input.path !== undefined) {
      throw new Error(INVALID_CALLBACK_STRATEGY_MESSAGE);
    }
    return {
      url: requiredString(input.url),
      ...(port === undefined ? {} : { port }),
      appendProfileId: input.appendProfileId,
    };
  }
  if (!isExactLoopbackHost(String(input.host))) {
    throw new Error("Invalid callback host");
  }
  return {
    host: input.host as NonNullable<OAuthCallbackStrategy["host"]>,
    path: requiredString(input.path),
    ...(port === undefined ? {} : { port }),
    appendProfileId: input.appendProfileId,
  };
}

function parseStoredCallback(value: unknown): OAuthCallbackStrategy | LegacyOAuthCallback {
  const input = record(value);
  if (!Object.hasOwn(input, "kind")) return parseCallback(input);
  assertExactKeys(input, ["kind", "port", "baseUrl"]);
  if (!["claude", "codex", "manual"].includes(String(input.kind))) {
    throw new Error("Invalid callback kind");
  }
  const port = callbackPort(input.port);
  const baseUrl = optionalString(input.baseUrl);
  return {
    kind: input.kind as LegacyOAuthCallback["kind"],
    ...(port === undefined ? {} : { port }),
    ...(baseUrl === undefined ? {} : { baseUrl }),
  };
}

function normalizeCallback(
  callback: OAuthCallbackStrategy | LegacyOAuthCallback,
): OAuthCallbackStrategy {
  if (!("kind" in callback)) return callback;
  if (callback.kind === "claude") {
    return {
      host: OAUTH_LOCALHOST,
      path: DEFAULT_OAUTH_CALLBACK_PATH,
      ...(callback.port === undefined ? {} : { port: callback.port }),
      appendProfileId: false,
    };
  }
  return callback.baseUrl
    ? {
        url: callback.baseUrl,
        ...(callback.port === undefined ? {} : { port: callback.port }),
        appendProfileId: true,
      }
    : {
        host: OAUTH_IPV4_LOOPBACK_HOST,
        path: DEFAULT_OAUTH_CALLBACK_PATH,
        ...(callback.port === undefined ? {} : { port: callback.port }),
        appendProfileId: true,
      };
}

function callbackPort(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > MAX_TCP_PORT) {
    throw new Error("Invalid callback port");
  }
  return value;
}

function parseClientMetadata(value: unknown): OAuthProfileMetadata["clientMetadata"] {
  const input = record(value);
  assertExactKeys(input, CLIENT_METADATA_KEYS);
  const output: Record<string, unknown> = {};
  for (const key of CLIENT_METADATA_KEYS) {
    const item = input[key];
    if (item === undefined) continue;
    if (key === "grant_types" || key === "response_types" || key === "contacts") {
      output[key] = stringArray(item);
    } else if (key === "jwks") {
      output[key] = jsonCopy(item);
    } else {
      output[key] = requiredString(item);
    }
  }
  return output as OAuthProfileMetadata["clientMetadata"];
}

function parseEncryption(value: unknown): EncryptionEnvelope {
  const input = record(value);
  assertExactKeys(input, ["algorithm", "nonce", "ciphertext", "tag"]);
  if (input.algorithm !== AES_256_GCM_ALGORITHM) throw new Error("Invalid algorithm");
  const nonce = base64Url(input.nonce, 12);
  const ciphertext = base64Url(input.ciphertext);
  const tag = base64Url(input.tag, 16);
  return { algorithm: AES_256_GCM_ALGORITHM, nonce, ciphertext, tag };
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Expected object");
  }
  return value as Record<string, unknown>;
}

function assertExactKeys(value: Record<string, unknown>, allowed: readonly string[]): void {
  const allowedKeys = new Set(allowed);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) {
    throw new Error("Unexpected field");
  }
}

function requiredString(value: unknown): string {
  if (typeof value !== "string") throw new Error("Expected string");
  return value;
}

function optionalString(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  return requiredString(value);
}

function optionalNumber(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error("Expected number");
  return value;
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new Error("Expected string array");
  }
  return value;
}

function base64Url(value: unknown, bytes?: number): string {
  const text = requiredString(value);
  if (!/^[A-Za-z0-9_-]+$/.test(text)) throw new Error("Invalid base64url");
  const decoded = Buffer.from(text, "base64url");
  if (decoded.toString("base64url") !== text || (bytes !== undefined && decoded.length !== bytes)) {
    throw new Error("Invalid base64url");
  }
  return text;
}
