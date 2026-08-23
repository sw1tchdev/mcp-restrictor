import {
  discoverAuthorizationServerMetadata,
  discoverOAuthProtectedResourceMetadata,
  type AuthorizationServerMetadata,
  type FetchLike,
  type OAuthDiscoveryState,
  type OAuthProtectedResourceMetadata,
} from "@modelcontextprotocol/client";

import type { OAuthProfileMetadata } from "../storage.js";
import { isExactLoopbackHost } from "../urls.js";

type OAuthDiscoveryInput = {
  metadata: OAuthProfileMetadata;
  discoveryState?: OAuthDiscoveryState;
};

export type ValidatedDiscoveryState = OAuthDiscoveryState & {
  authorizationServerMetadata: AuthorizationServerMetadata;
};

const scopeToken = /^[\x21\x23-\x5B\x5D-\x7E]+$/;

export async function resolveDiscovery(
  input: OAuthDiscoveryInput,
  fetchFn: FetchLike,
  missingResourceMetadataUrls: Set<string>,
): Promise<ValidatedDiscoveryState> {
  const resourceMetadataUrl = input.metadata.resourceMetadataUrl
    ? secureOAuthUrl(input.metadata.resourceMetadataUrl)
    : undefined;
  const authServerMetadataUrl = input.metadata.authServerMetadataUrl
    ? secureOAuthUrl(input.metadata.authServerMetadataUrl)
    : undefined;
  const cached = input.discoveryState?.authorizationServerMetadata
    ? validateDiscoveryState(input.discoveryState)
    : undefined;
  if (
    cached?.resourceMetadata &&
    (!resourceMetadataUrl || cached.resourceMetadataUrl === resourceMetadataUrl.href)
  ) {
    if (!authServerMetadataUrl) return cached;
    return {
      ...cached,
      authorizationServerMetadata: await customAuthorizationMetadata(
        authServerMetadataUrl,
        new URL(cached.authorizationServerUrl),
        fetchFn,
      ),
    };
  }

  let resourceMetadata: OAuthProtectedResourceMetadata | undefined;
  try {
    const resourceFetchFn: FetchLike = async (url, init) => {
      const response = await fetchFn(url, init);
      if (response.status === 404) {
        missingResourceMetadataUrls.add(new URL(url).href);
      }
      return response;
    };
    resourceMetadata = await discoverOAuthProtectedResourceMetadata(
      input.metadata.serverUrl,
      resourceMetadataUrl ? { resourceMetadataUrl } : undefined,
      resourceFetchFn,
    );
  } catch (error) {
    if (!isMissingProtectedResourceMetadata(error)) throw error;
  }
  resourceMetadata = validateResourceMetadata(resourceMetadata);

  const selected =
    resourceMetadata?.authorization_servers?.[0] ?? new URL("/", input.metadata.serverUrl).href;
  const authorizationServerUrl = secureOAuthUrl(selected);
  let authorizationServerMetadata: AuthorizationServerMetadata | undefined;
  if (authServerMetadataUrl) {
    authorizationServerMetadata = await customAuthorizationMetadata(
      authServerMetadataUrl,
      authorizationServerUrl,
      fetchFn,
    );
  } else {
    authorizationServerMetadata = await discoverAuthorizationServerMetadata(
      authorizationServerUrl,
      { fetchFn },
    );
  }
  if (!authorizationServerMetadata) throw new Error("OAuth metadata is unavailable");
  authorizationServerMetadata = validateAuthorizationMetadata(
    authorizationServerMetadata,
    authorizationServerUrl,
  );
  return {
    authorizationServerUrl: authorizationServerUrl.href,
    authorizationServerMetadata,
    ...(resourceMetadata ? { resourceMetadata } : {}),
    ...(resourceMetadataUrl ? { resourceMetadataUrl: resourceMetadataUrl.href } : {}),
  };
}

export function validateDiscoveryState(cached: OAuthDiscoveryState): ValidatedDiscoveryState {
  const authorizationServerUrl = secureOAuthUrl(cached.authorizationServerUrl);
  const resourceMetadataUrl = cached.resourceMetadataUrl
    ? secureOAuthUrl(cached.resourceMetadataUrl).href
    : undefined;
  const resourceMetadata = validateResourceMetadata(cached.resourceMetadata);
  if (
    resourceMetadata?.authorization_servers?.[0] !== undefined &&
    new URL(resourceMetadata.authorization_servers[0]).href !== authorizationServerUrl.href
  ) {
    throw new Error("Cached OAuth discovery mismatch");
  }
  if (!cached.authorizationServerMetadata) {
    throw new Error("Cached OAuth metadata is missing");
  }
  const authorizationServerMetadata = validateAuthorizationMetadata(
    cached.authorizationServerMetadata,
    authorizationServerUrl,
  );
  return {
    authorizationServerUrl: authorizationServerUrl.href,
    authorizationServerMetadata,
    ...(resourceMetadata ? { resourceMetadata } : {}),
    ...(resourceMetadataUrl ? { resourceMetadataUrl } : {}),
  };
}

export function joinedScopes(scopes: readonly string[] | undefined): string | undefined {
  return scopes?.length ? scopes.join(" ") : undefined;
}

export function secureOAuthUrl(value: string | URL): URL {
  const url = new URL(value);
  if (url.username || url.password || url.hash) throw new Error("Unsafe OAuth URL");
  if (url.protocol === "https:") return url;
  if (url.protocol !== "http:" || !isExactLoopbackHost(url.hostname)) {
    throw new Error("Secure OAuth URL is required");
  }
  return url;
}

async function customAuthorizationMetadata(
  metadataUrl: URL,
  authorizationServerUrl: URL,
  fetchFn: FetchLike,
): Promise<AuthorizationServerMetadata> {
  const response = await fetchFn(metadataUrl);
  if (!response.ok) {
    await response.text().catch(() => undefined);
    throw new Error("OAuth metadata request failed");
  }
  let raw: unknown;
  try {
    raw = await response.clone().json();
  } catch {
    throw new Error("OAuth metadata is invalid");
  }
  let used = false;
  const parsed = await discoverAuthorizationServerMetadata(authorizationServerUrl, {
    fetchFn: async () => {
      if (used) throw new Error("OAuth metadata parser requested more than one response");
      used = true;
      return response;
    },
  });
  if (!used || !parsed || record(raw).issuer !== authorizationServerUrl.href) {
    throw new Error("OAuth metadata issuer mismatch");
  }
  return validateAuthorizationMetadata(parsed, authorizationServerUrl);
}

function validateAuthorizationMetadata(
  metadata: AuthorizationServerMetadata,
  authorizationServerUrl: URL,
): AuthorizationServerMetadata {
  if (metadata.issuer !== authorizationServerUrl.href) {
    throw new Error("OAuth metadata issuer mismatch");
  }
  secureOAuthUrl(metadata.issuer);
  secureOAuthUrl(metadata.authorization_endpoint);
  if (!metadata.token_endpoint) throw new Error("OAuth token endpoint is missing");
  secureOAuthUrl(metadata.token_endpoint);
  if (metadata.registration_endpoint) secureOAuthUrl(metadata.registration_endpoint);
  if (
    !Array.isArray(metadata.response_types_supported) ||
    metadata.response_types_supported.some((value) => typeof value !== "string")
  ) {
    throw new Error("OAuth response types are invalid");
  }
  validateScopes(metadata.scopes_supported);
  return metadata;
}

function validateResourceMetadata(
  metadata: OAuthProtectedResourceMetadata | undefined,
): OAuthProtectedResourceMetadata | undefined {
  if (!metadata) return undefined;
  const value = record(metadata);
  if (typeof value.resource !== "string") throw new Error("OAuth resource is invalid");
  const resource = new URL(value.resource);
  if (resource.hash) throw new Error("OAuth resource is invalid");
  if (
    value.authorization_servers !== undefined &&
    (!Array.isArray(value.authorization_servers) ||
      value.authorization_servers.some((item) => typeof item !== "string"))
  ) {
    throw new Error("OAuth authorization servers are invalid");
  }
  for (const server of (value.authorization_servers ?? []) as string[]) {
    new URL(server);
  }
  validateScopes(value.scopes_supported);
  return metadata;
}

function validateScopes(value: unknown): void {
  if (value === undefined) return;
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string" || !scopeToken.test(item))
  ) {
    throw new Error("OAuth scopes are invalid");
  }
}

function isMissingProtectedResourceMetadata(error: unknown): boolean {
  return (
    error instanceof Error &&
    Object.getPrototypeOf(error) === Error.prototype &&
    error.message === "Resource server does not implement OAuth 2.0 Protected Resource Metadata."
  );
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Expected OAuth metadata object");
  }
  return value as Record<string, unknown>;
}
