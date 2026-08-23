import { homedir } from "node:os";
import {
  refreshAuthorization,
  type AuthProvider,
  type AuthorizationServerMetadata,
  type FetchLike,
} from "@modelcontextprotocol/client";
import { withPrivateFileLock, writePrivateFileAtomically } from "../setup/transaction.js";
import { abortable } from "../utils/async.js";
import { OAUTH_SERVER_BINDING_MISMATCH_MESSAGE } from "./constants.js";
import { cleanOAuthFetch } from "./fetch.js";
import { canonicalOptionalUrl, canonicalUrl } from "./urls.js";
import {
  oauthProfilePath,
  readOAuthProfile,
  readOAuthProfileSnapshot,
  writeOAuthProfile,
  type OAuthProfile,
  type OAuthStorageOptions,
} from "./storage.js";

export type OAuthRuntimeOptions = OAuthStorageOptions & {
  fetchFn?: FetchLike;
  refresh?: typeof refreshAuthorization;
  signal?: AbortSignal;
  lockTimeoutMs?: number;
  refreshTimeoutMs?: number;
};

type OAuthBinding = { serverUrl: string; resource?: string };

const defaultTimeoutMs = 30_000;

export function createOAuthAuthProvider(
  profileId: string,
  binding: OAuthBinding,
  options: OAuthRuntimeOptions = {},
): AuthProvider {
  const runtime = { ...options, home: options.home ?? homedir() };
  const refreshTarget = `${oauthProfilePath(runtime.home, profileId)}.refresh`;
  const resource = binding.resource;
  const pinnedBinding: OAuthBinding = {
    serverUrl: canonicalUrl(binding.serverUrl),
    ...(resource === undefined ? {} : { resource: canonicalUrl(resource) }),
  };
  return {
    token: async () => {
      try {
        const profile = await readOAuthProfile(profileId, runtime);
        validateProfileBinding(profile, pinnedBinding);
        return profile.credentials.tokens.access_token;
      } catch {
        throw loginRequired(profileId);
      }
    },
    onUnauthorized: async (_context) => {
      try {
        await withPrivateFileLock(
          refreshTarget,
          async () => {
            const before = await readOAuthProfileSnapshot(profileId, runtime);
            const next = await refreshProfile(before.profile, pinnedBinding, runtime);
            const installed = await writeOAuthProfile(next, {
              ...runtime,
              before: before.snapshot,
            });
            return { before: before.snapshot, installed };
          },
          {
            ...(runtime.signal ? { signal: runtime.signal } : {}),
            timeoutMs: runtime.lockTimeoutMs ?? defaultTimeoutMs,
            rollback: async ({ before, installed }) => {
              await writePrivateFileAtomically({
                path: before.path,
                content: before.content,
                before: installed,
              });
            },
          },
        );
      } catch {
        throw loginRequired(profileId);
      }
    },
  };
}

async function refreshProfile(
  profile: OAuthProfile,
  binding: OAuthBinding,
  options: OAuthRuntimeOptions,
): Promise<OAuthProfile> {
  validateProfileBinding(profile, binding);
  const { issuer, metadata } = validateIssuers(profile);
  const refreshToken = profile.credentials.tokens.refresh_token;
  if (!refreshToken) throw new Error("OAuth refresh token is missing");

  const timeoutSignal = AbortSignal.timeout(options.refreshTimeoutMs ?? defaultTimeoutMs);
  const signal = AbortSignal.any(
    options.signal ? [options.signal, timeoutSignal] : [timeoutSignal],
  );
  signal.throwIfAborted();
  const refresh = options.refresh ?? refreshAuthorization;
  const fetchFn = cleanOAuthFetch(options.fetchFn ?? ((url, init) => fetch(url, init)), signal);
  const resource = oauthProfileResource(profile);
  const refreshPromise = refresh(profile.credentials.discoveryState.authorizationServerUrl, {
    metadata,
    clientInformation: profile.credentials.clientInformation,
    refreshToken,
    ...(resource === undefined ? {} : { resource: new URL(resource) }),
    fetchFn,
  });
  const tokens = await abortable(refreshPromise, signal);

  return {
    ...profile,
    credentials: {
      ...profile.credentials,
      tokens: {
        ...tokens,
        refresh_token: tokens.refresh_token ?? refreshToken,
        issuer,
      },
    },
  };
}

function validateProfileBinding(profile: OAuthProfile, binding: OAuthBinding): void {
  if (canonicalUrl(profile.metadata.serverUrl) !== canonicalUrl(binding.serverUrl)) {
    throw new Error(OAUTH_SERVER_BINDING_MISMATCH_MESSAGE);
  }
  if (
    canonicalOptionalUrl(oauthProfileResource(profile)) !== canonicalOptionalUrl(binding.resource)
  ) {
    throw new Error("OAuth resource binding mismatch");
  }
}

export function oauthProfileResource(profile: OAuthProfile): string | undefined {
  return profile.metadata.resource ?? profile.credentials.discoveryState.resourceMetadata?.resource;
}

function validateIssuers(profile: OAuthProfile): {
  issuer: string;
  metadata: AuthorizationServerMetadata;
} {
  const { clientInformation, tokens, discoveryState } = profile.credentials;
  const metadata = discoveryState.authorizationServerMetadata;
  const issuer = metadata?.issuer;
  if (
    !metadata ||
    typeof issuer !== "string" ||
    tokens.issuer !== issuer ||
    clientInformation.issuer !== issuer ||
    canonicalUrl(discoveryState.authorizationServerUrl) !== canonicalUrl(issuer)
  ) {
    throw new Error("OAuth issuer binding mismatch");
  }
  return { issuer, metadata };
}

function loginRequired(profileId: string): Error {
  return new Error(`OAuth credentials require login: mcp-restrictor oauth login ${profileId}`);
}
