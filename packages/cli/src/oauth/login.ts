import { randomBytes } from "node:crypto";
import {
  auth,
  checkResourceAllowed,
  type FetchLike,
  type OAuthClientMetadata,
  type OAuthClientProvider,
  type OAuthDiscoveryState,
  type StoredOAuthClientInformation,
  type StoredOAuthTokens,
} from "@modelcontextprotocol/client";

import { cleanOAuthFetch } from "./fetch.js";
import { ABORT_ERROR_NAME, abortable } from "../utils/async.js";
import {
  redactedCallback,
  selectCallback,
  validateCallback,
  type CallbackPlan,
} from "./login/callback.js";
import {
  joinedScopes,
  resolveDiscovery,
  validateDiscoveryState,
  type ValidatedDiscoveryState,
} from "./login/discovery.js";
import type { OAuthProfile, OAuthProfileMetadata } from "./storage.js";

export type OAuthLoginInput = {
  metadata: OAuthProfileMetadata;
  clientInformation?: StoredOAuthClientInformation;
  discoveryState?: OAuthDiscoveryState;
};

export type OAuthRedirectDelivery = "listener" | "paste";

export type OAuthLoginIO = {
  selectRedirectDelivery?(): Promise<OAuthRedirectDelivery>;
  confirmAuthorizationServer(details: {
    authorizationServerUrl: URL;
    resourceMetadataUrl?: URL;
    callbackUrl: URL;
    scope?: string;
  }): Promise<boolean>;
  writeAuthorizationUrl(url: URL): void | Promise<void>;
  readPastedRedirect(): Promise<URL>;
};

const loginTimeoutMs = 300_000;

class LocalCancellation extends Error {}

export async function loginOAuthProfile(options: {
  input: OAuthLoginInput;
  io: OAuthLoginIO;
  signal: AbortSignal;
  fetchFn?: FetchLike;
  timeoutMs?: number;
}): Promise<OAuthProfile> {
  const signal = AbortSignal.any([
    options.signal,
    AbortSignal.timeout(options.timeoutMs ?? loginTimeoutMs),
  ]);
  let callback: CallbackPlan | undefined;
  let clearProvider: (() => void) | undefined;
  let redirectDeliveryError: unknown;
  try {
    try {
      signal.throwIfAborted();
      const state = randomBytes(32).toString("base64url");
      let delivery: OAuthRedirectDelivery = "listener";
      if (options.io.selectRedirectDelivery) {
        try {
          delivery = await abortable(options.io.selectRedirectDelivery(), signal);
        } catch (error) {
          redirectDeliveryError = error;
          throw error;
        }
      }
      callback = await selectCallback(options.input.metadata, state, delivery);
      const fetchFn = cleanOAuthFetch(options.fetchFn ?? ((url, init) => fetch(url, init)), signal);
      const missingResourceMetadataUrls = new Set<string>();
      const discovery = await resolveDiscovery(options.input, fetchFn, missingResourceMetadataUrls);
      const customScope = options.input.metadata.authServerMetadataUrl
        ? joinedScopes(discovery.authorizationServerMetadata.scopes_supported)
        : undefined;
      const effectiveRequestedScope = options.input.metadata.requestedScope ?? customScope;
      const confirmationScope =
        effectiveRequestedScope ??
        joinedScopes(discovery.resourceMetadata?.scopes_supported) ??
        options.input.metadata.clientMetadata.scope;

      const confirmed = await abortable(
        options.io.confirmAuthorizationServer({
          authorizationServerUrl: new URL(discovery.authorizationServerMetadata.issuer),
          ...(discovery.resourceMetadataUrl
            ? { resourceMetadataUrl: new URL(discovery.resourceMetadataUrl) }
            : {}),
          callbackUrl: redactedCallback(callback.url),
          ...(confirmationScope ? { scope: confirmationScope } : {}),
        }),
        signal,
      );
      if (!confirmed) throw new LocalCancellation();

      const transient = transientProvider({
        metadata: options.input.metadata,
        callbackUrl: callback.url,
        state,
        io: options.io,
        ...(options.input.clientInformation
          ? { clientInformation: options.input.clientInformation }
          : {}),
        discoveryState: discovery,
      });
      clearProvider = transient.clear;
      const sdkFetchFn: FetchLike = async (url, init) => {
        signal.throwIfAborted();
        if (
          (!init?.method || init.method.toUpperCase() === "GET") &&
          missingResourceMetadataUrls.has(new URL(url).href)
        ) {
          return new Response(null, { status: 404 });
        }
        return fetchFn(url, init);
      };
      const authOptions = {
        serverUrl: options.input.metadata.serverUrl,
        ...(effectiveRequestedScope ? { scope: effectiveRequestedScope } : {}),
        ...(discovery.resourceMetadataUrl
          ? { resourceMetadataUrl: new URL(discovery.resourceMetadataUrl) }
          : {}),
        fetchFn: sdkFetchFn,
      };
      const first = await abortable(auth(transient.provider, authOptions), signal);
      if (first !== "REDIRECT") throw new Error("OAuth redirect was not started");

      const redirect = await callback.receive(options.io, signal);
      const result = validateCallback(redirect, callback.url, state);
      transient.saveAuthorizationCode(result.code);
      const second = await abortable(
        auth(transient.provider, {
          ...authOptions,
          authorizationCode: transient.authorizationCode(),
          ...(result.iss === undefined ? {} : { iss: result.iss }),
        }),
        signal,
      );
      if (second !== "AUTHORIZED") throw new Error("OAuth authorization did not complete");

      const credentials = transient.credentials();
      return {
        metadata: {
          ...options.input.metadata,
          ...(effectiveRequestedScope === undefined
            ? {}
            : { requestedScope: effectiveRequestedScope }),
          callbackUrl: callback.url.href,
        },
        credentials,
      };
    } finally {
      clearProvider?.();
      await callback?.close();
      callback = undefined;
    }
  } catch (error) {
    if (
      error instanceof Error &&
      error.name === ABORT_ERROR_NAME &&
      (error === redirectDeliveryError ||
        (options.signal.aborted && error === options.signal.reason))
    ) {
      throw error;
    }
    if (error instanceof LocalCancellation || options.signal.aborted) {
      throw new Error("OAuth login cancelled");
    }
    throw new Error("OAuth login failed");
  }
}

function transientProvider(options: {
  metadata: OAuthProfileMetadata;
  callbackUrl: URL;
  state: string;
  io: OAuthLoginIO;
  clientInformation?: StoredOAuthClientInformation;
  discoveryState: ValidatedDiscoveryState;
}): {
  provider: OAuthClientProvider;
  credentials(): OAuthProfile["credentials"];
  saveAuthorizationCode(code: string): void;
  authorizationCode(): string;
  clear(): void;
} {
  const clientMetadata: OAuthClientMetadata = {
    ...options.metadata.clientMetadata,
    redirect_uris: [options.callbackUrl.href],
  };
  let state: string | undefined = options.state;
  let clientInformation = options.clientInformation;
  let tokens: StoredOAuthTokens | undefined;
  let verifier: string | undefined;
  let authorizationCode: string | undefined;
  let discoveryState: OAuthDiscoveryState | undefined = options.discoveryState;
  let authorizationUrl: URL | undefined;
  const provider: OAuthClientProvider = {
    get redirectUrl() {
      return options.callbackUrl.href;
    },
    get clientMetadata() {
      return clientMetadata;
    },
    state: () => {
      if (!state) throw new Error("OAuth state is unavailable");
      return state;
    },
    clientInformation: () => clientInformation,
    saveClientInformation: (value) => {
      clientInformation = value;
    },
    tokens: () => tokens,
    saveTokens: (value) => {
      tokens = value;
    },
    redirectToAuthorization: async (url) => {
      authorizationUrl = new URL(url);
      await options.io.writeAuthorizationUrl(new URL(authorizationUrl));
    },
    saveCodeVerifier: (value) => {
      verifier = value;
    },
    codeVerifier: () => {
      if (!verifier) throw new Error("OAuth verifier is unavailable");
      return verifier;
    },
    saveDiscoveryState: (value) => {
      discoveryState = validateDiscoveryState(value);
    },
    discoveryState: () => discoveryState,
    validateResourceURL: (serverUrl, discoveredResource) => {
      const configuredResource = options.metadata.resource;
      if (
        configuredResource &&
        discoveredResource &&
        !checkResourceAllowed({
          requestedResource: discoveredResource,
          configuredResource,
        })
      ) {
        throw new Error("OAuth resource mismatch");
      }
      const selectedResource = configuredResource ?? discoveredResource;
      if (!selectedResource) return Promise.resolve(undefined);
      if (
        !checkResourceAllowed({
          requestedResource: serverUrl,
          configuredResource: selectedResource,
        })
      ) {
        throw new Error("OAuth resource mismatch");
      }
      return Promise.resolve(new URL(selectedResource));
    },
  };
  return {
    provider,
    credentials: () => {
      if (!clientInformation || !tokens || !discoveryState) {
        throw new Error("OAuth credentials are incomplete");
      }
      return { clientInformation, tokens, discoveryState };
    },
    saveAuthorizationCode: (value) => {
      authorizationCode = value;
    },
    authorizationCode: () => {
      if (!authorizationCode) throw new Error("OAuth authorization code is unavailable");
      return authorizationCode;
    },
    clear: () => {
      state = undefined;
      verifier = undefined;
      authorizationCode = undefined;
      authorizationUrl = undefined;
    },
  };
}
