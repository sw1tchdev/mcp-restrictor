import { randomUUID } from "node:crypto";
import type { Writable } from "node:stream";
import type { StoredOAuthClientInformation } from "@modelcontextprotocol/client";
import { discoverToolNames, type UpstreamConfig } from "@mcp-restrictor/transports";
import { UpstreamProtocolIncompatibleError } from "../client-adapter.js";
import {
  loginOAuthProfile,
  type OAuthLoginIO,
  type OAuthRedirectDelivery,
} from "../oauth/login.js";
import {
  assertOAuthStorageReady,
  configuredMasterKeyFile,
  MASTER_KEY_FILE_ENV,
  prepareOAuthStorageForSetup,
  readOAuthProfileSnapshot,
  type OAuthProfile,
  type OAuthProfileMetadata,
  type OAuthStorageOptions,
} from "../oauth/storage.js";
import { canonicalOptionalUrl } from "../oauth/urls.js";
import { OAUTH_SERVER_BINDING_MISMATCH_MESSAGE } from "../oauth/constants.js";
import { CONTAINER_MARKER_ENV, OAUTH_UPSTREAM_REQUIRED_MESSAGE } from "./constants.js";
import { SetupCancelled, type SetupInteraction } from "./interaction.js";
import { quoted, redactedUrl } from "./presentation.js";
import { withOAuthProfile } from "./remote.js";
import type { ServerCandidate, SourceSpec } from "./wrapper.js";
import { ABORT_ERROR_NAME } from "../utils/async.js";
import {
  challengeProbeUpstream,
  isAbort,
  OAuthChallengeRequired,
  probeSseChallenge,
} from "./discovery/challenge.js";

export { isAbort } from "./discovery/challenge.js";

export type SetupTarget = {
  client?: string;
  name: string;
  source: SourceSpec;
  upstream: UpstreamConfig;
  alternatives?: ServerCandidate["alternatives"];
  wrapperEnvironment: { env?: Record<string, string> };
  oauth?: ServerCandidate["oauth"];
  context: string;
};

export type PreparedServer = {
  tools: string[];
  source: SourceSpec;
  upstream: UpstreamConfig;
  oauthProfile?: OAuthProfile;
  oauthBaseline?: Awaited<ReturnType<typeof readOAuthProfileSnapshot>>;
  storage?: OAuthStorageOptions;
};

export type DiscoveryOptions = {
  home: string;
  environment: NodeJS.ProcessEnv;
  signal: AbortSignal;
  stderr: Writable;
  login: typeof loginOAuthProfile;
  usesTui: boolean;
  readSecret(question: string): Promise<string>;
  selectIndexes: SetupInteraction["selectIndexes"];
  confirm(message: string): Promise<boolean>;
  write(value: string): void;
};

class OAuthReloginRequired extends Error {}

const oauthClientMetadata = {
  client_name: "MCP Restrictor",
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
};

export async function discoverSetupServer(
  server: SetupTarget,
  options: DiscoveryOptions,
): Promise<PreparedServer> {
  if (
    server.source.kind !== "stdio" &&
    server.source.kind !== "websocket" &&
    server.source.oauthProfileId
  ) {
    return discoverManagedOAuthServer(server, options);
  }
  if (!server.oauth) {
    return discoverAlternatives(server, options);
  }

  const storage = oauthStorage(server, options.home, options.environment);
  if (server.oauth.mode === "challenge") {
    const candidates = serverCandidates(server);
    for (let index = 0; index < candidates.length; index += 1) {
      const candidate = candidates[index]!;
      try {
        if (candidate.upstream.kind === "sse") {
          await probeSseChallenge(candidate.upstream, options.signal);
        }
        return {
          tools: await discover(
            server,
            protocolUpstream(server, challengeProbeUpstream(candidate.upstream), index),
            options,
            (error) => error instanceof OAuthChallengeRequired,
          ),
          ...candidate,
        };
      } catch (error) {
        if (isProtocolIncompatible(error) && index + 1 < candidates.length) continue;
        if (!(error instanceof OAuthChallengeRequired)) throw error;
        return loginAndDiscover(
          { ...server, ...candidate, alternatives: candidates.slice(index + 1) },
          options,
          storage,
          {
            profileId: randomUUID(),
            ...(error.scope ? { requestedScope: error.scope } : {}),
            resourceMetadataUrl: error.resourceMetadataUrl,
          },
        );
      }
    }
    throw new Error(`Tool discovery failed for ${server.context}`);
  }

  return loginAndDiscover(server, options, storage, { profileId: randomUUID() });
}

async function discoverManagedOAuthServer(
  server: SetupTarget,
  options: DiscoveryOptions,
): Promise<PreparedServer> {
  if (server.source.kind === "stdio" || server.source.kind === "websocket") {
    throw new Error(`OAuth profile is invalid for ${server.context}`);
  }
  const profileId = server.source.oauthProfileId!;
  const storage = oauthStorage(server, options.home, options.environment);
  const baseline = await readOAuthProfileSnapshot(profileId, storage);
  requireProfileBinding(
    baseline.profile,
    remoteUrl(server.upstream),
    baseline.profile.metadata.resource,
  );
  try {
    const upstream = profileUpstream(server.upstream, baseline.profile, true);
    return {
      tools: await discover(
        server,
        upstream,
        options,
        (error) => error instanceof OAuthReloginRequired,
      ),
      source: server.source,
      upstream,
      oauthProfile: baseline.profile,
      oauthBaseline: baseline,
      storage,
    };
  } catch (error) {
    if (!(error instanceof OAuthReloginRequired)) throw error;
  }

  await assertOAuthStorageReady(storage);
  const profile = await options.login({
    input: {
      metadata: baseline.profile.metadata,
      clientInformation: baseline.profile.credentials.clientInformation,
      discoveryState: baseline.profile.credentials.discoveryState,
    },
    io: oauthIO(options),
    signal: options.signal,
  });
  requireProfileId(profile, profileId);
  requireProfileBinding(profile, remoteUrl(server.upstream), baseline.profile.metadata.resource);
  const upstream = profileUpstream(server.upstream, profile);
  return {
    tools: await discover(server, upstream, options),
    source: server.source,
    upstream,
    oauthProfile: profile,
    oauthBaseline: baseline,
    storage,
  };
}

async function loginAndDiscover(
  server: SetupTarget,
  options: DiscoveryOptions,
  storage: OAuthStorageOptions,
  challenge: {
    profileId: string;
    requestedScope?: string;
    resourceMetadataUrl?: string;
  },
): Promise<PreparedServer> {
  await prepareOAuthStorageForSetup(storage);
  const hint = server.oauth!;
  let clientInformation: StoredOAuthClientInformation | undefined;
  if (hint.clientId) {
    let secret = hint.clientSecret;
    if (secret === undefined) {
      if (options.usesTui) {
        const [choice] = await options.selectIndexes(
          "OAuth client secret",
          ["No client secret", "Enter client secret"],
          { allowNone: false, single: true },
        );
        secret = choice === 1 ? await options.readSecret("OAuth client secret: ") : "";
      } else {
        secret = await options.readSecret("Optional OAuth client secret (leave empty for none): ");
      }
    }
    clientInformation = {
      client_id: hint.clientId,
      ...(secret ? { client_secret: secret } : {}),
    };
  }
  const metadata: OAuthProfileMetadata = {
    version: 1,
    profileId: challenge.profileId,
    serverUrl: remoteUrl(server.upstream),
    ...((challenge.requestedScope ?? hint.requestedScope)
      ? { requestedScope: challenge.requestedScope ?? hint.requestedScope }
      : {}),
    ...(hint.resource ? { resource: hint.resource } : {}),
    ...((challenge.resourceMetadataUrl ?? hint.resourceMetadataUrl)
      ? { resourceMetadataUrl: challenge.resourceMetadataUrl ?? hint.resourceMetadataUrl }
      : {}),
    ...(hint.authServerMetadataUrl ? { authServerMetadataUrl: hint.authServerMetadataUrl } : {}),
    callback: hint.callback,
    clientMetadata: {
      ...oauthClientMetadata,
      ...(hint.fallbackScope ? { scope: hint.fallbackScope } : {}),
    },
  };
  const profile = await options.login({
    input: {
      metadata,
      ...(clientInformation ? { clientInformation } : {}),
    },
    io: oauthIO(options),
    signal: options.signal,
  });
  requireProfileId(profile, challenge.profileId);
  requireProfileBinding(profile, metadata.serverUrl, hint.resource);
  const discovered = await discoverAlternatives(server, options, (upstream) =>
    profileUpstream(upstream, profile),
  );
  return {
    ...discovered,
    source: withOAuthProfile(discovered.source, challenge.profileId),
    oauthProfile: profile,
    storage,
  };
}

async function discoverAlternatives(
  server: SetupTarget,
  options: DiscoveryOptions,
  transform: (upstream: UpstreamConfig) => UpstreamConfig = (upstream) => upstream,
): Promise<PreparedServer> {
  const candidates = serverCandidates(server);
  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index]!;
    const upstream = protocolUpstream(server, transform(candidate.upstream), index);
    try {
      return {
        tools: await discover(server, upstream, options),
        source: candidate.source,
        upstream,
      };
    } catch (error) {
      if (!isProtocolIncompatible(error) || index + 1 === candidates.length) throw error;
    }
  }
  throw new Error(`Tool discovery failed for ${server.context}`);
}

function serverCandidates(
  server: SetupTarget,
): Array<{ source: SourceSpec; upstream: UpstreamConfig }> {
  return [{ source: server.source, upstream: server.upstream }, ...(server.alternatives ?? [])];
}

function protocolUpstream(
  server: SetupTarget,
  upstream: UpstreamConfig,
  index: number,
): UpstreamConfig {
  if (
    server.client !== "opencode" ||
    !server.alternatives?.length ||
    index !== 0 ||
    upstream.kind !== "http"
  )
    return upstream;
  const validate = upstream.validateResponse;
  return {
    ...upstream,
    validateResponse: async (response) => {
      if ([404, 405, 406, 415].includes(response.status)) {
        await response.body?.cancel();
        throw new UpstreamProtocolIncompatibleError();
      }
      await validate?.(response);
    },
  };
}

function isProtocolIncompatible(error: unknown): boolean {
  const first = error instanceof AggregateError ? error.errors[0] : error;
  return first instanceof UpstreamProtocolIncompatibleError;
}

function oauthIO(options: DiscoveryOptions): OAuthLoginIO {
  return {
    ...(options.usesTui
      ? {
          selectRedirectDelivery: async (): Promise<OAuthRedirectDelivery> => {
            try {
              const [choice] = await options.selectIndexes(
                "OAuth redirect delivery",
                ["Loopback listener", "Paste redirected URL"],
                { allowNone: false, single: true, defaultIndexes: [0] },
              );
              return choice === 1 ? "paste" : "listener";
            } catch (error) {
              if (error instanceof SetupCancelled) {
                throw new DOMException("Aborted", ABORT_ERROR_NAME);
              }
              throw error;
            }
          },
        }
      : {}),
    confirmAuthorizationServer: async (details) => {
      options.write(
        `OAuth authorization server: ${quoted(details.authorizationServerUrl.origin)}\n`,
      );
      if (details.resourceMetadataUrl) {
        options.write(
          `OAuth resource metadata: ${quoted(redactedUrl(details.resourceMetadataUrl.href))}\n`,
        );
      }
      options.write(`OAuth callback: ${quoted(redactedUrl(details.callbackUrl.href))}\n`);
      if (details.scope) options.write(`OAuth scope: ${quoted(details.scope)}\n`);
      return options.confirm("Continue with OAuth authorization?");
    },
    writeAuthorizationUrl: (url) => {
      options.write(`Open this URL to authorize:\n${url.href}\n`);
    },
    readPastedRedirect: async () =>
      new URL((await options.readSecret("Paste the final redirect URL: ")).trim()),
  };
}

async function discover(
  server: SetupTarget,
  upstream: UpstreamConfig,
  options: Pick<DiscoveryOptions, "signal" | "stderr">,
  preserveError?: (error: unknown) => boolean,
): Promise<string[]> {
  try {
    return await discoverToolNames(upstream, {
      signal: options.signal,
      stderr: options.stderr,
      preserveError: (error) => isProtocolIncompatible(error) || Boolean(preserveError?.(error)),
    });
  } catch (error) {
    if (isAbort(error, options.signal) || isProtocolIncompatible(error) || preserveError?.(error)) {
      throw error;
    }
    throw new Error(`Tool discovery failed for ${server.context}`);
  }
}

function profileUpstream(
  upstream: UpstreamConfig,
  profile: OAuthProfile,
  reloginOnUnauthorized = false,
): UpstreamConfig {
  if (upstream.kind !== "http" && upstream.kind !== "sse") {
    throw new Error(OAUTH_UPSTREAM_REQUIRED_MESSAGE);
  }
  return {
    ...upstream,
    authProviderFactory: () => ({
      token: async () => profile.credentials.tokens.access_token,
      ...(reloginOnUnauthorized
        ? {
            onUnauthorized: async () => {
              throw new OAuthReloginRequired();
            },
          }
        : {}),
    }),
  };
}

function remoteUrl(upstream: UpstreamConfig): string {
  if (upstream.kind !== "http" && upstream.kind !== "sse") {
    throw new Error(OAUTH_UPSTREAM_REQUIRED_MESSAGE);
  }
  return new URL(upstream.url).href;
}

function oauthStorage(
  server: SetupTarget,
  home: string,
  environment: NodeJS.ProcessEnv,
): OAuthStorageOptions {
  const configured =
    configuredMasterKeyFile(server.wrapperEnvironment.env ?? {}) ??
    configuredMasterKeyFile(environment);
  const snapshot: NodeJS.ProcessEnv = {};
  if (configured) snapshot[MASTER_KEY_FILE_ENV] = configured;
  if (Object.hasOwn(environment, CONTAINER_MARKER_ENV)) {
    snapshot[CONTAINER_MARKER_ENV] = environment[CONTAINER_MARKER_ENV];
  }
  return { home, environment: snapshot };
}

function requireProfileId(profile: OAuthProfile, profileId: string): void {
  if (profile.metadata.profileId !== profileId) {
    throw new Error("OAuth login returned a different profile ID");
  }
}

function requireProfileBinding(profile: OAuthProfile, serverUrl: string, resource?: string): void {
  try {
    if (
      new URL(profile.metadata.serverUrl).href !== new URL(serverUrl).href ||
      canonicalOptionalUrl(profile.metadata.resource) !== canonicalOptionalUrl(resource)
    )
      throw new Error();
  } catch {
    throw new Error(OAUTH_SERVER_BINDING_MISMATCH_MESSAGE);
  }
}
