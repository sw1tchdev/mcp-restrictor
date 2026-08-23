import { once } from "node:events";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  auth,
  checkResourceAllowed,
  type FetchLike,
  type OAuthDiscoveryState,
  type StoredOAuthClientInformation,
} from "@modelcontextprotocol/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { loginOAuthProfile, type OAuthLoginIO, type OAuthLoginInput } from "../src/oauth/login.js";
import { cleanOAuthFetch } from "../src/oauth/fetch.js";
import { selectCallback } from "../src/oauth/login/callback.js";
import type { OAuthProfileMetadata } from "../src/oauth/storage.js";
import { closeServer } from "./helpers.js";

vi.mock("@modelcontextprotocol/client", { spy: true });

const actualSdk = await vi.importActual<typeof import("@modelcontextprotocol/client")>(
  "@modelcontextprotocol/client",
);
const profileId = "11111111-1111-4111-8111-111111111111";
const sensitiveValues = [
  "authorization-code-secret",
  "client-secret-value",
  "verifier-secret-value",
  "access-token-secret",
  "refresh-token-secret",
  "https://callback.example/complete?code=authorization-code-secret",
] as const;
const openServers = new Set<Server>();

beforeEach(() => {
  vi.mocked(auth).mockReset();
  vi.mocked(auth).mockImplementation(actualSdk.auth);
  vi.mocked(checkResourceAllowed).mockReset();
  vi.mocked(checkResourceAllowed).mockImplementation(actualSdk.checkResourceAllowed);
});

afterEach(async () => {
  await Promise.all(
    [...openServers].map(async (server) => {
      openServers.delete(server);
      await closeServer(server).catch(() => undefined);
    }),
  );
});

describe("cleanOAuthFetch", () => {
  it("forces the supplied signal and redirect rejection while preserving OAuth request data", async () => {
    const controller = new AbortController();
    const delegate = vi.fn<FetchLike>().mockResolvedValue(new Response(null, { status: 204 }));
    const wrapped = cleanOAuthFetch(delegate, controller.signal);

    await wrapped("https://auth.example/token", {
      method: "POST",
      headers: { Authorization: "Basic generated-by-sdk", "X-OAuth": "kept" },
      body: "grant_type=authorization_code",
      redirect: "follow",
      signal: new AbortController().signal,
    });

    expect(delegate).toHaveBeenCalledOnce();
    expect(delegate).toHaveBeenCalledWith(
      "https://auth.example/token",
      expect.objectContaining({
        method: "POST",
        body: "grant_type=authorization_code",
        redirect: "error",
        signal: controller.signal,
      }),
    );
    expect(new Headers(delegate.mock.calls[0]![1]?.headers)).toEqual(
      new Headers({ Authorization: "Basic generated-by-sdk", "X-OAuth": "kept" }),
    );
  });
});

describe("the transient OAuth provider", () => {
  it("implements the pinned SDK contract without persisting derived redirect metadata", async () => {
    const callbackUrl = new URL("https://callback.example/complete?tenant=private-value");
    const finalCallbackUrl = new URL(
      `https://callback.example/complete/mcp-restrictor/${profileId}?tenant=private-value`,
    );
    const discoveryState = safeDiscoveryState();
    const clientInformation: StoredOAuthClientInformation = {
      client_id: "pre-registered-client",
      client_secret: "client-secret-value",
    };
    const observations: Record<string, unknown> = {};
    let calls = 0;
    vi.mocked(auth).mockImplementation(async (provider, options) => {
      calls += 1;
      observations.redirectUrl = provider.redirectUrl;
      observations.clientMetadata = provider.clientMetadata;
      observations.state = await provider.state?.();
      if (calls === 1) {
        observations.clientInformation = await provider.clientInformation({
          issuer: "https://auth.example/",
        });
      }
      observations.discoveryState = await provider.discoveryState?.();
      observations.resource = await provider.validateResourceURL?.(
        "https://resource.example/mcp/tools",
        "https://resource.example/mcp",
      );
      expect(() =>
        provider.validateResourceURL?.(
          "https://resource.example/mcp/tools",
          "https://attacker.example/mcp",
        ),
      ).toThrow();
      if (calls === 1) {
        await provider.saveClientInformation?.(
          { client_id: "saved-client", issuer: "https://auth.example/" },
          { issuer: "https://auth.example/" },
        );
        observations.savedClient = await provider.clientInformation({
          issuer: "https://auth.example/",
        });
        await provider.saveCodeVerifier("verifier-secret-value");
        observations.verifier = await provider.codeVerifier();
        expect(() =>
          provider.saveDiscoveryState?.({
            ...discoveryState,
            authorizationServerMetadata: {
              ...discoveryState.authorizationServerMetadata!,
              token_endpoint: "http://auth.example/token",
            },
          }),
        ).toThrow();
        await provider.saveDiscoveryState?.(discoveryState);
        const authorizationUrl = new URL("https://auth.example/authorize");
        authorizationUrl.searchParams.set("redirect_uri", String(provider.redirectUrl));
        authorizationUrl.searchParams.set("state", String(observations.state));
        await provider.redirectToAuthorization(authorizationUrl);
        return "REDIRECT";
      }
      await provider.saveTokens(
        {
          access_token: "access-token-secret",
          refresh_token: "refresh-token-secret",
          token_type: "Bearer",
          issuer: "https://auth.example/",
        },
        { issuer: "https://auth.example/" },
      );
      observations.tokens = await provider.tokens({ issuer: "https://auth.example/" });
      observations.secondOptions = options;
      return "AUTHORIZED";
    });
    const io = pasteIo((authorizationUrl) => {
      const redirect = pastedCallback(authorizationUrl);
      redirect.searchParams.set("iss", "https://auth.example/");
      return redirect;
    });
    const metadata = baseMetadata({
      serverUrl: "https://resource.example/mcp/tools",
      requestedScope: "read write",
      resource: "https://resource.example/mcp",
      resourceMetadataUrl: "https://resource.example/metadata",
      callback: { url: callbackUrl.href, appendProfileId: true },
      clientMetadata: {
        client_name: "MCP Restrictor",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      },
    });

    const profile = await loginOAuthProfile({
      input: { metadata, clientInformation, discoveryState },
      io,
      signal: new AbortController().signal,
      fetchFn: vi.fn(() => Promise.reject(new Error("unexpected network request"))),
    });

    expect(observations.redirectUrl).toBe(finalCallbackUrl.href);
    expect(observations.clientMetadata).toEqual({
      ...metadata.clientMetadata,
      redirect_uris: [finalCallbackUrl.href],
    });
    expect(observations.state).toMatch(/^[A-Za-z0-9_-]{32,}$/);
    expect(observations.clientInformation).toEqual(clientInformation);
    expect(observations.savedClient).toMatchObject({ client_id: "saved-client" });
    expect(observations.verifier).toBe("verifier-secret-value");
    expect(observations.discoveryState).toEqual(discoveryState);
    expect(observations.resource).toEqual(new URL("https://resource.example/mcp"));
    expect(observations.tokens).toMatchObject({ access_token: "access-token-secret" });
    expect(checkResourceAllowed).toHaveBeenCalledWith({
      requestedResource: "https://resource.example/mcp/tools",
      configuredResource: "https://resource.example/mcp",
    });
    expect(observations.secondOptions).toEqual(
      expect.objectContaining({
        serverUrl: metadata.serverUrl,
        authorizationCode: "authorization-code-secret",
        iss: "https://auth.example/",
        scope: "read write",
        resourceMetadataUrl: new URL(metadata.resourceMetadataUrl!),
      }),
    );
    expect(profile.metadata.clientMetadata).toEqual(metadata.clientMetadata);
    expect(profile.metadata.clientMetadata).not.toHaveProperty("redirect_uris");
    expect(profile.metadata.callbackUrl).toBe(finalCallbackUrl.href);
    expect(io.confirmations[0]?.callbackUrl.searchParams.get("tenant")).toBe("REDACTED");
    expect(io.confirmations[0]?.callbackUrl.searchParams.has("tenant")).toBe(true);
  });
});

describe("authorization-server discovery and confirmation", () => {
  it("rejects a remote plaintext authorization server before requesting it", async () => {
    const requests: string[] = [];
    const fetchFn = discoveryFetch({
      requests,
      authorizationServerUrl: "http://auth.example/",
    });
    const io = pasteIo(() => new URL("https://callback.example/complete"));

    await expect(loginWith({ metadata: syntheticMetadata(), io, fetchFn })).rejects.toThrow(
      "OAuth login failed",
    );

    expect(requests).toEqual(["http://127.0.0.1:49151/resource-metadata"]);
    expect(io.confirmations).toHaveLength(0);
    expect(auth).not.toHaveBeenCalled();
  });

  it.each([
    ["issuer", { issuer: "http://auth.example/" }],
    ["authorization endpoint", { authorization_endpoint: "http://auth.example/authorize" }],
    ["registration endpoint", { registration_endpoint: "http://auth.example/register" }],
    ["token endpoint", { token_endpoint: "http://auth.example/token" }],
  ])("rejects an unsafe default-discovery %s before confirmation", async (_name, override) => {
    const requests: string[] = [];
    const io = pasteIo(() => new URL("https://callback.example/complete"));
    const fetchFn = discoveryFetch({ requests, authorizationMetadata: override });

    await expect(loginWith({ metadata: syntheticMetadata(), io, fetchFn })).rejects.toThrow(
      "OAuth login failed",
    );

    expect(requests).toHaveLength(2);
    expect(io.confirmations).toHaveLength(0);
    expect(auth).not.toHaveBeenCalled();
  });

  it("accepts exact loopback metadata and confirms before any SDK OAuth operation", async () => {
    const events: string[] = [];
    const io = pasteIo(() => new URL("https://callback.example/complete"), {
      confirm: false,
      events,
    });
    const fetchFn = discoveryFetch({ requests: events });

    await expect(loginWith({ metadata: syntheticMetadata(), io, fetchFn })).rejects.toThrow(
      "OAuth login cancelled",
    );

    expect(events.at(-1)).toBe("confirm");
    expect(io.written).toHaveLength(0);
    expect(io.reads).toBe(0);
    expect(auth).not.toHaveBeenCalled();
  });

  it("normalizes only the SDK protected-metadata 404 and rejects other discovery failures", async () => {
    const noMetadataFetch = vi.fn<FetchLike>(async (url) => {
      const target = new URL(url);
      if (target.pathname.includes("oauth-protected-resource")) {
        return new Response(null, { status: 404 });
      }
      return jsonResponse(safeAuthorizationMetadata("http://127.0.0.1:49151/"));
    });
    const noMetadataIo = pasteIo(() => new URL("https://callback.example/complete"), {
      confirm: false,
    });
    const fallback = baseMetadata({
      serverUrl: "http://127.0.0.1:49151/mcp",
      callback: { url: "https://callback.example/complete", appendProfileId: true },
    });

    await expect(
      loginWith({ metadata: fallback, io: noMetadataIo, fetchFn: noMetadataFetch }),
    ).rejects.toThrow("OAuth login cancelled");
    expect(noMetadataIo.confirmations[0]?.authorizationServerUrl.href).toBe(
      "http://127.0.0.1:49151/",
    );

    const brokenFetch = vi
      .fn<FetchLike>()
      .mockResolvedValue(new Response("temporary failure", { status: 503 }));
    await expect(
      loginWith({ metadata: fallback, io: noMetadataIo, fetchFn: brokenFetch }),
    ).rejects.toThrow("OAuth login failed");
  });

  it("replays a protected-metadata 404 without changing resource semantics", async () => {
    const fixture = await startOAuthFixture({
      fallbackAuthorizationServer: true,
      resourceMetadata404Once: true,
      lateResourceScopes: ["late-scope"],
      tokenEndpointAtResourceMetadataUrl: true,
    });
    const collidingTokenRequests: string[] = [];
    const fetchFn: FetchLike = async (input, init) => {
      if (new URL(input).href === fixture.resourceMetadataUrl && init?.method === "POST") {
        collidingTokenRequests.push(String(init.body));
        return jsonResponse({
          access_token: "access-token-secret",
          refresh_token: "refresh-token-secret",
          token_type: "Bearer",
          expires_in: 3600,
        });
      }
      return fetch(input, init);
    };
    const io = pasteIo(pastedCallback);
    const metadata = baseMetadata({
      serverUrl: fixture.serverUrl,
      resourceMetadataUrl: fixture.resourceMetadataUrl,
      authServerMetadataUrl: fixture.customMetadataUrl,
      callback: { url: "https://callback.example/complete", appendProfileId: true },
      clientMetadata: {
        client_name: "MCP Restrictor",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        scope: "client-fallback",
      },
    });

    const profile = await loginWith({
      metadata,
      clientInformation: { client_id: "pre-registered-client" },
      io,
      fetchFn,
    });

    expect(fixture.resourceMetadataRequests).toBe(1);
    expect(io.confirmations[0]?.scope).toBe("client-fallback");
    const authorizationUrl = new URL(io.written[0]!);
    expect(authorizationUrl.searchParams.get("scope")).toBe("client-fallback");
    expect(authorizationUrl.searchParams.has("resource")).toBe(false);
    expect(collidingTokenRequests).toHaveLength(1);
    expect(new URLSearchParams(collidingTokenRequests[0]).has("resource")).toBe(false);
    expect(profile.credentials.discoveryState).not.toHaveProperty("resourceMetadata");
    expect(profile.credentials.discoveryState.resourceMetadataUrl).toBe(
      fixture.resourceMetadataUrl,
    );
    await fixture.close();
  });

  it.each(["resourceMetadataUrl", "authServerMetadataUrl"] as const)(
    "rejects an unsafe configured %s before using cached discovery",
    async (field) => {
      const fetchFn = vi.fn<FetchLike>();
      const io = pasteIo(pastedCallback, { confirm: false });
      const metadata = baseMetadata({
        serverUrl: "https://resource.example/mcp",
        [field]: "http://metadata.example/unsafe",
      });

      await expect(
        loginWith({
          metadata,
          discoveryState: safeDiscoveryState(),
          io,
          fetchFn,
        }),
      ).rejects.toThrow("OAuth login failed");

      expect(fetchFn).not.toHaveBeenCalled();
      expect(io.confirmations).toHaveLength(0);
    },
  );

  it("refetches a changed protected-metadata source instead of using cached discovery", async () => {
    const changedUrl = "http://127.0.0.1:49151/changed-resource-metadata";
    const requests: string[] = [];
    const fetchFn: FetchLike = async (input) => {
      const url = new URL(input);
      requests.push(url.href);
      if (url.href === changedUrl) {
        return jsonResponse({
          resource: "http://127.0.0.1:49151/mcp",
          authorization_servers: ["http://127.0.0.1:49152/"],
          scopes_supported: ["current-scope"],
        });
      }
      return jsonResponse(safeAuthorizationMetadata("http://127.0.0.1:49152/"));
    };
    const io = pasteIo(pastedCallback, { confirm: false });
    const metadata = baseMetadata({
      serverUrl: "http://127.0.0.1:49151/mcp",
      resourceMetadataUrl: changedUrl,
    });

    await expect(
      loginWith({
        metadata,
        discoveryState: safeDiscoveryState(),
        io,
        fetchFn,
      }),
    ).rejects.toThrow("OAuth login cancelled");

    expect(requests[0]).toBe(changedUrl);
    expect(io.confirmations[0]?.authorizationServerUrl.href).toBe("http://127.0.0.1:49152/");
  });

  it("exact-fetches configured authorization metadata even with cached discovery", async () => {
    const exactUrl = "https://auth.example/exact-metadata";
    const requests: string[] = [];
    const fetchFn: FetchLike = async (input) => {
      requests.push(new URL(input).href);
      return jsonResponse(safeAuthorizationMetadata("https://auth.example/"));
    };
    const io = pasteIo(pastedCallback, { confirm: false });
    const metadata = baseMetadata({
      serverUrl: "https://resource.example/mcp",
      authServerMetadataUrl: exactUrl,
    });

    await expect(
      loginWith({
        metadata,
        discoveryState: safeDiscoveryState(),
        io,
        fetchFn,
      }),
    ).rejects.toThrow("OAuth login cancelled");

    expect(requests).toEqual([exactUrl]);
    expect(requests.some((value) => value.includes(".well-known/"))).toBe(false);
  });

  it("revalidates configured authorization metadata fetched over cached discovery", async () => {
    const exactUrl = "https://auth.example/exact-metadata";
    const fetchFn = vi.fn<FetchLike>().mockResolvedValue(
      jsonResponse({
        ...safeAuthorizationMetadata("https://auth.example/"),
        token_endpoint: "http://auth.example/token",
      }),
    );
    const io = pasteIo(pastedCallback, { confirm: false });
    const metadata = baseMetadata({
      serverUrl: "https://resource.example/mcp",
      authServerMetadataUrl: exactUrl,
    });

    await expect(
      loginWith({
        metadata,
        discoveryState: safeDiscoveryState(),
        io,
        fetchFn,
      }),
    ).rejects.toThrow("OAuth login failed");

    expect(fetchFn).toHaveBeenCalledOnce();
    expect(io.confirmations).toHaveLength(0);
  });

  it.each([undefined, "https://resource.example/metadata"])(
    "reuses compatible cached discovery when the current resource source is %s",
    async (resourceMetadataUrl) => {
      const fetchFn = vi.fn<FetchLike>();
      const io = pasteIo(pastedCallback, { confirm: false });
      const metadata = baseMetadata({
        serverUrl: "https://resource.example/mcp",
        ...(resourceMetadataUrl ? { resourceMetadataUrl } : {}),
      });

      await expect(
        loginWith({
          metadata,
          discoveryState: safeDiscoveryState(),
          io,
          fetchFn,
        }),
      ).rejects.toThrow("OAuth login cancelled");

      expect(fetchFn).not.toHaveBeenCalled();
    },
  );
});

describe("custom authorization metadata and scope selection", () => {
  it.each([
    [
      "configured scope",
      "configured read",
      ["custom"],
      ["resource"],
      "configured read",
      "configured read",
    ],
    [
      "custom metadata scope",
      undefined,
      ["custom", "write"],
      ["resource"],
      "custom write",
      "custom write",
    ],
    [
      "protected-resource before client fallback",
      undefined,
      undefined,
      ["resource", "read"],
      undefined,
      undefined,
    ],
  ])(
    "uses %s precedence without turning a Codex fallback into requested scope",
    async (
      _name,
      requestedScope,
      customScopes,
      resourceScopes,
      expectedAuthScope,
      expectedStoredScope,
    ) => {
      mockTwoLegAuth();
      const requests: string[] = [];
      const metadata = syntheticMetadata({
        ...(requestedScope ? { requestedScope } : {}),
        ...(customScopes
          ? { authServerMetadataUrl: "http://127.0.0.1:49152/custom-metadata" }
          : {}),
        clientMetadata: {
          client_name: "MCP Restrictor",
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          scope: "client-fallback",
        },
      });
      const io = pasteIo(pastedCallback);
      const fetchFn = discoveryFetch({
        requests,
        ...(customScopes ? { customScopes } : {}),
        resourceScopes,
      });

      const profile = await loginWith({ metadata, io, fetchFn });

      expect(vi.mocked(auth).mock.calls[0]?.[1]).toEqual(
        expect.objectContaining({
          serverUrl: metadata.serverUrl,
          ...(expectedAuthScope ? { scope: expectedAuthScope } : {}),
          resourceMetadataUrl: new URL(metadata.resourceMetadataUrl!),
          fetchFn: expect.any(Function),
        }),
      );
      expect(profile.metadata.requestedScope).toBe(expectedStoredScope);
      if (customScopes) {
        expect(requests).toContain("http://127.0.0.1:49152/custom-metadata");
        expect(
          requests.some((value) => value.includes(".well-known/oauth-authorization-server")),
        ).toBe(false);
      }
      expect(io.confirmations[0]?.scope).toBe(
        expectedAuthScope ?? resourceScopes?.join(" ") ?? "client-fallback",
      );
    },
  );

  it.each([
    ["remote plaintext metadata URL", "http://auth.example/metadata", undefined],
    ["redirected response", "http://127.0.0.1:49152/custom-metadata", "redirect"],
    ["malformed JSON", "http://127.0.0.1:49152/custom-metadata", "malformed"],
    ["issuer mismatch", "http://127.0.0.1:49152/custom-metadata", "issuer"],
    ["unsafe authorization endpoint", "http://127.0.0.1:49152/custom-metadata", "authorization"],
    ["unsafe registration endpoint", "http://127.0.0.1:49152/custom-metadata", "registration"],
    ["unsafe token endpoint", "http://127.0.0.1:49152/custom-metadata", "token"],
    ["invalid scopes", "http://127.0.0.1:49152/custom-metadata", "scopes"],
  ])("rejects custom metadata with %s before authorization", async (_name, url, failure) => {
    const requests: string[] = [];
    const io = pasteIo(pastedCallback);
    const metadata = syntheticMetadata({ authServerMetadataUrl: url });
    const fetchFn = discoveryFetch({
      requests,
      ...(failure ? { customFailure: failure } : {}),
    });

    await expect(loginWith({ metadata, io, fetchFn })).rejects.toThrow("OAuth login failed");

    expect(auth).not.toHaveBeenCalled();
    expect(io.written).toHaveLength(0);
  });
});

describe("callback selection and authorization-code exchange", () => {
  it("explicit Paste redirect delivery opens no listener", async () => {
    const port = await unusedPort();
    const plan = await selectCallback(
      syntheticMetadata({
        callback: { host: "127.0.0.1", path: "/callback", port, appendProfileId: false },
      }),
      "state",
      "paste",
    );

    try {
      const competing = await listen(createServer(), "127.0.0.1", port);
      await stop(competing);
    } finally {
      await plan.close();
    }
  });

  it("Paste uses a random high port when redirect delivery has no exact port", async () => {
    const plan = await selectCallback(
      syntheticMetadata({
        callback: { host: "127.0.0.1", path: "/callback", appendProfileId: true },
      }),
      "state",
      "paste",
    );

    try {
      const port = Number(plan.url.port);
      expect(port).toBeGreaterThanOrEqual(49_152);
      expect(port).toBeLessThanOrEqual(65_535);
      expect(plan.url.pathname).toBe(`/callback/mcp-restrictor/${profileId}`);
      const competing = await listen(createServer(), "127.0.0.1", port);
      await stop(competing);
    } finally {
      await plan.close();
    }
  });

  it("explicit Paste preserves an exact configured callback URI", async () => {
    const port = await unusedPort();
    const exact = `http://127.0.0.1:${port}/exact?tenant=one`;
    const plan = await selectCallback(syntheticMetadata({ callbackUrl: exact }), "state", "paste");

    try {
      expect(plan.url.href).toBe(exact);
      const competing = await listen(createServer(), "127.0.0.1", port);
      await stop(competing);
    } finally {
      await plan.close();
    }
  });

  it.each([
    [
      { host: "localhost", path: "/callback", port: 0, appendProfileId: false },
      /^http:\/\/localhost:\d+\/callback$/,
    ],
    [
      { host: "127.0.0.1", path: "/callback", port: 0, appendProfileId: true },
      /\/callback\/mcp-restrictor\/[0-9a-f-]+$/,
    ],
    [
      { url: "https://callback.example/finish?tenant=one", appendProfileId: false },
      /^https:\/\/callback\.example\/finish/,
    ],
  ] as const)(
    "derives the callback URL from a generic strategy: %j",
    async (callback, expected) => {
      mockTwoLegAuth();
      const io = "url" in callback ? pasteIo(pastedCallback) : listenerIo();

      const profile = await loginWith({
        metadata: syntheticMetadata({ callback }),
        io,
        fetchFn: discoveryFetch({ requests: [] }),
      });

      expect(profile.metadata.callbackUrl).toMatch(expected);
    },
  );

  it.each([
    ["invalid host", { host: "callback.example", path: "/callback", appendProfileId: false }],
    ["relative URL", { url: "/callback", appendProfileId: false }],
    ["URL fragment", { url: "https://callback.example/finish#fragment", appendProfileId: false }],
    [
      "reserved callback query",
      { url: "https://callback.example/finish?code=one", appendProfileId: false },
    ],
    ["invalid path", { host: "localhost", path: "callback", appendProfileId: false }],
    [
      "port above 65535",
      { host: "localhost", path: "/callback", port: 65_536, appendProfileId: false },
    ],
  ] as const)(
    "rejects a generic strategy with %s before OAuth discovery",
    async (_name, callback) => {
      const fetchFn = vi.fn<FetchLike>();

      await expect(
        loginWith({
          metadata: syntheticMetadata({
            callback: callback as OAuthProfileMetadata["callback"],
          }),
          io: pasteIo(pastedCallback),
          fetchFn,
        }),
      ).rejects.toThrow("OAuth login failed");

      expect(fetchFn).not.toHaveBeenCalled();
      expect(auth).not.toHaveBeenCalled();
    },
  );

  it("completes dynamic registration through an ephemeral Codex loopback callback", async () => {
    const fixture = await startOAuthFixture();
    const io = listenerIo();
    const metadata = baseMetadata({
      serverUrl: fixture.serverUrl,
      resourceMetadataUrl: fixture.resourceMetadataUrl,
      callback: { host: "127.0.0.1", path: "/callback", appendProfileId: true },
    });

    const profile = await loginWith({ metadata, io, fetchFn: fetch });

    expect(profile.metadata.callbackUrl).toMatch(
      new RegExp(`^http://127\\.0\\.0\\.1:\\d+/callback/mcp-restrictor/${profileId}$`),
    );
    expect(profile.credentials.clientInformation).toMatchObject({
      client_id: "dynamic-client",
      issuer: fixture.authorizationServerUrl,
    });
    expect(profile.credentials.tokens).toMatchObject({
      access_token: "access-token-secret",
      refresh_token: "refresh-token-secret",
      issuer: fixture.authorizationServerUrl,
    });
    expect(fixture.registrationRequests).toHaveLength(1);
    expect(fixture.tokenRequests).toHaveLength(1);
    expect(fixture.tokenRequests[0]).toContain("code=authorization-code-secret");
    expect(new URLSearchParams(fixture.tokenRequests[0]).get("code_verifier")).toMatch(
      /^[A-Za-z0-9._~-]+$/,
    );
    expect(io.reads).toBe(0);
    await fixture.close();
  });

  it("falls back to non-echo paste when a fixed Manual loopback port cannot bind", async () => {
    const blocker = await listen(createServer(), "127.0.0.1");
    const blockedPort = serverPort(blocker);
    const fixture = await startOAuthFixture();
    const io = pasteIo(pastedCallback);
    const metadata = baseMetadata({
      serverUrl: fixture.serverUrl,
      resourceMetadataUrl: fixture.resourceMetadataUrl,
      callback: { host: "127.0.0.1", path: "/callback", port: blockedPort, appendProfileId: true },
    });

    const profile = await loginWith({
      metadata,
      clientInformation: { client_id: "pre-registered-client" },
      io,
      fetchFn: fetch,
    });

    expect(profile.metadata.callbackUrl).toBe(
      `http://127.0.0.1:${blockedPort}/callback/mcp-restrictor/${profileId}`,
    );
    expect(io.reads).toBe(1);
    expect(io.written.join("\n")).not.toContain("authorization-code-secret");
    expect(fixture.registrationRequests).toHaveLength(0);
    expect(fixture.tokenRequests).toHaveLength(1);
    await fixture.close();
    await stop(blocker);
  });

  it("registers exactly the configured Claude callback", async () => {
    mockTwoLegAuth();
    const port = await unusedPort();
    const metadata = syntheticMetadata({
      callback: { host: "localhost", path: "/callback", port, appendProfileId: false },
    });
    const io = listenerIo();

    const profile = await loginWith({ metadata, io, fetchFn: discoveryFetch({ requests: [] }) });

    expect(profile.metadata.callbackUrl).toBe(`http://localhost:${port}/callback`);
    expect(vi.mocked(auth).mock.calls[0]?.[0].clientMetadata.redirect_uris).toEqual([
      `http://localhost:${port}/callback`,
    ]);
  });

  it("binds an IPv6 loopback callback URL when the host supports it", async (context) => {
    if (!(await hasIpv6Loopback())) {
      context.skip();
      return;
    }
    const fixture = await startOAuthFixture();
    const io = listenerIo();
    const metadata = baseMetadata({
      serverUrl: fixture.serverUrl,
      resourceMetadataUrl: fixture.resourceMetadataUrl,
      callback: { url: "http://[::1]:0/callback", appendProfileId: true },
    });

    try {
      const profile = await loginWith({
        metadata,
        clientInformation: { client_id: "pre-registered-client" },
        io,
        fetchFn: fetch,
      });

      expect(profile.metadata.callbackUrl).toMatch(
        new RegExp(`^http://\\[::1\\]:\\d+/callback/mcp-restrictor/${profileId}$`),
      );
      expect(fixture.tokenRequests).toHaveLength(1);
    } finally {
      await fixture.close();
    }
  });

  it("reuses an authenticated final callback without changing its port or URI", async () => {
    mockTwoLegAuth();
    const callbackUrl = "https://callback.example/exact/path?tenant=one";
    const metadata = syntheticMetadata({
      callback: { url: "https://ignored.example/base", port: 1234, appendProfileId: true },
      callbackUrl,
    });
    const io = pasteIo(pastedCallback);

    const profile = await loginWith({ metadata, io, fetchFn: discoveryFetch({ requests: [] }) });

    expect(profile.metadata.callbackUrl).toBe(callbackUrl);
    expect(vi.mocked(auth).mock.calls[0]?.[0].redirectUrl).toBe(callbackUrl);
  });

  it("keeps the loopback listener open after an invalid callback during confirmation", async () => {
    const fixture = await startOAuthFixture();
    const io = listenerIo();
    const invalidStatuses: number[] = [];
    const unhandled: unknown[] = [];
    const onUnhandled = (error: unknown) => unhandled.push(error);
    process.on("unhandledRejection", onUnhandled);
    io.confirmAuthorizationServer = async (details) => {
      io.confirmations.push(details);
      const invalid = new URL(details.callbackUrl);
      invalid.pathname = "/invalid-callback";
      const response = await fetch(invalid);
      invalidStatuses.push(response.status);
      await response.text();
      await new Promise((resolve) => setImmediate(resolve));
      return true;
    };
    const metadata = baseMetadata({
      serverUrl: fixture.serverUrl,
      resourceMetadataUrl: fixture.resourceMetadataUrl,
      callback: { host: "127.0.0.1", path: "/callback", appendProfileId: true },
    });

    try {
      await loginWith({
        metadata,
        clientInformation: { client_id: "pre-registered-client" },
        io,
        fetchFn: fetch,
      });
      await new Promise((resolve) => setImmediate(resolve));

      expect(invalidStatuses).toEqual([400]);
      expect(unhandled).toEqual([]);
      expect(fixture.tokenRequests).toHaveLength(1);
    } finally {
      process.off("unhandledRejection", onUnhandled);
      await fixture.close();
    }
  });

  it("uses a pre-registered client secret without dynamic registration", async () => {
    const fixture = await startOAuthFixture({
      authorizationMetadata: (origin) => ({
        ...safeAuthorizationMetadata(origin),
        token_endpoint_auth_methods_supported: ["client_secret_post"],
      }),
    });
    const io = pasteIo(pastedCallback);
    const metadata = baseMetadata({
      serverUrl: fixture.serverUrl,
      resourceMetadataUrl: fixture.resourceMetadataUrl,
      callback: { url: "https://callback.example/complete", appendProfileId: true },
      clientMetadata: {
        client_name: "MCP Restrictor",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_post",
      },
    });

    await loginWith({
      metadata,
      clientInformation: {
        client_id: "pre-registered-client",
        client_secret: "client-secret-value",
      },
      io,
      fetchFn: fetch,
    });

    expect(fixture.registrationRequests).toHaveLength(0);
    expect(fixture.tokenRequests[0]).toContain("client_secret=client-secret-value");
    await fixture.close();
  });

  it.each([
    ["wrong state", (url: URL) => url.searchParams.set("state", "wrong-state")],
    [
      "wrong path",
      (url: URL) => {
        url.pathname = "/other";
      },
    ],
    [
      "wrong origin",
      (url: URL) => {
        url.host = "other.example";
      },
    ],
    ["extra query", (url: URL) => url.searchParams.set("extra", "value")],
    ["duplicate code", (url: URL) => url.searchParams.append("code", "second")],
    ["duplicate state", (url: URL) => url.searchParams.append("state", "second")],
    [
      "duplicate issuer",
      (url: URL) => {
        url.searchParams.set("iss", "first");
        url.searchParams.append("iss", "second");
      },
    ],
    ["missing code", (url: URL) => url.searchParams.delete("code")],
  ])("explicit Paste rejects a callback with %s before the token leg", async (_name, mutate) => {
    mockTwoLegAuth();
    const metadata = syntheticMetadata({
      callback: { url: "https://callback.example/complete?tenant=one", appendProfileId: true },
    });
    const selectRedirectDelivery = vi.fn(async () => "paste" as const);
    const io = Object.assign(
      pasteIo((authorizationUrl) => {
        const url = pastedCallback(authorizationUrl);
        url.searchParams.set("tenant", "one");
        mutate(url);
        return url;
      }),
      { selectRedirectDelivery },
    );

    await expect(
      loginWith({ metadata, io, fetchFn: discoveryFetch({ requests: [] }) }),
    ).rejects.toThrow("OAuth login failed");

    expect(auth).toHaveBeenCalledTimes(1);
    expect(selectRedirectDelivery).toHaveBeenCalledOnce();
  });

  it.each([
    ["duplicate static query", "https://callback.example/complete?tenant=one&tenant=two"],
    ["code", "https://callback.example/complete?code=one"],
    ["state", "https://callback.example/complete?state=one"],
    ["iss", "https://callback.example/complete?iss=one"],
    ["error", "https://callback.example/complete?error=one"],
    ["error description", "https://callback.example/complete?error_description=one"],
    ["error URI", "https://callback.example/complete?error_uri=one"],
  ])(
    "explicit Paste rejects %s in configured or stored callback before discovery",
    async (_name, callbackUrl) => {
      const fetchFn = vi.fn<FetchLike>();
      const selectRedirectDelivery = vi.fn(async () => "paste" as const);
      const io = Object.assign(pasteIo(pastedCallback), { selectRedirectDelivery });
      const configured = baseMetadata({
        callback: { url: callbackUrl, appendProfileId: true },
      });
      await expect(loginWith({ metadata: configured, io, fetchFn })).rejects.toThrow(
        "OAuth login failed",
      );
      const stored = baseMetadata({
        callback: { url: "https://callback.example/ok", appendProfileId: true },
        callbackUrl,
      });
      await expect(loginWith({ metadata: stored, io, fetchFn })).rejects.toThrow(
        "OAuth login failed",
      );
      expect(fetchFn).not.toHaveBeenCalled();
      expect(auth).not.toHaveBeenCalled();
      expect(io.reads).toBe(0);
      expect(selectRedirectDelivery).toHaveBeenCalledTimes(2);
    },
  );

  it("explicit Paste rejects callback issuer mismatch before sending the authorization code", async () => {
    const fixture = await startOAuthFixture({
      authorizationMetadata: (origin) => ({
        ...safeAuthorizationMetadata(origin),
        authorization_response_iss_parameter_supported: true,
      }),
    });
    const selectRedirectDelivery = vi.fn(async () => "paste" as const);
    const io = Object.assign(
      pasteIo((authorizationUrl) => {
        const redirect = pastedCallback(authorizationUrl);
        redirect.searchParams.set("iss", "https://attacker.example/");
        return redirect;
      }),
      { selectRedirectDelivery },
    );
    const metadata = baseMetadata({
      serverUrl: fixture.serverUrl,
      resourceMetadataUrl: fixture.resourceMetadataUrl,
      callback: { url: "https://callback.example/complete", appendProfileId: true },
    });

    await expect(
      loginWith({
        metadata,
        clientInformation: { client_id: "pre-registered-client" },
        io,
        fetchFn: fetch,
      }),
    ).rejects.toThrow("OAuth login failed");

    expect(fixture.tokenRequests).toHaveLength(0);
    expect(selectRedirectDelivery).toHaveBeenCalledOnce();
    await fixture.close();
  });

  it("rejects protected-resource mismatch before authorization", async () => {
    const requests: string[] = [];
    const io = pasteIo(pastedCallback);
    const metadata = syntheticMetadata({ resource: "http://127.0.0.1:49151/other" });

    await expect(
      loginWith({ metadata, io, fetchFn: discoveryFetch({ requests }) }),
    ).rejects.toThrow("OAuth login failed");

    expect(io.written).toHaveLength(0);
  });
});

describe("redirect, cancellation, cleanup, and redaction boundaries", () => {
  it("preserves an AbortError rejected by the delivery selector", async () => {
    const cancellation = new DOMException("delivery selector cancelled", "AbortError");
    const selectRedirectDelivery = vi.fn().mockRejectedValue(cancellation);
    const io = Object.assign(pasteIo(pastedCallback), { selectRedirectDelivery });
    const fetchFn = vi.fn<FetchLike>();

    await expect(loginWith({ metadata: syntheticMetadata(), io, fetchFn })).rejects.toBe(
      cancellation,
    );

    expect(selectRedirectDelivery).toHaveBeenCalledOnce();
    expect(fetchFn).not.toHaveBeenCalled();
    expect(auth).not.toHaveBeenCalled();
  });

  it("classifies a delivery-selector timeout as an OAuth failure", async () => {
    const timeout = new AbortController();
    const timeoutSpy = vi.spyOn(AbortSignal, "timeout").mockReturnValue(timeout.signal);
    const selection = deferred<"paste">();
    const selectRedirectDelivery = vi.fn(() => selection.promise);
    const io = Object.assign(pasteIo(pastedCallback), { selectRedirectDelivery });
    const fetchFn = vi.fn<FetchLike>();

    try {
      const login = loginWith({
        metadata: syntheticMetadata(),
        io,
        fetchFn,
        timeoutMs: 50,
      });
      await vi.waitFor(() => expect(selectRedirectDelivery).toHaveBeenCalledOnce());
      timeout.abort(new DOMException("OAuth login deadline", "TimeoutError"));

      await expect(login).rejects.toThrow("OAuth login failed");
      expect(fetchFn).not.toHaveBeenCalled();
      expect(auth).not.toHaveBeenCalled();
    } finally {
      timeoutSpy.mockRestore();
    }
  });

  it("classifies an unexpected delivery-selector rejection as an OAuth failure", async () => {
    const selectRedirectDelivery = vi
      .fn()
      .mockRejectedValue(new Error("unexpected selector detail"));
    const io = Object.assign(pasteIo(pastedCallback), { selectRedirectDelivery });
    const fetchFn = vi.fn<FetchLike>();

    await expect(loginWith({ metadata: syntheticMetadata(), io, fetchFn })).rejects.toThrow(
      "OAuth login failed",
    );

    expect(fetchFn).not.toHaveBeenCalled();
    expect(auth).not.toHaveBeenCalled();
  });

  it("redacts an unrelated later-stage AbortError after delivery selection", async () => {
    const secret = "later-stage-abort-secret";
    const io = Object.assign(pasteIo(pastedCallback), {
      selectRedirectDelivery: async () => "paste" as const,
    });
    const fetchFn = vi.fn<FetchLike>().mockRejectedValue(new DOMException(secret, "AbortError"));

    const error = await loginWith({ metadata: syntheticMetadata(), io, fetchFn }).catch(
      (failure: unknown) => failure,
    );

    expect(error).toEqual(new Error("OAuth login failed"));
    expect(String(error)).not.toContain(secret);
    expect(io.written.join("\n")).not.toContain(secret);
    expect(io.confirmations).toHaveLength(0);
  });

  it.each(["custom-metadata", "registration", "token"] as const)(
    "does not follow a %s redirect to a second origin",
    async (phase) => {
      const sink = await startSink();
      const fixture = await startOAuthFixture({ redirectPhase: phase, redirectLocation: sink.url });
      const metadata = baseMetadata({
        serverUrl: fixture.serverUrl,
        resourceMetadataUrl: fixture.resourceMetadataUrl,
        ...(phase === "custom-metadata"
          ? { authServerMetadataUrl: fixture.customMetadataUrl }
          : {}),
        callback: { url: "https://callback.example/complete", appendProfileId: true },
      });
      const io = pasteIo(pastedCallback);

      await expect(
        loginWith({
          metadata,
          ...(phase === "registration"
            ? {}
            : { clientInformation: { client_id: "pre-registered-client" } }),
          io,
          fetchFn: fetch,
        }),
      ).rejects.toThrow("OAuth login failed");

      expect(sink.hits).toBe(0);
      await fixture.close();
      await sink.close();
    },
  );

  it("aborts a pending metadata fetch and closes the fixed callback listener", async () => {
    const port = await unusedPort();
    const controller = new AbortController();
    const started = deferred<void>();
    const fetchFn = cooperativeNeverFetch(started);
    const metadata = baseMetadata({
      callback: { host: "127.0.0.1", path: "/callback", port, appendProfileId: true },
    });
    const promise = loginWith({ metadata, io: listenerIo(), fetchFn, signal: controller.signal });
    await started.promise;

    controller.abort(new Error("abort-reason-secret"));
    await expect(promise).rejects.toThrow("OAuth login cancelled");
    const rebound = await listen(createServer(), "127.0.0.1", port);
    await stop(rebound);
  });

  it("times out a pending token exchange, closes its listener, and aborts the request", async () => {
    const fixture = await startOAuthFixture({ hangToken: true });
    const timeout = new AbortController();
    const timeoutSpy = vi.spyOn(AbortSignal, "timeout").mockReturnValue(timeout.signal);
    const io = listenerIo();
    const metadata = baseMetadata({
      serverUrl: fixture.serverUrl,
      resourceMetadataUrl: fixture.resourceMetadataUrl,
      callback: { host: "127.0.0.1", path: "/callback", appendProfileId: true },
    });

    try {
      const promise = loginWith({
        metadata,
        clientInformation: { client_id: "pre-registered-client" },
        io,
        fetchFn: fetch,
        timeoutMs: 50,
      });
      await vi.waitFor(() => expect(fixture.tokenRequests).toHaveLength(1));
      timeout.abort(new DOMException("OAuth login deadline", "TimeoutError"));

      await expect(promise).rejects.toThrow("OAuth login failed");
      await fixture.tokenAborted.promise;
      const callback = new URL(io.confirmations[0]!.callbackUrl);
      const rebound = await listen(createServer(), callback.hostname, Number(callback.port));
      await stop(rebound);
    } finally {
      timeoutSpy.mockRestore();
      await fixture.close();
    }
  });

  it("cancels a non-cancellable pasted-input wait without leaking a late rejection", async () => {
    mockTwoLegAuth();
    const controller = new AbortController();
    const late = deferred<URL>();
    const io = pasteIo(() => late.promise);
    const add = vi.spyOn(AbortSignal.prototype, "addEventListener");
    const remove = vi.spyOn(AbortSignal.prototype, "removeEventListener");
    try {
      const promise = loginWith({
        metadata: syntheticMetadata(),
        io,
        fetchFn: discoveryFetch({ requests: [] }),
        signal: controller.signal,
      });
      await vi.waitFor(() => expect(io.reads).toBe(1));
      controller.abort(new Error("pasted-abort-secret"));
      await expect(promise).rejects.toThrow("OAuth login cancelled");
      expect(abortListenerCalls(remove)).toBe(abortListenerCalls(add));
      late.reject(new Error("late-pasted-secret"));
      await new Promise((resolve) => setImmediate(resolve));
    } finally {
      add.mockRestore();
      remove.mockRestore();
    }
  });

  it("redacts raw token errors, callback codes, client secrets, verifiers, and tokens", async () => {
    const rawBody = JSON.stringify({
      error: "invalid_grant",
      error_description: sensitiveValues.join(" "),
    });
    const fixture = await startOAuthFixture({ tokenStatus: 400, tokenBody: rawBody });
    const io = pasteIo(pastedCallback);
    const metadata = baseMetadata({
      serverUrl: fixture.serverUrl,
      resourceMetadataUrl: fixture.resourceMetadataUrl,
      callback: { url: "https://callback.example/complete", appendProfileId: true },
    });

    const error = await loginWith({
      metadata,
      clientInformation: {
        client_id: "pre-registered-client",
        client_secret: "client-secret-value",
      },
      io,
      fetchFn: fetch,
    }).catch((value: unknown) => value);

    expect(error).toEqual(new Error("OAuth login failed"));
    for (const secret of sensitiveValues) expect(String(error)).not.toContain(secret);
    expect(String(error)).not.toContain(rawBody);
    expect(io.written.join("\n")).not.toContain("authorization-code-secret");
    await fixture.close();
  });
});

type PasteIo = OAuthLoginIO & {
  confirmations: Array<Parameters<OAuthLoginIO["confirmAuthorizationServer"]>[0]>;
  written: string[];
  reads: number;
};

function pasteIo(
  callback: (authorizationUrl: URL) => URL | Promise<URL>,
  options: { confirm?: boolean; events?: string[] } = {},
): PasteIo {
  let authorizationUrl: URL | undefined;
  const confirmations: PasteIo["confirmations"] = [];
  const written: string[] = [];
  const io: PasteIo = {
    confirmations,
    written,
    reads: 0,
    confirmAuthorizationServer: async (details) => {
      options.events?.push("confirm");
      confirmations.push(details);
      return options.confirm ?? true;
    },
    writeAuthorizationUrl: (url) => {
      authorizationUrl = new URL(url);
      written.push(url.href);
    },
    readPastedRedirect: async () => {
      io.reads += 1;
      if (!authorizationUrl) throw new Error("authorization URL was not written");
      return await callback(authorizationUrl);
    },
  };
  return io;
}

function listenerIo(): PasteIo {
  const io = pasteIo(() => {
    throw new Error("paste fallback was not expected");
  });
  io.writeAuthorizationUrl = async (authorizationUrl) => {
    io.written.push(authorizationUrl.href);
    const redirect = new URL(authorizationUrl.searchParams.get("redirect_uri")!);
    redirect.searchParams.set("code", "authorization-code-secret");
    redirect.searchParams.set("state", authorizationUrl.searchParams.get("state")!);
    const response = await fetch(redirect);
    await response.text();
  };
  return io;
}

function pastedCallback(authorizationUrl: URL): URL {
  const redirect = new URL(authorizationUrl.searchParams.get("redirect_uri")!);
  redirect.searchParams.set("code", "authorization-code-secret");
  redirect.searchParams.set("state", authorizationUrl.searchParams.get("state")!);
  return redirect;
}

function baseMetadata(override: Partial<OAuthProfileMetadata> = {}): OAuthProfileMetadata {
  return {
    version: 1,
    profileId,
    serverUrl: "http://127.0.0.1:49151/mcp",
    callback: { url: "https://callback.example/complete", appendProfileId: true },
    clientMetadata: {
      client_name: "MCP Restrictor",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    },
    ...override,
  };
}

function syntheticMetadata(override: Partial<OAuthProfileMetadata> = {}): OAuthProfileMetadata {
  return baseMetadata({
    resourceMetadataUrl: "http://127.0.0.1:49151/resource-metadata",
    ...override,
  });
}

async function loginWith(options: {
  metadata: OAuthProfileMetadata;
  clientInformation?: StoredOAuthClientInformation;
  discoveryState?: OAuthDiscoveryState;
  io: OAuthLoginIO;
  fetchFn: FetchLike;
  signal?: AbortSignal;
  timeoutMs?: number;
}) {
  const input: OAuthLoginInput = {
    metadata: options.metadata,
    ...(options.clientInformation ? { clientInformation: options.clientInformation } : {}),
    ...(options.discoveryState ? { discoveryState: options.discoveryState } : {}),
  };
  return loginOAuthProfile({
    input,
    io: options.io,
    signal: options.signal ?? new AbortController().signal,
    fetchFn: options.fetchFn,
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
  });
}

function safeAuthorizationMetadata(origin: string): Record<string, unknown> {
  return {
    issuer: origin,
    authorization_endpoint: new URL("/authorize", origin).href,
    token_endpoint: new URL("/token", origin).href,
    registration_endpoint: new URL("/register", origin).href,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
  };
}

function safeDiscoveryState(): OAuthDiscoveryState {
  return {
    authorizationServerUrl: "https://auth.example/",
    authorizationServerMetadata: safeAuthorizationMetadata("https://auth.example/") as NonNullable<
      OAuthDiscoveryState["authorizationServerMetadata"]
    >,
    resourceMetadata: {
      resource: "https://resource.example/mcp",
      authorization_servers: ["https://auth.example/"],
      scopes_supported: ["read", "write"],
    },
    resourceMetadataUrl: "https://resource.example/metadata",
  };
}

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

function discoveryFetch(options: {
  requests: string[];
  authorizationServerUrl?: string;
  authorizationMetadata?: Record<string, unknown>;
  customScopes?: string[];
  resourceScopes?: string[];
  customFailure?: string;
}): FetchLike {
  const authorizationServerUrl = options.authorizationServerUrl ?? "http://127.0.0.1:49152/";
  return async (input, init) => {
    const url = new URL(input);
    options.requests.push(url.href);
    expect(init?.redirect).toBe("error");
    if (url.href === "http://127.0.0.1:49151/resource-metadata") {
      return jsonResponse({
        resource: "http://127.0.0.1:49151/mcp",
        authorization_servers: [authorizationServerUrl],
        ...(options.resourceScopes ? { scopes_supported: options.resourceScopes } : {}),
      });
    }
    if (url.href === "http://127.0.0.1:49152/custom-metadata") {
      switch (options.customFailure) {
        case "redirect":
          return new Response(null, {
            status: 302,
            headers: { location: "http://127.0.0.1:49153/stolen" },
          });
        case "malformed":
          return new Response("{not-json", { status: 200 });
      }
      const custom: Record<string, unknown> = {
        ...safeAuthorizationMetadata(authorizationServerUrl),
        ...(options.customScopes ? { scopes_supported: options.customScopes } : {}),
      };
      if (options.customFailure === "issuer") custom.issuer = "https://other.example/";
      if (options.customFailure === "authorization") {
        custom.authorization_endpoint = "http://auth.example/authorize";
      }
      if (options.customFailure === "registration") {
        custom.registration_endpoint = "http://auth.example/register";
      }
      if (options.customFailure === "token") custom.token_endpoint = "http://auth.example/token";
      if (options.customFailure === "scopes") custom.scopes_supported = ["read write"];
      return jsonResponse(custom);
    }
    return jsonResponse({
      ...safeAuthorizationMetadata(authorizationServerUrl),
      ...options.authorizationMetadata,
    });
  };
}

function mockTwoLegAuth(): void {
  let call = 0;
  vi.mocked(auth).mockImplementation(async (provider) => {
    call += 1;
    if (call === 1) {
      if (!(await provider.clientInformation())) {
        await provider.saveClientInformation?.({
          client_id: "dynamic-client",
          issuer: "http://127.0.0.1:49152/",
        });
      }
      const state = await provider.state?.();
      await provider.saveCodeVerifier("verifier-secret-value");
      const authorizationUrl = new URL("https://auth.example/authorize");
      authorizationUrl.searchParams.set("redirect_uri", String(provider.redirectUrl));
      authorizationUrl.searchParams.set("state", String(state));
      await provider.redirectToAuthorization(authorizationUrl);
      return "REDIRECT";
    }
    await provider.saveTokens({
      access_token: "access-token-secret",
      refresh_token: "refresh-token-secret",
      token_type: "Bearer",
      issuer: "http://127.0.0.1:49152/",
    });
    return "AUTHORIZED";
  });
}

type OAuthFixture = {
  serverUrl: string;
  resourceMetadataUrl: string;
  authorizationServerUrl: string;
  customMetadataUrl: string;
  registrationRequests: string[];
  tokenRequests: string[];
  tokenAborted: Deferred<void>;
  readonly resourceMetadataRequests: number;
  close(): Promise<void>;
};

async function startOAuthFixture(
  options: {
    authorizationMetadata?: (origin: string) => Record<string, unknown>;
    redirectPhase?: "custom-metadata" | "registration" | "token";
    redirectLocation?: string;
    hangToken?: boolean;
    tokenStatus?: number;
    tokenBody?: string;
    fallbackAuthorizationServer?: boolean;
    resourceMetadata404Once?: boolean;
    lateResourceScopes?: string[];
    tokenEndpointAtResourceMetadataUrl?: boolean;
  } = {},
): Promise<OAuthFixture> {
  const registrationRequests: string[] = [];
  const tokenRequests: string[] = [];
  const tokenAborted = deferred<void>();
  let authorizationServerUrl = "";
  let serverUrl = "";
  let resourceMetadataUrl = "";
  const authServer = await listen(
    createServer((request, response) => {
      void (async () => {
        const url = new URL(request.url ?? "/", authorizationServerUrl || "http://127.0.0.1");
        if (url.pathname === "/custom-metadata" && options.redirectPhase === "custom-metadata") {
          redirect(response, options.redirectLocation!);
          return;
        }
        if (
          url.pathname === "/custom-metadata" ||
          url.pathname.includes(".well-known/oauth-authorization-server") ||
          url.pathname.includes(".well-known/openid-configuration")
        ) {
          const issuer = options.fallbackAuthorizationServer
            ? new URL("/", serverUrl).href
            : authorizationServerUrl;
          const metadata =
            options.authorizationMetadata?.(issuer) ?? safeAuthorizationMetadata(issuer);
          if (options.fallbackAuthorizationServer) {
            metadata.authorization_endpoint = new URL("/authorize", authorizationServerUrl).href;
            metadata.token_endpoint = options.tokenEndpointAtResourceMetadataUrl
              ? resourceMetadataUrl
              : new URL("/token", authorizationServerUrl).href;
            metadata.registration_endpoint = new URL("/register", authorizationServerUrl).href;
          }
          sendJson(response, metadata);
          return;
        }
        if (url.pathname === "/register") {
          const body = await requestBody(request);
          registrationRequests.push(body);
          if (options.redirectPhase === "registration") {
            redirect(response, options.redirectLocation!);
            return;
          }
          sendJson(
            response,
            {
              ...(JSON.parse(body) as Record<string, unknown>),
              client_id: "dynamic-client",
              client_secret: "dynamic-secret",
              token_endpoint_auth_method: "client_secret_post",
            },
            201,
          );
          return;
        }
        if (url.pathname === "/token") {
          request.once("aborted", () => tokenAborted.resolve());
          response.once("close", () => {
            if (!response.writableEnded) tokenAborted.resolve();
          });
          tokenRequests.push(await requestBody(request));
          if (options.redirectPhase === "token") {
            redirect(response, options.redirectLocation!);
            return;
          }
          if (options.hangToken) return;
          if (options.tokenStatus !== undefined) {
            response.writeHead(options.tokenStatus, { "content-type": "application/json" });
            response.end(options.tokenBody ?? "{}");
            return;
          }
          sendJson(response, {
            access_token: "access-token-secret",
            refresh_token: "refresh-token-secret",
            token_type: "Bearer",
            expires_in: 3600,
          });
          return;
        }
        response.writeHead(404).end();
      })().catch(() => response.writeHead(500).end());
    }),
    "127.0.0.1",
  );
  authorizationServerUrl = `http://127.0.0.1:${serverPort(authServer)}/`;

  let resourceMetadataRequests = 0;
  const resourceServer = await listen(
    createServer((request, response) => {
      const url = new URL(request.url ?? "/", serverUrl || "http://127.0.0.1");
      if (
        url.pathname === "/resource-metadata" ||
        url.pathname.includes(".well-known/oauth-protected-resource")
      ) {
        resourceMetadataRequests += 1;
        if (options.resourceMetadata404Once && resourceMetadataRequests === 1) {
          response.writeHead(404).end();
          return;
        }
      }
      sendJson(response, {
        resource: serverUrl,
        authorization_servers: [
          options.fallbackAuthorizationServer
            ? new URL("/", serverUrl).href
            : authorizationServerUrl,
        ],
        scopes_supported: options.lateResourceScopes ?? ["resource-scope"],
      });
    }),
    "127.0.0.1",
  );
  serverUrl = `http://127.0.0.1:${serverPort(resourceServer)}/mcp`;
  resourceMetadataUrl = `http://127.0.0.1:${serverPort(resourceServer)}/resource-metadata`;

  return {
    serverUrl,
    resourceMetadataUrl,
    authorizationServerUrl,
    customMetadataUrl: new URL("/custom-metadata", authorizationServerUrl).href,
    registrationRequests,
    tokenRequests,
    tokenAborted,
    get resourceMetadataRequests() {
      return resourceMetadataRequests;
    },
    close: async () => {
      await stop(resourceServer);
      await stop(authServer);
    },
  };
}

async function startSink(): Promise<{ url: string; hits: number; close(): Promise<void> }> {
  const state = { hits: 0 };
  const server = await listen(
    createServer((_request, response) => {
      state.hits += 1;
      response.writeHead(200).end();
    }),
    "127.0.0.1",
  );
  return {
    url: `http://127.0.0.1:${serverPort(server)}/stolen`,
    get hits() {
      return state.hits;
    },
    close: () => stop(server),
  };
}

async function listen(server: Server, host: string, port = 0): Promise<Server> {
  openServers.add(server);
  server.listen(port, host);
  await once(server, "listening");
  return server;
}

async function stop(server: Server): Promise<void> {
  if (!openServers.delete(server)) return;
  await closeServer(server);
}

function serverPort(server: Server): number {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("missing test server port");
  return address.port;
}

async function unusedPort(): Promise<number> {
  const server = await listen(createServer(), "127.0.0.1");
  const port = serverPort(server);
  await stop(server);
  return port;
}

async function hasIpv6Loopback(): Promise<boolean> {
  const server = createServer();
  try {
    await listen(server, "::1");
    await stop(server);
    return true;
  } catch {
    openServers.delete(server);
    return false;
  }
}

function sendJson(response: ServerResponse, value: unknown, status = 200): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(value));
}

function redirect(response: ServerResponse, location: string): void {
  response.writeHead(302, { location }).end();
}

async function requestBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function cooperativeNeverFetch(started: Deferred<void>): FetchLike {
  return async (_url, init) =>
    new Promise<Response>((_resolve, reject) => {
      started.resolve();
      const signal = init?.signal;
      if (!signal) return;
      if (signal.aborted) reject(signal.reason);
      else signal.addEventListener("abort", () => reject(signal.reason), { once: true });
    });
}

type Deferred<T> = {
  promise: Promise<T>;
  resolve(value: T | PromiseLike<T>): void;
  reject(reason?: unknown): void;
};

function deferred<T>(): Deferred<T> {
  let resolve!: Deferred<T>["resolve"];
  let reject!: Deferred<T>["reject"];
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function abortListenerCalls(spy: { mock: { calls: readonly (readonly unknown[])[] } }): number {
  return spy.mock.calls.filter((call) => call[0] === "abort").length;
}
