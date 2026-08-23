import { randomBytes, randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { OAuthTokens } from "@modelcontextprotocol/client";
import { afterEach, expect, test, vi } from "vitest";
import { createOAuthAuthProvider, type OAuthRuntimeOptions } from "../src/oauth/provider.ts";
import {
  oauthProfilePath,
  readOAuthProfileSnapshot,
  writeOAuthProfile,
  type OAuthProfile,
} from "../src/oauth/storage.ts";

const unlinkFailure = vi.hoisted(() => ({ path: undefined as string | undefined }));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    unlink: async (path: Parameters<typeof actual.unlink>[0]) => {
      if (String(path) === unlinkFailure.path) {
        unlinkFailure.path = undefined;
        throw Object.assign(new Error("injected refresh lock release failure"), {
          code: "EIO",
        });
      }
      return actual.unlink(path);
    },
  };
});

const homes: string[] = [];

afterEach(async () => {
  unlinkFailure.path = undefined;
  await Promise.all(homes.splice(0).map((home) => rm(home, { recursive: true })));
});

test("token reloads the encrypted profile and enforces exact server binding", async () => {
  const fixture = await storedProfile();
  const provider = createOAuthAuthProvider(fixture.id, binding(), fixture.options);

  await expect(provider.token()).resolves.toBe("access-1");
  const before = await readOAuthProfileSnapshot(fixture.id, fixture.options);
  await writeOAuthProfile(
    {
      ...before.profile,
      credentials: {
        ...before.profile.credentials,
        tokens: { ...before.profile.credentials.tokens, access_token: "access-2" },
      },
    },
    { ...fixture.options, before: before.snapshot },
  );
  await expect(provider.token()).resolves.toBe("access-2");
});

test("snapshots caller-owned runtime inputs for both token and refresh", async () => {
  const fixture = await storedProfile();
  const configured = binding();
  const refresh = vi.fn<NonNullable<OAuthRuntimeOptions["refresh"]>>(async (_url, options) => {
    expect(options.resource?.href).toBe("https://resource.example.com/mcp");
    return refreshedTokens();
  });
  const runtime: OAuthRuntimeOptions = {
    ...fixture.options,
    refresh,
  };
  const provider = createOAuthAuthProvider(fixture.id, configured, runtime);

  configured.serverUrl = "https://attacker.example.com/mcp";
  configured.resource = "https://attacker.example.com/resource";
  runtime.home = join(fixture.home, "attacker-home");
  runtime.refresh = async () => {
    throw new Error("mutated refresh must not run");
  };

  await expect(provider.token()).resolves.toBe("access-1");
  await expect(provider.onUnauthorized!(unauthorizedContext())).resolves.toBeUndefined();
  expect(refresh).toHaveBeenCalledOnce();
});

test("rejects an invalid profile id without reflecting control characters", () => {
  const unsafeId = "\u001b[31m\r\nsecret-profile-input";
  let caught: unknown;
  try {
    createOAuthAuthProvider(unsafeId, binding());
  } catch (error) {
    caught = error;
  }

  expect(caught).toBeInstanceOf(Error);
  const message = caught instanceof Error ? caught.message : String(caught);
  expect(message).toMatch(/invalid oauth profile id/i);
  expect(message).not.toContain(unsafeId);
  expect(message).not.toMatch(/[\u001b\r\n]/);
});

test.each([
  "https://other.example.com/mcp/path",
  "https://api.example.com:8443/mcp/path",
  "https://api.example.com/mcp/other",
])("token rejects mismatched server binding %s", async (serverUrl) => {
  const fixture = await storedProfile();
  const provider = createOAuthAuthProvider(
    fixture.id,
    { ...binding(), serverUrl },
    fixture.options,
  );

  await expect(provider.token()).rejects.toThrow(loginInstruction(fixture.id));
});

test.each([
  [undefined, "https://resource.example.com/mcp"],
  ["https://resource.example.com/mcp", undefined],
  ["https://resource.example.com/mcp", "https://resource.example.com/other"],
])("token rejects asymmetric resource binding", async (stored, configured) => {
  const fixture = await storedProfile((profile) => {
    if (stored === undefined) delete profile.metadata.resource;
    else profile.metadata.resource = stored;
  });
  const provider = createOAuthAuthProvider(
    fixture.id,
    { serverUrl: binding().serverUrl, ...(configured ? { resource: configured } : {}) },
    fixture.options,
  );

  await expect(provider.token()).rejects.toThrow(loginInstruction(fixture.id));
});

test("uses the discovered protected resource for binding and every refresh", async () => {
  const resource = "https://discovered-resource.example.com/mcp";
  const fixture = await storedProfile((profile) => {
    delete profile.metadata.resource;
    profile.credentials.discoveryState.resourceMetadata = {
      resource,
      authorization_servers: ["https://auth.example.com"],
    };
  });
  const seen: Array<string | undefined> = [];
  const refresh = vi.fn<NonNullable<OAuthRuntimeOptions["refresh"]>>(async (_url, options) => {
    seen.push(options.resource?.href);
    return refreshedTokens();
  });
  const provider = createOAuthAuthProvider(
    fixture.id,
    { serverUrl: binding().serverUrl, resource },
    { ...fixture.options, refresh },
  );

  await expect(provider.token()).resolves.toBe("access-1");
  await provider.onUnauthorized!(unauthorizedContext());
  await provider.onUnauthorized!(unauthorizedContext());

  expect(seen).toEqual([resource, resource]);
});

test("rejects an omitted discovered resource binding before refresh network", async () => {
  const fixture = await storedProfile((profile) => {
    delete profile.metadata.resource;
    profile.credentials.discoveryState.resourceMetadata = {
      resource: "https://discovered-resource.example.com/mcp",
      authorization_servers: ["https://auth.example.com"],
    };
  });
  const refresh = vi.fn<NonNullable<OAuthRuntimeOptions["refresh"]>>();
  const fetchFn = vi.fn<NonNullable<OAuthRuntimeOptions["fetchFn"]>>();
  const provider = createOAuthAuthProvider(
    fixture.id,
    { serverUrl: binding().serverUrl },
    { ...fixture.options, refresh, fetchFn },
  );

  await expect(provider.onUnauthorized!(unauthorizedContext())).rejects.toThrow(
    loginInstruction(fixture.id),
  );
  expect(refresh).not.toHaveBeenCalled();
  expect(fetchFn).not.toHaveBeenCalled();
});

test("an explicitly configured resource wins over discovered metadata", async () => {
  const fixture = await storedProfile((profile) => {
    profile.credentials.discoveryState.resourceMetadata = {
      resource: "https://discovered-resource.example.com/mcp",
      authorization_servers: ["https://auth.example.com"],
    };
  });
  const refresh = vi.fn<NonNullable<OAuthRuntimeOptions["refresh"]>>(async (_url, options) => {
    expect(options.resource?.href).toBe(binding().resource);
    return refreshedTokens();
  });
  const provider = createOAuthAuthProvider(fixture.id, binding(), {
    ...fixture.options,
    refresh,
  });

  await provider.onUnauthorized!(unauthorizedContext());

  expect(refresh).toHaveBeenCalledOnce();
});

test.each([
  [
    "server binding mismatch",
    (profile: OAuthProfile) => {
      profile.metadata.serverUrl = "https://api.example.com/other";
    },
  ],
  [
    "resource binding mismatch",
    (profile: OAuthProfile) => {
      profile.metadata.resource = "https://resource.example.com/other";
    },
  ],
  [
    "missing token issuer",
    (profile: OAuthProfile) => {
      delete profile.credentials.tokens.issuer;
    },
  ],
  [
    "missing client issuer",
    (profile: OAuthProfile) => {
      delete profile.credentials.clientInformation.issuer;
    },
  ],
  [
    "mixed issuer",
    (profile: OAuthProfile) => {
      profile.credentials.tokens.issuer = "https://other.example.com";
    },
  ],
  [
    "authorization server mismatch",
    (profile: OAuthProfile) => {
      profile.credentials.discoveryState.authorizationServerUrl = "https://auth.example.com/other";
    },
  ],
  [
    "missing authorization server metadata",
    (profile: OAuthProfile) => {
      delete profile.credentials.discoveryState.authorizationServerMetadata;
    },
  ],
  [
    "missing refresh token",
    (profile: OAuthProfile) => {
      delete profile.credentials.tokens.refresh_token;
    },
  ],
] as const)("refresh rejects %s before network", async (_name, mutate) => {
  const fixture = await storedProfile(mutate);
  const refresh = vi.fn<NonNullable<OAuthRuntimeOptions["refresh"]>>();
  const fetchFn = vi.fn<NonNullable<OAuthRuntimeOptions["fetchFn"]>>();
  const provider = createOAuthAuthProvider(fixture.id, binding(), {
    ...fixture.options,
    refresh,
    fetchFn,
  });

  await expect(provider.onUnauthorized?.(unauthorizedContext())).rejects.toThrow(
    loginInstruction(fixture.id),
  );
  expect(refresh).not.toHaveBeenCalled();
  expect(fetchFn).not.toHaveBeenCalled();
});

test("refresh uses only the configured clean fetch and persists rotated stamped tokens", async () => {
  const fixture = await storedProfile();
  const configuredFetch = vi.fn(async (_url: string | URL, init?: RequestInit) => {
    expect(init?.redirect).toBe("error");
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    return new Response(null, { status: 204 });
  });
  const refresh = vi.fn<NonNullable<OAuthRuntimeOptions["refresh"]>>(
    async (authorizationServerUrl, options) => {
      expect(new URL(authorizationServerUrl).href).toBe("https://auth.example.com/");
      expect(options.metadata).toMatchObject({
        issuer: "https://auth.example.com",
        token_endpoint: "https://auth.example.com/token",
      });
      expect(options.clientInformation).toMatchObject({
        client_id: "client-id-secret",
        client_secret: "client-secret-literal",
      });
      expect(options.refreshToken).toBe("refresh-1");
      expect(options.resource?.href).toBe(binding().resource);
      expect(options).not.toHaveProperty("addClientAuthentication");
      await options.fetchFn?.("https://auth.example.com/token", { method: "POST" });
      return refreshedTokens({ refresh_token: "refresh-rotated" });
    },
  );
  const context = unauthorizedContext();
  const provider = createOAuthAuthProvider(fixture.id, binding(), {
    ...fixture.options,
    fetchFn: configuredFetch,
    refresh,
  });

  await provider.onUnauthorized?.(context);

  expect(context.fetchFn).not.toHaveBeenCalled();
  expect(configuredFetch).toHaveBeenCalledTimes(1);
  const stored = await readOAuthProfileSnapshot(fixture.id, fixture.options);
  expect(stored.profile.credentials.tokens).toMatchObject({
    access_token: "access-2",
    refresh_token: "refresh-rotated",
    issuer: "https://auth.example.com",
  });
});

test("refresh preserves an omitted refresh token and restores the issuer stamp", async () => {
  const fixture = await storedProfile();
  const refresh = vi.fn<NonNullable<OAuthRuntimeOptions["refresh"]>>(async () => ({
    access_token: "access-2",
    token_type: "Bearer",
  }));
  const provider = createOAuthAuthProvider(fixture.id, binding(), {
    ...fixture.options,
    refresh,
  });

  await provider.onUnauthorized?.(unauthorizedContext());

  const stored = await readOAuthProfileSnapshot(fixture.id, fixture.options);
  expect(stored.profile.credentials.tokens).toMatchObject({
    access_token: "access-2",
    refresh_token: "refresh-1",
    issuer: "https://auth.example.com",
  });
});

test("failed refresh leaves encrypted bytes unchanged and redacts errors", async () => {
  const fixture = await storedProfile();
  const before = await profileBytes(fixture);
  const provider = createOAuthAuthProvider(fixture.id, binding(), {
    ...fixture.options,
    refresh: async () => {
      throw new Error("refresh-1 client-secret-literal server-response-secret");
    },
  });

  const message = await rejectionMessage(() => provider.onUnauthorized!(unauthorizedContext()));
  expect(message).toMatch(loginInstruction(fixture.id));
  expect(message).not.toMatch(/refresh-1|client-secret|server-response/);
  expect(await profileBytes(fixture)).toBe(before);
});

test("concurrent refreshes serialize and reload the rotated token", async () => {
  const fixture = await storedProfile();
  const entered = deferred<void>();
  const release = deferred<void>();
  const seen: string[] = [];
  const refresh = vi.fn<NonNullable<OAuthRuntimeOptions["refresh"]>>(async (_url, options) => {
    seen.push(options.refreshToken);
    if (seen.length === 1) {
      entered.resolve();
      await release.promise;
    }
    return refreshedTokens({
      access_token: `access-${seen.length + 1}`,
      refresh_token: `refresh-${seen.length + 1}`,
    });
  });
  const provider = createOAuthAuthProvider(fixture.id, binding(), {
    ...fixture.options,
    refresh,
  });

  const first = provider.onUnauthorized!(unauthorizedContext());
  await waitUntilEntered(entered.promise, first);
  const second = provider.onUnauthorized!(unauthorizedContext());
  release.resolve();
  await Promise.all([first, second]);

  expect(seen).toEqual(["refresh-1", "refresh-2"]);
  await expect(provider.token()).resolves.toBe("access-3");
});

test.each(["abort", "timeout"] as const)(
  "%s cancels refresh and releases the lock",
  async (mode) => {
    const fixture = await storedProfile();
    const controller = new AbortController();
    const entered = deferred<void>();
    let rejectLate!: (error: unknown) => void;
    const never = new Promise<OAuthTokens>((_resolve, reject) => {
      rejectLate = reject;
    });
    const provider = createOAuthAuthProvider(fixture.id, binding(), {
      ...fixture.options,
      refresh: async () => {
        entered.resolve();
        return never;
      },
      ...(mode === "abort"
        ? { signal: controller.signal, refreshTimeoutMs: 5_000 }
        : { refreshTimeoutMs: 10 }),
    });

    const attempt = provider.onUnauthorized!(unauthorizedContext());
    await waitUntilEntered(entered.promise, attempt);
    if (mode === "abort") controller.abort();
    await expect(attempt).rejects.toThrow(loginInstruction(fixture.id));
    rejectLate(new Error("late refresh secret"));

    const retry = createOAuthAuthProvider(fixture.id, binding(), {
      ...fixture.options,
      lockTimeoutMs: 100,
      refresh: async () => refreshedTokens(),
    });
    await expect(retry.onUnauthorized!(unauthorizedContext())).resolves.toBeUndefined();
  },
);

test("a refresh-lock release failure restores the exact encrypted profile", async () => {
  const fixture = await storedProfile();
  const before = await profileBytes(fixture);
  unlinkFailure.path = join(
    fixture.home,
    ".mcp-restrictor",
    "oauth",
    `.${fixture.id}.json.refresh.lock`,
  );
  const provider = createOAuthAuthProvider(fixture.id, binding(), {
    ...fixture.options,
    refresh: async () => refreshedTokens(),
  });

  await expect(provider.onUnauthorized!(unauthorizedContext())).rejects.toThrow(
    loginInstruction(fixture.id),
  );
  expect(unlinkFailure.path).toBeUndefined();
  expect(await profileBytes(fixture)).toBe(before);
});

test("a redirected refresh cannot leak credentials to another origin", async () => {
  let leaked = "";
  const receiver = createServer(async (request, response) => {
    leaked += `${request.headers.authorization ?? ""}${await requestBody(request)}`;
    response.end();
  });
  const receiverUrl = await listen(receiver);
  const redirector = createServer((_request, response) => {
    response.statusCode = 307;
    response.setHeader("location", receiverUrl);
    response.end();
  });
  const redirectorUrl = await listen(redirector);
  try {
    const fixture = await storedProfile();
    const before = await profileBytes(fixture);
    const provider = createOAuthAuthProvider(fixture.id, binding(), {
      ...fixture.options,
      refresh: async (_url, options) => {
        await options.fetchFn?.(redirectorUrl, {
          method: "POST",
          headers: { authorization: "Basic client-secret-literal" },
          body: `refresh_token=${options.refreshToken}`,
        });
        return refreshedTokens();
      },
    });

    await expect(provider.onUnauthorized!(unauthorizedContext())).rejects.toThrow(
      loginInstruction(fixture.id),
    );
    expect(leaked).toBe("");
    expect(await profileBytes(fixture)).toBe(before);
  } finally {
    await Promise.all([close(receiver), close(redirector)]);
  }
});

type StoredFixture = {
  id: string;
  home: string;
  options: OAuthRuntimeOptions;
};

async function storedProfile(mutate?: (profile: OAuthProfile) => void): Promise<StoredFixture> {
  const home = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-provider-")));
  homes.push(home);
  const id = randomUUID();
  const key = randomBytes(32).toString("base64url");
  const options: OAuthRuntimeOptions = {
    home,
    environment: {},
    loadKeyringEntry: async () => ({
      getPassword: () => key,
      setPassword: () => undefined,
    }),
  };
  const profile = exampleProfile(id);
  mutate?.(profile);
  await writeOAuthProfile(profile, options);
  return { id, home, options };
}

function exampleProfile(id: string): OAuthProfile {
  const issuer = "https://auth.example.com";
  return {
    metadata: {
      version: 1,
      profileId: id,
      serverUrl: binding().serverUrl,
      resource: binding().resource,
      callback: {
        host: "127.0.0.1",
        path: "/callback",
        appendProfileId: true,
      },
      clientMetadata: {},
    },
    credentials: {
      clientInformation: {
        client_id: "client-id-secret",
        client_secret: "client-secret-literal",
        issuer,
      },
      tokens: {
        access_token: "access-1",
        refresh_token: "refresh-1",
        token_type: "Bearer",
        issuer,
      },
      discoveryState: {
        authorizationServerUrl: issuer,
        authorizationServerMetadata: {
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks.json`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          token_endpoint_auth_methods_supported: ["client_secret_basic"],
        },
      },
    },
  };
}

function binding(): { serverUrl: string; resource: string } {
  return {
    serverUrl: "https://api.example.com/mcp/path",
    resource: "https://resource.example.com/mcp",
  };
}

function unauthorizedContext() {
  return {
    response: new Response(null, { status: 401 }),
    serverUrl: new URL(binding().serverUrl),
    fetchFn: vi.fn(async () => {
      throw new Error("transport fetch leaked configured secret");
    }),
  };
}

function loginInstruction(id: string): RegExp {
  return new RegExp(`mcp-restrictor oauth login ${id}`);
}

async function profileBytes(fixture: StoredFixture): Promise<string> {
  return readFile(oauthProfilePath(fixture.home, fixture.id), "utf8");
}

function refreshedTokens(override: Partial<OAuthTokens> = {}): OAuthTokens {
  return {
    access_token: "access-2",
    refresh_token: "refresh-2",
    token_type: "Bearer",
    ...override,
  };
}

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((accept, fail) => {
    resolve = accept;
    reject = fail;
  });
  return { promise, resolve, reject };
}

async function rejectionMessage(run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
    throw new Error("Expected rejection");
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

async function waitUntilEntered(entered: Promise<void>, attempt: Promise<unknown>): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      entered,
      attempt.then(
        () => {
          throw new Error("Refresh completed before entering the test seam");
        },
        (error) => {
          throw error;
        },
      ),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("Refresh did not enter")), 1_000);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Missing test address");
  return `http://127.0.0.1:${address.port}/token`;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function requestBody(request: NodeJS.ReadableStream): Promise<string> {
  let body = "";
  for await (const chunk of request) body += String(chunk);
  return body;
}
