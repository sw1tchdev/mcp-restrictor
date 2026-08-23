import { createCipheriv, randomBytes, randomUUID } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import * as oauthStorage from "../src/oauth/storage.ts";
import {
  MASTER_KEY_FILE_ENV,
  assertOAuthStorageReady,
  configuredMasterKeyFile,
  oauthProfilePath,
  prepareOAuthProfileWrite,
  readOAuthProfile,
  readOAuthProfileSnapshot,
  writeOAuthProfile,
  type KeyringEntry,
  type OAuthProfile,
  type OAuthStorageOptions,
} from "../src/oauth/storage.ts";
import { CONTAINER_MARKER_ENV } from "../src/setup/constants.ts";

const storageTestState = vi.hoisted(() => ({
  accountHome: undefined as string | undefined,
  containerRoot: undefined as string | undefined,
  environmentHomes: [] as string[],
  lockBarrier: undefined as
    | {
        successes: number;
        release(): void;
        wait: Promise<void>;
      }
    | undefined,
  containerCreateRace: undefined as
    | {
        missingObservations: number;
        publications: number;
        winner?: { content: string; ino: number; mode: number };
        releaseMissing(): void;
        bothMissing: Promise<void>;
      }
    | undefined,
  targetUid: undefined as number | undefined,
  targetLstatCalls: 0,
}));

vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return {
    ...actual,
    homedir: () =>
      storageTestState.environmentHomes.shift() ?? storageTestState.accountHome ?? actual.homedir(),
    userInfo: () => ({
      ...actual.userInfo(),
      homedir: storageTestState.accountHome ?? actual.userInfo().homedir,
    }),
  };
});

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  const mapped = (path: Parameters<typeof actual.lstat>[0]) => {
    if (
      typeof path !== "string" ||
      storageTestState.containerRoot === undefined ||
      (path !== "/home" && !path.startsWith("/home/"))
    ) {
      return path;
    }
    return `${storageTestState.containerRoot}${path.slice("/home".length)}`;
  };
  return {
    ...actual,
    chmod: (path: Parameters<typeof actual.chmod>[0], mode: number | string) =>
      actual.chmod(mapped(path), mode),
    lstat: async (path: Parameters<typeof actual.lstat>[0], options?: object) => {
      let stat;
      try {
        stat = await actual.lstat(mapped(path), options as never);
      } catch (error) {
        const race = storageTestState.containerCreateRace;
        if (
          path === "/home/restrictor/.mcp-restrictor-key/oauth-master-key-v1" &&
          (error as NodeJS.ErrnoException).code === "ENOENT" &&
          race &&
          race.missingObservations < 2
        ) {
          race.missingObservations += 1;
          if (race.missingObservations === 2) race.releaseMissing();
          await race.bothMissing;
        }
        throw error;
      }
      if (
        path === "/home/restrictor/.mcp-restrictor-key/oauth-master-key-v1" &&
        storageTestState.targetUid !== undefined
      ) {
        storageTestState.targetLstatCalls += 1;
        const uid = storageTestState.targetUid;
        return new Proxy(stat, {
          get(target, property) {
            if (property === "uid") return uid;
            const value = Reflect.get(target, property, target);
            return typeof value === "function" ? value.bind(target) : value;
          },
        });
      }
      return stat;
    },
    mkdir: (path: Parameters<typeof actual.mkdir>[0], options?: object) =>
      actual.mkdir(mapped(path), options as never),
    open: (path: Parameters<typeof actual.open>[0], ...args: unknown[]) =>
      actual.open(mapped(path), ...(args as [string | number, number?])),
    rename: async (
      oldPath: Parameters<typeof actual.rename>[0],
      newPath: Parameters<typeof actual.rename>[1],
    ) => {
      await actual.rename(mapped(oldPath), mapped(newPath));
      const race = storageTestState.containerCreateRace;
      if (newPath === "/home/restrictor/.mcp-restrictor-key/oauth-master-key-v1" && race) {
        race.publications += 1;
        if (!race.winner) {
          const [content, stat] = await Promise.all([
            actual.readFile(mapped(newPath), "utf8"),
            actual.lstat(mapped(newPath)),
          ]);
          race.winner = { content, ino: stat.ino, mode: stat.mode & 0o7777 };
        }
      }
    },
    rmdir: (path: Parameters<typeof actual.rmdir>[0]) => actual.rmdir(mapped(path)),
    unlink: (path: Parameters<typeof actual.unlink>[0]) => actual.unlink(mapped(path)),
    link: async (existingPath: string, newPath: string) => {
      const barrier = storageTestState.lockBarrier;
      try {
        await actual.link(mapped(existingPath), mapped(newPath));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "EEXIST") barrier?.release();
        throw error;
      }
      if (barrier) {
        barrier.successes += 1;
        if (barrier.successes === 2) barrier.release();
        await barrier.wait;
      }
    },
  };
});

const temporaryDirectories: string[] = [];

beforeEach(async () => {
  storageTestState.accountHome = await temporaryDirectory();
  storageTestState.containerRoot = await temporaryDirectory();
  await mkdir(join(storageTestState.containerRoot, "restrictor"), { mode: 0o700 });
  await chmod(join(storageTestState.containerRoot, "restrictor"), 0o700);
});

afterEach(async () => {
  vi.restoreAllMocks();
  storageTestState.lockBarrier?.release();
  storageTestState.lockBarrier = undefined;
  storageTestState.containerCreateRace?.releaseMissing();
  storageTestState.containerCreateRace = undefined;
  storageTestState.targetUid = undefined;
  storageTestState.targetLstatCalls = 0;
  storageTestState.accountHome = undefined;
  storageTestState.containerRoot = undefined;
  storageTestState.environmentHomes.length = 0;
  await Promise.all(
    temporaryDirectories.splice(0).map((path) => rm(path, { force: true, recursive: true })),
  );
});

test("encrypts credentials and discovery state with AES-256-GCM and round-trips", async () => {
  const home = await temporaryDirectory();
  const profile = exampleProfile();
  const options = keyringOptions(home, randomBytes(32));

  const prepared = await prepareOAuthProfileWrite(profile, options);
  const envelope = JSON.parse(prepared.content) as Record<string, unknown>;
  const encryption = envelope.encryption as Record<string, string>;

  expect(prepared.path).toBe(oauthProfilePath(home, profile.metadata.profileId));
  expect(prepared.mode).toBe(0o600);
  expect(Object.keys(envelope)).toEqual([
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
    "encryption",
  ]);
  expect(encryption.algorithm).toBe("A256GCM");
  expect(Buffer.from(encryption.nonce!, "base64url")).toHaveLength(12);
  expect(Buffer.from(encryption.tag!, "base64url")).toHaveLength(16);
  for (const plaintext of [
    "access-token-literal",
    "refresh-token-literal",
    "client-secret-literal",
    JSON.stringify(profile.credentials.discoveryState),
  ]) {
    expect(prepared.content).not.toContain(plaintext);
  }

  await writeOAuthProfile(profile, options);
  const stored = await readOAuthProfileSnapshot(profile.metadata.profileId, options);
  expect(stored.profile).toEqual(profile);
  expect(stored.snapshot.content).toBe(await readFile(prepared.path, "utf8"));
  expect((await lstat(prepared.path)).mode & 0o7777).toBe(0o600);
  expect((await lstat(dirname(prepared.path))).mode & 0o7777).toBe(0o700);
});

test("decrypts legacy callback AAD before normalizing stored metadata", async () => {
  const home = await temporaryDirectory();
  const profile = exampleProfile();
  const key = Buffer.alloc(32, 7);
  const options = keyringOptions(home, key);
  const storedMetadata = {
    ...profile.metadata,
    callback: { kind: "codex" },
  };
  const nonce = Buffer.alloc(12, 8);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify(storedMetadata)));
  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(profile.credentials))),
    cipher.final(),
  ]);
  const path = oauthProfilePath(home, profile.metadata.profileId);
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(
    path,
    JSON.stringify({
      ...storedMetadata,
      encryption: {
        algorithm: "A256GCM",
        nonce: nonce.toString("base64url"),
        ciphertext: ciphertext.toString("base64url"),
        tag: cipher.getAuthTag().toString("base64url"),
      },
    }),
    { mode: 0o600 },
  );

  const stored = await readOAuthProfileSnapshot(profile.metadata.profileId, options);

  expect(stored.profile.metadata.callback).toEqual({
    host: "127.0.0.1",
    path: "/callback",
    appendProfileId: true,
  });
});

test("uses a fresh 12-byte nonce for two real writes of equal plaintext", async () => {
  const home = await temporaryDirectory();
  const profile = exampleProfile();
  const options = keyringOptions(home, randomBytes(32));

  const first = await writeOAuthProfile(profile, options);
  const firstEnvelope = JSON.parse(await readFile(first.path, "utf8")) as {
    encryption: { nonce: string };
  };
  const second = await writeOAuthProfile(profile, { ...options, before: first });
  const secondEnvelope = JSON.parse(await readFile(second.path, "utf8")) as {
    encryption: { nonce: string };
  };

  expect(Buffer.from(firstEnvelope.encryption.nonce, "base64url")).toHaveLength(12);
  expect(Buffer.from(secondEnvelope.encryption.nonce, "base64url")).toHaveLength(12);
  expect(secondEnvelope.encryption.nonce).not.toBe(firstEnvelope.encryption.nonce);
});

test("rejects ciphertext tampering and a wrong master key without secret-bearing errors", async () => {
  const home = await temporaryDirectory();
  const profile = exampleProfile();
  const path = oauthProfilePath(home, profile.metadata.profileId);
  const correct = keyringOptions(home, Buffer.alloc(32, 1));
  await writeOAuthProfile(profile, correct);
  const envelope = JSON.parse(await readFile(path, "utf8")) as {
    encryption: { ciphertext: string };
  };
  envelope.encryption.ciphertext = mutateBase64Url(envelope.encryption.ciphertext);
  await writeFile(path, JSON.stringify(envelope), { mode: 0o600 });

  const tampered = await rejectionMessage(() =>
    readOAuthProfile(profile.metadata.profileId, correct),
  );
  expect(tampered).toMatch(new RegExp(profile.metadata.profileId));
  expect(tampered).not.toMatch(/access-token-literal|refresh-token-literal|client-secret-literal/);

  const wrongKeyHome = await temporaryDirectory();
  const rightKeyOptions = keyringOptions(wrongKeyHome, Buffer.alloc(32, 1));
  await writeOAuthProfile(profile, rightKeyOptions);
  const wrongKey = await rejectionMessage(() =>
    readOAuthProfile(profile.metadata.profileId, keyringOptions(wrongKeyHome, Buffer.alloc(32, 2))),
  );
  expect(wrongKey).toMatch(new RegExp(profile.metadata.profileId));
  expect(wrongKey).not.toMatch(/access-token-literal|refresh-token-literal|client-secret-literal/);
});

test("authenticates every clear metadata field as fixed-order AAD", async () => {
  const home = await temporaryDirectory();
  const profile = exampleProfile();
  const options = keyringOptions(home, Buffer.alloc(32, 3));
  const prepared = await prepareOAuthProfileWrite(profile, options);
  const path = prepared.path;
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });

  const mutations: Array<[string, (value: Record<string, any>) => void]> = [
    [
      "version",
      (value) => {
        value.version = 2;
      },
    ],
    [
      "profileId",
      (value) => {
        value.profileId = randomUUID();
      },
    ],
    [
      "server origin",
      (value) => {
        value.serverUrl = "https://other.example.com/original/path";
      },
    ],
    [
      "server path",
      (value) => {
        value.serverUrl = "https://api.example.com/changed/path";
      },
    ],
    [
      "requestedScope",
      (value) => {
        value.requestedScope = "admin";
      },
    ],
    [
      "resource",
      (value) => {
        value.resource = "https://resource.example.com/other";
      },
    ],
    [
      "resourceMetadataUrl",
      (value) => {
        value.resourceMetadataUrl = "https://resource.example.com/other-metadata";
      },
    ],
    [
      "authServerMetadataUrl",
      (value) => {
        value.authServerMetadataUrl = "https://auth.example.com/other-metadata";
      },
    ],
    [
      "callback port",
      (value) => {
        value.callback.port = 4555;
      },
    ],
    [
      "callback URL",
      (value) => {
        value.callback.url = "http://127.0.0.1:4555/callback";
      },
    ],
    [
      "callback profile suffix",
      (value) => {
        value.callback.appendProfileId = false;
      },
    ],
    [
      "callbackUrl",
      (value) => {
        value.callbackUrl = "http://127.0.0.1:4555/complete";
      },
    ],
    [
      "clientMetadata",
      (value) => {
        value.clientMetadata.client_name = "tampered client";
      },
    ],
  ];

  for (const [name, mutate] of mutations) {
    const envelope = JSON.parse(prepared.content) as Record<string, any>;
    mutate(envelope);
    await writeFile(path, JSON.stringify(envelope), { mode: 0o600 });
    await expect(readOAuthProfile(profile.metadata.profileId, options), name).rejects.toThrow(
      /OAuth profile.*(parse|decrypt)/i,
    );
  }
});

test("rejects malformed envelope fields before decryption", async () => {
  const home = await temporaryDirectory();
  const profile = exampleProfile();
  const options = keyringOptions(home, Buffer.alloc(32, 4));
  const prepared = await prepareOAuthProfileWrite(profile, options);
  const path = prepared.path;
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const envelope = JSON.parse(prepared.content) as Record<string, any>;
  envelope.encryption.nonce = "not/base64url";
  await writeFile(path, JSON.stringify(envelope), { mode: 0o600 });

  await expect(readOAuthProfile(profile.metadata.profileId, options)).rejects.toThrow(
    /OAuth profile.*parse/i,
  );
});

test("rejects a valid authenticated envelope relocated to another profile UUID path", async () => {
  const home = await temporaryDirectory();
  const profile = exampleProfile();
  const relocatedId = randomUUID();
  const options = keyringOptions(home, Buffer.alloc(32, 9));
  const written = await writeOAuthProfile(profile, options);
  const relocatedPath = oauthProfilePath(home, relocatedId);
  await writeFile(relocatedPath, await readFile(written.path, "utf8"), {
    mode: 0o600,
  });
  await chmod(relocatedPath, 0o600);

  await expect(readOAuthProfileSnapshot(relocatedId, options)).rejects.toThrow(
    new RegExp(`OAuth profile ${relocatedId} decrypt failed`),
  );
});

test("validates a canonical random UUID before joining a profile path", async () => {
  const home = await temporaryDirectory();
  const id = randomUUID();
  expect(oauthProfilePath(home, id)).toBe(join(home, ".mcp-restrictor", "oauth", `${id}.json`));
  for (const invalid of ["../escape", id.toUpperCase(), "00000000-0000-0000-0000-000000000000"]) {
    expect(() => oauthProfilePath(home, invalid)).toThrow(/profile/i);
  }
});

test("resolves only an own non-empty master-key file selector", () => {
  const cwd = "/fixed/wrapper/root";
  expect(configuredMasterKeyFile({}, cwd)).toBeUndefined();
  expect(configuredMasterKeyFile({ [MASTER_KEY_FILE_ENV]: "" }, cwd)).toBeUndefined();

  const inherited = Object.create({
    [MASTER_KEY_FILE_ENV]: "inherited.key",
  }) as NodeJS.ProcessEnv;
  expect(configuredMasterKeyFile(inherited, cwd)).toBeUndefined();

  const nullPrototype = Object.create(null) as NodeJS.ProcessEnv;
  nullPrototype[MASTER_KEY_FILE_ENV] = "__proto__/master.key";
  expect(configuredMasterKeyFile(nullPrototype, cwd)).toBe(resolve(cwd, "__proto__/master.key"));
  expect(configuredMasterKeyFile({ [MASTER_KEY_FILE_ENV]: "/absolute/master.key" }, cwd)).toBe(
    "/absolute/master.key",
  );
});

test("container setup key creates only the exact default private file", async () => {
  const loadKeyringEntry = vi.fn(async () => memoryEntry(null).entry);

  await prepareSetupKey(containerStorageOptions({ loadKeyringEntry }));

  const path = physicalContainerKeyPath();
  const content = await readFile(path, "utf8");
  expect(content).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(Buffer.from(content, "base64url")).toHaveLength(32);
  expect(content).not.toContain("\n");
  expect((await lstat(path)).mode & 0o7777).toBe(0o600);
  expect((await lstat(dirname(path))).mode & 0o7777).toBe(0o700);
  expect(loadKeyringEntry).not.toHaveBeenCalled();
});

test("container setup key reuses valid bytes without replacing the file", async () => {
  const parent = dirname(physicalContainerKeyPath());
  await mkdir(parent, { mode: 0o700 });
  await chmod(parent, 0o700);
  const expected = Buffer.alloc(32, 11).toString("base64url");
  await writeFile(physicalContainerKeyPath(), expected, { mode: 0o600 });
  await chmod(physicalContainerKeyPath(), 0o600);
  const before = await lstat(physicalContainerKeyPath());

  await prepareSetupKey(containerStorageOptions());

  const after = await lstat(physicalContainerKeyPath());
  expect(await readFile(physicalContainerKeyPath(), "utf8")).toBe(expected);
  expect(after.ino).toBe(before.ino);
});

test("container setup key remains after the caller cancels setup", async () => {
  const options = containerStorageOptions();
  const controller = new AbortController();
  const cancelAfterPreparation = async () => {
    await prepareSetupKey(options);
    controller.abort();
    controller.signal.throwIfAborted();
  };

  await expect(cancelAfterPreparation()).rejects.toThrow();
  const before = await lstat(physicalContainerKeyPath());
  const content = await readFile(physicalContainerKeyPath(), "utf8");
  await prepareSetupKey(options);

  expect(await readFile(physicalContainerKeyPath(), "utf8")).toBe(content);
  expect((await lstat(physicalContainerKeyPath())).ino).toBe(before.ino);
});

test("concurrent container setup key creation installs one create-only winner", async () => {
  const options = containerStorageOptions();
  let releaseMissing!: () => void;
  const bothMissing = new Promise<void>((resolve) => {
    releaseMissing = resolve;
  });
  storageTestState.containerCreateRace = {
    missingObservations: 0,
    publications: 0,
    releaseMissing,
    bothMissing,
  };

  await Promise.all([prepareSetupKey(options), prepareSetupKey(options)]);

  const content = await readFile(physicalContainerKeyPath(), "utf8");
  const stat = await lstat(physicalContainerKeyPath());
  expect(content).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(storageTestState.containerCreateRace.missingObservations).toBe(2);
  expect(storageTestState.containerCreateRace.publications).toBe(1);
  expect({ content, ino: stat.ino, mode: stat.mode & 0o7777 }).toEqual(
    storageTestState.containerCreateRace.winner,
  );
  expect(await readdir(dirname(physicalContainerKeyPath()))).toEqual(["oauth-master-key-v1"]);
});

test.each([undefined, "", "true", "01"])(
  "container setup key requires exact marker 1: %j",
  async (marker) => {
    const environment: NodeJS.ProcessEnv = {
      [MASTER_KEY_FILE_ENV]: "/home/restrictor/.mcp-restrictor-key/oauth-master-key-v1",
      ...(marker === undefined ? {} : { [CONTAINER_MARKER_ENV]: marker }),
    };

    await expect(
      prepareSetupKey({ home: storageTestState.accountHome!, environment }),
    ).rejects.toThrow(/master key/i);
    expect(await exists(physicalContainerKeyPath())).toBe(false);
  },
);

test("container setup key refuses a missing custom selector", async () => {
  const home = await temporaryDirectory();
  const custom = join(home, "custom.key");

  await expect(
    prepareSetupKey({
      home,
      environment: {
        [CONTAINER_MARKER_ENV]: "1",
        [MASTER_KEY_FILE_ENV]: custom,
      },
    }),
  ).rejects.toThrow(/master key/i);

  expect(await exists(custom)).toBe(false);
  expect(await exists(physicalContainerKeyPath())).toBe(false);
});

test("container setup key rejects linked, permissive, and malformed existing files", async () => {
  const parent = dirname(physicalContainerKeyPath());
  await mkdir(parent, { mode: 0o700 });
  await chmod(parent, 0o700);
  const target = join(storageTestState.containerRoot!, "target.key");
  await writeFile(target, Buffer.alloc(32, 12).toString("base64url"), { mode: 0o600 });
  await symlink(target, physicalContainerKeyPath());
  await expect(prepareSetupKey(containerStorageOptions())).rejects.toThrow(/master key/i);
  await rm(physicalContainerKeyPath());

  await writeFile(physicalContainerKeyPath(), Buffer.alloc(32, 13).toString("base64url"), {
    mode: 0o640,
  });
  await chmod(physicalContainerKeyPath(), 0o640);
  if (process.platform !== "win32") {
    await expect(prepareSetupKey(containerStorageOptions())).rejects.toThrow(/master key/i);
  }
  await rm(physicalContainerKeyPath());

  await writeFile(physicalContainerKeyPath(), "not-a-master-key", { mode: 0o600 });
  await chmod(physicalContainerKeyPath(), 0o600);
  await expect(prepareSetupKey(containerStorageOptions())).rejects.toThrow(/master key/i);
  expect(await readFile(physicalContainerKeyPath(), "utf8")).toBe("not-a-master-key");
});

test("container setup key rejects a wrong-owner target without changing it", async () => {
  if (!process.getuid) return;
  const parent = dirname(physicalContainerKeyPath());
  await mkdir(parent, { mode: 0o700 });
  await chmod(parent, 0o700);
  const content = Buffer.alloc(32, 14).toString("base64url");
  await writeFile(physicalContainerKeyPath(), content, { mode: 0o600 });
  await chmod(physicalContainerKeyPath(), 0o600);
  const before = await lstat(physicalContainerKeyPath());
  storageTestState.targetUid = before.uid + 1;

  try {
    await expect(prepareSetupKey(containerStorageOptions())).rejects.toThrow(/master key/i);
    expect(storageTestState.targetLstatCalls).toBeGreaterThanOrEqual(2);
  } finally {
    storageTestState.targetUid = undefined;
  }

  const after = await lstat(physicalContainerKeyPath());
  expect(await readFile(physicalContainerKeyPath(), "utf8")).toBe(content);
  expect(after.ino).toBe(before.ino);
  expect(after.mode).toBe(before.mode);
});

test("container setup key rejects a linked or permissive parent", async () => {
  const parent = dirname(physicalContainerKeyPath());
  const target = join(storageTestState.containerRoot!, "key-parent");
  await mkdir(target, { mode: 0o700 });
  await symlink(target, parent);
  await expect(prepareSetupKey(containerStorageOptions())).rejects.toThrow(/master key/i);
  await rm(parent);

  await mkdir(parent, { mode: 0o755 });
  await chmod(parent, 0o755);
  await expect(prepareSetupKey(containerStorageOptions())).rejects.toThrow(/master key/i);
  expect((await lstat(parent)).mode & 0o7777).toBe(0o755);
});

test("setup key preparation preserves native keyring behavior without creating a file", async () => {
  const generated = memoryEntry(null);

  await prepareSetupKey({
    home: storageTestState.accountHome!,
    environment: {},
    loadKeyringEntry: async () => generated.entry,
  });

  expect(generated.setPassword).toHaveBeenCalledOnce();
  expect(generated.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(await exists(physicalContainerKeyPath())).toBe(false);
});

test("uses a strict private master-key file without loading keyring", async () => {
  const home = await temporaryDirectory();
  const keyPath = join(home, "master.key");
  const key = Buffer.alloc(32, 5).toString("base64url");
  await writeFile(keyPath, key, { mode: 0o600 });
  await chmod(keyPath, 0o600);
  const loadKeyringEntry = vi.fn(async () => memoryEntry(null));
  const options: OAuthStorageOptions = {
    home,
    environment: { [MASTER_KEY_FILE_ENV]: keyPath },
    loadKeyringEntry,
  };

  await assertOAuthStorageReady(options);
  await prepareOAuthProfileWrite(exampleProfile(), options);

  expect(loadKeyringEntry).not.toHaveBeenCalled();
  expect(await exists(join(home, ".mcp-restrictor", "oauth"))).toBe(false);
});

test("rejects malformed, linked, non-regular, and non-private key files", async () => {
  const home = await temporaryDirectory();
  const valid = join(home, "valid.key");
  const linked = join(home, "linked.key");
  const directory = join(home, "key-directory");
  await writeFile(valid, Buffer.alloc(32, 6).toString("base64url"), { mode: 0o600 });
  await chmod(valid, 0o600);
  await symlink(valid, linked);
  await mkdir(directory);

  const invalidFiles: Array<[string, string]> = [
    ["short.key", Buffer.alloc(31, 1).toString("base64url")],
    ["newline.key", `${Buffer.alloc(32, 1).toString("base64url")}\n`],
    ["padded.key", `${Buffer.alloc(32, 1).toString("base64url")}=`],
  ];
  for (const [name, content] of invalidFiles) {
    const path = join(home, name);
    await writeFile(path, content, { mode: 0o600 });
    await chmod(path, 0o600);
    await expect(assertOAuthStorageReady(keyFileOptions(home, path))).rejects.toThrow(
      /master key/i,
    );
  }

  await expect(assertOAuthStorageReady(keyFileOptions(home, linked))).rejects.toThrow(
    /master key/i,
  );
  await expect(assertOAuthStorageReady(keyFileOptions(home, directory))).rejects.toThrow(
    /master key/i,
  );

  if (process.platform !== "win32") {
    await chmod(valid, 0o640);
    await expect(assertOAuthStorageReady(keyFileOptions(home, valid))).rejects.toThrow(
      /master key/i,
    );
  }
});

test("rejects a master-key file owned by another uid", async () => {
  if (!process.getuid) return;
  const home = await temporaryDirectory();
  const path = join(home, "master.key");
  await writeFile(path, Buffer.alloc(32, 7).toString("base64url"), { mode: 0o600 });
  await chmod(path, 0o600);
  const uid = process.getuid();
  const getuid = vi.spyOn(process, "getuid").mockReturnValue(uid + 1);
  try {
    await expect(assertOAuthStorageReady(keyFileOptions(home, path))).rejects.toThrow(
      /master key/i,
    );
  } finally {
    getuid.mockRestore();
  }
});

test("reuses a keyring key or generates and stores one key exactly once", async () => {
  const firstHome = await temporaryDirectory();
  const existing = memoryEntry(Buffer.alloc(32, 8).toString("base64url"));
  await assertOAuthStorageReady({
    home: firstHome,
    environment: {},
    loadKeyringEntry: async () => existing.entry,
  });
  expect(existing.getPassword).toHaveBeenCalledOnce();
  expect(existing.setPassword).not.toHaveBeenCalled();

  const secondHome = await temporaryDirectory();
  const generated = memoryEntry(null);
  const generatedOptions: OAuthStorageOptions = {
    home: secondHome,
    environment: {},
    loadKeyringEntry: async () => generated.entry,
  };
  await assertOAuthStorageReady(generatedOptions);
  await assertOAuthStorageReady(generatedOptions);

  expect(generated.setPassword).toHaveBeenCalledOnce();
  expect(generated.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(Buffer.from(generated.value!, "base64url")).toHaveLength(32);
  expect(await exists(join(secondHome, ".mcp-restrictor", "oauth"))).toBe(false);
});

test("concurrent keyring first use across environment homes uses one OS-account winner", async () => {
  const homes = await Promise.all([temporaryDirectory(), temporaryDirectory()]);
  storageTestState.environmentHomes.push(
    ...(await Promise.all([temporaryDirectory(), temporaryDirectory()])),
  );
  const profiles = [exampleProfile(), exampleProfile()];
  const state = { value: null as string | null, setCalls: 0, loads: 0 };
  let release!: () => void;
  const bothLoaded = new Promise<void>((resolve) => {
    release = resolve;
  });
  let releaseLocked!: () => void;
  const bothLocked = new Promise<void>((resolve) => {
    releaseLocked = resolve;
  });
  let lockedLoads = 0;
  let releaseLocks!: () => void;
  const lockWait = new Promise<void>((resolve) => {
    releaseLocks = resolve;
  });
  storageTestState.lockBarrier = {
    successes: 0,
    release: releaseLocks,
    wait: lockWait,
  };
  const loadKeyringEntry = async (): Promise<KeyringEntry> => {
    const observed = state.value;
    state.loads += 1;
    if (state.loads <= 2) {
      if (state.loads === 2) release();
      await bothLoaded;
    }
    if (observed === null && storageTestState.lockBarrier?.successes === 2) {
      lockedLoads += 1;
      if (lockedLoads === 2) releaseLocked();
      await bothLocked;
    }
    return {
      getPassword: () => observed,
      setPassword: (password) => {
        state.setCalls += 1;
        state.value = password;
      },
    };
  };
  const options = homes.map<OAuthStorageOptions>((home) => ({
    home,
    environment: {},
    loadKeyringEntry,
  }));

  await Promise.all(profiles.map((profile, index) => writeOAuthProfile(profile, options[index]!)));

  expect(state.setCalls).toBe(1);
  await expect(
    Promise.all(
      profiles.map(({ metadata }, index) =>
        readOAuthProfile(
          metadata.profileId,
          keyringOptions(homes[index]!, Buffer.from(state.value!, "base64url")),
        ),
      ),
    ),
  ).resolves.toEqual(profiles);
});

test("has no plaintext fallback when keyring loading or stored key validation fails", async () => {
  const home = await temporaryDirectory();
  const unavailable = await rejectionMessage(() =>
    assertOAuthStorageReady({
      home,
      environment: {},
      loadKeyringEntry: async () => {
        throw new Error("backend unavailable with secret detail");
      },
    }),
  );
  expect(unavailable).toMatch(/master key/i);
  expect(unavailable).not.toContain("secret detail");

  const invalid = memoryEntry("plaintext-key");
  await expect(
    assertOAuthStorageReady({
      home,
      environment: {},
      loadKeyringEntry: async () => invalid.entry,
    }),
  ).rejects.toThrow(/master key/i);
  expect(invalid.setPassword).not.toHaveBeenCalled();
  expect(await exists(join(home, ".mcp-restrictor", "oauth"))).toBe(false);
});

function exampleProfile(): OAuthProfile {
  return {
    metadata: {
      version: 1,
      profileId: randomUUID(),
      serverUrl: "https://api.example.com/original/path",
      requestedScope: "read write",
      resource: "https://resource.example.com/mcp",
      resourceMetadataUrl: "https://resource.example.com/.well-known/oauth-protected-resource",
      authServerMetadataUrl: "https://auth.example.com/.well-known/oauth-authorization-server",
      callback: {
        url: "http://127.0.0.1:3210/callback",
        port: 3210,
        appendProfileId: true,
      },
      callbackUrl: "http://127.0.0.1:3210/complete",
      clientMetadata: {
        token_endpoint_auth_method: "client_secret_post",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        application_type: "native",
        client_name: "MCP Restrictor",
        client_uri: "https://example.com/client",
        logo_uri: "https://example.com/logo.png",
        scope: "read write",
        contacts: ["security@example.com"],
        tos_uri: "https://example.com/terms",
        policy_uri: "https://example.com/policy",
        jwks_uri: "https://example.com/jwks.json",
        jwks: { keys: [{ kty: "RSA", kid: "one" }] },
        software_id: "mcp-restrictor",
        software_version: "0.1.0",
        software_statement: "software-statement",
      },
    },
    credentials: {
      clientInformation: {
        client_id: "client-id-literal",
        client_secret: "client-secret-literal",
        client_id_issued_at: 1_700_000_000,
        client_secret_expires_at: 1_800_000_000,
        issuer: "https://auth.example.com",
      },
      tokens: {
        access_token: "access-token-literal",
        refresh_token: "refresh-token-literal",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "read write",
        issuer: "https://auth.example.com",
      },
      discoveryState: {
        authorizationServerUrl: "https://auth.example.com",
        authorizationServerMetadata: {
          issuer: "https://auth.example.com",
          authorization_endpoint: "https://auth.example.com/authorize",
          token_endpoint: "https://auth.example.com/token",
          jwks_uri: "https://auth.example.com/jwks.json",
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
        },
        resourceMetadata: {
          resource: "https://resource.example.com/mcp",
          authorization_servers: ["https://auth.example.com"],
        },
        resourceMetadataUrl: "https://resource.example.com/.well-known/oauth-protected-resource",
      },
    },
  };
}

function keyringOptions(home: string, key: Buffer): OAuthStorageOptions {
  return {
    home,
    environment: {},
    loadKeyringEntry: async () => memoryEntry(key.toString("base64url")).entry,
  };
}

function keyFileOptions(home: string, path: string): OAuthStorageOptions {
  return {
    home,
    environment: { [MASTER_KEY_FILE_ENV]: path },
    loadKeyringEntry: async () => {
      throw new Error("keyring must not load");
    },
  };
}

function containerStorageOptions(
  overrides: Partial<OAuthStorageOptions> = {},
): OAuthStorageOptions {
  return {
    home: storageTestState.accountHome!,
    environment: {
      [CONTAINER_MARKER_ENV]: "1",
      [MASTER_KEY_FILE_ENV]: "/home/restrictor/.mcp-restrictor-key/oauth-master-key-v1",
    },
    loadKeyringEntry: async () => {
      throw new Error("keyring must not load");
    },
    ...overrides,
  };
}

function physicalContainerKeyPath(): string {
  return join(
    storageTestState.containerRoot!,
    "restrictor",
    ".mcp-restrictor-key",
    "oauth-master-key-v1",
  );
}

async function prepareSetupKey(options: OAuthStorageOptions): Promise<void> {
  const prepare = (
    oauthStorage as typeof oauthStorage & {
      prepareOAuthStorageForSetup?(options: OAuthStorageOptions): Promise<void>;
    }
  ).prepareOAuthStorageForSetup;
  if (!prepare) throw new Error("setup key preparation is unavailable");
  await prepare(options);
}

function memoryEntry(initial: string | null): {
  entry: KeyringEntry;
  getPassword: ReturnType<typeof vi.fn<() => string | null>>;
  setPassword: ReturnType<typeof vi.fn<(password: string) => void>>;
  value: string | null;
} {
  const state = { value: initial };
  const getPassword = vi.fn(() => state.value);
  const setPassword = vi.fn((password: string) => {
    state.value = password;
  });
  return {
    entry: { getPassword, setPassword },
    getPassword,
    setPassword,
    get value() {
      return state.value;
    },
  };
}

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-oauth-")));
  temporaryDirectories.push(path);
  return path;
}

async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function mutateBase64Url(value: string): string {
  return `${value[0] === "A" ? "B" : "A"}${value.slice(1)}`;
}

async function rejectionMessage(operation: () => Promise<unknown>): Promise<string> {
  try {
    await operation();
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("Expected operation to reject");
}
