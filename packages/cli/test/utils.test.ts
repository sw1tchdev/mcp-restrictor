import { describe, expect, it } from "vitest";
import { ABORT_ERROR_NAME, abortable, TERMINATION_SIGNALS } from "../src/utils/async.js";
import { RESTRICTOR_HOME_DIRECTORY } from "../src/utils/paths.js";
import {
  AES_256_GCM_ALGORITHM,
  INVALID_CALLBACK_STRATEGY_MESSAGE,
  OAUTH_SERVER_BINDING_MISMATCH_MESSAGE,
} from "../src/oauth/constants.js";
import { errorCode } from "../src/utils/filesystem.js";
import { escapeControls } from "../src/utils/terminal.js";
import {
  DEFAULT_OAUTH_CALLBACK_PATH,
  OAUTH_IPV4_LOOPBACK_HOST,
  OAUTH_IPV6_LOOPBACK_HOST,
  OAUTH_LOCALHOST,
  isExactLoopbackHost,
  canonicalOptionalUrl,
  canonicalUrl,
  isReservedOAuthCallbackParameter,
  MAX_TCP_PORT,
} from "../src/oauth/urls.js";
import { validOpenCodeEntryState } from "../src/setup/opencode/entry.js";
import {
  supportsOAuthChallenge,
  withOAuthProfile,
  withStorageEnvironment,
} from "../src/setup/remote.js";
import {
  CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE,
  CONFIGURED_CREDENTIAL_PLACEHOLDER,
  DEFAULT_RESTRICTOR_COMMAND,
  INVALID_OAUTH_METADATA_MESSAGE,
  INVALID_REMOTE_CONFIGURATION_MESSAGE,
  INVALID_STDIO_ARGUMENTS_MESSAGE,
  INVALID_STDIO_ENVIRONMENT_MESSAGE,
  OAUTH_HEADER_MAPPING_CONFLICT_MESSAGE,
  OAUTH_UPSTREAM_REQUIRED_MESSAGE,
  UPSTREAM_KIND_MISMATCH_MESSAGE,
} from "../src/setup/constants.js";
import { CLIENT_CONFIGURATION_TARGET } from "../src/setup/snapshot.js";
import { sameFileSnapshot } from "../src/setup/transaction/snapshots.js";
import { processIsAlive } from "../src/utils/filesystem.js";
import {
  asciiLower,
  defineOwn,
  isRecord,
  stringArrayOrEmpty,
  stringRecordOrEmpty,
} from "../src/utils/values.js";

describe("shared CLI values", () => {
  it("keeps object parsing safe for special keys", () => {
    const record: Record<string, string> = {};
    defineOwn(record, "__proto__", "literal");

    expect(isRecord(record)).toBe(true);
    expect(isRecord(null)).toBe(false);
    expect(isRecord([])).toBe(false);
    expect(Object.getPrototypeOf(record)).toBe(Object.prototype);
    expect(Object.hasOwn(record, "__proto__")).toBe(true);
    expect(record.__proto__).toBe("literal");
    expect(asciiLower("X-ÄBC")).toBe("x-Äbc");
  });

  it("parses optional string collections without accepting mixed values", () => {
    expect(stringArrayOrEmpty(undefined)).toEqual([]);
    expect(stringArrayOrEmpty(["a", "b"])).toEqual(["a", "b"]);
    expect(stringArrayOrEmpty(["a", 1])).toBeUndefined();
    expect(stringRecordOrEmpty(undefined)).toEqual({});
    expect(stringRecordOrEmpty({ a: "b" })).toEqual({ a: "b" });
    expect(stringRecordOrEmpty({ a: 1 })).toBeUndefined();
  });
});

describe("shared CLI abort handling", () => {
  it("returns work and rejects with the abort reason", async () => {
    expect([TERMINATION_SIGNALS, ABORT_ERROR_NAME]).toEqual([["SIGINT", "SIGTERM"], "AbortError"]);
    await expect(abortable(Promise.resolve("done"), new AbortController().signal)).resolves.toBe(
      "done",
    );

    const controller = new AbortController();
    const pending = abortable(new Promise<never>(() => undefined), controller.signal);
    const reason = new Error("cancelled");
    controller.abort(reason);
    await expect(pending).rejects.toBe(reason);
  });
});

describe("shared CLI domain helpers", () => {
  it("normalizes OAuth URLs and attaches profiles only to supported sources", () => {
    expect(canonicalUrl("https://example.test")).toBe("https://example.test/");
    expect(canonicalOptionalUrl(undefined)).toBeUndefined();
    expect(
      withOAuthProfile(
        { kind: "http", url: "https://example.test/mcp", headers: [] },
        "123e4567-e89b-42d3-a456-426614174000",
      ),
    ).toMatchObject({ oauthProfileId: "123e4567-e89b-42d3-a456-426614174000" });
    expect(() =>
      withOAuthProfile({ kind: "stdio", command: "mcp", args: [], envNames: [] }, "profile"),
    ).toThrow("OAuth requires an HTTP or SSE upstream");
  });

  it("recognizes remote sources that may use an OAuth challenge", () => {
    expect(
      supportsOAuthChallenge({ kind: "http", url: "https://example.test/mcp", headers: [] }),
    ).toBe(true);
    expect(
      supportsOAuthChallenge({
        kind: "sse",
        url: "https://example.test/sse",
        headers: [{ name: "authorization", environmentVariable: "AUTH" }],
      }),
    ).toBe(false);
    expect(
      supportsOAuthChallenge({ kind: "websocket", url: "wss://example.test/mcp", headers: [] }),
    ).toBe(false);
  });

  it("adds the configured master-key path without mutating the original environment", () => {
    const wrapper = { env: { EXISTING: "value" } };
    const result = withStorageEnvironment(
      wrapper,
      { MCP_RESTRICTOR_MASTER_KEY_FILE: "/private/master.key" },
      true,
    );

    expect(result.env).toEqual({
      EXISTING: "value",
      MCP_RESTRICTOR_MASTER_KEY_FILE: "/private/master.key",
    });
    expect(wrapper.env).toEqual({ EXISTING: "value" });
  });

  it("shares OpenCode state validation and errno extraction", () => {
    expect(validOpenCodeEntryState({ enabled: true, timeout: 1 }, "v1")).toBe(true);
    expect(validOpenCodeEntryState({ enabled: false }, "v1")).toBe(false);
    expect(validOpenCodeEntryState({ disabled: false, timeout: { startup: 1 } }, "v2")).toBe(true);
    expect(validOpenCodeEntryState({ disabled: "no" }, "v2")).toBe(false);
    expect(errorCode(Object.assign(new Error("missing"), { code: "ENOENT" }))).toBe("ENOENT");
    expect(errorCode("missing")).toBeUndefined();
    expect(escapeControls("safe\u001bunsafe")).toBe("safe\\u001bunsafe");
  });

  it("shares process, callback, and complete snapshot checks", () => {
    expect(processIsAlive(process.pid)).toBe(true);
    expect(isReservedOAuthCallbackParameter("code")).toBe(true);
    expect(isReservedOAuthCallbackParameter("custom")).toBe(false);
    expect(MAX_TCP_PORT).toBe(65_535);
    expect(DEFAULT_OAUTH_CALLBACK_PATH).toBe("/callback");
    expect(["localhost", "127.0.0.1", "::1"].every(isExactLoopbackHost)).toBe(true);
    expect(isExactLoopbackHost("example.test")).toBe(false);
    expect([
      OAUTH_UPSTREAM_REQUIRED_MESSAGE,
      OAUTH_HEADER_MAPPING_CONFLICT_MESSAGE,
      INVALID_REMOTE_CONFIGURATION_MESSAGE,
      CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE,
      INVALID_OAUTH_METADATA_MESSAGE,
      INVALID_STDIO_ARGUMENTS_MESSAGE,
      INVALID_STDIO_ENVIRONMENT_MESSAGE,
      CONFIGURED_CREDENTIAL_PLACEHOLDER,
      DEFAULT_RESTRICTOR_COMMAND,
      UPSTREAM_KIND_MISMATCH_MESSAGE,
    ]).toEqual([
      "OAuth requires an HTTP or SSE upstream",
      "OAuth header mapping conflicts with the master key selector",
      "invalid remote configuration",
      "conflicting upstream authentication",
      "invalid OAuth metadata",
      "invalid STDIO arguments",
      "invalid STDIO environment",
      "configured",
      "mcp-restrictor",
      "upstream kind does not match source",
    ]);
    expect([
      AES_256_GCM_ALGORITHM,
      INVALID_CALLBACK_STRATEGY_MESSAGE,
      OAUTH_SERVER_BINDING_MISMATCH_MESSAGE,
      OAUTH_IPV4_LOOPBACK_HOST,
      OAUTH_IPV6_LOOPBACK_HOST,
      OAUTH_LOCALHOST,
    ]).toEqual([
      "A256GCM",
      "Invalid callback strategy",
      "OAuth server binding mismatch",
      "127.0.0.1",
      "::1",
      "localhost",
    ]);
    expect([RESTRICTOR_HOME_DIRECTORY, CLIENT_CONFIGURATION_TARGET]).toEqual([
      ".mcp-restrictor",
      "client configuration",
    ]);

    const snapshot = {
      path: "/tmp/config",
      content: "content",
      mode: 0o600,
      size: 7,
      mtimeMs: 1,
      dev: 2,
      ino: 3,
    };
    expect(sameFileSnapshot(snapshot, { ...snapshot })).toBe(true);
    expect(sameFileSnapshot(snapshot, { ...snapshot, path: "/tmp/other" })).toBe(false);
  });
});
