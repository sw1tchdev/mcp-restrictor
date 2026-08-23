import { describe, expect, it } from "vitest";
import {
  abortError,
  ABORT_ERROR_NAME,
  asError,
  CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE,
  isAbortError,
  isRecord,
  MAX_MCP_MESSAGE_BYTES,
  raceWithAbort,
} from "../src/utils.js";

describe("shared transport values", () => {
  it("normalizes errors and recognizes records", () => {
    const error = new Error("failure");
    expect(asError(error)).toBe(error);
    expect(asError("failure")).toEqual(new Error("failure"));
    expect(isRecord({ value: 1 })).toBe(true);
    expect(isRecord([])).toBe(false);
    expect(isRecord(null)).toBe(false);
    expect(MAX_MCP_MESSAGE_BYTES).toBe(10 * 1024 * 1024);
    expect(abortError()).toMatchObject({ name: "AbortError", message: "AbortError" });
    expect(ABORT_ERROR_NAME).toBe("AbortError");
    expect(CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE).toBe("conflicting upstream authentication");
  });
});

describe("shared transport abort handling", () => {
  it("returns completed work and races pending work with abort", async () => {
    await expect(raceWithAbort(Promise.resolve("done"))).resolves.toBe("done");

    const controller = new AbortController();
    const pending = raceWithAbort(new Promise<never>(() => undefined), controller.signal);
    controller.abort();
    const error = await pending.catch((failure: unknown) => failure);
    expect(isAbortError(error)).toBe(true);
  });
});
