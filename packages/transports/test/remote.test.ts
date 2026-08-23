import { expect, test, vi } from "vitest";
import { fetchWithoutRedirects } from "../src/remote.ts";

test("awaits an asynchronous response validator before returning the response", async () => {
  const validationError = new Error("validation failed");
  const validator = vi.fn(async () => {
    await Promise.resolve();
    throw validationError;
  });
  const request = fetchWithoutRedirects(
    async () => new Response(null, { status: 200 }),
    validator,
  )("https://example.test/mcp");

  await expect(request).rejects.toBe(validationError);
  expect(validator).toHaveBeenCalledOnce();
});
