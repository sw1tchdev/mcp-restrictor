import { createInterface } from "node:readline/promises";
import { PassThrough } from "node:stream";
import { expect, test } from "vitest";
import { ConfirmationCancelled, confirmTerminal } from "../src/confirmation.ts";

function runTextConfirmation(value: string | undefined, signal = new AbortController().signal) {
  const input = new PassThrough();
  const output = new PassThrough();
  const readline = createInterface({ input, crlfDelay: Infinity });
  const answers = readline[Symbol.asyncIterator]();
  const confirmation = confirmTerminal({
    message: "Connect to this upstream?",
    input,
    output,
    error: output,
    readline,
    signal,
    ask: async (question) => {
      output.write(question);
      const answer = await answers.next();
      if (answer.done) throw new ConfirmationCancelled();
      return answer.value.trim();
    },
  });
  if (value !== undefined) setImmediate(() => input.end(value));
  return { confirmation, input, output };
}

test.each([
  ["\n", true],
  ["y\n", true],
  ["YES\n", true],
  ["n\n", false],
  ["No\n", false],
])("confirms %j as %j", async (input, expected) => {
  await expect(runTextConfirmation(input).confirmation).resolves.toBe(expected);
});

test("re-prompts after invalid text confirmation", async () => {
  const { confirmation, output } = runTextConfirmation("maybe\n\n");

  await expect(confirmation).resolves.toBe(true);
  expect(output.read()?.toString()).toBe(
    "Connect to this upstream? [Y/n]: Enter yes or no.\nConnect to this upstream? [Y/n]: ",
  );
});

test("cancels text confirmation at end of input", async () => {
  const { confirmation, input } = runTextConfirmation(undefined);
  input.end();
  await expect(confirmation).rejects.toBeInstanceOf(ConfirmationCancelled);
});

test("cancels text confirmation when aborted", async () => {
  const controller = new AbortController();
  const { confirmation, input } = runTextConfirmation(undefined, controller.signal);
  controller.abort();
  await expect(confirmation).rejects.toBeInstanceOf(ConfirmationCancelled);
  input.end();
});
