import type { Interface } from "node:readline/promises";
import { abortable } from "./utils/async.js";
import { withExclusiveReadlineInput } from "./utils/terminal-input.js";
import { MultiSelectCancelled, selectWithTui } from "./setup/tui/multi-select.js";

export class ConfirmationCancelled extends Error {}

export async function confirmTerminal(options: {
  message: string;
  input: NodeJS.ReadableStream;
  output: NodeJS.WritableStream;
  error: NodeJS.WritableStream;
  readline: Interface;
  signal: AbortSignal;
  ask(question: string): Promise<string>;
}): Promise<boolean> {
  const input = options.input as NodeJS.ReadStream;
  const supportsTui =
    input.isTTY &&
    (options.output as NodeJS.WriteStream).isTTY &&
    typeof (options.input as { setRawMode?: unknown }).setRawMode === "function";
  if (supportsTui) {
    try {
      const [index] = await withExclusiveReadlineInput(input, options.readline, () =>
        selectWithTui({
          message: options.message,
          choices: ["Yes", "No"],
          input,
          output: options.output as NodeJS.WriteStream,
          error: options.error as NodeJS.WriteStream,
          signal: options.signal,
          required: true,
          single: true,
        }),
      );
      return index === 0;
    } catch (error) {
      if (error instanceof MultiSelectCancelled || options.signal.aborted)
        throw new ConfirmationCancelled();
      throw error;
    }
  }

  for (;;) {
    try {
      const answer = (await abortable(options.ask(`${options.message} [Y/n]: `), options.signal))
        .trim()
        .toLowerCase();
      if (answer === "" || answer === "y" || answer === "yes") return true;
      if (answer === "n" || answer === "no") return false;
      options.output.write("Enter yes or no.\n");
    } catch (error) {
      if (error instanceof ConfirmationCancelled || options.signal.aborted)
        throw new ConfirmationCancelled();
      throw error;
    }
  }
}
