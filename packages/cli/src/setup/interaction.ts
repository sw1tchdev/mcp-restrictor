import { clearScreenDown, cursorTo } from "node:readline";
import { createInterface } from "node:readline/promises";
import { Writable } from "node:stream";
import { ConfirmationCancelled, confirmTerminal } from "../confirmation.js";
import { readSecretLine } from "../secret-input.js";
import { abortable, TERMINATION_SIGNALS } from "../utils/async.js";
import { withExclusiveReadlineInput } from "../utils/terminal-input.js";
import { MultiSelectCancelled, selectWithTui } from "./tui/multi-select.js";
import { readTextWithTui, TextInputCancelled } from "./tui/text-input.js";

const ENTER_ALTERNATE_SCREEN = "\u001B[?1049h";
const EXIT_ALTERNATE_SCREEN = "\u001B[?1049l";

export class SetupCancelled extends Error {}

export type ReadTextOptions = {
  required?: boolean;
  placeholder?: string;
  trim?: boolean;
  secret?: boolean;
  validate?: (value: string) => string | undefined;
};

export class SetupInteraction {
  readonly signal: AbortSignal;
  readonly stderr: Writable;
  readonly usesTui: boolean;
  readonly write: (value: string) => void;
  readonly readText: (question: string, options?: ReadTextOptions) => Promise<string>;
  readonly ask: (question: string) => Promise<string>;
  readonly confirm: (message: string) => Promise<boolean>;
  readonly readSecret: (question: string) => Promise<string>;
  readonly selectIndexes: (
    question: string,
    choices: readonly string[],
    options: {
      allowNone: boolean;
      allSize?: number;
      defaultIndexes?: readonly number[];
      exclusiveIndex?: number;
      rejectDuplicates?: boolean;
      single?: boolean;
      tuiRequired?: boolean;
    },
  ) => Promise<number[]>;

  readonly #controller = new AbortController();
  readonly #input: NodeJS.ReadableStream;
  readonly #output: NodeJS.WritableStream;
  readonly #providedSignal: boolean;
  readonly #readline;
  readonly #abort = () => this.#controller.abort();
  #fullscreen = false;
  #nextScreen = true;
  #screenText = "";

  #beginScreen(): void {
    if (!this.#fullscreen || !this.#nextScreen) return;
    cursorTo(this.#output, 0, 0);
    clearScreenDown(this.#output);
    this.#screenText = "";
    this.#nextScreen = false;
  }

  #endPrompt(): void {
    if (this.#fullscreen) this.#nextScreen = true;
  }

  constructor(options: {
    input: NodeJS.ReadableStream;
    output: NodeJS.WritableStream;
    error: NodeJS.WritableStream;
    signal?: AbortSignal;
    readSecret?: (question: string) => Promise<string>;
  }) {
    this.#input = options.input;
    this.#output = options.output;
    this.#providedSignal = options.signal !== undefined;
    this.signal = options.signal
      ? AbortSignal.any([options.signal, this.#controller.signal])
      : this.#controller.signal;
    this.usesTui = Boolean(
      (options.input as NodeJS.ReadStream).isTTY &&
      (options.output as NodeJS.WriteStream).isTTY &&
      typeof (options.input as NodeJS.ReadStream).setRawMode === "function",
    );
    if (this.usesTui) this.#input.once("end", this.#abort);
    if (this.usesTui) {
      this.#fullscreen = true;
      this.#output.write(ENTER_ALTERNATE_SCREEN);
    }
    if (!this.#providedSignal) {
      for (const signal of TERMINATION_SIGNALS) process.on(signal, this.#abort);
    }

    this.#readline = createInterface({ input: options.input, crlfDelay: Infinity });
    const answers = this.#readline[Symbol.asyncIterator]();
    let reportedSuppressedStderr = false;
    this.stderr = new Writable({
      write(_chunk, _encoding, callback) {
        if (!reportedSuppressedStderr) {
          reportedSuppressedStderr = true;
          options.error.write("Upstream diagnostics suppressed during setup.\n");
        }
        callback();
      },
    });
    this.write = (value) => {
      this.#beginScreen();
      if (this.#fullscreen) this.#screenText += value;
      this.#output.write(value);
    };
    const lineAsk = async (question: string) => {
      this.signal.throwIfAborted();
      this.write(question);
      try {
        const answer = await abortable(answers.next(), this.signal);
        if (answer.done) throw new SetupCancelled();
        return answer.value;
      } finally {
        this.#endPrompt();
      }
    };
    this.readText = async (question, textOptions = {}) => {
      const {
        required = false,
        trim = true,
        validate: validateValue,
        placeholder,
        secret,
      } = textOptions;
      const normalize = (value: string) => (trim ? value.trim() : value);
      const validate = (raw: string) => {
        const value = normalize(raw);
        if (required && !value) return "This field is required.";
        return validateValue?.(value);
      };
      if (!this.usesTui) return normalize(await lineAsk(question));
      this.#beginScreen();
      try {
        const value = await withExclusiveReadlineInput(options.input, this.#readline, () =>
          readTextWithTui({
            message: question.replace(/:\s*$/, ""),
            input: options.input as NodeJS.ReadStream,
            output: options.output as NodeJS.WriteStream,
            error: options.error as NodeJS.WriteStream,
            signal: this.signal,
            validate,
            ...(placeholder === undefined ? {} : { placeholder }),
            ...(secret ? { secret: true } : {}),
          }),
        );
        return normalize(value);
      } catch (error) {
        if (error instanceof TextInputCancelled || this.signal.aborted) {
          this.#abort();
          throw new SetupCancelled();
        }
        throw error;
      } finally {
        this.#endPrompt();
      }
    };
    this.ask = (question) => this.readText(question);
    this.confirm = async (message) => {
      this.#beginScreen();
      try {
        return await confirmTerminal({
          message,
          input: options.input,
          output: options.output,
          error: options.error,
          readline: this.#readline,
          signal: this.signal,
          ask: this.ask,
        });
      } catch (error) {
        if (error instanceof ConfirmationCancelled || error instanceof SetupCancelled) {
          this.#abort();
          throw new SetupCancelled();
        }
        throw error;
      } finally {
        this.#endPrompt();
      }
    };
    this.readSecret = async (question) => {
      if (options.readSecret) {
        try {
          return await options.readSecret(question);
        } finally {
          this.#endPrompt();
        }
      }
      if (this.usesTui) return this.readText(question, { secret: true, trim: false });
      this.write(question);
      try {
        return await readSecretLine({
          input: options.input as Parameters<typeof readSecretLine>[0]["input"],
          readline: this.#readline,
          signal: this.signal,
          cancel: this.#abort,
        });
      } catch (error) {
        if (this.signal.aborted) throw this.signal.reason ?? error;
        throw error;
      } finally {
        this.write("\n");
        this.#endPrompt();
      }
    };
    this.selectIndexes = async (question, choices, selectionOptions) => {
      const size = choices.length;
      const defaults = selectionOptions.defaultIndexes ?? [];
      if (
        new Set(defaults).size !== defaults.length ||
        defaults.some((index) => !Number.isInteger(index) || index < 0 || index >= size) ||
        (selectionOptions.exclusiveIndex !== undefined &&
          defaults.includes(selectionOptions.exclusiveIndex) &&
          defaults.length !== 1)
      ) {
        throw new Error("Invalid default selection");
      }
      const normalIndexes = Array.from({ length: size }, (_, index) => index)
        .filter((index) => index !== selectionOptions.exclusiveIndex)
        .slice(0, selectionOptions.allSize ?? size);
      if (this.usesTui) {
        this.#beginScreen();
        try {
          return await withExclusiveReadlineInput(options.input, this.#readline, () =>
            selectWithTui({
              message: question.replace(/:\s*$/, ""),
              choices,
              input: options.input as NodeJS.ReadStream,
              output: options.output as NodeJS.WriteStream,
              error: options.error as NodeJS.WriteStream,
              signal: this.signal,
              required: selectionOptions.tuiRequired ?? !selectionOptions.allowNone,
              ...(selectionOptions.single ? { single: true } : {}),
              ...(selectionOptions.allSize === undefined
                ? {}
                : { allSize: selectionOptions.allSize }),
              ...(selectionOptions.defaultIndexes === undefined
                ? {}
                : { defaultIndexes: selectionOptions.defaultIndexes }),
              ...(selectionOptions.exclusiveIndex === undefined
                ? {}
                : { exclusiveIndex: selectionOptions.exclusiveIndex }),
            }),
          );
        } catch (error) {
          if (error instanceof MultiSelectCancelled) throw new SetupCancelled();
          throw error;
        } finally {
          this.#endPrompt();
        }
      }
      for (;;) {
        const answer = (await this.ask(question)).toLowerCase();
        if (!selectionOptions.single && answer === "all") {
          return normalIndexes;
        }
        if (!answer && defaults.length) return [...defaults];
        if (selectionOptions.allowNone && answer === "none") return [];
        const values = answer.split(",").map((value) => value.trim());
        if (
          values.length > 0 &&
          (!selectionOptions.single || values.length === 1) &&
          values.every((value) => /^\d+$/.test(value))
        ) {
          if (selectionOptions.rejectDuplicates && new Set(values).size !== values.length) {
            this.write("Invalid selection. Enter numbers, all, or none where allowed.\n");
            continue;
          }
          const indexes = [...new Set(values.map(Number))]
            .filter((value) => value >= 1 && value <= size)
            .map((value) => value - 1)
            .sort((left, right) => left - right);
          if (
            indexes.length > 0 &&
            (indexes.length === values.length || indexes.length === new Set(values).size)
          )
            return indexes;
        }
        this.write(
          selectionOptions.single
            ? "Invalid selection. Enter one number.\n"
            : "Invalid selection. Enter numbers, all, or none where allowed.\n",
        );
      }
    };
  }

  close(replayCurrentScreen = false): void {
    const replay = replayCurrentScreen ? this.#screenText : "";
    this.#screenText = "";
    if (this.#fullscreen) {
      this.#fullscreen = false;
      this.#output.write(EXIT_ALTERNATE_SCREEN);
    }
    if (replay) this.#output.write(replay);
    this.#readline.close();
    if (this.usesTui) (this.#input as NodeJS.ReadStream).unref?.();
    this.stderr.end();
    this.#input.removeListener("end", this.#abort);
    if (!this.#providedSignal) {
      for (const signal of TERMINATION_SIGNALS) process.removeListener(signal, this.#abort);
    }
  }
}
