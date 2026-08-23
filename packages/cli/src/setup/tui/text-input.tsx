import { Box, Text, render, useApp, useInput, usePaste } from "ink";
import { useState } from "react";
import { abortable } from "../../utils/async.js";

const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });

const graphemes = (value: string) => [...segmenter.segment(value)].map(({ segment }) => segment);
const printableLine = (value: string) => !/[\u0000-\u001F\u007F-\u009F\r\n]/u.test(value);

type TextInputResult = { type: "submit"; value: string } | { type: "cancel" };

export class TextInputCancelled extends Error {}

export type TextInputValidation = (value: string) => string | undefined;

export function TextInputScreen(options: {
  message: string;
  placeholder?: string;
  secret?: boolean;
  validate?: TextInputValidation;
  onSubmit?: (value: string) => void;
  onCancel?: () => void;
}): React.JSX.Element {
  const { exit } = useApp();
  const [value, setValue] = useState("");
  const [cursor, setCursor] = useState(0);
  const [error, setError] = useState<string>();
  const parts = graphemes(value);
  const update = (next: string, nextCursor: number) => {
    setError(undefined);
    setValue(next);
    setCursor(nextCursor);
  };
  const insert = (text: string) => {
    const next = [...parts.slice(0, cursor), ...graphemes(text), ...parts.slice(cursor)].join("");
    update(next, cursor + graphemes(text).length);
  };
  const cancel = () => {
    options.onCancel?.();
    exit({ type: "cancel" } satisfies TextInputResult);
  };

  useInput((input, key) => {
    if ((key.ctrl && input === "c") || key.escape) return cancel();
    if (key.return) {
      const validationError = options.validate?.(value);
      if (validationError) return setError(validationError);
      options.onSubmit?.(value);
      return exit({ type: "submit", value } satisfies TextInputResult);
    }
    if (key.leftArrow) return setCursor(Math.max(0, cursor - 1));
    if (key.rightArrow) return setCursor(Math.min(parts.length, cursor + 1));
    if (key.home) return setCursor(0);
    if (key.end) return setCursor(parts.length);
    if (key.backspace) {
      if (cursor > 0)
        update([...parts.slice(0, cursor - 1), ...parts.slice(cursor)].join(""), cursor - 1);
      return;
    }
    if (key.delete) {
      if (cursor < parts.length)
        update([...parts.slice(0, cursor), ...parts.slice(cursor + 1)].join(""), cursor);
      return;
    }
    if (key.ctrl && input === "u") return update("", 0);
    if (!key.ctrl && printableLine(input)) insert(input);
  });

  usePaste((text) => {
    if (printableLine(text)) insert(text);
  });

  const shown = options.secret
    ? value
      ? "<hidden>"
      : (options.placeholder ?? "<empty>")
    : value
      ? `${parts.slice(0, cursor).join("")}│${parts.slice(cursor).join("")}`
      : (options.placeholder ?? "│");

  return (
    <Box flexDirection="column">
      <Text bold>{options.message}</Text>
      <Text>{shown}</Text>
      {error ? <Text color="red">{error}</Text> : null}
    </Box>
  );
}

export async function readTextWithTui(options: {
  message: string;
  input: NodeJS.ReadStream;
  output: NodeJS.WriteStream;
  error: NodeJS.WriteStream;
  signal: AbortSignal;
  placeholder?: string;
  secret?: boolean;
  validate?: TextInputValidation;
}): Promise<string> {
  options.signal.throwIfAborted();
  await new Promise<void>((resolve) => setImmediate(resolve));
  options.signal.throwIfAborted();
  const eof = new AbortController();
  const onEnd = () => eof.abort(new TextInputCancelled());
  options.input.once("end", onEnd);
  if (options.input.readableEnded) onEnd();
  const signal = AbortSignal.any([options.signal, eof.signal]);
  let instance: ReturnType<typeof render> | undefined;
  try {
    instance = render(
      <TextInputScreen
        message={options.message}
        {...(options.placeholder === undefined ? {} : { placeholder: options.placeholder })}
        {...(options.secret ? { secret: true } : {})}
        {...(options.validate === undefined ? {} : { validate: options.validate })}
      />,
      {
        stdin: options.input,
        stdout: options.output,
        stderr: options.error,
        exitOnCtrlC: false,
        patchConsole: false,
        interactive: true,
      },
    );
    const result = (await abortable(instance.waitUntilExit(), signal)) as
      | TextInputResult
      | undefined;
    if (!result || result.type === "cancel") throw new TextInputCancelled();
    return result.value;
  } finally {
    options.input.removeListener("end", onEnd);
    instance?.unmount();
  }
}
