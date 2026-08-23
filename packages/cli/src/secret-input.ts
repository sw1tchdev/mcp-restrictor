import type { Interface } from "node:readline/promises";
import { withExclusiveReadlineInput } from "./utils/terminal-input.js";

type TtyInput = NodeJS.ReadableStream & {
  isTTY?: boolean;
  isRaw?: boolean;
  isPaused(): boolean;
  read(size?: number): string | Buffer | null;
  setRawMode?(mode: boolean): unknown;
  unshift(chunk: string | Uint8Array): void;
};

const SECRET_INPUT_CANCELLED_MESSAGE = "Secret input cancelled";

export async function readSecretLine(options: {
  input: TtyInput;
  readline: Interface;
  signal: AbortSignal;
  cancel?: () => void;
}): Promise<string> {
  const { input, readline, signal } = options;
  if (input.isTTY !== true || typeof input.setRawMode !== "function") {
    throw new Error("Secret input requires an interactive terminal");
  }
  if (signal.aborted) throw new Error(SECRET_INPUT_CANCELLED_MESSAGE);
  const wasRaw = input.isRaw === true;
  return withExclusiveReadlineInput(input, readline, async () => {
    try {
      input.setRawMode!(true);
      return await new Promise<string>((resolveSecret, rejectSecret) => {
        let buffered = Buffer.alloc(0);
        let settled = false;
        const cleanup = () => {
          input.removeListener("readable", onReadable);
          input.removeListener("end", onEnd);
          input.removeListener("error", onError);
          signal.removeEventListener("abort", onAbort);
        };
        const finish = (error?: Error, value?: string) => {
          if (settled) return;
          settled = true;
          cleanup();
          if (error) rejectSecret(error);
          else resolveSecret(value!);
        };
        const cancel = () => {
          if (settled) return;
          settled = true;
          cleanup();
          try {
            options.cancel?.();
          } finally {
            rejectSecret(new Error(SECRET_INPUT_CANCELLED_MESSAGE));
          }
        };
        const consume = (chunk: string | Buffer) => {
          buffered = Buffer.concat([buffered, Buffer.from(chunk)]);
          const control = buffered.indexOf(3);
          const carriageReturn = buffered.indexOf(13);
          const lineFeed = buffered.indexOf(10);
          const newline =
            carriageReturn < 0
              ? lineFeed
              : lineFeed < 0
                ? carriageReturn
                : Math.min(carriageReturn, lineFeed);
          if (control >= 0 && (newline < 0 || control < newline)) {
            cancel();
            return;
          }
          if (newline < 0) return;
          const delimiterSize = buffered[newline] === 13 && buffered[newline + 1] === 10 ? 2 : 1;
          const remainder = buffered.subarray(newline + delimiterSize);
          if (remainder.length > 0) input.unshift(remainder);
          finish(undefined, buffered.subarray(0, newline).toString("utf8"));
        };
        const onReadable = () => {
          let chunk: string | Buffer | null;
          while (!settled && (chunk = input.read()) !== null) consume(chunk);
        };
        const onEnd = () => finish(new Error(SECRET_INPUT_CANCELLED_MESSAGE));
        const onError = () => finish(new Error(SECRET_INPUT_CANCELLED_MESSAGE));
        const onAbort = () => cancel();

        input.on("readable", onReadable);
        input.once("end", onEnd);
        input.once("error", onError);
        signal.addEventListener("abort", onAbort, { once: true });
        onReadable();
      });
    } finally {
      input.setRawMode!(wasRaw);
    }
  });
}
