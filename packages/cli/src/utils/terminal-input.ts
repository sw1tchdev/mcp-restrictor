import type { Interface } from "node:readline/promises";

type SuspendableInput = NodeJS.ReadableStream & {
  isPaused(): boolean;
  ref?(): unknown;
};

export async function withExclusiveReadlineInput<T>(
  input: SuspendableInput,
  readline: Interface,
  operation: () => Promise<T>,
): Promise<T> {
  const wasPaused = input.isPaused();
  readline.pause();
  input.pause();
  const dataListeners = input.listeners("data");
  for (const listener of dataListeners) input.removeListener("data", listener);
  try {
    return await operation();
  } finally {
    for (const listener of dataListeners) input.on("data", listener);
    if (wasPaused) {
      readline.pause();
      input.pause();
    } else {
      input.ref?.();
      readline.resume();
    }
  }
}
