export const TERMINATION_SIGNALS = ["SIGINT", "SIGTERM"] as const;
export const ABORT_ERROR_NAME = "AbortError";

export function abortable<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const cleanup = () => signal.removeEventListener("abort", onAbort);
    const onAbort = () => {
      cleanup();
      reject(signal.reason ?? new DOMException("Aborted", ABORT_ERROR_NAME));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
    work.then(
      (value) => {
        cleanup();
        resolve(value);
      },
      (error: unknown) => {
        cleanup();
        reject(error);
      },
    );
  });
}
