export const MAX_MCP_MESSAGE_BYTES = 10 * 1024 * 1024;
export const ABORT_ERROR_NAME = "AbortError";
export const CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE = "conflicting upstream authentication";

export async function raceWithAbort<T>(operation: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return operation;
  if (signal.aborted) {
    void operation.catch(() => {});
    throw abortError();
  }
  let rejectAbort!: (error: Error) => void;
  const aborted = new Promise<never>((_, reject) => {
    rejectAbort = reject;
  });
  const abort = () => rejectAbort(abortError());
  signal.addEventListener("abort", abort, { once: true });
  void operation.catch(() => {});
  try {
    return await Promise.race([operation, aborted]);
  } finally {
    signal.removeEventListener("abort", abort);
  }
}

export function abortError(): Error {
  return new DOMException(ABORT_ERROR_NAME, ABORT_ERROR_NAME);
}

export function isAbortError(error: unknown): error is Error {
  return error instanceof Error && error.name === ABORT_ERROR_NAME;
}

export function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
