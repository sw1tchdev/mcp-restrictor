import { validateServerCandidate, type ServerCandidate } from "../wrapper.js";
import type { OpenCodeSchema } from "./candidate.js";
import { validV1Timeout, validV2Timeout } from "./values.js";

export function validOpenCodeEntryState(
  entry: Record<string, unknown>,
  schema: OpenCodeSchema,
): boolean {
  return !(
    (schema === "v1" && entry.enabled !== undefined && typeof entry.enabled !== "boolean") ||
    (schema === "v2" && entry.disabled !== undefined && typeof entry.disabled !== "boolean") ||
    (schema === "v2" && entry.codemode !== undefined && typeof entry.codemode !== "boolean") ||
    (schema === "v1" && !validV1Timeout(entry.timeout)) ||
    (schema === "v2" && !validV2Timeout(entry.timeout)) ||
    (schema === "v1" ? entry.enabled === false : entry.disabled === true)
  );
}

export function validatedOpenCodeCandidate(
  candidate: ServerCandidate,
): ServerCandidate | undefined {
  try {
    validateServerCandidate(candidate);
    return candidate;
  } catch {
    return undefined;
  }
}
