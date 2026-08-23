import { defineOwn, isRecord } from "../../utils/values.js";

const environmentSubstitution = /^\{env:([A-Za-z_][A-Za-z0-9_]*)\}$/;
const fileSubstitution = /^\{file:([^}]+)\}$/;

export type DeferredValue =
  | { kind: "literal"; value: string }
  | { kind: "environment"; name: string }
  | { kind: "file"; path: string };

export function stringValue(record: Record<string, unknown>, name: string): string | undefined {
  const value = record[name];
  return typeof value === "string" ? value : undefined;
}

export function stringArray(value: unknown): string[] | undefined {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
    ? value
    : undefined;
}

export function stringRecord(value: unknown): Record<string, string> | undefined {
  if (value === undefined) return {};
  if (!isRecord(value) || !Object.values(value).every((item) => typeof item === "string")) {
    return undefined;
  }
  const result: Record<string, string> = {};
  for (const [name, item] of Object.entries(value)) defineOwn(result, name, item as string);
  return result;
}

export function validDeferredValues(values: readonly string[]): boolean {
  try {
    values.forEach(parseDeferred);
    return true;
  } catch {
    return false;
  }
}

export function parseDeferred(value: string): DeferredValue {
  const environment = environmentSubstitution.exec(value);
  if (environment) return { kind: "environment", name: environment[1]! };
  const file = fileSubstitution.exec(value);
  if (file) return { kind: "file", path: file[1]! };
  if (value.includes("{env:") || value.includes("{file:")) {
    throw new Error("Invalid OpenCode substitution");
  }
  return { kind: "literal", value };
}

export function validV1Timeout(value: unknown): boolean {
  return value === undefined || (typeof value === "number" && Number.isFinite(value) && value > 0);
}

export function validV2Timeout(value: unknown): boolean {
  if (value === undefined) return true;
  if (
    !isRecord(value) ||
    Object.keys(value).some((key) => key !== "startup" && key !== "catalog" && key !== "execution")
  )
    return false;
  return Object.values(value).every(
    (timeout) => Number.isInteger(timeout) && (timeout as number) > 0,
  );
}
