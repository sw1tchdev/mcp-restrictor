export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asciiLower(value: string): string {
  return value.replace(/[A-Z]/g, (character) => character.toLowerCase());
}

export function defineOwn<T>(record: Record<string, T>, name: string, value: T): void {
  Object.defineProperty(record, name, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

export function stringArrayOrEmpty(value: unknown): string[] | undefined {
  if (value === undefined) return [];
  return Array.isArray(value) && value.every((item) => typeof item === "string")
    ? value
    : undefined;
}

export function stringRecordOrEmpty(value: unknown): Record<string, string> | undefined {
  if (value === undefined) return {};
  if (!isRecord(value) || Object.values(value).some((item) => typeof item !== "string"))
    return undefined;
  return value as Record<string, string>;
}
