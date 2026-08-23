import type { Node as JsonNode } from "jsonc-parser";

export function hasDuplicateJsonProperties(node: JsonNode): boolean {
  if (node.type === "object") {
    const names = new Set<string>();
    for (const property of node.children ?? []) {
      const [key, value] = property.children ?? [];
      if (typeof key?.value !== "string" || !value || names.has(key.value)) return true;
      names.add(key.value);
      if (hasDuplicateJsonProperties(value)) return true;
    }
    return false;
  }
  return (node.children ?? []).some(hasDuplicateJsonProperties);
}
