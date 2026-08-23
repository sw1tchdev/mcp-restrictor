import { isDeepStrictEqual } from "node:util";
import {
  applyEdits,
  findNodeAtLocation,
  getNodeValue,
  modify,
  parseTree,
  type Node,
  type ParseError,
} from "jsonc-parser";
import type { ClientRestoreEntry } from "../../client-adapter.js";
import { hasDuplicateJsonProperties } from "../json.js";

export function restoreJsonEntries(
  source: string,
  entries: readonly ClientRestoreEntry[],
  entryPath: (source: string, name: string) => string[],
): string {
  for (const entry of entries) {
    const currentTree = tree(source);
    const path = entryPath(source, entry.name);
    const current = findNodeAtLocation(currentTree, path);
    const originalSource = entry.originalSource;
    const original = findNodeAtLocation(
      tree(originalSource),
      entryPath(originalSource, entry.name),
    );
    if (!current) throw new Error("Restore entry is missing");
    let installed: Node | undefined;
    if (entry.installedSource !== undefined) {
      const installedSource = entry.installedSource;
      installed = findNodeAtLocation(tree(installedSource), entryPath(installedSource, entry.name));
      if (!installed || !isDeepStrictEqual(getNodeValue(current), getNodeValue(installed))) {
        throw new Error("Restore entry changed");
      }
    }
    if (original) {
      source = `${source.slice(0, current.offset)}${originalSource.slice(original.offset, original.offset + original.length)}${source.slice(current.offset + current.length)}`;
    } else {
      if (entry.created !== true || entry.installedSource === undefined) {
        throw new Error("Restore entry is missing");
      }
      const exactInstalled = removeFirstProperty(entry.installedSource, installed!);
      const exactCurrent = removeFirstProperty(source, current);
      source =
        exactInstalled === originalSource && exactCurrent !== undefined
          ? exactCurrent
          : applyEdits(
              source,
              modify(source, path, undefined, {
                formattingOptions: { insertSpaces: true, tabSize: 2, eol: "\n" },
              }),
            );
    }
    tree(source);
  }
  return source;
}

function removeFirstProperty(source: string, node: Node): string | undefined {
  const property = node.parent;
  const object = property?.parent;
  if (
    property?.type !== "property" ||
    object?.type !== "object" ||
    object.children?.[0] !== property
  ) {
    return undefined;
  }
  let end = property.offset + property.length;
  while (/\s/.test(source[end] ?? "")) end += 1;
  if (source[end] !== ",") return undefined;
  end += 1;
  while (/\s/.test(source[end] ?? "")) end += 1;
  return `${source.slice(0, property.offset)}${source.slice(end)}`;
}

function tree(source: string): Node {
  const errors: ParseError[] = [];
  const root = parseTree(source, errors, { allowTrailingComma: true });
  if (!root || errors.length || hasDuplicateJsonProperties(root)) {
    throw new Error("Invalid JSON source");
  }
  return root;
}
