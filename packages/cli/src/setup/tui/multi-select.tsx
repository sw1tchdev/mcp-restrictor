import { Box, Text, render, useApp, useInput, useWindowSize } from "ink";
import { useEffect, useRef, useState } from "react";
import { abortable } from "../../utils/async.js";

const DEFAULT_PAGE_SIZE = 10;
const EMPTY_SELECTION_MESSAGE = "Select at least one item.";
const MCP_SHIELD_COLUMNS = 21;
const MCP_SHIELD_MIN_TERMINAL_COLUMNS = 64;
const MCP_SHIELD_FRAME_MS = 160;
const MCP_SHIELD_DIM = "#69717d";
const MCP_SHIELD_MID = "#aeb4bd";
const MCP_SHIELD_BRIGHT = "#f7f8fa";
const MCP_SHIELD_ROWS = [
  "   ▄█████████████▄",
  " ████▀         ▀████",
  " ████   M C P   ████",
  " ████▄         ▄████",
  "   ████▄     ▄████",
  "     ████▄ ▄████",
  "       ▀█████▀",
  "          ▼",
] as const;

function shieldColor(column: number, frame: number): string {
  const distance = Math.abs(column - frame);
  if (distance === 0) return MCP_SHIELD_BRIGHT;
  if (distance === 1) return MCP_SHIELD_MID;
  return MCP_SHIELD_DIM;
}

function McpShield() {
  const { columns } = useWindowSize();
  const [frame, setFrame] = useState(0);
  const visible = columns >= MCP_SHIELD_MIN_TERMINAL_COLUMNS;

  useEffect(() => {
    if (!visible) return;
    const timer = setInterval(
      () => setFrame((current) => (current + 1) % MCP_SHIELD_COLUMNS),
      MCP_SHIELD_FRAME_MS,
    );
    timer.unref();
    return () => clearInterval(timer);
  }, [visible]);

  if (!visible) return null;
  return (
    <Box aria-hidden flexDirection="column" width={MCP_SHIELD_COLUMNS} flexShrink={0}>
      {MCP_SHIELD_ROWS.map((row, rowIndex) => (
        <Text key={rowIndex}>
          {[...row].map((character, column) => (
            <Text key={column} color={shieldColor(column, frame)}>
              {character}
            </Text>
          ))}
        </Text>
      ))}
    </Box>
  );
}

type MultiSelectResult = { type: "submit"; indexes: number[] } | { type: "cancel" };

export class MultiSelectCancelled extends Error {}

export function MultiSelectScreen(options: {
  message: string;
  choices: readonly string[];
  required?: boolean;
  allSize?: number;
  defaultIndexes?: readonly number[];
  exclusiveIndex?: number;
  single?: boolean;
  pageSize?: number;
  onSubmit?: (indexes: number[]) => void;
  onCancel?: () => void;
}) {
  const { exit } = useApp();
  const [active, setActive] = useState(0);
  const [selected, setSelected] = useState<ReadonlySet<number>>(
    () => new Set(options.defaultIndexes ?? []),
  );
  const activeRef = useRef(active);
  const selectedRef = useRef(selected);
  const [error, setError] = useState<string>();
  const choiceCount = options.choices.length;
  const normalIndexes = Array.from({ length: choiceCount }, (_, index) => index)
    .filter((index) => index !== options.exclusiveIndex)
    .slice(0, options.allSize ?? choiceCount);
  const pageSize = Math.max(1, options.pageSize ?? DEFAULT_PAGE_SIZE);

  const updateSelected = (next: ReadonlySet<number>) => {
    selectedRef.current = next;
    setSelected(next);
  };

  const toggle = (index: number) => {
    setError(undefined);
    const current = selectedRef.current;
    if (index === options.exclusiveIndex) {
      updateSelected(current.has(index) ? new Set() : new Set([index]));
      return;
    }
    const next = new Set(current);
    if (options.exclusiveIndex !== undefined) next.delete(options.exclusiveIndex);
    if (next.has(index)) next.delete(index);
    else next.add(index);
    updateSelected(next);
  };

  useInput((input, key) => {
    if ((key.ctrl && input === "c") || key.escape) {
      options.onCancel?.();
      exit({ type: "cancel" } satisfies MultiSelectResult);
      return;
    }
    if (key.upArrow || key.downArrow) {
      if (choiceCount === 0) return;
      setError(undefined);
      activeRef.current = key.upArrow
        ? (activeRef.current - 1 + choiceCount) % choiceCount
        : (activeRef.current + 1) % choiceCount;
      setActive(activeRef.current);
      return;
    }
    if (!options.single && input === " ") {
      if (choiceCount === 0) return;
      toggle(activeRef.current);
      return;
    }
    if (!options.single && input === "a") {
      setError(undefined);
      const everyNormalItemSelected = normalIndexes.every((index) =>
        selectedRef.current.has(index),
      );
      updateSelected(everyNormalItemSelected ? new Set() : new Set(normalIndexes));
      return;
    }
    if (!options.single && input === "i") {
      setError(undefined);
      updateSelected(new Set(normalIndexes.filter((index) => !selectedRef.current.has(index))));
      return;
    }
    if (key.return) {
      const indexes = options.single
        ? choiceCount > 0
          ? [activeRef.current]
          : []
        : options.required && selectedRef.current.size === 0 && choiceCount > 0
          ? [activeRef.current]
          : [...selectedRef.current].sort((left, right) => left - right);
      if (options.required && indexes.length === 0) {
        setError(EMPTY_SELECTION_MESSAGE);
        return;
      }
      options.onSubmit?.(indexes);
      exit({ type: "submit", indexes } satisfies MultiSelectResult);
    }
  });

  const firstVisible = Math.min(
    Math.max(active - pageSize + 1, 0),
    Math.max(choiceCount - pageSize, 0),
  );
  const visibleChoices = options.choices.slice(firstVisible, firstVisible + pageSize);

  return (
    <Box width="100%" justifyContent="space-between">
      <Box flexDirection="column">
        <Text bold>{options.message}</Text>
        {choiceCount === 0 ? <Text dimColor>No items available.</Text> : null}
        {visibleChoices.map((choice, offset) => {
          const index = firstVisible + offset;
          const checked = selected.has(index);
          return (
            <Box
              key={index}
              aria-role={options.single ? "radio" : "checkbox"}
              aria-state={{ checked: options.single ? index === active : checked }}
              aria-label={choice}
            >
              <Text {...(index === active ? { color: "cyan" } : {})}>
                {index === active ? "›" : " "} {options.single ? "" : `${checked ? "◉" : "◯"} `}
                {choice}
              </Text>
            </Box>
          );
        })}
        {error ? <Text color="red">{error}</Text> : null}
        <Text dimColor>
          {options.single
            ? "↑↓ move · enter choose"
            : "↑↓ move · space toggle · a all · i invert · enter choose/confirm"}
        </Text>
      </Box>
      <McpShield />
    </Box>
  );
}

export async function selectWithTui(options: {
  message: string;
  choices: readonly string[];
  input: NodeJS.ReadStream;
  output: NodeJS.WriteStream;
  error: NodeJS.WriteStream;
  signal: AbortSignal;
  required: boolean;
  single?: boolean;
  allSize?: number;
  defaultIndexes?: readonly number[];
  exclusiveIndex?: number;
}): Promise<number[]> {
  options.signal.throwIfAborted();
  // Keep one loop turn alive so completed async work cannot close this renderer via beforeExit.
  await new Promise<void>((resolve) => setImmediate(resolve));
  options.signal.throwIfAborted();
  const eof = new AbortController();
  const onEnd = () => eof.abort(new MultiSelectCancelled());
  options.input.once("end", onEnd);
  if (options.input.readableEnded) onEnd();
  const signal = AbortSignal.any([options.signal, eof.signal]);
  let instance: ReturnType<typeof render> | undefined;
  try {
    instance = render(
      <MultiSelectScreen
        message={options.message}
        choices={options.choices}
        required={options.required}
        {...(options.single ? { single: true } : {})}
        {...(options.allSize === undefined ? {} : { allSize: options.allSize })}
        {...(options.defaultIndexes === undefined
          ? {}
          : { defaultIndexes: options.defaultIndexes })}
        {...(options.exclusiveIndex === undefined
          ? {}
          : { exclusiveIndex: options.exclusiveIndex })}
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
      | MultiSelectResult
      | undefined;
    if (!result || result.type === "cancel") throw new MultiSelectCancelled();
    return result.indexes;
  } finally {
    options.input.removeListener("end", onEnd);
    instance?.unmount();
  }
}
