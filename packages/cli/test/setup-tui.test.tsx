import { cleanup, render } from "ink-testing-library";
import { randomBytes } from "node:crypto";
import { chmod, mkdtemp, mkdir, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { PassThrough, Readable, Writable } from "node:stream";
import { fileURLToPath, pathToFileURL } from "node:url";
import { act } from "react";
import { afterEach, expect, test, vi } from "vitest";
import { defineClientAdapter } from "../src/client-adapter.ts";
import {
  MASTER_KEY_FILE_ENV,
  readOAuthProfile,
  type OAuthStorageOptions,
} from "../src/oauth/storage.ts";
import { loadRoutes } from "../src/routes.ts";
import { runSetupCommand } from "../src/setup/index.ts";
import { generatedConfigPath, generatedPolicyLocation } from "../src/setup/generated.ts";
import { SetupCancelled, SetupInteraction } from "../src/setup/interaction.ts";
import { planOptionalSavedPolicy, savedPolicyDirectory } from "../src/setup/saved-policies.ts";
import { claudeAdapter } from "../src/setup/claude.ts";
import { codexAdapter } from "../src/setup/codex.ts";
import {
  policyFingerprint,
  restoreStatePath,
  serializeRestoreState,
} from "../src/setup/restore/state.ts";
import {
  MultiSelectCancelled,
  MultiSelectScreen,
  selectWithTui,
} from "../src/setup/tui/multi-select.tsx";
import {
  TextInputCancelled,
  TextInputScreen,
  readTextWithTui,
} from "../src/setup/tui/text-input.tsx";
import { startRemoteAuthFixture } from "../../transports/test/remote-auth-fixture.ts";
import { snapshotTree, writeNodeLauncher } from "./helpers.ts";
import { CONTAINER_MARKER_ENV } from "../src/setup/constants.ts";

type OAuthLogin = (typeof import("../src/oauth/login.ts"))["loginOAuthProfile"];
type PrepareOAuthStorage =
  (typeof import("../src/oauth/storage.ts"))["prepareOAuthStorageForSetup"];

const setupTuiFakes = vi.hoisted(() => ({
  login: undefined as
    | undefined
    | ((actual: OAuthLogin, options: Parameters<OAuthLogin>[0]) => ReturnType<OAuthLogin>),
  prepare: undefined as
    | undefined
    | ((actual: PrepareOAuthStorage, options: OAuthStorageOptions) => Promise<void>),
}));

vi.mock("../src/oauth/login.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/oauth/login.ts")>();
  return {
    ...actual,
    loginOAuthProfile: (...args: Parameters<typeof actual.loginOAuthProfile>) =>
      setupTuiFakes.login
        ? setupTuiFakes.login(actual.loginOAuthProfile, args[0])
        : actual.loginOAuthProfile(...args),
  };
});

vi.mock("../src/oauth/storage.ts", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/oauth/storage.ts")>();
  return {
    ...actual,
    prepareOAuthStorageForSetup: (options: OAuthStorageOptions) =>
      setupTuiFakes.prepare
        ? setupTuiFakes.prepare(actual.prepareOAuthStorageForSetup, options)
        : actual.prepareOAuthStorageForSetup(options),
  };
});

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const choices = ["Claude Code", "Codex", "Manual upstream"] as const;
const ENTER_ALTERNATE_SCREEN = "\u001B[?1049h";
const EXIT_ALTERNATE_SCREEN = "\u001B[?1049l";
const CLEAR_VIEWPORT = "\u001B[1;1H\u001B[0J";
const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const cli = resolve(projectRoot, "packages/cli/dist/index.js");
const upstream = resolve(
  projectRoot,
  "packages/transports/test/fixtures/config-sensitive-upstream.mjs",
);

function occurrences(source: string, value: string): number {
  return source.split(value).length - 1;
}

function primaryOutput(source: string): string {
  return source.slice(source.lastIndexOf(EXIT_ALTERNATE_SCREEN) + EXIT_ALTERNATE_SCREEN.length);
}

function alternateOutput(source: string): string {
  return source.slice(
    source.indexOf(ENTER_ALTERNATE_SCREEN) + ENTER_ALTERNATE_SCREEN.length,
    source.lastIndexOf(EXIT_ALTERNATE_SCREEN),
  );
}

function setupTty(observeOutput?: (value: string) => void) {
  const rawModes: boolean[] = [];
  const input = Object.assign(new PassThrough(), {
    isTTY: true as const,
    isRaw: false,
    setRawMode(mode: boolean) {
      this.isRaw = mode;
      rawModes.push(mode);
      return this;
    },
    ref() {
      return this;
    },
    unref() {
      return this;
    },
  });
  const chunks: Buffer[] = [];
  const output = Object.assign(
    new Writable({
      write(chunk, _encoding, callback) {
        const value = Buffer.from(chunk);
        chunks.push(value);
        observeOutput?.(value.toString("utf8"));
        callback();
      },
    }),
    { isTTY: true as const, columns: 80, rows: 24 },
  );
  return {
    input,
    output,
    raw: () => Buffer.concat(chunks).toString("utf8"),
    waitForSelection: (count: number) =>
      vi.waitFor(() => expect(rawModes.filter(Boolean)).toHaveLength(count), { timeout: 5_000 }),
  };
}

async function choose(terminal: ReturnType<typeof setupTty>, count: number, ...keys: string[]) {
  await terminal.waitForSelection(count);
  await new Promise<void>((resolve) => setImmediate(resolve));
  await press(terminal.input, ...keys);
}

async function enterManualStdio(
  terminal: ReturnType<typeof setupTty>,
  firstPrompt: number,
  command = process.execPath,
) {
  let prompt = firstPrompt;
  await terminal.waitForSelection(prompt++);
  await press(terminal.input, "files", "\r");
  await choose(terminal, prompt++, "\r");
  await terminal.waitForSelection(prompt++);
  await press(terminal.input, command, "\r");
  for (const argument of ["", "  spaced  "]) {
    await choose(terminal, prompt++, "\u001B[B", "\r");
    await terminal.waitForSelection(prompt++);
    await press(terminal.input, argument, "\r");
  }
  await choose(terminal, prompt++, "\r");
  for (const environmentVariable of ["API_KEY", "PATH"]) {
    await choose(terminal, prompt++, "\u001B[B", "\r");
    await terminal.waitForSelection(prompt++);
    await press(terminal.input, environmentVariable, "\r");
  }
  await choose(terminal, prompt, "\r");
}

async function enterManualOAuthUntilRedirectDelivery(
  terminal: ReturnType<typeof setupTty>,
): Promise<void> {
  await choose(terminal, 1, "\r");
  await choose(terminal, 2, "\u001B[B", "\r");
  await terminal.waitForSelection(3);
  await press(terminal.input, "oauth", "\r");
  await choose(terminal, 4, "\u001B[B", "\u001B[B", "\r");
  await terminal.waitForSelection(5);
  await press(terminal.input, "https://upstream.example/events", "\r");
  await choose(terminal, 6, "\r");
  await choose(terminal, 7, "\u001B[B", "\u001B[B", "\r");
  await choose(terminal, 8, "\u001B[B", "\r");
  await terminal.waitForSelection(9);
  await press(terminal.input, "manual-client-id", "\r");
  for (const [selection, value] of [
    [10, "fixture-scope"],
    [12, "https://resource.example/mcp"],
    [14, "https://resource.example/metadata"],
    [16, "https://auth.example/metadata"],
  ] as const) {
    await choose(terminal, selection, "\u001B[B", "\r");
    await terminal.waitForSelection(selection + 1);
    await press(terminal.input, value, "\r");
  }
  await choose(terminal, 18, "\u001B[B", "\r");
  await terminal.waitForSelection(19);
  await press(terminal.input, "49152", "\r");
  await choose(terminal, 20, "\u001B[B", "\r");
  await terminal.waitForSelection(21);
  await press(terminal.input, "http://127.0.0.1:49152/callback", "\r");
  await choose(terminal, 22, "\u001B[B", " ", "\r");
  await choose(terminal, 23, "\r");
  await choose(terminal, 24, "\r");
  await choose(terminal, 25, "\r");
  await choose(terminal, 26, "\r");
  await terminal.waitForSelection(27);
  await vi.waitFor(() =>
    expect(alternateOutput(terminal.raw())).toContain("OAuth redirect delivery"),
  );
}

async function writeFixedManualUpstream(directory: string): Promise<string> {
  const path = join(directory, "manual-upstream");
  await writeFile(
    path,
    `#!/usr/bin/env node\nprocess.chdir(${JSON.stringify(directory)});\nprocess.argv = [process.execPath, ${JSON.stringify(upstream)}, ${JSON.stringify(directory)}, "normal"];\nvoid import(${JSON.stringify(pathToFileURL(upstream).href)});\n`,
    { mode: 0o700 },
  );
  await chmod(path, 0o700);
  return path;
}

function expectCompletedManualFullscreen(raw: string, configPath: string): void {
  expect(occurrences(raw, ENTER_ALTERNATE_SCREEN)).toBe(1);
  expect(occurrences(raw, EXIT_ALTERNATE_SCREEN)).toBe(1);
  expect(occurrences(alternateOutput(raw), CLEAR_VIEWPORT)).toBeGreaterThan(1);
  expect(primaryOutput(raw)).toContain(`Changed: ${JSON.stringify(configPath)}\n`);
  expect(primaryOutput(raw)).toContain("Restart Claude Code");
  for (const oldPrompt of [
    "Transport (stdio/http/sse/websocket)",
    "Arguments as JSON array",
    "comma-separated",
    "HEADER=ENV_NAME",
    "Authentication (none/bearer/oauth)",
    "empty for",
  ]) {
    expect(alternateOutput(raw)).not.toContain(oldPrompt);
  }
  for (const priorScreen of ["Actions:", "Clients:", "Destination:", "Preview:"]) {
    expect(primaryOutput(raw)).not.toContain(priorScreen);
  }
}

afterEach(() => {
  setupTuiFakes.login = undefined;
  setupTuiFakes.prepare = undefined;
  cleanup();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

const shieldRows = [
  "   ▄█████████████▄",
  " ████▀         ▀████",
  " ████   M C P   ████",
  " ████▄         ▄████",
  "   ████▄     ▄████",
  "     ████▄ ▄████",
  "       ▀█████▀",
  "          ▼",
] as const;

function picker(
  options: { required?: boolean; pageSize?: number; defaultIndexes?: readonly number[] } = {},
) {
  const onSubmit = vi.fn<(indexes: number[]) => void>();
  const onCancel = vi.fn<() => void>();
  const screen = render(
    <MultiSelectScreen
      message="Select clients"
      choices={choices}
      allSize={2}
      exclusiveIndex={2}
      {...(options.defaultIndexes ? { defaultIndexes: options.defaultIndexes } : {})}
      onSubmit={onSubmit}
      onCancel={onCancel}
      {...options}
    />,
  );
  return { ...screen, onSubmit, onCancel };
}

function expectCompleteShield(screen: { lastFrame(): string | undefined }) {
  const lines = (screen.lastFrame() ?? "").split("\n");
  expect(lines).toHaveLength(8);
  for (const [index, row] of shieldRows.entries()) expect(lines[index]?.endsWith(row)).toBe(true);
}

test("renders the symmetric filled MCP shield on a wide terminal", async () => {
  const screen = picker();
  Object.defineProperty(screen.stdout, "columns", { configurable: true, value: 80 });
  await act(async () => screen.stdout.emit("resize"));
  expectCompleteShield(screen);
});

test("keeps the complete MCP shield geometry at exactly 64 columns", async () => {
  const screen = picker();
  Object.defineProperty(screen.stdout, "columns", { configurable: true, value: 64 });
  await act(async () => screen.stdout.emit("resize"));
  expectCompleteShield(screen);
});

test("hides the MCP shield when the terminal becomes narrow", async () => {
  const screen = picker();
  expect(screen.lastFrame()).toContain("M C P");
  Object.defineProperty(screen.stdout, "columns", { configurable: true, value: 63 });
  await act(async () => screen.stdout.emit("resize"));
  expect(screen.lastFrame()).not.toContain("M C P");
});

test("animates the MCP shield without leaking its timer", async () => {
  vi.useFakeTimers();
  const setIntervalSpy = vi.spyOn(globalThis, "setInterval");
  const clearIntervalSpy = vi.spyOn(globalThis, "clearInterval");
  const screen = picker();
  const shieldTimer = setIntervalSpy.mock.results.at(-1)?.value;
  expect(shieldTimer).toBeDefined();
  const initialFrames = screen.frames.length;

  await act(async () => vi.advanceTimersByTime(160));
  expect(screen.frames.length).toBeGreaterThan(initialFrames);
  expect(screen.lastFrame()).toContain("M C P");

  screen.unmount();
  expect(clearIntervalSpy).toHaveBeenCalledWith(shieldTimer);
});

async function press(stdin: { write(value: string): void }, ...keys: string[]) {
  for (const key of keys) {
    await act(async () => stdin.write(key));
  }
}

test("text input edits Unicode text and submits the exact visible value", async () => {
  const onSubmit = vi.fn<(value: string) => void>();
  const screen = render(<TextInputScreen message="Server name" onSubmit={onSubmit} />);

  await press(screen.stdin, "A👩‍💻B", "\u001B[D", "\u007F", "C", "\r");

  expect(onSubmit).toHaveBeenCalledWith("ACB");
});

test("validation error remains inline until corrected text input submits", async () => {
  const onSubmit = vi.fn<(value: string) => void>();
  const screen = render(
    <TextInputScreen
      message="Callback port"
      validate={(value) => (/^\d+$/.test(value) ? undefined : "Enter a valid port.")}
      onSubmit={onSubmit}
    />,
  );

  await press(screen.stdin, "bad", "\r");
  expect(screen.lastFrame()).toContain("Enter a valid port.");
  expect(onSubmit).not.toHaveBeenCalled();
  await press(screen.stdin, "\u0015", "43123", "\r");
  expect(onSubmit).toHaveBeenCalledWith("43123");
});

test("usePaste accepts one printable line and rejects control-bearing content", async () => {
  const onSubmit = vi.fn<(value: string) => void>();
  const screen = render(<TextInputScreen message="URL" onSubmit={onSubmit} />);

  await act(async () => screen.stdin.write("\u001B[200~https://example.test/mcp\u001B[201~"));
  expect(screen.lastFrame()).toContain("https://example.test/mcp");
  await act(async () => screen.stdin.write("\u001B[200~bad\nvalue\u001B[201~"));
  await act(async () => screen.stdin.write("\u001B[200~bad\rvalue\u001B[201~"));
  expect(screen.lastFrame()).not.toContain("bad");
  await press(screen.stdin, "\r");
  expect(onSubmit).toHaveBeenCalledWith("https://example.test/mcp");
});

test("fixed marker text input never records a secret", async () => {
  const secret = "client-secret-value";
  const screen = render(<TextInputScreen message="Client secret" secret />);

  await press(screen.stdin, secret);

  expect(screen.lastFrame()).toContain("<hidden>");
  expect(screen.lastFrame()).not.toContain(secret);
  expect(screen.lastFrame()).not.toContain("*".repeat(secret.length));
  for (const frame of screen.frames) {
    expect(frame).not.toContain(secret);
    expect(frame).not.toContain("*".repeat(secret.length));
  }
});

test("text input supports Home End Delete Ctrl-U and optional empty Enter", async () => {
  const onSubmit = vi.fn<(value: string) => void>();
  const screen = render(<TextInputScreen message="Name" onSubmit={onSubmit} />);

  await press(
    screen.stdin,
    "ac",
    "\u001B[H",
    "b",
    "\u001B[F",
    "\u001B[D",
    "\u001B[3~",
    "\u0015",
    "\r",
  );

  expect(onSubmit).toHaveBeenCalledWith("");
});

test.each(["\u001B", "\u0003"])("text input cancels on %j", async (key) => {
  const onCancel = vi.fn<() => void>();
  const onSubmit = vi.fn<(value: string) => void>();
  const screen = render(<TextInputScreen message="Name" onCancel={onCancel} onSubmit={onSubmit} />);

  await press(screen.stdin, key);

  await vi.waitFor(() => expect(onCancel).toHaveBeenCalledOnce());
  expect(onSubmit).not.toHaveBeenCalled();
});

test.each(["text", "select"] as const)("cancels an active %s renderer on EOF", async (kind) => {
  const terminal = setupTty();
  const beforeEndListeners = terminal.input.listenerCount("end");
  const operation =
    kind === "text"
      ? readTextWithTui({
          message: "Name",
          input: terminal.input as unknown as NodeJS.ReadStream,
          output: terminal.output as unknown as NodeJS.WriteStream,
          error: terminal.output as unknown as NodeJS.WriteStream,
          signal: new AbortController().signal,
        })
      : selectWithTui({
          message: "Action",
          choices: ["Add"],
          input: terminal.input as unknown as NodeJS.ReadStream,
          output: terminal.output as unknown as NodeJS.WriteStream,
          error: terminal.output as unknown as NodeJS.WriteStream,
          signal: new AbortController().signal,
          required: true,
          single: true,
        });

  await terminal.waitForSelection(1);
  const rejected = expect(operation).rejects.toBeInstanceOf(
    kind === "text" ? TextInputCancelled : MultiSelectCancelled,
  );
  await act(async () => terminal.input.end());
  await rejected;
  expect(terminal.input.isRaw).toBe(false);
  expect(terminal.input.listenerCount("end")).toBe(beforeEndListeners);
});

test.each(["text", "select"] as const)(
  "releases %s renderer resources when setup throws synchronously",
  async (kind) => {
    const terminal = setupTty();
    const failure = new Error("renderer setup failed");
    const beforeEndListeners = terminal.input.listenerCount("end");
    const beforeResizeListeners = terminal.output.listenerCount("resize");
    terminal.output.on = (() => {
      throw failure;
    }) as unknown as typeof terminal.output.on;
    const operation =
      kind === "text"
        ? readTextWithTui({
            message: "Name",
            input: terminal.input as unknown as NodeJS.ReadStream,
            output: terminal.output as unknown as NodeJS.WriteStream,
            error: terminal.output as unknown as NodeJS.WriteStream,
            signal: new AbortController().signal,
          })
        : selectWithTui({
            message: "Action",
            choices: ["Add"],
            input: terminal.input as unknown as NodeJS.ReadStream,
            output: terminal.output as unknown as NodeJS.WriteStream,
            error: terminal.output as unknown as NodeJS.WriteStream,
            signal: new AbortController().signal,
            required: true,
            single: true,
          });

    await expect(operation).rejects.toBe(failure);
    expect(terminal.input.listenerCount("end")).toBe(beforeEndListeners);
    expect(terminal.output.listenerCount("resize")).toBe(beforeResizeListeners);
    expect(terminal.input.isRaw).toBe(false);
  },
);

test("selects multiple rows with Space and submits sorted indexes", async () => {
  const { stdin, onSubmit } = picker({ required: true });

  await press(stdin, " ", "\u001B[B", " ", "\r");

  expect(onSubmit).toHaveBeenCalledWith([0, 1]);
});

test("submits the configured default selection", async () => {
  const { stdin, lastFrame, onSubmit } = picker({ defaultIndexes: [0] });

  expect(lastFrame()).toContain("› ◉ Claude Code");
  await press(stdin, "\r");

  expect(onSubmit).toHaveBeenCalledWith([0]);
});

test("rejects an invalid default before opening the TUI", async () => {
  const terminal = setupTty();
  const interaction = new SetupInteraction({
    input: terminal.input,
    output: terminal.output,
    error: terminal.output,
  });
  try {
    await expect(
      interaction.selectIndexes("Destination", ["Copy"], {
        allowNone: false,
        defaultIndexes: [1],
      }),
    ).rejects.toThrow("Invalid default selection");
  } finally {
    interaction.close();
    terminal.input.end();
  }
});

test.each([0, 2])("line-mode all excludes exclusive index %i", async (exclusiveIndex) => {
  const output = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
  const interaction = new SetupInteraction({
    input: Readable.from(["all\n"]),
    output,
    error: output,
  });
  try {
    await expect(
      interaction.selectIndexes("Destination", ["Copy", "Claude", "Codex"], {
        allowNone: false,
        allSize: 2,
        exclusiveIndex,
        defaultIndexes: [exclusiveIndex],
      }),
    ).resolves.toEqual([0, 1, 2].filter((index) => index !== exclusiveIndex));
  } finally {
    interaction.close();
  }
});

test("line-mode Enter uses the configured default", async () => {
  const output = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
  const interaction = new SetupInteraction({ input: Readable.from(["\n"]), output, error: output });
  try {
    await expect(
      interaction.selectIndexes("Destination", ["Copy", "Codex"], {
        allowNone: false,
        exclusiveIndex: 0,
        defaultIndexes: [0],
      }),
    ).resolves.toEqual([0]);
  } finally {
    interaction.close();
  }
});

test("line-mode readText preserves trim false while ask and default readText trim", async () => {
  const output = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
  const interaction = new SetupInteraction({
    input: Readable.from(["  raw value  \n", "  ask value  \n", "  default value  \n"]),
    output,
    error: output,
  });
  try {
    await expect(interaction.readText("Raw: ", { trim: false })).resolves.toBe("  raw value  ");
    await expect(interaction.ask("Ask: ")).resolves.toBe("ask value");
    await expect(interaction.readText("Default: ")).resolves.toBe("default value");
  } finally {
    interaction.close();
  }
});

test("reselects an exclusive default after selecting a normal row", async () => {
  const onSubmit = vi.fn<(indexes: number[]) => void>();
  const screen = render(
    <MultiSelectScreen
      message="Destination"
      choices={["Show configuration only", "Codex"]}
      exclusiveIndex={0}
      defaultIndexes={[0]}
      onSubmit={onSubmit}
      onCancel={() => {}}
    />,
  );

  await press(screen.stdin, "\u001B[B", " ", "\u001B[A", " ", "\r");
  expect(onSubmit).toHaveBeenCalledWith([0]);
});

test.each([0, 2])("bulk selection excludes exclusive index %i", async (exclusiveIndex) => {
  const onSubmit = vi.fn<(indexes: number[]) => void>();
  const screen = render(
    <MultiSelectScreen
      message="Destination"
      choices={["Copy", "Claude", "Codex"]}
      exclusiveIndex={exclusiveIndex}
      defaultIndexes={[exclusiveIndex]}
      onSubmit={onSubmit}
      onCancel={() => {}}
    />,
  );

  await press(screen.stdin, "a", "\r");
  expect(onSubmit).toHaveBeenCalledWith([0, 1, 2].filter((index) => index !== exclusiveIndex));
});

test("wraps arrow navigation and renders the active cursor", async () => {
  const { stdin, lastFrame } = picker();

  await press(stdin, "\u001B[A");

  expect(lastFrame()).toContain("› ◯ Manual upstream");
});

test("selects and clears all normal rows without selecting the exclusive row", async () => {
  const first = picker();
  await press(first.stdin, "a", "\r");
  expect(first.onSubmit).toHaveBeenCalledWith([0, 1]);

  const second = picker();
  await press(second.stdin, "a", "a", "\r");
  expect(second.onSubmit).toHaveBeenCalledWith([]);
});

test.each([0, 2])("inverts only normal rows when exclusive index is %i", async (exclusiveIndex) => {
  const onSubmit = vi.fn<(indexes: number[]) => void>();
  const screen = render(
    <MultiSelectScreen
      message="Destination"
      choices={["Copy", "Claude", "Codex"]}
      exclusiveIndex={exclusiveIndex}
      defaultIndexes={[exclusiveIndex]}
      onSubmit={onSubmit}
      onCancel={() => {}}
    />,
  );

  await press(screen.stdin, "i", "\r");
  expect(onSubmit).toHaveBeenCalledWith([0, 1, 2].filter((index) => index !== exclusiveIndex));
});

test("keeps Manual upstream mutually exclusive with client adapters", async () => {
  const manual = picker();
  await press(manual.stdin, " ", "\u001B[B", "\u001B[B", " ", "\r");
  expect(manual.onSubmit).toHaveBeenCalledWith([2]);

  const client = picker();
  await press(client.stdin, "\u001B[A", " ", "\u001B[A", " ", "\r");
  expect(client.onSubmit).toHaveBeenCalledWith([1]);
});

test("applies navigation and toggle keys delivered in one stdin chunk in order", async () => {
  const screen = picker();
  await press(screen.stdin, "a");

  await act(async () => screen.stdin.write("\u001B[B\u001B[B "));
  await press(screen.stdin, "\r");

  expect(screen.onSubmit).toHaveBeenCalledWith([2]);
});

test("submits the active row when a required selection has no checked rows", async () => {
  const { stdin, onSubmit } = picker({ required: true });

  await press(stdin, "\r");

  expect(onSubmit).toHaveBeenCalledWith([0]);
});

test("chooses the active row in single-choice mode without bulk controls", async () => {
  const onSubmit = vi.fn<(indexes: number[]) => void>();
  const screen = render(
    <MultiSelectScreen
      message="Select action"
      choices={["Add MCP", "Restore MCP"]}
      single
      onSubmit={onSubmit}
      onCancel={() => {}}
    />,
  );

  await press(screen.stdin, "\u001B[B");
  expect(screen.lastFrame()).toContain("↑↓ move · enter choose");
  expect(screen.lastFrame()).not.toContain("space toggle");

  await press(screen.stdin, "\r");

  expect(onSubmit).toHaveBeenCalledWith([1]);
});

test("keeps a required empty choice list on screen with an inline error", async () => {
  const onSubmit = vi.fn<(indexes: number[]) => void>();
  const screen = render(
    <MultiSelectScreen
      message="Select tools"
      choices={[]}
      required
      onSubmit={onSubmit}
      onCancel={() => {}}
    />,
  );

  await press(screen.stdin, "\r");

  expect(onSubmit).not.toHaveBeenCalled();
  expect(screen.lastFrame()).toContain("Select at least one item.");
});

test.each(["\u001B", "\u0003"])("cancels on %j", async (key) => {
  const { stdin, onCancel, onSubmit } = picker();

  await press(stdin, key);

  await vi.waitFor(() => expect(onCancel).toHaveBeenCalledOnce());
  expect(onSubmit).not.toHaveBeenCalled();
});

test("keeps the active row visible in a paged list", async () => {
  const longChoices = Array.from({ length: 8 }, (_, index) => `Tool ${index + 1}`);
  const screen = render(
    <MultiSelectScreen
      message="Select tools"
      choices={longChoices}
      pageSize={3}
      onSubmit={() => {}}
      onCancel={() => {}}
    />,
  );

  await press(screen.stdin, ...Array<string>(5).fill("\u001B[B"));

  expect(screen.lastFrame()).toContain("› ◯ Tool 6");
  expect(screen.lastFrame()).not.toContain("Tool 1");
});

test("submits an optional empty choice list without creating an invalid index", async () => {
  const onSubmit = vi.fn<(indexes: number[]) => void>();
  const screen = render(
    <MultiSelectScreen
      message="Select tools"
      choices={[]}
      onSubmit={onSubmit}
      onCancel={() => {}}
    />,
  );

  await press(screen.stdin, "\u001B[B", " ");

  expect(screen.lastFrame()).toContain("No items available.");
  await press(screen.stdin, "\r");
  expect(onSubmit).toHaveBeenCalledWith([]);
});

test("routes text, secret, and selection handoff through Ink and restores readline", async () => {
  const rawModes: boolean[] = [];
  let referenced = true;
  let references = 0;
  const input = Object.assign(new PassThrough(), {
    isTTY: true as const,
    isRaw: false,
    setRawMode(mode: boolean) {
      this.isRaw = mode;
      rawModes.push(mode);
      return this;
    },
    ref() {
      referenced = true;
      references += 1;
      return this;
    },
    unref() {
      referenced = false;
      return this;
    },
  });
  const chunks: Buffer[] = [];
  const output = Object.assign(
    new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(Buffer.from(chunk));
        callback();
      },
    }),
    { isTTY: true as const, columns: 80, rows: 24 },
  );
  const interaction = new SetupInteraction({ input, output, error: output });
  expect(interaction.usesTui).toBe(true);

  try {
    const referencesBeforeAction = references;
    const actionSelection = interaction.selectIndexes("Select action", ["Add MCP", "Restore MCP"], {
      allowNone: false,
      single: true,
    });
    expect(references).toBe(referencesBeforeAction);
    await vi.waitFor(() => expect(rawModes).toContain(true));
    input.write("a");
    await new Promise<void>((resolve) => setImmediate(resolve));
    input.write("\r");
    await expect(actionSelection).resolves.toEqual([0]);
    expect(input.isRaw).toBe(false);
    expect(referenced).toBe(true);
    interaction.write("Action selected.\n");

    const first = interaction.readText("Server name", { required: true });
    await vi.waitFor(() => expect(rawModes.filter(Boolean)).toHaveLength(2));
    await press(input, "files", "\r");
    await expect(first).resolves.toBe("files");
    expect(input.isRaw).toBe(false);
    expect(referenced).toBe(true);

    const secret = interaction.readSecret("OAuth client secret");
    await vi.waitFor(() => expect(rawModes.filter(Boolean)).toHaveLength(3));
    await press(input, "do-not-render", "\r");
    await expect(secret).resolves.toBe("do-not-render");
    expect(input.isRaw).toBe(false);
    expect(referenced).toBe(true);

    const confirmed = interaction.confirm("Connect to this upstream?");
    await vi.waitFor(() => expect(rawModes.filter(Boolean)).toHaveLength(4));
    input.write("\r");
    await expect(confirmed).resolves.toBe(true);
    expect(Buffer.concat(chunks).toString("utf8")).toContain("› Yes");
    expect(input.isRaw).toBe(false);
    expect(referenced).toBe(true);
    interaction.write("Connection confirmed.\n");

    const declined = interaction.confirm("Connect to this upstream?");
    await vi.waitFor(() => expect(rawModes.filter(Boolean)).toHaveLength(5));
    input.write("\u001B[B");
    await new Promise<void>((resolve) => setImmediate(resolve));
    input.write("\r");
    await expect(declined).resolves.toBe(false);
    expect(input.isRaw).toBe(false);
    expect(referenced).toBe(true);

    const referencesBeforeClients = references;
    const selection = interaction.selectIndexes("Select clients", choices, {
      allowNone: false,
      allSize: 2,
      exclusiveIndex: 2,
    });
    expect(references).toBe(referencesBeforeClients);
    await vi.waitFor(() => expect(rawModes.filter(Boolean)).toHaveLength(6));
    const observedSelection = selection.then(
      (value) => ({ value }),
      (error: unknown) => ({ error }),
    );
    input.write("a");
    await new Promise<void>((resolve) => setImmediate(resolve));
    input.write("\r");
    await expect(observedSelection).resolves.toEqual({ value: [0, 1] });
    expect(input.isRaw).toBe(false);
    expect(referenced).toBe(true);

    const next = interaction.readText("Saved configuration name", { required: true });
    await vi.waitFor(() => expect(rawModes.filter(Boolean)).toHaveLength(7));
    await press(input, "safe-default", "\r");
    await expect(next).resolves.toBe("safe-default");
    expect(input.isRaw).toBe(false);
    expect(referenced).toBe(true);

    interaction.write("Setup complete.\n");
  } finally {
    interaction.close(true);
    input.end();
  }

  expect(referenced).toBe(false);
  const raw = Buffer.concat(chunks).toString("utf8");
  expect(occurrences(raw, ENTER_ALTERNATE_SCREEN)).toBe(1);
  expect(occurrences(raw, EXIT_ALTERNATE_SCREEN)).toBe(1);
  expect(occurrences(raw, CLEAR_VIEWPORT)).toBeGreaterThan(1);
  expect(raw).toContain("Select clients");
  expect(raw).toContain("Connect to this upstream?");
  expect(raw).not.toContain("do-not-render");
  expect(primaryOutput(raw)).toBe("Setup complete.\n");
});

test.each([
  [
    "text",
    "Escape",
    async (terminal: ReturnType<typeof setupTty>, _controller: AbortController) => {
      await press(terminal.input, "\u001B");
    },
  ],
  [
    "text",
    "Ctrl-C",
    async (terminal: ReturnType<typeof setupTty>, _controller: AbortController) => {
      await press(terminal.input, "\u0003");
    },
  ],
  [
    "text",
    "EOF",
    (terminal: ReturnType<typeof setupTty>, _controller: AbortController) => terminal.input.end(),
  ],
  [
    "text",
    "external abort",
    (_terminal: ReturnType<typeof setupTty>, controller: AbortController) => controller.abort(),
  ],
  [
    "secret",
    "Escape",
    async (terminal: ReturnType<typeof setupTty>, _controller: AbortController) => {
      await press(terminal.input, "do-not-render", "\u001B");
    },
  ],
  [
    "secret",
    "Ctrl-C",
    async (terminal: ReturnType<typeof setupTty>, _controller: AbortController) => {
      await press(terminal.input, "do-not-render", "\u0003");
    },
  ],
  [
    "secret",
    "EOF",
    (terminal: ReturnType<typeof setupTty>, _controller: AbortController) => terminal.input.end(),
  ],
  [
    "secret",
    "external abort",
    async (terminal: ReturnType<typeof setupTty>, controller: AbortController) => {
      await press(terminal.input, "do-not-render");
      controller.abort();
    },
  ],
] as const)("cancels an Ink %s on %s", async (kind, _name, cancel) => {
  const terminal = setupTty();
  const controller = new AbortController();
  const interaction = new SetupInteraction({
    input: terminal.input,
    output: terminal.output,
    error: terminal.output,
    signal: controller.signal,
  });

  try {
    const operation =
      kind === "text"
        ? interaction.readText("Server name", { required: true })
        : interaction.readSecret("OAuth client secret");
    await terminal.waitForSelection(1);
    const rejected = expect(operation).rejects.toBeInstanceOf(SetupCancelled);
    await cancel(terminal, controller);
    await rejected;
    expect(terminal.input.isRaw).toBe(false);
  } finally {
    interaction.close();
    terminal.input.end();
  }

  const raw = terminal.raw();
  expect(occurrences(raw, EXIT_ALTERNATE_SCREEN)).toBe(1);
  expect(alternateOutput(raw)).not.toContain("do-not-render");
  expect(primaryOutput(raw)).not.toContain("do-not-render");
});

test("keeps saved-policy collision retry in one Ink screen without replaying the name", async () => {
  const root = await mkdtemp("/private/tmp/mcp-restrictor-tui-saved-policy-");
  const terminal = setupTty();
  const context = {
    client: "codex",
    scope: "project" as const,
    serverName: "files",
    projectRoot: root,
    restrictorHome: join(root, "home"),
  };
  const directory = savedPolicyDirectory(context);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await writeFile(
    join(directory, "existing.yaml"),
    "version: 1\ndefault: deny\ntools:\n  allow: []\n  deny: []\n",
    {
      mode: 0o600,
    },
  );
  const interaction = new SetupInteraction({
    input: terminal.input,
    output: terminal.output,
    error: terminal.output,
  });

  try {
    const planned = planOptionalSavedPolicy({
      interaction,
      context,
      policySource: "version: 1\ndefault: deny\ntools:\n  allow: []\n  deny: []\n",
      backupKey: join(root, "config.json"),
    });
    await choose(terminal, 1, "\u001B[B", "\r");
    await terminal.waitForSelection(2);
    expect(terminal.input.isRaw).toBe(true);
    expect(alternateOutput(terminal.raw())).toContain("Saved configuration name");
    await press(terminal.input, "existing", "\r");
    await terminal.waitForSelection(3);
    await press(terminal.input, "safe-default", "\r");
    await expect(planned).resolves.toMatchObject({ path: join(directory, "safe-default.yaml") });
    expect(occurrences(terminal.raw(), ENTER_ALTERNATE_SCREEN)).toBe(1);
    expect(occurrences(terminal.raw(), EXIT_ALTERNATE_SCREEN)).toBe(0);
  } finally {
    interaction.close(true);
    terminal.input.end();
    await rm(root, { recursive: true, force: true });
  }

  expect(primaryOutput(terminal.raw())).not.toContain("safe-default");
});

test("replays only a managed Add result after raw-TTY setup", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-add-")));
  const configPath = join(root, ".codex", "config.toml");
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(
    configPath,
    `[mcp_servers.files]\ncommand = ${JSON.stringify(process.execPath)}\nargs = [${JSON.stringify(upstream)}, ${JSON.stringify(root)}]\ncwd = ${JSON.stringify(root)}\n\n[mcp_servers.files.env]\nAPI_KEY = "secret"\n`,
  );
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home: join(root, "home"),
      environment: { PATH: process.env.PATH },
      adapters: [codexAdapter],
      restrictor: { command: process.execPath, argsPrefix: [cli] },
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\r");
    await choose(terminal, 3, " ", "\r");
    await choose(terminal, 4, "\r");
    await choose(terminal, 5, " ", "\r");
    await choose(terminal, 6, "\r");
    await choose(terminal, 7, "\r");
    await choose(terminal, 8, "\r");
    await setup;

    const raw = terminal.raw();
    expect(occurrences(raw, ENTER_ALTERNATE_SCREEN)).toBe(1);
    expect(occurrences(raw, EXIT_ALTERNATE_SCREEN)).toBe(1);
    expect(alternateOutput(raw)).toContain("Actions:");
    expect(alternateOutput(raw)).toContain("Clients:");
    expect(alternateOutput(raw)).toContain("Supported MCP servers:");
    expect(primaryOutput(raw)).toContain("Setup complete.\n");
    expect(primaryOutput(raw)).not.toContain("Actions:");
    expect(primaryOutput(raw)).not.toContain("Clients:");
    expect(primaryOutput(raw)).not.toContain("Supported MCP servers:");
    expect(primaryOutput(raw)).not.toContain("Preview:");
    expect(primaryOutput(raw)).not.toContain("Tools for");
  } finally {
    terminal.input.end();
    await rm(root, { recursive: true, force: true });
  }
});

test("installs HTTP Manual headers through the public fullscreen flow", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-manual-http-")));
  const home = join(root, "home");
  const configPath = join(root, ".mcp.json");
  await writeFile(configPath, '{"mcpServers": {}}\n');
  const restrictor = await writeNodeLauncher(root, cli);
  const remote = await startRemoteAuthFixture({
    transport: "http",
    requiredHeaders: { "X-Key": "key-secret", "X-Tenant": "tenant-secret" },
  });
  const terminal = setupTty();
  const before = await snapshotTree(root, { exact: true });

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home,
      environment: {
        PATH: process.env.PATH,
        API_KEY: "key-secret",
        TENANT: "tenant-secret",
      },
      adapters: [claudeAdapter],
      restrictor: { command: restrictor, argsPrefix: [] },
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\u001B[B", "\r");
    await terminal.waitForSelection(3);
    await press(terminal.input, "remote", "\r");
    await choose(terminal, 4, "\u001B[B", "\r");
    await terminal.waitForSelection(5);
    await press(terminal.input, "http://example.test/mcp", "\r");
    await choose(terminal, 6, "\u001B[B", "\r");
    await terminal.waitForSelection(7);
    await press(terminal.input, "X-Key", "\r");
    await terminal.waitForSelection(8);
    await press(terminal.input, "API_KEY", "\r");
    await choose(terminal, 9, "\u001B[B", "\r");
    await terminal.waitForSelection(10);
    await press(terminal.input, "x-key", "\r");
    await vi.waitFor(() => expect(alternateOutput(terminal.raw())).toContain("duplicate"));
    await press(terminal.input, "\u0015", "X-Tenant", "\r");
    await terminal.waitForSelection(11);
    await press(terminal.input, "TENANT", "\r");
    await choose(terminal, 12, "\r");
    await choose(terminal, 13, "\r");
    await terminal.waitForSelection(14);
    expect(terminal.raw().slice(terminal.raw().lastIndexOf(CLEAR_VIEWPORT))).toContain(
      "Upstream URL",
    );
    expect(await snapshotTree(root, { exact: true })).toEqual(before);
    await press(terminal.input, "http://example.test/mcp", "\r");
    await vi.waitFor(() =>
      expect(alternateOutput(terminal.raw())).toContain("Enter a valid upstream URL."),
    );
    expect(await snapshotTree(root, { exact: true })).toEqual(before);
    await press(terminal.input, "\u0015", remote.url, "\r");
    await choose(terminal, 15, "\u001B[B", " ", "\r");
    await choose(terminal, 16, "\r");
    await choose(terminal, 17, "\r");
    await choose(terminal, 18, "\r");
    await choose(terminal, 19, " ", "\r");
    await choose(terminal, 20, "\r");
    await choose(terminal, 21, "\r");
    await setup;

    const entry = JSON.parse(await readFile(configPath, "utf8")).mcpServers.remote;
    expect(entry.command).toBe(restrictor);
    expect(entry.args.slice(entry.args.indexOf("--upstream-http"))).toEqual([
      "--upstream-http",
      remote.url,
      "--upstream-header-env",
      "X-Key=API_KEY",
      "--upstream-header-env",
      "X-Tenant=TENANT",
    ]);
    expect(entry.env).toEqual({ API_KEY: "${API_KEY}", TENANT: "${TENANT}" });
    const policy = await readFile(
      join(root, ".mcp-restrictor", "policies", "claude", "remote.yaml"),
      "utf8",
    );
    expect(policy).toContain("name: allowed_tool");
    expect(policy).not.toContain("name: denied_tool");
    expectCompletedManualFullscreen(terminal.raw(), configPath);
  } finally {
    terminal.input.end();
    await remote.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("installs WebSocket Manual Authorization through the public fullscreen flow", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-manual-websocket-")),
  );
  const home = join(root, "home");
  const configPath = join(root, ".mcp.json");
  await writeFile(configPath, '{"mcpServers": {}}\n');
  const restrictor = await writeNodeLauncher(root, cli);
  const remote = await startRemoteAuthFixture({
    transport: "websocket",
    requiredHeaders: { Authorization: "Basic websocket-secret" },
  });
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home,
      environment: {
        PATH: process.env.PATH,
        AUTHORIZATION: "Basic websocket-secret",
      },
      adapters: [claudeAdapter],
      restrictor: { command: restrictor, argsPrefix: [] },
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\u001B[B", "\r");
    await terminal.waitForSelection(3);
    await press(terminal.input, "socket", "\r");
    await choose(terminal, 4, "\u001B[B", "\u001B[B", "\u001B[B", "\r");
    await terminal.waitForSelection(5);
    await press(terminal.input, remote.url, "\r");
    await choose(terminal, 6, "\u001B[B", "\r");
    await terminal.waitForSelection(7);
    await press(terminal.input, "Authorization", "\r");
    await terminal.waitForSelection(8);
    await press(terminal.input, "AUTHORIZATION", "\r");
    await choose(terminal, 9, "\r");
    await choose(terminal, 10, "\u001B[B", " ", "\r");
    await choose(terminal, 11, "\r");
    await choose(terminal, 12, "\r");
    await choose(terminal, 13, "\r");
    await choose(terminal, 14, " ", "\r");
    await choose(terminal, 15, "\r");
    await choose(terminal, 16, "\r");
    await setup;

    const entry = JSON.parse(await readFile(configPath, "utf8")).mcpServers.socket;
    expect(entry.command).toBe(restrictor);
    expect(entry.args.slice(entry.args.indexOf("--upstream-websocket"))).toEqual([
      "--upstream-websocket",
      remote.url,
      "--upstream-header-env",
      "Authorization=AUTHORIZATION",
    ]);
    expect(entry.env).toEqual({ AUTHORIZATION: "${AUTHORIZATION}" });
    const policy = await readFile(
      join(root, ".mcp-restrictor", "policies", "claude", "socket.yaml"),
      "utf8",
    );
    expect(policy).toContain("name: allowed_tool");
    expect(policy).not.toContain("name: denied_tool");
    expect(alternateOutput(terminal.raw())).not.toContain("Authentication");
    expectCompletedManualFullscreen(terminal.raw(), configPath);
  } finally {
    terminal.input.end();
    await remote.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("installs SSE Manual OAuth options through the public fullscreen flow", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-manual-sse-")));
  const home = join(root, "home");
  const configPath = join(root, ".mcp.json");
  const keyPath = join(root, "oauth-master.key");
  const keyBytes = randomBytes(32).toString("base64url");
  await Promise.all([
    writeFile(configPath, '{"mcpServers": {}}\n'),
    writeFile(keyPath, keyBytes, { mode: 0o600 }),
  ]);
  await chmod(keyPath, 0o600);
  const restrictor = await writeNodeLauncher(root, cli);
  const remote = await startRemoteAuthFixture({
    transport: "sse",
    oauth: {
      expectedScope: "fixture-scope",
      challengeScope: "fixture-scope",
      expectedCallback: "manual",
    },
  });
  const origin = new URL(remote.url).origin;
  const resourceMetadataUrl = `${origin}/resource-metadata`;
  const authServerMetadataUrl = `${origin}/.well-known/oauth-authorization-server`;
  const previousHome = process.env.HOME;
  const previousUserProfile = process.env.USERPROFILE;
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  let authorizationOutput = "";
  let loginInput: { clientInformation?: unknown } | undefined;
  let preparedStorage: OAuthStorageOptions | undefined;
  const setupEvents: string[] = [];
  setupTuiFakes.prepare = async (actual, options) => {
    setupEvents.push("prepare");
    preparedStorage = options;
    await actual(options);
  };
  setupTuiFakes.login = async (actual, options) => {
    setupEvents.push("login");
    loginInput = options.input;
    const { clientInformation: _clientInformation, ...input } = options.input;
    return actual({
      ...options,
      input,
    });
  };
  const terminal = setupTty((value) => {
    authorizationOutput += value;
    const match = /Open this URL to authorize:\n([^\n]+)\n/.exec(authorizationOutput);
    if (!match?.[1]) return;
    authorizationOutput = "";
    void fetch(match[1])
      .then((response) => response.text())
      .catch(() => undefined);
  });

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home,
      environment: {
        PATH: process.env.PATH,
        [CONTAINER_MARKER_ENV]: "1",
        [MASTER_KEY_FILE_ENV]: keyPath,
      },
      adapters: [claudeAdapter],
      restrictor: { command: restrictor, argsPrefix: [] },
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\u001B[B", "\r");
    await terminal.waitForSelection(3);
    await press(terminal.input, "oauth", "\r");
    await choose(terminal, 4, "\u001B[B", "\u001B[B", "\r");
    await terminal.waitForSelection(5);
    await press(terminal.input, remote.url, "\r");
    await choose(terminal, 6, "\r");
    await choose(terminal, 7, "\u001B[B", "\u001B[B", "\r");
    await choose(terminal, 8, "\u001B[B", "\r");
    await terminal.waitForSelection(9);
    await press(terminal.input, "manual-client-id", "\r");
    for (const [selection, invalid, value, error] of [
      [10, undefined, "fixture-scope", undefined],
      [12, "relative", remote.url, "Enter a valid absolute URL."],
      [
        14,
        "http://metadata.example.test/resource",
        resourceMetadataUrl,
        "Enter a secure OAuth URL.",
      ],
      [16, "http://auth.example.test/metadata", authServerMetadataUrl, "Enter a secure OAuth URL."],
    ] as const) {
      await choose(terminal, selection, "\u001B[B", "\r");
      await terminal.waitForSelection(selection + 1);
      if (invalid && error) {
        const priorErrors = occurrences(alternateOutput(terminal.raw()), error);
        await press(terminal.input, invalid, "\r");
        await vi.waitFor(() =>
          expect(occurrences(alternateOutput(terminal.raw()), error)).toBeGreaterThan(priorErrors),
        );
        await press(terminal.input, "\u0015");
      }
      await press(terminal.input, value, "\r");
    }
    await choose(terminal, 18, "\u001B[B", "\r");
    await terminal.waitForSelection(19);
    await press(terminal.input, "70000", "\r");
    await vi.waitFor(() =>
      expect(alternateOutput(terminal.raw())).toContain("Enter an integer from 0 to 65535."),
    );
    await press(terminal.input, "\u0015", "0", "\r");
    await choose(terminal, 20, "\u001B[B", "\r");
    await terminal.waitForSelection(21);
    await press(terminal.input, "http://127.0.0.1:0/callback?state=fixed", "\r");
    await vi.waitFor(() =>
      expect(alternateOutput(terminal.raw())).toContain("Enter a valid OAuth callback URL."),
    );
    await press(terminal.input, "\u0015");
    await press(terminal.input, "http://127.0.0.1:0/callback", "\r");
    await choose(terminal, 22, "\u001B[B", " ", "\r");
    await choose(terminal, 23, "\r");
    await choose(terminal, 24, "\r");
    await choose(terminal, 25, "\r");
    await choose(terminal, 26, "\r");
    await choose(terminal, 27, "\r");
    await choose(terminal, 28, "\r");
    await choose(terminal, 29, " ", "\r");
    await choose(terminal, 30, "\r");
    await choose(terminal, 31, "\r");
    await setup;

    const entry = JSON.parse(await readFile(configPath, "utf8")).mcpServers.oauth;
    const upstreamIndex = entry.args.indexOf("--upstream-sse");
    expect(entry.command).toBe(restrictor);
    expect(entry.args.slice(upstreamIndex, upstreamIndex + 2)).toEqual([
      "--upstream-sse",
      remote.url,
    ]);
    const profileIndex = entry.args.indexOf("--upstream-oauth-profile");
    expect(profileIndex).toBeGreaterThan(upstreamIndex);
    expect(entry.env).toEqual({ [MASTER_KEY_FILE_ENV]: keyPath });
    const profile = await readOAuthProfile(entry.args[profileIndex + 1], {
      home,
      environment: { [MASTER_KEY_FILE_ENV]: keyPath },
    });
    expect(profile.metadata).toMatchObject({
      requestedScope: "fixture-scope",
      resource: remote.url,
      resourceMetadataUrl,
      authServerMetadataUrl,
      callback: {
        url: "http://127.0.0.1:0/callback",
        port: 0,
        appendProfileId: true,
      },
    });
    expect(loginInput?.clientInformation).toEqual({ client_id: "manual-client-id" });
    expect(preparedStorage).toEqual({
      home,
      environment: {
        [MASTER_KEY_FILE_ENV]: keyPath,
        [CONTAINER_MARKER_ENV]: "1",
      },
    });
    expect(setupEvents).toEqual(["prepare", "login"]);
    expect(alternateOutput(terminal.raw())).toContain("OAuth redirect delivery");
    expect(alternateOutput(terminal.raw())).toContain("Loopback listener");
    expect(alternateOutput(terminal.raw())).toContain("Paste redirected URL");
    const policy = await readFile(
      join(root, ".mcp-restrictor", "policies", "claude", "oauth.yaml"),
      "utf8",
    );
    expect(policy).toContain("name: allowed_tool");
    expect(policy).not.toContain("name: denied_tool");
    expect(remote.authorizationRequests()).toBe(1);
    expect(remote.tokenRequests()).toBe(1);
    for (const secret of [keyBytes, ...remote.sensitiveValues()]) {
      expect(`${terminal.raw()}\n${await readFile(configPath, "utf8")}\n${policy}`).not.toContain(
        secret,
      );
    }
    expect(`${terminal.raw()}\n${await readFile(configPath, "utf8")}`).not.toContain(
      CONTAINER_MARKER_ENV,
    );
    expectCompletedManualFullscreen(terminal.raw(), configPath);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    if (previousUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = previousUserProfile;
    terminal.input.end();
    await remote.close();
    await rm(root, { recursive: true, force: true });
  }
}, 20_000);

test.each([
  ["Escape", (terminal: ReturnType<typeof setupTty>) => press(terminal.input, "\u001B")],
  ["Ctrl-C", (terminal: ReturnType<typeof setupTty>) => press(terminal.input, "\u0003")],
  [
    "EOF",
    async (terminal: ReturnType<typeof setupTty>) => {
      terminal.input.end();
    },
  ],
] as const)(
  "cancels real OAuth redirect delivery on %s through the fullscreen setup result",
  async (_name, cancel) => {
    const root = await realpath(
      await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-oauth-delivery-cancel-")),
    );
    const home = join(root, "home");
    const configPath = join(root, ".mcp.json");
    const keyPath = join(root, "oauth-master.key");
    const keyBytes = randomBytes(32).toString("base64url");
    await Promise.all([
      writeFile(configPath, '{"mcpServers": {}}\n'),
      writeFile(keyPath, keyBytes, { mode: 0o600 }),
    ]);
    await chmod(keyPath, 0o600);
    const restrictor = await writeNodeLauncher(root, cli);
    const before = await snapshotTree(root, { exact: true });
    const terminal = setupTty();

    try {
      const setup = runSetupCommand({
        input: terminal.input,
        output: terminal.output,
        error: terminal.output,
        cwd: root,
        home,
        environment: { PATH: process.env.PATH, [MASTER_KEY_FILE_ENV]: keyPath },
        adapters: [claudeAdapter],
        restrictor: { command: restrictor, argsPrefix: [] },
      });
      void setup.catch(() => undefined);
      await enterManualOAuthUntilRedirectDelivery(terminal);
      await cancel(terminal);
      await setup;

      expect(primaryOutput(terminal.raw())).toBe("Setup cancelled.\n");
      expect(await snapshotTree(root, { exact: true })).toEqual(before);
    } finally {
      terminal.input.end();
      await rm(root, { recursive: true, force: true });
    }
  },
  10_000,
);

test("keeps the installed Manual fullscreen flow ordered and replays only its result", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-manual-installed-")),
  );
  const home = join(root, "home");
  const configPath = join(root, ".mcp.json");
  await writeFile(configPath, '{"mcpServers": {}}\n');
  const restrictor = await writeNodeLauncher(root, cli);
  const manualUpstream = await writeFixedManualUpstream(root);
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH, API_KEY: "secret" },
      adapters: [claudeAdapter],
      restrictor: { command: restrictor, argsPrefix: [] },
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\u001B[B", "\r");
    await enterManualStdio(terminal, 3, manualUpstream);
    await choose(terminal, 16, "\u001B[B", " ", "\r");
    await choose(terminal, 17, "\r");
    await choose(terminal, 18, "\r");
    await choose(terminal, 19, "\r");
    await choose(terminal, 20, " ", "\r");
    await choose(terminal, 21, "\r");
    await choose(terminal, 22, "\r");
    await setup;

    const raw = terminal.raw();
    const screens = alternateOutput(raw);
    const order = [
      "Server name",
      "Destination:",
      "Client connection",
      "Select Tools & Policy",
      "Connect to this upstream?",
      "Select allowed tools",
      "Preview:",
      "Apply these changes?",
      "Setup complete.",
    ];
    const indices = order.map((label) => screens.indexOf(label));
    expect(indices).not.toContain(-1);
    for (let index = 1; index < indices.length; index += 1) {
      expect(indices[index - 1]!).toBeLessThan(indices[index]!);
    }
    expect(screens).toContain("action=add");
    expect(primaryOutput(raw)).toContain(`Changed: ${JSON.stringify(configPath)}\n`);
    expect(primaryOutput(raw)).toContain("Restart Claude Code");
    expect(primaryOutput(raw)).not.toMatch(/^(command|args|environment):/m);
    for (const label of order.slice(0, -1)) {
      expect(primaryOutput(raw)).not.toContain(label);
    }
    const installed = JSON.parse(await readFile(configPath, "utf8")).mcpServers.files;
    expect(installed.args.slice(-3)).toEqual([manualUpstream, "", "  spaced  "]);
    expect(installed.env).toEqual({ API_KEY: "${API_KEY}", PATH: "${PATH}" });
    expectCompletedManualFullscreen(raw, configPath);
  } finally {
    terminal.input.end();
    await rm(root, { recursive: true, force: true });
  }
});

test("keeps a Manual HTTP route fullscreen and replays only its final result", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-manual-route-")));
  const home = join(root, "home");
  const configPath = join(root, ".mcp.json");
  await writeFile(configPath, '{"mcpServers": {}}\n');
  const restrictor = await writeNodeLauncher(root, cli);
  const manualUpstream = await writeFixedManualUpstream(root);
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH, API_KEY: "secret" },
      adapters: [claudeAdapter],
      restrictor: { command: restrictor, argsPrefix: [] },
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\u001B[B", "\r");
    await enterManualStdio(terminal, 3, manualUpstream);
    await choose(terminal, 16, "\u001B[B", " ", "\r");
    await choose(terminal, 17, "\u001B[B", "\r");
    await choose(terminal, 18, "\r");
    await choose(terminal, 19, "\r");
    await choose(terminal, 20, "\r");
    await choose(terminal, 21, " ", "\r");
    await choose(terminal, 22, "\r");
    await choose(terminal, 23, "\r");
    await setup;

    const raw = terminal.raw();
    const final = primaryOutput(raw);
    const routes = await loadRoutes(home);
    expect(routes).toHaveLength(1);
    expect(JSON.parse(await readFile(configPath, "utf8")).mcpServers.files).toEqual({
      type: "http",
      url: routes[0]!.definition.listenUrl,
    });
    expect(final).toContain("Start HTTP routes: mcp-restrictor run");
    expect(final).not.toContain("HTTP gateway port");
    expect(final).not.toContain("Preview:");
    expect(alternateOutput(raw)).toContain("HTTP gateway port");
    expect(occurrences(raw, ENTER_ALTERNATE_SCREEN)).toBe(1);
    expect(occurrences(raw, EXIT_ALTERNATE_SCREEN)).toBe(1);
  } finally {
    terminal.input.end();
    await rm(root, { recursive: true, force: true });
  }
});

test("generates a private client preset through one fullscreen flow and replays only its result", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-generated-")));
  const home = join(root, "home");
  const restrictor = await writeNodeLauncher(root, cli);
  const manualUpstream = await writeFixedManualUpstream(root);
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH, API_KEY: "secret" },
      adapters: [claudeAdapter],
      restrictor: { command: restrictor, argsPrefix: [] },
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\u001B[B", "\r");
    await enterManualStdio(terminal, 3, manualUpstream);
    await choose(terminal, 16, "\u001B[B", " ", "\r");
    await choose(terminal, 17, "\r");
    await choose(terminal, 18, "\r");
    await choose(terminal, 19, "\r");
    await choose(terminal, 20, "\r");
    await choose(terminal, 21, " ", "\r");
    await choose(terminal, 22, "\r");
    await choose(terminal, 23, "\r");
    await setup;

    const configPath = generatedConfigPath(home, "claude");
    const policyPath = generatedPolicyLocation({
      home,
      adapterId: "claude",
      serverName: "files",
    }).diskPath;
    const config = JSON.parse(await readFile(configPath, "utf8"));
    const raw = terminal.raw();
    const final = primaryOutput(raw);
    expect(config.mcpServers.files).toEqual({
      type: "http",
      url: expect.stringMatching(/^http:\/\/127\.0\.0\.1:17319\/mcp\/claude\/[0-9a-f]{64}$/),
    });
    expect((await stat(dirname(configPath))).mode & 0o7777).toBe(0o700);
    expect((await stat(configPath)).mode & 0o7777).toBe(0o600);
    expect((await stat(policyPath)).mode & 0o7777).toBe(0o600);
    expect(final).toContain(`Changed: ${JSON.stringify(configPath)}`);
    expect(final).toContain("Client preset fragment — Claude Code");
    expect(final).toContain("Merge this entry into the host client configuration");
    expect(final).toContain("Start HTTP routes: mcp-restrictor run");
    for (const prior of [
      "Actions:",
      "Clients:",
      "Destination:",
      "Generated client presets:",
      "HTTP gateway port",
      "Preview:",
    ]) {
      expect(final).not.toContain(prior);
    }
    expect(alternateOutput(raw)).toContain("Generated client presets:");
    expect(occurrences(raw, ENTER_ALTERNATE_SCREEN)).toBe(1);
    expect(occurrences(raw, EXIT_ALTERNATE_SCREEN)).toBe(1);
  } finally {
    terminal.input.end();
    await rm(root, { recursive: true, force: true });
  }
}, 15_000);

test("cancels generated client selection without a partial write", async () => {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-generated-cancel-")),
  );
  const home = join(root, "home");
  const restrictor = await writeNodeLauncher(root, cli);
  const manualUpstream = await writeFixedManualUpstream(root);
  const before = await snapshotTree(root, { exact: true });
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH },
      adapters: [claudeAdapter],
      restrictor: { command: restrictor, argsPrefix: [] },
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\u001B[B", "\r");
    await enterManualStdio(terminal, 3, manualUpstream);
    await choose(terminal, 16, "\u001B[B", " ", "\r");
    await choose(terminal, 17, "\u001B");
    await setup;

    expect(await snapshotTree(root, { exact: true })).toEqual(before);
    expect(primaryOutput(terminal.raw())).toBe("Setup cancelled.\n");
  } finally {
    terminal.input.end();
    await rm(root, { recursive: true, force: true });
  }
});

test("keeps two independent Manual HTTP routes fullscreen and replays only their final result", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-manual-routes-")));
  const home = join(root, "home");
  const claudePath = join(root, ".mcp.json");
  const codexPath = join(home, ".codex", "config.toml");
  await mkdir(dirname(codexPath), { recursive: true });
  await writeFile(claudePath, '{"mcpServers": {}}\n');
  await writeFile(codexPath, "");
  const restrictor = await writeNodeLauncher(root, cli);
  const manualUpstream = await writeFixedManualUpstream(root);
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH, API_KEY: "secret" },
      adapters: [claudeAdapter, codexAdapter],
      restrictor: { command: restrictor, argsPrefix: [] },
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\u001B[B", "\u001B[B", "\r");
    await enterManualStdio(terminal, 3, manualUpstream);
    await choose(terminal, 16, "\u001B[B", " ", "\u001B[B", " ", "\r");
    await choose(terminal, 17, "\u001B[B", "\r");
    await choose(terminal, 18, "\u001B[B", "\r");
    await choose(terminal, 19, "\r");
    await choose(terminal, 20, "\r");
    await choose(terminal, 21, "\r");
    await choose(terminal, 22, "\r");
    await choose(terminal, 23, " ", "\r");
    await choose(terminal, 24, "\r");
    await choose(terminal, 25, " ", "\r");
    await choose(terminal, 26, "\r");
    await choose(terminal, 27, "\r");
    await setup;

    const raw = terminal.raw();
    const final = primaryOutput(raw);
    const routes = await loadRoutes(home);
    expect(routes).toHaveLength(2);
    expect(new Set(routes.map(({ definition }) => definition.owner.adapterId))).toEqual(
      new Set(["claude", "codex"]),
    );
    expect(new Set(routes.map(({ definition }) => new URL(definition.listenUrl).origin))).toEqual(
      new Set(["http://127.0.0.1:17319"]),
    );
    expect(final).toContain(`Changed: ${JSON.stringify(claudePath)}`);
    expect(final).toContain(`Changed: ${JSON.stringify(codexPath)}`);
    expect(final).toContain("Start HTTP routes: mcp-restrictor run");
    for (const prior of ["Destination:", "Client connection", "HTTP gateway port", "Preview:"]) {
      expect(final).not.toContain(prior);
    }
    expect(occurrences(raw, ENTER_ALTERNATE_SCREEN)).toBe(1);
    expect(occurrences(raw, EXIT_ALTERNATE_SCREEN)).toBe(1);
  } finally {
    terminal.input.end();
    await rm(root, { recursive: true, force: true });
  }
}, 15_000);

test("retries a custom Manual HTTP gateway port in the same fullscreen editor", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-manual-port-")));
  const home = join(root, "home");
  const configPath = join(root, ".mcp.json");
  await writeFile(configPath, '{"mcpServers": {}}\n');
  const restrictor = await writeNodeLauncher(root, cli);
  const manualUpstream = await writeFixedManualUpstream(root);
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH, API_KEY: "secret" },
      adapters: [claudeAdapter],
      restrictor: { command: restrictor, argsPrefix: [] },
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\u001B[B", "\r");
    await enterManualStdio(terminal, 3, manualUpstream);
    await choose(terminal, 16, "\u001B[B", " ", "\r");
    await choose(terminal, 17, "\u001B[B", "\r");
    await choose(terminal, 18, "\u001B[B", "\r");
    await terminal.waitForSelection(19);
    await press(terminal.input, "\r");
    await vi.waitFor(() => expect(terminal.raw()).toContain("This field is required."));
    await press(terminal.input, "0", "\r");
    await vi.waitFor(() => expect(terminal.raw()).toContain("Enter an integer from 1 to 65535."));
    await press(terminal.input, "\u0015", "abc", "\r");
    await vi.waitFor(() =>
      expect(
        terminal.raw().match(/Enter an integer from 1 to 65535\./g)?.length,
      ).toBeGreaterThanOrEqual(2),
    );
    await press(terminal.input, "\u0015", "65536", "\r");
    await vi.waitFor(() =>
      expect(
        terminal.raw().match(/Enter an integer from 1 to 65535\./g)?.length,
      ).toBeGreaterThanOrEqual(3),
    );
    await press(terminal.input, "\u0015", "7318", "\r");
    await choose(terminal, 20, "\r");
    await choose(terminal, 21, "\r");
    await choose(terminal, 22, " ", "\r");
    await choose(terminal, 23, "\r");
    await choose(terminal, 24, "\r");
    await setup;

    const raw = terminal.raw();
    expect((await loadRoutes(home))[0]!.definition.listenUrl).toContain("127.0.0.1:7318/");
    expect(raw).toContain("This field is required.");
    expect(raw.match(/Enter an integer from 1 to 65535\./g)?.length).toBeGreaterThanOrEqual(3);
    expect(primaryOutput(raw)).not.toContain("65536");
  } finally {
    terminal.input.end();
    await rm(root, { recursive: true, force: true });
  }
}, 10_000);

test("replays only generic wrapper values for copy-only Manual setup", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-manual-copy-")));
  const restrictor = await writeNodeLauncher(root, cli);
  const manualUpstream = await writeFixedManualUpstream(root);
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home: join(root, "home"),
      environment: { PATH: process.env.PATH, API_KEY: "secret" },
      adapters: [claudeAdapter],
      restrictor: { command: restrictor, argsPrefix: [] },
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\u001B[B", "\r");
    await enterManualStdio(terminal, 3, manualUpstream);
    await choose(terminal, 16, "\r");
    await choose(terminal, 17, "\r");
    await choose(terminal, 18, "\r");
    await choose(terminal, 19, " ", "\r");
    await choose(terminal, 20, "\r");
    await choose(terminal, 21, "\r");
    await setup;

    const final = primaryOutput(terminal.raw());
    expect(final).toMatch(/^Setup complete\.\ncommand: /);
    expect(final).toContain("args: ");
    expect(final).toContain("environment: ");
    expect(final).not.toContain("Changed: ");
    for (const label of [
      "Server name:",
      "Destination:",
      "Select Tools & Policy",
      "Connect to this upstream?",
      "Select allowed tools",
      "Preview:",
      "Apply these changes?",
    ]) {
      expect(final).not.toContain(label);
    }
  } finally {
    terminal.input.end();
    await rm(root, { recursive: true, force: true });
  }
});

test.each([
  [
    "Escape at Destination",
    async (terminal: ReturnType<typeof setupTty>) => {
      await press(terminal.input, "\u001B");
    },
  ],
  [
    "Ctrl-C at Destination",
    async (terminal: ReturnType<typeof setupTty>) => {
      await press(terminal.input, "\u0003");
    },
  ],
  [
    "EOF at Destination",
    async (terminal: ReturnType<typeof setupTty>) => {
      terminal.input.end();
    },
  ],
  [
    "Escape at client connection",
    async (terminal: ReturnType<typeof setupTty>) => {
      await choose(terminal, 16, "\u001B[B", " ", "\r");
      await choose(terminal, 17, "\u001B");
    },
  ],
  [
    "Escape at HTTP gateway port",
    async (terminal: ReturnType<typeof setupTty>) => {
      await choose(terminal, 16, "\u001B[B", " ", "\r");
      await choose(terminal, 17, "\u001B[B", "\r");
      await choose(terminal, 18, "\u001B");
    },
  ],
  [
    "Escape at destination policy",
    async (terminal: ReturnType<typeof setupTty>) => {
      await choose(terminal, 16, "\u001B[B", " ", "\r");
      await choose(terminal, 17, "\r");
      await choose(terminal, 18, "\u001B");
    },
  ],
  [
    "Escape at Connect",
    async (terminal: ReturnType<typeof setupTty>) => {
      await choose(terminal, 16, "\u001B[B", " ", "\r");
      await choose(terminal, 17, "\r");
      await choose(terminal, 18, "\r");
      await choose(terminal, 19, "\u001B");
    },
  ],
  [
    "Escape at Tools",
    async (terminal: ReturnType<typeof setupTty>) => {
      await choose(terminal, 16, "\u001B[B", " ", "\r");
      await choose(terminal, 17, "\r");
      await choose(terminal, 18, "\r");
      await choose(terminal, 19, "\r");
      await choose(terminal, 20, "\u001B");
    },
  ],
  [
    "declined Apply",
    async (terminal: ReturnType<typeof setupTty>) => {
      await choose(terminal, 16, "\u001B[B", " ", "\r");
      await choose(terminal, 17, "\r");
      await choose(terminal, 18, "\r");
      await choose(terminal, 19, "\r");
      await choose(terminal, 20, " ", "\r");
      await choose(terminal, 21, "\r");
      await choose(terminal, 22, "\u001B[B", "\r");
    },
  ],
] as const)("leaves every file unchanged after Manual %s", async (_case, cancel) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-manual-cancel-")));
  const home = join(root, "home");
  const configPath = join(root, ".mcp.json");
  await writeFile(configPath, '{"mcpServers": {}}\n');
  const restrictor = await writeNodeLauncher(root, cli);
  const manualUpstream = await writeFixedManualUpstream(root);
  const before = await snapshotTree(root, { exact: true });
  const logical = await snapshotTree(root);
  expect(logical).not.toEqual(
    expect.arrayContaining([expect.stringMatching(/^directory \. mode=/)]),
  );
  expect(before).toEqual(
    expect.arrayContaining([
      expect.stringMatching(
        /^directory \. mode=\d+ size=\d+ mtimeMs=\d+(?:\.\d+)? dev=\d+ ino=\d+ bytes=$/,
      ),
      expect.stringMatching(
        /^file .+ mode=\d+ size=\d+ mtimeMs=\d+(?:\.\d+)? dev=\d+ ino=\d+ bytes=.+$/,
      ),
    ]),
  );
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH, API_KEY: "secret" },
      adapters: [claudeAdapter],
      restrictor: { command: restrictor, argsPrefix: [] },
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\u001B[B", "\r");
    await enterManualStdio(terminal, 3, manualUpstream);
    await terminal.waitForSelection(16);
    await new Promise<void>((resolve) => setImmediate(resolve));
    await cancel(terminal);
    await setup;

    expect(await snapshotTree(root, { exact: true })).toEqual(before);
    expect(primaryOutput(terminal.raw())).toBe("Setup cancelled.\n");
  } finally {
    terminal.input.end();
    await rm(root, { recursive: true, force: true });
  }
});

test("Enter keeps Current before any Connect screen and replays only the result", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-current-")));
  const configPath = join(root, ".codex", "config.toml");
  const policyPath = join(root, ".mcp-restrictor", "policies", "codex", "files.yaml");
  await mkdir(dirname(configPath), { recursive: true });
  await mkdir(dirname(policyPath), { recursive: true });
  await writeFile(
    configPath,
    `[mcp_servers.files]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(policyPath)}, "--", "node", "files.mjs"]\n`,
  );
  await writeFile(policyPath, "version: 1\ndefault: deny\ntools:\n  allow: []\n  deny: []\n");
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home: join(root, "home"),
      environment: { PATH: process.env.PATH },
      adapters: [codexAdapter],
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\r");
    await choose(terminal, 3, "\r");
    await terminal.waitForSelection(4);
    expect(alternateOutput(terminal.raw())).toContain("Select Tools & Policy");
    expect(alternateOutput(terminal.raw())).toContain("Current");
    await new Promise<void>((resolve) => setImmediate(resolve));
    await press(terminal.input, "\r");
    await setup;

    const raw = terminal.raw();
    expect(raw).not.toContain("Connect to this upstream?");
    expect(primaryOutput(raw)).toBe("No changes selected.\n");
    expect(primaryOutput(raw)).not.toContain("Actions:");
    expect(primaryOutput(raw)).not.toContain("Select Tools & Policy");
  } finally {
    terminal.input.end();
    await rm(root, { recursive: true, force: true });
  }
});

test("replays only a successful Restore result after raw-TTY setup", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mcp-restrictor-tui-restore-")));
  const home = join(root, "home");
  const configPath = join(root, ".codex", "config.toml");
  const policyPath = join(root, ".mcp-restrictor", "policies", "codex", "files.yaml");
  const policySource = "allow:\n  - read_file\n";
  const originalSource = `[mcp_servers.files]\ncommand = "node"\nargs = ["files.mjs"]\n`;
  const installedSource = `[mcp_servers.files]\ncommand = "mcp-restrictor"\nargs = ["--policy", ${JSON.stringify(policyPath)}, "--", "node", "files.mjs"]\n`;
  await mkdir(dirname(configPath), { recursive: true });
  await writeFile(configPath, installedSource);
  await mkdir(dirname(policyPath), { recursive: true, mode: 0o700 });
  await chmod(dirname(policyPath), 0o700);
  await writeFile(policyPath, policySource, { mode: 0o600 });
  await chmod(policyPath, 0o600);
  const statePath = restoreStatePath(home, configPath);
  await mkdir(dirname(statePath), { recursive: true, mode: 0o700 });
  await chmod(dirname(statePath), 0o700);
  await writeFile(
    statePath,
    serializeRestoreState({
      version: 1,
      adapterId: "codex",
      configPath: resolve(configPath),
      servers: [
        {
          name: "files",
          scope: "project",
          projectRoot: resolve(root),
          originalSource,
          installedSource,
          policy: {
            path: policyPath,
            before: null,
            installed: policyFingerprint(policySource, 0o600),
          },
        },
      ],
    }),
    { mode: 0o600 },
  );
  await chmod(statePath, 0o600);
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      cwd: root,
      home,
      environment: { PATH: process.env.PATH },
      adapters: [codexAdapter],
    });
    await choose(terminal, 1, "\u001B[B", "\r");
    await choose(terminal, 2, "\r");
    await choose(terminal, 3, "\r");
    await setup;

    const raw = terminal.raw();
    expect(occurrences(raw, ENTER_ALTERNATE_SCREEN)).toBe(1);
    expect(occurrences(raw, EXIT_ALTERNATE_SCREEN)).toBe(1);
    expect(alternateOutput(raw)).toContain("Actions:");
    expect(alternateOutput(raw)).toContain("Managed MCP servers:");
    expect(alternateOutput(raw)).toContain("Restore plan:");
    expect(primaryOutput(raw)).toContain(`Restored: ${JSON.stringify(configPath)}\n`);
    expect(primaryOutput(raw)).not.toContain("Actions:");
    expect(primaryOutput(raw)).not.toContain("Managed MCP servers:");
    expect(primaryOutput(raw)).not.toContain("Restore plan:");
  } finally {
    terminal.input.end();
    await rm(root, { recursive: true, force: true });
  }
});

test("replays only outer action-menu cancellation after raw-TTY setup", async () => {
  const terminal = setupTty();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
    });
    await choose(terminal, 1, "\u001B");
    await setup;

    const raw = terminal.raw();
    expect(occurrences(raw, EXIT_ALTERNATE_SCREEN)).toBe(1);
    expect(alternateOutput(raw)).toContain("Actions:");
    expect(primaryOutput(raw)).toBe("Setup cancelled.\n");
  } finally {
    terminal.input.end();
  }
});

test("exits raw-TTY setup without replaying a thrown-error screen", async () => {
  const terminal = setupTty();
  const brokenAdapter = defineClientAdapter({
    apiVersion: 1,
    id: "broken",
    label: "Broken",
    load: async () => {
      throw new Error("adapter failure");
    },
    render: (config) => config.source,
  });

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      adapters: [brokenAdapter],
    });
    await choose(terminal, 1, "\r");
    await choose(terminal, 2, "\r");
    await expect(setup).rejects.toThrow("Failed to load client configuration");

    const raw = terminal.raw();
    expect(occurrences(raw, EXIT_ALTERNATE_SCREEN)).toBe(1);
    expect(alternateOutput(raw)).toContain("Actions:");
    expect(alternateOutput(raw)).toContain("Clients:");
    expect(primaryOutput(raw)).toBe("");
  } finally {
    terminal.input.end();
  }
});

test.each([
  ["EOF", (terminal: ReturnType<typeof setupTty>) => terminal.input.end()],
  [
    "external abort",
    (terminal: ReturnType<typeof setupTty>, controller: AbortController) => controller.abort(),
  ],
] as const)("restores the primary screen on raw-TTY %s", async (_name, stop) => {
  const terminal = setupTty();
  const controller = new AbortController();

  try {
    const setup = runSetupCommand({
      input: terminal.input,
      output: terminal.output,
      error: terminal.output,
      signal: controller.signal,
    });
    await terminal.waitForSelection(1);
    stop(terminal, controller);
    await setup;

    const raw = terminal.raw();
    expect(occurrences(raw, EXIT_ALTERNATE_SCREEN)).toBe(1);
    expect(primaryOutput(raw)).toBe("Setup cancelled.\n");
  } finally {
    terminal.input.end();
  }
});

test("replays one final block when close(true) is repeated", () => {
  const input = Object.assign(new PassThrough(), {
    isTTY: true as const,
    isRaw: false,
    setRawMode(mode: boolean) {
      this.isRaw = mode;
      return this;
    },
    unref() {
      return this;
    },
  });
  const chunks: Buffer[] = [];
  const output = Object.assign(
    new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(Buffer.from(chunk));
        callback();
      },
    }),
    { isTTY: true as const, columns: 80, rows: 24 },
  );
  const interaction = new SetupInteraction({ input, output, error: output });

  interaction.write("Preview\n");
  interaction.close(true);
  interaction.close(true);
  input.end();

  const raw = Buffer.concat(chunks).toString("utf8");
  expect(occurrences(raw, ENTER_ALTERNATE_SCREEN)).toBe(1);
  expect(occurrences(raw, EXIT_ALTERNATE_SCREEN)).toBe(1);
  expect(primaryOutput(raw)).toBe("Preview\n");
});

test.each(["\u001B", "\u0003"])("cancels an Ink confirmation on %j", async (key) => {
  const input = Object.assign(new PassThrough(), {
    isTTY: true as const,
    isRaw: false,
    setRawMode(mode: boolean) {
      this.isRaw = mode;
      return this;
    },
    ref() {
      return this;
    },
    unref() {
      return this;
    },
  });
  const chunks: Buffer[] = [];
  const output = Object.assign(
    new Writable({
      write(chunk, _encoding, callback) {
        chunks.push(Buffer.from(chunk));
        callback();
      },
    }),
    { isTTY: true as const, columns: 80, rows: 24 },
  );
  const interaction = new SetupInteraction({ input, output, error: output });

  try {
    const confirmation = interaction.confirm("Connect to this upstream?");
    await vi.waitFor(() => expect(input.isRaw).toBe(true));
    input.write(key);
    await expect(confirmation).rejects.toBeInstanceOf(SetupCancelled);
  } finally {
    interaction.close();
    input.end();
  }
  expect(occurrences(Buffer.concat(chunks).toString("utf8"), EXIT_ALTERNATE_SCREEN)).toBe(1);
});
