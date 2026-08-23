import { homedir } from "node:os";
import { createInterface } from "node:readline/promises";
import type { Readable, Writable } from "node:stream";
import { ConfirmationCancelled, confirmTerminal } from "../confirmation.js";
import {
  installClientAdapter,
  listClientAdapters,
  loadInstalledClientAdapters,
  removeClientAdapter,
  withInstalledClientAdapters,
  type ClientAdapterListEntry,
} from "../client-plugins.js";
import { abortable, TERMINATION_SIGNALS } from "../utils/async.js";
import { escapeControls } from "../utils/terminal.js";

export type ClientPluginOperations = {
  install: typeof installClientAdapter;
  list: typeof listClientAdapters;
  load: typeof loadInstalledClientAdapters;
  remove: typeof removeClientAdapter;
  withLoaded?: typeof withInstalledClientAdapters;
};

export const defaultClientPlugins: ClientPluginOperations = {
  install: installClientAdapter,
  list: listClientAdapters,
  load: loadInstalledClientAdapters,
  remove: removeClientAdapter,
  withLoaded: withInstalledClientAdapters,
};

export async function runClientCommand(
  argv: readonly string[],
  options: {
    signal?: AbortSignal;
    home?: string;
    environment?: NodeJS.ProcessEnv;
    clientPlugins?: ClientPluginOperations;
  },
  input: Readable,
  output: Writable,
): Promise<void> {
  const command = argv[3];
  if (command === "install") {
    if (argv.length !== 5) throw new Error("Usage: mcp-restrictor client install NPM_SPEC");
    await confirmTrustedInstall(input, output, options.signal);
    const result = await runClientPluginOperation(async () => {
      const clientPlugins = options.clientPlugins ?? defaultClientPlugins;
      return clientPlugins.install(argv[4]!, {
        home: options.home ?? homedir(),
        environment: options.environment ?? process.env,
      });
    }, "Client adapter installation failed");
    output.write(
      `Installed ${terminalText(result.plugin.packageName)}@${terminalText(result.plugin.version)}.\n`,
    );
    for (const warning of result.warnings) {
      output.write(`Warning: ${terminalText(warning)}.\n`);
    }
    return;
  }
  if (command === "list") {
    if (argv.length !== 4) throw new Error("Usage: mcp-restrictor client list");
    writeClientPluginList(
      await runClientPluginOperation(async () => {
        const clientPlugins = options.clientPlugins ?? defaultClientPlugins;
        return clientPlugins.list({ home: options.home ?? homedir() });
      }, "Failed to list client adapters"),
      output,
    );
    return;
  }
  if (command === "remove") {
    if (argv.length !== 5) throw new Error("Usage: mcp-restrictor client remove PACKAGE_NAME");
    const result = await runClientPluginOperation(async () => {
      const clientPlugins = options.clientPlugins ?? defaultClientPlugins;
      return clientPlugins.remove(argv[4]!, { home: options.home ?? homedir() });
    }, "Failed to remove client adapter");
    output.write(`Removed ${terminalText(argv[4]!)}.\n`);
    for (const warning of result.warnings) {
      output.write(`Warning: ${terminalText(warning)}.\n`);
    }
    return;
  }
  throw new Error("Usage: mcp-restrictor client (install NPM_SPEC | list | remove PACKAGE_NAME)");
}

async function runClientPluginOperation<T>(
  operation: () => Promise<T>,
  publicMessage: string,
): Promise<T> {
  try {
    return await operation();
  } catch {
    throw new Error(publicMessage);
  }
}

async function confirmTrustedInstall(
  input: Readable,
  output: Writable,
  providedSignal?: AbortSignal,
): Promise<void> {
  const controller = new AbortController();
  const signal = providedSignal ?? controller.signal;
  const abort = () => controller.abort();
  if (!providedSignal) {
    for (const signal of TERMINATION_SIGNALS) process.once(signal, abort);
  }
  const readline = createInterface({ input, crlfDelay: Infinity });
  const answers = readline[Symbol.asyncIterator]();
  try {
    const confirmed = await confirmTerminal({
      message:
        "This npm package is trusted code and will run with your user permissions. npm lifecycle scripts will be disabled. Install it?",
      input,
      output,
      error: output,
      readline,
      signal,
      ask: async (question) => {
        output.write(question);
        const answer = await abortable(answers.next(), signal);
        if (answer.done) throw new ConfirmationCancelled();
        return answer.value;
      },
    });
    if (!confirmed) {
      throw new Error("Client adapter installation cancelled");
    }
  } catch (error) {
    if (error instanceof ConfirmationCancelled || signal.aborted)
      throw new Error("Client adapter installation cancelled");
    throw error;
  } finally {
    readline.close();
    if (!providedSignal) {
      for (const signal of TERMINATION_SIGNALS) process.removeListener(signal, abort);
    }
  }
}

function writeClientPluginList(entries: readonly ClientAdapterListEntry[], output: Writable): void {
  if (entries.length === 0) {
    output.write("No installed client adapters.\n");
    return;
  }
  const sorted = [...entries].sort((left, right) =>
    left.packageName < right.packageName ? -1 : Number(left.packageName > right.packageName),
  );
  for (const entry of sorted) {
    const identity = `${terminalText(entry.packageName)}${entry.version ? `@${terminalText(entry.version)}` : ""}`;
    if (entry.status === "available") {
      output.write(
        `${identity} available (id=${terminalText(entry.id)}, label=${quotedTerminalText(entry.label)})\n`,
      );
    } else {
      output.write(`${identity} unavailable (${terminalText(entry.reason)})\n`);
    }
  }
}

function terminalText(value: string): string {
  return escapeControls(value);
}

function quotedTerminalText(value: string): string {
  return escapeControls(JSON.stringify(value));
}
