import { homedir } from "node:os";
import { join, resolve } from "node:path";
import type { ClientAdapter } from "../../client-adapter.js";
import { RESTRICTOR_HOME_DIRECTORY } from "../../utils/paths.js";
import { createAdapterLoader, type LoadedConfig } from "../adapter-boundary.js";
import { builtInAdapters, createAdapterRegistry } from "../adapters.js";
import { isAbort } from "../discovery.js";
import { SetupCancelled, SetupInteraction } from "../interaction.js";
import {
  compareCandidates,
  displayServerName,
  escapeControls,
  quoted,
  terminalSafeError,
} from "../presentation.js";
import { resolveProjectRoot } from "../system.js";
import { applyFileTransaction } from "../transaction.js";
import { generatedPresetKind, generatedPresetLabel } from "../generated.js";
import { loadRestoreChoices, planSelectedRestore } from "./planning.js";
import { withRestoreStateLock } from "./state.js";

export type RestoreOptions = {
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  error?: NodeJS.WritableStream;
  interactive?: boolean;
  cwd?: string;
  home?: string;
  environment?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  adapters?: readonly ClientAdapter[];
  unavailableAdapters?: readonly { packageName: string; reason: string }[];
};

export type RestoreContextOptions = Omit<
  RestoreOptions,
  "input" | "output" | "error" | "interactive" | "signal"
>;

export async function runRestore(options: RestoreOptions = {}): Promise<void> {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const interactive =
    options.interactive ??
    Boolean(
      (input as NodeJS.ReadableStream & { isTTY?: boolean }).isTTY &&
      (output as NodeJS.WritableStream & { isTTY?: boolean }).isTTY,
    );
  if (!interactive) throw new Error("restore requires an interactive terminal");

  const interaction = new SetupInteraction({
    input,
    output,
    error: options.error ?? process.stderr,
    ...(options.signal ? { signal: options.signal } : {}),
  });
  let replayCurrentScreen = false;
  try {
    await runRestoreWithInteraction(options, interaction);
    replayCurrentScreen = true;
  } finally {
    interaction.close(replayCurrentScreen);
  }
}

export async function runRestoreWithInteraction(
  options: RestoreContextOptions,
  interaction: SetupInteraction,
): Promise<void> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const home = resolve(options.home ?? homedir());
  const environment = options.environment ?? process.env;
  const { confirm, selectIndexes, signal, usesTui, write } = interaction;

  try {
    const projectRoot = await resolveProjectRoot(cwd, { PATH: environment.PATH });
    const adapters = options.adapters
      ? createAdapterRegistry(options.adapters).available
      : builtInAdapters;
    const loader = createAdapterLoader({ includeManagedRoutes: true });
    const loaded: LoadedConfig[] = [];
    const context = { home, projectRoot, cwd, environment };
    const labelsByClient = new Map(adapters.map((adapter) => [adapter.id, adapter.label]));
    for (const adapter of adapters) {
      loaded.push(...(await loader.load(adapter, context)).configurations);
    }
    const restored = await loadRestoreChoices({ ...context, loaded });
    const choices = restored.choices.sort((left, right) => compareCandidates(left, right));
    const labels = choices.map(
      ({ adapter, server }) =>
        `${escapeControls(adapter.label)} / ${escapeControls(displayServerName(server.name))} (${server.scope}, ${quoted(escapeControls(server.configPath))})`,
    );

    write("Managed MCP servers:\n");
    if (!usesTui) labels.forEach((label, index) => write(`${index + 1}. ${label}\n`));
    if (restored.unavailable.length || options.unavailableAdapters?.length) {
      write("Unavailable MCP restore targets:\n");
      for (const server of restored.unavailable) {
        write(
          `- ${escapeControls(labelsByClient.get(server.client) ?? server.client)} / ${escapeControls(displayServerName(server.name))} (${server.scope}, ${quoted(escapeControls(server.configPath))}): ${escapeControls(server.reason)}\n`,
        );
      }
      for (const adapter of options.unavailableAdapters ?? []) {
        write(`- ${escapeControls(adapter.packageName)}: ${escapeControls(adapter.reason)}\n`);
      }
    }
    if (!choices.length) {
      write("No managed MCP servers can be restored.\n");
      return;
    }

    const selectedIndexes = await selectIndexes("Select servers to restore: ", labels, {
      allowNone: true,
      tuiRequired: true,
    });
    if (!selectedIndexes.length) throw new SetupCancelled();
    const selected = selectedIndexes.map((index) => choices[index]!);

    write("Restore plan:\n");
    for (const { adapter, server } of selected) {
      write(
        `- ${escapeControls(adapter.label)} / ${escapeControls(displayServerName(server.name))} config=${quoted(escapeControls(server.configPath))}\n`,
      );
    }
    if (!(await confirm("Restore selected MCP servers?"))) {
      throw new SetupCancelled();
    }

    const plan = await withRestoreStateLock(
      home,
      async () => {
        const planned = await planSelectedRestore({
          home,
          projectRoot,
          environment,
          choices: selected,
        });
        await applyFileTransaction(planned.changes, {
          backupRoot: join(home, RESTRICTOR_HOME_DIRECTORY, "backups"),
          verify: planned.verify,
          signal,
        });
        return planned;
      },
      signal,
    );

    for (const path of new Set(selected.map(({ server }) => resolve(server.configPath)))) {
      write(`Restored: ${quoted(escapeControls(path))}\n`);
    }
    for (const warning of plan.warnings) write(`Warning: ${escapeControls(warning)}\n`);
    for (const { adapter, server } of selected) {
      const generated = generatedPresetKind(home, adapter.id, server.configPath);
      if (!generated) continue;
      write(
        `Warning: Remove ${quoted(escapeControls(server.name))} from the host ${generatedPresetLabel(generated)} configuration if you pasted its generated fragment.\n`,
      );
    }
  } catch (error) {
    if (error instanceof SetupCancelled || isAbort(error, signal)) {
      write("Restore cancelled.\n");
      return;
    }
    throw terminalSafeError(error);
  }
}
