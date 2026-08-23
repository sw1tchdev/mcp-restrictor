import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { createPolicyAuthorizer } from "@mcp-restrictor/policy";
import type { UpstreamConfig } from "@mcp-restrictor/transports";
import { loginOAuthProfile } from "../oauth/login.js";
import {
  readOAuthProfileSnapshot,
  type OAuthProfile,
  type OAuthStorageOptions,
} from "../oauth/storage.js";
import { type ClientAdapter, type ClientResolutionDependency } from "../client-adapter.js";
import { RESTRICTOR_HOME_DIRECTORY } from "../utils/paths.js";
import { builtInAdapters, createAdapterRegistry } from "./adapters.js";
import { DEFAULT_RESTRICTOR_COMMAND } from "./constants.js";
import {
  createAdapterLoader,
  type LoadedConfig,
  recheckDependencies,
  resolveAdapterCandidate,
} from "./adapter-boundary.js";
import { discoverSetupServer, isAbort, type PreparedServer } from "./discovery.js";
import { SetupCancelled, SetupInteraction } from "./interaction.js";
import { runManualSetup } from "./manual.js";
import { applyFileTransaction } from "./transaction.js";
import {
  compareCandidates,
  compareUnsupported,
  displayServerName,
  escapeControls,
  previewEndpoint,
  quoted,
  renderSetupCompletion,
  terminalSafeError,
} from "./presentation.js";
import { planProfileWrites, planWrites } from "./planning.js";
import { planSetupRestoreStateChanges } from "./restore/planning.js";
import { runRestoreWithInteraction } from "./restore/index.js";
import { withRestoreStateLock } from "./restore/state.js";
import { readSetupSnapshot, setupTargetExists } from "./snapshot.js";
import {
  choosePolicySource,
  planOptionalSavedPolicy,
  recheckPolicySource,
  type PolicySourceChoice,
} from "./saved-policies.js";
import { requireExecutable, resolveProjectRoot } from "./system.js";
import type { FileSnapshot, PlannedWrite } from "./transaction.js";
import { verifySelections } from "./verification.js";
import {
  planManagedWrapper,
  policyLocation,
  type Replacement,
  type RestrictorCommand,
  type ServerCandidate,
  type UnsupportedServer,
} from "./wrapper.js";

export type SetupOptions = {
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  error?: NodeJS.WritableStream;
  interactive?: boolean;
  cwd?: string;
  home?: string;
  environment?: NodeJS.ProcessEnv;
  restrictor?: RestrictorCommand;
  signal?: AbortSignal;
  readSecret?: (question: string) => Promise<string>;
  adapters?: readonly ClientAdapter[];
  unavailableAdapters?: readonly { packageName: string; reason: string }[];
};

type Selection = {
  adapter: ClientAdapter;
  server: ServerCandidate;
  dependencies: readonly ClientResolutionDependency[];
  tools: string[];
  policy: { diskPath: string; argument: string };
  replacement: Replacement;
  policySource: string;
  policyBaseline: FileSnapshot | null;
  unownedPolicyBaseline?: FileSnapshot;
  savedPolicyChoice: PolicySourceChoice;
  savedPolicyWrite?: PlannedWrite;
  verificationUpstream: UpstreamConfig;
  oauthProfile?: OAuthProfile;
  oauthBaseline?: Awaited<ReturnType<typeof readOAuthProfileSnapshot>>;
  storage?: OAuthStorageOptions;
  backupKey: string;
  context: string;
};

type UnsupportedEntry = { adapter: ClientAdapter; server: UnsupportedServer };

const ACTIONS = ["Add MCP", "Restore MCP"] as const;
export async function runSetup(options: SetupOptions = {}): Promise<void> {
  const interaction = createSetupInteraction(options);
  let replayCurrentScreen = false;
  try {
    await runAddSetupWithInteraction(options, interaction);
    replayCurrentScreen = true;
  } finally {
    interaction.close(replayCurrentScreen);
  }
}

export async function runSetupCommand(options: SetupOptions = {}): Promise<void> {
  const interaction = createSetupInteraction(options);
  const { selectIndexes, usesTui, write } = interaction;
  let replayCurrentScreen = false;
  try {
    write(
      `Actions:\n${usesTui ? "" : ACTIONS.map((action, index) => `${index + 1}. ${action}\n`).join("")}`,
    );
    const [action] = await selectIndexes("Select action: ", ACTIONS, {
      allowNone: false,
      single: true,
    });
    if (action === 1) await runRestoreWithInteraction(options, interaction);
    else await runAddSetupWithInteraction(options, interaction);
    replayCurrentScreen = true;
  } catch (error) {
    if (error instanceof SetupCancelled || isAbort(error, interaction.signal)) {
      write("Setup cancelled.\n");
      replayCurrentScreen = true;
      return;
    }
    throw error;
  } finally {
    interaction.close(replayCurrentScreen);
  }
}

function createSetupInteraction(options: SetupOptions): SetupInteraction {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const interactive =
    options.interactive ??
    Boolean(
      (input as NodeJS.ReadableStream & { isTTY?: boolean }).isTTY &&
      (output as NodeJS.WritableStream & { isTTY?: boolean }).isTTY,
    );
  if (!interactive) throw new Error("setup requires an interactive terminal");

  return new SetupInteraction({
    input,
    output,
    error: options.error ?? process.stderr,
    ...(options.signal ? { signal: options.signal } : {}),
    ...(options.readSecret ? { readSecret: options.readSecret } : {}),
  });
}

async function runAddSetupWithInteraction(
  options: SetupOptions,
  interaction: SetupInteraction,
): Promise<void> {
  const cwd = resolve(options.cwd ?? process.cwd());
  const home = resolve(options.home ?? homedir());
  const environment = options.environment ?? process.env;
  const restrictor = options.restrictor ?? {
    command: DEFAULT_RESTRICTOR_COMMAND,
    argsPrefix: [],
  };
  const adapters = options.adapters
    ? createAdapterRegistry(options.adapters).available
    : builtInAdapters;
  const {
    confirm,
    readSecret,
    selectIndexes,
    signal,
    stderr: suppressedStderr,
    usesTui,
    write,
  } = interaction;

  try {
    const clientChoices = [
      ...adapters.map((adapter) => escapeControls(adapter.label)),
      "Manual upstream",
    ];
    write(
      `Clients:\n${usesTui ? "" : clientChoices.map((label, index) => `${index + 1}. ${label}\n`).join("")}`,
    );
    if (options.unavailableAdapters?.length) {
      write("Unavailable client adapters:\n");
      for (const { packageName, reason } of options.unavailableAdapters) {
        write(`- ${escapeControls(packageName)}: ${escapeControls(reason)}\n`);
      }
    }
    let clientIndexes: number[];
    for (;;) {
      clientIndexes = await selectIndexes("Select clients: ", clientChoices, {
        allowNone: false,
        allSize: adapters.length,
        exclusiveIndex: adapters.length,
        rejectDuplicates: true,
      });
      if (clientIndexes.includes(adapters.length) && clientIndexes.length !== 1) {
        write("Manual upstream must be selected by itself.\n");
        continue;
      }
      break;
    }
    if (clientIndexes[0] === adapters.length) {
      const projectRoot = await resolveProjectRoot(cwd, { PATH: environment.PATH });
      write(`Project root: ${quoted(projectRoot)}\n`);
      await runManualSetup({
        interaction,
        projectRoot,
        cwd,
        home,
        environment,
        restrictor,
        restrictorHome: join(home, RESTRICTOR_HOME_DIRECTORY),
        adapters,
      });
      return;
    }
    const projectRoot = await resolveProjectRoot(cwd, { PATH: environment.PATH });
    write(`Project root: ${quoted(projectRoot)}\n`);
    const selectedAdapters = clientIndexes.map((index) => adapters[index]!);
    const loader = createAdapterLoader();
    const loaded: LoadedConfig[] = [];
    const adapterUnsupported: UnsupportedEntry[] = [];
    const loadContext = {
      home,
      projectRoot,
      cwd,
      environment,
    };
    for (const adapter of selectedAdapters) {
      const result = await loader.load(adapter, loadContext);
      loaded.push(...result.configurations);
      adapterUnsupported.push(...result.unsupported.map((server) => ({ adapter, server })));
    }
    const candidates = loaded
      .flatMap(({ adapter, config }) => config.servers.map((server) => ({ adapter, server })))
      .sort(compareCandidates);
    const unsupported = [
      ...adapterUnsupported,
      ...loaded.flatMap(({ adapter, config }) =>
        config.unsupported.map((server) => ({ adapter, server })),
      ),
    ].sort(compareUnsupported);

    const candidateChoices = candidates.map(
      ({ adapter, server }) =>
        `${escapeControls(adapter.label)} / ${displayServerName(server.name)} (${server.scope}, ${server.source.kind}, ${quoted(server.configPath)})`,
    );
    write("Supported MCP servers:\n");
    if (!usesTui) {
      candidateChoices.forEach((label, index) => write(`${index + 1}. ${label}\n`));
    }
    if (unsupported.length) {
      write("Unsupported MCP servers:\n");
      for (const { adapter, server } of unsupported) {
        write(
          `- ${escapeControls(adapter.label)} / ${displayServerName(server.name)} (${server.scope}, ${quoted(server.configPath)}): ${quoted(server.reason)}\n`,
        );
      }
    }
    if (!candidates.length) {
      write("No supported MCP servers found.\n");
      return;
    }

    const selectedIndexes = await selectIndexes("Select servers: ", candidateChoices, {
      allowNone: true,
      tuiRequired: true,
    });
    if (!selectedIndexes.length) throw new SetupCancelled();

    const selections: Selection[] = [];
    let pinnedRestrictor: RestrictorCommand | undefined;
    const restrictorHome = join(home, RESTRICTOR_HOME_DIRECTORY);
    for (const index of selectedIndexes) {
      const { adapter, server } = candidates[index]!;
      const policy = policyLocation({
        client: adapter.id,
        scope: server.scope,
        serverName: server.name,
        projectRoot,
        restrictorHome,
      });
      const targetExisted = await setupTargetExists(policy.diskPath, "policy");
      const managedTarget =
        server.managedPolicyPath !== undefined &&
        resolve(server.managedPolicyPath) === resolve(policy.diskPath);
      const context = {
        client: adapter.id,
        scope: server.scope,
        serverName: server.name,
        projectRoot,
        restrictorHome,
      };
      let target: FileSnapshot | undefined;
      let policyChoice: PolicySourceChoice;
      if (targetExisted && !managedTarget) {
        target = await readSetupSnapshot(policy.diskPath, "policy");
        if (!target) throw new Error("Existing policy changed during setup; rerun setup");
        policyChoice = await choosePolicySource({
          interaction,
          context,
          hasCurrent: false,
          existingPolicy: target,
        });
      } else {
        policyChoice = await choosePolicySource({
          interaction,
          context,
          hasCurrent: targetExisted && managedTarget,
        });
        if (policyChoice.kind === "current") continue;
        target = await readSetupSnapshot(policy.diskPath, "policy");
        if (targetExisted !== Boolean(target)) {
          throw new Error(
            managedTarget
              ? "Managed policy changed during setup; rerun setup"
              : "Existing policy changed during setup; rerun setup",
          );
        }
      }
      const unownedPolicyBaseline = target && !managedTarget ? target : undefined;
      previewEndpoint(server, write);
      if (!(await confirm("Connect to this upstream?"))) {
        throw new SetupCancelled();
      }
      const resolved = await resolveAdapterCandidate(adapter, server, loadContext, loader.host);
      const dependencies = loader.acceptDependencies(resolved.dependencies);
      const resolvedServer = resolved.candidate;
      const prepared = await discoverSetupServer(
        {
          ...resolvedServer,
          context: serverContext(resolvedServer),
        },
        {
          home,
          environment,
          signal,
          stderr: suppressedStderr,
          login: loginOAuthProfile,
          usesTui,
          readSecret,
          selectIndexes,
          confirm,
          write,
        },
      );
      const tools = prepared.tools;
      const frozenServer = freezeSuccessfulServer(resolvedServer, prepared);
      let allowedTools: string[];
      if (policyChoice.kind === "policy") {
        const authorizer = createPolicyAuthorizer(policyChoice.policy);
        allowedTools = tools.filter((name) => authorizer.discover(name));
      } else {
        write(
          `Tools for ${escapeControls(adapter.label)} / ${displayServerName(resolvedServer.name)} (${resolvedServer.scope}):\n`,
        );
        const toolChoices = tools.map(quoted);
        if (!usesTui) {
          toolChoices.forEach((name, toolIndex) => write(`${toolIndex + 1}. ${name}\n`));
        }
        const toolIndexes = await selectIndexes("Select allowed tools: ", toolChoices, {
          allowNone: true,
        });
        allowedTools = toolIndexes.map((toolIndex) => tools[toolIndex]!);
      }
      pinnedRestrictor ??= {
        ...restrictor,
        command: await requireExecutable(restrictor.command, cwd, environment),
      };
      const projectWrapper =
        resolvedServer.scope === "project"
          ? adapter.projectWrapper?.({
              projectRoot,
              relativePolicyPath: policy.relativePath,
              diskPolicyPath: policy.diskPath,
            })
          : undefined;
      const generated = planManagedWrapper({
        server: frozenServer,
        allowedTools,
        policy: projectWrapper ? { ...policy, argument: projectWrapper.policyArgument } : policy,
        restrictor: pinnedRestrictor,
        verificationEnvironment: environment,
        ...(projectWrapper?.cwd !== undefined ? { wrapperCwd: projectWrapper.cwd } : {}),
      });
      const planned =
        policyChoice.kind === "policy"
          ? { ...generated, policySource: policyChoice.source }
          : generated;
      const savedPolicyWrite =
        policyChoice.kind === "configure"
          ? await planOptionalSavedPolicy({
              interaction,
              context: {
                client: adapter.id,
                scope: resolvedServer.scope,
                serverName: resolvedServer.name,
                projectRoot,
                restrictorHome,
              },
              policySource: planned.policySource,
              backupKey: resolve(resolvedServer.configPath),
            })
          : undefined;
      selections.push({
        adapter,
        server: frozenServer,
        dependencies,
        tools: allowedTools,
        policy,
        ...planned,
        policyBaseline: target ?? null,
        ...(unownedPolicyBaseline ? { unownedPolicyBaseline } : {}),
        savedPolicyChoice: policyChoice,
        ...(savedPolicyWrite ? { savedPolicyWrite } : {}),
        ...(prepared.oauthProfile ? { oauthProfile: prepared.oauthProfile } : {}),
        ...(prepared.oauthBaseline ? { oauthBaseline: prepared.oauthBaseline } : {}),
        ...(prepared.storage ? { storage: prepared.storage } : {}),
        backupKey: resolve(resolvedServer.configPath),
        context: serverContext(resolvedServer),
      });
    }

    if (!selections.length) {
      write("No changes selected.\n");
      return;
    }

    await planWrites(loaded, selections);

    write("Preview:\n");
    for (const selection of selections) {
      write(
        `- ${escapeControls(selection.adapter.label)} / ${displayServerName(selection.server.name)} ${selection.server.scope} transport=${selection.server.source.kind} config=${quoted(selection.server.configPath)} policy=${quoted(selection.policy.diskPath)} tools=${JSON.stringify(selection.tools)}\n`,
      );
    }
    write("Warning: do not edit the client configuration during the write window.\n");
    if (!(await confirm("Apply these changes?"))) {
      throw new SetupCancelled();
    }

    const { result, visibleWrites, writes } = await withRestoreStateLock(
      home,
      async () => {
        await Promise.all(
          selections.map(({ savedPolicyChoice }) => recheckPolicySource(savedPolicyChoice)),
        );
        const clientWrites = await planWrites(loaded, selections);
        const profileWrites = await planProfileWrites(selections);
        const savedPolicyWrites = selections.flatMap(({ savedPolicyWrite }) =>
          savedPolicyWrite ? [savedPolicyWrite] : [],
        );
        const policyPaths = new Set(selections.map(({ policy }) => resolve(policy.diskPath)));
        const configPaths = new Set(selections.map(({ server }) => resolve(server.configPath)));
        const policyWrites = clientWrites.filter(({ path }) => policyPaths.has(resolve(path)));
        const configWrites = clientWrites.filter(({ path }) => configPaths.has(resolve(path)));
        if (policyWrites.length + configWrites.length !== clientWrites.length) {
          throw new Error("Invalid setup write plan");
        }
        const stateWrites = await planSetupRestoreStateChanges({
          home,
          projectRoot,
          environment,
          loaded,
          selections: selections.map(
            ({ adapter, server, policy, policySource, unownedPolicyBaseline, oauthProfile }) => ({
              adapter,
              server,
              policy,
              policySource,
              ...(unownedPolicyBaseline ? { unownedPolicyBaseline } : {}),
              ...(oauthProfile ? { oauthProfileId: oauthProfile.metadata.profileId } : {}),
            }),
          ),
          clientWrites,
        });
        const visibleWrites = [...savedPolicyWrites, ...profileWrites, ...clientWrites];
        const writes = [
          ...savedPolicyWrites,
          ...profileWrites,
          ...policyWrites,
          ...stateWrites,
          ...configWrites,
        ];
        await recheckDependencies(
          selections.flatMap(({ dependencies }) => dependencies),
          environment,
        );
        const result = await applyFileTransaction(writes, {
          backupRoot: join(restrictorHome, "backups"),
          verify: async (acceptInstalledUpdate) => {
            await verifySelections(selections, acceptInstalledUpdate, signal, suppressedStderr);
          },
          signal,
        });
        return { result, visibleWrites, writes };
      },
      signal,
    );

    renderSetupCompletion({
      write,
      visibleWrites,
      writes,
      backupDirectories: result.backupDirectories,
      adapters: selectedAdapters,
      projectRoot,
    });
  } catch (error) {
    if (error instanceof SetupCancelled || isAbort(error, signal)) {
      write("Setup cancelled.\n");
      return;
    }
    throw terminalSafeError(error);
  }
}

function freezeSuccessfulServer(
  server: ServerCandidate,
  prepared: Pick<PreparedServer, "source" | "upstream">,
): ServerCandidate {
  const { alternatives: _alternatives, ...candidate } = server;
  return { ...candidate, source: prepared.source, upstream: prepared.upstream };
}

function serverContext(server: ServerCandidate): string {
  return `${server.client} ${server.scope} server ${quoted(server.name)} in ${quoted(server.configPath)}`;
}
