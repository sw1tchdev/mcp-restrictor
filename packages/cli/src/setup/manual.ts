import { join, resolve } from "node:path";
import { createPolicyAuthorizer, stringifyPolicy } from "@mcp-restrictor/policy";
import {
  createStdioEnvironment,
  parseHeaderEnvironmentMapping,
  resolveHeaderEnvironment,
  validateRemoteUpstream,
  type UpstreamConfig,
} from "@mcp-restrictor/transports";
import { loginOAuthProfile } from "../oauth/login.js";
import { callbackUrl } from "../oauth/login/callback.js";
import { secureOAuthUrl } from "../oauth/login/discovery.js";
import { configuredMasterKeyFile, MASTER_KEY_FILE_ENV } from "../oauth/storage.js";
import { loadRoutes } from "../routes.js";
import {
  DEFAULT_OAUTH_CALLBACK_PATH,
  MAX_TCP_PORT,
  OAUTH_IPV4_LOOPBACK_HOST,
} from "../oauth/urls.js";
import { RESTRICTOR_HOME_DIRECTORY } from "../utils/paths.js";
import { asciiLower } from "../utils/values.js";
import {
  CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE,
  CONTAINER_MARKER_ENV,
  OAUTH_HEADER_MAPPING_CONFLICT_MESSAGE,
} from "./constants.js";
import { discoverSetupServer, type PreparedServer, type SetupTarget } from "./discovery.js";
import { SetupCancelled, type SetupInteraction } from "./interaction.js";
import {
  createGeneratedManualDestination,
  discoverManualDestinations,
  type ManualDestination,
} from "./manual/destinations.js";
import {
  generatedPresetConfig,
  generatedPresetLabel,
  readGeneratedFileSnapshot,
} from "./generated.js";
import { planManualDestinationHttpRoute, planManualDestinationWrapper } from "./manual/planning.js";
import { planProfileWrites } from "./planning.js";
import { escapeControls, previewEndpoint, quoted, renderSetupCompletion } from "./presentation.js";
import { assertPolicyTakeoversAllowed, planSetupRestoreStateChanges } from "./restore/planning.js";
import {
  matchesPrivateFingerprint,
  policyFingerprint,
  withRestoreStateLock,
} from "./restore/state.js";
import {
  choosePolicySource,
  planOptionalSavedPolicy,
  recheckPolicySource,
  type PolicySourceChoice,
} from "./saved-policies.js";
import { readSetupSnapshot } from "./snapshot.js";
import { requireExecutable } from "./system.js";
import { withOAuthProfile } from "./remote.js";
import {
  applyFileTransaction,
  readPrivateFileSnapshot,
  sameFileSnapshot,
  type PlannedWrite,
} from "./transaction.js";
import { verifySelection, verifySelections, type VerificationSelection } from "./verification.js";
import {
  assertNoReservedUpstreamEnvironment,
  buildVerificationEnvironment,
  buildWrapperArgs,
  hasMasterKeyHeaderMapping,
  policyFileName,
  policyLocation,
  type OAuthSetupHint,
  type RestrictorCommand,
  type ServerCandidate,
  type SourceSpec,
} from "./wrapper.js";
import type { ClientAdapter } from "../client-adapter.js";
import {
  createAdapterLoader,
  installAdapterConfig,
  installAdapterHttpConfig,
  type LoadedConfig,
} from "./adapter-boundary.js";

export type ManualCandidate = {
  name: string;
  source: SourceSpec;
  oauth?: OAuthSetupHint;
};

export async function runManualSetup(options: {
  interaction: SetupInteraction;
  projectRoot: string;
  cwd: string;
  home: string;
  environment: NodeJS.ProcessEnv;
  restrictor: RestrictorCommand;
  restrictorHome: string;
  adapters: readonly ClientAdapter[];
}): Promise<void> {
  const { interaction } = options;
  const candidate = await promptManualCandidate({ interaction });
  const destinations = await discoverManualDestinations({
    adapters: options.adapters,
    context: {
      home: options.home,
      projectRoot: options.projectRoot,
      cwd: options.cwd,
      environment: options.environment,
    },
    serverName: candidate.name,
    restrictorHome: options.restrictorHome,
  });
  const destinationChoices = [
    "Show configuration only",
    ...destinations.available.map(
      ({ adapter, config }) =>
        `${escapeControls(adapter.label)} / ${config.scope} / ${quoted(escapeControls(config.path))}`,
    ),
    ...(destinations.generated.length ? ["Generate client presets"] : []),
  ];
  const generatedIndex = destinations.generated.length ? destinationChoices.length - 1 : -1;
  interaction.write(
    `Destination:\n${interaction.usesTui ? "" : destinationChoices.map((choice, index) => `${index + 1}. ${choice}\n`).join("")}`,
  );
  if (destinations.unavailable.length) {
    interaction.write("Unavailable destinations:\n");
    for (const destination of destinations.unavailable) {
      interaction.write(
        `- ${escapeControls(destination.adapterLabel)}${destination.scope ? ` / ${destination.scope}` : ""}${destination.configPath ? ` / ${quoted(escapeControls(destination.configPath))}` : ""}: ${escapeControls(destination.reason)}\n`,
      );
    }
  }
  let selectedIndexes: number[];
  for (;;) {
    const selected = await interaction.selectIndexes("Select destination: ", destinationChoices, {
      allowNone: false,
      exclusiveIndex: 0,
      defaultIndexes: [0],
      rejectDuplicates: true,
    });
    if (selected.includes(0) && selected.length !== 1) {
      interaction.write("Show configuration only must be selected by itself.\n");
      continue;
    }
    const scopes = new Set<string>();
    const duplicateScope = selected
      .filter((index) => index > 0)
      .some((index) => {
        if (index === generatedIndex) return false;
        const destination = destinations.available[index - 1]!;
        const key = `${destination.adapter.id}\0${destination.config.scope}`;
        if (scopes.has(key)) return true;
        scopes.add(key);
        return false;
      });
    if (duplicateScope) {
      interaction.write("Select at most one destination per client and scope.\n");
      continue;
    }
    selectedIndexes = selected;
    break;
  }
  const selectedDestinations = selectedIndexes
    .filter((index) => index > 0 && index !== generatedIndex)
    .map((index) => destinations.available[index - 1]!);
  if (selectedIndexes.includes(generatedIndex)) {
    const labels = destinations.generated.map(({ adapter }) => escapeControls(adapter.label));
    interaction.write(
      `Generated client presets:\n${interaction.usesTui ? "" : labels.map((label, index) => `${index + 1}. ${label}\n`).join("")}`,
    );
    const indexes = await interaction.selectIndexes("Select generated client presets: ", labels, {
      allowNone: selectedDestinations.length > 0,
      defaultIndexes: labels.map((_label, index) => index),
      rejectDuplicates: true,
      tuiRequired: true,
    });
    const context = {
      home: options.home,
      projectRoot: options.projectRoot,
      cwd: options.cwd,
      environment: options.environment,
    };
    for (const index of indexes) {
      const choice = destinations.generated[index]!;
      let kind = choice.kinds[0]!;
      if (choice.kinds.length > 1) {
        const formats = ["Current (V2)", "Legacy (V1)"];
        interaction.write(
          `OpenCode format:\n${interaction.usesTui ? "" : formats.map((format, formatIndex) => `${formatIndex + 1}. ${format}\n`).join("")}`,
        );
        kind = choice.kinds[await selectOne(interaction, "Select OpenCode format", formats)]!;
      }
      selectedDestinations.push(
        await createGeneratedManualDestination({
          choice,
          kind,
          context,
          serverName: candidate.name,
        }),
      );
    }
  }
  if (selectedDestinations.length) {
    await runSelectedManualDestinations({
      ...options,
      candidate,
      destinations: selectedDestinations,
    });
    return;
  }
  const policy = policyLocation({
    client: "manual",
    scope: "project",
    serverName: candidate.name,
    projectRoot: options.projectRoot,
    restrictorHome: options.restrictorHome,
  });
  const policyBaseline = await readSetupSnapshot(policy.diskPath, "policy");
  const policyChoice = await choosePolicySource({
    interaction,
    context: {
      client: "manual",
      scope: "project",
      serverName: candidate.name,
      projectRoot: options.projectRoot,
      restrictorHome: options.restrictorHome,
    },
    hasCurrent: false,
    ...(policyBaseline ? { existingPolicy: policyBaseline } : {}),
  });
  const previewTarget: SetupTarget = {
    ...candidate,
    upstream: previewUpstream(candidate),
    wrapperEnvironment: {},
    context: `manual server ${quoted(candidate.name)}`,
  };
  previewEndpoint(previewTarget, interaction.write);
  if (!(await interaction.confirm("Connect to this upstream?"))) {
    throw new SetupCancelled();
  }

  const keyFile = configuredMasterKeyFile(options.environment, options.cwd);
  const storageEnvironment: NodeJS.ProcessEnv = {};
  if (keyFile) storageEnvironment[MASTER_KEY_FILE_ENV] = keyFile;
  if (Object.hasOwn(options.environment, CONTAINER_MARKER_ENV)) {
    storageEnvironment[CONTAINER_MARKER_ENV] = options.environment[CONTAINER_MARKER_ENV];
  }
  const upstream = resolveManualUpstream(candidate, options.environment);
  const target: SetupTarget = {
    ...candidate,
    upstream,
    wrapperEnvironment:
      candidate.oauth && keyFile ? { env: { [MASTER_KEY_FILE_ENV]: keyFile } } : {},
    context: previewTarget.context,
  };
  const prepared = await discoverSetupServer(target, {
    home: options.home,
    environment: storageEnvironment,
    signal: interaction.signal,
    stderr: interaction.stderr,
    login: loginOAuthProfile,
    usesTui: interaction.usesTui,
    readSecret: interaction.readSecret,
    selectIndexes: interaction.selectIndexes,
    confirm: interaction.confirm,
    write: interaction.write,
  });
  let tools: string[];
  if (policyChoice.kind === "policy") {
    const authorizer = createPolicyAuthorizer(policyChoice.policy);
    tools = prepared.tools.filter((name) => authorizer.discover(name));
  } else {
    interaction.write(`Tools for ${quoted(candidate.name)}:\n`);
    const toolChoices = prepared.tools.map(quoted);
    if (!interaction.usesTui) {
      toolChoices.forEach((name, index) => interaction.write(`${index + 1}. ${name}\n`));
    }
    const indexes = await interaction.selectIndexes("Select allowed tools: ", toolChoices, {
      allowNone: true,
      tuiRequired: true,
    });
    tools = indexes.map((index) => prepared.tools[index]!);
  }
  const restrictor = {
    ...options.restrictor,
    command: await requireExecutable(options.restrictor.command, options.cwd, options.environment),
  };
  const generated = planManualWrapper({
    candidate: { ...candidate, source: prepared.source },
    allowedTools: tools,
    projectRoot: options.projectRoot,
    restrictor,
    upstream: prepared.upstream,
    verificationEnvironment: options.environment,
    ...(prepared.oauthProfile ? { oauthProfileId: prepared.oauthProfile.metadata.profileId } : {}),
    ...(candidate.oauth && keyFile ? { environment: { [MASTER_KEY_FILE_ENV]: keyFile } } : {}),
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
            client: "manual",
            scope: "project",
            serverName: candidate.name,
            projectRoot: options.projectRoot,
            restrictorHome: options.restrictorHome,
          },
          policySource: planned.policySource,
          backupKey: planned.policyPath,
        })
      : undefined;

  interaction.write(
    `Preview:\n- manual name=${quoted(candidate.name)} transport=${prepared.source.kind} policy=${quoted(planned.policyPath)} tools=${JSON.stringify(tools)}\n`,
  );
  if (!(await interaction.confirm("Apply these changes?"))) {
    throw new SetupCancelled();
  }

  const verification: VerificationSelection = {
    tools,
    verificationUpstream: planned.verificationUpstream,
    context: previewTarget.context,
    ...(prepared.oauthProfile ? { oauthProfile: prepared.oauthProfile } : {}),
    ...(prepared.storage ? { storage: prepared.storage } : {}),
  };
  await withRestoreStateLock(
    options.home,
    async () => {
      await recheckPolicySource(policyChoice);
      const current = await readSetupSnapshot(planned.policyPath, "policy");
      if (policyBaseline) {
        if (!current || !sameFileSnapshot(current, policyBaseline)) {
          throw new Error("Existing policy changed during setup; rerun setup");
        }
        await assertPolicyTakeoversAllowed(options.home, [{ policyPath: planned.policyPath }]);
      } else if (current) {
        throw new Error("policy path is not owned by setup");
      }
      const policyWrite: PlannedWrite = {
        path: planned.policyPath,
        ...(current ? { before: current } : {}),
        content: planned.policySource,
        mode: current?.mode ?? 0o600,
        backupKey: planned.policyPath,
      };
      const profileWrites = await planProfileWrites([
        {
          ...verification,
          ...(prepared.oauthBaseline ? { oauthBaseline: prepared.oauthBaseline } : {}),
          backupKey: planned.policyPath,
        },
      ]);
      await applyFileTransaction(
        [...(savedPolicyWrite ? [savedPolicyWrite] : []), ...profileWrites, policyWrite],
        {
          backupRoot: join(options.restrictorHome, "backups"),
          verify: async (acceptInstalledUpdate) => {
            await verifySelection(
              verification,
              acceptInstalledUpdate,
              interaction.signal,
              interaction.stderr,
            );
          },
        },
      );
    },
    interaction.signal,
  );

  const inherit = manualEnvironmentNames(prepared.source);
  const set = candidate.oauth && keyFile ? { [MASTER_KEY_FILE_ENV]: keyFile } : {};
  interaction.write("Setup complete.\n");
  interaction.write(`command: ${JSON.stringify(planned.command)}\n`);
  interaction.write(`args: ${JSON.stringify(planned.args)}\n`);
  interaction.write(`environment: ${JSON.stringify({ inherit, set })}\n`);
}

export type ManualClientConnection =
  | { kind: "stdio" }
  | { kind: "http"; url: string; routePath: string; routeSource: string };

export type ManualDestinationSelection = {
  destination: ManualDestination;
  connection: ManualClientConnection;
  policyChoice: PolicySourceChoice;
};

type ChosenManualDestination = {
  destination: ManualDestination;
  connection: "stdio" | "http";
  policyChoice: PolicySourceChoice;
  tools: string[];
  policySource: string;
  savedPolicyWrite?: PlannedWrite;
};

type ManualDestinationPlan = ManualDestinationSelection & {
  policy: ReturnType<typeof policyLocation>;
  tools: string[];
  server: ServerCandidate;
  policySource: string;
  configSource: string;
  verification: VerificationSelection;
  fragmentSource?: string;
  savedPolicyWrite?: PlannedWrite;
};

type RouteBaseline = Awaited<ReturnType<typeof loadRoutes>>;

async function runSelectedManualDestinations(options: {
  interaction: SetupInteraction;
  candidate: ManualCandidate;
  destinations: readonly ManualDestination[];
  projectRoot: string;
  cwd: string;
  home: string;
  environment: NodeJS.ProcessEnv;
  restrictor: RestrictorCommand;
  restrictorHome: string;
}): Promise<void> {
  const choices: Array<{
    destination: ManualDestination;
    connection: "stdio" | "http";
    policyChoice?: PolicySourceChoice;
  }> = [];
  for (const destination of options.destinations) {
    if (destination.generated) {
      choices.push({ destination, connection: "http" });
      continue;
    }
    const labels = [
      "STDIO — client starts Restrictor",
      ...(supportsManualHttp(destination.adapter)
        ? ["HTTP — connects through mcp-restrictor run"]
        : []),
    ];
    options.interaction.write(
      `Client connection — ${manualDestinationLabel(destination)}:\n${options.interaction.usesTui ? "" : labels.map((label, index) => `${index + 1}. ${label}\n`).join("")}`,
    );
    const selected = await selectOne(options.interaction, "Select client connection", labels);
    choices.push({ destination, connection: selected === 1 ? "http" : "stdio" });
  }

  const hasHttp = choices.some(({ connection }) => connection === "http");
  const routeBaseline = hasHttp ? await loadRoutes(options.home) : undefined;
  const port = routeBaseline
    ? await selectManualGatewayPort(options.interaction, routeBaseline)
    : undefined;
  for (const choice of choices) {
    const destination = choice.destination;
    options.interaction.write(`Tools & Policy — ${manualDestinationLabel(destination)}:\n`);
    choice.policyChoice = await choosePolicySource({
      interaction: options.interaction,
      context: {
        client: destination.adapter.id,
        scope: destination.config.scope,
        serverName: options.candidate.name,
        projectRoot: options.projectRoot,
        restrictorHome: options.restrictorHome,
      },
      hasCurrent: false,
      ...(destination.policyBaseline ? { existingPolicy: destination.policyBaseline } : {}),
    });
  }

  const previewTarget: SetupTarget = {
    ...options.candidate,
    upstream: previewUpstream(options.candidate),
    wrapperEnvironment: {},
    context: `manual server ${quoted(options.candidate.name)}`,
  };
  previewEndpoint(previewTarget, options.interaction.write);
  if (!(await options.interaction.confirm("Connect to this upstream?"))) {
    throw new SetupCancelled();
  }

  const keyFile = configuredMasterKeyFile(options.environment, options.cwd);
  const storageEnvironment: NodeJS.ProcessEnv = {};
  if (keyFile) storageEnvironment[MASTER_KEY_FILE_ENV] = keyFile;
  if (Object.hasOwn(options.environment, CONTAINER_MARKER_ENV)) {
    storageEnvironment[CONTAINER_MARKER_ENV] = options.environment[CONTAINER_MARKER_ENV];
  }
  const prepared = await discoverSetupServer(
    {
      ...options.candidate,
      upstream: resolveManualUpstream(options.candidate, options.environment),
      wrapperEnvironment:
        options.candidate.oauth && keyFile ? { env: { [MASTER_KEY_FILE_ENV]: keyFile } } : {},
      context: previewTarget.context,
    },
    {
      home: options.home,
      environment: storageEnvironment,
      signal: options.interaction.signal,
      stderr: options.interaction.stderr,
      login: loginOAuthProfile,
      usesTui: options.interaction.usesTui,
      readSecret: options.interaction.readSecret,
      selectIndexes: options.interaction.selectIndexes,
      confirm: options.interaction.confirm,
      write: options.interaction.write,
    },
  );
  const selected: ChosenManualDestination[] = [];
  for (const choice of choices) {
    const policyChoice = choice.policyChoice!;
    let tools: string[];
    if (policyChoice.kind === "policy") {
      const authorizer = createPolicyAuthorizer(policyChoice.policy);
      tools = prepared.tools.filter((name) => authorizer.discover(name));
    } else {
      options.interaction.write(`Tools — ${manualDestinationLabel(choice.destination)}:\n`);
      const toolChoices = prepared.tools.map(quoted);
      if (!options.interaction.usesTui) {
        toolChoices.forEach((name, index) => options.interaction.write(`${index + 1}. ${name}\n`));
      }
      const indexes = await options.interaction.selectIndexes(
        "Select allowed tools: ",
        toolChoices,
        {
          allowNone: true,
          tuiRequired: true,
        },
      );
      tools = indexes.map((index) => prepared.tools[index]!);
    }
    const policySource =
      policyChoice.kind === "policy"
        ? policyChoice.source
        : stringifyPolicy({
            version: 1,
            default: "deny",
            tools: { allow: tools.map((name) => ({ name })), deny: [] },
          });
    const savedPolicyWrite =
      policyChoice.kind === "configure"
        ? await planOptionalSavedPolicy({
            interaction: options.interaction,
            context: {
              client: choice.destination.adapter.id,
              scope: choice.destination.config.scope,
              serverName: options.candidate.name,
              projectRoot: options.projectRoot,
              restrictorHome: options.restrictorHome,
            },
            policySource,
            backupKey: resolve(choice.destination.config.path),
          })
        : undefined;
    selected.push({
      destination: choice.destination,
      connection: choice.connection,
      policyChoice,
      tools,
      policySource,
      ...(savedPolicyWrite ? { savedPolicyWrite } : {}),
    });
  }
  const restrictor = {
    ...options.restrictor,
    command: await requireExecutable(options.restrictor.command, options.cwd, options.environment),
  };
  await installManualDestinations({
    ...options,
    selections: selected,
    ...(routeBaseline ? { routeBaseline } : {}),
    ...(port === undefined ? {} : { port }),
    prepared,
    restrictor,
    ...(options.candidate.oauth && keyFile
      ? { fixedEnvironment: { [MASTER_KEY_FILE_ENV]: keyFile } }
      : {}),
  });
}

async function installManualDestinations(options: {
  interaction: SetupInteraction;
  candidate: ManualCandidate;
  selections: readonly ChosenManualDestination[];
  routeBaseline?: RouteBaseline;
  port?: number;
  prepared: PreparedServer;
  restrictor: RestrictorCommand;
  projectRoot: string;
  cwd: string;
  home: string;
  environment: NodeJS.ProcessEnv;
  restrictorHome: string;
  fixedEnvironment?: Readonly<Record<string, string>>;
}): Promise<void> {
  await preflightManualDestinations(options.selections.map(({ destination }) => destination));
  if (options.routeBaseline) await assertRoutesUnchanged(options.home, options.routeBaseline);
  const initialPlans = planManualDestinationPlans(options);
  if (options.routeBaseline) assertDistinctManualPlans(initialPlans, options.routeBaseline);

  options.interaction.write("Preview:\n");
  for (const plan of initialPlans) {
    const { adapter, config } = plan.destination;
    options.interaction.write(
      `- ${escapeControls(adapter.label)} / ${config.scope} manual name=${quoted(options.candidate.name)} connection=${plan.connection.kind}${plan.connection.kind === "http" ? ` url=${quoted(plan.connection.url)} route=${quoted(plan.connection.routePath)}` : ""} transport=${options.prepared.source.kind} config=${quoted(config.path)} action=add policy=${quoted(plan.policy.diskPath)} tools=${JSON.stringify(plan.tools)}\n`,
    );
  }
  options.interaction.write(
    "Warning: do not edit the client configuration during the write window.\n",
  );
  if (!(await options.interaction.confirm("Apply these changes?"))) {
    throw new SetupCancelled();
  }

  const { result, visibleWrites, writes, adapters } = await withRestoreStateLock(
    options.home,
    async () => {
      for (const { policyChoice } of options.selections) await recheckPolicySource(policyChoice);
      if (options.routeBaseline) await assertRoutesUnchanged(options.home, options.routeBaseline);
      const refreshedDestinations = await rediscoverSelectedManualDestinations({
        ...options,
        destinations: options.selections.map(({ destination }) => destination),
      });
      const refreshedSelections = options.selections.map((selection, index) => ({
        ...selection,
        destination: refreshedDestinations[index]!,
      }));
      await preflightManualDestinations(refreshedDestinations);
      const refreshedPlans = planManualDestinationPlans({
        ...options,
        selections: refreshedSelections,
      });
      if (options.routeBaseline) assertDistinctManualPlans(refreshedPlans, options.routeBaseline);
      const { policyWrites, routeWrites, configWrites } =
        planManualDestinationWrites(refreshedPlans);
      await assertPolicyTakeoversAllowed(
        options.home,
        refreshedPlans.map(({ policy }) => ({ policyPath: policy.diskPath })),
      );
      const profileWrites = await planProfileWrites(
        refreshedPlans.map(({ destination }) => ({
          ...(options.prepared.oauthProfile ? { oauthProfile: options.prepared.oauthProfile } : {}),
          ...(options.prepared.oauthBaseline
            ? { oauthBaseline: options.prepared.oauthBaseline }
            : {}),
          ...(options.prepared.storage ? { storage: options.prepared.storage } : {}),
          backupKey: resolve(destination.config.path),
        })),
      );
      const stateWrites = await planSetupRestoreStateChanges({
        home: options.home,
        projectRoot: options.projectRoot,
        environment: options.environment,
        loaded: refreshedPlans.map(({ destination }) => ({
          adapter: destination.adapter,
          config: destination.config,
          ...(destination.snapshot ? { snapshot: destination.snapshot } : {}),
        })),
        selections: refreshedPlans.map(
          ({ destination, policy, server, policySource: source, connection }) => ({
            adapter: destination.adapter,
            server,
            policy,
            policySource: source,
            created: true,
            ...(destination.generated ? { ownerProjectRoot: options.home } : {}),
            ...(connection.kind === "http"
              ? {
                  route: {
                    write: routeWrites.find(
                      ({ path }) => resolve(path) === resolve(connection.routePath),
                    )!,
                    installed: policyFingerprint(connection.routeSource, 0o600),
                  },
                }
              : {}),
            ...(options.prepared.oauthProfile
              ? { oauthProfileId: options.prepared.oauthProfile.metadata.profileId }
              : {}),
          }),
        ),
        clientWrites: [...policyWrites, ...routeWrites, ...configWrites],
      });
      const savedPolicyWrites = refreshedPlans.flatMap(({ savedPolicyWrite }) =>
        savedPolicyWrite ? [savedPolicyWrite] : [],
      );
      const visibleWrites = [
        ...savedPolicyWrites,
        ...profileWrites,
        ...policyWrites,
        ...routeWrites,
        ...configWrites,
      ];
      const writes = [
        ...savedPolicyWrites,
        ...profileWrites,
        ...policyWrites,
        ...routeWrites,
        ...stateWrites,
        ...configWrites,
      ];
      const result = await applyFileTransaction(writes, {
        backupRoot: join(options.restrictorHome, "backups"),
        verify: async (acceptInstalledUpdate) => {
          await verifyInstalledManualConfigurations({
            plans: refreshedPlans,
            home: options.home,
            projectRoot: options.projectRoot,
            cwd: options.cwd,
            environment: options.environment,
          });
          await verifySelections(
            refreshedPlans.map(({ verification }) => verification),
            acceptInstalledUpdate,
            options.interaction.signal,
            options.interaction.stderr,
          );
        },
        signal: options.interaction.signal,
      });
      return {
        result,
        visibleWrites,
        writes,
        adapters: uniqueAdapters(refreshedPlans.map(({ destination }) => destination.adapter)),
      };
    },
    options.interaction.signal,
  );
  renderSetupCompletion({
    write: options.interaction.write,
    visibleWrites,
    writes,
    backupDirectories: result.backupDirectories,
    adapters,
    projectRoot: options.projectRoot,
    hasHttpRoutes: initialPlans.some(({ connection }) => connection.kind === "http"),
  });
  for (const plan of initialPlans) {
    if (!plan.destination.generated || !plan.fragmentSource) continue;
    options.interaction.write(
      `Client preset fragment — ${generatedPresetLabel(plan.destination.generated)} / ${quoted(options.candidate.name)}:\n${plan.fragmentSource}Merge this entry into the host client configuration; do not overwrite unrelated settings.\n`,
    );
  }
}

function planManualDestinationPlans(options: {
  candidate: ManualCandidate;
  selections: readonly ChosenManualDestination[];
  port?: number;
  prepared: PreparedServer;
  restrictor: RestrictorCommand;
  projectRoot: string;
  home: string;
  fixedEnvironment?: Readonly<Record<string, string>>;
  environment: NodeJS.ProcessEnv;
}): ManualDestinationPlan[] {
  const inheritedEnvironment = manualEnvironmentNames(options.prepared.source);
  return options.selections.map((selection) => {
    const { destination } = selection;
    const { adapter, config } = destination;
    if (selection.connection === "http") {
      if (options.port === undefined) throw new Error("Missing HTTP gateway port");
      const planned = planManualDestinationHttpRoute({
        candidate: { ...options.candidate, source: options.prepared.source },
        client: adapter.id,
        scope: config.scope,
        configPath: config.path,
        projectRoot: options.projectRoot,
        ...(destination.generated ? { ownerProjectRoot: options.home } : {}),
        allowedTools: selection.tools,
        policy: destination.policy,
        restrictor: options.restrictor,
        upstream: options.prepared.upstream,
        ...(options.prepared.oauthProfile
          ? { oauthProfileId: options.prepared.oauthProfile.metadata.profileId }
          : {}),
        ...(options.fixedEnvironment ? { fixedEnvironment: options.fixedEnvironment } : {}),
        verificationEnvironment: options.environment,
        inheritedEnvironment,
        port: options.port,
        home: options.home,
        policySource: selection.policySource,
      });
      return {
        destination,
        policy: destination.policy,
        policyChoice: selection.policyChoice,
        tools: selection.tools,
        connection: {
          kind: "http",
          url: planned.entry.url,
          routePath: planned.routePath,
          routeSource: planned.routeSource,
        },
        server: planned.server,
        policySource: planned.policySource,
        configSource: installAdapterHttpConfig(adapter, config, planned.entry),
        ...(destination.generated
          ? {
              fragmentSource: installAdapterHttpConfig(
                adapter,
                generatedPresetConfig({
                  home: options.home,
                  kind: destination.generated,
                  environment: options.environment,
                }),
                planned.entry,
              ),
            }
          : {}),
        verification: manualDestinationVerification(options, selection, planned),
        ...(selection.savedPolicyWrite ? { savedPolicyWrite: selection.savedPolicyWrite } : {}),
      };
    }
    const projectWrapper =
      config.scope === "project"
        ? adapter.projectWrapper?.({
            projectRoot: options.projectRoot,
            relativePolicyPath: destination.policy.relativePath,
            diskPolicyPath: destination.policy.diskPath,
          })
        : undefined;
    const policy = projectWrapper
      ? { ...destination.policy, argument: projectWrapper.policyArgument }
      : destination.policy;
    const planned = planManualDestinationWrapper({
      candidate: { ...options.candidate, source: options.prepared.source },
      client: adapter.id,
      scope: config.scope,
      configPath: config.path,
      allowedTools: selection.tools,
      policy,
      restrictor: options.restrictor,
      upstream: options.prepared.upstream,
      ...(options.prepared.oauthProfile
        ? { oauthProfileId: options.prepared.oauthProfile.metadata.profileId }
        : {}),
      ...(options.fixedEnvironment ? { fixedEnvironment: options.fixedEnvironment } : {}),
      verificationEnvironment: options.environment,
      inheritedEnvironment,
      ...(projectWrapper?.cwd !== undefined ? { wrapperCwd: projectWrapper.cwd } : {}),
      policySource: selection.policySource,
    });
    return {
      destination,
      policy: destination.policy,
      policyChoice: selection.policyChoice,
      tools: selection.tools,
      connection: { kind: "stdio" },
      server: planned.server,
      policySource: planned.policySource,
      configSource: installAdapterConfig(adapter, config, planned.entry),
      verification: manualDestinationVerification(options, selection, planned),
      ...(selection.savedPolicyWrite ? { savedPolicyWrite: selection.savedPolicyWrite } : {}),
    };
  });
}

function planManualDestinationWrites(plans: readonly ManualDestinationPlan[]): {
  policyWrites: PlannedWrite[];
  routeWrites: PlannedWrite[];
  configWrites: PlannedWrite[];
} {
  assertDistinctManualDestinations(plans.map(({ destination }) => destination));
  return {
    policyWrites: plans.map(({ destination, policySource }) => ({
      path: destination.policy.diskPath,
      ...(destination.policyBaseline ? { before: destination.policyBaseline } : {}),
      content: policySource,
      mode: destination.policyBaseline?.mode ?? 0o600,
      backupKey: resolve(destination.config.path),
      ...(destination.generated ? { private: true as const } : {}),
    })),
    routeWrites: plans.flatMap(({ connection, destination }) =>
      connection.kind === "http"
        ? [
            {
              path: connection.routePath,
              content: connection.routeSource,
              mode: 0o600,
              backupKey: resolve(destination.config.path),
              private: true as const,
            },
          ]
        : [],
    ),
    configWrites: plans.map(({ destination, configSource }) => ({
      path: destination.config.path,
      ...(destination.snapshot ? { before: destination.snapshot } : {}),
      content: configSource,
      mode: destination.snapshot?.mode ?? 0o600,
      backupKey: resolve(destination.config.path),
      ...(destination.generated ? { private: true as const } : {}),
    })),
  };
}

function manualDestinationVerification(
  options: { candidate: ManualCandidate; prepared: PreparedServer },
  selection: ChosenManualDestination,
  planned: { verificationUpstream: UpstreamConfig },
): VerificationSelection {
  return {
    tools: selection.tools,
    verificationUpstream: planned.verificationUpstream,
    context: manualDestinationContext(selection.destination, options.candidate.name),
    ...(options.prepared.oauthProfile ? { oauthProfile: options.prepared.oauthProfile } : {}),
    ...(options.prepared.storage ? { storage: options.prepared.storage } : {}),
  };
}

async function selectManualGatewayPort(
  interaction: SetupInteraction,
  routes: RouteBaseline,
): Promise<number> {
  if (routes.length) return Number(new URL(routes[0]!.definition.listenUrl).port);
  const choices = ["17319 (default)", "Custom"];
  interaction.write(
    `HTTP gateway port:\n${interaction.usesTui ? "" : choices.map((choice, index) => `${index + 1}. ${choice}\n`).join("")}`,
  );
  if ((await selectOne(interaction, "Select HTTP gateway port", choices)) === 0) return 17319;
  for (;;) {
    const raw = await interaction.readText("HTTP gateway port", {
      required: true,
      validate: validateManualGatewayPort,
    });
    if (!validateManualGatewayPort(raw)) return Number(raw);
    if (!interaction.usesTui) interaction.write("Enter an integer from 1 to 65535.\n");
  }
}

function validateManualGatewayPort(value: string): string | undefined {
  const port = Number(value);
  return /^[0-9]+$/.test(value) && Number.isSafeInteger(port) && port >= 1 && port <= 65_535
    ? undefined
    : "Enter an integer from 1 to 65535.";
}

function supportsManualHttp(adapter: ClientAdapter): boolean {
  try {
    return typeof adapter.installHttp === "function" && typeof adapter.restore === "function";
  } catch {
    return false;
  }
}

function manualDestinationLabel(destination: ManualDestination): string {
  return `${escapeControls(destination.adapter.label)} / ${destination.config.scope}`;
}

async function assertRoutesUnchanged(home: string, expected: RouteBaseline): Promise<void> {
  const current = await loadRoutes(home);
  if (
    current.length !== expected.length ||
    current.some(({ snapshot }, index) => !sameFileSnapshot(snapshot, expected[index]!.snapshot))
  ) {
    throw new Error("Managed HTTP routes changed during setup; rerun setup");
  }
}

function assertDistinctManualPlans(
  plans: readonly ManualDestinationPlan[],
  existingRoutes: RouteBaseline,
): void {
  const paths = new Set(existingRoutes.map(({ snapshot }) => resolve(snapshot.path)));
  const urls = new Set(existingRoutes.map(({ definition }) => definition.listenUrl));
  for (const { connection } of plans) {
    if (connection.kind !== "http") continue;
    const path = resolve(connection.routePath);
    if (paths.has(path)) throw new Error("HTTP route target already exists");
    if (urls.has(connection.url)) throw new Error("HTTP route URL already exists");
    paths.add(path);
    urls.add(connection.url);
  }
}

async function preflightManualDestinations(
  destinations: readonly ManualDestination[],
): Promise<void> {
  assertDistinctManualDestinations(destinations);
  for (const destination of destinations) {
    const current = destination.generated
      ? await readGeneratedFileSnapshot(destination.config.path)
      : await readSetupSnapshot(destination.config.path, "client configuration");
    if (
      destination.snapshot
        ? !current || !sameFileSnapshot(current, destination.snapshot)
        : current !== undefined
    ) {
      throw new Error("Client configuration changed during setup; rerun setup");
    }
    const policy = destination.generated
      ? await readGeneratedFileSnapshot(destination.policy.diskPath)
      : await readSetupSnapshot(destination.policy.diskPath, "policy");
    if (destination.policyBaseline) {
      if (!policy || !sameFileSnapshot(policy, destination.policyBaseline)) {
        throw new Error("Existing policy changed during setup; rerun setup");
      }
    } else if (policy) {
      throw new Error("policy path is not owned by setup");
    }
  }
}

async function rediscoverSelectedManualDestinations(options: {
  candidate: ManualCandidate;
  destinations: readonly ManualDestination[];
  home: string;
  projectRoot: string;
  cwd: string;
  environment: NodeJS.ProcessEnv;
  restrictorHome: string;
}): Promise<ManualDestination[]> {
  const fresh = await discoverManualDestinations({
    adapters: uniqueAdapters(options.destinations.map(({ adapter }) => adapter)),
    context: {
      home: options.home,
      projectRoot: options.projectRoot,
      cwd: options.cwd,
      environment: options.environment,
    },
    serverName: options.candidate.name,
    restrictorHome: options.restrictorHome,
  });
  const rediscovered: ManualDestination[] = [];
  for (const expected of options.destinations) {
    let actual: ManualDestination | undefined;
    if (expected.generated && !expected.snapshot) {
      const matching = fresh.generated.filter(
        ({ adapter, kinds }) =>
          adapter === expected.adapter &&
          adapter.id === expected.adapter.id &&
          kinds.includes(expected.generated!),
      );
      if (matching.length === 1) {
        actual = await createGeneratedManualDestination({
          choice: matching[0]!,
          kind: expected.generated,
          context: {
            home: options.home,
            projectRoot: options.projectRoot,
            cwd: options.cwd,
            environment: options.environment,
          },
          serverName: options.candidate.name,
        });
      }
    } else {
      const matching = fresh.available.filter(
        (candidate) =>
          candidate.adapter === expected.adapter &&
          candidate.adapter.id === expected.adapter.id &&
          candidate.config.scope === expected.config.scope &&
          resolve(candidate.config.path) === resolve(expected.config.path) &&
          candidate.generated === expected.generated,
      );
      actual = matching.length === 1 ? matching[0] : undefined;
    }
    if (
      !actual ||
      Boolean(actual.snapshot) !== Boolean(expected.snapshot) ||
      (actual.snapshot !== undefined &&
        expected.snapshot !== undefined &&
        !sameFileSnapshot(actual.snapshot, expected.snapshot)) ||
      resolve(actual.policy.diskPath) !== resolve(expected.policy.diskPath) ||
      Boolean(actual.policyBaseline) !== Boolean(expected.policyBaseline) ||
      (actual.policyBaseline !== undefined &&
        expected.policyBaseline !== undefined &&
        !sameFileSnapshot(actual.policyBaseline, expected.policyBaseline))
    ) {
      throw new Error("Selected destination changed during setup; rerun setup");
    }
    rediscovered.push(actual);
  }
  return rediscovered;
}

function assertDistinctManualDestinations(destinations: readonly ManualDestination[]): void {
  const adapterScopes = new Set<string>();
  const configPaths = new Set<string>();
  const configIdentities = new Set<string>();
  const policyPaths = new Set<string>();
  for (const destination of destinations) {
    const adapterScope = `${destination.adapter.id}\0${destination.config.scope}`;
    const configPath = resolve(destination.config.path);
    const configIdentity = destination.snapshot
      ? `${destination.snapshot.dev}:${destination.snapshot.ino}`
      : undefined;
    const policyPath = resolve(destination.policy.diskPath);
    if (adapterScopes.has(adapterScope)) {
      throw new Error("Select at most one destination per client and scope");
    }
    if (configPaths.has(configPath) || (configIdentity && configIdentities.has(configIdentity))) {
      throw new Error("Selected destinations share a client configuration");
    }
    if (policyPaths.has(policyPath)) throw new Error("Duplicate policy target");
    adapterScopes.add(adapterScope);
    configPaths.add(configPath);
    if (configIdentity) configIdentities.add(configIdentity);
    policyPaths.add(policyPath);
  }
}

async function verifyInstalledManualConfigurations(options: {
  plans: readonly ManualDestinationPlan[];
  home: string;
  projectRoot: string;
  cwd: string;
  environment: NodeJS.ProcessEnv;
}): Promise<void> {
  const reloaded = new Map<
    ClientAdapter,
    { configurations: LoadedConfig[]; unsupported: readonly { name: string }[] }
  >();
  for (const adapter of uniqueAdapters(
    options.plans.map(({ destination }) => destination.adapter),
  )) {
    const result = await createAdapterLoader({ includeManagedRoutes: true }).load(adapter, {
      home: options.home,
      projectRoot: options.projectRoot,
      cwd: options.cwd,
      environment: options.environment,
    });
    reloaded.set(adapter, result);
  }
  for (const plan of options.plans) {
    const adapterResult = reloaded.get(plan.destination.adapter);
    const loaded = adapterResult?.configurations.filter(
      ({ config }) => resolve(config.path) === resolve(plan.destination.config.path),
    );
    const config = loaded?.length === 1 ? loaded[0] : undefined;
    const servers = config?.config.servers.filter(({ name }) => name === plan.server.name) ?? [];
    const server = servers.length === 1 ? servers[0] : undefined;
    let installedConnection = false;
    if (plan.connection.kind === "stdio") {
      installedConnection =
        server?.managedPolicyPath !== undefined &&
        resolve(server.managedPolicyPath) === resolve(plan.policy.diskPath);
    } else {
      try {
        const route = await readPrivateFileSnapshot(plan.connection.routePath);
        const expectedRoute = policyFingerprint(plan.connection.routeSource, 0o600);
        installedConnection =
          server?.source.kind === "http" &&
          server.source.url === plan.connection.url &&
          server.managedPolicyPath === undefined &&
          matchesPrivateFingerprint(route, expectedRoute);
      } catch {
        installedConnection = false;
      }
    }
    if (
      !config ||
      config.snapshot.content !== plan.configSource ||
      config.config.source !== plan.configSource ||
      config.config.unsupported.some(({ name }) => name === plan.server.name) ||
      adapterResult?.unsupported.some(({ name }) => name === plan.server.name) ||
      !installedConnection
    ) {
      throw new Error("Installed client configuration verification failed");
    }
  }
}

function manualDestinationContext(destination: ManualDestination, name: string): string {
  return `${destination.adapter.id} ${destination.config.scope} server ${quoted(name)} in ${quoted(destination.config.path)}`;
}

function uniqueAdapters(adapters: readonly ClientAdapter[]): ClientAdapter[] {
  return [...new Set(adapters)];
}

type ManualInteraction = Pick<
  SetupInteraction,
  "ask" | "readText" | "selectIndexes" | "usesTui" | "write"
>;

async function selectOne(
  interaction: ManualInteraction,
  message: string,
  choices: readonly string[],
): Promise<number> {
  const [index] = await interaction.selectIndexes(message, choices, {
    allowNone: false,
    single: true,
  });
  return index!;
}

async function optionalText(
  interaction: ManualInteraction,
  message: string,
  defaultLabel: string,
  customLabel: string,
  prompt: string,
  validate?: (value: string) => string | undefined,
): Promise<string | undefined> {
  return (await selectOne(interaction, message, [defaultLabel, customLabel])) === 0
    ? undefined
    : interaction.readText(prompt, {
        required: true,
        ...(validate === undefined ? {} : { validate }),
      });
}

export async function promptManualCandidate(options: {
  interaction: ManualInteraction;
}): Promise<ManualCandidate> {
  return options.interaction.usesTui
    ? promptManualCandidateWithTui(options.interaction)
    : promptManualCandidateLine(options.interaction.ask);
}

async function promptManualCandidateWithTui(
  interaction: ManualInteraction,
): Promise<ManualCandidate> {
  const name = await interaction.readText("Server name", { required: true });
  const kind = (["stdio", "http", "sse", "websocket"] as const)[
    await selectOne(interaction, "Transport", ["STDIO", "HTTP", "SSE", "WebSocket"])
  ]!;
  if (kind === "stdio") {
    const command = await interaction.readText("Upstream command", { required: true });
    const args: string[] = [];
    while ((await selectOne(interaction, "STDIO arguments", ["Done", "Add argument"])) === 1) {
      args.push(await interaction.readText("Argument", { trim: false }));
    }
    const envNames: string[] = [];
    while (
      (await selectOne(interaction, "Inherited environment variables", [
        "Done",
        "Add variable",
      ])) === 1
    ) {
      envNames.push(
        await interaction.readText("Environment variable", {
          required: true,
          validate: (value) => {
            try {
              parseHeaderEnvironmentMapping(`X=${value}`);
              return undefined;
            } catch {
              return "Enter a valid environment variable name.";
            }
          },
        }),
      );
    }
    return { name, source: { kind, command, args, envNames } };
  }

  let url = await interaction.readText("Upstream URL", {
    required: true,
    validate: (value) => {
      try {
        validateRemoteUpstream({ kind, url: value, headers: [] });
        return undefined;
      } catch {
        return "Enter a valid upstream URL.";
      }
    },
  });
  const headers: ReturnType<typeof parseHeaderEnvironmentMapping>[] = [];
  while ((await selectOne(interaction, "Headers", ["Done", "Add header"])) === 1) {
    const headerName = await interaction.readText("Header name", {
      required: true,
      validate: (value) => {
        try {
          validateRemoteUpstream({
            kind,
            url: kind === "websocket" ? "wss://example.invalid" : "https://example.invalid",
            headers: [...headers.map(({ name }) => [name, "value"] as const), [value, "value"]],
          });
          return undefined;
        } catch (error) {
          return error instanceof Error ? error.message : "invalid upstream header";
        }
      },
    });
    const environmentVariable = await interaction.readText("Environment variable", {
      required: true,
      validate: (value) => {
        try {
          parseHeaderEnvironmentMapping(`X=${value}`);
          return undefined;
        } catch {
          return "Enter a valid environment variable name.";
        }
      },
    });
    headers.push(parseHeaderEnvironmentMapping(`${headerName}=${environmentVariable}`));
  }

  let auth: "none" | "bearer" | "oauth" = "none";
  if (kind !== "websocket") {
    const authorization = headers.some(({ name }) => asciiLower(name) === "authorization");
    const masterKey = hasMasterKeyHeaderMapping(headers);
    if (authorization) {
      interaction.write(
        "An Authorization header mapping is already configured; only None is available.\n",
      );
    } else if (masterKey) {
      interaction.write(
        "A master-key header mapping is already configured; OAuth is unavailable.\n",
      );
    }
    const choices = [
      "None",
      ...(authorization ? [] : ["Bearer"]),
      ...(authorization || masterKey ? [] : ["OAuth"]),
    ];
    auth = choices[await selectOne(interaction, "Authentication", choices)]!.toLowerCase() as
      | "none"
      | "bearer"
      | "oauth";
  }

  const authorization = headers.some(({ name }) => asciiLower(name) === "authorization");
  if (authorization && auth !== "none") {
    throw new Error(CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE);
  }

  const placeholderHeaders = headers.map(({ name }) => [name, "value"] as const);
  const selectedAuth = auth === "bearer" || auth === "oauth" ? { auth } : {};
  const validateFinalUrl = (value: string) => {
    try {
      validateRemoteUpstream({ kind, url: value, headers: placeholderHeaders, ...selectedAuth });
      return undefined;
    } catch {
      return "Enter a valid upstream URL.";
    }
  };
  if (validateFinalUrl(url)) {
    url = await interaction.readText("Upstream URL", {
      required: true,
      validate: validateFinalUrl,
    });
  }

  let bearerTokenEnvVar: string | undefined;
  if (auth === "bearer") {
    bearerTokenEnvVar = await interaction.readText("Bearer token environment variable", {
      required: true,
      validate: (value) => {
        try {
          parseHeaderEnvironmentMapping(`X=${value}`);
          return undefined;
        } catch {
          return "Enter a valid environment variable name.";
        }
      },
    });
  }
  let oauth: OAuthSetupHint | undefined;
  if (auth === "oauth") {
    if (hasMasterKeyHeaderMapping(headers)) {
      throw new Error(OAUTH_HEADER_MAPPING_CONFLICT_MESSAGE);
    }
    const clientId = await optionalText(
      interaction,
      "OAuth client ID",
      "Dynamic registration",
      "Enter client ID",
      "OAuth client ID",
    );
    const requestedScope = await optionalText(
      interaction,
      "OAuth requested scope",
      "Discover automatically",
      "Enter scope",
      "OAuth requested scope",
    );
    const resource = await optionalText(
      interaction,
      "OAuth resource",
      "None",
      "Enter resource",
      "OAuth resource",
      (value) => {
        try {
          new URL(value);
          return undefined;
        } catch {
          return "Enter a valid absolute URL.";
        }
      },
    );
    const resourceMetadataUrl = await optionalText(
      interaction,
      "OAuth resource metadata URL",
      "Discover automatically",
      "Enter URL",
      "OAuth resource metadata URL",
      (value) => {
        try {
          secureOAuthUrl(value);
          return undefined;
        } catch {
          return "Enter a secure OAuth URL.";
        }
      },
    );
    const authServerMetadataUrl = await optionalText(
      interaction,
      "OAuth authorization metadata URL",
      "Discover automatically",
      "Enter URL",
      "OAuth authorization metadata URL",
      (value) => {
        try {
          secureOAuthUrl(value);
          return undefined;
        } catch {
          return "Enter a secure OAuth URL.";
        }
      },
    );
    const rawPort = await optionalText(
      interaction,
      "OAuth callback port",
      "Ephemeral",
      "Enter port",
      "OAuth callback port",
      (value) => {
        const port = Number(value);
        return Number.isInteger(port) && port >= 0 && port <= MAX_TCP_PORT
          ? undefined
          : "Enter an integer from 0 to 65535.";
      },
    );
    const baseUrl = await optionalText(
      interaction,
      "OAuth callback base URL",
      "Loopback",
      "Enter URL",
      "OAuth callback base URL",
      (value) => {
        try {
          callbackUrl(value);
          return undefined;
        } catch {
          return "Enter a valid OAuth callback URL.";
        }
      },
    );
    const port = rawPort === undefined ? undefined : Number(rawPort);
    oauth = {
      mode: "explicit",
      ...(clientId ? { clientId } : {}),
      ...(requestedScope ? { requestedScope } : {}),
      ...(resource ? { resource } : {}),
      ...(resourceMetadataUrl ? { resourceMetadataUrl } : {}),
      ...(authServerMetadataUrl ? { authServerMetadataUrl } : {}),
      callback: baseUrl
        ? {
            url: baseUrl,
            ...(port === undefined ? {} : { port }),
            appendProfileId: true,
          }
        : {
            host: OAUTH_IPV4_LOOPBACK_HOST,
            path: DEFAULT_OAUTH_CALLBACK_PATH,
            ...(port === undefined ? {} : { port }),
            appendProfileId: true,
          },
    };
  }

  const source: SourceSpec =
    kind === "websocket"
      ? { kind, url, headers }
      : {
          kind,
          url,
          headers,
          ...(bearerTokenEnvVar ? { bearerTokenEnvVar } : {}),
        };
  validateRemoteUpstream({
    kind,
    url,
    headers: placeholderHeaders,
    ...selectedAuth,
  });
  return { name, source, ...(oauth ? { oauth } : {}) };
}

async function promptManualCandidateLine(
  ask: (question: string) => Promise<string>,
): Promise<ManualCandidate> {
  const name = await required(ask, "Server name: ");
  const kind = (await required(ask, "Transport (stdio/http/sse/websocket): ")).toLowerCase();
  if (kind === "stdio") {
    const command = await required(ask, "Upstream command: ");
    const rawArgs = await ask("Arguments as JSON array (empty for none): ");
    const args = parseArguments(rawArgs);
    const envNames = commaSeparated(
      await ask("Inherited environment variable names, comma-separated (empty for none): "),
    );
    for (const envName of envNames) parseHeaderEnvironmentMapping(`X=${envName}`);
    return { name, source: { kind, command, args, envNames } };
  }
  if (kind !== "http" && kind !== "sse" && kind !== "websocket") {
    throw new Error("invalid manual upstream transport");
  }

  const url = await required(ask, "Upstream URL: ");
  const headers = [];
  const headerNames = new Set<string>();
  for (;;) {
    const raw = await ask("Header mapping HEADER=ENV_NAME (empty when done): ");
    if (!raw) break;
    const mapping = parseHeaderEnvironmentMapping(raw);
    const normalized = asciiLower(mapping.name);
    if (headerNames.has(normalized)) throw new Error("duplicate upstream header");
    headerNames.add(normalized);
    headers.push(mapping);
  }
  const auth = (await required(ask, "Authentication (none/bearer/oauth): ")).toLowerCase();
  if (!["none", "bearer", "oauth"].includes(auth)) {
    throw new Error("invalid manual upstream authentication");
  }
  if (kind === "websocket" && auth !== "none") {
    throw new Error("Bearer and OAuth do not support WebSocket upstreams");
  }
  const authorization = headers.some(({ name }) => asciiLower(name) === "authorization");
  if (authorization && auth !== "none") {
    throw new Error(CONFLICTING_UPSTREAM_AUTHENTICATION_MESSAGE);
  }

  let bearerTokenEnvVar: string | undefined;
  if (auth === "bearer") {
    bearerTokenEnvVar = await required(ask, "Bearer token environment variable: ");
    parseHeaderEnvironmentMapping(`X=${bearerTokenEnvVar}`);
  }
  let oauth: OAuthSetupHint | undefined;
  if (auth === "oauth") {
    if (hasMasterKeyHeaderMapping(headers)) {
      throw new Error(OAUTH_HEADER_MAPPING_CONFLICT_MESSAGE);
    }
    const clientId = await ask("OAuth client ID (empty for dynamic registration): ");
    const requestedScope = await ask("OAuth requested scope (empty for discovery): ");
    const resource = await ask("OAuth resource (empty for none): ");
    const resourceMetadataUrl = await ask("OAuth resource metadata URL (empty for discovery): ");
    const authServerMetadataUrl = await ask(
      "OAuth authorization metadata URL (empty for discovery): ",
    );
    const rawPort = await ask("OAuth callback port (empty for ephemeral): ");
    const baseUrl = await ask("OAuth callback base URL (empty for loopback): ");
    const port = rawPort ? Number(rawPort) : undefined;
    if (port !== undefined && (!Number.isInteger(port) || port < 0 || port > MAX_TCP_PORT)) {
      throw new Error("invalid OAuth callback port");
    }
    oauth = {
      mode: "explicit",
      ...(clientId ? { clientId } : {}),
      ...(requestedScope ? { requestedScope } : {}),
      ...(resource ? { resource } : {}),
      ...(resourceMetadataUrl ? { resourceMetadataUrl } : {}),
      ...(authServerMetadataUrl ? { authServerMetadataUrl } : {}),
      callback: baseUrl
        ? {
            url: baseUrl,
            ...(port === undefined ? {} : { port }),
            appendProfileId: true,
          }
        : {
            host: OAUTH_IPV4_LOOPBACK_HOST,
            path: DEFAULT_OAUTH_CALLBACK_PATH,
            ...(port === undefined ? {} : { port }),
            appendProfileId: true,
          },
    };
  }

  const source: SourceSpec =
    kind === "websocket"
      ? { kind, url, headers }
      : {
          kind,
          url,
          headers,
          ...(bearerTokenEnvVar ? { bearerTokenEnvVar } : {}),
        };
  validateRemoteUpstream({
    kind,
    url,
    headers: headers.map(({ name }) => [name, "value"]),
    ...(auth === "bearer" || auth === "oauth" ? { auth } : {}),
  });
  return { name, source, ...(oauth ? { oauth } : {}) };
}

export function resolveManualUpstream(
  candidate: ManualCandidate,
  environment: NodeJS.ProcessEnv,
): UpstreamConfig {
  assertNoReservedUpstreamEnvironment(candidate.source);
  const source = candidate.source;
  if (source.kind === "stdio") {
    return {
      kind: "stdio",
      command: source.command,
      args: source.args,
      ...(source.envNames.length
        ? { env: createStdioEnvironment(source.envNames, environment) }
        : {}),
      ...(source.cwd !== undefined ? { cwd: source.cwd } : {}),
    };
  }
  const headers = resolveHeaderEnvironment(source.headers, environment);
  if (source.kind === "websocket") {
    validateRemoteUpstream({ kind: source.kind, url: source.url, headers });
    return { kind: source.kind, url: source.url, ...(headers.length ? { headers } : {}) };
  }
  const bearerToken =
    source.bearerTokenEnvVar === undefined
      ? undefined
      : environmentValue(environment, source.bearerTokenEnvVar);
  validateRemoteUpstream({
    kind: source.kind,
    url: source.url,
    headers,
    ...(candidate.oauth ? { auth: "oauth" } : bearerToken !== undefined ? { auth: "bearer" } : {}),
  });
  return {
    kind: source.kind,
    url: source.url,
    ...(headers.length ? { headers } : {}),
    ...(bearerToken !== undefined ? { bearerToken } : {}),
  };
}

export function planManualWrapper(options: {
  candidate: ManualCandidate;
  allowedTools: readonly string[];
  projectRoot: string;
  restrictor: RestrictorCommand;
  upstream: UpstreamConfig;
  oauthProfileId?: string;
  environment?: Record<string, string>;
  verificationEnvironment?: NodeJS.ProcessEnv;
}): {
  policyPath: string;
  policySource: string;
  command: string;
  args: string[];
  verificationUpstream: UpstreamConfig;
} {
  const policyPath = join(
    options.projectRoot,
    RESTRICTOR_HOME_DIRECTORY,
    "policies",
    "manual",
    policyFileName(options.candidate.name),
  );
  const source = options.oauthProfileId
    ? withOAuthProfile(options.candidate.source, options.oauthProfileId)
    : options.candidate.source;
  const args = buildWrapperArgs({
    policyArgument: policyPath,
    source,
    restrictor: options.restrictor,
  });
  const environment = buildVerificationEnvironment({
    source,
    upstream: options.upstream,
    ...(options.environment ? { fixedEnvironment: options.environment } : {}),
    ...(options.verificationEnvironment
      ? { verificationEnvironment: options.verificationEnvironment }
      : {}),
  });
  return {
    policyPath,
    policySource: stringifyPolicy({
      version: 1,
      default: "deny",
      tools: { allow: options.allowedTools.map((name) => ({ name })), deny: [] },
    }),
    command: options.restrictor.command,
    args,
    verificationUpstream: {
      kind: "stdio",
      command: options.restrictor.command,
      args,
      ...(environment ? { env: environment } : {}),
    },
  };
}

function previewUpstream(candidate: ManualCandidate): UpstreamConfig {
  const source = candidate.source;
  if (source.kind === "stdio") {
    return { kind: "stdio", command: source.command, args: source.args };
  }
  return { kind: source.kind, url: source.url };
}

function manualEnvironmentNames(source: SourceSpec): string[] {
  const names =
    source.kind === "stdio"
      ? source.envNames
      : [
          ...source.headers.map(({ environmentVariable }) => environmentVariable),
          ...(source.kind !== "websocket" && source.bearerTokenEnvVar
            ? [source.bearerTokenEnvVar]
            : []),
        ];
  return [...new Set(names)];
}

function parseArguments(value: string): string[] {
  if (!value) return [];
  try {
    const args: unknown = JSON.parse(value);
    if (Array.isArray(args) && args.every((entry) => typeof entry === "string")) return args;
  } catch {
    // Replaced below with a stable, non-reflective message.
  }
  throw new Error("Arguments must be a JSON array of strings");
}

function commaSeparated(value: string): string[] {
  return value
    ? value
        .split(",")
        .map((entry) => entry.trim())
        .filter(Boolean)
    : [];
}

async function required(
  ask: (question: string) => Promise<string>,
  question: string,
): Promise<string> {
  const value = await ask(question);
  if (!value) throw new Error("manual setup field is required");
  return value;
}

function environmentValue(environment: NodeJS.ProcessEnv, name: string): string {
  const value = Object.hasOwn(environment, name) ? environment[name] : undefined;
  if (typeof value !== "string" || !value) {
    throw new Error(`Environment variable ${name} is empty or missing`);
  }
  return value;
}
