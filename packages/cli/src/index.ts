#!/usr/bin/env node

import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, resolve } from "node:path";
import type { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { runStdioProxy, startHttpGateway, startHttpProxy } from "@mcp-restrictor/transports";
import {
  defaultClientPlugins,
  runClientCommand,
  type ClientPluginOperations,
} from "./commands/client.js";
import { CLIENT_ADAPTER_LOAD_FAILURE } from "./client-plugins/constants.js";
import { runOAuthLoginCommand } from "./commands/oauth.js";
import { runProxyCommand } from "./commands/proxy.js";
import { runRoutesCommand } from "./commands/run.js";
import { loginOAuthProfile } from "./oauth/login.js";
import { createOAuthAuthProvider } from "./oauth/provider.js";
import { readOAuthProfile, readOAuthProfileSnapshot, writeOAuthProfile } from "./oauth/storage.js";
import { builtInAdapters, createAdapterRegistry } from "./setup/adapters.js";
import { DEFAULT_RESTRICTOR_COMMAND } from "./setup/constants.js";
import { runSetupCommand } from "./setup/index.js";

type MainOptions = {
  argv?: readonly string[];
  environment?: NodeJS.ProcessEnv;
  home?: string;
  input?: Readable;
  output?: Writable;
  signal?: AbortSignal;
  readOAuthProfile?: typeof readOAuthProfile;
  readOAuthProfileSnapshot?: typeof readOAuthProfileSnapshot;
  loginOAuthProfile?: typeof loginOAuthProfile;
  writeOAuthProfile?: typeof writeOAuthProfile;
  createOAuthAuthProvider?: typeof createOAuthAuthProvider;
  readSecret?: (question: string) => Promise<string>;
  runStdioProxy?: typeof runStdioProxy;
  startHttpGateway?: typeof startHttpGateway;
  startHttpProxy?: typeof startHttpProxy;
  clientPlugins?: ClientPluginOperations;
};

export async function main(options: MainOptions = {}): Promise<void> {
  const argv = options.argv ?? process.argv;
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;

  if (argv[2] === "client") {
    await runClientCommand(argv, options, input, output);
    return;
  }

  const interactiveCommand = argv[2];
  if (interactiveCommand === "setup") {
    if (argv.length !== 3) throw new Error("Usage: mcp-restrictor setup");
    const home = options.home ?? homedir();
    const environment = options.environment ?? process.env;
    const run = async (registry: ReturnType<typeof createAdapterRegistry>) => {
      const commandOptions = {
        home,
        environment,
        input,
        output,
        ...(options.signal ? { signal: options.signal } : {}),
        adapters: registry.available,
        unavailableAdapters: [...registry.unavailable].sort((left, right) =>
          left.packageName < right.packageName ? -1 : Number(left.packageName > right.packageName),
        ),
      };
      await runSetupCommand(commandOptions);
    };
    let operations: ClientPluginOperations;
    let withLoaded: ClientPluginOperations["withLoaded"];
    try {
      operations = options.clientPlugins ?? defaultClientPlugins;
      withLoaded = operations.withLoaded;
    } catch {
      await run(failedClientAdapterRegistry());
      return;
    }
    if (withLoaded) {
      let started = false;
      try {
        await withLoaded({ home }, async (loaded) => {
          started = true;
          await run(clientAdapterRegistry(loaded));
        });
      } catch (error) {
        if (started) throw error;
        await run(failedClientAdapterRegistry());
      }
    } else {
      let registry: ReturnType<typeof createAdapterRegistry>;
      try {
        registry = await loadClientAdapterRegistry(home, operations);
      } catch {
        registry = failedClientAdapterRegistry();
      }
      await run(registry);
    }
    return;
  }

  if (argv[2] === "run") {
    const bindHostname =
      argv.length === 3
        ? undefined
        : argv.length === 5 && argv[3] === "--bind" && argv[4] === "0.0.0.0"
          ? "0.0.0.0"
          : null;
    if (bindHostname === null) {
      throw new Error("Usage: mcp-restrictor run [--bind 0.0.0.0]");
    }
    await runRoutesCommand({
      home: options.home ?? homedir(),
      environment: options.environment ?? process.env,
      ...(bindHostname ? { bindHostname } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
      ...(options.readOAuthProfile ? { readOAuthProfile: options.readOAuthProfile } : {}),
      ...(options.createOAuthAuthProvider
        ? { createOAuthAuthProvider: options.createOAuthAuthProvider }
        : {}),
      ...(options.startHttpGateway ? { startHttpGateway: options.startHttpGateway } : {}),
    });
    return;
  }

  const environment = options.environment ?? process.env;
  const home = options.home ?? homedir();
  if (argv[2] === "oauth" && argv[3] === "login") {
    if (argv.length !== 5) throw new Error("Usage: mcp-restrictor oauth login PROFILE_ID");
    await runOAuthLoginCommand(argv[4]!, options, { home, environment, input, output });
    return;
  }

  await runProxyCommand(options, { argv, home, environment, input, output });
}

async function loadClientAdapterRegistry(
  home: string,
  operations: ClientPluginOperations,
): Promise<ReturnType<typeof createAdapterRegistry>> {
  return clientAdapterRegistry(await operations.load({ home }));
}

function clientAdapterRegistry(
  loaded: Awaited<ReturnType<ClientPluginOperations["load"]>>,
): ReturnType<typeof createAdapterRegistry> {
  return createAdapterRegistry(builtInAdapters, [
    ...loaded.adapters,
    ...loaded.unavailable.map(({ packageName }) => ({
      packageName,
      error: new Error(CLIENT_ADAPTER_LOAD_FAILURE),
    })),
  ]);
}

function failedClientAdapterRegistry(): ReturnType<typeof createAdapterRegistry> {
  return createAdapterRegistry(builtInAdapters, [
    { packageName: "unknown client adapter", error: new Error(CLIENT_ADAPTER_LOAD_FAILURE) },
  ]);
}

const entry = process.argv[1];
let directEntry = false;
if (entry) {
  try {
    const resolvedEntry = realpathSync(resolve(entry));
    directEntry =
      resolvedEntry === realpathSync(fileURLToPath(import.meta.url)) ||
      basename(resolvedEntry) === DEFAULT_RESTRICTOR_COMMAND;
  } catch {
    directEntry = false;
  }
}
if (directEntry) {
  void main().catch((failure: unknown) => {
    process.stderr.write(
      `mcp-restrictor: ${failure instanceof Error ? failure.message : String(failure)}\n`,
    );
    process.exitCode = 1;
  });
}
