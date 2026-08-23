import type { FileSnapshot } from "./setup/transaction.js";
import type {
  ParsedConfig,
  Replacement,
  ServerCandidate,
  UnsupportedServer,
} from "./setup/wrapper.js";

export type ClientLoadContext = {
  home: string;
  projectRoot: string;
  cwd: string;
  environment: NodeJS.ProcessEnv;
};
export type LoadedClientConfig = { config: ParsedConfig; snapshot: FileSnapshot };
export type ClientLoadResult = {
  configurations: readonly LoadedClientConfig[];
  unsupported: readonly UnsupportedServer[];
};
export type ClientRestoreEntry = {
  name: string;
  originalSource: string;
  installedSource?: string;
  created?: true;
};
export type ClientInstallEntry = {
  name: string;
  command: string;
  args: readonly string[];
  cwd?: string;
  environment: {
    inherit: readonly string[];
    set: Readonly<Record<string, string>>;
  };
};
export type ClientHttpInstallEntry = { name: string; url: string };
export type ClientAdapterHost = {
  readConfig(path: string): Promise<FileSnapshot | undefined>;
  readSecretFile(path: string): Promise<FileSnapshot>;
};
export type ClientResolveContext = {
  home: string;
  projectRoot: string;
  cwd: string;
  environment: NodeJS.ProcessEnv;
};
export type ClientResolutionDependency =
  | { kind: "environment"; name: string; value: string }
  | { kind: "file"; snapshot: FileSnapshot };
export type ClientResolveResult = {
  candidate: ServerCandidate;
  dependencies: readonly ClientResolutionDependency[];
};

export class UpstreamProtocolIncompatibleError extends Error {
  constructor() {
    super("Upstream transport protocol is incompatible");
  }
}
export type ClientProjectWrapperContext = {
  projectRoot: string;
  relativePolicyPath: string;
  diskPolicyPath: string;
};
export type ClientCompletionContext = { projectRoot: string };
export type ClientAdapter = {
  apiVersion: 1;
  id: string;
  label: string;
  load(context: ClientLoadContext, host: ClientAdapterHost): Promise<ClientLoadResult>;
  resolve?(
    candidate: ServerCandidate,
    context: ClientResolveContext,
    host: ClientAdapterHost,
  ): Promise<ClientResolveResult>;
  projectWrapper?(context: ClientProjectWrapperContext): {
    policyArgument: string;
    cwd?: string;
  };
  render(config: ParsedConfig, replacements: ReadonlyMap<string, Replacement>): string;
  install?(config: ParsedConfig, entry: ClientInstallEntry): string;
  installHttp?(config: ParsedConfig, entry: ClientHttpInstallEntry): string;
  restore?(
    config: ParsedConfig,
    entries: readonly ClientRestoreEntry[],
    context: ClientLoadContext,
  ): string;
  completionMessage?(context: ClientCompletionContext): readonly string[];
};

const clientId = /^[a-z][a-z0-9-]{0,63}$/;
const definedClientAdapters = new WeakSet<ClientAdapter>();

export function defineClientAdapter(adapter: ClientAdapter): ClientAdapter {
  if (definedClientAdapters.has(adapter)) return adapter;
  const {
    apiVersion,
    id,
    label,
    load,
    resolve,
    projectWrapper,
    render,
    install,
    installHttp,
    restore,
    completionMessage,
  } = adapter;
  if (apiVersion !== 1) throw new Error("Unsupported client adapter API version");
  if (typeof id !== "string" || !clientId.test(id)) throw new Error("Invalid client adapter ID");
  if (typeof label !== "string" || !label.trim()) throw new Error("Invalid client adapter label");
  if (typeof load !== "function") throw new Error("Invalid client adapter load");
  if (resolve !== undefined && typeof resolve !== "function") {
    throw new Error("Invalid client adapter resolve");
  }
  if (projectWrapper !== undefined && typeof projectWrapper !== "function") {
    throw new Error("Invalid client adapter projectWrapper");
  }
  if (typeof render !== "function") throw new Error("Invalid client adapter render");
  if (install !== undefined && typeof install !== "function") {
    throw new Error("Invalid client adapter install");
  }
  if (installHttp !== undefined && typeof installHttp !== "function") {
    throw new Error("Invalid client adapter installHttp");
  }
  if (restore !== undefined && typeof restore !== "function") {
    throw new Error("Invalid client adapter restore");
  }
  if (completionMessage !== undefined && typeof completionMessage !== "function") {
    throw new Error("Invalid client adapter completionMessage");
  }
  const defined = Object.freeze({
    apiVersion,
    id,
    label,
    load,
    ...(resolve ? { resolve } : {}),
    ...(projectWrapper ? { projectWrapper } : {}),
    render,
    ...(install ? { install } : {}),
    ...(installHttp ? { installHttp } : {}),
    ...(restore ? { restore } : {}),
    ...(completionMessage ? { completionMessage } : {}),
  });
  definedClientAdapters.add(defined);
  return defined;
}
