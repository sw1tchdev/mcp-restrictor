import type { HeaderEnvironmentMapping, UpstreamConfig } from "@mcp-restrictor/transports";
import type { OAuthCallbackStrategy } from "../../oauth/storage.js";

export type ClientId = string;
export type Scope = "user" | "project";
export type CodexEnvVar = string | { name: string; source: "local" | "remote" };
export type SourceSpec =
  | {
      kind: "stdio";
      command: string;
      args: string[];
      envNames: string[];
      cwd?: string;
    }
  | {
      kind: "http" | "sse";
      url: string;
      headers: HeaderEnvironmentMapping[];
      bearerTokenEnvVar?: string;
      oauthProfileId?: string;
    }
  | {
      kind: "websocket";
      url: string;
      headers: HeaderEnvironmentMapping[];
    };
export type OAuthSetupHint = {
  mode: "explicit" | "challenge";
  clientId?: string;
  clientSecret?: string;
  requestedScope?: string;
  fallbackScope?: string;
  resource?: string;
  resourceMetadataUrl?: string;
  authServerMetadataUrl?: string;
  callback: OAuthCallbackStrategy;
};
export type WrapperEnvironment = {
  env?: Record<string, string>;
  envVars?: CodexEnvVar[];
};
export type ServerCandidate = {
  client: ClientId;
  scope: Scope;
  name: string;
  configPath: string;
  source: SourceSpec;
  upstream: UpstreamConfig;
  alternatives?: readonly { source: SourceSpec; upstream: UpstreamConfig }[];
  wrapperEnvironment: WrapperEnvironment;
  original: Record<string, unknown>;
  oauth?: OAuthSetupHint;
  managedPolicyPath?: string;
};
export type UnsupportedServer = {
  client: ClientId;
  scope: Scope;
  name: string;
  configPath: string;
  reason: string;
};
export type ParsedConfig = {
  client: ClientId;
  scope: Scope;
  path: string;
  source: string;
  servers: ServerCandidate[];
  unsupported: UnsupportedServer[];
};
export type Replacement = {
  command: string;
  args: string[];
  env?: Record<string, string>;
  envVars?: CodexEnvVar[];
  cwd?: string;
};
export type RestrictorCommand = { command: string; argsPrefix: string[] };
