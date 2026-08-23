import { win32 } from "node:path";
import {
  parseHeaderEnvironmentMapping,
  validateRemoteUpstream,
  type HeaderEnvironmentMapping,
} from "@mcp-restrictor/transports";
import { MASTER_KEY_FILE_ENV, oauthProfilePath } from "../../oauth/storage.js";
import { asciiLower } from "../../utils/values.js";
import type { SourceSpec } from "./model.js";

const wrapperHeaderEnvironmentPrefix = "MCP_RESTRICTOR_UPSTREAM_HEADER_";

export function reserveWrapperEnvironmentName(occupied: Set<string>): string {
  const normalized = new Set([...occupied].map(asciiLower));
  for (let index = 0; ; index += 1) {
    const name = `${wrapperHeaderEnvironmentPrefix}${index}`;
    if (!normalized.has(asciiLower(name))) {
      occupied.add(name);
      return name;
    }
  }
}

export function isManagedWrapperCommand(command: string): boolean {
  return /^mcp-restrictor(?:\.(?:cmd|exe|bat|com))?$/i.test(win32.basename(command));
}

export function parseManagedWrapper(
  command: string,
  args: readonly string[],
): { policyArgument: string; source: SourceSpec } | undefined {
  if (!isManagedWrapperCommand(command)) return undefined;

  let policyArgument: string | undefined;
  let remote: { kind: "http" | "sse" | "websocket"; url: string } | undefined;
  let bearerTokenEnvVar: string | undefined;
  let oauthProfileId: string | undefined;
  let cwd: string | undefined;
  const envNames: string[] = [];
  const headers: HeaderEnvironmentMapping[] = [];
  const headerNames = new Set<string>();
  let separator = -1;

  for (let index = 0; index < args.length; index += 1) {
    const option = args[index]!;
    if (option === "--") {
      separator = index;
      break;
    }
    if (!option.startsWith("--")) return undefined;
    if (option === "--upstream-env") {
      const value = optionValue(args, ++index);
      if (value === undefined) return undefined;
      envNames.push(value);
      continue;
    }
    if (option === "--upstream-header-env" || option === "--upstream-header-base64url-env") {
      const value = optionValue(args, ++index);
      if (value === undefined) return undefined;
      let mapping: HeaderEnvironmentMapping;
      try {
        mapping = parseHeaderEnvironmentMapping(
          value,
          option === "--upstream-header-base64url-env" ? "base64url" : undefined,
        );
      } catch {
        return undefined;
      }
      const normalized = mapping.name.toLowerCase();
      if (headerNames.has(normalized)) return undefined;
      headerNames.add(normalized);
      headers.push(mapping);
      continue;
    }
    if (
      option !== "--policy" &&
      option !== "--upstream-http" &&
      option !== "--upstream-sse" &&
      option !== "--upstream-websocket" &&
      option !== "--upstream-bearer-token-env" &&
      option !== "--upstream-oauth-profile" &&
      option !== "--upstream-cwd"
    ) {
      return undefined;
    }
    const value = optionValue(args, ++index);
    if (value === undefined) return undefined;
    if (option === "--policy") {
      if (policyArgument !== undefined) return undefined;
      policyArgument = value;
    } else if (
      option === "--upstream-http" ||
      option === "--upstream-sse" ||
      option === "--upstream-websocket"
    ) {
      if (remote !== undefined) return undefined;
      remote = {
        kind:
          option === "--upstream-http" ? "http" : option === "--upstream-sse" ? "sse" : "websocket",
        url: value,
      };
    } else if (option === "--upstream-bearer-token-env") {
      if (bearerTokenEnvVar !== undefined) return undefined;
      bearerTokenEnvVar = value;
    } else if (option === "--upstream-oauth-profile") {
      if (oauthProfileId !== undefined) return undefined;
      oauthProfileId = value;
    } else {
      if (cwd !== undefined) return undefined;
      cwd = value;
    }
  }

  if (!policyArgument) return undefined;
  const positionals = separator === -1 ? [] : args.slice(separator + 1);
  if (remote !== undefined) {
    if (separator !== -1 || envNames.length > 0 || cwd !== undefined) return undefined;
    if (
      (bearerTokenEnvVar !== undefined &&
        (bearerTokenEnvVar.startsWith("-") || remote.kind === "websocket")) ||
      (oauthProfileId !== undefined &&
        (remote.kind === "websocket" ||
          bearerTokenEnvVar !== undefined ||
          !validOAuthProfileId(oauthProfileId))) ||
      (oauthProfileId !== undefined && hasMasterKeyHeaderMapping(headers)) ||
      !validRemoteSource(
        remote,
        headers,
        bearerTokenEnvVar ? "bearer" : oauthProfileId ? "oauth" : undefined,
      )
    )
      return undefined;
    const source: SourceSpec =
      remote.kind === "websocket"
        ? { kind: remote.kind, url: remote.url, headers }
        : {
            kind: remote.kind,
            url: remote.url,
            headers,
            ...(bearerTokenEnvVar ? { bearerTokenEnvVar } : {}),
            ...(oauthProfileId ? { oauthProfileId } : {}),
          };
    return { policyArgument, source };
  }
  if (
    bearerTokenEnvVar !== undefined ||
    oauthProfileId !== undefined ||
    headers.length > 0 ||
    positionals.length === 0
  )
    return undefined;
  const [upstreamCommand, ...upstreamArgs] = positionals;
  if (isManagedWrapperCommand(upstreamCommand!)) return undefined;
  return {
    policyArgument,
    source: {
      kind: "stdio",
      command: upstreamCommand!,
      args: upstreamArgs,
      envNames,
      ...(cwd !== undefined ? { cwd } : {}),
    },
  };
}

function optionValue(args: readonly string[], index: number): string | undefined {
  const value = args[index];
  return value && value !== "--" && !value.startsWith("--") ? value : undefined;
}

export function validRemoteSource(
  remote: { kind: "http" | "sse" | "websocket"; url: string },
  mappings: readonly HeaderEnvironmentMapping[],
  auth?: "bearer" | "oauth",
): boolean {
  try {
    const parsed = mappings.map(({ name, environmentVariable, encoding }) =>
      parseHeaderEnvironmentMapping(`${name}=${environmentVariable}`, encoding),
    );
    const url = remote.url.includes("${")
      ? remote.kind === "websocket"
        ? "wss://example.test/mcp"
        : "https://example.test/mcp"
      : remote.url;
    validateRemoteUpstream({
      kind: remote.kind,
      url,
      headers: parsed.map(({ name }) => [name, "value"]),
      ...(auth ? { auth } : {}),
    });
    return true;
  } catch {
    return false;
  }
}

export function hasMasterKeyHeaderMapping(mappings: readonly HeaderEnvironmentMapping[]): boolean {
  return mappings.some(
    ({ environmentVariable }) =>
      asciiLower(environmentVariable) === asciiLower(MASTER_KEY_FILE_ENV),
  );
}

export function validOAuthProfileId(profileId: string): boolean {
  try {
    oauthProfilePath("/", profileId);
    return true;
  } catch {
    return false;
  }
}
