import { extractWWWAuthenticateParams } from "@modelcontextprotocol/client";
import type { UpstreamConfig } from "@mcp-restrictor/transports";
import { cleanOAuthFetch } from "../../oauth/fetch.js";
import { secureOAuthUrl } from "../../oauth/login/discovery.js";
import { ABORT_ERROR_NAME } from "../../utils/async.js";

const INVALID_OAUTH_CHALLENGE_MESSAGE = "OAuth challenge is invalid";

export class OAuthChallengeRequired extends Error {
  constructor(
    readonly resourceMetadataUrl: string,
    readonly scope?: string,
  ) {
    super("OAuth authorization is required");
  }
}

export async function probeSseChallenge(
  upstream: Extract<UpstreamConfig, { kind: "sse" }>,
  signal: AbortSignal,
): Promise<void> {
  const headers = new Headers(upstream.headers?.map(([name, value]) => [name, value]));
  headers.set("Accept", "text/event-stream");
  let response: Response;
  try {
    response = await cleanOAuthFetch((url, init) => fetch(url, init), signal)(upstream.url, {
      headers,
    });
  } catch (error) {
    if (isAbort(error, signal)) throw error;
    throw new Error("SSE challenge probe failed");
  }
  try {
    if (response.status === 200) return;
    if (response.status === 401 || response.status === 403) throwOAuthChallenge(response);
    throw new Error(`SSE challenge probe failed (status ${response.status})`);
  } finally {
    await response.body?.cancel().catch(() => undefined);
  }
}

export function challengeProbeUpstream(upstream: UpstreamConfig): UpstreamConfig {
  if (upstream.kind !== "http" && upstream.kind !== "sse") return upstream;
  const challenge = (response: Response) => {
    if (response.status === 403) throwOAuthChallenge(response);
  };
  return {
    ...upstream,
    authProviderFactory: () => ({
      token: async () => undefined,
      onUnauthorized: async ({ response }) => throwOAuthChallenge(response),
    }),
    validateResponse: challenge,
  };
}

export function isAbort(error: unknown, signal: AbortSignal): boolean {
  return (
    (signal.aborted && error === signal.reason) ||
    (error instanceof Error && error.name === ABORT_ERROR_NAME)
  );
}

function throwOAuthChallenge(response: Response): never {
  const header = response.headers.get("WWW-Authenticate");
  const bearer = header && bearerChallenge(header);
  if (!bearer) throw new Error(INVALID_OAUTH_CHALLENGE_MESSAGE);
  const isolated = new Response(null, { headers: { "WWW-Authenticate": bearer } });
  const values = extractWWWAuthenticateParams(isolated);
  if (!values.resourceMetadataUrl) throw new Error(INVALID_OAUTH_CHALLENGE_MESSAGE);
  const url = secureChallengeUrl(values.resourceMetadataUrl);
  const scope = values.scope;
  if (scope !== undefined && !validScope(scope)) {
    throw new Error(INVALID_OAUTH_CHALLENGE_MESSAGE);
  }
  throw new OAuthChallengeRequired(url.href, scope);
}

function bearerChallenge(header: string): string | undefined {
  const parts = splitOutsideQuotes(header);
  if (!parts) return undefined;
  const challenges: string[] = [];
  for (const part of parts) {
    const value = part.trim();
    if (!value) return undefined;
    if (startsAuthenticationChallenge(value)) challenges.push(value);
    else if (challenges.length) challenges[challenges.length - 1] += `, ${value}`;
    else return undefined;
  }
  const bearer = challenges.filter((value) => /^Bearer(?:[ \t]+|$)/i.test(value));
  if (bearer.length !== 1) return undefined;
  const parameters = bearer[0]!.replace(/^Bearer[ \t]+/i, "");
  return validUniqueAuthParameters(parameters) ? `Bearer ${parameters}` : undefined;
}

function splitOutsideQuotes(value: string): string[] | undefined {
  const parts: string[] = [];
  let start = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]!;
    if (quoted && escaped) {
      escaped = false;
      continue;
    }
    if (quoted && character === "\\") {
      escaped = true;
      continue;
    }
    if (character === '"') quoted = !quoted;
    else if (!quoted && character === ",") {
      parts.push(value.slice(start, index));
      start = index + 1;
    }
  }
  if (quoted || escaped) return undefined;
  parts.push(value.slice(start));
  return parts;
}

function startsAuthenticationChallenge(value: string): boolean {
  const match = /^([!#$%&'*+\-.^_`|~0-9A-Za-z]+)([ \t]+|$)/.exec(value);
  if (!match) return false;
  return !value.slice(match[0].length).trimStart().startsWith("=");
}

function validUniqueAuthParameters(value: string): boolean {
  const parameters = splitOutsideQuotes(value);
  if (!parameters) return false;
  const names = new Set<string>();
  for (const parameter of parameters) {
    const match =
      /^[ \t]*([!#$%&'*+\-.^_`|~0-9A-Za-z]+)[ \t]*=[ \t]*("(?:\\[\t !-~\x80-\xff]|[\t !#-\u005B\]-~\x80-\xff])*"|[!#$%&'*+\-.^_`|~0-9A-Za-z]+)[ \t]*$/.exec(
        parameter,
      );
    if (!match) return false;
    const name = match[1]!.toLowerCase();
    if (names.has(name)) return false;
    names.add(name);
  }
  return parameters.length > 0;
}

function secureChallengeUrl(value: URL): URL {
  try {
    return secureOAuthUrl(value);
  } catch {
    throw new Error(INVALID_OAUTH_CHALLENGE_MESSAGE);
  }
}

function validScope(value: string): boolean {
  return (
    value.length > 0 &&
    value.split(" ").every((token) => token.length > 0 && /^[\x21\x23-\x5B\x5D-\x7E]+$/.test(token))
  );
}
