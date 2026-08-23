const reservedCallbackParameters = new Set([
  "code",
  "state",
  "iss",
  "error",
  "error_description",
  "error_uri",
]);

export const MAX_TCP_PORT = 65_535;
export const DEFAULT_OAUTH_CALLBACK_PATH = "/callback";
export const OAUTH_LOCALHOST = "localhost";
export const OAUTH_IPV4_LOOPBACK_HOST = "127.0.0.1";
export const OAUTH_IPV6_LOOPBACK_HOST = "::1";

export function canonicalUrl(value: string): string {
  return new URL(value).href;
}

export function canonicalOptionalUrl(value: string | undefined): string | undefined {
  return value === undefined ? undefined : canonicalUrl(value);
}

export function isReservedOAuthCallbackParameter(name: string): boolean {
  return reservedCallbackParameters.has(name);
}

export function isExactLoopbackHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return (
    host === OAUTH_LOCALHOST ||
    host === OAUTH_IPV4_LOOPBACK_HOST ||
    host === OAUTH_IPV6_LOOPBACK_HOST
  );
}
