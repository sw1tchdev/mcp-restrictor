import type { FetchLike } from "@modelcontextprotocol/client";
import { fetchWithoutRedirects } from "@mcp-restrictor/transports";

export function cleanOAuthFetch(fetchFn: FetchLike, signal: AbortSignal): FetchLike {
  return fetchWithoutRedirects((url, init) => fetchFn(url, { ...init, signal }));
}
