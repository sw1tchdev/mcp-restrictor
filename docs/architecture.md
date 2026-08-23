# Architecture

## The boundary in one picture

```text
Client
  | JSON-RPC over STDIO or HTTP(S)
  v
MCP Restrictor
  | JSON-RPC over STDIO, HTTP, SSE, or WebSocket
  v
MCP server
```

For a managed HTTP route, the two transport legs are deliberately independent:

```text
Agent --HTTP loopback--> Restrictor --HTTPS--> upstream
```

The HTTPS upstream in this example is not an HTTPS downstream listener. This
HTTP-loopback-to-HTTPS-upstream composition is supported and expected.

In the official image the host and container addresses remain deliberately
different:

```text
Host agent
  -> http://127.0.0.1:17319/mcp/<client>/<route-id>
  -> Docker host-loopback publish
  -> Restrictor socket bound to 0.0.0.0 inside the bridge
  -> the route's independent STDIO, HTTP(S), SSE, or WebSocket upstream
```

The wildcard bind is transport plumbing, not a change to the advertised URL or
its Host/Origin validation. See [Docker deployment](./container.md) for the
exact publish boundary.

Restrictor is an MCP proxy, not a general client sandbox. It filters `tools/list` responses, independently authorizes well-formed `tools/call` requests, and rejects malformed calls. Client-native tools and non-MCP traffic are outside this boundary.

## Request flow

1. The client sends JSON-RPC to the selected downstream transport.
2. Restrictor records each outstanding request ID. A duplicate outstanding ID is rejected with a JSON-RPC invalid-request error; numeric and string IDs remain distinct.
3. A `tools/list` request is forwarded. Its successful response has only discoverable tools retained, while other response fields remain intact.
4. A well-formed `tools/call` is authorized against the policy. Allowed calls are forwarded; denied calls receive a JSON-RPC error with the original request ID.
5. Other JSON-RPC traffic is bridged to the upstream transport.

## What is enforced

Two operations are enforced:

- Discovery: `tools/list` responses are filtered by the policy's discovery decision.
- Invocation: every well-formed `tools/call` is independently authorized with its name and arguments, including calls for tools that appeared in discovery.

Malformed JSON-RPC is rejected. A malformed `tools/call` is not forwarded. The policy decision for each well-formed invocation is emitted as an audit event.

## What passes through

Restrictor does not content-filter all MCP traffic. Prompts, resources, other methods, notifications, tool results, and upstream errors pass through without content filtering. STDIO diagnostics from the upstream are also passed to the proxy's error stream without content filtering.

For `tools/list`, only a successful response's `tools` array is filtered; pagination and other result metadata pass through. An upstream request is not mistaken for a response merely because it uses the same request ID.

## Transport composition

The CLI can accept STDIO, HTTP, or HTTPS downstream traffic. It connects to one configured upstream over STDIO, Streamable HTTP, SSE, or WebSocket. The bridge creates the same message filter between the chosen downstream and upstream transports, so policy behavior does not depend on the transport pair.

Direct HTTP and HTTPS listeners are loopback-only. HTTPS requires a certificate
and key. The managed gateway also defaults to loopback; its exact
`--bind 0.0.0.0` override changes the socket bind while retaining the
advertised loopback origin and validation. The HTTP proxy validates Host and
Origin for the advertised listener address.

`mcp-restrictor run` is the managed multi-route form. It advertises
`127.0.0.1`, puts all destinations on one configured port with different exact
derived paths, and constructs a separate policy authorizer, upstream transport,
legacy session map, active bridge set, session namespace, audit identity, and
lifecycle for each path. Unknown paths, path aliases, and cross-route session
IDs are rejected. It preflights the complete startup snapshot before binding,
so one invalid route prevents any listener; it does not hot-reload route
changes.

## Sessions and protocol versions

Legacy HTTP clients establish an MCP session. Each legacy session has its own downstream transport, bridge, and upstream transport; closing the session closes its upstream.

Sessionless MCP `2026-07-28` HTTP requests use a per-request downstream transport and a new upstream transport for that request. This preserves sessionless behavior rather than creating a shared session. Other modern revisions are rejected by the HTTP listener.

During initialization, the bridge adopts the upstream protocol version for both transport ends. Restrictor does not translate one protocol era into another: a modern client is not converted for a legacy-only upstream.

## Audit output and errors

The CLI writes one JSON line to standard error for each well-formed `tools/call`, with an ISO timestamp, `action: "tool.call"`, tool name, `ALLOW` or `DENY` decision, and an optional reason. A policy denial returns JSON-RPC code `-32001`; duplicate outstanding request IDs return `-32600`.

Protocol-level upstream errors are passed through as received. Transport failures are reported through the proxy error handler; remote upstream connection and request errors are redacted before that handler receives them.

## Package responsibilities

- `@mcp-restrictor/core` owns JSON-RPC message filtering, duplicate-ID tracking, tool discovery filtering, invocation authorization, and audit-event types.
- `@mcp-restrictor/policy` parses and validates YAML policy, then creates the authorizer used by core.
- `@mcp-restrictor/transports` composes the core filter with STDIO and HTTP(S) proxy transports and selected upstream transports.
- `@mcp-restrictor/cli` parses command-line configuration, loads policy, selects the transport, and writes audit and operational output.

These are current repository responsibilities, not a promise of a stable embedding SDK contract.

## Design limits

Restrictor controls MCP messages that traverse this proxy only. It cannot restrict tools built into a client, direct connections that bypass it, or behavior inside an allowed upstream tool. It filters tool discovery and invocations; it does not inspect or sanitize prompt, resource, notification, or tool-result content.
