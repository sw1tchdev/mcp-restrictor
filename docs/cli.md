# CLI reference

Install `@mcp-restrictor/cli` with Node.js 22 or newer:

```bash
npm install --global @mcp-restrictor/cli
mcp-restrictor setup
```

Run setup from the project you intend to configure so it derives the correct
project root. See [interactive setup](./setup.md), the [policy
reference](./policy.md), and the [security model](../SECURITY.md). For the
official image, use the [Docker deployment guide](./container.md).

## Commands

The proxy command is the default command. `mcp-restrictor run` serves every
installed managed HTTP route. `mcp-restrictor setup` starts the interactive
wrapper and policy setup. `mcp-restrictor oauth login PROFILE_ID` reauthorizes
an existing OAuth profile. Client adapters are managed with
`mcp-restrictor client install NPM_SPEC`, `client list`, and
`client remove PACKAGE_NAME`.

<a id="managed-http-routes"></a>

## Managed HTTP routes

Manual setup can install native HTTP entries for Claude Code, Codex, and
OpenCode, including generated presets. Serve native-host routes with:

```bash
mcp-restrictor run
```

The official container uses the only supported bind override:

```bash
mcp-restrictor run --bind 0.0.0.0
```

No other bind value, duplicate `--bind`, IPv6 wildcard, or extra argument is
accepted. `run` stays in the foreground and otherwise binds one HTTP listener
to the advertised `127.0.0.1` host. `--bind 0.0.0.0` changes only the socket
bind address so Docker bridge traffic can reach it; stored client URLs and
Host/Origin validation remain loopback-based.

New setups default to port `17319`. Existing routes retain their stored port,
and all route files must use the same origin and port. Each destination has a
different exact path and an independent policy, upstream transport, legacy
session map, active bridge set, audit identity, and lifecycle. For example:

```text
Agent --HTTP loopback--> Restrictor --HTTPS--> upstream
http://127.0.0.1:17319/mcp/claude/<route-id>
http://127.0.0.1:17319/mcp/codex/<different-route-id>
```

HTTP on the client-to-Restrictor loopback leg and HTTPS on the
Restrictor-to-upstream leg is supported and expected. Upstream TLS and
authentication do not add downstream authentication.

Unknown paths, trailing-slash variants, dot or encoded aliases, and a session
ID issued by another route are rejected. Route paths are identifiers, not
credentials.

At startup, `run` loads all private one-file-per-destination definitions from
`$HOME/.mcp-restrictor/routes/` and preflights every route before binding. Any
invalid policy, missing required environment variable, invalid OAuth binding,
or invalid route prevents the shared listener from opening; there is no partial
bind. The loaded routes are a startup snapshot with no hot reload. Restart
`run` and affected clients after setup or Restore.

Launch `run` with every environment variable named by its upstream routes,
including STDIO variables, header variables, and bearer-token variables. OAuth
profiles must remain readable through the same OS keyring or configured master
key file used by setup. When setup recorded a master-key file path, the route
supplies that path but the file must still exist and be readable. If an HTTPS
upstream uses a private CA, provide Node's `NODE_EXTRA_CA_CERTS` to both setup
and `run`; certificate verification remains enabled.

Managed `run` provides no HTTPS listener, daemon or service management, socket
activation, hot reload, or custom route path. Route paths are identifiers, not
secrets. Direct single-route invocation remains available, including
`--listen-https` with an explicit certificate and key as described below.
The container publishes the stored port only to host loopback while binding
the process wildcard inside the bridge; see the [Docker guide](./container.md)
for the exact command and security boundary.

## Proxy command

Every proxy invocation requires `--policy FILE` (or `-p FILE`) and exactly one
upstream selector: one of `--upstream-http URL`, `--upstream-sse URL`,
`--upstream-websocket URL`, or a STDIO command after `--`. Remote selectors are
mutually exclusive, and a command cannot be combined with a remote selector.

```bash
# STDIO downstream to STDIO upstream
mcp-restrictor -p ./policy.yaml -- node ./server.mjs

# STDIO downstream to Streamable HTTP(S), SSE, or WebSocket upstream
mcp-restrictor --policy ./policy.yaml --upstream-http https://mcp.example.com/mcp
mcp-restrictor --policy ./policy.yaml --upstream-sse https://mcp.example.com/events
mcp-restrictor --policy ./policy.yaml --upstream-websocket wss://mcp.example.com/mcp
```

## Downstream listeners

Without a listener, the downstream is STDIO. Use `--listen-http URL` for an
HTTP listener or `--listen-https URL` for HTTPS. The two listener options are
mutually exclusive and both bind only to `127.0.0.1`, `localhost`, or `::1`.
`--listen-https` requires both `--tls-cert FILE` and `--tls-key FILE`; those
TLS options are invalid without it. Port `0` selects an available port and the
effective URL is written to standard error.

```bash
# HTTP listener to a STDIO upstream
mcp-restrictor -p ./policy.yaml --listen-http http://127.0.0.1:3000/mcp -- node ./server.mjs

# HTTPS listener to a Streamable HTTP upstream
mcp-restrictor -p ./policy.yaml --listen-https https://127.0.0.1:3443/mcp \
  --tls-cert ./cert.pem --tls-key ./key.pem --upstream-http https://mcp.example.com/mcp
```

## Upstream transports

`--upstream-http` accepts `http:` or `https:` Streamable HTTP URLs;
`--upstream-sse` accepts HTTP(S) SSE URLs; `--upstream-websocket` accepts
`ws:` or `wss:` URLs. Remote URLs cannot contain userinfo, a query string, or
a fragment. HTTP fetches reject redirects. HTTPS certificate verification uses
Node's trust configuration and remains enabled.

## Headers and authentication

Use repeatable `--upstream-header-env HEADER=ENV_NAME` to pass a header value
from the named environment variable. `--upstream-header-base64url-env
HEADER=ENV_NAME` does the same after decoding canonical unpadded base64url
UTF-8. `--upstream-bearer-token-env ENV_NAME` supplies bearer authentication;
the argument is an environment name, never the secret value.

Headers or authentication require HTTPS/WSS unless the remote URL is a
validated loopback address. Use `--upstream-oauth-profile PROFILE_ID` to select
exactly one existing OAuth profile for an HTTP or SSE upstream. OAuth and
bearer-token options are mutually exclusive and neither supports WebSocket;
use an environment-backed header for WebSocket authentication instead. See
[OAuth](./oauth.md).

## STDIO process environment

For a STDIO upstream only, repeat `--upstream-env ENV_NAME` to pass selected
environment variables to the child process. Missing selected variables fail
startup. `--upstream-cwd DIRECTORY` sets that process's working directory.
Neither option can be used with a remote upstream. The upstream command and
arguments follow `--` and are started directly, without a shell.

## OAuth login

`mcp-restrictor oauth login PROFILE_ID` performs interactive reauthorization
for the existing profile. The profile remains bound to its configured server
and resource; it does not create a policy or change wrapper arguments. OAuth
profiles work with HTTP and SSE, not STDIO or WebSocket. See the [OAuth
guide](./oauth.md) for login, encryption, and retention details.

When both input and output are TTYs, the authorization confirmation and pasted
redirect prompts use inline Ink screens. The authorization URL remains visible,
while the redirect field displays only the fixed `<hidden>` marker. Escape,
Ctrl-C, EOF, or an external abort cancels before the profile is published.

With TTY input and redirected output, confirmation keeps its line prompt and
the redirect uses the existing raw, no-echo reader. With fully non-TTY streams,
the default OAuth reader rejects secret input; programmatic callers can inject
a reader. These fallbacks emit no Ink UI.

## Client adapters

`mcp-restrictor client install NPM_SPEC` installs a trusted external client
adapter after confirmation. `client list` shows installed adapters and
`client remove PACKAGE_NAME` removes one. Adapters execute with your user
permissions; install only packages you trust.

Client installation confirmation uses an inline Ink selector only when both
input and output are TTYs. Otherwise it retains the line-based yes/no prompt;
EOF cancels before package installation starts.

## Manual output

The default Manual result, **Show configuration only**, writes its Manual
policy (and, when selected, a saved policy or encrypted OAuth profile), then
prints JSON-safe `command`, `args`, and `environment` values for copying into
another client. Each value after a label is JSON-encoded:

They are separate wrapper fields, not one JSON document or a complete native
client configuration.

```text
Setup complete.
command: "mcp-restrictor"
args: ["--policy","/project/.mcp-restrictor/policies/manual/files.yaml","--upstream-env","API_KEY","--","node","server.mjs"]
environment: {"inherit":["API_KEY"],"set":{}}
```

When Manual installs into selected existing client configurations, its final
result instead prints changed file paths, backup locations, and client
completion messages. It does not print generic `command`, `args`, or
`environment` values. See [manual setup](./setup.md#manual-setup) for
Destination, eligibility, transaction, and Restore MCP behavior.

## Exit, diagnostics, and audit events

MCP protocol messages use standard output. Operational diagnostics and upstream
STDIO diagnostics use standard error, so do not merge that output into the
protocol stream. Each well-formed `tools/call` emits one JSON line on standard error:

```text
{"time":"2026-08-18T00:00:00.000Z","action":"tool.call","tool":"read_file","decision":"ALLOW"}
```

Denied calls use `"decision":"DENY"` and may include `"reason"`. A normal
listener shutdown sets exit status 0; command errors set a nonzero status.
