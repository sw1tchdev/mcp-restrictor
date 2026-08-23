# MCP Restrictor

MCP Restrictor is a default-deny proxy that limits which MCP tools a client can discover and call. Only MCP traffic passing through Restrictor is controlled; client-native tools, direct upstream connections, and non-MCP traffic remain outside its boundary.

## Why MCP Restrictor

An MCP server can expose more tools than an agent needs. Restrictor sits between the client and server, filters `tools/list`, and independently checks every well-formed `tools/call` against a YAML policy. A hidden tool therefore cannot be invoked directly by name.

Restrictor bridges existing MCP servers without modifying them. Interactive setup can wrap supported entries already configured in Claude Code, Codex, or OpenCode. Manual setup defaults to portable wrapper details, or can add a Manual upstream to explicitly selected existing client configurations over STDIO or managed loopback HTTP.

## Install

The published container is the shortest path to a persistent managed HTTP
gateway:

```bash
docker pull ghcr.io/sw1tchdev/mcp-restrictor:latest

docker run --rm -it \
  -v mcp-restrictor-state:/home/restrictor/.mcp-restrictor \
  -v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key \
  ghcr.io/sw1tchdev/mcp-restrictor:latest \
  setup

docker run -d \
  --name mcp-restrictor \
  --init \
  --restart unless-stopped \
  -p 127.0.0.1:17319:17319 \
  -v mcp-restrictor-state:/home/restrictor/.mcp-restrictor \
  -v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key \
  ghcr.io/sw1tchdev/mcp-restrictor:latest \
  run --bind 0.0.0.0
```

Generated Claude Code, Codex, and OpenCode presets can be copied into host
client configuration. Read the [Docker deployment guide](./docs/container.md)
before adding upstream credentials, changing ports, using OAuth, or backing up
the paired volumes.

For native use, install the CLI with Node.js 22 or newer:

```bash
npm install --global @mcp-restrictor/cli
mcp-restrictor setup
```

See the [CLI reference](./docs/cli.md) for command details.

## Quick start

Start the five-minute interactive setup from the project you want to configure:

```bash
cd /path/to/project
mcp-restrictor setup
```

1. Choose **Add MCP** and a supported client, or choose **Manual upstream** on its own.
2. For Claude Code, Codex, or OpenCode, select existing MCP server entries. For Manual, enter upstream details, choose **Destination**, then choose existing configurations or generated client presets. Choose a local STDIO or HTTP connection where setup offers one; generated presets always use managed HTTP.
3. Choose Tools & Policy per imported entry or Manual destination.
4. Confirm the connection and discovered tools.
5. Review the plan and confirm **Apply**.

Setup runs as one temporary fullscreen interaction. Restart affected clients after setup or Restore. If any Manual destination uses HTTP, keep `mcp-restrictor run` running in the foreground and restart it after setup or Restore. For controls, discovery paths, unsupported entries, and restore behavior, read [Interactive setup](./docs/setup.md).

## Choose Tools & Policy

Tools & Policy is a reusable tool policy, separate from connection details and OAuth credentials.

| Choice            | What it does                                                            |
| ----------------- | ----------------------------------------------------------------------- |
| `Current`         | Keeps an already managed entry and skips discovery.                     |
| A saved name      | Installs the selected saved policy after discovering the current tools. |
| `Existing policy` | Installs the exact unowned policy already at the target path.           |
| `Configure new`   | Discovers tools, generates a default-deny allowlist, and can save it.   |

See [Interactive setup](./docs/setup.md#tools--policy-choices) for exact availability and replacement behavior.

## Supported clients

This **setup-import matrix** describes existing client entries that interactive setup can wrap. Manual is entered directly; installation renders either a local STDIO wrapper or, where supported, a native HTTP entry into each selected existing client configuration.

| Upstream transport | Claude Code | Codex                   | OpenCode                | Manual |
| ------------------ | ----------- | ----------------------- | ----------------------- | ------ |
| STDIO              | Yes         | Yes                     | V1 and V2               | Yes    |
| Streamable HTTP    | Yes         | Yes                     | V1 and V2               | Yes    |
| Legacy SSE         | Yes         | No native configuration | V1 typed fallback only  | Yes    |
| WebSocket          | Yes         | No native configuration | No native configuration | Yes    |

External client adapters are supported and execute with the user's permissions; install only adapters you trust. There are no proxy extension hooks.

<a id="run"></a>

## Supported transports

This **runtime transport matrix** describes the proxy bridge, independently of what each built-in setup adapter can import.

| Downstream | STDIO upstream | Streamable HTTP(S) upstream | SSE upstream | WebSocket upstream |
| ---------- | -------------- | --------------------------- | ------------ | ------------------ |
| STDIO      | Yes            | Yes                         | Yes          | Yes                |
| HTTP       | Yes            | Yes                         | Yes          | Yes                |
| HTTPS      | Yes            | Yes                         | Yes          | Yes                |

Direct HTTP and HTTPS listeners are loopback-only. Managed routes advertise
one foreground `mcp-restrictor run` HTTP listener on `127.0.0.1`, with a
different derived path and independent policy, session, and upstream per
destination. The official image uses the exact `--bind 0.0.0.0` override only
inside its Docker bridge while publishing the host port to loopback. A
client-to-Restrictor HTTP connection with a Restrictor-to-upstream HTTPS
connection is supported and expected. For lifecycle, selectors, TLS,
authentication, and complete examples, see the [CLI reference](./docs/cli.md)
and [Docker guide](./docs/container.md).

## Policy in one minute

```yaml
version: 1
default: deny
tools:
  allow:
    - name: read_file
    - name: write_file
      conditions:
        - argument: path
          operator: startsWith
          value: /workspace/
  deny:
    - name: delete_file
```

A matching deny wins, then a matching allow, then `default`. Conditions support `equals`, `startsWith`, and `regex` on direct properties of the tool's `arguments` object. Read the [policy reference](./docs/policy.md) before treating argument conditions as a security control.

## What setup changes

For a selected existing server, setup preserves its name, scope, and supported client controls, then replaces it with a Restrictor STDIO wrapper. Manual copy-only setup writes its Manual policy and prints wrapper values. Manual installation adds a new native STDIO or HTTP entry to selected existing client configurations, with an independent policy and restore state for each target. All selected Manual destinations apply and verify as one transaction; a failure leaves no partial installation.

Apply is transactional: setup checks for concurrent edits, backs up replaced files, verifies the installed wrapper, and rolls back on failure. **Restore MCP** restores selected managed client entries while preserving unrelated edits; saved policies, OAuth profiles, master keys, and backups are retained. See [What setup changes](./docs/setup.md#what-setup-changes) and [OAuth](./docs/oauth.md).

## Security at a glance

- Restrictor filters successful `tools/list` responses and authorizes every well-formed `tools/call` that passes through it.
- Resource and prompt policy enforcement is not implemented; those methods pass through without content filtering, as do notifications, tool results, upstream errors, and other methods.
- Downstream credentials are not forwarded upstream. Upstream credentials are configured separately.
- Loopback listeners do not authenticate local clients. Any local process that can reach one may invoke policy-allowed tools.
- Restrictor is not a client sandbox, DLP system, operating-system isolation boundary, or substitute for least-privilege upstream credentials.

Read the complete [security model](./SECURITY.md) and [architecture boundary](./docs/architecture.md) before deploying Restrictor across a trust boundary.

## Documentation

- [Interactive setup](./docs/setup.md) — add, apply, backup, rollback, and restore workflows.
- [CLI reference](./docs/cli.md) — commands, transports, listeners, and authentication options.
- [Policy reference](./docs/policy.md) — YAML schema, evaluation order, conditions, and limitations.
- [OAuth](./docs/oauth.md) — profile lifecycle, reauthorization, key storage, and cleanup responsibility.
- [Docker deployment](./docs/container.md) — image setup, generated presets, persistence, hardening, backup, and recovery.
- [Architecture](./docs/architecture.md) — proxy boundary, request flow, sessions, and package responsibilities.
- [Security](./SECURITY.md) — guarantees, non-guarantees, deployment guidance, and vulnerability reporting.

## Project status

MCP Restrictor implements policy enforcement for `tools/list` and `tools/call` across the runtime transport matrix above, with interactive setup for the listed clients.

Every well-formed `tools/call` produces a JSON audit decision on standard error. There is no shadow or audit-only policy mode.

Resource and prompt policy enforcement is not implemented; those methods pass through. There are no proxy extension hooks, although external client adapters are supported. There is no documented stable embedding SDK contract.

## Development

```bash
pnpm install --frozen-lockfile
pnpm build
pnpm test
pnpm typecheck
pnpm lint
pnpm format:check
```

The repository uses Node.js 22 or newer and pnpm 9.

## License and security reports

MCP Restrictor is available under the [MIT License](./LICENSE). Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/sw1tchdev/mcp-restrictor/security/advisories/new), not a public issue. See [SECURITY.md](./SECURITY.md) for reporting details.
