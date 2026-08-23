# Security

## Security model

MCP Restrictor is a policy-enforcing MCP proxy. Its boundary is the MCP traffic
that traverses the proxy, as described in [the architecture](./docs/architecture.md).
It is not a general client sandbox, a data-loss-prevention system, or an
operating-system isolation boundary.

## Trusted components

The user trusts the Restrictor executable, its policy, its wrapper and client
configuration, the current OS account, and the configured upstream server. The
upstream server's own permissions and its handling of allowed tool calls remain
outside Restrictor's control.

For the official image, the Docker daemon, host root/Docker administrators,
the image entrypoint, and the paired state/key volumes are also trusted.

## Untrusted inputs

Downstream JSON-RPC messages and upstream tool metadata are untrusted. The
proxy treats `tools/list` and `tools/call` as security-sensitive data. Upstream
tool results and errors, other MCP methods and content, and upstream STDIO
diagnostics are not sanitized by Restrictor.

## What Restrictor guarantees

- For MCP traffic that reaches this proxy, successful `tools/list` responses
  are filtered and every well-formed `tools/call` is independently authorized.
- Malformed JSON-RPC framing and malformed security-sensitive `tools/list` or
  `tools/call` data fail closed rather than being forwarded as authorization
  decisions.
- Direct HTTP and HTTPS listeners bind only to loopback addresses and validate
  Host and Origin for the listener address. Managed `run` defaults to loopback;
  its exact container bind override retains the advertised loopback origin and
  validation.
- Downstream `Authorization` and arbitrary request headers are not forwarded
  to HTTP or HTTPS upstreams. Upstream credentials are configured separately.

## What Restrictor does not guarantee

Restrictor does not sandbox clients or upstream tools, provide DLP,
authenticate downstream clients, authenticate an upstream on their behalf
beyond the configured upstream mechanism, rate-limit calls, or perform
semantic path authorization. It has no JWT support, mTLS, custom CA trust-store
management, policy hot reload, protocol translation, or automatic credential
cleanup. The container bind override can make managed HTTP reachable through a
Docker bridge; it does not turn that listener into an authenticated remote
service.

Client-native tools, direct upstream connections, non-MCP traffic, prompt and
resource content, notifications, tool results, and allowed upstream behavior
are outside the policy boundary. See [Policy limitations](./docs/policy.md#security-limitations).

## Deployment checklist

- Protect the policy file, wrapper command, client configuration, and secret
  sources from untrusted modification and reading.
- Give the upstream server only the permissions and credentials it needs.
- Keep loopback listeners local. Host and Origin validation are browser and
  DNS-rebinding defenses, not client authentication; any local process that can
  reach the port may invoke policy-allowed tools.
- For Docker, publish only the selected host-loopback mapping documented in the
  [container guide](./docs/container.md). Do not use host networking or expose
  the managed listener on a public interface.
- Use HTTPS for non-loopback HTTP or SSE upstreams, and WSS for WebSocket
  upstreams, when custom headers or upstream credentials are configured.
- Keep protocol output on stdout and treat diagnostics on stderr as unsanitized
  operational output.

## Credentials and backups

OAuth profiles encrypt credentials and discovery state, while clear metadata is
authenticated with the ciphertext. This does not encrypt client configurations,
environment or file secret sources, or backups, and it does not protect against
compromise of the same OS account. Profiles, master keys, and backups are
retained; credential revocation and cleanup are the user's responsibility. In
Docker, root and Docker administrators can read both volumes and the running
environment, including upstream secret values. See [OAuth](./docs/oauth.md)
for the profile lifecycle and key-file rules.

## Network boundary

The direct HTTP and HTTPS listeners are loopback-only. The managed
`mcp-restrictor run` gateway advertises HTTP on `127.0.0.1`; the official image
binds its socket to `0.0.0.0` inside the Docker bridge and relies on the exact
host-only publish `127.0.0.1:17319:17319`. Docker does not prevent an operator
from publishing it more broadly. The gateway has no downstream authentication.
Route paths are identifiers, not credentials. Any process or container peer
that can reach the port can invoke policy-allowed tools.

Managed `run` does not provide downstream HTTPS termination, daemon or service
management, socket activation, hot reload, or custom paths.
Direct `--listen-https` remains available and requires a certificate and key.

HTTPS upstream certificate verification remains enabled through Node's trust
configuration. A private CA can be added with Node's `NODE_EXTRA_CA_CERTS` for
setup and `run`; Restrictor does not manage a trust store or implement mTLS.
Managed route definitions are private files under
`$HOME/.mcp-restrictor/routes/`, one per destination. They are not encrypted and
do not hide route metadata, environment-variable names, or an optional master-key
file path. They do not store resolved credential values. Restrictor does not
translate between MCP protocol eras.

## Container boundary

State and OAuth key volumes are a paired, local-filesystem contract. They must
not be shared between independent state roots or placed on NFS/network storage;
the entrypoint and transactions depend on local `flock`, hard links, and atomic
rename. The image validates private ownership and modes, but cannot defend
against a compromised Docker daemon or host root.

The container key file replaces native OS-keyring storage only inside the
official image workflow. It remains plaintext key material with mode `0600` in
the separate key volume. Upstream header and bearer values remain environment
values: route files store their names, while Docker administrators can inspect
the resolved values.

Run mutating operations such as `setup` and `oauth login` only through a new
official-image container after stopping the service. `docker exec` bypasses
the entrypoint's global lock and is unsupported for those operations.
Generated presets never edit host configuration; Restore cannot remove a
fragment that was pasted into a host file. Backup both volumes together while
stopped and follow the
[container recovery procedure](./docs/container.md#oauth-in-containers) if the
master key is lost.

## Policy limitations

Policy filters tool discovery and tool invocation only. It evaluates direct
tool arguments; it does not canonicalize filesystem paths, inspect nested
arguments or other content, or constrain behavior inside an allowed tool. Read
the full [policy reference](./docs/policy.md), especially its security
limitations, before using a condition as a security control.

## Reporting a vulnerability

Do not publish exploit details in a public issue. Use GitHub's
[private vulnerability reporting](https://github.com/sw1tchdev/mcp-restrictor/security/advisories/new)
and include the affected version, reproduction, and impact.
