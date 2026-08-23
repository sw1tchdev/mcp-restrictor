# Interactive setup

`mcp-restrictor setup` wraps supported MCP entries that already exist in a
supported client configuration. **Manual upstream** defaults to copyable
wrapper details, can add a new Manual wrapper to explicitly selected existing
client configurations, or can create private generated presets for Claude
Code, Codex, and OpenCode when a host configuration is not available.

## Before you start

- Run setup from an interactive terminal (TTY) with `mcp-restrictor` available
  on `PATH`.
- Run it from the project you intend to configure. Setup uses the Git top-level
  directory as the project root; outside a Git work tree, it uses the current
  working directory.
- Existing client entries must be supported by their adapter. Unsupported
  entries are listed and left unchanged.

For the official image, paired volumes, generated presets, and the required
stop-setup-restart lifecycle, follow the [Docker deployment guide](./container.md).

For remote OAuth upstreams, setup may perform interactive login. Tools & Policy
and OAuth profiles are separate: a saved Tools & Policy contains only policy,
not connection details or credentials. See [OAuth](./oauth.md) for its
supported transports, profile lifecycle, and key storage.

## Add MCP in five steps

1. Run `mcp-restrictor setup`, select **Add MCP**, then choose Claude Code,
   Codex, OpenCode, or **Manual upstream**. Manual must be chosen on its own.
2. For a client, setup searches its existing configuration and lists supported
   MCP entries by client, scope, transport, and file. Select the entries to
   wrap. For Manual, enter upstream details, choose **Destination**, select
   existing configurations or **Generate client presets**, then choose a local
   STDIO or HTTP client connection where setup offers one. Generated presets
   always use managed HTTP.
3. Choose **Tools & Policy** per imported entry or Manual destination. The table
   below defines each choice exactly.
4. Confirm the upstream connection. Setup resolves the selected client entry,
   discovers its tools when needed, and performs the requested OAuth flow.
5. Review the preview and confirm **Apply**. Setup writes the wrapper, policy,
   route, generated preset, and required state as one verified transaction.
   Manual copy-only mode prints portable values; Manual installation writes
   every selected destination in that same all-or-nothing transaction.

## Fullscreen controls

With both standard input and output attached to TTYs, setup is one temporary
fullscreen interaction: each screen replaces the previous one, and after setup
exits only the final result remains in the terminal history. The public setup
command requires both TTY streams; it does not fall back to a line-based
interactive mode.

| Key        | Behavior                                                                                                    |
| ---------- | ----------------------------------------------------------------------------------------------------------- |
| Arrow keys | Move the active item. On Yes/No confirmation, select `No` with Up or Down.                                  |
| Space      | Toggle the active checkbox.                                                                                 |
| `a`        | Select all normal checkbox choices, or clear them when all are selected.                                    |
| `i`        | Invert the normal checkbox choices.                                                                         |
| Enter      | Submit the active single choice, confirm a selection, or accept the highlighted `Yes` on Connect and Apply. |
| Escape     | Cancel setup from a selector or text field.                                                                 |
| Ctrl-C     | Cancel setup.                                                                                               |

The optional **Save Tools & Policy?** confirmation highlights `No`; choose
`Yes` explicitly to save. Screens that select a single action or a policy
source use arrows and Enter; Space, `a`, and `i` apply to checkbox lists.
EOF also cancels setup. Cancellation leaves setup writes unapplied.

Text fields support ordinary typing and terminal paste through Ink's paste
handling (`usePaste`). Use Left/Right or Home/End to move the cursor,
Backspace/Delete to edit, Ctrl-U to clear, and Enter to submit. Required-field
and value errors remain inline on the current screen. Pasted line breaks and
terminal control characters are rejected. Secret fields use the same controls
but display only an empty state or the fixed marker `<hidden>`; this prevents
the value and its length from appearing in the rendered UI, but is not
encryption.

## Tools & Policy choices

Tools & Policy is the reusable tool policy described in the
[policy reference](./policy.md). It is independent of upstream credentials and
connection details.

| Choice            | Appears when                                                                                           | Discovery occurs            | Tool selection occurs                                                                         |
| ----------------- | ------------------------------------------------------------------------------------------------------ | --------------------------- | --------------------------------------------------------------------------------------------- |
| `Current`         | The selected entry already points at Restrictor's expected managed policy path and that policy exists. | No; setup skips that entry. | No.                                                                                           |
| A saved name      | A saved Tools & Policy exists for the selected client, scope, and server name.                         | Yes.                        | No; its exact policy filters the discovered tools.                                            |
| `Existing policy` | The target policy path exists but is not the selected entry's managed policy.                          | Yes.                        | No; that exact policy filters the discovered tools.                                           |
| `Configure new`   | Always.                                                                                                | Yes.                        | Yes; select tools to generate a default-deny allowlist, then optionally save it under a name. |

When an unowned `Existing policy` is selected, setup uses its exact contents;
replacing it through `Configure new` first makes a backup. A saved name is
valid only for a valid policy file and is rechecked before applying changes.
Saved and Existing policies are installed byte-for-byte. They may use
`default: allow`, deny rules, or conditions; only `Configure new` generates a
default-deny allowlist.

## What setup changes

For a selected client entry, setup preserves its name, scope, and supported
client-specific controls, then replaces that entry with an STDIO Restrictor
wrapper. It installs the selected effective policy, records restore state for
managed client entries, and may write a saved policy or encrypted OAuth
profile. Only `Configure new` creates a default-deny generated policy from the
selected tools. Manual copy-only mode writes no client configuration; Manual
installation adds a new entry rather than replacing an existing one.

Wrapper arguments use policy and connection references with environment-variable
names, not token or header values. Imported literal headers can remain in the
wrapper environment, including reversible base64url values for WebSocket, so
protect client configuration. See the [policy reference](./policy.md) for
evaluation semantics and limitations.

## Configuration discovery

Setup reads the paths below when they exist. Environment-variable paths are
used as supplied; otherwise `$HOME` means the current user's home directory
and `$PROJECT_ROOT` is the Git root (or the current directory outside Git).

### Claude Code

| Scope   | Path                                                                                         |
| ------- | -------------------------------------------------------------------------------------------- |
| User    | `$CLAUDE_CONFIG_DIR/.claude.json`, or `$HOME/.claude.json` when `CLAUDE_CONFIG_DIR` is unset |
| Project | `$PROJECT_ROOT/.mcp.json`                                                                    |

### Codex

| Scope   | Path                                                                                |
| ------- | ----------------------------------------------------------------------------------- |
| User    | `$CODEX_HOME/config.toml`, or `$HOME/.codex/config.toml` when `CODEX_HOME` is unset |
| Project | `$PROJECT_ROOT/.codex/config.toml`                                                  |

### OpenCode

OpenCode searches both `opencode.json` and `opencode.jsonc` in these locations:

- user: `$HOME/.config/opencode/`;
- an explicit user location from `OPENCODE_CONFIG`, when set;
- project: `$PROJECT_ROOT` and every directory between it and the current
  working directory, plus each corresponding `.opencode/` directory.

If both `.json` and `.jsonc` exist in one searched location, that location is
ambiguous and is reported without modification. `OPENCODE_CONFIG_CONTENT` is
detectable inline configuration but is never writable. Remote organization- or
administrator-managed OpenCode sources are not fetched, copied, or changed.

## Supported imported entries

This is the **setup import** matrix: it says which existing client entries
setup can wrap. It is not the proxy's runtime transport matrix; the proxy can
bridge every listed upstream transport for its STDIO, HTTP, and HTTPS listeners
as documented in the [runtime matrix](../README.md#run).

| Existing entry  | Claude Code | Codex                   | OpenCode                | Manual |
| --------------- | ----------- | ----------------------- | ----------------------- | ------ |
| STDIO           | Yes         | Yes                     | V1 and V2               | Yes    |
| Streamable HTTP | Yes         | Yes                     | V1 and V2               | Yes    |
| Legacy SSE      | Yes         | No native configuration | V1 typed fallback only  | Yes    |
| WebSocket       | Yes         | No native configuration | No native configuration | Yes    |

OpenCode preserves the selected V1 or V2 shape; it does not migrate either
schema. Its JSONC edits replace only selected server ranges, preserving content
outside those ranges. Claude Code and Codex preserve supported controls while
their selected entry is wrapped. OAuth is supported only for HTTP and SSE
upstreams; see [OAuth](./oauth.md).

## Unsupported entries

Adapters report unsupported entries and leave their files untouched. Examples
include Claude Code `headersHelper`, unsupported/disabled fields, and WebSocket
URLs with `${...}` interpolation; Codex `auth = "chatgpt"`, native SSE or
WebSocket configuration, remote STDIO executors, and conflicting bearer/OAuth
configuration; and unsupported or disabled OpenCode entries.

Across adapters, remote URLs with credentials, query strings, or fragments are
not imported. OAuth and the dedicated bearer selector are unsupported for
WebSocket; an environment-backed header such as `Authorization` is supported.
OpenCode's inline content, ambiguous sibling `.json` and `.jsonc` files, and
remote organization or admin sources are reported rather than changed.

## Preview and Apply

Setup previews the upstream before connecting and shows a final plan containing
each client, server, scope, transport, configuration path, policy path, and
allowed tools. Confirm **Connect** before discovery and **Apply** before any
write. Do not edit a selected client configuration between the preview and
Apply: setup checks for drift and aborts rather than overwrite a changed file.

At Apply, setup rechecks saved policies and current snapshots, writes all
planned files in one transaction, then verifies each installed connection. A
failed write or verification rolls back the transaction.

## Backups and rollback

Before replacing an existing planned file, setup writes a private backup under:

```text
$HOME/.mcp-restrictor/backups/<sha256-of-backup-key>/<timestamp-and-nonce>/
```

Rollback is automatic failure recovery for the current transaction: it restores
replaced files or removes newly installed files only when their installed
contents still match the transaction journal. It is not a later user action.

## Restore MCP

Choose **Restore MCP** from setup to semantically undo selected managed client
entries. Restore lists only currently discoverable managed entries, lets you
select individual entries, restores those entries' original configuration, and
preserves unrelated edits in the same configuration file.

Restore removes or restores a generated policy only after exact ownership and
content checks: it must be the recorded policy for the selected entry, no other
restore record may still reference it, and its installed fingerprint and prior
content must match. Otherwise it retains the artifact and warns. Legacy entries
may recover configuration from setup backups without deleting uncertain
artifacts.

Restore is deliberately different from automatic rollback. It does not remove
saved Tools & Policy files, OAuth profiles, master keys, or backups. OAuth
retention and manual cleanup are documented in [OAuth](./oauth.md#retention-revocation-and-cleanup).
Restart `mcp-restrictor run` and affected clients after Restore. Until restart,
an already running gateway continues serving the route snapshot it loaded at
startup.

For a generated preset, Restore removes only the exact setup-owned generated
entry and its proven route/policy artifacts. It cannot edit a host client file
where you manually pasted the fragment. The final result names the server and
client format that you must remove from the host configuration yourself.

## Manual setup

Manual setup asks for a server name, STDIO command or remote URL, environment
variable mappings, and authentication. It supports STDIO, HTTP, legacy SSE,
and WebSocket. Bearer and OAuth authentication are available for HTTP and SSE,
not WebSocket; WebSocket supports environment-backed headers such as
`Authorization`. It may run OAuth login; see [OAuth](./oauth.md).

Transport and authentication are selected rather than typed. The transport
selector offers `STDIO`, `HTTP`, `SSE`, and `WebSocket`, starting on `STDIO`.
HTTP and SSE offer `None`, `Bearer`, and `OAuth`, starting on `None`. WebSocket
has no authentication selector. Bearer and OAuth are omitted
when an `Authorization` header mapping conflicts with them, and OAuth is also
omitted when its master-key environment variable is already mapped as a
header.

STDIO arguments and inherited environment variables are entered one at a time
with **Add argument**/**Add variable** and **Done**. Remote headers use
**Add header** and **Done**, with separate fields for the header and environment
variable names. This fullscreen path never asks for a JSON array,
comma-separated list, or `HEADER=ENV_NAME` mapping. An argument may be empty or
contain leading or trailing spaces.

Manual OAuth uses explicit default/custom choices:

| Value                      | Default                | Custom          |
| -------------------------- | ---------------------- | --------------- |
| Client ID                  | Dynamic registration   | Enter client ID |
| Requested scope            | Discover automatically | Enter scope     |
| Resource                   | None                   | Enter resource  |
| Resource metadata URL      | Discover automatically | Enter URL       |
| Authorization metadata URL | Discover automatically | Enter URL       |
| Callback port              | Ephemeral              | Enter port      |
| Callback base URL          | Loopback               | Enter URL       |

When a client ID has no configured secret, setup similarly offers **No client
secret** or **Enter client secret**. Custom values open a text or secret field;
callback-port validation remains on that field.

### Destination

The Manual screens are ordered as follows:

```text
Manual upstream details → Destination → Generated client selection and OpenCode format when needed → Client connection for existing destinations → HTTP gateway port when needed → Tools & Policy → Connect → Tools when configuring a new policy → Preview → Apply → Result
```

**Destination** appears after the Manual details and before either Tools &
Policy or a network connection. Its first row is the exclusive default:

```text
Show configuration only
```

It cannot be combined with client destinations. This copy-only choice is always
available, including when every client configuration is unavailable. Setup reads
discovery locations to populate Destination and report unavailable rows; the
copy-only default blocks client-configuration writes, not those reads. The remaining rows name an
exact loaded configuration, in deterministic adapter, scope, and path order
(project before user):

| Client      | Existing project target                                             | Existing user target                                                         |
| ----------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Claude Code | `$PROJECT_ROOT/.mcp.json`                                           | `$CLAUDE_CONFIG_DIR/.claude.json`, or `$HOME/.claude.json`                   |
| Codex       | `$PROJECT_ROOT/.codex/config.toml`                                  | `$CODEX_HOME/config.toml`, or `$HOME/.codex/config.toml`                     |
| OpenCode    | One unambiguous existing project location found by OpenCode loading | One unambiguous existing user location, including `OPENCODE_CONFIG` when set |
| External    | An existing configuration that the adapter reports as `project`     | An existing configuration that the adapter reports as `user`                 |

OpenCode project and user locations are the existing paths described in
[Configuration discovery](#configuration-discovery); inline, ambiguous,
shadowed, and invalid locations are not targets. Select several destinations
when needed, but only one exact configuration per adapter ID and scope. Setup
never creates a missing host configuration file.

When at least one built-in client has no discovered eligible configuration,
Destination also offers **Generate client presets**. That opens a multi-select
in deterministic client order for Claude Code, Codex, and OpenCode. If
OpenCode's schema cannot be inferred, select **Current (V2)** or **Legacy
(V1)**; V2 is selected by default. An already managed generated entry remains
available under Restore and is not offered again under Add.

For every selected existing destination, **Client connection** offers **STDIO —
client starts Restrictor**. Claude Code, Codex, and OpenCode also offer **HTTP —
connects through mcp-restrictor run**. Generated presets always use managed
HTTP and skip the **Client connection** prompt. If any destination uses HTTP,
choose one gateway port for the transaction; `17319` is the default. Every HTTP
destination uses that origin with a different exact path derived by Restrictor:

```text
http://127.0.0.1:<port>/mcp/<client>/<route-id>
```

The path cannot be customized and is an identifier, not a credential. Each
destination keeps its own policy, upstream transport, sessions, audit identity,
route file, and Restore ownership. STDIO destinations remain independent
wrappers started by their clients. An all-STDIO installation creates no managed
route and does not require `mcp-restrictor run`; **Show configuration only**
remains copy-only.

Setup writes native HTTP entries. The exact derived URL replaces `<url>` in
these shapes.

Claude Code (`.mcp.json` or `.claude.json`):

```json
{ "mcpServers": { "files": { "type": "http", "url": "<url>" } } }
```

Codex (`config.toml`):

```toml
[mcp_servers.files]
url = "<url>"
```

OpenCode Current (V2) (`opencode.json` or `opencode.jsonc`):

```json
{ "mcp": { "servers": { "files": { "type": "remote", "url": "<url>", "oauth": false } } } }
```

OpenCode Legacy (V1) (`opencode.json` or `opencode.jsonc`):

```json
{ "mcp": { "files": { "type": "remote", "url": "<url>", "oauth": false } } }
```

These compact examples show the destination shape. The exact fragment printed
by setup is authoritative and preserves the selected installer format.

After Apply, start `mcp-restrictor run` in a foreground terminal with the
required upstream environment variables. Restart it and the affected clients
after later setup changes because the running gateway uses its startup
snapshot. Operational details are in the [CLI reference](./cli.md#managed-http-routes).

### Generated preset output and ownership

Generated presets use the same built-in HTTP installers as real client
configuration. Setup stores private source files under
`$HOME/.mcp-restrictor/generated/` and prints installer-derived fragments for
merging into host configuration. The printed shape is rendered by the same
adapter operation against an empty baseline, not by a parallel template.

Generated policies have a separate ownership namespace:

```text
$HOME/.mcp-restrictor/generated/policies/<adapter-id>/<server>.yaml
```

Each generated preset owns its configuration entry, policy, route, and Restore
record independently. A real discovered configuration with the same client and
server name does not share that generated policy. Generated parents use mode
`0700` and files use mode `0600`.

Setup prints each fragment with its exact client format and instructs you to
merge the entry without overwriting unrelated settings. The safe v1
reconfiguration flow is **Restore MCP**, followed by **Add MCP**; generated
entries are not updated through a second in-place protocol.

An external adapter is a Manual destination only when it supports both
installation and Restore MCP. Existing adapters without those capabilities stay
valid for their current uses, but are not offered here. A destination can also
be unavailable for one of these reported reasons:

- `client adapter does not support installation and restore`;
- `client configuration could not be loaded`;
- `client ID is reserved for Manual configuration`;
- `client configuration aliases another destination`;
- `server name already exists`; or
- `destination policy path is unavailable`.

These checks prevent Manual from adopting or overwriting an owned entry or
policy. A readable existing destination policy remains selectable as that
destination's exact baseline. Before Apply writes anything, ownership preflight
rejects a policy referenced by another restore state, and setup rechecks
snapshots, paths, identities, and bytes for drift.

### Policies, Preview, and Apply

Manual chooses Tools & Policy independently for each destination and performs
pre-Apply Connect/discovery once. Installed connections connect again for
verification. Saved and Existing source bytes come from the Manual project policy namespace, and
installation leaves the Manual runtime policy unchanged. The selected effective
policy bytes are copied to an independent runtime policy for each installed
destination:

```text
project: $PROJECT_ROOT/.mcp-restrictor/policies/<adapter-id>/<server>.yaml
user:    $HOME/.mcp-restrictor/policies/<adapter-id>/<server>.yaml
```

No two destinations share a runtime policy. **Configure new** may save one
named source policy, and runtime policy bytes are copied only to destination
paths that are absent. Copy-only mode keeps its existing Manual project policy
path and can still write a saved policy and encrypted OAuth profile when
selected; it is not a dry run.

An installed Preview lists every target's client, scope, exact configuration
path, policy path, transport, selected tools, and `action=add`. **Apply** then
writes the optional saved policy/OAuth profile, every independent policy,
restore state, and every selected client configuration in one transaction.
All installed connections are verified before the result is shown. A write,
verification, or drift failure rolls back every target; Escape, Ctrl-C, EOF,
or declining Connect or Apply writes nothing.

After a copy-only result, setup prints JSON-safe `command`, `args`, and
`environment` values for copying. After an installed result, it prints changed
paths, backup locations, and client completion messages only; it does not
repeat those generic wrapper values. For Manual authentication and environment
mappings, installed configuration renders environment names, an OAuth profile
ID, and any configured master-key path, not bearer-token or header values.
User-supplied Manual STDIO arguments remain as supplied and may contain secrets.

### Restore and limits

Manual installation records each added entry for **Restore MCP**. Restore
removes an added entry only when that exact current entry still matches its
recorded installed form. It refuses an edited, removed, or replaced entry;
otherwise it deletes only the added entry and its created policy when the
existing policy ownership and fingerprint checks succeed. Unrelated edits in
the same client file are preserved, and the client configuration file itself is
never removed. Copy-only Manual setup creates no Restore MCP entry. If a
created policy fails its ownership or content check, Restore retains it and
prints a warning.

Saved policies, OAuth profiles, master keys, and backups are retained by
Restore MCP. Existing-destination Manual installation does not create missing
host configurations, replace or wrap an existing MCP entry, point several
clients at a shared policy, convert Restrictor OAuth into client-native OAuth,
run client-specific configuration commands, or allow partial success across
selected destinations.

## Files created by Restrictor

`<server>` below is the percent-encoded server name and `<name>` is a saved
configuration name.

| Artifact             | User scope                                                                                     | Project scope                                                                  |
| -------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Managed policy       | `$HOME/.mcp-restrictor/policies/<client>/<server>.yaml`                                        | `$PROJECT_ROOT/.mcp-restrictor/policies/<client>/<server>.yaml`                |
| Saved Tools & Policy | `$HOME/.mcp-restrictor/saved-policies/<client>/<server>.d/<name>.yaml`                         | `$PROJECT_ROOT/.mcp-restrictor/saved-policies/<client>/<server>.d/<name>.yaml` |
| Restore state        | `$HOME/.mcp-restrictor/restore/<sha256-of-absolute-config-path>.json`                          | Same user-home location                                                        |
| Transaction backups  | `$HOME/.mcp-restrictor/backups/`                                                               | Same user-home location                                                        |
| Managed HTTP route   | `$HOME/.mcp-restrictor/routes/<route-id>.json`                                                 | Same user-home location                                                        |
| Generated preset     | `$HOME/.mcp-restrictor/generated/{claude.json,codex.toml,opencode-v1.jsonc,opencode-v2.jsonc}` | Not applicable                                                                 |
| Generated policy     | `$HOME/.mcp-restrictor/generated/policies/<client>/<server>.yaml`                              | Not applicable                                                                 |

OAuth profiles live at `$HOME/.mcp-restrictor/oauth/<profile-id>.json`; their
master key is normally in the operating system keyring or at the explicitly
configured `MCP_RESTRICTOR_MASTER_KEY_FILE`. See [OAuth](./oauth.md) for the
security and retention details.

For Manual copy-only setup, `<client>` in the generated-policy path is
`manual`. For Manual installation, it is the selected destination adapter ID.
The routes directory is private and each destination has one private route
file. Route files are not encrypted and do not conceal route metadata: they
contain the owner, listen URL, proxy arguments, environment-variable names,
and an optional OAuth master-key file path, but not resolved credential values.

## Troubleshooting

| Problem                                  | What to do                                                                                                                                                                                                    |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `setup requires an interactive terminal` | Run setup from a TTY. It intentionally does not use a non-interactive setup flow.                                                                                                                             |
| No supported MCP servers found           | Check the client paths above. Manual can show portable wrapper values, install into eligible existing destinations, or generate a private client preset when a built-in client has no discovered destination. |
| Project configuration was not found      | Run from the intended project. Setup uses `git rev-parse --show-toplevel`; outside Git, the current directory is the project root.                                                                            |
| OpenCode configuration is ambiguous      | Keep only one sibling `opencode.json` or `opencode.jsonc` at the reported location, then rerun setup.                                                                                                         |
| An entry is listed as unsupported        | Read the reported reason. Setup leaves it unchanged; convert it to a supported client configuration or use Manual when applicable.                                                                            |
| The selected file changed during setup   | Rerun setup and avoid concurrent edits during the preview-to-Apply window.                                                                                                                                    |
| The client does not use the wrapper yet  | Restart Claude Code, Codex, or OpenCode. Claude Code may ask you to approve the changed project `.mcp.json`; restart Codex in a trusted project.                                                              |
