# OAuth

## Why OAuth is separate from Tools & Policy

Setup keeps three independent objects:

- Upstream connection details select the command or remote server and its transport.
- [Tools & Policy](./policy.md) is reusable authorization configuration.
- An OAuth profile holds credentials for one server and, when present, one resource.

The wrapper refers to an OAuth profile only by its UUID. It does not contain the
profile credentials. This keeps reusable Tools & Policy independent from an
upstream identity and lets a profile be reauthorized without replacing a policy.

## Supported transports and flows

OAuth profiles are supported for HTTP and SSE upstreams, not STDIO or WebSocket
upstreams. Interactive login discovers the authorization server, asks for
confirmation, prints the authorization URL for the user to open, then receives
a loopback redirect or accepts a pasted redirect and stores the resulting
credentials. OAuth discovery and endpoint URLs require HTTPS, except exact
loopback HTTP URLs.

## Profile lifecycle

Interactive setup can create an encrypted profile and put its UUID in the
generated wrapper as `--upstream-oauth-profile PROFILE_ID`. The profile is
bound to its configured server URL and, if configured or discovered, its
resource. A wrapper cannot use it for a different server or resource.

When an access token is rejected, Restrictor tries to refresh the profile. If
the profile cannot be read, decrypted, refreshed, or validated, the wrapper
requires login again:

```bash
mcp-restrictor oauth login PROFILE_ID
```

## What the wrapper stores

A wrapper contains its normal upstream connection details and Tools & Policy
reference. Its OAuth reference is only a profile UUID; credentials, client
information, tokens, and discovery state remain in the encrypted profile.

Saved Tools & Policy configurations contain policy only. They do not include an
OAuth profile or its credentials.

## Encryption and master keys

Profile credentials and discovery state are encrypted with AES-256-GCM. Clear
profile metadata is authenticated as additional data, so changing it makes the
encrypted profile unreadable. Profile files and their parent storage are
checked as current-user private paths before use.

By default, the 32-byte master key is stored in the OS keyring under service
`mcp-restrictor` and account `oauth-master-key-v1`. Keyring access fails closed:
there is no plaintext fallback.

The native keyring is the current user's login Keychain on macOS, Windows
Credential Manager on Windows, and Secret Service on Linux when available
(with the keyring library's kernel-keyring fallback). These native locations
are unchanged by the container feature.

## Headless environments

Set `MCP_RESTRICTOR_MASTER_KEY_FILE` to use a master-key file instead of the OS
keyring. The value is resolved as a path and is accepted only for a regular,
non-symlink file owned by the current user with no group or other permission
bits on POSIX. Its content must be exactly one canonical, unpadded base64url
encoding of 32 bytes. An unavailable or invalid key file prevents profile use.

## Official container key file

The image sets:

```text
MCP_RESTRICTOR_MASTER_KEY_FILE=/home/restrictor/.mcp-restrictor-key/oauth-master-key-v1
```

That path lives in a named key volume separate from
`/home/restrictor/.mcp-restrictor`, but the state and key volumes are one
operational pair. Setup creates the default file only when the official
container marker is active and OAuth is selected. `run` and `oauth login`
never create a missing key. The parent directory must be a non-symlink private
directory owned by image UID `1000` with mode `0700`; the key is a regular,
non-symlink owner file with mode `0600`.

Host root, a Docker administrator, and the container UID can read the raw key.
Separate volumes reduce accidental state-only disclosure; they do not defend
against Docker-host compromise. Back up both volumes together while the
service is stopped and restore them together.

Container reauthorization is also a mutating operation: stop the service, run
`oauth login PROFILE_ID` through the entrypoint of a new official-image
container with the paired volumes and required environment/CA mounts, then
restart only if its options are unchanged or recreate it if they changed.
Never use `docker exec` because it bypasses the global lock. See the exact
commands in [Docker deployment](./container.md#oauth-in-containers).

If the original key is lost, `oauth login PROFILE_ID` cannot decrypt or
recover the existing ciphertext because login must read that profile before
publishing replacement credentials. Restore a consistent paired backup or
delete both volumes and configure Restrictor again. The
[Docker deployment guide](./container.md#oauth-in-containers) gives the exact
stop, container-removal, paired-volume-removal, and host-fragment cleanup
commands.

An advanced deployment may bind-mount a pre-created valid key at the default
path or choose another pre-created absolute path during the original setup.
Automatic creation is limited to the image default. The chosen path is stored
with the OAuth route; changing an environment value later does not migrate or
decrypt that route, so Restore and recreate it instead.

## Reauthorization

Reauthorize the existing profile rather than creating a new policy or changing
the wrapper reference:

```bash
mcp-restrictor oauth login PROFILE_ID
```

The command repeats interactive authorization and writes fresh encrypted
credentials for that profile. It remains bound to its server and resource.

Inside a bridged container, choose **Paste redirected URL** rather than the
loopback listener. The browser can display an unreachable local page; copy the
complete address-bar URL into the hidden prompt. No callback port or host
networking is required. Native execution continues to default to the loopback
listener.

## Retention, revocation, and cleanup

Profiles and master keys are retained. Setup restore also retains them and its
backups. Restrictor does not revoke credentials or automatically remove OAuth
profiles, master keys, backups, client configuration, or other secret sources.
Credential revocation and cleanup remain the user's responsibility.

## Security boundary

Encrypted profiles do not encrypt client configuration, environment- or
file-backed secret sources, or backups. They also do not protect credentials
from compromise of the same OS account. OAuth authenticates Restrictor to an
upstream server; it does not authenticate local downstream clients. See the
canonical [security model](../SECURITY.md) and the proxy
[architecture boundary](./architecture.md).
