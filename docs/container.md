# Docker deployment

The official image is `ghcr.io/sw1tchdev/mcp-restrictor`. It runs as an
unprivileged user, supports `linux/amd64` and `linux/arm64`, and contains both
the interactive `setup` command and the managed HTTP gateway. This guide is
the canonical container workflow; the [security model](../SECURITY.md) still
defines the trust boundary.

The intended deployment is one Docker host, two paired local volumes, and one
host-loopback port. The image is not a remote gateway and does not add
downstream authentication or HTTPS termination.

## Quick start

Pull the image:

```bash
docker pull ghcr.io/sw1tchdev/mcp-restrictor:latest
```

For reproducible deployments, replace `latest` with a release tag or immutable
digest after first trying the release in your environment.

### 1. Run interactive setup

Mount both named volumes every time you run setup:

```bash
docker run --rm -it \
  -v mcp-restrictor-state:/home/restrictor/.mcp-restrictor \
  -v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key \
  ghcr.io/sw1tchdev/mcp-restrictor:latest \
  setup
```

Both stdin and stdout must be TTYs, which is why the command uses `-it`.
Setup remains one fullscreen Ink flow. If it cannot discover host client
configuration, choose **Manual upstream** and **Generate client presets**.
Setup can generate ready-to-merge fragments for Claude Code, Codex, and
OpenCode while retaining the corresponding private source files in the state
volume.

Remote upstream headers, bearer tokens, and selected STDIO variables are
passed by environment-variable name. The value must be available during both
setup and `run`. For example, if setup maps a bearer token to
`ACME_MCP_BEARER`:

```bash
export ACME_MCP_BEARER='replace-with-the-real-value'
docker run --rm -it \
  --env ACME_MCP_BEARER \
  -v mcp-restrictor-state:/home/restrictor/.mcp-restrictor \
  -v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key \
  ghcr.io/sw1tchdev/mcp-restrictor:latest \
  setup
```

The environment name is stored in route configuration; its value is not.
Docker administrators can nevertheless inspect a running container's
environment, so Docker administration remains a trusted boundary.

### 2. Start the gateway

Start the persistent service with the same volume pair and required upstream
environment names:

```bash
docker run -d \
  --name mcp-restrictor \
  --init \
  --restart unless-stopped \
  -p 127.0.0.1:17319:17319 \
  --env ACME_MCP_BEARER \
  -v mcp-restrictor-state:/home/restrictor/.mcp-restrictor \
  -v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key \
  ghcr.io/sw1tchdev/mcp-restrictor:latest \
  run --bind 0.0.0.0
```

Omit `--env ACME_MCP_BEARER` when no saved route requires that name. Add only
the environment names reported by setup. A missing required value makes
startup fail before the listener opens.

For foreground use, omit `-d`, `--name mcp-restrictor`, and
`--restart unless-stopped`:

```bash
docker run --rm -it \
  --init \
  -p 127.0.0.1:17319:17319 \
  --env ACME_MCP_BEARER \
  -v mcp-restrictor-state:/home/restrictor/.mcp-restrictor \
  -v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key \
  ghcr.io/sw1tchdev/mcp-restrictor:latest \
  run --bind 0.0.0.0
```

`--init` provides child reaping for STDIO upstreams. Docker sends shutdown
signals to Restrictor, which closes every route before exiting.

## What the network settings mean

New managed HTTP setups default to port `17319`. Generated client fragments
always advertise host-loopback URLs such as:

```text
http://127.0.0.1:17319/mcp/claude/<route-id>
http://127.0.0.1:17319/mcp/codex/<different-route-id>
http://127.0.0.1:17319/mcp/opencode/<different-route-id>
```

One gateway owns the port, but every exact path has its own policy, upstream,
session namespace, active bridges, restore ownership, and audit identity.
Unknown paths, path aliases, and session IDs from another route are rejected.

The two transport legs are independent. A common deployment is:

```text
Host agent --HTTP--> Restrictor container --HTTPS--> upstream MCP server
```

`run --bind 0.0.0.0` makes the process reachable through the Docker bridge. It
does not change the advertised `127.0.0.1` URLs or their Host/Origin checks.
The host publish is deliberately restricted to
`127.0.0.1:17319:17319`. The unqualified mapping `17319:17319` may expose the
listener on every host interface and is unsafe for this design. Route paths
are identifiers, not credentials, and the gateway has no downstream
authentication.

The image exposes port metadata but Docker does not publish it automatically.
Do not use host networking or publish the managed listener on a public
interface. If another trust boundary must terminate TLS or authenticate
clients, place an explicitly configured reverse proxy in front only after
reviewing the [security model](../SECURITY.md); Restrictor itself provides no
managed HTTPS termination.

### Custom port

Choose the custom port during setup, then publish the same value on both sides.
If a container already owns the `mcp-restrictor` name, stop and remove that
container before recreating it; named volumes remain intact:

```bash
docker stop mcp-restrictor
docker rm mcp-restrictor
```

On a fresh install, skip those two replacement commands. Start the new service
with the port stored by setup:

```bash
docker run -d \
  --name mcp-restrictor \
  --init \
  --restart unless-stopped \
  -p 127.0.0.1:18080:18080 \
  -v mcp-restrictor-state:/home/restrictor/.mcp-restrictor \
  -v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key \
  ghcr.io/sw1tchdev/mcp-restrictor:latest \
  run --bind 0.0.0.0
```

All existing routes pin one shared stored origin and port. To change it later,
stop the service, Restore every managed HTTP destination, add them again with
the new port, remove the old service container as shown above, and update any
manually pasted host fragments before starting the replacement.

## Generated client presets

When a client configuration is not mounted into the container, Manual setup
offers **Generate client presets** after **Destination**. Select any eligible
combination of Claude Code, Codex, and OpenCode. If no existing OpenCode file
reveals its schema, choose **Current (V2)** or **Legacy (V1)**; V2 is the
default.

Restrictor uses each built-in client's real HTTP installer to create the
private preset and the printed fragment. The fragment is therefore the same
shape as the setup-owned entry. Merge it into the host configuration; do not
replace unrelated settings. The generated files are:

```text
/home/restrictor/.mcp-restrictor/generated/claude.json
/home/restrictor/.mcp-restrictor/generated/codex.toml
/home/restrictor/.mcp-restrictor/generated/opencode-v2.jsonc
/home/restrictor/.mcp-restrictor/generated/opencode-v1.jsonc
```

Each generated destination owns an independent policy under
`generated/policies/<client>/`, an exact route, and Restore state. Restoring a
generated destination removes only the owned container artifacts. The
container cannot edit a host file into which you pasted a fragment, so the
Restore result names the host entry you must remove manually.

To reconfigure an existing generated destination, use **Restore MCP** and then
**Add MCP**. Setup deliberately does not maintain a second in-place update
protocol.

## Reconfigure or Restore

`run` loads one startup snapshot and has no hot reload. The official entrypoint
also holds one global lock for the state/key volume pair. Stop the service,
then run setup through the entrypoint of a separate temporary container. Pass
the same required upstream environment values, CA files, executable/project
mounts, and paired volumes used by the service. This representative command
shows an environment-backed credential and private CA:

```bash
docker stop mcp-restrictor

docker run --rm -it \
  --env ACME_MCP_BEARER \
  --env NODE_EXTRA_CA_CERTS=/run/secrets/acme-ca.pem \
  -v /absolute/path/to/acme-ca.pem:/run/secrets/acme-ca.pem:ro \
  -v mcp-restrictor-state:/home/restrictor/.mcp-restrictor \
  -v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key \
  ghcr.io/sw1tchdev/mcp-restrictor:latest \
  setup
```

Replace the representative environment and CA options with every value and
mount required by your routes; omit them only when they are not used.

For a state-only change, the stopped service can be started again only when
the same image, environment names and values, mounts, published port, and all
other container options remain correct:

```bash
docker start mcp-restrictor
```

Docker does not detect or reconcile those options from the new state. If setup
adds or removes an environment name or mount, or if the port, image, or any
container option changes, remove the stopped service and recreate it with the
complete updated command. For example:

```bash
docker rm mcp-restrictor

docker run -d \
  --name mcp-restrictor \
  --init \
  --restart unless-stopped \
  -p 127.0.0.1:17319:17319 \
  --env ACME_MCP_BEARER \
  --env NODE_EXTRA_CA_CERTS=/run/secrets/acme-ca.pem \
  -v /absolute/path/to/acme-ca.pem:/run/secrets/acme-ca.pem:ro \
  -v mcp-restrictor-state:/home/restrictor/.mcp-restrictor \
  -v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key \
  ghcr.io/sw1tchdev/mcp-restrictor:latest \
  run --bind 0.0.0.0
```

Choose **Restore MCP** in the same setup UI for selective removal. Starting or
recreating the service is required after both setup and Restore because a
running process would retain its old snapshot.

Do not use `docker exec` for `setup`, `oauth login`, or any other mutating
Restrictor operation. `docker exec` bypasses the image entrypoint, so the new
process would not acquire the global container lock and could write alongside
the gateway. This path is unsupported and dangerous even if it appears to
work.

## OAuth in containers

Native Restrictor uses the current user's OS keyring. The image instead sets:

```text
MCP_RESTRICTOR_MASTER_KEY_FILE=/home/restrictor/.mcp-restrictor-key/oauth-master-key-v1
```

Setup creates that file only after OAuth is selected. The key volume stays
separate from route/profile state, but both volumes form one operational pair.
The raw key is readable by container UID `1000` and by a host root or Docker
administrator. Separation protects against accidentally disclosing only the
state volume; it is not protection from Docker-host compromise.

For an OAuth flow in a bridged container, choose **Paste redirected URL**.
The browser may show an unreachable loopback page after authorization. Copy
the complete address-bar URL and paste it into the hidden setup field. No
callback port needs to be published. `oauth login PROFILE_ID` asks for the
delivery method again; choose Paste in the container.

To reauthorize an existing profile, stop the managed service and run
`oauth login` in a new temporary official-image container through its
entrypoint. Supply the paired volumes and every environment, CA, executable,
and project mount needed by the profile or its upstream:

```bash
docker stop mcp-restrictor

docker run --rm -it \
  --env ACME_MCP_BEARER \
  --env NODE_EXTRA_CA_CERTS=/run/secrets/acme-ca.pem \
  -v /absolute/path/to/acme-ca.pem:/run/secrets/acme-ca.pem:ro \
  -v mcp-restrictor-state:/home/restrictor/.mcp-restrictor \
  -v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key \
  ghcr.io/sw1tchdev/mcp-restrictor:latest \
  oauth login PROFILE_ID
```

If the stopped service still has the exact required image, environment,
mounts, port, and options, restart it:

```bash
docker start mcp-restrictor
```

If any option changed, remove it instead and recreate it with the complete
updated background command from [Reconfigure or Restore](#reconfigure-or-restore):

```bash
docker rm mcp-restrictor
```

These are alternative final steps, not commands to run in sequence. Never use
`docker exec` for reauthorization because it bypasses the entrypoint lock.

Always mount the same key file at the recorded absolute path for setup, `run`,
and reauthorization. A missing, replaced, malformed, permissive, wrong-owner,
or symlinked key fails closed. `oauth login` cannot recover or decrypt profile
ciphertext after the original key is lost because it must decrypt the existing
profile before it can replace the credentials.

Advanced users may bind-mount a pre-created valid key at the default path or
choose another pre-created absolute path during the original setup. Automatic
creation is limited to the image default. The selected path is stored with the
OAuth route and cannot be changed later by passing a different value to
`run`; Restore and recreate the affected route instead.

Recover either a consistent backup of both volumes or reset the pair. For a
full reset, first accept that all Restrictor-managed state and encrypted OAuth
profiles will be lost, then run these exact commands:

```bash
docker stop mcp-restrictor
docker rm mcp-restrictor
docker volume rm mcp-restrictor-state mcp-restrictor-key
```

Rerun the quick-start setup and service commands afterward. Also manually
delete every host client entry copied from a generated fragment, then paste
the newly generated entries. Revoke old upstream credentials when possible.

See [OAuth](./oauth.md) for native keyrings, file validation, login, and
retention behavior.

## Filesystem and process contract

The image runs as numeric UID/GID `1000` with `HOME=/home/restrictor` and
working directory `/workspace`. Named volumes are initialized with private
directories. Bind-mounted state, key, project, executable, certificate, and
policy files must be readable by UID `1000`; private writable directories must
remain owned by that user with mode `0700`, and private files use `0600`. Do
not override the image user.

State and key volumes must be local filesystems. NFS and other shared/network
filesystems are unsupported because locking and transactions require local
`flock`, hard links, and atomic rename. This limitation is not proactively
detected on every filesystem.

Never pair one key volume with several state volumes, and never run two
official containers against the same pair concurrently. The entrypoint's
non-blocking global lock belongs to the pair and fails closed when the state is
already in use.

The generic image does not contain arbitrary STDIO upstream executables. A
saved STDIO command runs inside the container, not on the Docker host, and
retains its absolute command and working directory. Install it in a custom
image or mount the executable and project at the same container paths during
both setup and `run`; pass every selected environment name to both commands.
If the saved working directory is `/workspace/project`, that directory must
exist after every restart.

Do not place credentials in a command argument or URL. Manual STDIO arguments
are retained as entered; use selected environment-variable names for secrets.
For a private upstream CA, mount the same certificate path and pass
`NODE_EXTRA_CA_CERTS` to both setup and `run`.

Likewise, `localhost` in an upstream URL means the container itself. Reaching a
service on the Docker host requires platform-specific host routing; on Linux,
an explicit `--add-host host.docker.internal:host-gateway` is commonly needed.
Use verified HTTPS for non-loopback upstreams carrying credentials.

## Hardened run

The image supports a read-only root filesystem. The two volumes remain
writable for routes, Restore state, OAuth refresh, locks, backups, and atomic
replacement; `/tmp` remains a small writable runtime area:

```bash
docker run -d \
  --name mcp-restrictor \
  --init \
  --restart unless-stopped \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges=true \
  -p 127.0.0.1:17319:17319 \
  --env ACME_MCP_BEARER \
  -v mcp-restrictor-state:/home/restrictor/.mcp-restrictor \
  -v mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key \
  ghcr.io/sw1tchdev/mcp-restrictor:latest \
  run --bind 0.0.0.0
```

These flags reduce container privileges; they do not hide environment values
or mounted files from a Docker administrator.

## Inline Compose equivalent

Docker Compose is optional. The equivalent service can be kept in your own
deployment file; this repository intentionally does not ship a `compose.yml`:

```yaml
services:
  mcp-restrictor:
    image: ghcr.io/sw1tchdev/mcp-restrictor:latest
    init: true
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=16m
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    ports:
      - "127.0.0.1:17319:17319"
    environment:
      - ACME_MCP_BEARER
    volumes:
      - mcp-restrictor-state:/home/restrictor/.mcp-restrictor
      - mcp-restrictor-key:/home/restrictor/.mcp-restrictor-key
    command: ["run", "--bind", "0.0.0.0"]

volumes:
  mcp-restrictor-state:
  mcp-restrictor-key:
```

Stop the service before running `docker compose run --rm mcp-restrictor setup`.
Run it from an interactive terminal and do not pass `-T`; setup requires both
TTY streams. Keep only the environment names actually selected during setup.

If the OAuth key is lost in this inline Compose deployment, do not reuse the
plain-Docker volume-removal command: Compose normally scopes the volume names
to its project. From the intended Compose project, reset and configure the
whole deployment with:

```bash
docker compose down --volumes
docker compose run --rm mcp-restrictor setup
docker compose up -d
```

`docker compose down --volumes` is destructive across the current Compose
project: it removes its service containers and networks plus its declared
named and attached anonymous volumes, not only Restrictor state. Run it only
when every affected project resource may be removed. Delete pasted host client
fragments manually and revoke old upstream credentials as described in the
plain-Docker recovery procedure.

## Backup and upgrade

Treat the state and key volumes as one backup set while keeping them separate
in normal storage:

1. Stop the service so locks, profiles, routes, and Restore state are stable.
2. Back up both named volumes with the same snapshot timestamp using your
   Docker-volume or host backup tooling.
3. Restore both volumes together. Restoring one without the other can leave
   encrypted OAuth profiles permanently unreadable.
4. Protect the backup as credential material.

An image upgrade does not rotate the master key or rewrite saved routes merely
because the image changed. Upgrade by pulling the desired tag or digest,
stopping and removing only the service container, and recreating it with the
same command and volume pair:

```bash
docker pull ghcr.io/sw1tchdev/mcp-restrictor:latest
docker stop mcp-restrictor
docker rm mcp-restrictor
```

Then repeat the background start command. Removing a container does not remove
named volumes unless you explicitly request volume removal.

## Release and image provenance

Official images are published only to `ghcr.io/sw1tchdev/mcp-restrictor` when
the CLI package has a verified release. A stable `0.2.3` release receives
`0.2.3`, `0.2`, and `latest`; a prerelease receives only its exact prerelease
tag. Pre-1.0 releases do not publish a broad `0` tag, and no release publishes
a broad major tag.

The release workflow builds one `linux/amd64`/`linux/arm64` index with an SBOM,
max-mode BuildKit provenance, OCI source/revision/version metadata, and a
digest-bound GitHub artifact attestation. Consumers that need immutability
should deploy the resulting digest. After the first publication, the repository
owner must make the GHCR package public once and verify both an anonymous pull
and the attestation; Docker Hub is not an official source.

## Build locally

To inspect or customize the image, build the repository Dockerfile and replace
the image name in the same setup/run commands:

```bash
docker build --tag mcp-restrictor:local .
```

Keep the official entrypoint. Bypassing it also bypasses private mount checks,
the process marker, and the global volume-pair lock.

## Troubleshooting

| Symptom                                  | Check                                                                                                                                                         |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `setup requires an interactive terminal` | Run setup with both stdin and stdout attached to a TTY (`-it`).                                                                                               |
| `state is in use`                        | Stop the other container that mounts this state/key pair. Do not work around the lock with `docker exec` or a custom entrypoint.                              |
| `No managed HTTP routes; run setup`      | Run setup with the same two volumes and create at least one HTTP/generated destination.                                                                       |
| The host client cannot connect           | Publish the exact stored port to `127.0.0.1`, keep `run --bind 0.0.0.0`, and restart after setup or Restore.                                                  |
| One generated URL returns 404            | Confirm the exact current fragment and route path. Restored, aliased, trailing-slash, and unknown paths are rejected.                                         |
| Upstream preflight fails                 | Pass every environment name and value used during setup; mount the same CA/project/executable paths; remember that container `localhost` is not the host.     |
| OAuth key is invalid or missing          | Mount the original paired key volume at the recorded path. If the key was lost, use the full-pair recovery above; `oauth login` cannot repair the ciphertext. |
| Permission or private-path error         | Keep UID/GID `1000`, directory mode `0700`, file mode `0600`, and avoid symlinked state/key paths.                                                            |
| A setup change is not visible            | Stop and restart the service. Managed `run` uses a startup snapshot and has no hot reload.                                                                    |

## Cleanup

Stop and remove the service before deleting its data:

```bash
docker stop mcp-restrictor
docker rm mcp-restrictor
docker volume rm mcp-restrictor-state mcp-restrictor-key
```

Volume removal is destructive. It does not remove fragments pasted into host
Claude Code, Codex, or OpenCode configuration, revoke upstream credentials, or
delete external backups. Clean up those items separately.
