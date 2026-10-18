# mythic-beaconcrypt

An external Beaconcrypt cryptographic provider for Mythic 4.0 beta. Mythic owns transport, framing, application messages, callback routing, and the generic provider/storage APIs; this service implements the existing Beaconcrypt protocol and persists a separate server identity and session set for each Mythic campaign (operation) through Mythic's opaque storage API.

This repository follows the [ExampleContainers](https://github.com/MythicMeta/ExampleContainers) layout: `config.json` selects the installable service in `Payload_Type/mythic_beaconcrypt`. That directory contains the Go module, Dockerfile, native build scripts, and runtime code. It consumes Beaconcrypt without changing its protocol, Rust implementation, Go bindings, or proof tree, and has no dependency on the Mythic server module or direct PostgreSQL access.

## Starting from the template

For a new provider, start with the crypto-provider template proposed for ExampleContainers. [`template.json`](template.json) identifies its source repository and exact revision. This implementation copies that template's production scaffold and supplies Beaconcrypt behind its provider interface. The scaffold is ordinary source in this repository; there is no runtime or build dependency on the template repository.

| Code under `Payload_Type/mythic_beaconcrypt` | Responsibility |
| --- | --- |
| `main.go`, `internal/service` | Generic startup, provider registration, and RPC dispatch |
| `internal/transport`, `internal/storage/client.go` | Generic SDK/AMQP integration and Mythic storage calls |
| `internal/wire` | Mythic's versioned provider and storage message contracts |
| `internal/provider` | Beaconcrypt settings and construction of the protocol engine |
| `internal/engine`, `internal/native` | Beaconcrypt sessions, durable checkpoints/results, and native-library adapter |
| `scripts/build-native.sh`, `scripts/beaconcrypt-releases.txt` | Beaconcrypt's pinned release archives and link preparation |

The copied production files are listed in [`template.json`](template.json), which records their SHA-256 digests and the exact template commit. CI checks that they still match after substituting this repository's Go module path. Provider-specific behavior belongs behind `internal/provider`, rather than in the copied transport or dispatch code. To check the scaffold locally, run:

```sh
python3 scripts/check-template.py
# Optionally verify the recorded source against an existing checkout at its pinned commit:
python3 scripts/check-template.py --source /path/to/ExampleContainers
```

When deliberately adopting a template update, first copy the changed scaffold with the module path substituted, then run `python3 scripts/check-template.py --record --source /path/to/ExampleContainers` from this repository. The command records only committed source files and checks the local copy before writing the manifest. Review the template commit and manifest change together.

## Compatibility

- Mythic's generic crypto-provider API v1 on `crypto-shim`, using plain JSON RPC and ordinary Mythic authorization-context headers.
- Mythic `crypto-shim` with request-scoped container identity. Storage uses Mythic's standard serial RPC dispatch. Earlier MAC-envelope revisions are incompatible with this wire format.
- MythicContainer's [`Mythic-v4.0.0` branch](https://github.com/MythicMeta/MythicContainer/tree/Mythic-v4.0.0), reviewed at `a4c7e05f17b02e86820cc92ca425095bbe3b19be`; consuming-container wire version `v1.5.0`.
- Beaconcrypt `v0.5.2`, tag commit `b32af5768adae7e97240b660e1e9139b884bd056`, pinned in `go.mod` and the matching native archive.

The Go module pins MythicContainer `v1.7.0-rc5`, which resolves to the reviewed branch commit. The SDK does not yet have a crypto service registry or typed storage helpers. The provider registers custom context-aware SDK queues, starts them with `rabbitmq.Initialize` / `rabbitmq.StartServices`, and uses the SDK RPC API for sync and storage calls. The local adapter supplies the crypto messages and terminal failure handling around those APIs. The business RPC consumer uses bounded concurrent workers on the SDK-owned connection; lifecycle queues and outbound calls keep the SDK APIs. It does not modify or fork the SDK. `internal/wire` carries the versioned Mythic-owned contract types. Fixed AMQP, HTTP/2, and gRPC dependency versions override older transitive versions from the SDK.

## Build and development

Install [pre-commit](https://pre-commit.com/#install), Go 1.26+ (production uses patched Go 1.27.2), a C compiler, `curl`, `sha256sum`, `flock`, and `ripgrep`. Builds support Linux amd64 and arm64 and use the matching published Beaconcrypt archive. On Debian/Ubuntu, install the tools with `apt install build-essential curl coreutils util-linux ripgrep`. Rust and the Cap'n Proto compiler are not required.

```sh
make setup
make build
make test
make vet
```

`make setup` downloads and verifies the pinned native dependency and runs `pre-commit install` using `.pre-commit-config.yaml`. It also removes this repository's legacy `.githooks` setting when present. The hooks check staged Go source with `gofmt -d` and run `go vet ./...`; they never reformat or stage source automatically. Clones must run `make setup` to enable the hooks. Run `pre-commit run --all-files` to check the entire repository.

`scripts/build-native.sh` downloads the host's `gobinds` static archive from the exact Beaconcrypt GitHub release pinned in `go.mod`. `scripts/beaconcrypt-releases.txt` records each supported version, Rust target, asset name, and SHA-256. Every cache hit verifies the archive checksum, including caches left by earlier source builds. Downloads are checked before atomic publication under a cache lock; failed downloads leave the previous cache intact. An unlisted version or target fails explicitly and must be added with a verified release checksum. There is no source-build fallback.

The cache remains `.build/native-target/release/libbeaconcrypt.a` with a matching `module-version` file. `scripts/go.sh` uses this archive for cgo and refuses a missing or differently pinned dependency. The Go module cache is unchanged. The Docker build uses the same downloader and a C compiler, without Rust or Cap'n Proto build tools. When replacing a source-built archive at the same module version, run `go clean -cache` once before manual builds: Go does not track changes to external static libraries in its build cache. Fresh container builds already relink the downloaded archive.

GitHub Actions checks formatting, vet, race tests, `govulncheck`, and `golangci-lint`. Native archive preparation runs before analysis so cgo packages are included.

### Client integration tests

`make test-integration` runs actual Mythic components from a separate checkout, together with this provider and real Beaconcrypt Go clients. Mythic initializes its complete schema and migrations in a temporary PostgreSQL database. Registration and encrypted agent traffic pass through its real HTTP `/agent_message` endpoint, including staging, callback creation, UUID/base64 framing, provider RPCs, and PostgreSQL-backed state/result storage. It also checks two campaigns with separate identities and state records, cross-campaign rejection, independent revisions, and restart recovery.

The test checks four clients across two campaigns, authenticated staging and check-in, ordinary agent messages and replies, cached establishment retries, and continued communication after restarting the provider with the same live clients. It runs the production initializers, HTTP router, AMQP listeners, and PostgreSQL storage in the test process so ordinary process-local Mythic authorization contexts can be validated. The native client dependency is added only to a temporary test copy of Mythic; neither production module gains a dependency on the other.

Set these variables before running the target:

- `MYTHIC_SOURCE`: the root of a Mythic Git checkout containing the generic crypto-provider support.
- `MYTHIC_REF`: optional local commit/ref, default `crypto-shim`. The runner archives this committed source and reports its full SHA. Working-tree changes are excluded.
- `BEACONCRYPT_AMQP_TEST_URL`: an isolated RabbitMQ broker URL.
- `CRYPTO_PROVIDER_TEST_DSN`: a PostgreSQL URL for an isolated test instance. Its user needs `CREATEDB`; the test creates and drops a uniquely named database.

For example, from this repository with disposable test services already running:

```sh
MYTHIC_SOURCE=~/Mythic \
BEACONCRYPT_AMQP_TEST_URL='amqp://provider_test:transport-tests-only@127.0.0.1:5673/' \
CRYPTO_PROVIDER_TEST_DSN='postgres://mythic_test:mythic-integration-only@127.0.0.1:5433/mythic_test?sslmode=disable' \
  make test-integration
```

The target fails if source or service configuration is missing and disables Go's test cache. Temporary source, test module changes, processes, and databases are cleaned up. Original checkouts remain untouched. CI provisions PostgreSQL and RabbitMQ and runs this target in a dedicated step. CI checks out `0xd6cb6d73/Mythic` at `crypto-shim` and archives that checkout's exact `HEAD` commit. The branch must be published on our fork for GitHub to fetch it.

`make test` runs unit/native tests. `make test-transport`, with a broker URL, separately checks SDK queue ownership, concurrent RPC dispatch, and lazy campaign lifecycle using a small test peer. The real Mythic client integration is `make test-integration`. No production credentials are required.

## Persistence with Beaconcrypt v0.5.2

The new Go `SnapshotStore` interface was evaluated against Mythic's durable
storage contract. `Load` returns the trusted current snapshot;
`CompareAndSwap` compares the complete expected lineage, generation, and digest,
validates its successor, and durably commits the replacement before returning
success. Creation commits generation zero; restoration commits an activation
generation. Failed or uncertain CAS suppresses operation output and poisons that
native owner. Snapshot digests identify bytes; storage remains responsible for
integrity, provenance, coordination, and rollback protection.

This provider retains Beaconcrypt's documented checkpoint compatibility
constructors, `NewServer` and `NewServerFromState`. They let the engine publish
its snapshot, provider metadata, and exact immutable response together through
one Mythic storage commit before releasing any result. Mythic's owner epoch and
revision checks remain authoritative. Initial and restored snapshots are checked
with the library's `ParseSnapshotHead` / `ValidateSnapshotSuccessor` helpers;
restoration must produce the exact next activation generation.

A direct caller-store adapter cannot preserve that transaction: its CAS runs
before Beaconcrypt returns the generated ciphertext, plaintext, or registration
response. Saving the snapshot in that callback and saving the response afterward
would leave a crash interval with consumed ratchet state but no recoverable
response or session mapping. Returning CAS success for an in-memory buffer while
waiting for the outer commit would violate the durable-store contract. A pending
operation journal could fence that interval but could not reconstruct lost
output; it would weaken the existing result recovery guarantee. The production
provider therefore does not wire a separate snapshot CAS into Mythic storage.
Native caller-store tests exercise publication ordering and the durable callback
contract using a fault-injected in-memory store, including owner fencing,
rejection neutrality, restoration, and lost acknowledgements.

Typed native persistence failures stay unresolved, even if an exported checkpoint
appears unchanged. The provider commits any exportable checkpoint and immutable
failure together, releases no native output, and retires the handle. Ordinary
rejected receives still leave the checkpoint unchanged and consume no durable
request slot. The v0.5.2 binary version-2 snapshot format matches the prior pinned
library. Campaign isolation changes the provider's storage layout: old unscoped
local-development payloads and callbacks must be rebuilt. No migration from the
shared server record is provided. For campaign records, always restore the
current trusted Mythic checkpoint rather than an older backup.

## Configuration and campaign creation

Use a backend containing the generic provider migration and RPC handlers,
including request-scoped container authorization. RPC bodies are ordinary JSON.
Mythic sends its normal transient authorization-context token in the AMQP header;
the provider forwards that context for storage calls. Mythic binds the context to
the registered provider and derives storage ownership from that identity.
Provider-specific shared secrets and message MAC envelopes are not used.

The request context exists only while the crypto request is in flight. Tokens
are excluded from durable request digests, snapshots, and retained results. The
provider does not retain operator credentials from container startup messages.

Set `RABBITMQ_URL` to the Mythic AMQP URL, or supply `RABBITMQ_PASSWORD` with optional `RABBITMQ_HOST`, `RABBITMQ_PORT`, `RABBITMQ_USER`, and `RABBITMQ_VHOST`. Defaults match the container SDK: `mythic_rabbitmq:5672`, user `mythic_user`, vhost `mythic_vhost`. The pinned SDK only supports AMQP; AMQPS is rejected. Broker confidentiality therefore requires a protected network or an external secure tunnel. Avoid printing credential-bearing environment values.

Start the service without a separate initialization command:

```sh
export RABBITMQ_URL='<Mythic broker URL>'
Payload_Type/mythic_beaconcrypt/.build/mythic-beaconcrypt
```

The first authenticated `prepare_profile` request for a campaign creates its
server identity and durable state. Later builds in the same campaign reuse that
identity. Requests for existing profiles and sessions only restore established
state; they cannot create a replacement identity when a record is missing.
Startup and capability discovery do not create or acquire any campaign state.
Keep the namespace and state-ID prefix stable across restarts.

For installation, run from the Mythic checkout:

```sh
./mythic-cli install folder ~/mythic-beaconcrypt
```

The installer uses `Payload_Type` as the service bundle location; this provider registers as a crypto consuming service. Mythic supplies the standard `RABBITMQ_*` values. The included optional override sets the provider name and runtime restrictions:

```sh
docker compose -f docker-compose.yml -f ~/mythic-beaconcrypt/compose.provider.yaml.example \
  up -d --no-deps mythic_beaconcrypt
```

Mythic and its storage RPC handlers must already be running. If using the optional override, include it on subsequent Compose operations too, including after Mythic regenerates its configuration.

The image contains an empty `.env` beside its binary because SDK initialization requires that file. Provider-specific settings are read from the process environment; copying the repository's `.env.example` alone does not load them.

The service needs one active replica per registered provider. It binds exclusive AMQP consumers before accepting campaign requests, so a duplicate process cannot displace campaign owners during startup. Broker loss or an uncertain SDK transport timeout ends the process; the Compose restart policy starts a fresh worker, which restores campaigns lazily as requests arrive. SDK retries can repeat an identical storage request after an uncertain publish; durable request digests and operation results provide reconciliation.

Select `provider:beaconcrypt:beaconcrypt` in a Mythic crypto parameter. A custom `BEACONCRYPT_PROVIDER_NAME` changes the middle component and must match the registered consuming-service name. Payload builders and agents must support this qualified provider selection.

## Existing agent protocol

Profile preparation returns JSON build material as opaque `agent_config` bytes, projected by Mythic as base64 `provider_config`:

```json
{"version":1,"server_kid":"0","server_public_key":"<base64 public key>"}
```

The same JSON is returned in the optional `enc_key`/`dec_key` compatibility fields for builders that already consume the historical material shape. No private identity or ratchet checkpoint is included.

The initial body is the historical plaintext staging request, inside Mythic's existing payload UUID/base64 framing:

```json
{"action":"staging","session_id":"<client correlation>","data":"<base64 GenerateRegistration bytes>"}
```

The provider calls `RegisterBeacon` with authenticated initial JSON containing `action: staging`, `status: success`, the supplied next UUID, and the exact session ID. Its outer reply contains `action`, `uuid`, `session_id`, and base64 registration `data`. Clients must validate the authenticated initial message before adopting the new UUID. Subsequent check-in/callback bodies use the same live Beaconcrypt client session; Mythic keeps its normal application messages and UUID transition.

Before native decryption, a bounded Cap'n Proto parser checks that the advertised sender matches the routed session. Native authentication remains authoritative, and the returned authenticated sender is checked again. The service uses only `EncryptAndUpdate` and `DecryptAndUpdate` for server traffic and discards their non-restorable observational state strings.

## Persistence and failure behavior

Each Mythic campaign (`operation_scope_id`) has its own Beaconcrypt server
identity, native handle, mutex, and durable record. Its key is
`(BEACONCRYPT_NAMESPACE, <BEACONCRYPT_STATE_ID>/campaign/<operation ID>)`.
`BEACONCRYPT_STATE_ID` is a prefix, defaulting to `server`. Authenticated Mythic operation
scope selects the owner; a request cannot select another campaign by supplying
its namespace, state ID, profile reference, or session reference.

Each campaign record contains its whole native server checkpoint in `state_blob`,
with that campaign's profiles, sessions, revocations, and retained-request metadata
in `provider_json`. A campaign's callbacks share its snapshot and serialize under
its mutex. Different campaigns have independent state revisions, admission
budgets, and locks; no router lock covers native work or storage RPCs. The
provider's bounded concurrent business consumer can handle different campaigns
concurrently, while Mythic's generic storage RPC consumer keeps its standard
serial dispatch. A blocked storage request can delay storage requests from other
campaigns; independent state ownership does not guarantee independent storage
latency. The existing Mythic schema and crypto-provider contract are sufficient.

For each native operation the provider still saves the whole campaign snapshot;
it does not persist per-callback deltas. The ownership check currently reads the
whole campaign row. A campaign mutex covers native work, export, and conditional
state/result commit. No ciphertext or plaintext is released before its matching
commit is authoritative. Replay returns the stored business result with the
current transient authorization context.

Restoration acquires an owner epoch, restores the native checkpoint, and immediately saves its newly activated export before serving requests. A stale writer discards its live state and cannot automatically steal ownership back. Lost commit replies are reconciled through immutable storage results; unresolved persistence never authorizes speculative native output.

Native errors are handled conservatively. An unchanged pre/post checkpoint can establish an effect-free rejection; typed native persistence failures remain unresolved even when those bytes match. Live handles are retired after native failures, and checkpoint/export failures never release output.

For an unresolved native receive or send failure whose checkpoint can be saved, the provider records the failed request ID on that session inside its opaque `provider_json`, atomically with the native checkpoint and failed-operation result. Fresh receive/send requests on that session require reestablishment. Replaying the original failed request, looking up its result, and revoking the session remain available; other sessions in the campaign continue normally. Mythic does not interpret or maintain this Beaconcrypt-specific session fence.

A lost AMQP response or a successful commit's lost acknowledgement does not create this fence. The native checkpoint and exact operation result are committed together, so retrying the same request ID recovers the stored result. A failure before an authoritative checkpoint commit releases no output and retires the handle before restoration. Revocation is a durable service tombstone and cannot erase peer secrets from a native checkpoint because the current public library has no removal API.

The initial implementation retains accepted-operation results and tombstones without pruning them. The advertised retention is a minimum, not a deletion deadline. Configurable per-campaign admission limits default to 1 MiB per message, 1,000 profiles, 1,000 sessions, and 5,000 retained requests; The message limit can be raised to 8 MiB, leaving room for native framing and JSON/base64 in Mythic's 16 MiB result limit; the 16 MiB checkpoint and 1 MiB metadata limits also apply. Normal admission reserves journal and metadata capacity for each session's first revocation and metadata capacity for its native-failure fence. Retrying that original revocation returns its immutable success; a fresh request ID for an already revoked session is rejected without journal growth. Capacity is rejected before more work where possible. Automatic expiry/compaction and sustained-load sizing remain follow-up work. Requests rejected before native work, or whose native failure yields an identical checkpoint, do not consume retained-operation slots. Some native registration failures advance snapshot bookkeeping; these remain unresolved and retained conservatively. Structural registration preflight rejects malformed frames before native work, while cryptographic validation stays in Beaconcrypt.

Other optional settings are `BEACONCRYPT_NAMESPACE`, `BEACONCRYPT_STATE_ID`, `BEACONCRYPT_SERVER_KID`, `BEACONCRYPT_RPC_TIMEOUT` (1–30 seconds), `BEACONCRYPT_MAX_MESSAGE_BYTES`, `BEACONCRYPT_MAX_PROFILES`, `BEACONCRYPT_MAX_SESSIONS`, `BEACONCRYPT_MAX_REQUESTS`, and `BEACONCRYPT_RESULT_RETENTION_SECONDS`.
