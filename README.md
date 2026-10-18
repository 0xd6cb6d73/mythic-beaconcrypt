# mythic-beaconcrypt

This repository instantiates the crypto-provider template before adding the Beaconcrypt protocol. Paths below are relative to `Payload_Type/mythic_beaconcrypt`.

This standalone Go service shows the Mythic crypto-provider API without a particular cryptographic implementation. It registers `beaconcrypt`, describes the `example` scheme and explicitly rejects the six protocol methods with `not_implemented`. Replace `internal/provider` with your implementation before building an agent that selects it.

This example requires [Mythic's crypto-provider API v1](https://github.com/0xd6cb6d73/Mythic/blob/611243e0fb7658b5af287904306ee7c52286ed76/mythic-docker/src/crypto/provider/README.md). The pinned MythicContainer SDK supplies RabbitMQ transport and request authorization, but does not yet have a crypto service registration API. The small adapter here supplies that lifecycle; it does not register a payload type or C2 profile.

## Files to keep and files to replace

| Path | Purpose |
| --- | --- |
| `main.go` | Load provider configuration, connect the backend to the service, and stop on SIGTERM. |
| `internal/provider` | Replace this package with your protocol, agent configuration, key handling, state ownership and limits. |
| `internal/service` | Shared configuration, registration, authorization checks and process lifecycle. |
| `internal/transport` | SDK adapter, exclusive queues, bounded concurrent RPC and reply handling. |
| `internal/wire` | API v1 JSON contract, validation, routing and optional opaque state types. |
| `internal/storage` | Authenticated client for Mythic's optional opaque state store. |

The copied generic files are pinned in the root `template.json`. Run `python3 scripts/check-template.py` from the repository root to verify their normalized SHA-256 digests; an optional `--source /path/to/ExampleContainers` also verifies the recorded source commit. The `internal/provider` package retains the template's explicit protocol stubs. Cryptographic algorithms, native libraries and their build dependencies belong in the replaceable provider package and its Docker build.

## Run and install

Run `make test` from the repository root for the native-free tests, or `make build` to build the service. For a local broker, export `RABBITMQ_URL` or the connection settings shown in `.env.example`, then run `make run`. The SDK also reads an `.env` file beside the executable. The Dockerfile pre-creates that file and runs the binary as an unprivileged user.

Install this service repository from the Mythic checkout:

```sh
./mythic-cli install folder /path/to/mythic-beaconcrypt
```

Mythic supplies the `RABBITMQ_*` settings to installed containers. `BEACONCRYPT_PROVIDER_NAME` defaults to `beaconcrypt`; `BEACONCRYPT_RPC_TIMEOUT` defaults to `20s`. The pinned SDK supports `amqp` URLs. Restart the container after changing connection configuration.

## Required provider lifecycle

`service.Run` starts exclusive provider, resync and startup queues before announcing the service with `consuming_container_sync`. Registration includes `type: crypto`, a version and capabilities; the business route is `<registered-name>_crypto_provider_rpc`. The resync queue re-announces the same definition. Startup notifications do not supply a credential to retain, and constructing a backend does not create campaign state.

Every business request carries the transient Mythic authorization context in both its RabbitMQ header and JSON body. The service checks that they agree before calling the backend. Preserve the supplied `context.Context` for every storage RPC, echo `auth_context`, `request_id` and `operation_scope_id` in responses, and never persist or log the authorization context. It changes between attempts and is excluded from request digests.

The SDK owns the connection and outgoing RPC correlation. The adapter processes a bounded number of business requests concurrently so one operation cannot block all other operations. It terminates the worker after connection loss or an uncertain transport timeout; let the container supervisor start a fresh process.

## Implementing the protocol

`internal/provider.Provider.Handle` is the dispatch point:

| Method | Required implementation |
| --- | --- |
| `describe` | Return the same capabilities used during registration. Implemented here. |
| `prepare_profile` | Create or restore a provider profile and return an opaque profile reference and agent configuration. |
| `begin_session` | Authenticate the agent's initial message and routing claims, establish a session, and return its reply and opaque session identity. |
| `open` | Authenticate and decrypt one incoming message within the selected operation and session. |
| `seal` | Encrypt and authenticate one outgoing message within that session. |
| `get_operation` | Resolve a previous request's outcome using its original request ID. |
| `revoke_session` | Revoke the selected session and prevent subsequent use. |

Validate every request before processing. Honor the advertised size limit and result-retention interval, and preserve the operation scope when looking up profiles, sessions and request IDs. Keep cryptographic formats opaque to Mythic. A `rejected` failure promises there is no unresolved cryptographic effect; after an ambiguous stateful effect, return `unresolved` and resolve it through `get_operation` instead of retrying it as new work.

This skeleton advertises `volatile` session persistence because it has no durable implementation. It creates no profiles or sessions and does not claim usable encryption. A real implementation must provide repeatable outcomes for repeated request IDs, reject reuse with changed inputs, and decide whether session state survives a worker restart. Advertise `durable` only when that promise is implemented.

The optional `storage.Store` passed to `provider.New` stores opaque provider snapshots and exact operation results through Mythic RPC. For a durable implementation, scope state keys to the Mythic operation, acquire an owner epoch, and commit snapshot and result together using the expected revision and owner epoch. A stale owner must stop processing. Storage `request_id` values identify transport calls; the immutable operation request ID and input digest identify the cryptographic effect. State access must use the current authenticated request context. The example deliberately performs no storage calls at startup or during `describe`.

## Agent-side integration

Installing this service supplies the server half of a protocol. The agent needs its own matching implementation and compile-time configuration. Use the qualified selection `provider:<registered-name>:<scheme>`; for this skeleton that is `provider:beaconcrypt:example`. Return only the agent configuration your protocol needs from `prepare_profile`.

The payload container must advertise `supported_crypto_schemes: ["example"]` in its payload-type sync definition. These are bare scheme names, independent of the provider worker's registered name. Mythic passes the profile's opaque `agent_config` bytes to the builder as the base64 string `provider_config`; decode it before parsing the provider-specific configuration, and embed it for the selected C2 profile.

For an agent with a provider registry, add the provider's session implementation, register its scheme, and connect its target-specific build preparation and configuration parsing. Profiles should use the shared crypto session interface rather than compare the provider name to a particular library. Do not add Beaconcrypt dependencies or checks to a different provider's agent plumbing.

## License

The original scaffold is available under the BSD Zero Clause terms reproduced in `NOTICE`. The adapted Mythic wire contract retains its BSD 3-Clause notice there. Keep these notices when copying the example into a new repository.
