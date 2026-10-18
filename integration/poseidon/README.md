# Poseidon acceptance tests

These tests live with the Beaconcrypt provider and exercise its integration with
Poseidon and Mythic. Poseidon keeps its package-level tests in its own repository.
For a running deployment, see [setup](SETUP.md) and the
[installed-stack suite](installed/README.md).

This suite runs the production Mythic server, the production Beaconcrypt provider,
the production Poseidon payload container, and executable Poseidon agents produced
by the container's normal build function. It needs a disposable RabbitMQ broker
and PostgreSQL credentials with `CREATEDB`; it creates and drops its own database.
Do not point it at a broker shared with a running Mythic installation: real
payload containers use their ordinary queue names.

On Linux amd64, with Go, `curl`, `sha256sum`, `flock`, and
`x86_64-linux-gnu-gcc` installed, provision `/build` owned by the test user or run
in a disposable environment with a writable `/build`. Poseidon's normal builder
uses that fixed directory. The runner checks it before starting, and cleanup
removes only this test's `/build/<payload-uuid>-linux-amd64` artifact after the
payload container stops; it never clears `/build`.

Run from this provider checkout:

```sh
MYTHIC_SOURCE="$HOME/Mythic" \
MYTHIC_REF=crypto-shim \
POSEIDON_SOURCE="$HOME/poseidon" \
POSEIDON_REF=crypto-shim \
BEACONCRYPT_AMQP_TEST_URL=amqp://guest:guest@127.0.0.1:5672/ \
CRYPTO_PROVIDER_TEST_DSN='postgres://test:test@127.0.0.1:5432/postgres?sslmode=disable' \
make test-poseidon
```

The default command runs the entire matrix and the retry/restart scenario. The
runner prints the exact committed Mythic and Poseidon revisions, archives them
into a temporary directory, and tests this provider working tree. `MYTHIC_REF`
and `POSEIDON_REF` both default to `crypto-shim`; uncommitted changes in those
external checkouts are excluded. It builds the server, provider, and payload
container once. The test shares these real services
and one payload artifact across the scenarios, with a fresh agent process and
native session for each agent instance. Temporary source trees and executables
are removed on exit. The provider uses its normal ignored native cache and checks
its release checksum before use. Poseidon always uses a private cache outside its
staged module. A version-matching archive from the external checkout's ignored
`.build/beaconcrypt-native-target` cache may seed that private cache;
`POSEIDON_BEACONCRYPT_NATIVE_TARGET` may name another absolute candidate root.
The real release downloader then verifies the pinned SHA-256 and downloads or
replaces the private candidate when needed. The external checkout and its cache
remain read-only. The private cache is removed on exit. No production module file
is changed, and neither native source compilation nor Rust or Cap'n Proto build
tools are required.

The test checks that the real payload service registers its `beaconcrypt`
supported-crypto-scheme declaration alongside its commands and build parameters.
It authenticates through Mythic's actual operator HTTP API, builds a
Poseidon payload through Mythic's provider-config projection, AMQP build dispatch,
the Poseidon SDK build callback, and authenticated artifact upload. All agent
instances execute that uploaded ELF. Tasks go through the real task-creation API
and Poseidon container task handlers; agents register, check in, poll for tasks,
execute `pwd`, and post their responses through the production HTTP transport.

The nine matrix cases cover every combination below. A counted message is one
application task/response exchange per agent: one `pwd` task delivered and its
response stored by Mythic. Registration, check-in, background polls, and the final
`exit` control task are additional traffic excluded from these counts.

| Simultaneous agents | 1 message per agent | 2 messages per agent | 3 messages per agent |
| --- | --- | --- | --- |
| 1 | 1 exchange | 2 exchanges | 3 exchanges |
| 2 | 2 exchanges | 4 exchanges | 6 exchanges |
| 3 | 3 exchanges | 6 exchanges | 9 exchanges |

The matrix starts 18 real agent instances and verifies 36 `pwd` task/response
exchanges. Cases run in sequence; all agents within a case run simultaneously.
Before each round, the forwarding proxy holds a real poll from every agent while
the test creates and submits all of that round's tasks, then releases those polls
together. Each agent has a separate working directory. The test verifies distinct
callbacks and durable provider sessions, checks each task's response against its
own agent's directory, and requires exactly one stored response. All agents exit
through their real `exit` command before the next case starts.

A separate single-agent scenario injects a lost reply after the real server
handles a callback request. It checks that the agent retries the identical
ciphertext, Mythic returns the identical committed ciphertext, and the task
response is stored once. It then restarts the crypto provider while retaining the
same live agent and verifies another `pwd` task succeeds. The forwarding proxy
only holds, forwards, or drops traffic; production code handles the cryptographic
protocol and task execution.

Only HTTP C2 metadata is seeded. The real Poseidon HTTP transport connects to
Mythic's `/agent_message` endpoint with the ordinary `mythic: http` header. This
does not install or validate the separate HTTP C2 container, reverse proxy,
Hasura, or browser UI. Its optional OPSEC/config RPC checks have no consumer in
this test and use Mythic's existing bounded error-tolerant build behavior.
