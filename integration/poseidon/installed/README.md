# Installed Mythic end-to-end tests

This test uses an existing Mythic instance, its installed HTTP C2 profile, the
installed Poseidon payload container from `crypto-shim`, and the
running Beaconcrypt cryptographic provider. It builds and downloads a real Poseidon ELF
through Mythic's operator API, then executes that artifact against the HTTP C2
listener. All queries and task submission go through the operator HTTP/GraphQL
APIs. There are no database fixtures or agent-message forwarding proxies.

The standalone HTTP suite uses Linux amd64 with Python 3. The P2P suite below
also supports Linux ARM64 targets. The Mythic instance must run our `crypto-shim`
server code, Hasura and its matching metadata, the HTTP profile from
`MythicC2Profiles/http`'s `Mythic-v4.0.0` branch, our Poseidon container, and the
`beaconcrypt` provider advertising `Native` and `WASM` from its `main` branch.
The Mythic server remains on `crypto-shim`. Configure HTTP's `http/c2_code/config.json` listener with
`port: 8088`, `bind_ip: "127.0.0.1"`, and `use_ssl: false` when using Mythic's
normal host networking. The script starts that installed HTTP profile if its
internal server is stopped; it does not change the listener configuration.

Install Poseidon as described in [setup](../SETUP.md), then run from this provider checkout:

```sh
python3 integration/poseidon/installed/test_poseidon.py \
  --env-file "$HOME/Mythic/.env" \
  --url https://127.0.0.1:7443 \
  --callback-port 8088 \
  --beaconcrypt-backend native \
  --insecure
```

`--insecure` accepts the local instance's self-signed operator HTTPS certificate;
omit it when using a trusted certificate. Credentials are read from
`MYTHIC_ADMIN_USER` and `MYTHIC_ADMIN_PASSWORD` in the specified environment file
and are not printed or stored in reports.

Use `--api-token-file /path/to/token` to run under an existing operation bot
instead. This keeps the operator's current operation unchanged and lets tests
use a fresh campaign with its own provider state and admission budget. The token
needs `payload.write`, `task.write`, `callback.read`, `response.read`, `file.write`,
`c2.write`, `mythic.read`, and `operation.read`. Store it in a file readable only by
its owner, and revoke the temporary token after the run. The script does not
create operations or issue tokens. A campaign that has reached its provider's
retained-request limit cannot admit another payload profile; select a fresh test
campaign instead of resetting live callbacks.

The default runs three simultaneous real agents and three `pwd` task/response
exchanges per agent. `--agents 1` through `--agents 3` and `--messages 1` through
`--messages 3` select one case. To run every combination:

```sh
python3 integration/poseidon/installed/test_poseidon.py --insecure --matrix \
  --beaconcrypt-backend native --work-dir /path/to/http-native
python3 integration/poseidon/installed/test_poseidon.py --insecure --matrix \
  --beaconcrypt-backend wasm --work-dir /path/to/http-wasm
```

`--beaconcrypt-backend` accepts `native` (the default) or `wasm`. It selects
`provider:beaconcrypt:Native` or `provider:beaconcrypt:WASM` in the submitted
HTTP profile. There is no `beaconcrypt_backend` payload build parameter. The
selected alias must appear exactly in each callback's `crypto_type`; a legacy
`beaconcrypt` callback cannot satisfy a Native or WASM test. These aliases choose
the agent implementation and use the same worker engine and wire protocol.

Each invocation's nine cases execute sequentially and share one payload build.
They start 18 fresh agent processes and verify 36 `pwd` exchanges. Agents within each case run
simultaneously; each round submits their tasks concurrently. Every agent must
have a distinct callback using the selected `Native` or `WASM` alias, report its
own PID and working directory, and return exactly one correct response to each task. The test waits
for both `pwd` and `exit` to appear in each callback's loaded commands before
submitting tasks, since Mythic populates those after creating the callback.
After each case,
all agents exit through their real `exit` task, and the test checks the responses
again. This installed test does not synchronize wire-level polling with a proxy;
the [isolated integration suite](../README.md) covers synchronized polls,
lost replies, and provider restart.

The script prints its evidence directory before starting. It retains the
downloaded ELF, build configuration, per-agent logs, per-case reports, and an
aggregate `report.json`. Use `--work-dir /path/to/empty-directory` to choose it.
Registration, check-in, background polls, and `exit` tasks are additional traffic
excluded from the message counts. On failure, cleanup stops only the agent
process groups started by this test. Mythic and its installed services keep
running; payloads, callbacks, tasks, and responses remain available in Mythic for
inspection.

## TCP P2P cryptography matrix

The P2P test runs all nine combinations of `none` (unencrypted),
`aes256_hmac` (standard AESPSK), and `beaconcrypt` on the HTTP egress and TCP
P2P beacons. Each default cell uses one mode for all its TCP children:

| HTTP egress / TCP P2P | none | AESPSK | Beaconcrypt |
| --- | --- | --- | --- |
| none | Included | Included | Included |
| AESPSK | Included | Included | Included |
| Beaconcrypt | Included | Included | Included |

Install the standard `MythicC2Profiles/tcp` profile from `Mythic-v4.0.0` alongside
HTTP, and use the P2P-enabled Mythic `crypto-shim` server with the Poseidon
`crypto-shim` revision. TCP is
an agent-side listener; its profile container must register, but it does not run
a separate C2 server. The HTTP listener must already be running.

```sh
python3 integration/poseidon/installed/test_p2p.py --insecure \
  --api-token-file /path/to/temporary-bot-token \
  --beaconcrypt-backend native \
  --work-dir /path/to/poseidon-p2p-native
```

Repeat with `--beaconcrypt-backend wasm` and a separate evidence directory to
test the embedded backend. This flag applies to Beaconcrypt selections on both
the HTTP egress and TCP children; `none` and `aes256_hmac` keep their normal
settings. Reports retain the selected backend and exact provider alias.

Add `--mixed-children` to also test each egress mode with one `none`, one AESPSK,
and one Beaconcrypt TCP child simultaneously. This requires `--p2p-agents=3`
(the default) and runs twelve cells total. Per-agent reports record the selected
mode; mixed cells also record all three child modes.

`--egress-architecture` and `--p2p-architecture` independently select `amd64`
or `arm64`; both default to the Linux host's architecture. Native targets run
directly. On an amd64 host, ARM64 targets require explicit `--qemu-aarch64` and
`--arm64-sysroot` paths. The suite launches `qemu-aarch64 -L <sysroot> <agent>`;
it does not register or rely on global binfmt handlers. The sysroot must contain
the ARM64 dynamic loader and libraries required by the built agents.

For an amd64 egress with ARM64 TCP children and mixed encryption:

```sh
python3 integration/poseidon/installed/test_p2p.py --insecure \
  --api-token-file /path/to/temporary-bot-token \
  --egress-architecture amd64 --p2p-architecture arm64 \
  --beaconcrypt-backend wasm \
  --qemu-aarch64 /path/to/qemu-aarch64 \
  --arm64-sysroot /path/to/arm64-sysroot --mixed-children \
  --work-dir /path/to/poseidon-p2p-wasm-amd64-arm64
```

Run each architecture pair (`amd64/amd64`, `amd64/arm64`, `arm64/amd64`, and
`arm64/arm64`) from an amd64 host with those emulator paths and a separate
evidence directory. Each invocation runs the full nine-cell crypto matrix,
plus three mixed-child cells when requested. On a native ARM64 host the
`arm64/arm64` pair needs no emulator; amd64 execution on ARM64 is not provided.
Build reports record the exact launch command. Downloaded ELFs must report the
requested machine architecture, and callback architecture must match it while
PID and working directory still match the launched process.

The backend can also differ by role. `--egress-beaconcrypt-backend` and
`--p2p-beaconcrypt-backend` override `--beaconcrypt-backend` for HTTP and TCP
respectively. For a Native egress with three WASM children, run:

```sh
python3 integration/poseidon/installed/test_p2p.py --insecure \
  --api-token-file /path/to/temporary-bot-token \
  --egress-beaconcrypt-backend native --p2p-beaconcrypt-backend wasm \
  --cross-backend-only --work-dir /path/to/p2p-native-to-wasm
```

Swap the two role options to test a WASM egress with Native children. Add the
architecture and emulator options above for other architecture pairs.
`--cross-backend-only` selects only the Beaconcrypt/Beaconcrypt cell, requires
three children, and cannot be combined with `--mixed-children`. With the default
three message rounds it starts four agents and checks twelve `pwd` responses.
Omit the filter to run all nine cryptography combinations with those role
backend choices.

By default each cell starts one real HTTP egress agent and three real TCP P2P
agents. Every process has a distinct working directory, including the egress.
Before sending `link_tcp`, the suite checks Linux procfs for a TCP `LISTEN`
socket owned by that exact child process, including QEMU when used. A port left
in `TIME_WAIT`, a socket owned by another process, or a child that has only bound
the port does not count as ready. The probe makes no connection, preserving the
relay's first connection while allowing slower WASM initialization to finish.
The real `link_tcp` task connects the relay to each loopback child listener.
The test checks each callback's payload, PID, architecture, selected cryptography
and loaded commands, and verifies active TCP graph edges between every child
and its relay.
Children are built with TCP only, so they have no direct HTTP egress.

Each of three rounds submits `pwd` concurrently to the egress and all three
children. The dispatch oracle compares each task's callback ID and its single
output against the exact directory passed to that process's `Popen(cwd=...)`;
it never derives expected output from Mythic's callback metadata. Swapped egress
and P2P results, swapped siblings, duplicate output, wrong callback ownership and
missing results all fail. For each architecture pair, the nine default cells
exercise 36 real processes and 108 `pwd` task/response exchanges; `--mixed-children` increases these to 48
processes and 144 exchanges. Registration, links, polls and exits are extra
traffic. `--p2p-agents` and `--messages` accept 1–3 for shorter diagnostic runs;
all nine uniform crypto combinations always run. Counts in reports reflect the
selected cells, agents and messages.

Children exit through their real tasks before the relay exits. The test checks
all persisted `pwd` results again after exit. On failure it terminates only its
own process groups. Payloads, callbacks, tasks, builds, binaries, per-role logs,
route checks and exact expected/actual results remain available for inspection.
Use a fresh bot operation and revoke its temporary token after the run, as above.
Keep evidence outside Mythic's `tmp` directory: `mythic-cli install` clears that
directory during installation.

The offline tests check crypto/architecture selection, ELF validation, explicit
emulator commands and matrix coverage, and verify that the oracle rejects routing
mixups. Listener regressions reproduce the real `TIME_WAIT` false positive and verify
socket ownership and `LISTEN` state. Backend tests check exact advertised aliases, both role overrides,
callback selection and rejection of hidden backend build parameters. The
integration itself always uses real agents and the real server:

```sh
python3 -m unittest discover -s integration/poseidon/installed -p 'test_*.py' -v
```
