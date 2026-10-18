# Deploying Poseidon with Beaconcrypt

These instructions apply to the external Poseidon `crypto-shim` checkout used
with this provider.

The Poseidon branch targets Mythic 4.0 beta with the generic crypto provider
extension from Mythic's `crypto-shim` branch. It adds an opt-in Beaconcrypt client to
Poseidon; the existing AES builds keep their normal configuration.
The Beaconcrypt client and native library are pinned to v0.6.0. Upgrade the provider and agents together; v0.5.2 wire messages are incompatible with the new CBOR encoding.

Install the Poseidon checkout being tested and enable its local build context.
This exercises that source rather than a published image. From your Mythic
directory:

```sh
sudo ./mythic-cli install folder /path/to/poseidon
sudo ./mythic-cli config set poseidon_use_build_context true
sudo ./mythic-cli config set poseidon_use_volume false
sudo ./mythic-cli build poseidon
sudo ./mythic-cli start poseidon
```

Set those options explicitly when replacing an existing installation: Mythic can
retain settings from an older image or named volume. The locally built payload
container includes the pinned Beaconcrypt release archives; no Beaconcrypt source
checkout or native build tools are required on an agent host. The container keeps its
native archives under `/opt/poseidon`, outside Mythic's `/Mythic` source mount.
`POSEIDON_BEACONCRYPT_NATIVE_TARGET` selects an absolute archive root. Each target
has its own `<Rust-target-triple>/release/libbeaconcrypt.a` and matching
`<Rust-target-triple>/module-version`; old archives directly under the root are
not reused. Linux amd64 uses `x86_64-unknown-linux-gnu`, and Linux ARM64 uses
`aarch64-unknown-linux-gnu`. macOS Intel uses `x86_64-apple-darwin`, and macOS ARM64 uses `aarch64-apple-darwin`. The pinned module version must match the agent dependency.
A manual payload build needs `curl`, `sha256sum`, `flock`, and the target C compiler.
Run `Payload_Type/poseidon/scripts/build-native.sh linux amd64` or
`Payload_Type/poseidon/scripts/build-native.sh linux arm64` (or `darwin amd64` / `darwin arm64`) to download the target's
`gobinds` archive from the release pinned in the agent's Go module; omitted targets
default to the host. The provider's build script downloads its host archive into
its existing flat `.build/native-target` cache. Both downloaders verify the pinned
SHA-256 on cached and newly downloaded archives. They fail for unlisted versions
or targets rather than compiling a replacement. A Rust toolchain is not required for the provider or payload build.

Run the separate `mythic-beaconcrypt` provider with the matching
Mythic service credential before creating a payload. In the HTTP or TCP C2 profile's
`AESPSK` crypto parameter, choose **beaconcrypt (beaconcrypt)** under
**Encryption Type** in the normal payload creation wizard. Mythic discovers
compatible registered providers using Poseidon's `supported_crypto_schemes`
declaration. That choice is serialized as `provider:beaconcrypt:beaconcrypt`;
a different registered service name changes the middle component.
Mythic prepares the profile and supplies `provider_config` to the payload
builder; server keys are not manual Poseidon build parameters. The first profile
build in a Mythic campaign creates that campaign's native server identity and
durable state. Its callbacks share one snapshot; other campaigns use independent
identities and snapshots. There is no separate `--initialize` step.

The pinned MythicContainer SDK does not yet expose `supported_crypto_schemes`.
A narrow local sync adapter adds that generic field to the full payload
definition on startup and forced resync. It retains the SDK's command metadata,
queue consumers, build/task handlers, and container startup authorization. The
adapter can be removed once the SDK exposes the declaration directly.

Poseidon's Beaconcrypt build integration supports Linux and macOS `AMD_x64` and `ARM_x64`
executables (`mode=default`) with exactly one direct `http` profile or one P2P
`tcp` profile. Disable `static` and `garble`. The payload container must provide
the matching target compiler and native archive. Other targets, transports, and
multiple C2 profiles are rejected by this integration; these restrictions do not
apply to legacy AES builds.

The v0.6.0 macOS archives require macOS 15.5 or newer on Intel and macOS 26.5 or newer on ARM64, based on their native object deployment targets. The builder uses the existing osxcross compilers and sets those deployment targets. For Beaconcrypt macOS builds, it stages a private copy of the pinned Go module with the selected archive and uses an alternate module file, satisfying the binding's hardcoded Darwin archive path without modifying the shared module cache. These release-archive requirements apply to Beaconcrypt builds.

TCP agents use ordinary `link_tcp` routing through an HTTP egress callback.
AESPSK and Beaconcrypt can be selected independently for the HTTP egress and
each TCP agent.

The builder preserves the provider's configuration bytes and includes the
`beaconcrypt` build tag. At runtime Poseidon performs Beaconcrypt registration,
then encrypts its normal Mythic check-in and messages through that session.
Mythic owns the server-side durable checkpoint. The agent's native session lives
in memory; restarting the agent creates a fresh registration.

Run the [isolated acceptance suite](README.md) for payload build, task, retry and
provider restart coverage. The [installed-stack suite](installed/README.md) uses
real C2 profiles and covers HTTP concurrency plus all nine none/AESPSK/Beaconcrypt
HTTP-egress and TCP-P2P combinations, with optional mixed-encryption TCP siblings.
Its egress and child architecture flags exercise any Linux amd64/ARM64 pairing;
ARM64 agents on amd64 run through an explicitly selected QEMU user emulator and
sysroot, without global binfmt changes.
