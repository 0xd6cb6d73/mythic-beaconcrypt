#!/usr/bin/env bash
set -euo pipefail

module_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
repository_root=$(cd -- "$module_root/../.." && pwd -P)
mythic_ref=${MYTHIC_REF:-crypto-shim}
poseidon_ref=${POSEIDON_REF:-crypto-shim}

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

for required in MYTHIC_SOURCE POSEIDON_SOURCE BEACONCRYPT_AMQP_TEST_URL CRYPTO_PROVIDER_TEST_DSN; do
    [[ -n ${!required:-} ]] || fail "Set $required to run the real Poseidon integration test."
done
for dependency in git go curl sha256sum tar mktemp flock x86_64-linux-gnu-gcc; do
    command -v "$dependency" >/dev/null || fail "Required command missing: $dependency"
done
[[ $(go env GOHOSTOS)/$(go env GOHOSTARCH) == linux/amd64 ]] || fail 'This executable integration test currently requires a Linux amd64 host.'
[[ -d /build && -w /build ]] || fail 'Poseidon writes payloads to /build. Provision /build owned by the test user, or run in a disposable environment with a writable /build.'

mythic_source=$(cd -- "$MYTHIC_SOURCE" && pwd -P)
poseidon_source=$(cd -- "$POSEIDON_SOURCE" && pwd -P)
for source_root in "$mythic_source" "$poseidon_source"; do
    git_root=$(git -C "$source_root" rev-parse --show-toplevel)
    git_root=$(cd -- "$git_root" && pwd -P)
    [[ "$source_root" == "$git_root" ]] || fail 'MYTHIC_SOURCE and POSEIDON_SOURCE must point to their Git repository roots.'
done
mythic_commit=$(git -C "$mythic_source" rev-parse --verify --end-of-options "${mythic_ref}^{commit}")
poseidon_commit=$(git -C "$poseidon_source" rev-parse --verify --end-of-options "${poseidon_ref}^{commit}")
printf 'Testing Mythic commit: %s\nTesting Poseidon commit: %s\nTesting provider working tree: %s\n' "$mythic_commit" "$poseidon_commit" "$repository_root"
git -C "$mythic_source" cat-file -e "$mythic_commit:mythic-docker/src/rabbitmq/crypto_provider.go" || fail 'Selected Mythic commit lacks the crypto-provider API.'
for source_file in Payload_Type/poseidon/main.go Payload_Type/poseidon/scripts/build-native.sh Payload_Type/poseidon/poseidon/agent_code/pkg/cryptoprovider/provider.go Payload_Type/poseidon/poseidon/agent_code/pkg/cryptoprovider/beaconcrypt_native.go; do
    git -C "$poseidon_source" cat-file -e "$poseidon_commit:$source_file" || fail "Selected Poseidon commit lacks Beaconcrypt support: $source_file"
done
for test_source in integration/mythic/server_integration_test.go integration/poseidon/poseidon_integration_test.go; do
    [[ -f "$repository_root/$test_source" ]] || fail "Integration test source is missing: $test_source"
done

mkdir -p "$module_root/.build"
stage=$(mktemp -d "$module_root/.build/poseidon-mythic.XXXXXX")
cleanup() { rm -rf -- "$stage"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$stage/poseidon" "$stage/bin"
: > "$stage/bin/.env"
git -C "$mythic_source" archive --format=tar "$mythic_commit" mythic-docker/src | tar --extract --file=- --directory="$stage"
git -C "$poseidon_source" archive --format=tar "$poseidon_commit" Payload_Type/poseidon | tar --extract --file=- --directory="$stage/poseidon"
server_source="$stage/mythic-docker/src"
poseidon_module="$stage/poseidon/Payload_Type/poseidon"
mkdir -p "$server_source/files"

native_matches() {
    [[ -f "$1/release/libbeaconcrypt.a" && -f "$1/module-version" ]] && [[ $(cat "$1/module-version") == "$2" ]]
}

# The provider under test uses its normal ignored native cache. External source
# checkouts are only archived; a matching Poseidon native cache is read as-is.
native_version=$(cd -- "$module_root" && go list -m -f '{{.Version}}' github.com/0xd6cb6d73/beaconcrypt)
provider_native="$module_root/.build/native-target"
# Validate the pinned release checksum even when the module version is unchanged.
"$module_root/scripts/build-native.sh"
poseidon_native_version=$(cd -- "$poseidon_module/poseidon/agent_code" && go list -m -f '{{.Version}}' github.com/0xd6cb6d73/beaconcrypt)
poseidon_native_cache=${POSEIDON_BEACONCRYPT_NATIVE_TARGET:-"$poseidon_source/Payload_Type/poseidon/.build/beaconcrypt-native-target"}
[[ "$poseidon_native_cache" == /* ]] || fail 'POSEIDON_BEACONCRYPT_NATIVE_TARGET must be an absolute path.'
poseidon_native_triple=x86_64-unknown-linux-gnu
# Never let cache validation or repair write into the external checkout. Copy
# a candidate into the private target root; the helper checks its release digest.
export POSEIDON_BEACONCRYPT_NATIVE_TARGET="$stage/native/poseidon"
if native_matches "$poseidon_native_cache/$poseidon_native_triple" "$poseidon_native_version"; then
    private_target="$POSEIDON_BEACONCRYPT_NATIVE_TARGET/$poseidon_native_triple"
    mkdir -p "$private_target/release"
    cp -- "$poseidon_native_cache/$poseidon_native_triple/release/libbeaconcrypt.a" "$private_target/release/"
    cp -- "$poseidon_native_cache/$poseidon_native_triple/module-version" "$private_target/"
fi
"$poseidon_module/scripts/build-native.sh" linux amd64
(
    cd -- "$server_source"
    GOEXPERIMENT=jsonv2 CGO_ENABLED=0 go build -mod=readonly -tags=nomsgpack -buildvcs=false -trimpath -o "$stage/bin/mythic_server" .
)
"$module_root/scripts/go.sh" build -mod=readonly -buildvcs=false -trimpath -o "$stage/bin/mythic-beaconcrypt" .
(
    cd -- "$poseidon_module"
    CGO_ENABLED=0 go build -mod=readonly -buildvcs=false -trimpath -o "$stage/bin/poseidon-container" .
)

# Both suites share the provider's real server lifecycle and database helpers.
# The Beaconcrypt-only test is compiled but not selected by this test filter.
cp -- "$repository_root/integration/mythic/server_integration_test.go" "$server_source/beaconcrypt_helpers_test.go"
cp -- "$repository_root/integration/poseidon/poseidon_integration_test.go" "$server_source/poseidon_integration_test.go"
(
    cd -- "$server_source"
    go mod edit -require="github.com/0xd6cb6d73/beaconcrypt@$native_version"
    go mod tidy
)
export MYTHIC_TEST_SERVER_BINARY="$stage/bin/mythic_server"
export BEACONCRYPT_TEST_PROVIDER_BINARY="$stage/bin/mythic-beaconcrypt"
export POSEIDON_TEST_CONTAINER_BINARY="$stage/bin/poseidon-container"
export POSEIDON_TEST_MODULE_ROOT="$poseidon_module"
export CGO_ENABLED=1
export CGO_LDFLAGS="-L$provider_native/release ${CGO_LDFLAGS:-}"
cd -- "$server_source"
# Build once above; share real services and one payload across all nine matrix
# cells and the lost-reply/provider-restart checks.
go test -race -tags=nomsgpack -count=1 -timeout=15m -v -run '^TestPoseidonBeaconcryptMythicE2E$' .
