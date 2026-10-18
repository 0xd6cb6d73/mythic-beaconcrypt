#!/usr/bin/env bash
set -euo pipefail

# CRYPTO_PROVIDER_TEST_DSN must name a dedicated test database: the real
# server initializes its full schema, migrations, administrator, and operation.
# MYTHIC_SOURCE is archived at MYTHIC_REF; uncommitted changes are excluded.
module_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
repository_root=$(cd -- "$module_root/../.." && pwd -P)
default_mythic_ref=crypto-shim
mythic_ref=${MYTHIC_REF:-$default_mythic_ref}

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

for required in MYTHIC_SOURCE BEACONCRYPT_AMQP_TEST_URL CRYPTO_PROVIDER_TEST_DSN; do
    if [[ -z ${!required:-} ]]; then
        fail "Set $required to run the real Mythic integration test."
    fi
done
for dependency in git go curl sha256sum flock tar mktemp; do
    command -v "$dependency" >/dev/null || fail "Required command missing: $dependency"
done

source_root=$(cd -- "$MYTHIC_SOURCE" && pwd -P)
git_root=$(git -C "$source_root" rev-parse --show-toplevel)
git_root=$(cd -- "$git_root" && pwd -P)
[[ "$source_root" == "$git_root" ]] || fail 'MYTHIC_SOURCE must point to the Mythic Git repository root.'
source_commit=$(git -C "$source_root" rev-parse --verify --end-of-options "${mythic_ref}^{commit}")
for source_file in \
    mythic-docker/src/main.go \
    mythic-docker/src/rabbitmq/crypto_provider.go \
    mythic-docker/src/crypto/provider/contract.go \
    mythic-docker/src/crypto/provider/store.go; do
    git -C "$source_root" cat-file -e "$source_commit:$source_file" 2>/dev/null || \
        fail "Selected Mythic commit lacks the generic crypto-provider API: $source_file"
done
test_source="$repository_root/integration/mythic/server_integration_test.go"
[[ -f "$test_source" ]] || fail 'Real Mythic integration test source is missing from this provider repository.'
printf 'Testing Mythic source commit: %s\n' "$source_commit"

# Direct runner invocations also validate cached bytes against the pinned release.
"$module_root/scripts/build-native.sh"

mkdir -p "$module_root/.build"
stage=$(mktemp -d "$module_root/.build/mythic-integration.XXXXXX")
cleanup() {
    rm -rf -- "$stage"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Archive committed server source only. Working-tree changes, the original
# checkout, and both production module files remain untouched.
git -C "$source_root" archive --format=tar "$source_commit" mythic-docker/src | \
    tar --extract --file=- --directory="$stage"
server_source="$stage/mythic-docker/src"
mkdir "$stage/bin"
: > "$stage/bin/.env"

# Use the server's build profile without running its mutating make target.
# Its runtime needs this source directory for migrations and bundled assets.
(
    cd -- "$server_source"
    GOEXPERIMENT=jsonv2 CGO_ENABLED=0 go build -mod=readonly -tags=nomsgpack \
        -buildvcs=false -trimpath -o "$stage/bin/mythic_server" .
)
"$module_root/scripts/go.sh" build -mod=readonly -buildvcs=false -trimpath \
    -o "$stage/bin/mythic-beaconcrypt" .
native_version=$(cd -- "$module_root" && go list -m -f '{{.Version}}' github.com/0xd6cb6d73/beaconcrypt)

# Only the temporary test module imports the native client. Its dependency
# version must match the production provider and its checked native archive.
cp -- "$test_source" "$server_source/server_integration_test.go"
(
    cd -- "$server_source"
    go mod edit -require="github.com/0xd6cb6d73/beaconcrypt@$native_version"
    go mod tidy
)

export MYTHIC_TEST_SERVER_BINARY="$stage/bin/mythic_server"
export BEACONCRYPT_TEST_PROVIDER_BINARY="$stage/bin/mythic-beaconcrypt"
export CGO_ENABLED=1
export CGO_LDFLAGS="-L$module_root/.build/native-target/release ${CGO_LDFLAGS:-}"
cd -- "$server_source"
go test -race -tags=nomsgpack -count=1 -timeout=5m -v -run '^TestBeaconcryptMythicE2E$' .
