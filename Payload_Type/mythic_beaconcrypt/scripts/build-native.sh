#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_root"
if [[ $# != 0 ]]; then
    printf '%s\n' 'Usage: build-native.sh' >&2
    exit 1
fi
host_os=$(go env GOHOSTOS)
host_arch=$(go env GOHOSTARCH)
case "$host_os/$host_arch" in
    linux/amd64) rust_target=x86_64-unknown-linux-gnu ;;
    linux/arm64) rust_target=aarch64-unknown-linux-gnu ;;
    *) printf 'Unsupported Beaconcrypt provider target: %s/%s; expected linux/amd64 or linux/arm64.\n' "$host_os" "$host_arch" >&2; exit 1 ;;
esac
module_version=$(go list -m -f '{{.Version}}' github.com/0xd6cb6d73/beaconcrypt)
asset_name=
expected_sha=
while read -r version target asset digest extra; do
    [[ -z "$version" || "$version" == \#* ]] && continue
    if [[ "$version" == "$module_version" && "$target" == "$rust_target" ]]; then
        if [[ -n "$asset_name" || -n "$extra" || ! "$asset" =~ ^[a-zA-Z0-9._-]+$ || ! "$digest" =~ ^[0-9a-f]{64}$ ]]; then
            printf '%s\n' 'Invalid or duplicate pinned Beaconcrypt release manifest entry.' >&2
            exit 1
        fi
        asset_name=$asset
        expected_sha=$digest
    fi
done < "$project_root/scripts/beaconcrypt-releases.txt"
if [[ -z "$asset_name" || ! "$module_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([+-][a-zA-Z0-9._-]+)?$ ]]; then
    printf 'No pinned Beaconcrypt release archive for %s (%s); update scripts/beaconcrypt-releases.txt with a verified release and checksum.\n' "$module_version" "$rust_target" >&2
    exit 1
fi
for dependency in sha256sum flock mktemp; do
    command -v "$dependency" >/dev/null || { printf 'Required download tool missing: %s\n' "$dependency" >&2; exit 1; }
done
build_root="$project_root/.build"
native_target="$build_root/native-target"
mkdir -p "$native_target/release"
exec 9>"$build_root/native-download.lock"
flock 9
archive="$native_target/release/libbeaconcrypt.a"
marker="$native_target/module-version"
# Source-built archives may have the same module-version. Trust a cached release
# only after checking its exact, host-specific bytes against the pinned digest.
if [[ -f "$archive" && -f "$marker" ]] && [[ $(cat "$marker") == "$module_version" ]] &&
    printf '%s  %s\n' "$expected_sha" "$archive" | sha256sum --check --status; then
    exit 0
fi
command -v curl >/dev/null || { printf '%s\n' 'curl is required to download the pinned Beaconcrypt release archive.' >&2; exit 1; }
stage=$(mktemp -d "$native_target/.release-download.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
url="https://github.com/0xd6cb6d73/beaconcrypt/releases/download/$module_version/$asset_name"
curl --fail --location --silent --show-error \
    --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 20 --max-time 300 \
    --output "$stage/libbeaconcrypt.a" "$url"
if ! printf '%s  %s\n' "$expected_sha" "$stage/libbeaconcrypt.a" | sha256sum --check --status; then
    printf 'Checksum mismatch for Beaconcrypt release archive %s (%s).\n' "$asset_name" "$module_version" >&2
    exit 1
fi
printf '%s\n' "$module_version" > "$stage/module-version"
chmod 0644 "$stage/libbeaconcrypt.a" "$stage/module-version"
# Each rename publishes a complete file on the cache filesystem. The version
# marker follows the verified archive, so interrupted updates remain detectable.
mv -f -- "$stage/libbeaconcrypt.a" "$archive"
mv -f -- "$stage/module-version" "$marker"
