#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ ! -f "$project_root/.build/native-target/release/libbeaconcrypt.a" ]]; then
    printf '%s\n' 'Native library missing; run ./scripts/build-native.sh first.' >&2
    exit 1
fi
cd "$project_root"
module_version=$(go list -m -f '{{.Version}}' github.com/0xd6cb6d73/beaconcrypt)
if [[ ! -f "$project_root/.build/native-target/module-version" ]] || [[ $(cat "$project_root/.build/native-target/module-version") != "$module_version" ]]; then
    printf '%s\n' 'Native dependency changed; run ./scripts/build-native.sh.' >&2
    exit 1
fi
export CGO_ENABLED=1
export CGO_LDFLAGS="-L$project_root/.build/native-target/release ${CGO_LDFLAGS:-}"
exec go "$@"
