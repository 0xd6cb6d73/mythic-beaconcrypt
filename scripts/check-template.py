#!/usr/bin/env python3
"""Check the copied crypto-provider scaffold without fetching its source repository."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "template.json"


def relative_path(value):
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or str(path) in ("", "."):
        raise ValueError(f"invalid relative template path: {value!r}")
    return path


def module_path(directory):
    for line in (directory / "go.mod").read_text().splitlines():
        if line.startswith("module "):
            return line.split()[1]
    raise ValueError(f"no module directive in {directory / 'go.mod'}")


def digest(content):
    return hashlib.sha256(content).hexdigest()


def git(source, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(source), *arguments], stderr=subprocess.PIPE
    )


def source_contents(source, manifest, relative):
    path = relative_path(manifest["service_directory"]) / relative_path(relative)
    committed = git(source, "show", f"HEAD:{path}")
    if (source / path).read_bytes() != committed:
        raise ValueError(f"source checkout differs from HEAD: {path}")
    return committed


def check(manifest, source=None):
    if not re.fullmatch(r"[0-9a-f]{40}", manifest["commit"]):
        raise ValueError("template.json must pin a full template commit")
    files = manifest["files"]
    if not files:
        raise ValueError("template.json contains no scaffold files")
    local_directory = ROOT / relative_path(manifest["local_service_directory"])
    local_module = module_path(local_directory)
    source_module = manifest["module"]
    if source is not None:
        actual_commit = git(source, "rev-parse", "HEAD").decode().strip()
        if actual_commit != manifest["commit"]:
            raise ValueError(
                f"source commit is {actual_commit}; expected {manifest['commit']}"
            )
        source_directory = source / relative_path(manifest["service_directory"])
        if module_path(source_directory) != source_module:
            raise ValueError("source module path differs from template.json")
    failures = []
    for relative, expected in sorted(files.items()):
        path = relative_path(relative)
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError(f"invalid SHA-256 for {relative}")
        content = (local_directory / path).read_bytes().replace(
            local_module.encode(), source_module.encode()
        )
        if digest(content) != expected:
            failures.append(f"local scaffold differs: {relative}")
        if source is not None and digest(source_contents(source, manifest, relative)) != expected:
            failures.append(f"pinned source differs: {relative}")
    if failures:
        raise ValueError("\n".join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source", type=Path, help="also check an existing ExampleContainers checkout"
    )
    parser.add_argument(
        "--record", action="store_true",
        help="record the exact committed --source after verifying the local scaffold",
    )
    arguments = parser.parse_args()
    if arguments.record and arguments.source is None:
        parser.error("--record requires --source")
    try:
        manifest = json.loads(MANIFEST.read_text())
        if arguments.record:
            manifest["commit"] = git(arguments.source, "rev-parse", "HEAD").decode().strip()
            source_directory = arguments.source / relative_path(manifest["service_directory"])
            manifest["module"] = module_path(source_directory)
            manifest["files"] = {
                relative: digest(source_contents(arguments.source, manifest, relative))
                for relative in manifest["files"]
            }
        check(manifest, arguments.source)
        if arguments.record:
            MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"Template scaffold verified: {len(manifest['files'])} files at {manifest['commit']}")
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Template check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
