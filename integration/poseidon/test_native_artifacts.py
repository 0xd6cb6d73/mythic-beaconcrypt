"""Exercise the real release-archive helpers offline with checked fixture pins.

Run from this provider checkout with POSEIDON_SOURCE pointing at the Poseidon
checkout under test. Only temporary copies of scripts/manifests/caches are used;
Go and curl are stubbed, while checksum validation and cache publication are real.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


TRIPLES = {
    "amd64": "x86_64-unknown-linux-gnu",
    "arm64": "aarch64-unknown-linux-gnu",
}
DARWIN_TRIPLES = {
    "amd64": "x86_64-apple-darwin",
    "arm64": "aarch64-apple-darwin",
}


class NativeArtifactChecks:
    kind = None

    def setUp(self):
        repository = Path(__file__).resolve().parents[2]
        if self.kind == "provider":
            source = repository / "Payload_Type/mythic_beaconcrypt"
        else:
            checkout = Path(os.environ.get("POSEIDON_SOURCE", repository.parent / "poseidon"))
            source = checkout / "Payload_Type/poseidon"
            if not (source / "scripts/build-native.sh").is_file():
                self.skipTest("Set POSEIDON_SOURCE to the Poseidon checkout under test")
        self.temporary = tempfile.TemporaryDirectory(prefix="native-release-helper-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.project = self.root / "module"
        self.scripts = self.project / "scripts"
        self.scripts.mkdir(parents=True)
        for name in ("build-native.sh", "beaconcrypt-releases.txt"):
            shutil.copy2(source / "scripts" / name, self.scripts / name)
        (self.project / "poseidon/agent_code").mkdir(parents=True)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.curl_log = self.root / "curl.jsonl"
        self.cache_root = self.project / ".build/beaconcrypt-native-target"
        self.manifest = self.scripts / "beaconcrypt-releases.txt"
        self.fixtures = {}
        lines = []
        versions = []
        for line in self.manifest.read_text().splitlines():
            fields = line.split()
            if not fields or fields[0].startswith("#"):
                lines.append(line)
                continue
            self.assertEqual(len(fields), 4, "release manifest must contain four columns")
            version, triple, asset, _ = fields
            digest = self.add_fixture(version, triple)
            lines.append(" ".join((version, triple, asset, digest)))
            versions.append(version)
        self.assertTrue(versions, "release manifest must contain pinned archives")
        self.version = versions[0]
        self.manifest.write_text("\n".join(lines) + "\n")
        self.write_command("go", '''#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
if args and args[0] == "env":
    values = {"GOHOSTOS": os.environ["NATIVE_TEST_HOSTOS"], "GOHOSTARCH": os.environ["NATIVE_TEST_HOSTARCH"]}
    try:
        print("\\n".join(values[name] for name in args[1:]))
    except KeyError:
        sys.exit("Unexpected go env request")
elif args[:2] == ["list", "-m"]:
    print(os.environ["NATIVE_TEST_VERSION"])
else:
    sys.exit("Unexpected Go operation: " + repr(args))
''')
        self.write_command("curl", '''#!/usr/bin/env python3
import json, os, pathlib, shutil, sys
args = sys.argv[1:]
with open(os.environ["NATIVE_TEST_CURL_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
if os.environ.get("NATIVE_TEST_FORBID_DOWNLOAD"):
    sys.exit("Unexpected download on cache hit")
option = "--output" if "--output" in args else "-o"
output = pathlib.Path(args[args.index(option) + 1])
if os.environ.get("NATIVE_TEST_HTTP_FAILURE"):
    output.write_bytes(b"partial HTTP response")
    sys.exit(22)
shutil.copyfile(os.environ["NATIVE_TEST_RESPONSE"], output)
''')

    def write_command(self, name, text):
        command = self.bin / name
        command.write_text(text)
        command.chmod(0o700)

    def add_fixture(self, version, triple):
        # Valid checksummed fixture bytes; these tests exercise preparation only,
        # never native linkage. Production manifests and archives remain untouched.
        fixture = self.root / (version + "-" + triple + ".a")
        fixture.write_bytes(b"!<arch>\n" + (version + ":" + triple + ":release fixture\n").encode())
        self.fixtures[(version, triple)] = fixture
        return hashlib.sha256(fixture.read_bytes()).hexdigest()

    def paths(self, architecture="amd64", platform="linux"):
        if self.kind == "provider":
            target = self.project / ".build/native-target"
        else:
            triples = DARWIN_TRIPLES if platform == "darwin" else TRIPLES
            target = self.cache_root / triples[architecture]
        return target / "release/libbeaconcrypt.a", target / "module-version"

    def seed_cache(self, archive_bytes, version, architecture="amd64"):
        archive, marker = self.paths(architecture)
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.write_bytes(archive_bytes)
        marker.write_text(version + "\n")
        return archive, marker

    def invoke(self, architecture="amd64", version=None, response=None, platform="linux", **overrides):
        version = self.version if version is None else version
        triples = DARWIN_TRIPLES if platform == "darwin" else TRIPLES
        triple = triples.get(architecture, TRIPLES["amd64"])
        fixture = self.fixtures.get((version, triple), self.fixtures[(self.version, TRIPLES["amd64"])])
        environment = dict(os.environ)
        environment.pop("POSEIDON_BEACONCRYPT_NATIVE_TARGET", None)
        environment.update({
            "PATH": str(self.bin) + os.pathsep + environment["PATH"],
            "NATIVE_TEST_HOSTOS": "linux",
            "NATIVE_TEST_HOSTARCH": architecture if self.kind == "provider" else "amd64",
            "NATIVE_TEST_VERSION": version,
            "NATIVE_TEST_CURL_LOG": str(self.curl_log),
            "NATIVE_TEST_RESPONSE": str(response or fixture),
        })
        environment.update({key: str(value) for key, value in overrides.items()})
        arguments = ["bash", str(self.scripts / "build-native.sh")]
        if self.kind == "poseidon":
            arguments.extend((platform, architecture))
            environment["POSEIDON_BEACONCRYPT_NATIVE_TARGET"] = str(self.cache_root)
        return subprocess.run(arguments, env=environment, cwd=self.root,
                              text=True, capture_output=True, timeout=15)

    def downloads(self):
        if not self.curl_log.exists():
            return []
        return [json.loads(line) for line in self.curl_log.read_text().splitlines()]

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_wrong_download_digest_leaves_no_archive_or_stamp(self):
        wrong = self.root / "wrong.a"
        wrong.write_bytes(b"not the pinned archive")
        result = self.invoke(response=wrong)
        self.assertNotEqual(result.returncode, 0)
        archive, marker = self.paths()
        self.assertFalse(archive.exists())
        self.assertFalse(marker.exists())
        self.assertEqual(len(self.downloads()), 1)

    def test_failed_download_preserves_previous_archive_and_stamp(self):
        archive, marker = self.seed_cache(b"previous release archive", "v0.0.0-previous")
        before = archive.read_bytes(), marker.read_bytes()
        result = self.invoke(NATIVE_TEST_HTTP_FAILURE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((archive.read_bytes(), marker.read_bytes()), before)
        self.assertEqual(len(self.downloads()), 1)

    def test_verified_cache_hit_does_not_download(self):
        self.assert_success(self.invoke())
        self.assert_success(self.invoke(NATIVE_TEST_FORBID_DOWNLOAD="1"))
        archive, marker = self.paths()
        self.assertEqual(archive.read_bytes(), self.fixtures[(self.version, TRIPLES["amd64"])].read_bytes())
        self.assertEqual(marker.read_text(), self.version + "\n")
        self.assertEqual(len(self.downloads()), 1)

    def test_source_built_same_version_cache_requires_release_digest(self):
        archive, marker = self.seed_cache(b"old source-built archive", self.version)
        self.assert_success(self.invoke())
        self.assertEqual(archive.read_bytes(), self.fixtures[(self.version, TRIPLES["amd64"])].read_bytes())
        self.assertEqual(marker.read_text(), self.version + "\n")
        self.assertEqual(len(self.downloads()), 1)

    def test_unpinned_version_and_target_fail_before_download(self):
        for options in ({"version": "v999.0.0-unpinned"}, {"architecture": "riscv64"}):
            with self.subTest(options=options):
                result = self.invoke(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.downloads(), [])

    def test_target_archives_are_not_reused_for_another_architecture(self):
        self.assert_success(self.invoke("amd64"))
        amd64_archive, _ = self.paths("amd64")
        amd64_bytes = amd64_archive.read_bytes()
        self.assert_success(self.invoke("arm64"))
        arm64_archive, marker = self.paths("arm64")
        self.assertEqual(arm64_archive.read_bytes(), self.fixtures[(self.version, TRIPLES["arm64"])].read_bytes())
        self.assertEqual(marker.read_text(), self.version + "\n")
        if self.kind == "poseidon":
            self.assertNotEqual(amd64_archive, arm64_archive)
            self.assertEqual(amd64_archive.read_bytes(), amd64_bytes)
        self.assertEqual(len(self.downloads()), 2)

    def test_version_update_publishes_matching_archive_and_stamp(self):
        self.assert_success(self.invoke())
        next_version = "v999.0.1-test-release"
        triple = TRIPLES["amd64"]
        digest = self.add_fixture(next_version, triple)
        with self.manifest.open("a") as manifest:
            manifest.write(f"{next_version} {triple} libbeaconcrypt-test.a {digest}\n")
        self.assert_success(self.invoke(version=next_version))
        archive, marker = self.paths()
        self.assertEqual(archive.read_bytes(), self.fixtures[(next_version, triple)].read_bytes())
        self.assertEqual(marker.read_text(), next_version + "\n")
        self.assert_success(self.invoke(version=next_version, NATIVE_TEST_FORBID_DOWNLOAD="1"))
        self.assertEqual(len(self.downloads()), 2)


class ProviderNativeArtifactTests(NativeArtifactChecks, unittest.TestCase):
    kind = "provider"


class PoseidonNativeArtifactTests(NativeArtifactChecks, unittest.TestCase):
    kind = "poseidon"

    def test_all_four_targets_keep_independent_verified_caches(self):
        archives = {}
        for platform, triples in (("linux", TRIPLES), ("darwin", DARWIN_TRIPLES)):
            for architecture, triple in triples.items():
                with self.subTest(platform=platform, architecture=architecture):
                    self.assert_success(self.invoke(architecture, platform=platform))
                    archive, marker = self.paths(architecture, platform)
                    self.assertEqual(archive.read_bytes(), self.fixtures[(self.version, triple)].read_bytes())
                    self.assertEqual(marker.read_text(), self.version + "\n")
                    archives[archive] = archive.read_bytes()
                    self.assert_success(self.invoke(architecture, platform=platform, NATIVE_TEST_FORBID_DOWNLOAD="1"))
        self.assertEqual(len(archives), 4)
        self.assertEqual(len(self.downloads()), 4)
        for archive, original in archives.items():
            self.assertEqual(archive.read_bytes(), original)

    def test_unsupported_platform_fails_before_download(self):
        result = self.invoke(platform="windows")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.downloads(), [])


if __name__ == "__main__":
    unittest.main()
