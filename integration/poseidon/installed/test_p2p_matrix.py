"""Offline checks for the installed P2P suite's encryption selections and cells."""

import itertools
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from test_p2p import (ARCHITECTURES, CRYPTO_SELECTIONS, callback_for, crypto_selection,
                     execution_prefix, host_architecture, matrix_cases, verify_elf_architecture)


class EncryptionMatrixTests(unittest.TestCase):
    def test_crypto_modes_have_explicit_selections_without_fallback(self):
        self.assertEqual(CRYPTO_SELECTIONS, {
            "none": "none",
            "aes256_hmac": "aes256_hmac",
            "beaconcrypt": "provider:beaconcrypt:Native",
        })
        for mode, selection in CRYPTO_SELECTIONS.items():
            with self.subTest(mode=mode):
                self.assertEqual(crypto_selection(mode), selection)
        for mode in ("", "unknown", "AESPSK", "provider:other:unknown"):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, "Unsupported crypto mode"):
                crypto_selection(mode)

    def test_uniform_matrix_covers_all_nine_pairs_for_each_agent_count(self):
        pairs = set(itertools.product(CRYPTO_SELECTIONS, repeat=2))
        for count in range(1, 4):
            with self.subTest(p2p_agents=count):
                cases = matrix_cases(count)
                self.assertEqual(len(cases), 9)
                self.assertEqual({(egress, children[0]) for egress, children in cases}, pairs)
                for _, children in cases:
                    self.assertEqual(len(children), count)
                    self.assertEqual(len(set(children)), 1)

    def test_mixed_cells_add_one_of_every_child_mode_for_each_egress(self):
        uniform = matrix_cases(3)
        cases = matrix_cases(3, mixed_children=True)
        self.assertEqual(len(cases), 12)
        self.assertEqual([case for case in cases if len(set(case[1])) == 1], uniform)
        mixed = [case for case in cases if len(set(case[1])) > 1]
        self.assertEqual({egress for egress, _ in mixed}, set(CRYPTO_SELECTIONS))
        self.assertEqual(len(mixed), 3)
        for _, children in mixed:
            self.assertEqual(children, ["none", "aes256_hmac", "beaconcrypt"])

    def test_mixed_cells_require_exactly_three_children(self):
        for count in (1, 2):
            with self.subTest(p2p_agents=count), self.assertRaisesRegex(ValueError, "requires --p2p-agents=3"):
                matrix_cases(count, mixed_children=True)
        for count in (0, 4):
            with self.subTest(p2p_agents=count), self.assertRaisesRegex(ValueError, "between 1 and 3"):
                matrix_cases(count)


class ArchitectureTests(unittest.TestCase):
    def test_host_names_and_build_parameters_are_explicit(self):
        for machine, architecture in (("x86_64", "amd64"), ("AMD64", "amd64"),
                                      ("aarch64", "arm64"), ("arm64", "arm64")):
            with self.subTest(machine=machine):
                self.assertEqual(host_architecture(machine), architecture)
        self.assertEqual(ARCHITECTURES["amd64"]["build_parameter"], "AMD_x64")
        self.assertEqual(ARCHITECTURES["arm64"]["build_parameter"], "ARM_x64")
        with self.assertRaisesRegex(ValueError, "Unsupported host architecture"):
            host_architecture("riscv64")

    def test_native_execution_needs_no_emulator(self):
        for architecture in ARCHITECTURES:
            with self.subTest(architecture=architecture):
                self.assertEqual(execution_prefix(architecture, architecture), [])

    def test_arm64_execution_uses_explicit_emulator_and_sysroot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            emulator = root / "qemu-aarch64"
            emulator.write_text("not executed by this test")
            emulator.chmod(0o700)
            sysroot = root / "arm64-sysroot"
            sysroot.mkdir()
            self.assertEqual(execution_prefix("arm64", "amd64", emulator, sysroot),
                             [str(emulator), "-L", str(sysroot)])
            for qemu, libraries in ((None, sysroot), (emulator, None), (None, None)):
                with self.subTest(qemu=qemu, libraries=libraries), self.assertRaisesRegex(ValueError, "requires --qemu-aarch64"):
                    execution_prefix("arm64", "amd64", qemu, libraries)
            emulator.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "executable file"):
                execution_prefix("arm64", "amd64", emulator, sysroot)
            emulator.chmod(0o700)
            with self.assertRaisesRegex(ValueError, "directory"):
                execution_prefix("arm64", "amd64", emulator, root / "missing")
        with self.assertRaisesRegex(ValueError, "Executing amd64 payloads on arm64"):
            execution_prefix("amd64", "arm64")

    def test_downloaded_elf_must_match_target_architecture(self):
        for architecture, metadata in ARCHITECTURES.items():
            header = bytearray(64)
            header[:6] = b"\x7fELF\x02\x01"
            header[18:20] = metadata["elf_machine"].to_bytes(2, "little")
            with self.subTest(architecture=architecture):
                verify_elf_architecture(header, architecture)
                other = "arm64" if architecture == "amd64" else "amd64"
                with self.assertRaisesRegex(RuntimeError, "does not match requested"):
                    verify_elf_architecture(header, other)
            for invalid in (header[:20], b"not an ELF", header[:4] + b"\x01\x01" + header[6:],
                            header[:5] + b"\x02" + header[6:]):
                with self.subTest(invalid=invalid[:6]), self.assertRaisesRegex(RuntimeError, "64-bit little-endian ELF"):
                    verify_elf_architecture(invalid, architecture)

    def test_callback_architecture_matches_process_target(self):
        for architecture in ARCHITECTURES:
            row = {"crypto_type": "none", "architecture": architecture,
                   "loadedcommands": [{"command": {"cmd": "pwd"}}]}
            client = SimpleNamespace(graphql=lambda query, variables: {"callback": [row]})
            agent = {"process": SimpleNamespace(poll=lambda: None, pid=123),
                     "payload": {"id": 9}, "directory": Path("/test/child"),
                     "crypto": "none", "architecture": architecture, "role": "p2p-1", "commands": ["pwd"]}
            with self.subTest(architecture=architecture):
                self.assertIs(callback_for(client, agent), row)
                row["architecture"] = "arm64" if architecture == "amd64" else "amd64"
                with self.assertRaisesRegex(RuntimeError, "Callback architecture"):
                    callback_for(client, agent)


if __name__ == "__main__":
    unittest.main()
