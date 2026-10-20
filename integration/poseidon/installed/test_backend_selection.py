"""Check backend selection in the real runners' shared payload configuration."""

from pathlib import Path
from types import SimpleNamespace
import unittest

from test_poseidon import advertised_build_parameters, beaconcrypt_alias, beaconcrypt_selection
from test_p2p import (callback_crypto, callback_for, crypto_selection, matrix_cases,
                     profile_beaconcrypt_backend)


class BackendSelectionTests(unittest.TestCase):
    def test_advertised_alias_selects_each_backend_without_a_build_parameter(self):
        original = {"architecture": "ARM_x64", "mode": "default", "static": False}
        for backend, alias in (("native", "Native"), ("wasm", "WASM")):
            with self.subTest(backend=backend):
                selected = advertised_build_parameters(original)
                self.assertEqual(dict((item["name"], item["value"]) for item in selected),
                                 original)
                self.assertNotIn("beaconcrypt_backend", original)
                self.assertEqual(beaconcrypt_alias(backend), alias)
                self.assertEqual(beaconcrypt_selection(backend), "provider:beaconcrypt:" + alias)
                self.assertEqual(crypto_selection("beaconcrypt", backend), beaconcrypt_selection(backend))
                self.assertEqual(callback_crypto("beaconcrypt", backend), alias)

    def test_non_beaconcrypt_matrix_payloads_keep_their_original_build_parameters(self):
        original = {"architecture": "AMD_x64", "mode": "default"}
        for backend in ("native", "wasm"):
            for crypto in ("none", "aes256_hmac"):
                with self.subTest(backend=backend, crypto=crypto):
                    selected = advertised_build_parameters(original)
                    self.assertEqual(selected,
                                     [{"name": name, "value": value} for name, value in original.items()])
                    self.assertEqual(crypto_selection(crypto, backend), crypto)
                    self.assertEqual(callback_crypto(crypto, backend), crypto)

    def test_callback_requires_the_exact_selected_alias(self):
        for backend, alias in (("native", "Native"), ("wasm", "WASM")):
            row = {"crypto_type": alias, "architecture": "amd64",
                   "loadedcommands": [{"command": {"cmd": "pwd"}}]}
            client = SimpleNamespace(graphql=lambda query, variables: {"callback": [row]})
            agent = {"process": SimpleNamespace(poll=lambda: None, pid=123),
                     "payload": {"id": 9}, "directory": Path("/test/child"),
                     "crypto": "beaconcrypt", "beaconcrypt_backend": backend,
                     "architecture": "amd64", "role": "p2p-1", "commands": ["pwd"]}
            with self.subTest(backend=backend):
                self.assertIs(callback_for(client, agent), row)
                for wrong in ("beaconcrypt", "WASM" if alias == "Native" else "Native"):
                    row["crypto_type"] = wrong
                    with self.assertRaisesRegex(RuntimeError, "selected cryptography"):
                        callback_for(client, agent)

    def test_hidden_backend_build_parameter_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "without a build parameter"):
            advertised_build_parameters({"beaconcrypt_backend": "wasm"})

    def test_unknown_backend_fails_before_build_submission(self):
        with self.assertRaisesRegex(ValueError, "backend must be native or wasm"):
            beaconcrypt_alias("automatic")

    def test_profile_overrides_select_both_cross_backend_directions(self):
        for default in ("native", "wasm"):
            args = SimpleNamespace(beaconcrypt_backend=default,
                                   egress_beaconcrypt_backend=None, p2p_beaconcrypt_backend=None)
            self.assertEqual(profile_beaconcrypt_backend(args, "http"), default)
            self.assertEqual(profile_beaconcrypt_backend(args, "tcp"), default)
            for egress, children in (("native", "wasm"), ("wasm", "native")):
                with self.subTest(default=default, egress=egress, children=children):
                    args.egress_beaconcrypt_backend = egress
                    args.p2p_beaconcrypt_backend = children
                    self.assertEqual(crypto_selection("beaconcrypt", profile_beaconcrypt_backend(args, "http")),
                                     "provider:beaconcrypt:" + beaconcrypt_alias(egress))
                    self.assertEqual(crypto_selection("beaconcrypt", profile_beaconcrypt_backend(args, "tcp")),
                                     "provider:beaconcrypt:" + beaconcrypt_alias(children))

    def test_cross_backend_filter_selects_one_beaconcrypt_cell_with_three_children(self):
        self.assertEqual(matrix_cases(3, cross_backend_only=True),
                         [("beaconcrypt", ["beaconcrypt", "beaconcrypt", "beaconcrypt"])])
        self.assertEqual(len(matrix_cases(3)), 9)
        self.assertEqual(len(matrix_cases(3, mixed_children=True)), 12)
        for count in (1, 2):
            with self.subTest(count=count), self.assertRaisesRegex(ValueError, "requires --p2p-agents=3"):
                matrix_cases(count, cross_backend_only=True)
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            matrix_cases(3, mixed_children=True, cross_backend_only=True)


if __name__ == "__main__":
    unittest.main()
