"""Offline coverage for the installed large-payload evidence oracle."""

import base64
import copy
import unittest

from payload_sizes import (DEFAULT_PAYLOAD_SIZES, MAX_PAYLOAD_SIZE,
                           assert_payload_responses, parse_payload_size,
                           payload_value)


class PayloadSizesTests(unittest.TestCase):
    def test_requested_binary_sizes(self):
        self.assertEqual(tuple(map(parse_payload_size, ("1KiB", "64KiB", "1MiB", "10MiB"))), DEFAULT_PAYLOAD_SIZES)
        self.assertEqual(parse_payload_size(" 64 kib "), 65536)
        self.assertEqual(parse_payload_size("1024"), 1024)
        self.assertEqual(parse_payload_size("64MiB"), MAX_PAYLOAD_SIZE)

    def test_invalid_sizes_have_no_silent_rounding_or_decimal_unit(self):
        for value in ("", "0", "-1", "1.5MiB", "1MB", "64Kibits", "65MiB", str(MAX_PAYLOAD_SIZE + 1), None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_payload_size(value)

    def test_exact_deterministic_ascii_values_at_requested_sizes_and_boundaries(self):
        for size in (*DEFAULT_PAYLOAD_SIZES, 1, 3, 511999, 512000, 512001):
            with self.subTest(size=size):
                value = payload_value(size, "/tmp/egress:101:round1")
                self.assertEqual(len(value.encode("ascii")), size)
                self.assertTrue(set(value) <= set("0123456789abcdef"))
                self.assertEqual(value, payload_value(size, "/tmp/egress:101:round1"))
        self.assertNotEqual(payload_value(1024, "/tmp/egress:101:round1"), payload_value(1024, "/tmp/egress:101:round2"))
        self.assertNotEqual(payload_value(1024, "/tmp/egress:101:round1"), payload_value(1024, "/tmp/p2p:102:round1"))

    def test_invalid_payload_identity_and_size(self):
        for size, seed in ((0, "seed"), (True, "seed"), (MAX_PAYLOAD_SIZE + 1, "seed"), (1, ""), (1, None)):
            with self.subTest(size=size, seed=seed), self.assertRaises(ValueError):
                payload_value(size, seed)

    def expectation(self, size=1024, task_id=1, callback_id=101, directory="/tmp/egress", command="setenv"):
        value = payload_value(size, f"{directory}:{callback_id}:round1")
        if command == "setenv":
            output = "Set BEACONCRYPT_E2E_PAYLOAD=" + value
        else:
            env = {"PATH": "/bin:/usr/bin", "HOME": directory,
                   "BEACONCRYPT_E2E_AGENT": directory, "BEACONCRYPT_E2E_PAYLOAD": value}
            output = "\n".join(f"{name}={env[name]}" for name in sorted(env))
        return {"id": task_id, "callback_id": callback_id, "command": command, "output": output.encode()}

    def row(self, expectation, output=None, completed=True, chunk_size=512000):
        output = expectation["output"] if output is None else output
        return {"id": expectation["id"], "callback_id": expectation["callback_id"],
                "command_name": expectation["command"], "status": "completed" if completed else "processing", "completed": completed,
                "responses": [{"id": index + 1, "response_text": base64.encodebytes(output[start:start + chunk_size]).decode()}
                              for index, start in enumerate(range(0, len(output), chunk_size))]}

    def test_raw_params_match_existing_setenv_parser(self):
        value = payload_value(1024, "agent-101:round1")
        params = "BEACONCRYPT_E2E_PAYLOAD " + value
        # Poseidon SplitAfterN(task.Params, " ", 2), then TrimSpace.
        name, parsed = params.split(" ", 1)
        self.assertEqual(parsed.strip(), value)
        self.assertEqual("Set " + name + "=" + parsed.strip(), "Set BEACONCRYPT_E2E_PAYLOAD=" + value)

    def test_all_sizes_and_commands_pass_with_real_output_chunk_boundaries(self):
        for size in DEFAULT_PAYLOAD_SIZES:
            for command in ("setenv", "getenv"):
                with self.subTest(size=size, command=command):
                    expected = self.expectation(size, command=command)
                    rows = [self.row(expected)]
                    self.assertIs(assert_payload_responses(rows, [expected]), rows)

    def test_early_completed_first_chunk_waits_for_full_output(self):
        expected = self.expectation(1024 * 1024)
        row = self.row(expected)
        row["responses"] = row["responses"][:1]
        self.assertTrue(row["completed"])
        self.assertIsNone(assert_payload_responses([row], [expected]))

    def test_full_bytes_wait_for_task_completion(self):
        expected = self.expectation()
        self.assertIsNone(assert_payload_responses([self.row(expected, completed=False)], [expected]))

    def test_missing_rows_or_response_bytes_wait(self):
        expected = self.expectation()
        self.assertIsNone(assert_payload_responses([], [expected]))
        self.assertIsNone(assert_payload_responses([self.row(expected, output=b"")], [expected]))

    def test_partial_corruption_fails_before_completion(self):
        expected = self.expectation(1024 * 1024)
        row = self.row(expected, output=b"Set BEACONCRYPT_E2E_PAYLOAD=CORRUPT", completed=False)
        with self.assertRaisesRegex(RuntimeError, "Corrupt"):
            assert_payload_responses([row], [expected])

    def test_wrong_agent_seed_is_rejected(self):
        expected = self.expectation()
        other = self.expectation(callback_id=102, directory="/tmp/p2p-1")
        with self.assertRaisesRegex(RuntimeError, "Corrupt"):
            assert_payload_responses([self.row(expected, other["output"])], [expected])

    def test_getenv_marker_detects_swapped_process_with_same_payload(self):
        expected = self.expectation(command="getenv")
        wrong_process = expected["output"].replace(b"/tmp/egress", b"/tmp/p2p-1")
        with self.assertRaisesRegex(RuntimeError, "Corrupt"):
            assert_payload_responses([self.row(expected, wrong_process)], [expected])

    def test_wrong_callback_command_and_error_status(self):
        expected = self.expectation()
        for field, value in (("callback_id", 102), ("command_name", "pwd"), ("status", "error: bad task")):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                row = self.row(expected)
                row[field] = value
                assert_payload_responses([row], [expected])

    def test_invalid_expected_command_or_output_type(self):
        original = self.expectation()
        for field, value in (("command", "pwd"), ("output", "text")):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                assert_payload_responses([self.row(original)], [dict(original, **{field: value})])

    def test_late_extra_or_duplicate_output_is_rejected(self):
        expected = self.expectation()
        row = self.row(expected)
        self.assertIsNotNone(assert_payload_responses([row], [expected]))
        row["responses"].append({"id": 2, "response_text": base64.b64encode(b"extra").decode()})
        with self.assertRaisesRegex(RuntimeError, "Extra or duplicate"):
            assert_payload_responses([row], [expected])

    def test_duplicate_unordered_or_invalid_response_row_ids(self):
        expected = self.expectation(1024 * 1024)
        for invalid in (1, 0, "2", True):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                row = self.row(expected)
                row["responses"][1]["id"] = invalid
                assert_payload_responses([row], [expected])
        row = self.row(expected)
        row["responses"].reverse()
        with self.assertRaisesRegex(RuntimeError, "unordered"):
            assert_payload_responses([row], [expected])

    def test_invalid_base64_and_non_ascii_fail_without_output_disclosure(self):
        expected = self.expectation()
        for encoded in ("bad!", "é", None):
            with self.subTest(encoded=encoded), self.assertRaises(RuntimeError) as error:
                row = self.row(expected)
                row["responses"][0]["response_text"] = encoded
                assert_payload_responses([row], [expected])
            self.assertLess(len(str(error.exception)), 200)

    def test_concurrent_tasks_require_independent_valid_rows(self):
        expected = [self.expectation(task_id=1), self.expectation(task_id=2, callback_id=102, directory="/tmp/p2p-1", command="getenv")]
        rows = [self.row(item) for item in expected]
        self.assertIs(assert_payload_responses(rows, expected), rows)
        self.assertIsNone(assert_payload_responses(rows[:1], expected))

    def test_duplicate_or_unexpected_task_ids_fail(self):
        expected = self.expectation()
        row = self.row(expected)
        for rows, expectations in (([row, copy.deepcopy(row)], [expected]), ([row], [expected, expected]), ([dict(row, id=999)], [expected])):
            with self.subTest(rows=len(rows)), self.assertRaises(RuntimeError):
                assert_payload_responses(rows, expectations)


if __name__ == "__main__":
    unittest.main()
