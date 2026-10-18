"""Offline regression tests for the real-agent matrix's dispatch assertions."""

import base64
import copy
import unittest

from test_p2p import assert_pwd_responses


class DispatchOracleTests(unittest.TestCase):
    def setUp(self):
        self.expected = [
            {"id": index + 101, "callback_id": index + 201,
             "role": role, "directory": "/matrix/" + role}
            for index, role in enumerate(("egress", "p2p-1", "p2p-2", "p2p-3"))
        ]
        self.rows = [
            {"id": item["id"], "callback_id": item["callback_id"],
             "command_name": "pwd", "completed": True,
             "responses": [{"id": item["id"] + 1000,
                            "response_text": base64.b64encode(item["directory"].encode()).decode()}]}
            for item in self.expected
        ]

    def test_accepts_exact_results_in_any_order(self):
        rows = list(reversed(self.rows))
        self.assertIs(assert_pwd_responses(rows, self.expected), rows)

    def test_rejects_egress_child_and_sibling_swaps(self):
        for first, second in ((0, 1), (1, 2)):
            with self.subTest(first=first, second=second):
                rows = copy.deepcopy(self.rows)
                rows[first]["responses"], rows[second]["responses"] = (
                    rows[second]["responses"], rows[first]["responses"])
                with self.assertRaisesRegex(RuntimeError, "Cross-agent pwd dispatch"):
                    assert_pwd_responses(rows, self.expected)

    def test_rejects_response_attached_to_wrong_callback_or_command(self):
        for field, value in (("callback_id", self.expected[1]["callback_id"]),
                             ("command_name", "whoami")):
            with self.subTest(field=field):
                rows = copy.deepcopy(self.rows)
                rows[0][field] = value
                with self.assertRaisesRegex(RuntimeError, "wrong callback or command"):
                    assert_pwd_responses(rows, self.expected)

    def test_rejects_duplicate_responses(self):
        self.rows[1]["responses"] *= 2
        with self.assertRaisesRegex(RuntimeError, "Duplicate pwd responses"):
            assert_pwd_responses(self.rows, self.expected)

    def test_waits_for_missing_task_response_or_completion(self):
        for missing in ("task", "response", "completion"):
            with self.subTest(missing=missing):
                rows = copy.deepcopy(self.rows)
                if missing == "task":
                    rows.pop()
                elif missing == "response":
                    rows[-1]["responses"] = []
                else:
                    rows[-1]["completed"] = False
                self.assertIsNone(assert_pwd_responses(rows, self.expected))

    def test_rejects_duplicate_task_rows_hiding_a_missing_task(self):
        self.rows[-1] = copy.deepcopy(self.rows[0])
        with self.assertRaisesRegex(RuntimeError, "[Dd]uplicate.*task"):
            assert_pwd_responses(self.rows, self.expected)

    def test_rejects_unexpected_task(self):
        self.rows[0]["id"] = 999
        with self.assertRaisesRegex(RuntimeError, "Unexpected task"):
            assert_pwd_responses(self.rows, self.expected)

    def test_rejects_an_oracle_with_duplicate_directories_or_task_ids(self):
        for field in ("directory", "id"):
            with self.subTest(field=field):
                expected = copy.deepcopy(self.expected)
                expected[1][field] = expected[0][field]
                with self.assertRaisesRegex(RuntimeError, "distinct task IDs and working directories"):
                    assert_pwd_responses(self.rows, expected)


if __name__ == "__main__":
    unittest.main()
