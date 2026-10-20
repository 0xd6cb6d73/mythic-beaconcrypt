"""Offline regressions for size-probe isolation, final checks, and orchestration.

Only API/process boundaries are mocked; expected bytes and persisted-data
validation use the same helpers as the real installed-agent runners.
"""

import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from payload_sizes import payload_value
from payload_workload import (VALUE_NAME, expected_output, payload_environment,
                              verify_payload_results)
import test_poseidon


class PayloadIsolationTests(unittest.TestCase):
    def test_probe_environment_does_not_inherit_runner_credentials_or_preloads(self):
        directory = Path("/tmp/campagne-é/子-agent")
        with mock.patch.dict(os.environ, {
                "MYTHIC_ADMIN_PASSWORD": "private-password-must-stay-local",
                "AWS_SECRET_ACCESS_KEY": "private-cloud-secret",
                "LD_PRELOAD": "/tmp/untrusted.so", "PATH": "/tmp/private-bin"}):
            actual = payload_environment(directory)
        self.assertEqual(actual, {"PATH": os.defpath, "HOME": str(directory),
                                  "BEACONCRYPT_E2E_AGENT": str(directory)})

    def test_getenv_oracle_preserves_unicode_directory_bytes_and_exact_ascii_value(self):
        directory = "/tmp/campagne-é/子-agent"
        agent = {"directory": directory, "seed": directory + "/1024/1"}
        value = payload_value(1024, agent["seed"])
        wanted = ("BEACONCRYPT_E2E_AGENT=" + directory + "\n" +
                  VALUE_NAME + "=" + value + "\nHOME=" + directory +
                  "\nPATH=" + os.defpath).encode("utf-8")
        actual = expected_output(agent, 1024, "getenv")
        self.assertEqual(actual, wanted)
        self.assertEqual(actual.count(directory.encode("utf-8")), 2)
        self.assertEqual(expected_output(agent, 1024, "setenv"),
                         ("Set " + VALUE_NAME + "=" + value).encode("ascii"))


class PersistedWorkloadTests(unittest.TestCase):
    def fixture(self):
        directory, seed, size = "/tmp/campagne-é/agent", "private-agent-round-identity", 1024
        value = payload_value(size, seed)
        round_data = {"value_bytes": size,
                      "agents": [{"callback_id": 101, "directory": directory, "seed": seed}],
                      "setenv_tasks": [{"id": 1, "callback_id": 101}],
                      "getenv_tasks": [{"id": 2, "callback_id": 101}]}
        control = {"id": 3, "callback_id": 101, "directory": directory, "role": "agent"}
        outputs = {
            1: ("setenv", ("Set " + VALUE_NAME + "=" + value).encode("ascii")),
            2: ("getenv", ("BEACONCRYPT_E2E_AGENT=" + directory + "\n" + VALUE_NAME +
                          "=" + value + "\nHOME=" + directory + "\nPATH=" + os.defpath).encode("utf-8")),
            3: ("pwd", directory.encode("utf-8")),
        }
        rows = {task_id: {"id": task_id, "callback_id": 101,
                          "command_name": command, "completed": True, "status": "completed",
                          "responses": [{"id": task_id * 100,
                                         "response_text": base64.b64encode(output).decode("ascii")}]
                          } for task_id, (command, output) in outputs.items()}
        client = mock.Mock()
        client.graphql.side_effect = lambda query, variables: {
            "task": [copy.deepcopy(rows[task_id]) for task_id in variables["ids"] if task_id in rows]}
        return client, round_data, control, rows

    def test_final_check_requeries_payload_and_post_payload_dispatch_control(self):
        client, round_data, control, rows = self.fixture()
        verify_payload_results(client, [round_data], [control])
        self.assertEqual([call.args[1]["ids"] for call in client.graphql.call_args_list],
                         [[1], [2], [3]])

    def test_late_duplicate_pwd_response_fails_even_when_large_payload_is_intact(self):
        client, round_data, control, rows = self.fixture()
        verify_payload_results(client, [round_data], [control])
        duplicate = dict(rows[3]["responses"][0], id=301)
        rows[3]["responses"].append(duplicate)
        with self.assertRaisesRegex(RuntimeError, "Duplicate pwd responses"):
            verify_payload_results(client, [round_data], [control])

    def test_final_check_rejects_missing_control_and_wrong_process_directory(self):
        for mode in ("missing", "wrong-directory"):
            with self.subTest(mode=mode):
                client, round_data, control, rows = self.fixture()
                if mode == "missing":
                    del rows[3]
                else:
                    rows[3]["responses"][0]["response_text"] = base64.b64encode(b"/tmp/another-agent").decode()
                with self.assertRaises(RuntimeError):
                    verify_payload_results(client, [round_data], [control])


class HttpSizeOrchestrationTests(unittest.TestCase):
    def exercise(self, flags, fail_first=False):
        # This checks CLI planning and failure retention without modeling any
        # server protocol. The actual case executor is replaced at its boundary.
        with tempfile.TemporaryDirectory(prefix="http-size-plan-test-") as directory:
            work = Path(directory)
            client = mock.Mock()
            client.request.side_effect = [
                {"access_token": "unused-offline-token"},
                {"status": "success", "uuid": "offline-build"}, b"\x7fELFoffline",
            ]
            services = {name: [{"id": 1, "container_running": True, "running": True}]
                        for name in ("c2profile", "payloadtype", "consuming_container")}
            calls = []

            def run_case(client, binary, payload_id, case_work, agents, messages, backend,
                         size=0, timeout=90):
                calls.append((case_work.name, size, timeout))
                case_work.mkdir()
                result = {"status": "pass", "agents": agents,
                          "callbacks": [{"agent_callback_id": f"cell-{len(calls)}-agent-{index}"}
                                        for index in range(agents)],
                          "task_response_exchanges": agents * messages}
                if size:
                    result["payload_task_response_exchanges"] = 2 * agents * messages
                if fail_first and len(calls) == 1:
                    result.update(status="fail", error="controlled size failure")
                test_poseidon.write_report(case_work / "report.json", result)
                if result["status"] == "fail":
                    raise RuntimeError(result["error"])
                return result

            error = None
            with mock.patch.object(test_poseidon, "Mythic", return_value=client), \
                 mock.patch.object(test_poseidon, "read_env", return_value={
                     "MYTHIC_ADMIN_USER": "offline", "MYTHIC_ADMIN_PASSWORD": "offline"}), \
                 mock.patch.object(test_poseidon, "await_result", side_effect=[
                     services, {"id": 2, "uuid": "offline-build", "build_phase": "success"}]), \
                 mock.patch.object(test_poseidon, "run_case", side_effect=run_case), \
                 mock.patch.object(sys, "argv", ["test_poseidon.py", "--work-dir", directory] + flags), \
                 contextlib.redirect_stdout(io.StringIO()):
                try:
                    test_poseidon.main()
                except RuntimeError as caught:
                    error = str(caught)
            report = json.loads((work / "report.json").read_text())
            configuration = json.loads(client.request.call_args_list[1].args[1]["input"]["payloadDefinition"])
            return report, calls, configuration, error

    def test_size_axis_keep_going_retains_failure_and_still_fails_overall(self):
        report, calls, configuration, error = self.exercise(
            ["--matrix", "--payload-sizes", "1KiB", "64KiB", "--keep-going"], fail_first=True)
        self.assertIsNotNone(error)
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["failed_cases"], 1)
        self.assertEqual(len(report["cases"]), 18)
        self.assertEqual(report["cases"][0]["error"], "controlled size failure")
        self.assertEqual(sum(case["status"] == "pass" for case in report["cases"]), 17)
        self.assertEqual(report["payload_value_bytes"], [1024, 65536])
        self.assertEqual({size for name, size, timeout in calls}, {1024, 65536})
        self.assertEqual(len({name for name, size, timeout in calls}), 18)
        self.assertTrue(all(name.endswith("_payload-" + str(size)) for name, size, timeout in calls))
        self.assertEqual(set(configuration["commands"]), {"pwd", "exit", "setenv", "getenv"})
        self.assertEqual(report["payload_task_response_exchanges"],
                         sum(case["payload_task_response_exchanges"] for case in report["cases"]))

    def test_size_axis_stops_after_first_failure_without_keep_going(self):
        report, calls, configuration, error = self.exercise(
            ["--matrix", "--payload-sizes", "1KiB", "64KiB"], fail_first=True)
        self.assertEqual(error, "controlled size failure")
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(report["cases"]), 1)
        self.assertEqual(report["cases"][0]["status"], "fail")

    def test_default_probe_does_not_add_environment_commands_or_a_size_axis(self):
        report, calls, configuration, error = self.exercise([])
        self.assertIsNone(error)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0], ("agents-3_messages-3", 0, 90))
        self.assertNotIn("payload_value_bytes", report)
        self.assertNotIn("payload_task_response_exchanges", report)
        self.assertEqual(configuration["commands"], ["pwd", "exit"])

    def test_task_creation_failure_does_not_log_large_parameter_echo(self):
        client = test_poseidon.Mythic("https://unused.invalid", False)
        marker = "private-value-must-not-appear" * 100
        failures = ({"status": "error", "params": marker}, RuntimeError(marker))
        for failure in failures:
            patch = (mock.patch.object(client, "request", side_effect=failure)
                     if isinstance(failure, Exception)
                     else mock.patch.object(client, "request", return_value=failure))
            with self.subTest(failure=type(failure).__name__), patch:
                with self.assertRaises(RuntimeError) as error:
                    client.task({"display_id": 1}, "setenv", marker)
                self.assertNotIn(marker[:30], str(error.exception))
                self.assertLess(len(str(error.exception)), 250)


if __name__ == "__main__":
    unittest.main()
