"""Size probes using real Poseidon commands and persisted Mythic responses."""

import base64
import concurrent.futures
import hashlib
import os
from pathlib import Path
import time

from payload_sizes import assert_payload_responses, payload_value


VALUE_NAME = "BEACONCRYPT_E2E_PAYLOAD"


def payload_environment(directory):
    # getenv must never upload the test runner's inherited credentials. The
    # directory marker also identifies the process independently of routing.
    return {"PATH": os.defpath, "HOME": str(directory),
            "BEACONCRYPT_E2E_AGENT": str(directory)}


def read_payload_tasks(client, ids):
    return client.graphql("""query PayloadTasks($ids:[Int!]!) {
      task(where:{id:{_in:$ids}},order_by:{id:asc}) {
        id callback_id command_name status completed
        responses(order_by:{id:asc}) {id response_text}
      }
    }""", {"ids": ids})["task"]


def expected_output(agent, size, command):
    value = payload_value(size, agent["seed"])
    if command == "setenv":
        return ("Set " + VALUE_NAME + "=" + value).encode("ascii")
    if command == "getenv":
        environment = payload_environment(agent["directory"])
        environment[VALUE_NAME] = value
        return "\n".join(name + "=" + environment[name]
                         for name in sorted(environment)).encode("utf-8")
    raise ValueError("Payload probe requires setenv or getenv")


def expected_tasks(round_data, command):
    agents = {agent["callback_id"]: agent for agent in round_data["agents"]}
    return [dict(task, command=command,
                 output=expected_output(agents[task["callback_id"]],
                                        round_data["value_bytes"], command))
            for task in round_data[command + "_tasks"]]


def compact_result(rows, expected):
    by_id = {row["id"]: row for row in rows}
    return [dict(id=item["id"], callback_id=item["callback_id"],
                 response_bytes=len(item["output"]),
                 response_sha256=hashlib.sha256(item["output"]).hexdigest(),
                 response_chunks=len(by_id[item["id"]]["responses"]))
            for item in expected]


def wait_for_payload(client, expected, agents, timeout):
    started = time.monotonic()
    while True:
        for agent in agents:
            if agent["process"].poll() is not None:
                raise RuntimeError(agent["role"] + " exited during the payload probe")
        rows = read_payload_tasks(client, [item["id"] for item in expected])
        if assert_payload_responses(rows, expected):
            return rows, round(time.monotonic() - started, 3)
        if time.monotonic() - started >= timeout:
            counts = {row["id"]: sum(len(base64.b64decode(chunk["response_text"]))
                                     for chunk in row["responses"]) for row in rows}
            raise RuntimeError("Timed out waiting for exact " + expected[0]["command"] +
                               " payload results; stored response bytes=" + str(counts))
        time.sleep(0.5)


def verify_payload_results(client, rounds, control_tasks):
    """Recheck all chunks after the processes exit, including late duplicates."""
    for round_data in rounds:
        for command in ("setenv", "getenv"):
            expected = expected_tasks(round_data, command)
            if not expected or not assert_payload_responses(
                    read_payload_tasks(client, [item["id"] for item in expected]), expected):
                raise RuntimeError("Persisted payload results unavailable after agent exit")
    from test_p2p import assert_pwd_responses

    if not assert_pwd_responses(read_payload_tasks(client, [item["id"] for item in control_tasks]),
                                control_tasks):
        raise RuntimeError("Persisted post-payload pwd controls unavailable after agent exit")


def run_payload_workload(client, agents, size, messages, report, work, timeout=90):
    # Import after test_poseidon has defined its helpers; both standalone
    # scripts share the workload without a module initialization cycle.
    from test_poseidon import await_result, write_report

    rounds = report.setdefault("payload_rounds", [])
    report["payload_task_response_exchanges"] = 0
    for index in range(messages):
        round_data = {"round": index + 1, "value_bytes": size, "status": "fail",
                      "agents": [{"role": agent["role"],
                                  "callback_id": agent["callback"]["id"],
                                  "directory": str(agent["directory"]),
                                  "seed": str(agent["directory"]) + f"/{size}/{index + 1}"}
                                 for agent in agents],
                      "setenv_tasks": [], "getenv_tasks": []}
        rounds.append(round_data)
        write_report(Path(work) / "report.json", report)
        for command in ("setenv", "getenv"):
            started = time.monotonic()

            def submit(pair):
                agent, spec = pair
                params = VALUE_NAME + " " + payload_value(size, spec["seed"]) if command == "setenv" else ""
                return client.task(agent["callback"], command, params)

            # Retain IDs for tasks admitted before a sibling submission fails.
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(agents)) as pool:
                futures = [(agent, pool.submit(submit, (agent, spec)))
                           for agent, spec in zip(agents, round_data["agents"])]
                errors = []
                for agent, future in futures:
                    try:
                        task_id = future.result()
                        round_data[command + "_tasks"].append(
                            {"id": task_id, "callback_id": agent["callback"]["id"]})
                    except Exception as error:
                        errors.append(str(error))
            write_report(Path(work) / "report.json", report)
            if errors:
                raise RuntimeError("Payload task submission failed: " + "; ".join(errors))
            expected = expected_tasks(round_data, command)
            rows, wait_seconds = wait_for_payload(client, expected, agents, timeout)
            round_data[command + "_results"] = compact_result(rows, expected)
            round_data[command + "_wait_seconds"] = wait_seconds
            round_data[command + "_elapsed_seconds"] = round(time.monotonic() - started, 3)
            report["payload_task_response_exchanges"] += len(expected)
            write_report(Path(work) / "report.json", report)
        round_data["status"] = "pass"
        print(f"{Path(work).name}: payload round {index + 1}, {len(agents)} agents, "
              f"{size} value bytes each, exact setenv/getenv responses", flush=True)

    # A small task on every role must still reach that process after the large
    # exchange. Expected cwd comes from Popen, independently of callback data.
    from test_p2p import assert_pwd_responses

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(agents)) as pool:
        ids = list(pool.map(lambda agent: client.task(agent["callback"], "pwd"), agents))
    expected = [{"id": task_id, "callback_id": agent["callback"]["id"],
                 "role": agent["role"], "directory": str(agent["directory"])}
                for task_id, agent in zip(ids, agents)]
    report["payload_control_pwd_tasks"] = expected
    await_result("post-payload pwd dispatch on every role", lambda: assert_pwd_responses(
        read_payload_tasks(client, ids), expected), timeout)
    write_report(Path(work) / "report.json", report)
