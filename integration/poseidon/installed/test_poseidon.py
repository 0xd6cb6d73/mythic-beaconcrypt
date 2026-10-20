#!/usr/bin/env python3
"""Exercise real Poseidon agents against an already installed Mythic stack."""

import argparse
import base64
import concurrent.futures
import contextlib
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shlex
import signal
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

from payload_sizes import parse_payload_size
from payload_workload import (payload_environment, run_payload_workload,
                              verify_payload_results)


def read_env(path):
    settings = {}
    for raw in Path(path).read_text().splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            settings[key.strip()] = " ".join(shlex.split(value, comments=True))
    return settings


class Mythic:
    def __init__(self, base, insecure):
        self.base = base.rstrip("/")
        self.token = ""
        self.context = ssl._create_unverified_context() if insecure else None

    def request(self, path, body=None, binary=False):
        headers = {}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        encoded = None
        if body is not None:
            encoded = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, encoded, headers)
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=40) as reply:
                content = reply.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")[:2000]
            raise RuntimeError(f"{path}: HTTP {error.code}: {detail}") from None
        return content if binary else json.loads(content)

    def graphql(self, query, variables=None):
        reply = self.request("/graphql/", {"query": query, "variables": variables or {}})
        if reply.get("errors"):
            raise RuntimeError("GraphQL: " + json.dumps(reply["errors"]))
        return reply["data"]

    def task(self, callback, command, params=""):
        try:
            reply = self.request("/create_task_webhook", {"input": {
                "callback_display_id": callback["display_id"], "command": command, "params": params}})
        except RuntimeError:
            if params:
                raise RuntimeError(f"Task {command} request failed with {len(params.encode())} parameter bytes") from None
            raise
        if reply.get("status") != "success" or not reply.get("id"):
            # The server can echo task parameters in an error reply. Never dump
            # potentially megabytes of payload data into the evidence log.
            raise RuntimeError(f"Task {command} creation failed (status={reply.get('status')!r})")
        return reply["id"]


def await_result(description, check, timeout=90):
    deadline = time.monotonic() + timeout
    while True:
        value = check()
        if value:
            return value
        if time.monotonic() >= deadline:
            raise RuntimeError("Timed out waiting for " + description)
        time.sleep(0.5)


def write_report(path, report):
    path.write_text(json.dumps(report, indent=2) + "\n")


def beaconcrypt_alias(backend):
    try:
        return {"native": "Native", "wasm": "WASM"}[backend]
    except KeyError:
        raise ValueError("Beaconcrypt backend must be native or wasm") from None


def beaconcrypt_selection(backend):
    return "provider:beaconcrypt:" + beaconcrypt_alias(backend)


def advertised_build_parameters(parameters):
    if "beaconcrypt_backend" in parameters:
        raise ValueError("Advertised crypto choices must select the backend without a build parameter")
    return [{"name": name, "value": value} for name, value in parameters.items()]


def run_case(client, binary, payload_id, work, agent_count, message_count, backend,
             payload_size=0, payload_timeout=90):
    """Start fresh agents, submit concurrent rounds, and stop only these agents."""
    work.mkdir()
    processes, logs, callbacks, tasks = [], [], [], []
    report = {"status": "fail", "agents": agent_count, "messages_per_agent": message_count,
              "beaconcrypt_backend": backend, "beaconcrypt_alias": beaconcrypt_alias(backend),
              "callbacks": callbacks, "pwd_tasks": tasks}
    expected_commands = {"pwd", "exit"}
    if payload_size:
        expected_commands.update(("setenv", "getenv"))
        report["payload_value_bytes"] = payload_size

    def require_live_agents():
        for index, process in enumerate(processes):
            if process.poll() is not None:
                raise RuntimeError(f"Agent {index + 1} exited early; see {work / f'agent-{index + 1}' / 'agent.log'}")

    def read_tasks(ids):
        return client.graphql("""query Tasks($ids:[Int!]!) {
          task(where:{id:{_in:$ids}},order_by:{id:asc}) {
            id callback_id command_name status completed
            responses(order_by:{id:asc}) {id response_text}
          }
        }""", {"ids": ids})["task"]

    def assert_responses(expected_tasks):
        rows = read_tasks([task["id"] for task in expected_tasks])
        if len(rows) != len(expected_tasks) or not all(row["completed"] for row in rows):
            return None
        expected = {task["id"]: task for task in expected_tasks}
        for row in rows:
            task = expected[row["id"]]
            if row["callback_id"] != task["callback_id"] or row["command_name"] != "pwd":
                raise RuntimeError("Task delivered to an incorrect callback")
            if not row["responses"]:
                return None
            # Mythic's response_text computed field returns base64, including
            # PostgreSQL's wrapping for long values; retain the exact raw bytes.
            output = base64.b64decode(row["responses"][0]["response_text"])
            if len(row["responses"]) != 1 or output != os.fsencode(task["directory"]):
                raise RuntimeError("Missing, duplicate, or cross-agent task output: " + json.dumps(row))
        return rows

    try:
        for index in range(agent_count):
            directory = work / f"agent-{index + 1}"
            directory.mkdir()
            log = (directory / "agent.log").open("wb")
            logs.append(log)
            process_options = {"env": payload_environment(directory)} if payload_size else {}
            processes.append(subprocess.Popen([str(binary)], cwd=directory, stdout=log,
                                              stderr=subprocess.STDOUT, start_new_session=True,
                                              **process_options))

        def checked_in():
            require_live_agents()
            rows = client.graphql("""query Callbacks($payload:Int!,$pids:[Int!]!,$directories:[String!]!,$commands:[String!]!) {
              callback(where:{registered_payload_id:{_eq:$payload},pid:{_in:$pids},cwd:{_in:$directories}}) {
                id display_id pid cwd agent_callback_id crypto_type
                loadedcommands(where:{command:{cmd:{_in:$commands}}}) {command {cmd}}
              }
            }""", {"payload": payload_id, "pids": [process.pid for process in processes],
                   "directories": [str(work / f"agent-{index + 1}") for index in range(agent_count)],
                   "commands": sorted(expected_commands)})["callback"]
            if len(rows) < agent_count:
                return None
            by_pid = {row["pid"]: row for row in rows}
            if len(rows) != agent_count or len(by_pid) != agent_count or len({row["agent_callback_id"] for row in rows}) != agent_count:
                raise RuntimeError("Agents do not have distinct callbacks")
            ordered = []
            for index, process in enumerate(processes):
                callback = by_pid.get(process.pid)
                if not callback or callback["cwd"] != str(work / f"agent-{index + 1}"):
                    raise RuntimeError("Callback PID or directory does not match its real agent process")
                if callback["crypto_type"] != beaconcrypt_alias(backend):
                    raise RuntimeError("Callback does not use the selected Beaconcrypt alias")
                # Callback creation commits before its loaded commands are copied.
                if {loaded["command"]["cmd"] for loaded in callback["loadedcommands"]} != expected_commands:
                    return None
                ordered.append(callback)
            return ordered

        callbacks.extend(await_result("actual agents registering through installed HTTP C2", checked_in, 120))
        print(f"{work.name}: {agent_count} live agents registered with distinct Beaconcrypt callbacks", flush=True)
        for round_index in range(message_count):
            require_live_agents()
            with concurrent.futures.ThreadPoolExecutor(max_workers=agent_count) as pool:
                ids = list(pool.map(lambda callback: client.task(callback, "pwd"), callbacks))
            round_tasks = [{"id": task_id, "callback_id": callbacks[index]["id"],
                            "directory": str(work / f"agent-{index + 1}")}
                           for index, task_id in enumerate(ids)]
            tasks.extend(round_tasks)
            await_result(f"round {round_index + 1} real pwd responses", lambda: assert_responses(round_tasks), 120)
            report["task_response_exchanges"] = len(tasks)
            print(f"{work.name}: round {round_index + 1}, {agent_count} correct responses", flush=True)

        if payload_size:
            agents = [{"callback": callback, "process": processes[index],
                       "directory": work / f"agent-{index + 1}", "role": f"agent-{index + 1}"}
                      for index, callback in enumerate(callbacks)]
            run_payload_workload(client, agents, payload_size, message_count, report, work,
                                 timeout=payload_timeout)

        # Submit all exit controls before waiting for any owned process to stop.
        for callback in callbacks:
            client.task(callback, "exit")
        for process in processes:
            if process.wait(timeout=40) != 0:
                raise RuntimeError("Agent did not exit successfully through its real exit task")
        if not assert_responses(tasks):
            raise RuntimeError("Task outputs were unavailable after all agents exited")
        if payload_size:
            verify_payload_results(client, report["payload_rounds"], report["payload_control_pwd_tasks"])
        report.update(status="pass", task_response_exchanges=len(tasks))
        return report
    except BaseException as error:
        report["error"] = str(error) or type(error).__name__
        raise
    finally:
        for process in processes:
            if process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
        for process in processes:
            if process.poll() is None:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        for log in logs:
            log.close()
        write_report(work / "report.json", report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", default=str(Path.home() / "Mythic" / ".env"))
    parser.add_argument("--api-token-file", help="Read an existing Mythic API token instead of logging in")
    parser.add_argument("--url", default="https://127.0.0.1:7443")
    parser.add_argument("--callback-port", type=int, default=8088)
    parser.add_argument("--agents", type=int, choices=range(1, 4), default=3)
    parser.add_argument("--messages", type=int, choices=range(1, 4), default=3)
    parser.add_argument("--matrix", action="store_true", help="Run all nine combinations of 1–3 agents and 1–3 messages, overriding --agents/--messages")
    parser.add_argument("--payload-sizes", nargs="+", type=parse_payload_size,
                        help="Add exact-sized task and response values for each size, e.g. 1KiB 64KiB 1MiB 10MiB")
    parser.add_argument("--payload-timeout", type=float, default=90,
                        help="Seconds to wait for each large-payload round (default: 90)")
    parser.add_argument("--keep-going", action="store_true",
                        help="Retain failed case reports and attempt the remaining matrix cases")
    parser.add_argument("--beaconcrypt-backend", choices=("native", "wasm"), default="native")
    parser.add_argument("--work-dir", help="Fresh directory for reports, downloaded ELF, and agent logs")
    parser.add_argument("--insecure", action="store_true", help="Accept the local instance's self-signed HTTPS certificate")
    args = parser.parse_args()
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        parser.error("This Beaconcrypt/Poseidon integration currently requires Linux amd64")
    if not 1 <= args.callback_port <= 65535:
        parser.error("callback-port must be between 1 and 65535")
    if not math.isfinite(args.payload_timeout) or args.payload_timeout <= 0:
        parser.error("payload-timeout must be a finite positive number")
    if args.payload_sizes and len(set(args.payload_sizes)) != len(args.payload_sizes):
        parser.error("payload-sizes must not contain duplicate byte sizes")
    work = Path(args.work_dir or tempfile.mkdtemp(prefix="poseidon-installed-e2e-")).resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(work.iterdir()):
        parser.error("work-dir must be empty")
    print("Evidence directory: " + str(work), flush=True)
    report = {"status": "fail", "mythic": args.url,
              "callback": f"http://127.0.0.1:{args.callback_port}",
              "beaconcrypt_backend": args.beaconcrypt_backend,
              "beaconcrypt_alias": beaconcrypt_alias(args.beaconcrypt_backend), "cases": []}
    if args.payload_sizes:
        report["payload_value_bytes"] = args.payload_sizes
    try:
        client = Mythic(args.url, args.insecure)
        if args.api_token_file:
            client.token = Path(args.api_token_file).read_text().strip()
            if not client.token:
                raise RuntimeError("API token file is empty")
        else:
            settings = read_env(args.env_file)
            login = client.request("/auth", {
                "username": settings["MYTHIC_ADMIN_USER"], "password": settings["MYTHIC_ADMIN_PASSWORD"]})
            client.token = login.get("access_token", "")
            if not client.token:
                raise RuntimeError("Operator authentication failed")
        print("Authenticated to installed Mythic", flush=True)

        def ready():
            data = client.graphql("""query InstalledServices {
              c2profile(where:{name:{_eq:"http"},deleted:{_eq:false}}) {id container_running running}
              payloadtype(where:{name:{_eq:"poseidon"},deleted:{_eq:false}}) {id container_running}
              consuming_container(where:{name:{_eq:"beaconcrypt"},type:{_eq:"crypto"},deleted:{_eq:false}}) {id container_running}
            }""")
            return data if all(len(data[name]) == 1 and data[name][0]["container_running"]
                               for name in ("c2profile", "payloadtype", "consuming_container")) else None

        services = await_result("installed HTTP, Poseidon, and Beaconcrypt service registration", ready, 120)
        if not services["c2profile"][0]["running"]:
            started = client.request("/start_stop_profile_webhook", {"input": {
                "id": services["c2profile"][0]["id"], "action": "start"}})
            if started.get("status") != "success":
                raise RuntimeError("HTTP C2 start failed: " + json.dumps(started))
        print("Installed HTTP C2, Poseidon container, and Beaconcrypt provider are registered", flush=True)

        configuration = {
            "payload_type": "poseidon", "selected_os": "Linux", "filename": "poseidon-beaconcrypt-installed",
            "description": "Installed HTTP C2 / Poseidon / Beaconcrypt end-to-end test",
            "commands": ["pwd", "exit", "setenv", "getenv"] if args.payload_sizes else ["pwd", "exit"],
            "build_parameters": advertised_build_parameters({
                "architecture": "AMD_x64", "mode": "default", "garble": False, "debug": False,
                "static": False, "proxy_bypass": True, "egress_order": ["http"],
                "egress_failover": "failover", "failover_threshold": 10}),
            "c2_profiles": [{"c2_profile": "http", "c2_profile_parameters": {
                "callback_host": "http://127.0.0.1", "callback_port": args.callback_port,
                "callback_interval": 1, "callback_jitter": 0,
                "killdate": (datetime.date.today() + datetime.timedelta(days=2)).isoformat(),
                "get_uri": "index", "post_uri": "data", "query_path_name": "q",
                "headers": {"User-Agent": "Poseidon installed integration test"},
                "proxy_host": "", "proxy_port": "", "proxy_user": "", "proxy_pass": "",
                "encrypted_exchange_check": False, "AESPSK": beaconcrypt_selection(args.beaconcrypt_backend)}}],
        }
        write_report(work / "payload-config.json", configuration)
        build = client.request("/createpayload_webhook", {"input": {
            "payloadDefinition": json.dumps(configuration)}})
        if build.get("status") != "success" or not build.get("uuid"):
            raise RuntimeError("Payload build submission failed: " + json.dumps(build))
        report["payload_uuid"] = build["uuid"]
        print("Submitted real payload build " + build["uuid"], flush=True)

        def built():
            rows = client.graphql("""query Build($uuid:String!) {
              payload(where:{uuid:{_eq:$uuid}}) {id uuid build_phase build_message build_stderr}
            }""", {"uuid": build["uuid"]})["payload"]
            if not rows:
                return None
            if rows[0]["build_phase"] == "error":
                raise RuntimeError("Real payload build failed: " + json.dumps(rows[0]))
            return rows[0] if rows[0]["build_phase"] == "success" else None

        payload = await_result("installed Poseidon container payload build", built, 600)
        artifact = client.request("/direct/download/" + build["uuid"], binary=True)
        if not artifact.startswith(b"\x7fELF"):
            raise RuntimeError("Downloaded payload is not a Linux ELF")
        binary = work / "poseidon"
        binary.write_bytes(artifact)
        binary.chmod(0o700)
        report.update(payload_id=payload["id"], artifact_sha256=hashlib.sha256(artifact).hexdigest())
        print(f"Downloaded uploaded Poseidon ELF ({len(artifact)} bytes)", flush=True)

        cells = [(agents, messages) for agents in range(1, 4) for messages in range(1, 4)] if args.matrix else [(args.agents, args.messages)]
        cases = [(agents, messages, size) for size in (args.payload_sizes or [0])
                 for agents, messages in cells]
        for agents, messages, size in cases:
            case_name = f"agents-{agents}_messages-{messages}"
            if size:
                case_name += f"_payload-{size}"
            case_work = work / case_name
            try:
                case = run_case(client, binary, payload["id"], case_work, agents, messages,
                                args.beaconcrypt_backend, size, args.payload_timeout)
            except (RuntimeError, OSError, KeyError, ValueError, subprocess.TimeoutExpired):
                # run_case persists its failed report after stopping its owned
                # processes; include it before deciding whether to continue.
                case = json.loads((case_work / "report.json").read_text())
                report["cases"].append(case)
                write_report(work / "report.json", report)
                if not args.keep_going:
                    raise
                print(f"FAIL: {case_name}: {case['error']}", flush=True)
                continue
            report["cases"].append(case)
            all_callbacks = [callback for result in report["cases"] for callback in result["callbacks"]]
            if len({callback["agent_callback_id"] for callback in all_callbacks}) != len(all_callbacks):
                case.update(status="fail", error="Agent callbacks were reused across test cases")
                write_report(case_work / "report.json", case)
                write_report(work / "report.json", report)
                if not args.keep_going:
                    raise RuntimeError(case["error"])
                print(f"FAIL: {case_name}: {case['error']}", flush=True)
            write_report(work / "report.json", report)
        failed_cases = sum(case["status"] != "pass" for case in report["cases"])
        report.update(status="fail" if failed_cases else "pass",
                      agents=sum(case["agents"] for case in report["cases"]),
                      task_response_exchanges=sum(case.get("task_response_exchanges", 0) for case in report["cases"]))
        if args.payload_sizes:
            report["payload_task_response_exchanges"] = sum(
                case.get("payload_task_response_exchanges", 0) for case in report["cases"])
        if failed_cases:
            report["failed_cases"] = failed_cases
            raise RuntimeError(f"{failed_cases} of {len(cases)} HTTP matrix cases failed; see {work / 'report.json'}")
        print(f"PASS: {len(cases)} cases, {report['agents']} real Poseidon agents, {report['task_response_exchanges']} pwd exchanges through installed HTTP C2", flush=True)
    except BaseException as error:
        report["error"] = str(error) or type(error).__name__
        raise
    finally:
        write_report(work / "report.json", report)


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, KeyError, ValueError, subprocess.TimeoutExpired) as error:
        print("FAIL: " + str(error), file=sys.stderr)
        sys.exit(1)
