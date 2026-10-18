#!/usr/bin/env python3
"""Exercise real Poseidon agents against an already installed Mythic stack."""

import argparse
import base64
import concurrent.futures
import contextlib
import datetime
import hashlib
import json
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

    def task(self, callback, command):
        reply = self.request("/create_task_webhook", {"input": {
            "callback_display_id": callback["display_id"], "command": command, "params": ""}})
        if reply.get("status") != "success" or not reply.get("id"):
            raise RuntimeError(f"Task {command} creation failed: {reply}")
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


def run_case(client, binary, payload_id, work, agent_count, message_count):
    """Start fresh agents, submit concurrent rounds, and stop only these agents."""
    work.mkdir()
    processes, logs, callbacks, tasks = [], [], [], []
    report = {"status": "fail", "agents": agent_count, "messages_per_agent": message_count,
              "callbacks": callbacks, "pwd_tasks": tasks}

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
            processes.append(subprocess.Popen([str(binary)], cwd=directory, stdout=log,
                                              stderr=subprocess.STDOUT, start_new_session=True))

        def checked_in():
            require_live_agents()
            rows = client.graphql("""query Callbacks($payload:Int!,$pids:[Int!]!,$directories:[String!]!) {
              callback(where:{registered_payload_id:{_eq:$payload},pid:{_in:$pids},cwd:{_in:$directories}}) {
                id display_id pid cwd agent_callback_id crypto_type
                loadedcommands(where:{command:{cmd:{_in:["pwd","exit"]}}}) {command {cmd}}
              }
            }""", {"payload": payload_id, "pids": [process.pid for process in processes],
                   "directories": [str(work / f"agent-{index + 1}") for index in range(agent_count)]})["callback"]
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
                if callback["crypto_type"] != "beaconcrypt":
                    raise RuntimeError("Callback is not managed by Beaconcrypt")
                # Callback creation commits before its loaded commands are copied.
                if {loaded["command"]["cmd"] for loaded in callback["loadedcommands"]} != {"pwd", "exit"}:
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
            print(f"{work.name}: round {round_index + 1}, {agent_count} correct responses", flush=True)

        # Submit all exit controls before waiting for any owned process to stop.
        for callback in callbacks:
            client.task(callback, "exit")
        for process in processes:
            if process.wait(timeout=40) != 0:
                raise RuntimeError("Agent did not exit successfully through its real exit task")
        if not assert_responses(tasks):
            raise RuntimeError("Task outputs were unavailable after all agents exited")
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
    parser.add_argument("--work-dir", help="Fresh directory for reports, downloaded ELF, and agent logs")
    parser.add_argument("--insecure", action="store_true", help="Accept the local instance's self-signed HTTPS certificate")
    args = parser.parse_args()
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        parser.error("This Beaconcrypt/Poseidon integration currently requires Linux amd64")
    if not 1 <= args.callback_port <= 65535:
        parser.error("callback-port must be between 1 and 65535")
    work = Path(args.work_dir or tempfile.mkdtemp(prefix="poseidon-installed-e2e-")).resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(work.iterdir()):
        parser.error("work-dir must be empty")
    print("Evidence directory: " + str(work), flush=True)
    report = {"status": "fail", "mythic": args.url,
              "callback": f"http://127.0.0.1:{args.callback_port}", "cases": []}
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
            "commands": ["pwd", "exit"],
            "build_parameters": [{"name": name, "value": value} for name, value in {
                "architecture": "AMD_x64", "mode": "default", "garble": False, "debug": False,
                "static": False, "proxy_bypass": True, "egress_order": ["http"],
                "egress_failover": "failover", "failover_threshold": 10}.items()],
            "c2_profiles": [{"c2_profile": "http", "c2_profile_parameters": {
                "callback_host": "http://127.0.0.1", "callback_port": args.callback_port,
                "callback_interval": 1, "callback_jitter": 0,
                "killdate": (datetime.date.today() + datetime.timedelta(days=2)).isoformat(),
                "get_uri": "index", "post_uri": "data", "query_path_name": "q",
                "headers": {"User-Agent": "Poseidon installed integration test"},
                "proxy_host": "", "proxy_port": "", "proxy_user": "", "proxy_pass": "",
                "encrypted_exchange_check": False, "AESPSK": "provider:beaconcrypt:beaconcrypt"}}],
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
        for agents, messages in cells:
            case = run_case(client, binary, payload["id"], work / f"agents-{agents}_messages-{messages}", agents, messages)
            report["cases"].append(case)
            all_callbacks = [callback for result in report["cases"] for callback in result["callbacks"]]
            if len({callback["agent_callback_id"] for callback in all_callbacks}) != len(all_callbacks):
                raise RuntimeError("Agent callbacks were reused across test cases")
            write_report(work / "report.json", report)
        report.update(status="pass", agents=sum(case["agents"] for case in report["cases"]),
                      task_response_exchanges=sum(case["task_response_exchanges"] for case in report["cases"]))
        print(f"PASS: {len(cells)} cases, {report['agents']} real Poseidon agents, {report['task_response_exchanges']} pwd exchanges through installed HTTP C2", flush=True)
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
