#!/usr/bin/env python3
"""Test none/AESPSK/Beaconcrypt HTTP-egress and TCP-P2P combinations in real Mythic."""

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
import signal
import socket
import subprocess
import sys
import tempfile

from test_poseidon import (Mythic, advertised_build_parameters, await_result,
                           beaconcrypt_alias, beaconcrypt_selection, read_env, write_report)
from payload_sizes import parse_payload_size
from payload_workload import (payload_environment, run_payload_workload,
                              verify_payload_results)


CRYPTO_SELECTIONS = {
    "none": "none",
    "aes256_hmac": "aes256_hmac",
    "beaconcrypt": "provider:beaconcrypt:Native",
}
ARCHITECTURES = {
    "amd64": {"build_parameter": "AMD_x64", "elf_machine": 62},
    "arm64": {"build_parameter": "ARM_x64", "elf_machine": 183},
}


def host_architecture(machine=None):
    machine = (platform.machine() if machine is None else machine).lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    raise ValueError(f"Unsupported host architecture: {machine}")


def execution_prefix(architecture, host, qemu_aarch64=None, arm64_sysroot=None):
    if architecture not in ARCHITECTURES or host not in ARCHITECTURES:
        raise ValueError("Execution requires amd64 or arm64 architectures")
    if architecture == host:
        return []
    if host != "amd64" or architecture != "arm64":
        raise ValueError("Executing amd64 payloads on arm64 is not supported; run this pair from an amd64 host")
    if not qemu_aarch64 or not arm64_sysroot:
        raise ValueError("ARM64 execution on amd64 requires --qemu-aarch64 and --arm64-sysroot")
    emulator = Path(qemu_aarch64).expanduser().resolve()
    sysroot = Path(arm64_sysroot).expanduser().resolve()
    if not emulator.is_file() or not os.access(emulator, os.X_OK):
        raise ValueError("--qemu-aarch64 must name an executable file")
    if not sysroot.is_dir():
        raise ValueError("--arm64-sysroot must name a directory with the target loader and libraries")
    return [str(emulator), "-L", str(sysroot)]


def verify_elf_architecture(artifact, architecture):
    if len(artifact) < 64 or artifact[:4] != b"\x7fELF" or artifact[4:6] != b"\x02\x01":
        raise RuntimeError("Payload artifact is not a 64-bit little-endian ELF")
    machine = int.from_bytes(artifact[18:20], "little")
    if machine != ARCHITECTURES[architecture]["elf_machine"]:
        raise RuntimeError(f"Payload ELF machine {machine} does not match requested {architecture}")


def crypto_selection(mode, backend="native"):
    try:
        selected = CRYPTO_SELECTIONS[mode]
    except KeyError:
        raise ValueError(f"Unsupported crypto mode: {mode}") from None
    return beaconcrypt_selection(backend) if mode == "beaconcrypt" else selected


def callback_crypto(mode, backend="native"):
    crypto_selection(mode, backend)
    return beaconcrypt_alias(backend) if mode == "beaconcrypt" else mode


def profile_beaconcrypt_backend(args, profile):
    if profile not in ("http", "tcp"):
        raise ValueError("Backend selection requires an http or tcp profile")
    override = args.egress_beaconcrypt_backend if profile == "http" else args.p2p_beaconcrypt_backend
    backend = override or args.beaconcrypt_backend
    beaconcrypt_alias(backend)
    return backend


def matrix_cases(p2p_agents, mixed_children=False, cross_backend_only=False):
    if p2p_agents not in range(1, 4):
        raise ValueError("p2p-agents must be between 1 and 3")
    if cross_backend_only:
        if p2p_agents != 3:
            raise ValueError("--cross-backend-only requires --p2p-agents=3")
        if mixed_children:
            raise ValueError("--cross-backend-only cannot be combined with --mixed-children")
        return [("beaconcrypt", ["beaconcrypt"] * 3)]
    if mixed_children and p2p_agents != 3:
        raise ValueError("--mixed-children requires --p2p-agents=3")
    cases = []
    for egress_crypto in CRYPTO_SELECTIONS:
        for child_crypto in CRYPTO_SELECTIONS:
            cases.append((egress_crypto, [child_crypto] * p2p_agents))
        if mixed_children:
            cases.append((egress_crypto, list(CRYPTO_SELECTIONS)))
    return cases


def task(client, callback, command, params=None):
    reply = client.request("/create_task_webhook", {"input": {
        "callback_display_id": callback["display_id"], "command": command,
        "params": json.dumps(params) if params is not None else ""}})
    if reply.get("status") != "success" or not reply.get("id"):
        raise RuntimeError(f"{command} task creation failed: {reply}")
    return reply["id"]


def read_tasks(client, ids):
    return client.graphql("""query Tasks($ids:[Int!]!) {
      task(where:{id:{_in:$ids}},order_by:{id:asc}) {
        id callback_id command_name status completed
        responses(order_by:{id:asc}) {id response_text}
      }
    }""", {"ids": ids})["task"]


def assert_pwd_responses(rows, expected):
    """Expected paths come from Popen's cwd, never the server's callback data."""
    tasks = {item["id"]: item for item in expected}
    if len(tasks) != len(expected) or len({item["directory"] for item in expected}) != len(expected):
        raise RuntimeError("Dispatch oracle requires distinct task IDs and working directories")
    if {row["id"] for row in rows} - tasks.keys():
        raise RuntimeError("Unexpected task in dispatch results")
    if len({row["id"] for row in rows}) != len(rows):
        raise RuntimeError("Duplicate task IDs in dispatch results")
    if len(rows) != len(expected) or not all(row["completed"] for row in rows):
        return None
    for row in rows:
        intended = tasks[row["id"]]
        if row["callback_id"] != intended["callback_id"] or row["command_name"] != "pwd":
            raise RuntimeError("Task response attached to the wrong callback or command")
        if not row["responses"]:
            return None
        if len(row["responses"]) != 1:
            raise RuntimeError("Duplicate pwd responses: " + json.dumps(row))
        output = base64.b64decode(row["responses"][0]["response_text"])
        if output != os.fsencode(intended["directory"]):
            raise RuntimeError("Cross-agent pwd dispatch: " + json.dumps({
                "task_id": row["id"], "role": intended["role"],
                "expected_directory": intended["directory"],
                "actual_directory": os.fsdecode(output)}))
    return rows


def free_ports(count):
    with contextlib.ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(count)]
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in sockets]


def listening(process, port):
    if process.poll() is not None:
        raise RuntimeError("TCP child exited before its listener started")
    # Do not connect as a readiness probe: the relay must own the first connection.
    # A failed bind also matches TIME_WAIT and another process's socket. Require
    # a LISTEN inode held by this exact agent (or its QEMU process) instead.
    proc = Path("/proc") / str(process.pid)
    inodes = set()
    try:
        for descriptor in (proc / "fd").iterdir():
            try:
                target = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                inodes.add(target[8:-1])
        for protocol in ("tcp", "tcp6"):
            for line in (proc / "net" / protocol).read_text().splitlines()[1:]:
                fields = line.split()
                if len(fields) >= 10 and fields[3] == "0A" and fields[9] in inodes:
                    if int(fields[1].rsplit(":", 1)[1], 16) == port:
                        return True
    except FileNotFoundError:
        if process.poll() is not None:
            raise RuntimeError("TCP child exited before its listener started") from None
    return None


def callback_for(client, agent):
    if agent["process"].poll() is not None:
        raise RuntimeError(agent["role"] + " exited before check-in; see " + str(agent["directory"] / "agent.log"))
    rows = client.graphql("""query Callback($payload:Int!,$pid:Int!,$cwd:String!) {
      callback(where:{registered_payload_id:{_eq:$payload},pid:{_eq:$pid},cwd:{_eq:$cwd}}) {
        id display_id agent_callback_id pid cwd crypto_type architecture
        loadedcommands {command {cmd}}
      }
    }""", {"payload": agent["payload"]["id"], "pid": agent["process"].pid,
           "cwd": str(agent["directory"])})["callback"]
    if not rows:
        return None
    if len(rows) != 1 or rows[0]["crypto_type"] != callback_crypto(agent["crypto"], agent.get("beaconcrypt_backend", "native")):
        raise RuntimeError("Callback identity or selected cryptography does not match " + agent["role"])
    if rows[0]["architecture"] != agent["architecture"]:
        raise RuntimeError("Callback architecture does not match " + agent["role"])
    if not set(agent["commands"]).issubset({item["command"]["cmd"] for item in rows[0]["loadedcommands"]}):
        return None
    return rows[0]


def assert_links(client, agents):
    relay_id = agents[0]["callback"]["id"]
    children = [agent["callback"]["id"] for agent in agents[1:]]
    edges = client.graphql("""query Links($ids:[Int!]!) {
      callbackgraphedge(where:{end_timestamp:{_is_null:true},c2profile:{is_p2p:{_eq:true}},
        _or:[{source_id:{_in:$ids}},{destination_id:{_in:$ids}}]}) {
        id source_id destination_id c2profile {name is_p2p}
      }
    }""", {"ids": children})["callbackgraphedge"]
    linked = set()
    for edge in edges:
        endpoints = {edge["source_id"], edge["destination_id"]}
        if edge["c2profile"]["name"] != "tcp" or relay_id not in endpoints or len(endpoints) != 2:
            raise RuntimeError("P2P callback has an unexpected route: " + json.dumps(edge))
        linked.update(endpoints.intersection(children))
    return edges if linked == set(children) else None


def run_case(client, work, egress, children, messages, payload_size=0, payload_timeout=90):
    work.mkdir()
    agents, logs, pwd_tasks = [], [], []
    child_cryptos = [child["crypto"] for child in children]
    mixed = len(set(child_cryptos)) > 1
    report = {"status": "fail", "egress_crypto": egress["crypto"],
              "egress_beaconcrypt_backend": egress.get("beaconcrypt_backend", "native") if egress["crypto"] == "beaconcrypt" else None,
              "p2p_beaconcrypt_backends": [child.get("beaconcrypt_backend", "native") if child["crypto"] == "beaconcrypt" else None for child in children],
              "egress_crypto_alias": callback_crypto(egress["crypto"], egress.get("beaconcrypt_backend", "native")),
              "p2p_crypto_aliases": [callback_crypto(child["crypto"], child.get("beaconcrypt_backend", "native")) for child in children],
              "p2p_crypto": "mixed" if mixed else child_cryptos[0],
              "p2p_cryptos": child_cryptos, "mixed_children": mixed,
              "egress_architecture": egress["architecture"],
              "p2p_architectures": [child["architecture"] for child in children],
              "messages_per_agent": messages, "agents": [], "pwd_rounds": []}
    if payload_size:
        report["payload_value_bytes"] = payload_size

    def start(payload, role):
        directory = work / role
        directory.mkdir()
        log = (directory / "agent.log").open("wb")
        logs.append(log)
        agent = {"role": role, "directory": directory, "payload": payload,
                 "crypto": payload["crypto"], "architecture": payload["architecture"],
                 "beaconcrypt_backend": payload.get("beaconcrypt_backend", "native"),
                 "commands": payload["commands"],
                 "process": subprocess.Popen(payload["command"], cwd=directory,
                     stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                     env=payload_environment(directory) if payload_size else None)}
        agents.append(agent)
        return agent

    try:
        relay = start(egress, "egress")
        relay["callback"] = await_result("HTTP egress check-in", lambda: callback_for(client, relay), 120)
        for index, payload in enumerate(children):
            child = start(payload, f"p2p-{index + 1}")
            await_result(child["role"] + " TCP listener", lambda: listening(child["process"], payload["port"]), 30)
            child["link_task_id"] = task(client, relay["callback"], "link_tcp",
                                         {"address": "127.0.0.1", "port": payload["port"]})
        for agent in agents[1:]:
            agent["callback"] = await_result(agent["role"] + " delegated check-in",
                lambda agent=agent: callback_for(client, agent), 120)
        if len({agent["callback"]["agent_callback_id"] for agent in agents}) != len(agents):
            raise RuntimeError("Agents did not register distinct callbacks")
        report["agents"] = [{"role": agent["role"], "directory": str(agent["directory"]),
            "crypto": agent["crypto"], "architecture": agent["architecture"],
            "beaconcrypt_backend": agent["beaconcrypt_backend"] if agent["crypto"] == "beaconcrypt" else None,
            "crypto_alias": callback_crypto(agent["crypto"], agent["beaconcrypt_backend"]),
            "command": agent["payload"]["command"],
            "pid": agent["process"].pid, "payload_uuid": agent["payload"]["uuid"],
            "callback": agent["callback"]} for agent in agents]
        report["graph_edges"] = await_result("all TCP routes through the egress", lambda: assert_links(client, agents), 60)
        def links_complete():
            rows = read_tasks(client, [agent["link_task_id"] for agent in agents[1:]])
            if len(rows) != len(children) or not all(row["completed"] and row["responses"] for row in rows):
                return None
            for row in rows:
                if row["callback_id"] != relay["callback"]["id"] or row["command_name"] != "link_tcp":
                    raise RuntimeError("Link task was attached to a wrong callback")
                if base64.b64decode(row["responses"][0]["response_text"]) != b"Successfully Connected":
                    raise RuntimeError("Real link_tcp task failed: " + json.dumps(row))
            return rows
        report["link_tasks"] = await_result("real link_tcp results", links_complete, 60)
        print(f"{work.name}: HTTP egress + {len(children)} TCP P2P callbacks, distinct directories and verified routes", flush=True)
        for round_index in range(messages):
            for agent in agents:
                if agent["process"].poll() is not None:
                    raise RuntimeError(agent["role"] + " exited during dispatch")
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(agents)) as pool:
                ids = list(pool.map(lambda agent: task(client, agent["callback"], "pwd"), agents))
            expected = [{"id": task_id, "callback_id": agent["callback"]["id"],
                         "role": agent["role"], "directory": str(agent["directory"])}
                        for task_id, agent in zip(ids, agents)]
            round_data = {"round": round_index + 1, "expected": expected, "actual": []}
            report["pwd_rounds"].append(round_data)
            def observed():
                round_data["actual"] = read_tasks(client, ids)
                return assert_pwd_responses(round_data["actual"], expected)
            await_result("exact per-role pwd results", observed, 120)
            pwd_tasks.extend(expected)
            report["task_response_exchanges"] = len(pwd_tasks)
            report["graph_edges"] = assert_links(client, agents)
            if not report["graph_edges"]:
                raise RuntimeError("A P2P route disappeared during dispatch")
            print(f"{work.name}: round {round_index + 1}, {len(agents)} exact pwd responses including egress", flush=True)
            write_report(work / "report.json", report)
        if payload_size:
            run_payload_workload(client, agents, payload_size, messages, report, work,
                                 timeout=payload_timeout)
            report["graph_edges"] = assert_links(client, agents)
            if not report["graph_edges"]:
                raise RuntimeError("A P2P route disappeared during the payload probe")
        # Children must finish before their relay exits, keeping their real route live.
        for agent in agents[1:]:
            task(client, agent["callback"], "exit")
        for agent in agents[1:]:
            if agent["process"].wait(timeout=40) != 0:
                raise RuntimeError(agent["role"] + " failed its real exit task")
        task(client, relay["callback"], "exit")
        if relay["process"].wait(timeout=40) != 0:
            raise RuntimeError("Egress failed its real exit task")
        for round_data in report["pwd_rounds"]:
            expected = round_data["expected"]
            if not assert_pwd_responses(read_tasks(client, [item["id"] for item in expected]), expected):
                raise RuntimeError("Persisted results unavailable after exit")
        if payload_size:
            verify_payload_results(client, report["payload_rounds"], report["payload_control_pwd_tasks"])
        report.update(status="pass", task_response_exchanges=len(pwd_tasks))
        return report
    except BaseException as error:
        report["error"] = str(error) or type(error).__name__
        raise
    finally:
        for agent in agents:
            process = agent["process"]
            if process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGTERM)
        for agent in agents:
            process = agent["process"]
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
    parser.add_argument("--api-token-file")
    parser.add_argument("--url", default="https://127.0.0.1:7443")
    parser.add_argument("--callback-port", type=int, default=8088)
    parser.add_argument("--egress-architecture", choices=ARCHITECTURES,
                        help="HTTP egress target (default: host architecture)")
    parser.add_argument("--p2p-architecture", choices=ARCHITECTURES,
                        help="TCP child target (default: host architecture)")
    parser.add_argument("--qemu-aarch64", help="Explicit qemu-aarch64 executable for ARM64 agents on amd64")
    parser.add_argument("--arm64-sysroot", help="ARM64 loader/library root passed to qemu-aarch64 -L")
    parser.add_argument("--p2p-agents", type=int, choices=range(1, 4), default=3)
    parser.add_argument("--messages", type=int, choices=range(1, 4), default=3)
    parser.add_argument("--payload-sizes", nargs="+", type=parse_payload_size,
                        help="Multiply each crypto cell by these value sizes, e.g. 1KiB 64KiB 1MiB 10MiB")
    parser.add_argument("--payload-timeout", type=float, default=90,
                        help="Seconds to wait for each exact large-output stage (default: 90)")
    parser.add_argument("--keep-going", action="store_true",
                        help="Continue after failed cells; the overall result still fails")
    parser.add_argument("--beaconcrypt-backend", choices=("native", "wasm"), default="native")
    parser.add_argument("--egress-beaconcrypt-backend", choices=("native", "wasm"),
                        help="Override the Beaconcrypt backend for the HTTP egress")
    parser.add_argument("--p2p-beaconcrypt-backend", choices=("native", "wasm"),
                        help="Override the Beaconcrypt backend for the TCP children")
    parser.add_argument("--cross-backend-only", action="store_true",
                        help="Run only one Beaconcrypt egress with three Beaconcrypt children")
    parser.add_argument("--mixed-children", action="store_true",
                        help="Add one cell per egress mode with none, AESPSK and Beaconcrypt children together (requires --p2p-agents=3)")
    parser.add_argument("--work-dir")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()
    if not math.isfinite(args.payload_timeout) or args.payload_timeout <= 0:
        parser.error("payload-timeout must be a finite positive number")
    if args.payload_sizes and len(set(args.payload_sizes)) != len(args.payload_sizes):
        parser.error("payload-sizes must not contain duplicate sizes")
    if sys.platform != "linux":
        parser.error("Requires Linux for real agent processes")
    try:
        cases = matrix_cases(args.p2p_agents, args.mixed_children, args.cross_backend_only)
        host = host_architecture()
        args.egress_architecture = args.egress_architecture or host
        args.p2p_architecture = args.p2p_architecture or host
        prefixes = {architecture: execution_prefix(architecture, host, args.qemu_aarch64, args.arm64_sysroot)
                    for architecture in {args.egress_architecture, args.p2p_architecture}}
    except ValueError as error:
        parser.error(str(error))
    if not 1 <= args.callback_port <= 65535:
        parser.error("callback-port must be between 1 and 65535")
    work = Path(args.work_dir or tempfile.mkdtemp(prefix="poseidon-p2p-e2e-")).resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(work.iterdir()):
        parser.error("work-dir must be empty")
    print("Evidence directory: " + str(work), flush=True)
    report = {"status": "fail", "mythic": args.url, "crypto_modes": list(CRYPTO_SELECTIONS),
              "beaconcrypt_backend": args.beaconcrypt_backend,
              "beaconcrypt_alias": beaconcrypt_alias(args.beaconcrypt_backend),
              "egress_beaconcrypt_backend": profile_beaconcrypt_backend(args, "http"),
              "p2p_beaconcrypt_backend": profile_beaconcrypt_backend(args, "tcp"),
              "egress_beaconcrypt_alias": beaconcrypt_alias(profile_beaconcrypt_backend(args, "http")),
              "p2p_beaconcrypt_alias": beaconcrypt_alias(profile_beaconcrypt_backend(args, "tcp")),
              "cross_backend_only": args.cross_backend_only,
              "mixed_children": args.mixed_children, "host_architecture": host,
              "egress_architecture": args.egress_architecture,
              "p2p_architecture": args.p2p_architecture, "execution_prefixes": prefixes, "cases": []}
    if args.payload_sizes:
        report["payload_value_bytes"] = args.payload_sizes
    client = Mythic(args.url, args.insecure)
    try:
        if args.api_token_file:
            client.token = Path(args.api_token_file).read_text().strip()
        else:
            settings = read_env(args.env_file)
            client.token = client.request("/auth", {"username": settings["MYTHIC_ADMIN_USER"],
                "password": settings["MYTHIC_ADMIN_PASSWORD"]}).get("access_token", "")
        if not client.token:
            raise RuntimeError("Operator authentication failed or API token file is empty")
        data = client.graphql("""query Services {
          c2profile(where:{name:{_in:["http","tcp"]},deleted:{_eq:false}}) {name is_p2p container_running running}
          payloadtype(where:{name:{_eq:"poseidon"},deleted:{_eq:false}}) {container_running}
          consuming_container(where:{name:{_eq:"beaconcrypt"},type:{_eq:"crypto"},deleted:{_eq:false}}) {container_running}
        }""")
        if len(data["c2profile"]) != 2 or any(not row["container_running"] for rows in data.values() for row in rows) or not data["payloadtype"] or not data["consuming_container"]:
            raise RuntimeError("Install and start HTTP, TCP, Poseidon and Beaconcrypt containers")
        if not any(row["name"] == "http" and row["running"] and not row["is_p2p"] for row in data["c2profile"]) or not any(row["name"] == "tcp" and row["is_p2p"] for row in data["c2profile"]):
            raise RuntimeError("HTTP listener must be running and TCP must be a P2P profile")
        ports = free_ports(args.p2p_agents)
        cache = {}

        def build(profile, crypto, architecture, port=0):
            backend = profile_beaconcrypt_backend(args, profile)
            key = (profile, crypto, architecture, port)
            if key in cache:
                return cache[key]
            name = f"{profile}-{crypto}-{architecture}-{port}"
            directory = work / ("build-" + name)
            directory.mkdir()
            commands = ["pwd", "exit"] + (["link_tcp"] if profile == "http" else [])
            if args.payload_sizes:
                commands += ["setenv", "getenv"]
            parameters = {"AESPSK": crypto_selection(crypto, backend),
                "encrypted_exchange_check": False,
                "killdate": (datetime.date.today() + datetime.timedelta(days=2)).isoformat()}
            if profile == "http":
                parameters.update(callback_host="http://127.0.0.1", callback_port=args.callback_port,
                    callback_interval=1, callback_jitter=0, get_uri="index", post_uri="data",
                    query_path_name="q", headers={"User-Agent": "Poseidon real P2P integration"},
                    proxy_host="", proxy_port="", proxy_user="", proxy_pass="")
            else:
                parameters.update(port=str(port), localhost_only=True)
            configuration = {"payload_type": "poseidon", "selected_os": "Linux", "filename": "p2p-" + name,
                "description": "Real P2P cryptography matrix " + name, "commands": commands,
                "build_parameters": advertised_build_parameters({
                    "architecture": ARCHITECTURES[architecture]["build_parameter"],
                    "mode": "default", "garble": False, "debug": False,
                    "static": False, "proxy_bypass": True, "egress_order": [profile],
                    "egress_failover": "failover", "failover_threshold": 10}),
                "c2_profiles": [{"c2_profile": profile, "c2_profile_parameters": parameters}]}
            write_report(directory / "payload-config.json", configuration)
            submitted = client.request("/createpayload_webhook", {"input": {"payloadDefinition": json.dumps(configuration)}})
            if submitted.get("status") != "success" or not submitted.get("uuid"):
                raise RuntimeError("Build submission failed: " + json.dumps(submitted))
            def built():
                rows = client.graphql("query($uuid:String!){payload(where:{uuid:{_eq:$uuid}}){id uuid build_phase build_message build_stderr}}", {"uuid": submitted["uuid"]})["payload"]
                if rows and rows[0]["build_phase"] == "error":
                    raise RuntimeError("Real build failed: " + json.dumps(rows[0]))
                return rows[0] if rows and rows[0]["build_phase"] == "success" else None
            payload = await_result(name + " payload build", built, 600)
            artifact = client.request("/direct/download/" + payload["uuid"], binary=True)
            verify_elf_architecture(artifact, architecture)
            binary = directory / "poseidon"
            binary.write_bytes(artifact)
            binary.chmod(0o700)
            command = prefixes[architecture] + [str(binary)]
            write_report(directory / "build.json", dict(payload, architecture=architecture,
                         command=command, sha256=hashlib.sha256(artifact).hexdigest(),
                         crypto_alias=callback_crypto(crypto, backend),
                         beaconcrypt_backend=backend if crypto == "beaconcrypt" else None))
            result = dict(payload, binary=binary, crypto=crypto, architecture=architecture,
                          beaconcrypt_backend=backend,
                          command=command, commands=commands, port=port)
            cache[key] = result
            print("Built real " + name + " payload " + payload["uuid"], flush=True)
            return result

        for egress_crypto, child_cryptos in cases:
            egress = build("http", egress_crypto, args.egress_architecture)
            children = [build("tcp", crypto, args.p2p_architecture, port)
                        for crypto, port in zip(child_cryptos, ports)]
            child_label = "mixed" if len(set(child_cryptos)) > 1 else child_cryptos[0]
            case_name = f"egress-{egress_crypto}-{args.egress_architecture}_p2p-{child_label}-{args.p2p_architecture}"
            for size in args.payload_sizes or [0]:
                directory = work / (case_name + (f"_payload-{size}" if size else ""))
                try:
                    case = run_case(client, directory, egress, children, args.messages,
                                    payload_size=size, payload_timeout=args.payload_timeout)
                except (RuntimeError, OSError, KeyError, ValueError, subprocess.TimeoutExpired) as error:
                    case = json.loads((directory / "report.json").read_text()) if (directory / "report.json").exists() else {"status": "fail", "error": str(error), "agents": []}
                    report["cases"].append(case)
                    write_report(work / "report.json", report)
                    if not args.keep_going:
                        raise
                    print(f"FAIL: {directory.name}: {error}", file=sys.stderr, flush=True)
                    continue
                report["cases"].append(case)
                write_report(work / "report.json", report)
        failures = sum(case["status"] != "pass" for case in report["cases"])
        report.update(status="fail" if failures else "pass", case_count=len(report["cases"]),
                      agents=sum(len(case["agents"]) for case in report["cases"]),
                      task_response_exchanges=sum(case.get("task_response_exchanges", 0) for case in report["cases"]))
        if args.payload_sizes:
            report["payload_task_response_exchanges"] = sum(case.get("payload_task_response_exchanges", 0) for case in report["cases"])
        if failures:
            raise RuntimeError(f"{failures} of {report['case_count']} matrix cells failed; see per-case reports")
        print(f"PASS: {report['case_count']} matrix cells, {report['agents']} real agents, {report['task_response_exchanges']} exact pwd responses", flush=True)
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
