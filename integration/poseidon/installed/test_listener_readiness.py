"""Verify real owned LISTEN sockets without consuming the agent's connection."""

import errno
import os
from pathlib import Path
import socket
import subprocess
import sys
from types import SimpleNamespace
import unittest

from test_p2p import listening


@unittest.skipUnless(sys.platform == "linux" and Path("/proc/self/fd").is_dir(), "requires Linux procfs")
class ListenerReadinessTests(unittest.TestCase):
    def test_time_wait_port_is_not_a_listener(self):
        server = socket.socket()
        client = socket.socket()
        accepted = None
        try:
            server.bind(("127.0.0.1", 0))
            port = server.getsockname()[1]
            server.listen()
            client.connect(("127.0.0.1", port))
            accepted, _ = server.accept()
            # The server actively closes, leaving its port in TIME_WAIT.
            accepted.shutdown(socket.SHUT_WR)
            self.assertEqual(client.recv(1), b"")
            client.close()
            accepted.close()
            server.close()
            with socket.socket() as old_probe:
                with self.assertRaises(OSError) as failure:
                    old_probe.bind(("127.0.0.1", port))
                self.assertEqual(failure.exception.errno, errno.EADDRINUSE)
            process = SimpleNamespace(pid=os.getpid(), poll=lambda: None)
            self.assertIsNone(listening(process, port))
        finally:
            if accepted is not None:
                accepted.close()
            client.close()
            server.close()

    def test_only_the_agents_owned_listener_is_ready(self):
        program = """import socket, sys
server = socket.socket()
server.bind(('127.0.0.1', 0))
print(server.getsockname()[1], flush=True)
sys.stdin.readline()
server.listen()
print('listening', flush=True)
sys.stdin.readline()
"""
        process = subprocess.Popen([sys.executable, "-c", program],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            port = int(process.stdout.readline())
            self.assertIsNone(listening(process, port))
            with socket.socket() as unrelated:
                unrelated.bind(("127.0.0.1", 0))
                unrelated.listen()
                self.assertIsNone(listening(process, unrelated.getsockname()[1]))
            process.stdin.write("listen\n")
            process.stdin.flush()
            self.assertEqual(process.stdout.readline().strip(), "listening")
            self.assertTrue(listening(process, port))
        finally:
            process.terminate()
            process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()


if __name__ == "__main__":
    unittest.main()
