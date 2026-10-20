"""Deterministic large-message probes for real, installed Poseidon agents.

The existing setenv command carries a value to the agent and echoes it back.
This tests complete logical command and response bytes; Poseidon may split its
response into multiple Mythic response rows. Keep the distinct-directory pwd
oracle as well: an echoed challenge alone cannot identify the executing process.
"""

import base64
import binascii
import hashlib
import re


DEFAULT_PAYLOAD_SIZES = (1024, 64 * 1024, 1024 * 1024, 10 * 1024 * 1024)
MAX_PAYLOAD_SIZE = 64 * 1024 * 1024
DEFAULT_VARIABLE_NAME = "BEACONCRYPT_E2E_PAYLOAD"


def _validate_size(size):
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_PAYLOAD_SIZE:
        raise ValueError("Payload size must be between 1 byte and 64 MiB")
    return size


def parse_payload_size(value):
    """Parse a byte count or a binary KiB/MiB size without rounding."""
    if not isinstance(value, str):
        raise ValueError("Payload size must be a byte count or use KiB/MiB")
    match = re.fullmatch(r"([0-9]+)\s*(B|KiB|MiB)?", value.strip(), re.IGNORECASE)
    if not match:
        raise ValueError("Payload size must be a byte count or use KiB/MiB")
    unit = (match.group(2) or "b").lower()
    return _validate_size(int(match.group(1)) * {"b": 1, "kib": 1024, "mib": 1024 * 1024}[unit])


def payload_value(size, seed):
    """Return exact-size hexadecimal ASCII, deterministic for this private seed."""
    _validate_size(size)
    if not isinstance(seed, str) or not seed:
        raise ValueError("A nonempty payload seed is required")
    # Callers include independently known process directory, callback ID, size,
    # and round in their seed. SHAKE avoids compressible constant padding.
    material = b"mythic-poseidon-large-payload-v1\x00" + seed.encode("utf-8")
    return hashlib.shake_256(material).hexdigest((size + 1) // 2)[:size]


def _response_bytes(row):
    chunks = []
    previous_id = None
    for response in row.get("responses", []):
        response_id = response.get("id")
        if isinstance(response_id, bool) or not isinstance(response_id, int) or response_id < 1:
            raise RuntimeError("Large-payload response has an invalid row ID")
        if previous_id is not None and response_id <= previous_id:
            raise RuntimeError("Duplicate or unordered large-payload response rows")
        previous_id = response_id
        encoded = response.get("response_text")
        if not isinstance(encoded, str):
            raise RuntimeError("Large-payload response is missing its base64 text")
        try:
            # PostgreSQL's base64 computed field can wrap long text with LF.
            compact = "".join(encoded.split()).encode("ascii")
            chunks.append(base64.b64decode(compact, validate=True))
        except (UnicodeEncodeError, ValueError, binascii.Error):
            raise RuntimeError("Large-payload response contains invalid base64") from None
    return b"".join(chunks)


def assert_payload_responses(rows, expected):
    """Validate all available bytes, returning None until all bytes arrive.

    Poseidon marks its first user-output chunk completed, so task.completed alone
    cannot establish delivery. Re-run this oracle after agent shutdown to catch
    unexpected late output as well. Never include full output in exceptions.
    """
    intended = {item["id"]: item for item in expected}
    if len(intended) != len(expected):
        raise RuntimeError("Large-payload oracle requires distinct task IDs")
    actual_ids = [row["id"] for row in rows]
    if len(set(actual_ids)) != len(actual_ids):
        raise RuntimeError("Duplicate task IDs in large-payload results")
    if set(actual_ids) - intended.keys():
        raise RuntimeError("Unexpected task in large-payload results")
    ready = len(rows) == len(expected)
    for row in rows:
        task = intended[row["id"]]
        if task.get("command") not in ("setenv", "getenv") or not isinstance(task.get("output"), bytes):
            raise RuntimeError("Large-payload oracle requires an expected command and private output bytes")
        if row.get("callback_id") != task["callback_id"] or row.get("command_name") != task["command"]:
            raise RuntimeError("Large-payload response attached to the wrong callback or command")
        if "error" in str(row.get("status", "")).lower():
            raise RuntimeError(f"Large-payload task {row['id']} failed")
        wanted = task["output"]
        output = _response_bytes(row)
        if len(output) > len(wanted):
            raise RuntimeError(f"Extra or duplicate large-payload output for task {row['id']}: got {len(output)} bytes; expected {len(wanted)}")
        if output != wanted[:len(output)]:
            raise RuntimeError(f"Corrupt or mismatched large-payload output for task {row['id']}")
        if len(output) != len(wanted) or not row.get("completed"):
            ready = False
    return rows if ready else None
