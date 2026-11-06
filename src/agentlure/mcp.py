"""Minimal MCP client over stdio (newline-delimited JSON-RPC) plus
synthetic argument generation from tool input schemas."""

from __future__ import annotations

import json
import queue
import threading
import time

PROTOCOL_VERSION = "2024-11-05"


class MCPError(Exception):
    pass


class MCPTimeout(MCPError):
    pass


class MCPClient:
    def __init__(self, proc):
        self._proc = proc
        self._queue = queue.Queue()
        self._next_id = 1
        self._eof = threading.Event()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        try:
            for raw in self._proc.stdout:
                line = raw.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line.decode("utf-8", "replace"))
                except ValueError:
                    continue
                self._queue.put(msg)
        except (ValueError, OSError):
            pass
        finally:
            self._eof.set()

    def _send(self, payload):
        data = (json.dumps(payload) + "\n").encode()
        self._proc.stdin.write(data)
        self._proc.stdin.flush()

    def request(self, method, params, timeout):
        req_id = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        stash = []
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise MCPTimeout("timeout waiting for %s" % method)
            try:
                msg = self._queue.get(timeout=min(remaining, 0.25))
            except queue.Empty:
                if self._eof.is_set() or self._proc.poll() is not None:
                    raise MCPError(
                        "target process exited while waiting for %s" % method)
                continue
            if msg.get("id") == req_id:
                for extra in stash:
                    self._queue.put(extra)
                if "error" in msg:
                    raise MCPError("%s: %s" % (method, msg["error"]))
                return msg.get("result")
            stash.append(msg)

    def notify(self, method, params=None):
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._send(payload)

    def initialize(self, timeout):
        result = self.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "agentlure", "version": "0.1.0"},
        }, timeout)
        self.notify("notifications/initialized")
        return result


def synthesize_value(schema, depth=0):
    """One benign synthetic value for a JSON-schema fragment."""
    if not isinstance(schema, dict):
        return "hello"
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    stype = schema.get("type")
    if isinstance(stype, list):
        stype = stype[0] if stype else None
    if stype == "string" or (stype is None and "properties" not in schema):
        return "hello"
    if stype in ("number", "integer"):
        return 1
    if stype == "boolean":
        return True
    if stype == "array":
        return []
    if stype == "object" or "properties" in schema:
        if depth >= 3:
            return {}
        return {
            name: synthesize_value(prop, depth + 1)
            for name, prop in (schema.get("properties") or {}).items()
        }
    return "hello"


def synthesize_arguments(input_schema):
    """Build the arguments object for one tools/call: a synthesized value
    for every declared property (required or not), so the tool actually
    runs its code path."""
    if not isinstance(input_schema, dict):
        return {}
    properties = input_schema.get("properties")
    if not isinstance(properties, dict) or not properties:
        return {}
    return {name: synthesize_value(prop) for name, prop in properties.items()}
