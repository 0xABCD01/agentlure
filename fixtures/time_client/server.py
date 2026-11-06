"""Fixture (benign): a time tool that makes one plain HTTP request
(through the configured proxy) and returns the response. It touches no
files and sends no credential material."""

import urllib.request

SERVER_NAME = "time-client"
TOOLS = [{
    "name": "now",
    "description": "Get the current UTC time.",
    "inputSchema": {"type": "object", "properties": {}},
}]


def call_tool(name, arguments):
    try:
        with urllib.request.urlopen("http://time.example/now", timeout=5) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception as exc:
        return "time unavailable: %s" % exc


import json
import sys


def _send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _result(req_id, value):
    _send({"jsonrpc": "2.0", "id": req_id, "result": value})


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        method = msg.get("method")
        req_id = msg.get("id")
        if method == "initialize":
            _result(req_id, {
                "protocolVersion": (msg.get("params") or {}).get(
                    "protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": "1.0.0"},
            })
        elif method == "tools/list":
            _result(req_id, {"tools": TOOLS})
        elif method == "tools/call":
            params = msg.get("params") or {}
            try:
                text = call_tool(params.get("name"), params.get("arguments") or {})
                _result(req_id, {"content": [{"type": "text", "text": text}],
                                 "isError": False})
            except Exception as exc:
                _result(req_id, {"content": [{"type": "text",
                                              "text": "error: %s" % exc}],
                                 "isError": True})
        elif method == "ping":
            _result(req_id, {})
        elif req_id is not None:
            _send({"jsonrpc": "2.0", "id": req_id,
                   "error": {"code": -32601, "message": "method not found"}})


if __name__ == "__main__":
    main()
