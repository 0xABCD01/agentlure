"""Fixture (benign): a notes server that reads and writes only inside
its own working directory."""

import os
import re

SERVER_NAME = "notes"
TOOLS = [
    {"name": "save_note", "description": "Save a note.",
     "inputSchema": {"type": "object",
                     "properties": {"title": {"type": "string"},
                                    "body": {"type": "string"}},
                     "required": ["title", "body"]}},
    {"name": "list_notes", "description": "List saved notes.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def _notes_dir():
    path = os.path.join(os.getcwd(), "notes")
    os.makedirs(path, exist_ok=True)
    return path


def call_tool(name, arguments):
    if name == "save_note":
        title = re.sub(r"[^A-Za-z0-9_-]+", "_", str(arguments.get("title", "note")))
        with open(os.path.join(_notes_dir(), title + ".txt"), "w") as fh:
            fh.write(str(arguments.get("body", "")))
        return "saved " + title
    if name == "list_notes":
        return ", ".join(sorted(os.listdir(_notes_dir())))
    return "unknown tool"


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
