"""Sinkhole proxy: the only network endpoint a detonated target can reach.

Runs inside the sandbox on loopback. Plain HTTP proxy requests get a
benign JSON response; CONNECT attempts are logged and the tunnel is
accepted only to capture whatever the client sends next (no traffic is
ever forwarded anywhere). Every captured component (request line/URL,
headers, body, CONNECT target, tunneled bytes) is searched for canary
values, and every request is appended as one JSON line to the proxy log
for the scanner to grade.
"""

from __future__ import annotations

import base64
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .encodings import search_blob

_MAX_BODY = 4 * 1024 * 1024
_STORE_BODY = 256 * 1024


def _now():
    return datetime.now(timezone.utc).isoformat()


class _Log:
    def __init__(self, path):
        self._fh = open(path, "a", encoding="utf-8", buffering=1)
        self._lock = threading.Lock()

    def write(self, record):
        line = json.dumps(record)
        with self._lock:
            self._fh.write(line + "\n")

    def close(self):
        with self._lock:
            self._fh.close()


def make_handler(values, log):
    class SinkholeHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "agentlure-sinkhole"

        # Quieten default stderr logging; everything goes to the JSON log.
        def log_message(self, *args):
            pass

        def _search(self, where, data, base_record):
            hits = search_blob(data, values)
            for hit in hits:
                hit = dict(hit)
                hit["where"] = where
                base_record["hits"].append(hit)

        def _record(self, kind, target, body=b"", tunneled=b""):
            record = {
                "ts": _now(),
                "kind": kind,
                "method": self.command,
                "url": target,
                "headers": {k: v for k, v in self.headers.items()},
                "body_len": len(body),
                "body_b64": base64.b64encode(body[:_STORE_BODY]).decode() if body else "",
                "hits": [],
            }
            head_blob = (target + "\n" + "\n".join(
                "%s: %s" % kv for kv in self.headers.items())).encode("utf-8", "replace")
            self._search("request_line+headers", head_blob, record)
            if body:
                self._search("body", body, record)
            if tunneled:
                record["tunneled_len"] = len(tunneled)
                self._search("tunnel", tunneled, record)
            log.write(record)
            return record

        def _read_body(self):
            length = self.headers.get("Content-Length")
            if length is not None:
                try:
                    n = min(int(length), _MAX_BODY)
                except ValueError:
                    return b""
                return self.rfile.read(n) if n > 0 else b""
            if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
                chunks = []
                total = 0
                while total < _MAX_BODY:
                    size_line = self.rfile.readline(65536).strip()
                    try:
                        size = int(size_line.split(b";")[0], 16)
                    except ValueError:
                        break
                    if size == 0:
                        self.rfile.readline(65536)
                        break
                    data = self.rfile.read(size)
                    self.rfile.readline(65536)
                    chunks.append(data)
                    total += len(data)
                return b"".join(chunks)
            return b""

        def _handle_plain(self):
            body = self._read_body()
            self._record("http", self.path, body)
            payload = json.dumps({
                "ok": True,
                "service": "agentlure-sinkhole",
                "utc": _now(),
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = _handle_plain
        do_POST = _handle_plain
        do_PUT = _handle_plain
        do_PATCH = _handle_plain
        do_DELETE = _handle_plain
        do_OPTIONS = _handle_plain
        do_HEAD = _handle_plain

        def do_CONNECT(self):
            target = self.path
            self.send_response(200, "Connection Established")
            self.end_headers()
            tunneled = b""
            try:
                self.connection.settimeout(2.0)
                tunneled = self.connection.recv(65536)
            except OSError:
                tunneled = b""
            self._record("connect", target, b"", tunneled)
            try:
                self.connection.close()
            except OSError:
                pass

    return SinkholeHandler


class Sinkhole:
    """Threaded sinkhole proxy bound to loopback."""

    def __init__(self, values, log_path, host="127.0.0.1", port=18080):
        self._log = _Log(log_path)
        handler = make_handler(values, self._log)
        self._server = ThreadingHTTPServer((host, port), handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self):
        try:
            self._server.shutdown()
            self._server.server_close()
        finally:
            self._log.close()
