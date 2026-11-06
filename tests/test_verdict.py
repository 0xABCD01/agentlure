import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentlure.evidence import (
    CANARY_EGRESS, CANARY_READ, UNEXPECTED_SPAWN, WRITE_OUTSIDE,
    analyze_proxy, analyze_trace, compute_verdict, exit_code_for,
)
from agentlure.traceparse import TraceData


def ev(cls):
    return {"class": cls, "detail": "x"}


class VerdictTests(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(compute_verdict([]), "CLEAN")

    def test_egress_is_malicious(self):
        self.assertEqual(compute_verdict([ev(CANARY_EGRESS)]), "MALICIOUS")
        self.assertEqual(
            compute_verdict([ev(CANARY_READ), ev(CANARY_EGRESS)]), "MALICIOUS")

    def test_others_are_suspicious(self):
        for cls in (CANARY_READ, UNEXPECTED_SPAWN, WRITE_OUTSIDE):
            self.assertEqual(compute_verdict([ev(cls)]), "SUSPICIOUS", cls)

    def test_exit_codes_default(self):
        self.assertEqual(exit_code_for("CLEAN"), 0)
        self.assertEqual(exit_code_for("SUSPICIOUS"), 1)
        self.assertEqual(exit_code_for("MALICIOUS"), 2)

    def test_exit_codes_fail_on(self):
        self.assertEqual(exit_code_for("SUSPICIOUS", "malicious"), 0)
        self.assertEqual(exit_code_for("MALICIOUS", "malicious"), 2)
        self.assertEqual(exit_code_for("SUSPICIOUS", "suspicious"), 1)
        self.assertEqual(exit_code_for("CLEAN", "suspicious"), 0)


class ProxyEvidenceTests(unittest.TestCase):
    def test_hit_becomes_egress_with_masked_value(self):
        records = [{
            "ts": "2026-01-01T00:00:00+00:00", "kind": "http", "method": "POST",
            "url": "http://collector.example/x", "body_len": 10,
            "hits": [{"canary_type": "npm", "encoding": "raw",
                      "where": "body", "value_index": 0}],
        }]
        evidence, requests = analyze_proxy(records, {"npm": ["npm_ab…yz"]})
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["class"], CANARY_EGRESS)
        self.assertIn("npm_ab…yz", evidence[0]["detail"])
        self.assertEqual(len(requests), 1)

    def test_no_hits_no_evidence(self):
        records = [{"kind": "http", "method": "GET", "url": "http://t.example/",
                    "body_len": 0, "hits": []}]
        evidence, _ = analyze_proxy(records, {})
        self.assertEqual(evidence, [])


def make_trace(execs=(), file_events=(), parents=None, root=100, first_exec=None):
    trace = TraceData()
    trace.execs = list(execs)
    trace.file_events = list(file_events)
    trace.parents = parents or {}
    trace.root_pid = root
    trace.first_exec = first_exec or {}
    return trace


class TraceEvidenceTests(unittest.TestCase):
    def test_launch_shell_is_not_flagged(self):
        root_exec = {"pid": 100, "ts": 10.0, "path": "/bin/sh",
                     "basename": "sh", "seq": 1}
        trace = make_trace(execs=[root_exec], first_exec={100: root_exec})
        out = analyze_trace(trace, canary_file_types={},
                            allowed_write_prefixes=["/work"], init_done_ts=11.0)
        self.assertEqual(out, [])

    def test_spawned_curl_is_flagged(self):
        root_exec = {"pid": 100, "ts": 10.0, "path": "/usr/bin/python3",
                     "basename": "python3", "seq": 1}
        curl_exec = {"pid": 101, "ts": 12.0, "path": "/usr/bin/curl",
                     "basename": "curl", "seq": 2}
        trace = make_trace(execs=[root_exec, curl_exec],
                           parents={101: 100}, first_exec={100: root_exec})
        out = analyze_trace(trace, canary_file_types={},
                            allowed_write_prefixes=["/work"], init_done_ts=11.0)
        self.assertEqual([e["class"] for e in out], [UNEXPECTED_SPAWN])

    def test_canary_read_detected(self):
        fe = {"pid": 100, "ts": 12.0, "syscall": "openat",
              "path": "/home/u/.ssh/id_rsa", "resolved": "/home/u/.ssh/id_rsa",
              "flags": "O_RDONLY", "result": 3, "write": False}
        trace = make_trace(file_events=[fe])
        out = analyze_trace(
            trace, canary_file_types={"/home/u/.ssh/id_rsa": "ssh"},
            allowed_write_prefixes=["/work", "/home/u"], init_done_ts=11.0)
        self.assertEqual([e["class"] for e in out], [CANARY_READ])

    def test_write_outside_detected_and_home_write_allowed(self):
        bad = {"pid": 100, "ts": 12.0, "syscall": "openat",
               "path": "/etc/cron.d/x", "resolved": "/etc/cron.d/x",
               "flags": "O_WRONLY|O_CREAT", "result": 3, "write": True}
        good = {"pid": 100, "ts": 12.1, "syscall": "openat",
                "path": "/work/notes/a.txt", "resolved": "/work/notes/a.txt",
                "flags": "O_WRONLY|O_CREAT", "result": 3, "write": True}
        dev = {"pid": 100, "ts": 12.2, "syscall": "openat",
               "path": "/dev/null", "resolved": "/dev/null",
               "flags": "O_RDWR", "result": 3, "write": True}
        failed = {"pid": 100, "ts": 12.3, "syscall": "openat",
                  "path": "/etc/cron.d/y", "resolved": "/etc/cron.d/y",
                  "flags": "O_WRONLY|O_CREAT", "result": -1, "write": True}
        trace = make_trace(file_events=[bad, good, dev, failed])
        out = analyze_trace(trace, canary_file_types={},
                            allowed_write_prefixes=["/work", "/home/u"],
                            init_done_ts=11.0)
        self.assertEqual([e["class"] for e in out], [WRITE_OUTSIDE])
        self.assertEqual(out[0]["path"], "/etc/cron.d/x")


if __name__ == "__main__":
    unittest.main()
