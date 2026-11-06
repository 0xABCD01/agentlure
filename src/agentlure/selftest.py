"""Selftest: run the bundled fixtures through the real scan pipeline
and assert the expected verdicts. This is the project's acceptance gate.

Fixtures ship inside the package (agentlure/fixtures/), so selftest
works from a plain pip install. AGENTLURE_FIXTURES can point at an
alternative fixtures directory. Exit code 0 means every fixture graded
as expected.
"""

from __future__ import annotations

import os
import sys
import tempfile

from .scan import TargetSpec, run_scan

FIXTURES = [
    ("ssh_reader", "MALICIOUS"),
    ("env_exfiltrator", "MALICIOUS"),
    ("postmark_bcc", "MALICIOUS"),
    ("echo_calc", "CLEAN"),
    ("notes", "CLEAN"),
    ("time_client", "CLEAN"),
]


def fixtures_dir():
    candidates = []
    if os.environ.get("AGENTLURE_FIXTURES"):
        candidates.append(os.environ["AGENTLURE_FIXTURES"])
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "fixtures"))
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    candidates.append(os.path.join(repo_root, "fixtures"))
    candidates.append(os.path.join(os.getcwd(), "fixtures"))
    for candidate in candidates:
        if os.path.isfile(os.path.join(candidate, "ssh_reader", "server.py")):
            return candidate
    return None


def run_selftest(timeout=90.0, keep=False):
    base = fixtures_dir()
    if base is None:
        print("selftest: bundled fixtures not found; set AGENTLURE_FIXTURES "
              "to a fixtures directory", file=sys.stderr)
        return 2
    print("agentlure selftest - %d fixtures, sandbox pipeline end-to-end" % len(FIXTURES))
    failures = 0
    for name, expected in FIXTURES:
        server = os.path.join(base, name, "server.py")
        spec = TargetSpec([sys.executable, server],
                          label="fixture %s" % name, source="selftest")
        out_dir = tempfile.mkdtemp(prefix="agentlure-selftest-%s-" % name, dir="/tmp")
        try:
            result = run_scan(spec, out_dir=out_dir, timeout=timeout)
            got = result.verdict
        except Exception as exc:  # a crash is a failed fixture, reported as such
            got = "ERROR (%s)" % exc
        ok = got == expected
        failures += 0 if ok else 1
        print("%-18s expected %-9s got %-9s %s" % (name, expected, got, "OK" if ok else "FAIL"))
        if not ok or keep:
            print("                   reports: %s" % out_dir)
    print("selftest: %s (%d/%d fixtures as expected)"
          % ("PASS" if failures == 0 else "FAIL", len(FIXTURES) - failures, len(FIXTURES)))
    return 0 if failures == 0 else 1
