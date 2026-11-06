"""agentlure command line: scan / selftest / version."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

from . import __version__


def build_parser():
    parser = argparse.ArgumentParser(
        prog="agentlure",
        description="Detonate MCP servers against fake credentials before "
                    "you install them.")
    sub = parser.add_subparsers(dest="subcommand")

    scan = sub.add_parser("scan", help="detonate one MCP server and grade it")
    target = scan.add_mutually_exclusive_group(required=True)
    target.add_argument("--command", help='server launch command, e.g. "python3 server.py"')
    target.add_argument("--config", help="path to an MCP config JSON (mcpServers format)")
    scan.add_argument("--server", help="server name inside --config "
                                       "(required when the config defines several)")
    scan.add_argument("--out-dir", help="where to write report.json/.sarif/.html "
                                        "(default: ./agentlure-out/<timestamp>)")
    scan.add_argument("--timeout", type=float, default=60.0,
                      help="overall detonation budget in seconds (default 60)")
    scan.add_argument("--fail-on", choices=["suspicious", "malicious"],
                      help="CI gate: exit 0 when the verdict is below this grade. "
                           "Without it, the exit code is the grade code "
                           "(CLEAN 0, SUSPICIOUS 1, MALICIOUS 2).")
    scan.add_argument("--backend", choices=["auto", "docker", "podman", "namespace"],
                      default="auto", help="sandbox backend (default: auto-detect)")
    scan.add_argument("--sandbox-image",
                      help="image for the docker/podman backends "
                           "(default: agentlure-sandbox:latest)")
    scan.add_argument("--keep-sandbox", action="store_true",
                      help="keep the sandbox run directory for debugging")

    sub.add_parser("selftest", help="run the bundled fixtures through the "
                                    "real pipeline and check the verdicts")
    sub.add_parser("version", help="print the agentlure version")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.subcommand == "version":
        print("agentlure %s" % __version__)
        return 0
    if args.subcommand == "selftest":
        from .selftest import run_selftest
        return run_selftest()
    if args.subcommand == "scan":
        from .report import terminal_summary
        from .sandbox import SandboxError
        from .scan import run_scan, target_from_command, target_from_config
        try:
            if args.config:
                spec = target_from_config(args.config, args.server)
            else:
                spec = target_from_command(args.command)
        except (ValueError, OSError) as exc:
            print("agentlure: %s" % exc, file=sys.stderr)
            return 3
        out_dir = args.out_dir or os.path.join(
            "agentlure-out", datetime.now().strftime("%Y%m%d-%H%M%S"))
        try:
            result = run_scan(
                spec, out_dir=out_dir, timeout=args.timeout,
                backend=args.backend, sandbox_image=args.sandbox_image,
                fail_on=args.fail_on, keep_sandbox=args.keep_sandbox,
            )
        except SandboxError as exc:
            print("agentlure: %s" % exc, file=sys.stderr)
            return 3
        print(terminal_summary(result))
        print("reports: %s" % os.path.abspath(out_dir))
        return result.exit_code
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
