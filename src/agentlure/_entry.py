"""In-sandbox entry point: `python3 -m agentlure._entry --mode ... -- cmd...`

Runs INSIDE the sandbox (namespace or container). Responsibilities:

- namespace mode: make mounts private, bind the synthetic HOME over the
  real home path, mount a fresh /proc, raise loopback in the network
  namespace (loopback is the only interface there).
- start the sinkhole proxy on 127.0.0.1 (a thread in this process);
- apply CPU rlimits inherited by the target;
- scrub all AGENTLURE_* variables from the environment, set HOME to the
  (bind-mounted) home path, point HTTP_PROXY/HTTPS_PROXY at the sinkhole;
- launch the target under strace (when available), inheriting this
  process's stdin/stdout - which are the scanner's MCP pipes. Nothing in
  this module may print to stdout: it would corrupt the JSON-RPC channel.
  Diagnostics go to <evidence-dir>/entry.log.
"""

from __future__ import annotations

import argparse
import ctypes
import fcntl
import json
import os
import resource
import shutil
import socket
import struct
import subprocess
import sys

from .sinkhole import Sinkhole

MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8

SIOCSIFFLAGS = 0x8914
IFF_UP = 0x1
IFF_RUNNING = 0x40

STRACE_TRACE = (
    "execve,openat,open,creat,connect,chdir,fork,vfork,clone,clone3,"
    "unlink,unlinkat,rename,renameat,mkdir,mkdirat"
)


def _mount(source, target, fstype, flags, data=None):
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    ret = libc.mount(
        source.encode() if source else None,
        target.encode(),
        fstype.encode() if fstype else None,
        flags,
        data.encode() if data else None,
    )
    if ret != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), target)


def _raise_loopback():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack("16sh", b"lo", IFF_UP | IFF_RUNNING) + b"\x00" * 22
        fcntl.ioctl(sock, SIOCSIFFLAGS, ifreq)
    finally:
        sock.close()


def _log(evidence_dir, message):
    try:
        with open(os.path.join(evidence_dir, "entry.log"), "a") as fh:
            fh.write(message + "\n")
    except OSError:
        pass


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--" in argv:
        sep = argv.index("--")
        own, target_argv = argv[:sep], argv[sep + 1:]
    else:
        own, target_argv = argv, []
    parser = argparse.ArgumentParser(prog="agentlure-entry")
    parser.add_argument("--mode", choices=["namespace", "container"], required=True)
    parser.add_argument("--home-backing", required=True)
    parser.add_argument("--home-display", required=True)
    parser.add_argument("--workdir", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--proxy-port", type=int, default=18080)
    parser.add_argument("--cpu-seconds", type=int, default=90)
    parser.add_argument("--mask-pair", action="append", default=[],
                        help="backing=display: bind a canary path over the "
                             "matching real-home path (namespace mode)")
    args = parser.parse_args(own)

    evidence_dir = args.evidence_dir
    os.makedirs(evidence_dir, exist_ok=True)
    if not target_argv:
        _log(evidence_dir, "no target command given")
        return 2

    if args.mode == "namespace":
        try:
            _mount(None, "/", None, MS_REC | MS_PRIVATE)
            # Mask the credential-bearing paths of the real home with
            # their canary counterparts, where the real paths exist.
            # The rest of the home directory stays visible so the
            # target's own code (often under $HOME) keeps working.
            for pair in args.mask_pair:
                backing, _, display = pair.partition("=")
                if not backing or not display:
                    continue
                if os.path.isdir(display) and os.path.isdir(backing):
                    _mount(backing, display, None, MS_BIND | MS_REC)
                elif os.path.isfile(display) and os.path.isfile(backing):
                    _mount(backing, display, None, MS_BIND)
                else:
                    _log(evidence_dir, "mask skipped (missing): %s" % display)
            try:
                _mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)
            except OSError as exc:
                _log(evidence_dir, "proc mount skipped: %s" % exc)
            _raise_loopback()
        except OSError as exc:
            _log(evidence_dir, "namespace setup failed: %s" % exc)
            return 2

    # Resource limits (inherited by the target).
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (args.cpu_seconds, args.cpu_seconds + 5))
        resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    except (ValueError, OSError) as exc:
        _log(evidence_dir, "setrlimit failed: %s" % exc)

    # Sinkhole proxy. Canary values arrive via the environment; they are
    # scrubbed from the target's environment below.
    manifest = json.loads(os.environ.get("AGENTLURE_CANARY_MANIFEST", "{}"))
    sinkhole = Sinkhole(manifest, os.path.join(evidence_dir, "proxy.jsonl"),
                        port=args.proxy_port)
    sinkhole.start()
    _log(evidence_dir, "sinkhole listening on 127.0.0.1:%d" % sinkhole.port)

    # Target environment: scrub harness variables, plant HOME and proxies.
    env = {k: v for k, v in os.environ.items() if not k.startswith("AGENTLURE_")}
    env["HOME"] = args.home_display
    proxy_url = "http://127.0.0.1:%d" % sinkhole.port
    for key in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        env[key] = proxy_url
    env["no_proxy"] = ""
    env["NO_PROXY"] = ""
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    os.chdir(args.workdir)

    trace_dir = os.path.join(evidence_dir, "trace")
    os.makedirs(trace_dir, exist_ok=True)
    strace = shutil.which("strace")
    stderr_path = os.path.join(evidence_dir, "target-stderr.txt")
    with open(stderr_path, "ab") as stderr_fh:
        if strace:
            cmd = [
                strace, "-f", "-ff", "-tt", "-s", "4096",
                "-e", "trace=" + STRACE_TRACE,
                "-o", os.path.join(trace_dir, "trace"),
            ] + target_argv
        else:
            cmd = list(target_argv)
            _log(evidence_dir, "strace not available; filesystem/process evidence disabled")
        try:
            proc = subprocess.Popen(cmd, env=env, stderr=stderr_fh)
        except OSError as exc:
            _log(evidence_dir, "target launch failed: %s" % exc)
            sinkhole.stop()
            return 2
        exit_code = proc.wait()

    try:
        sinkhole.stop()
    except Exception:
        pass
    with open(os.path.join(evidence_dir, "entry.json"), "w") as fh:
        json.dump({"target_exit_code": exit_code, "strace": bool(strace)}, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
