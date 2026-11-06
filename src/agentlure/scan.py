"""Scan orchestration: plant canaries, detonate the target inside the
sandbox, drive it over MCP, collect evidence, grade, report."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

from . import __version__
from .canaries import mint_canaries, plant_canaries
from .evidence import (
    analyze_proxy,
    analyze_trace,
    compute_verdict,
    exit_code_for,
)
from .mcp import MCPClient, MCPError, MCPTimeout, synthesize_arguments
from .report import write_reports
from .sandbox import SandboxError, build_launch, detect_backend
from .traceparse import parse_trace_dir

PROXY_PORT = 18080


def _iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


class TargetSpec:
    def __init__(self, argv, env=None, label=None, source="command"):
        self.argv = list(argv)
        self.env = dict(env or {})
        self.label = label or " ".join(shlex.quote(a) for a in argv)
        self.source = source


# MCP configs and shell-style commands use paths relative to the
# caller's cwd or the config file; the sandbox runs the target from
# its own workdir, so rewrite any argument that names an existing
# file to its absolute path.
def _absolutize_args(args, bases):
    fixed = []
    for arg in args:
        if not os.path.isabs(arg):
            for base in bases:
                candidate = os.path.join(base, arg)
                if os.path.isfile(candidate):
                    arg = candidate
                    break
        fixed.append(arg)
    return fixed


def target_from_command(command):
    argv = shlex.split(command)
    if not argv:
        raise ValueError("empty --command")
    argv = [argv[0]] + _absolutize_args(argv[1:], [os.getcwd()])
    return TargetSpec(argv, label=command, source="--command")


def target_from_config(config_path, server_name):
    with open(config_path, encoding="utf-8") as fh:
        config = json.load(fh)
    servers = config.get("mcpServers") or {}
    if server_name is None:
        if len(servers) != 1:
            raise ValueError(
                "--server is required: config defines %d servers (%s)"
                % (len(servers), ", ".join(sorted(servers)) or "none"))
        server_name = next(iter(servers))
    if server_name not in servers:
        raise ValueError("server %r not found in %s (has: %s)"
                         % (server_name, config_path, ", ".join(sorted(servers))))
    entry = servers[server_name]
    command = entry.get("command")
    if not command:
        raise ValueError("server %r has no 'command'" % server_name)
    args = [str(a) for a in entry.get("args") or []]
    config_dir = os.path.dirname(os.path.abspath(config_path))
    fixed = _absolutize_args(args, [config_dir, os.getcwd()])
    return TargetSpec([command] + fixed, env=entry.get("env") or {},
                      label="%s (from %s)" % (server_name, config_path),
                      source="--config")


class ScanResult:
    def __init__(self, **fields):
        self.__dict__.update(fields)

    def to_dict(self):
        return {
            "tool": "agentlure",
            "version": __version__,
            "run_id": self.run_id,
            "started_at": _iso(self.started_ts),
            "finished_at": _iso(self.finished_ts),
            "target": {
                "label": self.spec.label,
                "argv": self.spec.argv,
                "source": self.spec.source,
            },
            "sandbox": {"backend": self.backend_name},
            "canaries": [
                {
                    "type": entry["type"],
                    "values_masked": entry["values_masked"],
                    "files": [{"sandbox_path": f["sandbox_path"]} for f in entry["files"]],
                }
                for entry in self.canary_manifest
            ],
            "tools": self.tools,
            "network_requests": self.network_requests,
            "observations": {"connects": self.connects},
            "evidence": self.evidence,
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "run_error": self.run_error,
        }


def _terminate_group(proc, grace=3.0):
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=grace)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass


def run_scan(spec, *, out_dir=None, timeout=60.0, backend="auto",
             sandbox_image=None, fail_on=None, keep_sandbox=False):
    """Run one scan. Returns a ScanResult; reports are written to
    out_dir when given. Raises SandboxError before launching anything
    if no sandbox backend works."""
    backend_obj = detect_backend(backend)
    started = time.time()
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(2).hex()

    # The run root lives outside the user's HOME: in namespace mode the
    # synthetic HOME is bind-mounted over the real home path, which would
    # hide anything stored underneath it.
    run_root = tempfile.mkdtemp(prefix="agentlure-run-", dir="/tmp")
    home_backing = os.path.join(run_root, "home")
    workdir = os.path.join(run_root, "work")
    evidence_dir = os.path.join(run_root, "evidence")
    for path in (home_backing, workdir, evidence_dir):
        os.makedirs(path, exist_ok=True)

    canaries = mint_canaries()
    plant_canaries(home_backing, canaries)
    real_home = os.path.expanduser("~")
    # The target's HOME is the synthetic home directory itself, for every
    # backend: os.path.expanduser("~") and $HOME both land on canaries.
    home_display = home_backing
    # In namespace mode the credential paths of the real home are also
    # bind-masked with canary versions (see _entry), which needs the
    # (backing, real) pairs for the paths we plant.
    mask_pairs = []
    if backend_obj.name == "namespace":
        for rel in (".aws", ".ssh", ".config/gh", ".env"):
            mask_pairs.append((os.path.join(home_backing, rel),
                               os.path.join(real_home, rel)))
    manifest = [c.manifest_entry(home_display, home_backing) for c in canaries]
    values_by_type = {}
    masked_by_type = {}
    for canary, entry in zip(canaries, manifest):
        values_by_type[canary.type] = canary.values
        masked_by_type[canary.type] = entry["values_masked"]

    env = dict(os.environ)
    env.update(spec.env)
    env["AGENTLURE_CANARY_MANIFEST"] = json.dumps(values_by_type)
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    launch = build_launch(
        backend_obj,
        home_backing=home_backing,
        home_display=home_display,
        workdir=workdir,
        evidence_dir=evidence_dir,
        proxy_port=PROXY_PORT,
        cpu_seconds=int(timeout) + 60,
        target_argv=spec.argv,
        image=sandbox_image,
        env_passthrough=tuple(spec.env.keys()),
        mask_pairs=mask_pairs,
    )

    tools = []
    run_error = None
    init_done_ts = None
    deadline = time.monotonic() + timeout
    launcher_stderr = open(os.path.join(evidence_dir, "launcher-stderr.txt"), "wb")
    proc = subprocess.Popen(
        launch, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=launcher_stderr, env=env, start_new_session=True,
    )
    try:
        client = MCPClient(proc)

        def remaining(cap):
            return max(0.1, min(cap, deadline - time.monotonic()))

        try:
            client.initialize(timeout=remaining(20))
            init_done_ts = time.time()
        except (MCPError, OSError) as exc:
            run_error = "MCP initialize failed: %s" % exc
        if init_done_ts is not None:
            try:
                listing = client.request("tools/list", {}, timeout=remaining(10))
                tool_list = (listing or {}).get("tools") or []
            except (MCPError, OSError) as exc:
                run_error = "tools/list failed: %s" % exc
                tool_list = []
            for tool in tool_list:
                name = tool.get("name", "?")
                arguments = synthesize_arguments(tool.get("inputSchema"))
                record = {"name": name, "arguments": arguments, "outcome": "skipped"}
                if time.monotonic() < deadline:
                    try:
                        client.request(
                            "tools/call",
                            {"name": name, "arguments": arguments},
                            timeout=remaining(15),
                        )
                        record["outcome"] = "ok"
                    except MCPTimeout:
                        record["outcome"] = "timeout"
                    except (MCPError, OSError) as exc:
                        record["outcome"] = "error: %s" % exc
                tools.append(record)
        # Observe window: let asynchronous behaviour (deferred exfil,
        # background spawns) surface before teardown.
        grace_end = time.monotonic() + 1.5
        while time.monotonic() < grace_end and proc.poll() is None:
            time.sleep(0.1)
    finally:
        try:
            if proc.stdin:
                proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        _terminate_group(proc)
        launcher_stderr.close()

    finished = time.time()

    # --- evidence: sinkhole -------------------------------------------
    proxy_records = []
    proxy_log = os.path.join(evidence_dir, "proxy.jsonl")
    if os.path.isfile(proxy_log):
        with open(proxy_log, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        proxy_records.append(json.loads(line))
                    except ValueError:
                        pass
    evidence, network_requests = analyze_proxy(proxy_records, masked_by_type)

    # --- evidence: strace ----------------------------------------------
    canary_file_types = {}
    for entry in manifest:
        for f in entry["files"]:
            canary_file_types[f["sandbox_path"]] = entry["type"]
            canary_file_types[f["backing_path"]] = entry["type"]
            # The real-home spelling, masked in namespace mode.
            canary_file_types[os.path.join(real_home, f["rel"])] = entry["type"]
    base_date = datetime.fromtimestamp(started).astimezone()
    trace = parse_trace_dir(os.path.join(evidence_dir, "trace"), workdir, base_date)
    allowed_write = [workdir, home_display, home_backing, "/tmp"]
    evidence.extend(analyze_trace(
        trace,
        canary_file_types=canary_file_types,
        allowed_write_prefixes=allowed_write,
        init_done_ts=init_done_ts,
    ))
    connects = [
        {"addr": c["addr"], "port": c["port"], "result": c["result"]}
        for c in trace.connects
    ]

    verdict = compute_verdict(evidence)
    exit_code = exit_code_for(verdict, fail_on)

    result = ScanResult(
        run_id=run_id, started_ts=started, finished_ts=finished,
        spec=spec, backend_name=backend_obj.name,
        canary_manifest=manifest, tools=tools,
        network_requests=network_requests, connects=connects,
        evidence=evidence, verdict=verdict, exit_code=exit_code,
        run_error=run_error,
    )
    if out_dir:
        write_reports(result, out_dir)
        net_src = proxy_log
        if os.path.isfile(net_src):
            shutil.copyfile(net_src, os.path.join(out_dir, "network.jsonl"))
    if keep_sandbox or os.environ.get("AGENTLURE_KEEP_RUN"):
        result.run_root = run_root
    else:
        shutil.rmtree(run_root, ignore_errors=True)
        result.run_root = None
    return result
