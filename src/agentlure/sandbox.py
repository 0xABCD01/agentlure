"""Sandbox backends.

The scanner refuses to run a target without a working sandbox backend.
Backends are auto-detected in this order: docker, podman, namespace.

- docker / podman: builds a hardened `run` invocation (read-only root,
  --cap-drop ALL, no-new-privileges, memory/CPU/pids caps, --network
  none; the sinkhole proxy runs inside the container on its loopback via
  the same in-sandbox entry point, and the synthetic HOME / workdir /
  evidence dir are bind-mounted at identical paths). The image must
  contain Python 3, strace and agentlure itself (default image name
  ``agentlure-sandbox:latest``, override with --sandbox-image or the
  AGENTLURE_SANDBOX_IMAGE environment variable).

  NOTE: the container backends are implemented to the same interface as
  the namespace backend but are NOT exercised by the project's own test
  environment (no Docker/Podman daemon is available there). Treat them
  as untested in v0.1.

- namespace: Linux user+mount+PID+network namespaces via unshare. The
  target's HOME is the synthetic home directory, and the credential
  paths inside the real home (~/.aws, ~/.ssh, ~/.config/gh, ~/.env)
  are additionally bind-masked with the canary versions when they
  exist, so absolute-path reads hit canaries too. The network
  namespace contains loopback only (raised by the entry point), and
  the target is traced with strace. This backend is the one covered
  by the project's selftest. It does not hide the rest of the host
  filesystem; see README for the honest limits.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

DEFAULT_IMAGE = "agentlure-sandbox:latest"
ENTRY_MODULE = "agentlure._entry"


class SandboxError(Exception):
    pass


class Backend:
    def __init__(self, name, binary=None):
        self.name = name          # "docker" | "podman" | "namespace"
        self.binary = binary      # container runtime path, if any

    def __repr__(self):
        return "Backend(%s)" % self.name


def _container_ok(binary):
    if not binary:
        return False
    try:
        proc = subprocess.run(
            [binary, "info"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _image_present(binary, image):
    try:
        proc = subprocess.run(
            [binary, "image", "inspect", image], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=15,
        )
        return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _namespace_ok():
    if not shutil.which("unshare"):
        return False
    try:
        with open("/proc/sys/user/max_user_namespaces") as fh:
            return int(fh.read().strip()) > 0
    except (OSError, ValueError):
        return True  # knob absent on some kernels; unshare will tell us


def detect_backend(preferred="auto", image=None):
    """Return a Backend or raise SandboxError. Never returns None:
    without a sandbox the scanner must not run the target at all.

    A container backend counts as working only when the daemon answers
    AND the sandbox image is present locally. An absent image makes
    `docker run` fail instantly, which in v0.1.x silently degraded the
    scan (the target died before initialize and the empty evidence
    graded CLEAN). Auto-detection therefore skips a container runtime
    whose image is missing and falls through to the namespace backend;
    an explicitly requested container backend raises instead, with the
    exact command that builds the image."""
    image = image or os.environ.get("AGENTLURE_SANDBOX_IMAGE") or DEFAULT_IMAGE
    order = ["docker", "podman", "namespace"] if preferred == "auto" else [preferred]
    failures = []
    for name in order:
        if name in ("docker", "podman"):
            binary = shutil.which(name)
            if not binary or not _container_ok(binary):
                failures.append(name + " (runtime missing or daemon unreachable)")
                continue
            if _image_present(binary, image):
                return Backend(name, binary)
            if preferred == name:
                raise SandboxError(
                    "%s is available but the sandbox image %s is not present. "
                    "Build it from the agentlure repository checkout:\n"
                    "  docker build -f Dockerfile.sandbox -t %s .\n"
                    "or point AGENTLURE_SANDBOX_IMAGE / --sandbox-image at an "
                    "image that contains Python 3, strace and agentlure."
                    % (name, image, image))
            failures.append(
                name + " (sandbox image %s not present; skipping)" % image)
        elif name == "namespace":
            if _namespace_ok():
                return Backend("namespace")
            failures.append("namespace (unshare unavailable)")
        else:
            raise SandboxError("unknown sandbox backend: %s" % name)
    raise SandboxError(
        "no working sandbox backend found; refusing to run the target "
        "unsandboxed. Tried: " + "; ".join(failures)
    )


def build_launch(backend, *, home_backing, home_display, workdir, evidence_dir,
                 proxy_port, cpu_seconds, target_argv, image=None,
                 env_passthrough=(), mask_pairs=()):
    """Return the argv that runs the in-sandbox entry point, which in
    turn launches target_argv. The returned process's stdin/stdout are
    the target's MCP stdio channel."""
    entry_args = [
        "--home-backing", home_backing,
        "--home-display", home_display,
        "--workdir", workdir,
        "--evidence-dir", evidence_dir,
        "--proxy-port", str(proxy_port),
        "--cpu-seconds", str(cpu_seconds),
    ]
    if backend.name == "namespace":
        mask_args = []
        for backing, display in mask_pairs:
            mask_args += ["--mask-pair", "%s=%s" % (backing, display)]
        return [
            "unshare", "-Urmpfn", "--kill-child",
            sys.executable, "-m", ENTRY_MODULE, "--mode", "namespace",
        ] + entry_args + mask_args + ["--"] + list(target_argv)
    if backend.name in ("docker", "podman"):
        image = image or os.environ.get("AGENTLURE_SANDBOX_IMAGE") or DEFAULT_IMAGE
        cmd = [
            backend.binary, "run", "--rm", "-i",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", "256m",
            "--cpus", "0.5",
            "--pids-limit", "128",
            "--network", "none",
            "--tmpfs", "/tmp:rw,size=64m,mode=1777",
            "-v", "%s:%s" % (home_backing, home_backing),
            "-v", "%s:%s" % (workdir, workdir),
            "-v", "%s:%s" % (evidence_dir, evidence_dir),
            # Pass through the variables the entry point and target need.
            "-e", "AGENTLURE_CANARY_MANIFEST",
            "-e", "PYTHONDONTWRITEBYTECODE",
        ] + [item for name in env_passthrough for item in ("-e", name)] + [
            image,
            "python3", "-m", ENTRY_MODULE, "--mode", "container",
        ] + entry_args + ["--"] + list(target_argv)
        return cmd
    raise SandboxError("unknown sandbox backend: %s" % backend.name)
