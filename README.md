# agentlure

Detonate MCP servers against fake credentials before you install them.

agentlure runs an untrusted MCP server inside a sandbox planted with
canary credentials and a sinkholed network, calls each of its tools
once, and reports what the server actually tried to read or send out.
The verdict is deterministic: no account, no LLM judge, no static
pattern matching.

## Quickstart

```sh
pip install agentlure
# or, with uv:
uvx agentlure scan --command "python3 path/to/server.py"

agentlure scan --config ~/.config/mcp.json --server my-server
agentlure scan --command "npx -y some-mcp-server"
```

Exit codes: `0` = CLEAN, `1` = SUSPICIOUS, `2` = MALICIOUS
(see `--fail-on` below for CI gating).

Requires Linux, Python 3.9+, and a sandbox backend: Docker, Podman, or
Linux namespaces (`unshare` + `strace`). agentlure refuses to run a
target when no sandbox backend is available.

## How a scan works

1. **Canaries are minted**, fresh for every run: an AWS key pair, a
   GitHub token, an npm token, an SSH key pair, and a `.env` bundle
   (database URL, Stripe key, SendGrid key). Each value has a
   recognizable prefix and a random suffix, so a captured payload
   attributes to exactly one run.
2. **A synthetic HOME is planted** with those canaries at the usual
   paths: `~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.env`,
   `~/.config/gh/hosts.yml`, `~/.npmrc`. The target's `HOME` points at
   the synthetic directory. Your real home is never the target's home.
3. **The target starts inside the sandbox** with no real network
   egress. Its only reachable endpoint is a sinkhole proxy on
   loopback, injected through the standard `HTTP_PROXY`/`HTTPS_PROXY`
   environment variables. The proxy logs every request and searches
   the payload — URL, headers, body — for canary values in raw,
   base64, hex, and URL-encoded form, including encoded-inside-encoded
   payloads (for example a base64'd file riding in a query string).
4. **agentlure drives the server over MCP** (stdio, JSON-RPC):
   `initialize`, `tools/list`, then one `tools/call` per tool with
   benign arguments synthesized from the tool's input schema (strings
   become `"hello"`, integers `1`, enums their first value, and so on).
5. **Behaviour is graded** from strace and proxy evidence, and reports
   are written: a terminal summary, `report.json`, `report.sarif`
   (SARIF 2.1.0), and a standalone `report.html`. Reports contain
   masked canary values only; the full proxy capture is kept in
   `network.jsonl` next to the reports.

## Evidence and verdicts

| Evidence | Meaning |
|---|---|
| `canary_egress` | A canary value was found in a payload captured by the sinkhole. |
| `canary_read` | The target opened a planted canary file. |
| `unexpected_spawn` | The target executed a network/shell tool (`curl`, `wget`, `nc`, `ncat`, `socat`, `bash`, `sh`) outside its launch chain. A shell that is itself the launched command, or a wrapper shell exec'd while the server was still starting, does not count. |
| `write_outside_workdir` | The target wrote, created, or deleted a file outside its sandbox workdir and outside the synthetic HOME. |

- **MALICIOUS** — any `canary_egress`.
- **SUSPICIOUS** — any of the other three classes, without egress.
- **CLEAN** — the detonation completed and produced no evidence.
- **ERROR** — the detonation itself failed (the target died, or the
  MCP handshake never completed), so the scan is inconclusive. ERROR
  exits 3 and never counts as a pass: a broken setup must not grade a
  server CLEAN.

Reading a canary is not proof of theft — a server may legitimately
look at its own configuration. Sending one out is. That is why only
egress grades MALICIOUS.

For CI, `--fail-on suspicious|malicious` turns the exit code into a
gate: the scan exits 0 when the verdict is below the chosen grade, and
with the grade code (1 or 2) at or above it. Without `--fail-on`, the
exit code is the grade code itself.

## Sandbox backends

Backends are auto-detected in this order: Docker, Podman, namespace.
`--backend` forces one. A container backend only counts as available
when its sandbox image is present locally; auto-detection skips a
runtime whose image is missing and falls through to the namespace
backend, because a `docker run` against a missing image kills the
target before the scan starts.

- **Docker / Podman** — `run` with a read-only root filesystem,
  `--cap-drop ALL`, `no-new-privileges`, memory/CPU/pids limits, and
  `--network none`; the sinkhole proxy runs inside the container on
  its loopback. The image (default `agentlure-sandbox:latest`,
  override with `--sandbox-image` or `AGENTLURE_SANDBOX_IMAGE`) must
  contain Python 3, strace, agentlure itself, and the runtime your
  target needs. Build it from the repository checkout:

  ```sh
  docker build -f Dockerfile.sandbox -t agentlure-sandbox:latest .
  ```

  **These backends are implemented to the same interface as the
  namespace backend but are not covered by the project's own tests**
  — the development environment has no container daemon. Prefer them
  for hostile targets once you have validated the image.
- **Namespace** — user + mount + PID + network namespaces via
  `unshare`. The target's `HOME` is the synthetic home; the
  credential-bearing paths of the real home (`~/.aws`, `~/.ssh`,
  `~/.config/gh`, `~/.env`) are additionally bind-masked with the
  canary versions when they exist, so absolute-path reads hit canaries
  too. The network namespace contains loopback only, with the sinkhole
  on it. The target is traced with `strace -f`. This backend is what
  `agentlure selftest` exercises.

## Self-safety model

agentlure exists to run hostile code, so the scanner treats itself as
part of the attack surface:

- The target never runs outside a sandbox backend; there is no
  `--no-sandbox` flag and there will not be one.
- Canary values are fake and minted per run. No real credential is
  ever planted, read, or passed into the sandbox. The canary manifest
  reaches the in-sandbox proxy through the environment and is scrubbed
  from the target's environment before launch.
- The network namespace has no route out; the sinkhole terminates
  every connection. CONNECT tunnels are logged and closed, never
  forwarded.
- Wall-clock timeouts, CPU rlimits, and process-group teardown bound
  every run.

Honest limits of the namespace backend: it redirects `HOME`, masks the
known credential paths, kills the network, and watches syscalls, but
it shares the host filesystem — a target that goes looking with
absolute paths can see (and, with your user's permissions, modify)
files outside the masked paths, and the PID namespace uses the host's
`/proc` when mounting a fresh one is not permitted. For code you
actively distrust, use a container backend or a throwaway VM.

## Limitations (v0.1)

- Linux only. Stdio MCP servers only — no remote/HTTP servers yet.
- Each tool is called once, with schema-derived arguments. Servers
  that misbehave only on specific argument values, on a second call,
  or after a delay longer than the observation window will not be
  caught by this version.
- A target that exfiltrates through a channel that ignores proxy
  environment variables gets no route out of the network namespace,
  so the attempt fails silently instead of producing evidence.
- Verdicts are evidence, not proof of intent: a SUSPICIOUS grade means
  "look at this", and the HTML report shows exactly what was observed.

## GitHub Action

```yaml
- uses: 0xABCD01/agentlure@v0.1.0
  with:
    config: mcp.json
    server: my-server
    fail-on: malicious
```

Inputs: `command` or `config` (+ `server`), `fail-on`, `version`.
Output: `verdict`. The full report is uploaded as a workflow artifact.

## npm wrapper

`npx agentlure ...` works through a thin Node shim (in `npm/`): it
delegates to `uvx agentlure@0.1.0` when uv is present, else to an
installed Python package (`python3 -m agentlure`), else it prints
install instructions. The scanner itself is the Python package.

## Selftest

The package ships six fixture servers (in `agentlure/fixtures/`) —
three malicious (SSH-key reader, `.env` exfiltrator, an email tool
with a silent BCC copy) and three benign (echo/calculator, a notes
server that stays in its workdir, a time client that makes one plain
HTTP request). From any install:

```sh
pip install agentlure
agentlure selftest        # expects MALICIOUS x3, CLEAN x3
```

From a source checkout, the unit tests run with
`python3 -m unittest discover`.

`selftest` runs every fixture through the real sandbox pipeline and
fails if any verdict differs from the expected one.

---

Created by [Hafiar](https://0xabcd01.github.io/) — bug hunter & pentester ([@0xABCD01](https://github.com/0xABCD01)).
