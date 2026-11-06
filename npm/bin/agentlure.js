#!/usr/bin/env node
// Thin npm wrapper for agentlure. The scanner itself is a Python
// package (PyPI: agentlure). This shim delegates to, in order:
//   1. `uvx agentlure@0.1.0 ...`   (no install needed)
//   2. `python3 -m agentlure ...`  (when the package is importable)
//   3. printed install instructions + exit 1.
"use strict";

const { spawnSync, spawn } = require("child_process");

const VERSION = "0.1.0";
const args = process.argv.slice(2);

function has(cmd) {
  const probe = spawnSync(cmd, ["--version"], { stdio: "ignore" });
  return !probe.error;
}

function run(cmd, cmdArgs) {
  const child = spawn(cmd, cmdArgs, { stdio: "inherit" });
  child.on("error", () => process.exit(1));
  child.on("close", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code === null ? 1 : code);
    }
  });
}

if (has("uvx")) {
  run("uvx", ["agentlure@" + VERSION, ...args]);
} else if (
  spawnSync("python3", ["-c", "import agentlure"], { stdio: "ignore" }).status === 0
) {
  run("python3", ["-m", "agentlure", ...args]);
} else {
  console.error(
    "agentlure is a Python tool and neither `uvx` nor an installed " +
      "`agentlure` Python package was found.\n" +
      "Install one of:\n" +
      "  uv:   https://docs.astral.sh/uv/  (then re-run: npx agentlure ...)\n" +
      "  pip:  pip install agentlure     (then re-run: npx agentlure ...)"
  );
  process.exit(1);
}
