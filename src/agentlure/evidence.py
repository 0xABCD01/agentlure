"""Evidence model and the deterministic verdict.

Evidence classes (no LLM anywhere in this path):

- canary_egress: a canary value was found in a payload captured by the
  sinkhole proxy. -> MALICIOUS
- canary_read: the target opened a planted canary file for reading.
- unexpected_spawn: the target executed a network/shell tool (curl,
  wget, nc, ncat, socat, bash, sh) outside the launch chain.
- write_outside_workdir: the target wrote/created/deleted a file
  outside its workdir and outside the synthetic HOME.

Verdicts: MALICIOUS if any canary_egress; else SUSPICIOUS if any of the
other classes fired; else CLEAN. Exit codes: CLEAN 0, SUSPICIOUS 1,
MALICIOUS 2 (see exit_code_for for --fail-on semantics).
"""

from __future__ import annotations

import posixpath

CANARY_READ = "canary_read"
CANARY_EGRESS = "canary_egress"
UNEXPECTED_SPAWN = "unexpected_spawn"
WRITE_OUTSIDE = "write_outside_workdir"

ALL_CLASSES = [CANARY_EGRESS, CANARY_READ, UNEXPECTED_SPAWN, WRITE_OUTSIDE]

WATCHLIST = {"curl", "wget", "nc", "ncat", "socat", "bash", "sh"}
SHELL_WRAPPERS = {"sh", "bash"}

GRADES = ["CLEAN", "SUSPICIOUS", "MALICIOUS"]
_GRADE_CODE = {"CLEAN": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}

# Prefixes a target may always write to: device files and kernel
# filesystems are not evidence.
_NEVER_FLAG_PREFIXES = ("/proc/", "/sys/", "/dev/")


def grade_of(verdict):
    return _GRADE_CODE[verdict]


def compute_verdict(evidence):
    classes = {e["class"] for e in evidence}
    if CANARY_EGRESS in classes:
        return "MALICIOUS"
    if classes & {CANARY_READ, UNEXPECTED_SPAWN, WRITE_OUTSIDE}:
        return "SUSPICIOUS"
    return "CLEAN"


def exit_code_for(verdict, fail_on=None):
    """Default: the exit code IS the grade code (0/1/2). With
    --fail-on T, the scan exits 0 when the verdict is below T and with
    the grade code otherwise, so CI can choose its own gate."""
    code = _GRADE_CODE[verdict]
    if fail_on is None:
        return code
    threshold = {"suspicious": 1, "malicious": 2}[fail_on]
    return code if code >= threshold else 0


def _under(path, prefixes):
    for prefix in prefixes:
        prefix = prefix.rstrip("/")
        if path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def analyze_trace(trace, *, canary_file_types, allowed_write_prefixes,
                  init_done_ts):
    """Turn parsed strace data into evidence entries.

    canary_file_types: {absolute_path: canary_type} for both the sandbox
    (bind-mounted) spelling and the backing spelling of each planted file.
    """
    evidence = []

    # --- process spawns -------------------------------------------------
    root = trace.root_pid
    root_first = trace.first_exec.get(root) if root is not None else None
    seen_spawns = set()
    for ev in trace.execs:
        base = ev["basename"]
        if base not in WATCHLIST:
            continue
        if ev.get("result") is not None and ev["result"] < 0:
            continue  # a failed execve (e.g. PATH probing) executed nothing
        if (base, ev["path"]) in seen_spawns:
            continue
        seen_spawns.add((base, ev["path"]))
        if root_first is not None and ev is root_first:
            continue  # the launched command itself (e.g. `sh -c ...`)
        if (
            init_done_ts is not None
            and ev["ts"] <= init_done_ts
            and base in SHELL_WRAPPERS
            and trace.first_exec.get(ev["pid"]) is ev
            and root is not None
            and trace.reaches_root(ev["pid"], root)
        ):
            # A shell wrapper exec'd while the launch chain was still
            # starting the server (the npx/sh -c pattern). Not evidence.
            continue
        evidence.append({
            "class": UNEXPECTED_SPAWN,
            "detail": "executed %s (%s)" % (base, ev["path"]),
            "path": ev["path"],
            "pid": ev["pid"],
            "ts": ev["ts"],
        })

    # --- file events ----------------------------------------------------
    seen_reads = set()
    seen_writes = set()
    for fe in trace.file_events:
        resolved = posixpath.normpath(fe["resolved"])
        if fe["result"] is not None and fe["result"] < 0:
            continue
        ctype = canary_file_types.get(resolved)
        if ctype and not fe["write"]:
            key = (resolved, ctype)
            if key not in seen_reads:
                seen_reads.add(key)
                evidence.append({
                    "class": CANARY_READ,
                    "detail": "read planted %s canary file %s" % (ctype, resolved),
                    "path": resolved,
                    "canary_type": ctype,
                    "pid": fe["pid"],
                    "ts": fe["ts"],
                })
            continue
        if fe["write"]:
            if _under(resolved, _NEVER_FLAG_PREFIXES):
                continue
            if _under(resolved, allowed_write_prefixes):
                continue
            if resolved in canary_file_types:
                continue  # writing over a canary file inside HOME: HOME is allowed
            if resolved not in seen_writes:
                seen_writes.add(resolved)
                evidence.append({
                    "class": WRITE_OUTSIDE,
                    "detail": "%s wrote outside workdir/HOME: %s" % (fe["syscall"], resolved),
                    "path": resolved,
                    "pid": fe["pid"],
                    "ts": fe["ts"],
                })
    return evidence


def _short_url(url, limit=240):
    """URLs in reports are truncated: an exfiltrating GET puts the whole
    payload in the URL, and reports are meant to be shareable. The full
    capture stays in the proxy log (network.jsonl)."""
    if url is None or len(url) <= limit:
        return url
    return url[:limit] + "…"


def analyze_proxy(records, masked_values):
    """Turn sinkhole proxy log records into canary_egress evidence.

    masked_values: {canary_type: [masked forms]} aligned by index with
    the hit's value_index, so reports never carry full canary values.
    """
    evidence = []
    requests = []
    seen_egress = set()
    for record in records:
        hits = record.get("hits") or []
        requests.append({
            "ts": record.get("ts"),
            "kind": record.get("kind"),
            "method": record.get("method"),
            "url": _short_url(record.get("url")),
            "body_len": record.get("body_len", 0),
            "hits": [
                {"canary_type": h["canary_type"], "encoding": h["encoding"],
                 "where": h.get("where")}
                for h in hits
            ],
        })
        for hit in hits:
            dedupe_key = (hit["canary_type"], record.get("method"),
                          record.get("url"), hit.get("where"))
            if dedupe_key in seen_egress:
                continue
            seen_egress.add(dedupe_key)
            masked_list = masked_values.get(hit["canary_type"]) or []
            idx = hit.get("value_index", 0)
            masked = masked_list[idx] if idx < len(masked_list) else "***"
            evidence.append({
                "class": CANARY_EGRESS,
                "detail": "%s canary value (%s) found %s in %s %s payload (%s encoding)"
                          % (hit["canary_type"], masked, hit.get("where", "?"),
                             record.get("method", "?"),
                             _short_url(record.get("url", "?")),
                             hit["encoding"]),
                "canary_type": hit["canary_type"],
                "encoding": hit["encoding"],
                "where": hit.get("where"),
                "url": record.get("url"),
                "method": record.get("method"),
                "ts": record.get("ts"),
            })
    return evidence, requests
