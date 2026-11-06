"""Parse strace -f -ff -tt output into process/file/network events.

The in-sandbox entry point runs the target under
``strace -ff -o <dir>/trace`` so each traced process gets its own file
``trace.<pid>``. This module reconstructs:

- the process tree (from clone/fork/vfork return values),
- execve events (image path per pid, in order),
- file events (openat/open/creat and path-mutating calls) with paths
  resolved against a per-pid cwd tracked from chdir calls,
- connect() attempts to INET addresses (observations, not graded).
"""

from __future__ import annotations

import os
import posixpath
import re
from datetime import datetime

_TIME_RE = re.compile(r"^(\d{2}):(\d{2}):(\d{2})\.(\d+)\s+(.*)$")
_CALL_RE = re.compile(r"^([a-z_0-9]+)\((.*)\)\s*=\s*(-?\d+)")
_CALL_LOOSE_RE = re.compile(r"^([a-z_0-9]+)\((.*)\)\s*=\s*")
_EXECVE_RE = re.compile(r'^execve\("((?:[^"\\]|\\.)*)"')
_OPENAT_RE = re.compile(r'^openat\(([^,]+),\s*"((?:[^"\\]|\\.)*)",\s*(.*)$')
_PATHARG_RE = re.compile(r'^(?:[^,]+,\s*)?"((?:[^"\\]|\\.)*)"')
_CONNECT_ADDR_RE = re.compile(r'inet_addr\("([\d.]+)"\)')
_CONNECT_PORT_RE = re.compile(r"htons\((\d+)\)")
_OCTAL_RE = re.compile(r"\\([0-7]{1,3})")


def _unescape(text):
    def repl(match):
        return chr(int(match.group(1), 8))
    text = _OCTAL_RE.sub(repl, text)
    return text.replace('\\"', '"').replace("\\\\", "\\")


class TraceData:
    def __init__(self):
        self.execs = []          # {pid, ts, path, basename, seq}
        self.file_events = []    # {pid, ts, syscall, path, resolved, flags, result, write}
        self.connects = []       # {pid, ts, addr, port, result}
        self.parents = {}        # child pid -> parent pid
        self.root_pid = None
        self.first_exec = {}     # pid -> first exec event

    def descendants(self, pid):
        out = set()
        frontier = [pid]
        while frontier:
            current = frontier.pop()
            for child, parent in self.parents.items():
                if parent == current and child not in out:
                    out.add(child)
                    frontier.append(child)
        return out

    def reaches_root(self, pid, root):
        seen = set()
        current = pid
        while current is not None and current not in seen:
            if current == root:
                return True
            seen.add(current)
            current = self.parents.get(current)
        return False


_WRITE_FLAG_TOKENS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
_PATH_CALLS = {"open", "creat", "unlink", "mkdir"}
_PATH_CALLS_DIRFD = {"openat", "unlinkat", "mkdirat", "renameat"}
_RENAME_OLD = re.compile(r'^(?:[^,]+,\s*)?"((?:[^"\\]|\\.)*)",\s*"((?:[^"\\]|\\.)*)"')
_RENAMEAT_RE = re.compile(
    r'^[^,]+,\s*"((?:[^"\\]|\\.)*)",\s*[^,]+,\s*"((?:[^"\\]|\\.)*)"')


def _parse_file(path, pid, data, workdir, base_date):
    cwd = {pid: workdir}
    pending = {}  # syscall -> partial text for <unfinished ...> stitching
    seq = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\n")
            m = _TIME_RE.match(line)
            if not m:
                continue
            hh, mm, ss, frac, rest = m.groups()
            ts = datetime(
                base_date.year, base_date.month, base_date.day,
                int(hh), int(mm), int(ss),
                tzinfo=base_date.tzinfo,
            ).timestamp() + int((frac + "000000")[:6]) / 1e6
            if rest.endswith("<unfinished ...>"):
                name = rest.split("(", 1)[0]
                pending[name] = rest[: -len("<unfinished ...>")]
                continue
            if rest.startswith("<... "):
                resumed = re.match(r"^<\.\.\. ([a-z_0-9]+) resumed>(.*)$", rest)
                if not resumed:
                    continue
                name, tail = resumed.groups()
                rest = pending.pop(name, name + "(") + tail
            call = _CALL_RE.match(rest)
            if call:
                name, argstr, result_s = call.groups()
                result = int(result_s)
            else:
                loose = _CALL_LOOSE_RE.match(rest)
                if not loose:
                    continue
                name, argstr = loose.groups()
                result = None
            seq += 1
            if name in ("clone", "clone3", "fork", "vfork"):
                if result and result > 0:
                    data.parents[result] = pid
                    cwd[result] = cwd.get(pid, workdir)
                continue
            if name == "chdir":
                pm = _PATHARG_RE.match(argstr)
                if pm and result == 0:
                    p = _unescape(pm.group(1))
                    cwd[pid] = p if p.startswith("/") else posixpath.normpath(
                        posixpath.join(cwd.get(pid, workdir), p))
                continue
            if name == "execve":
                em = _EXECVE_RE.match(rest)
                if em:
                    p = _unescape(em.group(1))
                    ev = {
                        "pid": pid, "ts": ts, "path": p,
                        "basename": posixpath.basename(p), "seq": seq,
                        "result": result,
                    }
                    data.execs.append(ev)
                    if pid not in data.first_exec:
                        data.first_exec[pid] = ev
                continue
            if name == "connect":
                am = _CONNECT_ADDR_RE.search(argstr)
                if am:
                    pm = _CONNECT_PORT_RE.search(argstr)
                    data.connects.append({
                        "pid": pid, "ts": ts, "addr": am.group(1),
                        "port": int(pm.group(1)) if pm else None,
                        "result": result,
                    })
                continue
            if name == "openat" or name in _PATH_CALLS or name in _PATH_CALLS_DIRFD \
                    or name in ("open", "rename"):
                _parse_path_call(data, name, argstr, result, pid, ts,
                                 cwd.get(pid, workdir))


def _parse_path_call(data, name, argstr, result, pid, ts, cwd):
    flags = ""
    paths = []
    write = False
    if name == "openat":
        m = _OPENAT_RE.match("openat(" + argstr)
        if not m:
            return
        _dirfd, p, flagstr = m.groups()
        paths = [_unescape(p)]
        flags = flagstr.split(")")[0].split(",")[0]
        write = any(tok in flags for tok in _WRITE_FLAG_TOKENS)
    elif name in ("open", "creat", "unlink", "mkdir"):
        m = _PATHARG_RE.match(argstr)
        if not m:
            return
        paths = [_unescape(m.group(1))]
        rest = argstr[m.end():]
        flags = rest.split(",")[0] if name == "open" else ""
        write = name != "unlink" and (
            name in ("creat", "mkdir") or any(tok in flags for tok in _WRITE_FLAG_TOKENS))
        if name in ("unlink", "mkdir"):
            write = True
    elif name in ("unlinkat", "mkdirat", "renameat"):
        if name == "renameat":
            m = _RENAMEAT_RE.match(argstr)
            if not m:
                return
            paths = [_unescape(m.group(1)), _unescape(m.group(2))]
        else:
            rest = argstr.split(",", 1)[1].lstrip() if "," in argstr else argstr
            m = _PATHARG_RE.match(rest)
            if not m:
                return
            paths = [_unescape(m.group(1))]
        write = True
    elif name == "rename":
        m = _RENAME_OLD.match(argstr)
        if not m:
            return
        paths = [_unescape(g) for g in m.groups()]
        write = True
    else:
        return
    for p in paths:
        resolved = p if p.startswith("/") else posixpath.normpath(posixpath.join(cwd, p))
        data.file_events.append({
            "pid": pid, "ts": ts, "syscall": name, "path": p,
            "resolved": resolved, "flags": flags, "result": result,
            "write": write,
        })


def parse_trace_dir(trace_dir, workdir, base_date):
    """Parse all trace.<pid> files in trace_dir into a TraceData."""
    data = TraceData()
    if not os.path.isdir(trace_dir):
        return data
    files = []
    for name in os.listdir(trace_dir):
        if name.startswith("trace.") and name[6:].isdigit():
            files.append((int(name[6:]), os.path.join(trace_dir, name)))
    for pid, path in sorted(files):
        _parse_file(path, pid, data, workdir, base_date)
    data.execs.sort(key=lambda e: (e["ts"], e["pid"], e["seq"]))
    if files:
        child_pids = set(data.parents)
        roots = [pid for pid, _ in files if pid not in child_pids]
        data.root_pid = roots[0] if roots else files[0][0]
    return data
