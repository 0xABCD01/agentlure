"""Report writers: terminal summary, report.json, report.sarif, report.html.

Reports carry masked canary values only - never the full secrets.
"""

from __future__ import annotations

import html
import json
import os

from . import __version__
from .evidence import CANARY_EGRESS, CANARY_READ, UNEXPECTED_SPAWN, WRITE_OUTSIDE

_RULES = [
    (CANARY_EGRESS, "Canary value in egress payload",
     "A planted canary credential value was found in a network payload captured by the sinkhole proxy.",
     "error"),
    (CANARY_READ, "Canary file read",
     "The target opened a planted canary credential file for reading.",
     "warning"),
    (UNEXPECTED_SPAWN, "Unexpected process spawn",
     "The target executed a network or shell tool outside its launch chain.",
     "warning"),
    (WRITE_OUTSIDE, "Write outside workdir",
     "The target wrote, created or deleted a file outside its workdir and outside the synthetic HOME.",
     "warning"),
]
_RULE_LEVEL = {rule_id: level for rule_id, _n, _d, level in _RULES}


def write_json(result, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, indent=2)
        fh.write("\n")


def write_sarif(result, path):
    rules = []
    for rule_id, name, desc, level in _RULES:
        rules.append({
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": name},
            "fullDescription": {"text": desc},
            "defaultConfiguration": {"level": level},
        })
    results = []
    for ev in result.evidence:
        location = {"physicalLocation": {"artifactLocation": {
            "uri": ev.get("path") or ev.get("url") or "stdio"}}}
        results.append({
            "ruleId": ev["class"],
            "level": _RULE_LEVEL.get(ev["class"], "warning"),
            "message": {"text": ev["detail"]},
            "locations": [location],
            "properties": {
                k: ev[k] for k in ("canary_type", "encoding", "where", "method")
                if ev.get(k) is not None
            },
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agentlure",
                "version": __version__,
                "informationUri": "https://github.com/0xABCD01/agentlure",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2)
        fh.write("\n")


_CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem auto;max-width:960px;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.5rem} table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #ccc;padding:.4rem .6rem;text-align:left;vertical-align:top;font-size:.92rem}
th{background:#f2f2f2} code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.88em;word-break:break-all}
.verdict{padding:1rem 1.2rem;border-radius:8px;font-size:1.3rem;font-weight:700;color:#fff}
.MALICIOUS{background:#b3261e}.SUSPICIOUS{background:#b26a00}.CLEAN{background:#1e7d32}.ERROR{background:#444}
.meta{color:#555;font-size:.9rem} .none{color:#666}
"""


def write_html(result, path):
    d = result.to_dict()
    esc = html.escape
    parts = []
    parts.append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    parts.append("<title>agentlure report - %s</title><style>%s</style></head><body>"
                 % (esc(d["verdict"]), _CSS))
    parts.append("<h1>agentlure scan report</h1>")
    parts.append("<div class=\"verdict %s\">%s</div>" % (esc(d["verdict"]), esc(d["verdict"])))
    parts.append("<p class=\"meta\">Target: <code>%s</code><br>Sandbox backend: %s<br>"
                 "Started: %s<br>Finished: %s<br>Exit code: %d</p>"
                 % (esc(d["target"]["label"]), esc(d["sandbox"]["backend"]),
                    esc(d["started_at"]), esc(d["finished_at"]), d["exit_code"]))
    if d.get("run_error"):
        parts.append("<p><strong>Run note:</strong> %s</p>" % esc(d["run_error"]))

    parts.append("<h2>Evidence</h2>")
    if d["evidence"]:
        parts.append("<table><tr><th>Class</th><th>Detail</th></tr>")
        for ev in d["evidence"]:
            parts.append("<tr><td><code>%s</code></td><td>%s</td></tr>"
                         % (esc(ev["class"]), esc(ev["detail"])))
        parts.append("</table>")
    else:
        parts.append("<p class=\"none\">No evidence recorded.</p>")

    parts.append("<h2>Tools called</h2>")
    if d["tools"]:
        parts.append("<table><tr><th>Tool</th><th>Synthetic arguments</th><th>Outcome</th></tr>")
        for tool in d["tools"]:
            parts.append("<tr><td><code>%s</code></td><td><code>%s</code></td><td>%s</td></tr>"
                         % (esc(tool["name"]),
                            esc(json.dumps(tool.get("arguments", {}))),
                            esc(tool.get("outcome", ""))))
        parts.append("</table>")
    else:
        parts.append("<p class=\"none\">No tools were listed.</p>")

    parts.append("<h2>Network requests (sinkhole)</h2>")
    if d["network_requests"]:
        parts.append("<table><tr><th>Method</th><th>URL</th><th>Body bytes</th><th>Canary hits</th></tr>")
        for req in d["network_requests"]:
            hits = ", ".join(
                "%s (%s)" % (h["canary_type"], h["encoding"]) for h in req["hits"]) or "-"
            parts.append("<tr><td>%s</td><td><code>%s</code></td><td>%d</td><td>%s</td></tr>"
                         % (esc(req["method"] or ""), esc(req["url"] or ""),
                            req["body_len"], esc(hits)))
        parts.append("</table>")
    else:
        parts.append("<p class=\"none\">No network requests captured.</p>")

    parts.append("<h2>Canaries planted</h2><table><tr><th>Type</th><th>Files</th><th>Values (masked)</th></tr>")
    for canary in d["canaries"]:
        files = "<br>".join(esc(f["sandbox_path"]) for f in canary["files"])
        vals = "<br>".join(esc(v) for v in canary["values_masked"])
        parts.append("<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td></tr>"
                     % (esc(canary["type"]), files, vals))
    parts.append("</table>")
    parts.append("<p class=\"meta\">Generated by agentlure %s. Verdicts are deterministic: "
                 "canary egress = MALICIOUS; canary read, unexpected spawn or write outside "
                 "workdir = SUSPICIOUS; otherwise CLEAN.</p>" % esc(__version__))
    parts.append("</body></html>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))


def terminal_summary(result):
    d = result.to_dict()
    lines = []
    lines.append("target:  %s" % d["target"]["label"])
    lines.append("sandbox: %s" % d["sandbox"]["backend"])
    tools = d["tools"]
    called = sum(1 for t in tools if t.get("outcome") == "ok")
    lines.append("tools:   %d listed, %d called ok" % (len(tools), called))
    lines.append("network: %d request(s) captured by the sinkhole" % len(d["network_requests"]))
    if d.get("run_error"):
        lines.append("note:    %s" % d["run_error"])
    if d["evidence"]:
        lines.append("evidence:")
        for ev in d["evidence"]:
            lines.append("  [%s] %s" % (ev["class"], ev["detail"]))
    lines.append("VERDICT: %s (exit %d)" % (d["verdict"], d["exit_code"]))
    return "\n".join(lines)


def write_reports(result, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    paths = {
        "json": os.path.join(out_dir, "report.json"),
        "sarif": os.path.join(out_dir, "report.sarif"),
        "html": os.path.join(out_dir, "report.html"),
    }
    write_json(result, paths["json"])
    write_sarif(result, paths["sarif"])
    write_html(result, paths["html"])
    return paths
