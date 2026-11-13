from __future__ import annotations

import json
from typing import Any

from .findings import Finding, sort_findings
from .rules import SEVERITIES
from .scanner import ScanResult, string_params


def _cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def counts(fs: list[Finding]) -> dict[str, int]:
    return {s: sum(1 for f in fs if f.severity == s) for s in reversed(SEVERITIES)}


def to_json(r: ScanResult) -> str:
    return json.dumps({"server": r.server, "active": r.active, "calls": r.calls, "notes": r.notes, "summary": counts(r.findings), "tools": [t.get("name") for t in r.tools], "findings": [f.to_dict() for f in sort_findings(r.findings)]}, indent=2)


def to_markdown(r: ScanResult) -> str:
    fs = sort_findings(r.findings)
    c = counts(fs)
    name = r.server.get("name", "unknown server") if isinstance(r.server, dict) else "unknown server"
    o: list[str] = [f"# MCP red team report: {name}", ""]
    o.append(f"- Mode: {'active (payloads sent, tools executed)' if r.active else 'passive (metadata only, no tool was called)'}")
    o.append(f"- Tools: {len(r.tools)}, tool calls made: {r.calls}")
    o.append(f"- Findings: {c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info")
    for n in r.notes:
        o.append(f"- Note: {n}")
    o.append("")
    if fs:
        o += ["## Findings", "", "| Severity | Code | Tool | Finding | Evidence |", "|---|---|---|---|---|"]
        for f in fs:
            ev = f"`{_cell(f.evidence)}`" if f.evidence else ""
            pl = f" (payload `{_cell(f.payload)}`)" if f.payload else ""
            o.append(f"| {f.severity} | {f.code} | {_cell(f.tool)} | {_cell(f.title)}: {_cell(f.detail)}{pl} | {ev} |")
        o.append("")
    else:
        o += ["## Findings", "", "None.", ""]
    o += ["## Tool inventory", "", "| Tool | String parameters | Description |", "|---|---|---|"]
    for t in r.tools:
        d = str(t.get("description", "")).strip().splitlines()[0:1]
        o.append(f"| {_cell(str(t.get('name')))} | {_cell(', '.join(string_params(t)) or '-')} | {_cell((d[0] if d else '')[:100])} |")
    o += ["", "> A clean report is not proof of safety: the probes are a fixed set of canary payloads. Only scan servers you own or are authorised to test.", ""]
    return "\n".join(o)


def to_text(r: ScanResult) -> str:
    """Compact terminal output: one line per finding."""
    fs = sort_findings(r.findings)
    c = counts(fs)
    name = r.server.get("name", "server") if isinstance(r.server, dict) else "server"
    o = [f"{name}: {len(r.tools)} tools, {r.calls} tool calls ({'active' if r.active else 'passive'})", f"{c['high']} high  {c['medium']} medium  {c['low']} low  {c['info']} info", ""]
    for f in fs:
        if f.severity == "info":
            continue
        extra = f"  payload: {f.payload}" if f.payload else ""
        o.append(f"[{f.severity.upper():6}] {f.code:9} {f.tool:14} {f.title}{extra}")
    if c["info"]:
        o.append(f"({c['info']} info findings hidden, use --format md)")
    return "\n".join(o) + "\n"
