"""Passive checks on tool metadata and detectors for tool output."""
from __future__ import annotations

from typing import Any, Iterable

from .findings import Finding, snippet
from .rules import HIDDEN_CHARS, INJECTION, RISKY_NAMES, RISKY_PARAM, SECRETS, redact


def metadata_text(tool: dict[str, Any]) -> list[tuple[str, str]]:
    """Every string a model reads about a tool, labelled by where it came from."""
    out: list[tuple[str, str]] = []
    for k in ("name", "title", "description"):
        if isinstance(tool.get(k), str):
            out.append((k, tool[k]))
    schema = tool.get("inputSchema")
    if isinstance(schema, dict):
        for pname, p in (schema.get("properties") or {}).items():
            if isinstance(p, dict):
                if isinstance(p.get("description"), str):
                    out.append((f"parameter {pname}", p["description"]))
                for v in p.get("enum", []) or []:
                    if isinstance(v, str):
                        out.append((f"parameter {pname} enum", v))
    return out


def scan_injection(tool: str, where: str, text: str, code: str, title: str) -> list[Finding]:
    """One finding per text, listing every pattern that matched."""
    hits = [(label, m) for label, rx in INJECTION if (m := rx.search(text))]
    if not hits:
        return []
    first = min((m for _, m in hits), key=lambda m: m.start())
    return [Finding(code, "high", title, tool, f"{where}: " + ", ".join(label for label, _ in hits), snippet(text, first.start(), first.end()))]


def static_checks(tools: list[dict[str, Any]]) -> list[Finding]:
    fs: list[Finding] = []
    seen: dict[str, int] = {}
    for t in tools:
        name = str(t.get("name", "?"))
        seen[name] = seen.get(name, 0) + 1
        for where, text in metadata_text(t):
            fs += scan_injection(name, where, text, "TP-001", "Tool metadata contains an instruction aimed at the model (tool poisoning)")
            m = HIDDEN_CHARS.search(text)
            if m:
                fs.append(Finding("TP-002", "high", "Invisible characters in tool metadata", name, f"{where} contains U+{ord(m.group()):04X}, which a human reviewer cannot see but a model reads", snippet(text, m.start(), m.end())))
        if RISKY_NAMES.search(name):
            fs.append(Finding("CAP-001", "medium", "High-risk capability exposed as a tool", name, "Tool names suggest command execution, deletion or system change. Require confirmation, an allowlist and least privilege."))
        schema = t.get("inputSchema")
        if not isinstance(schema, dict) or not schema:
            fs.append(Finding("SC-001", "low", "Tool has no input schema", name, "Without a schema nothing constrains what a model can pass."))
            continue
        props = schema.get("properties") or {}
        for pname, p in props.items():
            if not isinstance(p, dict):
                continue
            kinds = p.get("type")
            is_str = kinds == "string" or (isinstance(kinds, list) and "string" in kinds)
            constrained = any(k in p for k in ("enum", "pattern", "maxLength", "format", "const"))
            if is_str and RISKY_PARAM.search(pname) and not constrained:
                fs.append(Finding("SC-002", "low", "Unconstrained string parameter on a sensitive-looking name", name, f"Parameter '{pname}' has no enum, pattern, format or maxLength."))
            if "type" not in p and "enum" not in p and "$ref" not in p and "anyOf" not in p and "oneOf" not in p:
                fs.append(Finding("SC-004", "low", "Parameter has no declared type", name, f"Parameter '{pname}' accepts any JSON value."))
        if schema.get("additionalProperties") is not False and props:
            fs.append(Finding("SC-003", "info", "Schema accepts undeclared properties", name, "Set additionalProperties to false so unexpected arguments are rejected."))
    for n, c in seen.items():
        if c > 1:
            fs.append(Finding("TP-003", "medium", "Duplicate tool name", n, f"The name appears {c} times in tools/list, so one can shadow the other."))
    return fs


def redact_all(text: str) -> str:
    for _, rx, _ in SECRETS:
        text = rx.sub(lambda m: redact(m.group()), text)
    return text


def scan_output(tool: str, text: str, payload: str = "") -> list[Finding]:
    """Look for secrets and for instructions aimed at the model inside a tool result. Evidence never contains a full secret."""
    fs: list[Finding] = []
    safe = redact_all(text)
    for label, rx, sev in SECRETS:
        m = rx.search(text)
        if m:
            red = redact(m.group())
            i = safe.find(red)
            fs.append(Finding("SEC-001", sev, "Tool result contains a secret", tool, f"{label} in the output", snippet(safe, max(i, 0), max(i, 0) + len(red)), payload))
    fs += [Finding(f.code, f.severity, f.title, f.tool, f.detail, redact_all(f.evidence), payload) for f in scan_injection(tool, "tool result", text, "INJ-001", "Tool result contains an instruction aimed at the model (indirect prompt injection)")]
    return fs


def dedupe(fs: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[Finding] = []
    for f in fs:
        k = (*f.key(), f.detail)
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out
