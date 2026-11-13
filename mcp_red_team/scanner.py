"""Orchestrates a scan: passive checks always, active probing only when asked."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from .checks import dedupe, scan_output, static_checks
from .client import McpClient, ServerDied, Timeout, response_text
from .findings import Finding, snippet
from .rules import CATEGORIES, EVIDENCE


class ScanError(Exception):
    pass


@dataclass
class ScanResult:
    command: list[str]
    server: dict[str, Any]
    tools: list[dict[str, Any]]
    findings: list[Finding]
    active: bool
    calls: int = 0
    notes: list[str] = field(default_factory=list)


def _types(p: dict[str, Any]) -> list[str]:
    t = p.get("type")
    return [t] if isinstance(t, str) else [x for x in t if isinstance(x, str)] if isinstance(t, list) else []


def benign_args(tool: dict[str, Any]) -> dict[str, Any]:
    schema = tool.get("inputSchema") or {}
    props = schema.get("properties") or {}
    args: dict[str, Any] = {}
    for name in schema.get("required", []) or []:
        p = props.get(name) or {}
        if "enum" in p and p["enum"]:
            args[name] = p["enum"][0]
            continue
        ts = _types(p)
        if "string" in ts or not ts:
            args[name] = "a" * max(1, int(p.get("minLength", 4) or 4))
        elif "integer" in ts or "number" in ts:
            args[name] = max(1, int(p.get("minimum", 1) or 1))
        elif "boolean" in ts:
            args[name] = False
        elif "array" in ts:
            args[name] = []
        else:
            args[name] = {}
    return args


def string_params(tool: dict[str, Any]) -> list[str]:
    props = (tool.get("inputSchema") or {}).get("properties") or {}
    return [n for n, p in props.items() if isinstance(p, dict) and "string" in (_types(p) or ["string"])]


def categories_for(param: str) -> list[str]:
    hit = [code for code, (_, _, rx) in CATEGORIES.items() if rx.search(param)]
    return hit or list(CATEGORIES)  # unknown name: try every category, one payload each is cheap


def _canon(tool: dict[str, Any]) -> str:
    return json.dumps({"description": tool.get("description"), "inputSchema": tool.get("inputSchema"), "title": tool.get("title")}, sort_keys=True)


class Scanner:
    def __init__(self, cmd: list[str], active: bool = False, timeout: float = 5.0, skip: tuple[str, ...] = (), only: tuple[str, ...] = (), max_calls: int = 300) -> None:
        self.cmd, self.active, self.timeout, self.skip, self.only, self.max_calls = cmd, active, timeout, set(skip), set(only), max_calls
        self.client: Optional[McpClient] = None
        self.findings: list[Finding] = []
        self.calls = 0
        self.notes: list[str] = []
        self._hung: set[str] = set()

    # -- connection
    def _connect(self) -> dict[str, Any]:
        c = McpClient(self.cmd, timeout=self.timeout)
        try:
            c.start()
            info = c.initialize()
        except (ServerDied, Timeout, OSError, RuntimeError) as e:
            c.close()
            raise ScanError(f"could not start or initialise the server: {e or type(e).__name__}") from e
        self.client = c
        return info

    def _reconnect(self) -> bool:
        if self.client:
            self.client.close()
        try:
            self._connect()
            return True
        except ScanError:
            return False

    def _selected(self, tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [t for t in tools if str(t.get("name")) not in self.skip and (not self.only or str(t.get("name")) in self.only)]

    # -- one call with crash and hang handling
    def _call(self, tool: str, args: dict[str, Any], payload: str = "") -> Optional[dict[str, Any]]:
        assert self.client
        if self.calls >= self.max_calls:
            return None
        self.calls += 1
        try:
            return self.client.call(tool, args)
        except Timeout:
            if tool not in self._hung:
                self._hung.add(tool)
                self.findings.append(Finding("DOS-001", "medium", "Tool call hung", tool, f"No response within {self.timeout:g}s. A model can stall the agent with one crafted argument.", payload=payload))
            self._reconnect()
        except ServerDied:
            self.findings.append(Finding("DOS-002", "high", "Server crashed on a tool call", tool, "The server process exited while handling the call.", payload=payload))
            self._reconnect()
        return None

    # -- probes
    def _benign(self, tools: list[dict[str, Any]]) -> None:
        for t in self._selected(tools):
            name = str(t["name"])
            r = self._call(name, benign_args(t))
            if r is not None:
                self.findings += scan_output(name, response_text(r))

    def _payloads(self, tools: list[dict[str, Any]]) -> None:
        for t in self._selected(tools):
            name = str(t["name"])
            base = benign_args(t)
            for param in string_params(t):
                for cat in categories_for(param):
                    title, payloads, _ = CATEGORIES[cat]
                    for pl in payloads:
                        if self.calls >= self.max_calls:
                            self.notes.append(f"call budget of {self.max_calls} reached, some probes were skipped")
                            return
                        r = self._call(name, {**base, param: pl.value}, pl.value)
                        if r is None:
                            continue
                        text = response_text(r)
                        m = EVIDENCE[cat].search(text)
                        if m:
                            self.findings.append(Finding(f"{cat}-001", "high", f"{title} succeeded", name, f"Parameter '{param}' ({pl.note}): the output shows the attack worked.", snippet(text, m.start(), m.end()), pl.value))
                            break  # one proof per tool, parameter and category is enough
                        self.findings += scan_output(name, text, pl.value)

    def _robustness(self, tools: list[dict[str, Any]]) -> None:
        assert self.client
        try:
            r = self.client.request("tools/definitely_not_a_method")
            if "error" not in r:
                self.findings.append(Finding("ROB-002", "low", "Unknown method did not return an error", "(protocol)", "JSON-RPC requires error -32601 for a method that does not exist."))
        except (Timeout, ServerDied):
            self.findings.append(Finding("ROB-001", "medium", "Server failed on an unknown method", "(protocol)", "No answer, or the process exited."))
            self._reconnect()
        try:
            self.client.send_raw('{"jsonrpc": "2.0", "id": 1, "method": ')
            self.client.request("tools/list")
        except ServerDied:
            self.findings.append(Finding("ROB-001", "medium", "Server crashed on malformed JSON", "(protocol)", "A truncated JSON message killed the process. Any client on the same stdio can take the server down."))
            self._reconnect()
        except Timeout:
            pass
        sel = self._selected(tools)
        for t in sel:
            ps = string_params(t)
            if ps:
                self._call(str(t["name"]), {**benign_args(t), ps[0]: "A" * 200_000}, "A x 200000")
                break

    def _rug_pull(self, before: list[dict[str, Any]]) -> None:
        assert self.client
        try:
            after = self.client.list_tools()
        except (ServerDied, Timeout, RuntimeError):
            return
        b = {str(t.get("name")): _canon(t) for t in before}
        a = {str(t.get("name")): t for t in after}
        for name, canon in b.items():
            if name in a and _canon(a[name]) != canon:
                self.findings.append(Finding("RUG-001", "high", "Tool definition changed after use (rug pull)", name, "The description or schema differs between the first and the last tools/list. A server can earn trust, then change what a tool tells the model."))
        for name in a.keys() - b.keys():
            self.findings.append(Finding("RUG-002", "medium", "Tool appeared after use", name, "A tool that was not in the first tools/list showed up later."))
        # the changed definition is the dangerous one, so check it too
        changed = [a[n] for n in a if n in b and _canon(a[n]) != b[n]] + [a[n] for n in a.keys() - b.keys()]
        for f in static_checks(changed):
            if f.code in ("TP-001", "TP-002"):
                self.findings.append(Finding(f.code, f.severity, f.title + " (after use)", f.tool, f.detail, f.evidence))

    def run(self) -> ScanResult:
        info = self._connect()
        assert self.client
        try:
            tools = self.client.list_tools()
        except (ServerDied, Timeout, RuntimeError) as e:
            self.client.close()
            raise ScanError(f"tools/list failed: {e or type(e).__name__}") from e
        self.findings += static_checks(tools)
        if self.active:
            self._benign(tools)
            self._payloads(tools)
            self._robustness(tools)
            self._rug_pull(tools)
        if self.client:
            self.client.close()
        return ScanResult(self.cmd, info.get("serverInfo", {}) if isinstance(info, dict) else {}, tools, dedupe(self.findings), self.active, self.calls, self.notes)
