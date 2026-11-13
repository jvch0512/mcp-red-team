"""A minimal MCP client over stdio (newline-delimited JSON-RPC 2.0). Standard library only."""
from __future__ import annotations

import json
import queue
import subprocess
import threading
import time
from typing import Any, Optional

PROTOCOL_VERSION = "2024-11-05"


class ServerDied(Exception):
    """The server process closed its output or its input."""


class Timeout(Exception):
    """No matching response within the timeout."""


class McpClient:
    def __init__(self, cmd: list[str], timeout: float = 5.0, cwd: Optional[str] = None) -> None:
        self.cmd = cmd
        self.timeout = timeout
        self.cwd = cwd
        self._id = 0
        self._q: "queue.Queue[Optional[str]]" = queue.Queue()
        self.proc: Optional[subprocess.Popen[str]] = None
        self.notifications: list[dict[str, Any]] = []

    # -- process
    def start(self) -> None:
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1, cwd=self.cwd)
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc and self.proc.stdout
        try:
            for line in self.proc.stdout:
                self._q.put(line)
        finally:
            self._q.put(None)

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def close(self) -> None:
        if not self.proc:
            return
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=2)
        except Exception:
            self.proc.kill()
            self.proc.wait()
        finally:
            if self.proc.stdout:
                self.proc.stdout.close()

    # -- transport
    def send_raw(self, text: str) -> None:
        assert self.proc and self.proc.stdin
        try:
            self.proc.stdin.write(text + "\n")
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise ServerDied() from e

    def _read(self, deadline: float) -> dict[str, Any]:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Timeout()
            try:
                line = self._q.get(timeout=remaining)
            except queue.Empty as e:
                raise Timeout() from e
            if line is None:
                self._q.put(None)
                raise ServerDied()
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue  # stray output on stdout is not a protocol message
            if isinstance(msg, dict):
                return msg

    def request(self, method: str, params: Optional[dict[str, Any]] = None, timeout: Optional[float] = None) -> dict[str, Any]:
        self._id += 1
        rid = self._id
        self.send_raw(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}}))
        deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
        while True:
            msg = self._read(deadline)
            if msg.get("id") == rid:
                return msg
            if "method" in msg:
                self.notifications.append(msg)

    def notify(self, method: str, params: Optional[dict[str, Any]] = None) -> None:
        self.send_raw(json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}}))

    # -- MCP
    def initialize(self) -> dict[str, Any]:
        r = self.request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "mcp-red-team", "version": "1.0.0"}})
        if "error" in r:
            raise RuntimeError(f"initialize failed: {r['error']}")
        self.notify("notifications/initialized")
        return r.get("result", {})

    def list_tools(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: Optional[str] = None
        for _ in range(20):
            r = self.request("tools/list", {"cursor": cursor} if cursor else {})
            if "error" in r:
                raise RuntimeError(f"tools/list failed: {r['error']}")
            res = r.get("result", {})
            tools.extend(t for t in res.get("tools", []) if isinstance(t, dict))
            cursor = res.get("nextCursor")
            if not cursor:
                break
        return tools

    def call(self, name: str, arguments: dict[str, Any], timeout: Optional[float] = None) -> dict[str, Any]:
        return self.request("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)


def response_text(resp: dict[str, Any]) -> str:
    """All text a response puts in front of a model: result content, structured content and error messages."""
    parts: list[str] = []
    res = resp.get("result")
    if isinstance(res, dict):
        for c in res.get("content", []) or []:
            if isinstance(c, dict):
                if isinstance(c.get("text"), str):
                    parts.append(c["text"])
                elif isinstance(c.get("resource"), dict) and isinstance(c["resource"].get("text"), str):
                    parts.append(c["resource"]["text"])
        if "structuredContent" in res:
            parts.append(json.dumps(res["structuredContent"]))
    err = resp.get("error")
    if isinstance(err, dict):
        parts.append(str(err.get("message", "")))
        if "data" in err:
            parts.append(str(err["data"]))
    return "\n".join(parts)
