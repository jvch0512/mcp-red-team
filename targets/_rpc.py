"""Tiny stdio JSON-RPC loop shared by the demo targets. Not part of the scanner."""
import json
import os
import sys


def log_call(name):
    path = os.environ.get("MCP_TARGET_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(name + "\n")


def serve(handle, strict=True):
    """handle(method, params, state) -> result dict, or raises ValueError(code, message)."""
    state = {"calls": 0}
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            if strict:
                print(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}), flush=True)
                continue
            raise
        if not isinstance(msg, dict) or "method" not in msg:
            continue
        rid = msg.get("id")
        if rid is None:
            continue  # notification
        try:
            result = handle(msg["method"], msg.get("params") or {}, state)
            out = {"jsonrpc": "2.0", "id": rid, "result": result}
        except ValueError as e:
            code, text = e.args if len(e.args) == 2 else (-32602, str(e))
            out = {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": text}}
        print(json.dumps(out), flush=True)


def text(s, error=False):
    return {"content": [{"type": "text", "text": s}], "isError": error}
