"""A fragile MCP server: dies on malformed JSON and hangs on a crafted argument. Used to test robustness findings."""
import time

from _rpc import serve, text

TOOLS = [{"name": "echo", "description": "Echo some text.", "inputSchema": {"type": "object", "properties": {"text": {"type": "string", "maxLength": 100000}}, "required": ["text"], "additionalProperties": False}}]


def handle(method, params, state):
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "fragile-demo", "version": "0.1"}}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        t = (params.get("arguments") or {}).get("text", "")
        if ";" in t or "&&" in t:
            time.sleep(30)
        return text(t[:20])
    raise ValueError(-32601, "method not found")


serve(handle, strict=False)
