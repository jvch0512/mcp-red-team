"""A hardened MCP server: constrained schemas, allowlists and no echo of untrusted data. Used as the clean control."""
import re

from _rpc import log_call, serve, text

DOCS = {"readme": "Demo application.\n", "changelog": "1.0 first release\n"}
VOLUMES = {"data": "data: 41% used\n", "logs": "logs: 12% used\n"}

TOOLS = [
    {"name": "read_doc", "description": "Read one of the published documents.", "inputSchema": {"type": "object", "properties": {"doc": {"type": "string", "enum": sorted(DOCS)}}, "required": ["doc"], "additionalProperties": False}},
    {"name": "disk_usage", "description": "Report disk usage for a volume.", "inputSchema": {"type": "object", "properties": {"volume": {"type": "string", "enum": sorted(VOLUMES)}}, "required": ["volume"], "additionalProperties": False}},
    {"name": "find_user", "description": "Look up a user by first name.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string", "pattern": "^[A-Za-z]{1,30}$", "maxLength": 30}}, "required": ["name"], "additionalProperties": False}},
    {"name": "weather", "description": "Get the weather for a city.", "inputSchema": {"type": "object", "properties": {"city": {"type": "string", "pattern": "^[A-Za-z ]{1,40}$", "maxLength": 40}}, "required": ["city"], "additionalProperties": False}},
]


def handle(method, params, state):
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "hardened-demo", "version": "0.1"}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        log_call(str(name))
        if set(args) - {"doc", "volume", "name", "city"}:
            return text("invalid arguments", True)
        if name == "read_doc":
            return text(DOCS[args["doc"]]) if args.get("doc") in DOCS else text("invalid arguments", True)
        if name == "disk_usage":
            return text(VOLUMES[args["volume"]]) if args.get("volume") in VOLUMES else text("invalid arguments", True)
        if name == "find_user":
            n = args.get("name")
            return text("1 match") if isinstance(n, str) and re.fullmatch(r"[A-Za-z]{1,30}", n) else text("invalid arguments", True)
        if name == "weather":
            c = args.get("city")
            return text("Sunny") if isinstance(c, str) and re.fullmatch(r"[A-Za-z ]{1,40}", c) else text("invalid arguments", True)
        raise ValueError(-32602, "unknown tool")
    raise ValueError(-32601, "method not found")


serve(handle)
