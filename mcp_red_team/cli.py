from __future__ import annotations

import argparse
import sys
from typing import Optional

from .report import to_json, to_markdown, to_text
from .rules import SEV_RANK
from .scanner import ScanError, Scanner

DESC = """Probe an MCP server over stdio. Passive by default: it only reads tools/list. With --active it sends canary
payloads and EXECUTES the server's tools, so point it at a test instance you own.
Usage: mcp-red-team [options] -- COMMAND [ARGS...]"""


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="mcp-red-team", description=DESC, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--active", action="store_true", help="send payloads and call tools (executes the server's tools)")
    ap.add_argument("--timeout", type=float, default=5.0, help="seconds to wait for each response (default 5)")
    ap.add_argument("--skip-tool", action="append", default=[], metavar="NAME", help="never call this tool (repeatable)")
    ap.add_argument("--only-tool", action="append", default=[], metavar="NAME", help="only probe this tool (repeatable)")
    ap.add_argument("--max-calls", type=int, default=300, help="stop after this many tool calls (default 300)")
    ap.add_argument("--format", choices=("md", "json", "text"), default="md")
    ap.add_argument("--fail-on", choices=("info", "low", "medium", "high", "never"), default="high", help="exit 1 when a finding of this severity or above exists (default high)")
    ap.add_argument("command", nargs=argparse.REMAINDER, help="server command, after --")
    a = ap.parse_args(argv)
    cmd = a.command[1:] if a.command and a.command[0] == "--" else a.command
    if not cmd:
        print("error: give the server command after --, for example: mcp-red-team --active -- python server.py", file=sys.stderr)
        return 2
    if a.timeout <= 0 or a.max_calls < 1:
        print("error: --timeout and --max-calls must be positive", file=sys.stderr)
        return 2
    try:
        res = Scanner(cmd, active=a.active, timeout=a.timeout, skip=tuple(a.skip_tool), only=tuple(a.only_tool), max_calls=a.max_calls).run()
    except ScanError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print({"json": to_json, "text": to_text, "md": to_markdown}[a.format](res), end="" if a.format == "text" else "\n")
    if a.fail_on == "never":
        return 0
    return 1 if any(SEV_RANK[f.severity] >= SEV_RANK[a.fail_on] for f in res.findings) else 0


if __name__ == "__main__":
    sys.exit(main())
