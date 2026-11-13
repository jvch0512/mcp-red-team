from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .rules import SEV_RANK


@dataclass
class Finding:
    code: str
    severity: str
    title: str
    tool: str
    detail: str
    evidence: str = ""
    payload: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def key(self) -> tuple[str, str, str]:
        return (self.code, self.tool, self.title)


def sort_findings(fs: list[Finding]) -> list[Finding]:
    return sorted(fs, key=lambda f: (-SEV_RANK[f.severity], f.code, f.tool))


def snippet(text: str, start: int, end: int, width: int = 50) -> str:
    a, b = max(0, start - width), min(len(text), end + width)
    s = text[a:b].replace("\n", " ").replace("\r", " ")
    return ("..." if a > 0 else "") + s + ("..." if b < len(text) else "")
