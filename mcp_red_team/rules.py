"""Detection rules. Every detector looks for evidence that an attack worked, not for the payload being echoed back."""
from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITIES = ("info", "low", "medium", "high")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass(frozen=True)
class Payload:
    value: str
    note: str


# Payloads are read-only canaries: they ask for a well-known file, the output of `id`, or a metadata listing.
TRAVERSAL = [Payload("../../../../etc/passwd", "relative traversal"), Payload("/etc/passwd", "absolute path"), Payload("..\\..\\..\\windows\\win.ini", "windows traversal"), Payload("....//....//....//etc/passwd", "filter bypass")]
COMMAND = [Payload("x; id", "semicolon"), Payload("x && id", "and"), Payload("x | id", "pipe"), Payload("$(id)", "command substitution"), Payload("`id`", "backticks"), Payload("x\nid", "newline")]
SSRF = [Payload("http://169.254.169.254/latest/meta-data/", "cloud metadata"), Payload("file:///etc/passwd", "file scheme"), Payload("http://127.0.0.1:80/", "loopback")]
SQLI = [Payload("' OR '1'='1", "tautology"), Payload("'", "lone quote"), Payload("1; SELECT 1--", "stacked query"), Payload("' UNION SELECT NULL--", "union")]

CATEGORIES = {
    "PT": ("Path traversal", TRAVERSAL, re.compile(r"path|file|dir|folder|location|doc|template|attachment|source|dest", re.I)),
    "CMD": ("Command injection", COMMAND, re.compile(r"cmd|command|shell|script|exec|code|expr|run|args?$|binary|program", re.I)),
    "SSRF": ("Server-side request forgery", SSRF, re.compile(r"url|uri|endpoint|link|host|address|href|webhook|target|site|domain", re.I)),
    "SQL": ("SQL injection", SQLI, re.compile(r"query|sql|where|filter|search|statement|term|user|name|order", re.I)),
}

EVIDENCE = {
    "PT": re.compile(r"root:[x*!]:0:0:|\[(?:fonts|extensions|mci extensions)\]", re.I),
    "CMD": re.compile(r"uid=\d+\([\w.-]+\)\s+gid=\d+"),
    "SSRF": re.compile(r"ami-id|instance-id|iam/security-credentials|root:[x*!]:0:0:"),
    "SQL": re.compile(r"SQL syntax|sqlite3?\.\w*Error|unrecognized token|psycopg|ORA-\d{5}|unterminated quoted|syntax error at or near|mysql_fetch|SQLSTATE", re.I),
}

SECRETS = [
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"), "high"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}"), "high"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "medium"),
    ("credential assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[=:]\s*['\"]?[^\s'\"]{8,}"), "medium"),
]

INJECTION = [
    ("instruction override", re.compile(r"(?i)\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules)")),
    ("hidden-instruction tag", re.compile(r"(?i)<\s*(?:important|system|instructions?|secret)\s*>")),
    ("concealment", re.compile(r"(?i)\b(?:do not|don't|never)\s+(?:tell|mention|reveal|inform|show)\s+(?:the\s+)?user")),
    ("secret file access", re.compile(r"(?i)(?:read|cat|open|send|upload|include|pass)\b.{0,60}(?:\.ssh|id_rsa|\.env\b|credentials|\.aws|passwd|private key)")),
    ("exfiltration instruction", re.compile(r"(?i)\b(?:send|forward|post|email|upload)\b.{0,60}\b(?:to|at)\b.{0,30}(?:https?://|@)")),
    ("tool chaining instruction", re.compile(r"(?i)\b(?:you must|you should|always|first)\b.{0,40}\b(?:call|use|invoke|run)\b.{0,30}\b(?:tool|function)\b")),
]

HIDDEN_CHARS = re.compile("[​‌‍⁠﻿‪-‮\U000e0000-\U000e007f]")

RISKY_NAMES = re.compile(r"(?:^|_)(?:exec|execute|shell|eval|sudo|system|run_?command|delete|remove|drop|truncate|kill|format|chmod|chown)(?:_|$)", re.I)
RISKY_PARAM = re.compile(r"path|file|dir|url|uri|cmd|command|query|sql|code|script|expr|host", re.I)


def redact(s: str) -> str:
    """Keep enough of a secret to recognise it, never the whole value."""
    return s if len(s) <= 8 else s[:4] + "..." + s[-2:]
