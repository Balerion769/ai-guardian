"""Fast, deterministic rules for high-risk additions to code."""

import re
from dataclasses import dataclass
from typing import Literal, Pattern

from scanner.models import Vulnerability


@dataclass(frozen=True)
class Rule:
    """A precompiled expression and the finding it produces."""

    pattern: Pattern[str]
    severity: Literal["HIGH", "MEDIUM", "LOW"]
    category: str
    description: str
    remediation: str


class StaticAnalyzer:
    """Scan added diff lines, or every line of a plain code snippet."""

    _RULES: tuple[Rule, ...] = (
        Rule(re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "HIGH", "Secret Leak", "AWS access key is present in source.", "Remove the key, rotate it, and use a secret manager."),
        Rule(re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"), "HIGH", "Secret Leak", "A private key is present in source.", "Remove and rotate the key; load it from a secure secret store."),
        Rule(re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b"), "HIGH", "Secret Leak", "A GitHub token is present in source.", "Revoke the token and use a secret manager."),
        Rule(re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "HIGH", "Secret Leak", "A Slack token is present in source.", "Revoke the token and load a replacement from a secret manager."),
        Rule(re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "HIGH", "Secret Leak", "A hardcoded JWT is present in source.", "Remove the JWT, revoke it when possible, and use short-lived credentials."),
        Rule(re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"\s]{4,}['\"]", re.IGNORECASE), "HIGH", "Secret Leak", "A hardcoded password is present in source.", "Remove and rotate the password; read it from a secret manager."),
        Rule(re.compile(r"\b(?:eval|exec)\s*\("), "HIGH", "Unsafe Code Execution", "Dynamic code execution may run untrusted input.", "Replace dynamic execution with a safe parser or explicit dispatch."),
        Rule(re.compile(r"\b(?:execute|executemany|raw)\s*\(.*(?:['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'\"]*['\"]\s*\+|\+\s*['\"][^'\"]*(?:SELECT|INSERT|UPDATE|DELETE))", re.IGNORECASE), "HIGH", "SQL Injection", "SQL query is built with string concatenation.", "Use parameterized queries and pass values separately."),
        Rule(re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'\"@]+:[^\s'\"@]+@", re.IGNORECASE), "HIGH", "Cleartext Connection String", "A connection string contains embedded credentials.", "Move credentials to a secret manager and use encrypted transport."),
    )
    _HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    def analyze(self, diff_content: str, language: str) -> list[Vulnerability]:
        """Return all matching findings with new-file line references.

        The language is accepted for a stable engine interface; these rules
        deliberately cover common syntax across supported languages.
        """
        del language
        lines = diff_content.splitlines()
        is_diff = any(line.startswith("diff --git ") or self._HUNK.match(line) for line in lines)
        findings: list[Vulnerability] = []
        new_line = 0

        for source_line, line in enumerate(lines, start=1):
            if is_diff:
                hunk = self._HUNK.match(line)
                if hunk:
                    new_line = int(hunk.group(1))
                    continue
                if line.startswith("+++") or line.startswith("---"):
                    continue
                if not line.startswith("+"):
                    if line.startswith(" "):
                        new_line += 1
                    continue
                code = line[1:]
                reference = f"Line {new_line}" if new_line else f"Diff line {source_line}"
                new_line += 1
            else:
                code = line
                reference = f"Line {source_line}"

            for rule in self._RULES:
                if rule.pattern.search(code):
                    findings.append(
                        Vulnerability(
                            severity=rule.severity,
                            category=rule.category,
                            description=rule.description,
                            line_reference=reference,
                            remediation=rule.remediation,
                        )
                    )
        return findings
