"""Prompt injection scanner — detects jailbreaks, system overrides, and data exfiltration in prompts."""

from __future__ import annotations

from dataclasses import dataclass

from skillguard.patterns import get_all_patterns
from skillguard.scanners.static import Finding


class PromptScanner:
    """Scans prompts and skill descriptions for injection patterns."""

    def __init__(self) -> None:
        self.patterns = get_all_patterns("injection.json")

    def scan(self, content: str, source: str = "<prompt>") -> list[Finding]:
        """Scan prompt content for injection patterns."""
        import re

        findings: list[Finding] = []
        lines = content.splitlines()

        for line_no, line in enumerate(lines, start=1):
            for p in self.patterns:
                try:
                    regex = re.compile(p["regex"], re.IGNORECASE)
                except re.error:
                    continue
                for match in regex.finditer(line):
                    findings.append(Finding(
                        file=source,
                        line=line_no,
                        column=match.start() + 1,
                        severity=p["severity"],
                        category=p["category"],
                        description=p["description"],
                        matched_text=match.group()[:120],
                        line_content=line.strip()[:200],
                    ))
        return findings
