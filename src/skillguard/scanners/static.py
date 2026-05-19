"""Static code scanner — detects malware, obfuscation, suspicious imports, and credential leaks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skillguard.patterns import get_all_patterns


@dataclass
class Finding:
    """Single security finding."""
    file: str
    line: int
    column: int
    severity: str          # critical | high | warning | info
    category: str
    description: str
    matched_text: str
    line_content: str


@dataclass
class ScanResult:
    """Result of a scan operation."""
    target: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def risk_score(self) -> int:
        """Calculate risk score 0-100."""
        if not self.findings:
            return 0
        weights = {"critical": 25, "high": 15, "warning": 5, "info": 1}
        total = sum(weights.get(f.severity, 1) for f in self.findings)
        return min(total, 100)

    @property
    def risk_level(self) -> str:
        score = self.risk_score
        if score >= 75:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 25:
            return "MEDIUM"
        return "LOW"

    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "warning")


# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash", ".zsh",
    ".rb", ".go", ".rs", ".java", ".php", ".pl", ".lua",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    ".md", ".txt", ".env", ".dockerfile",
    ".html", ".htm", ".css", ".svg",
    ".gitignore", ".dockerignore",
}

# Directories to skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
}


class StaticScanner:
    """Scans files for malicious patterns."""

    def __init__(self) -> None:
        self.patterns = get_all_patterns("malware.json")
        self._compiled: list[tuple[re.Pattern, dict[str, Any]]] = []
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns."""
        for p in self.patterns:
            try:
                compiled = re.compile(p["regex"], re.IGNORECASE)
                self._compiled.append((compiled, p))
            except re.error:
                pass  # Skip invalid patterns

    def scan_file(self, filepath: Path) -> list[Finding]:
        """Scan a single file and return findings."""
        findings: list[Finding] = []
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return findings

        lines = content.splitlines()
        for line_no, line in enumerate(lines, start=1):
            for regex, meta in self._compiled:
                for match in regex.finditer(line):
                    findings.append(Finding(
                        file=str(filepath),
                        line=line_no,
                        column=match.start() + 1,
                        severity=meta["severity"],
                        category=meta["category"],
                        description=meta["description"],
                        matched_text=match.group()[:120],
                        line_content=line.strip()[:200],
                    ))
        return findings

    def scan_directory(self, target: str | Path) -> ScanResult:
        """Scan a directory recursively."""
        import time
        start = time.time()
        target = Path(target).resolve()
        result = ScanResult(target=str(target))

        if target.is_file():
            result.files_scanned = 1
            result.findings = self.scan_file(target)
        else:
            for filepath in target.rglob("*"):
                if any(skip in filepath.parts for skip in SKIP_DIRS):
                    continue
                if filepath.suffix.lower() in SCAN_EXTENSIONS or filepath.name.lower() in SCAN_EXTENSIONS:
                    result.files_scanned += 1
                    result.findings.extend(self.scan_file(filepath))

        result.duration_seconds = round(time.time() - start, 2)
        return result

    def scan_content(self, content: str, filename: str = "<input>") -> list[Finding]:
        """Scan raw string content (useful for prompt analysis)."""
        findings: list[Finding] = []
        lines = content.splitlines()
        for line_no, line in enumerate(lines, start=1):
            for regex, meta in self._compiled:
                for match in regex.finditer(line):
                    findings.append(Finding(
                        file=filename,
                        line=line_no,
                        column=match.start() + 1,
                        severity=meta["severity"],
                        category=meta["category"],
                        description=meta["description"],
                        matched_text=match.group()[:120],
                        line_content=line.strip()[:200],
                    ))
        return findings
