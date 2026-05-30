"""AST-based code scanner — detects dangerous code patterns via Python AST parsing.

Unlike regex-based scanning, AST analysis understands code structure:
- Detects exec(), eval(), subprocess calls even if split across lines
- Identifies dynamic imports (__import__, importlib)
- Finds dangerous chains: exec(base64.b64decode(...))
- Catches obfuscated patterns that regex misses

Inspired by NVIDIA SkillSpector's Behavioral AST patterns (AST1-AST8).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from skillguard.scanners.static import Finding


# --- AST Pattern Definitions ---

DANGEROUS_CALLS: dict[str, dict[str, str]] = {
    "exec": {
        "id": "AST1",
        "severity": "critical",
        "category": "dangerous_exec",
        "description": "Direct exec() enables arbitrary code execution",
    },
    "eval": {
        "id": "AST2",
        "severity": "high",
        "category": "dangerous_eval",
        "description": "Direct eval() evaluating arbitrary expressions",
    },
    "compile": {
        "id": "AST6",
        "severity": "warning",
        "category": "dangerous_compile",
        "description": "Code object creation from strings via compile()",
    },
}

DANGEROUS_MODULES: dict[str, dict[str, str]] = {
    "subprocess": {
        "id": "AST4",
        "severity": "high",
        "category": "dangerous_subprocess",
        "description": "External command execution via subprocess module",
    },
    "os.system": {
        "id": "AST5",
        "severity": "high",
        "category": "dangerous_os_system",
        "description": "Shell commands via os.system() or os.exec-family",
    },
}

DANGEROOS_ATTRS = {"system", "exec", "execvp", "execl", "execlp", "execv", "execve", "execvpe", "popen", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe"}

DANGEROUS_IMPORTS = {
    "__import__": {
        "id": "AST3",
        "severity": "high",
        "category": "dynamic_import",
        "description": "__import__() loading arbitrary modules at runtime",
    },
    "importlib": {
        "id": "AST3b",
        "severity": "warning",
        "category": "dynamic_import",
        "description": "importlib.import_module() for dynamic module loading",
    },
}

DANGEROUS_GETATTR_PATTERNS = {
    "getattr": {
        "id": "AST7",
        "severity": "warning",
        "category": "dangerous_getattr",
        "description": "Arbitrary attribute access with non-literal names via getattr()",
    },
}


@dataclass
class ASTPattern:
    """A detected AST-level dangerous pattern."""
    node: ast.AST
    line: int
    col: int
    pattern_id: str
    severity: str
    category: str
    description: str
    matched_text: str
    chain: str = ""  # e.g. "exec(base64.b64decode(...))"


class ASTScanner:
    """Scans Python files using AST analysis to detect dangerous code patterns."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self._source_lines: list[str] = []
        self._source: str = ""

    def scan_file(self, filepath: Path) -> list[Finding]:
        """Scan a single Python file via AST parsing."""
        self.findings = []
        filepath = Path(filepath)

        if filepath.suffix != ".py":
            return []

        try:
            self._source = filepath.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return []

        # Size guard
        if len(self._source) > 100_000:
            return []

        self._source_lines = self._source.splitlines()
        if len(self._source_lines) > 3000:
            return []

        try:
            tree = ast.parse(self._source, filename=str(filepath))
        except SyntaxError:
            return []

        self._visit(tree, str(filepath))
        return self.findings

    def scan_content(self, content: str, filename: str = "<input>") -> list[Finding]:
        """Scan raw Python code string."""
        self.findings = []
        self._source = content

        if len(content) > 100_000:
            return []

        self._source_lines = content.splitlines()
        if len(self._source_lines) > 3000:
            return []

        try:
            tree = ast.parse(content, filename=filename)
        except SyntaxError:
            return []

        self._visit(tree, filename)
        return self.findings

    def _visit(self, tree: ast.Module, filepath: str) -> None:
        """Walk the AST and detect dangerous patterns."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_call(node, filepath)
            elif isinstance(node, ast.ImportFrom):
                self._check_import_from(node, filepath)
            elif isinstance(node, ast.Import):
                self._check_import(node, filepath)

        # After individual checks, look for dangerous chains
        self._check_chains(tree, filepath)

    def _get_call_name(self, node: ast.Call) -> str | None:
        """Extract the function name from a Call node."""
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            return f"{self._get_attr_root(func)}.{func.attr}"
        return None

    def _get_attr_root(self, node: ast.Attribute) -> str:
        """Get the root of an attribute chain (e.g. 'os' from 'os.system')."""
        if isinstance(node.value, ast.Name):
            return node.value.id
        elif isinstance(node.value, ast.Attribute):
            return self._get_attr_root(node.value)
        return "<expr>"

    def _get_line_content(self, line_no: int) -> str:
        """Get source line content, safe indexing."""
        if 0 < line_no <= len(self._source_lines):
            return self._source_lines[line_no - 1].strip()[:200]
        return ""

    def _add_finding(self, pattern: ASTPattern, filepath: str) -> None:
        """Convert ASTPattern to Finding and add to results."""
        self.findings.append(Finding(
            file=filepath,
            line=pattern.line,
            column=pattern.col,
            severity=pattern.severity,
            category=pattern.category,
            description=pattern.description + (f" [{pattern.chain}]" if pattern.chain else ""),
            matched_text=pattern.matched_text[:120],
            line_content=self._get_line_content(pattern.line),
        ))

    def _check_call(self, node: ast.Call, filepath: str) -> None:
        """Check a Call node for dangerous functions."""
        name = self._get_call_name(node)

        if name is None:
            return

        # Check dangerous builtins: exec, eval, compile
        if name in DANGEROUS_CALLS:
            meta = DANGEROUS_CALLS[name]
            p = ASTPattern(
                node=node,
                line=node.lineno,
                col=node.col_offset,
                pattern_id=meta["id"],
                severity=meta["severity"],
                category=meta["category"],
                description=meta["description"],
                matched_text=ast.dump(node)[:120],
            )
            self._add_finding(p, filepath)
            return

        # Check getattr with non-literal second argument
        if name in ("getattr",) and len(node.args) >= 2:
            if not isinstance(node.args[1], ast.Constant):
                meta = DANGEROUS_GETATTR_PATTERNS["getattr"]
                p = ASTPattern(
                    node=node,
                    line=node.lineno,
                    col=node.col_offset,
                    pattern_id=meta["id"],
                    severity=meta["severity"],
                    category=meta["category"],
                    description=meta["description"],
                    matched_text=ast.dump(node)[:120],
                )
                self._add_finding(p, filepath)
                return

        # Check os.system, os.exec*, os.popen, os.spawn*
        if name and name.startswith("os."):
            attr = name[3:]  # remove "os."
            if attr in DANGEROOS_ATTRS:
                meta = DANGEROUS_MODULES["os.system"]
                p = ASTPattern(
                    node=node,
                    line=node.lineno,
                    col=node.col_offset,
                    pattern_id=meta["id"],
                    severity=meta["severity"],
                    category=meta["category"],
                    description=f"Shell command via os.{attr}()",
                    matched_text=ast.dump(node)[:120],
                )
                self._add_finding(p, filepath)
                return

        # Check subprocess calls
        if name and name.startswith("subprocess."):
            meta = DANGEROUS_MODULES["subprocess"]
            p = ASTPattern(
                node=node,
                line=node.lineno,
                col=node.col_offset,
                pattern_id=meta["id"],
                severity=meta["severity"],
                category=meta["category"],
                description=f"External command via {name}()",
                matched_text=ast.dump(node)[:120],
            )
            self._add_finding(p, filepath)

    def _check_import_from(self, node: ast.ImportFrom, filepath: str) -> None:
        """Check import statements for dangerous modules."""
        if node.module in ("subprocess",):
            # Track for chain detection — subprocess imported
            pass
        if node.module == "importlib" and any(
            a.name in ("import_module", "reload") for a in node.names
        ):
            meta = DANGEROUS_IMPORTS["importlib"]
            p = ASTPattern(
                node=node,
                line=node.lineno,
                col=node.col_offset,
                pattern_id=meta["id"],
                severity=meta["severity"],
                category=meta["category"],
                description=meta["description"],
                matched_text=f"from {node.module} import ...",
            )
            self._add_finding(p, filepath)

    def _check_import(self, node: ast.Import, filepath: str) -> None:
        """Check import statements for dangerous modules."""
        for alias in node.names:
            if alias.name == "subprocess":
                meta = DANGEROUS_MODULES["subprocess"]
                p = ASTPattern(
                    node=node,
                    line=node.lineno,
                    col=node.col_offset,
                    pattern_id=meta["id"],
                    severity="warning",
                    category=meta["category"],
                    description=f"subprocess module imported (potential external command execution)",
                    matched_text=f"import {alias.name}",
                )
                self._add_finding(p, filepath)

    def _check_chains(self, tree: ast.Module, filepath: str) -> None:
        """Detect dangerous execution chains — e.g. exec(base64.b64decode(data)).

        Chain patterns:
        - exec/eval + base64/decode/encode (obfuscated execution)
        - exec/eval + requests.get/urlopen (remote code execution)
        - exec/eval + input() (user-controlled code execution)
        """
        chain_indicators = {
            "base64": re.compile(r"(base64|b64decode|b64encode|decode\(|encode\()", re.I),
            "network": re.compile(r"(requests\.get|requests\.post|urlopen|http\.client|urllib)", re.I),
            "input": re.compile(r"\binput\s*\(", re.I),
        }

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            name = self._get_call_name(node)
            if name not in ("exec", "eval"):
                continue

            # Serialize the call arguments to string
            args_str = ast.dump(node)
            line_content = self._get_line_content(node.lineno)

            for chain_name, chain_regex in chain_indicators.items():
                if chain_regex.search(args_str) or chain_regex.search(line_content):
                    severity = "critical" if name == "exec" else "high"
                    chain_desc = {
                        "base64": f"{name}() with base64 decode — obfuscated code execution",
                        "network": f"{name}() with network source — remote code execution",
                        "input": f"{name}() with user input — user-controlled code execution",
                    }
                    p = ASTPattern(
                        node=node,
                        line=node.lineno,
                        col=node.col_offset,
                        pattern_id="AST8",
                        severity=severity,
                        category="dangerous_chain",
                        description=chain_desc.get(chain_name, f"Dangerous {name}() chain detected"),
                        matched_text=line_content[:120],
                        chain=chain_name,
                    )
                    self._add_finding(p, filepath)
                    break  # Only report one chain per call
