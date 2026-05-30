"""Taint tracking scanner — tracks data flow from sources to sinks in Python code.

Detects when sensitive data (credentials, env vars, secrets) flows to
dangerous sinks (network requests, file writes, subprocess calls).

Limitations:
- Python only (requires AST parsing)
- Max 50 files per scan
- Max 100KB / 3000 lines per file
- Simple intra-function tracking (no cross-function)
- Max 3 variable hops

Inspired by NVIDIA SkillSpector's Taint Tracking patterns (TT1-TT5).
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from skillguard.scanners.static import Finding


# --- Source definitions (where sensitive data originates) ---

ENV_VAR_SOURCES = {"os.environ", "os.getenv", "environ.get"}
CREDENTIAL_NAMES = {"password", "passwd", "secret", "token", "api_key", "apikey", "auth",
                    "credential", "private_key", "ssh_key", "access_key", "session_id",
                    "cookie", "bearer", "authorization", "credential_id",
                    "cmd", "payload", "command", "code", "expression"}

# Regex for credential variable names
_CRED_NAME_RE = re.compile(
    r"(password|passwd|secret|token|api_key|apikey|auth|credential|"
    r"private_key|ssh_key|access_key|session_id|cookie|bearer|"
    r"authorization|credential_id|cmd|payload|command|code|expression)",
    re.IGNORECASE,
)

# --- Sink definitions (where data flows dangerously) ---

NETWORK_SINKS = {
    "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete",
    "requests.head", "requests.options", "urllib.request.urlopen", "urlopen",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "socket.send", "socket.sendall", "socket.connect",
    "webbrowser.open",
}

FILE_SINKS = {"open", "Path.write_text", "Path.write_bytes", "write", "writelines"}

EXEC_SINKS = {"exec", "eval", "subprocess.run", "subprocess.call", "subprocess.Popen",
              "os.system", "os.popen"}


@dataclass
class TaintedVar:
    """A variable marked as tainted (contains sensitive data)."""
    name: str
    source_type: str  # "env_var" | "credential_name"
    line: int


class TaintTracker:
    """Tracks data flow from sources to sinks in Python code."""

    def __init__(self, max_files: int = 50, max_hops: int = 3) -> None:
        self.max_files = max_files
        self.max_hops = max_hops

    def scan_file(self, filepath: Path) -> list[Finding]:
        """Analyze a Python file for taint flow vulnerabilities."""
        filepath = Path(filepath)
        if filepath.suffix != ".py":
            return []

        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return []

        return self._scan_source(source, str(filepath))

    def scan_content(self, content: str, filename: str = "<input>") -> list[Finding]:
        """Scan raw Python code string for taint flows."""
        return self._scan_source(content, filename)

    def _scan_source(self, source: str, filepath: str) -> list[Finding]:
        if len(source) > 100_000:
            return []
        lines = source.splitlines()
        if len(lines) > 3000:
            return []

        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError:
            return []

        return self._analyze(tree, filepath, lines)

    def _analyze(self, tree: ast.Module, filepath: str, lines: list[str]) -> list[Finding]:
        """Walk AST, track tainted variables, detect sink flows."""
        findings: list[Finding] = []
        tainted: dict[str, TaintedVar] = {}

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_tainted = dict(tainted)  # Inherit outer scope
                self._track_function(node, func_tainted, findings, filepath, lines)
                tainted.update(func_tainted)
            elif isinstance(node, ast.Assign):
                self._check_assignment(node, tainted, findings, filepath, lines)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                self._check_sink_call(node.value, tainted, findings, filepath, lines)
            elif isinstance(node, ast.If):
                self._track_body(node.body, tainted, findings, filepath, lines)
                self._track_body(node.orelse, tainted, findings, filepath, lines)
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
                self._track_body(node.body, tainted, findings, filepath, lines)

        return findings

    def _track_function(self, func_node: ast.FunctionDef, tainted: dict,
                        findings: list, filepath: str, lines: list[str]) -> None:
        """Track taint within a function body."""
        local_tainted: dict[str, TaintedVar] = {}

        # Check if any parameter name suggests credentials
        for arg in func_node.args.args:
            if _CRED_NAME_RE.search(arg.arg):
                local_tainted[arg.arg] = TaintedVar(arg.arg, "credential_name", arg.lineno)

        # Walk function body
        self._track_body(func_node.body, local_tainted, findings, filepath, lines)

    def _track_body(self, body: list[ast.stmt], tainted: dict,
                    findings: list, filepath: str, lines: list[str]) -> None:
        """Track taint through a list of statements."""
        for stmt in body:
            if isinstance(stmt, ast.Assign):
                self._check_assignment(stmt, tainted, findings, filepath, lines)
            elif isinstance(stmt, ast.AugAssign):
                pass  # Augmented assignment keeps taint
            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                self._check_sink_call(stmt.value, tainted, findings, filepath, lines)
            elif isinstance(stmt, ast.Return):
                pass
            elif isinstance(stmt, ast.If):
                self._track_body(stmt.body, tainted, findings, filepath, lines)
                self._track_body(stmt.orelse, tainted, findings, filepath, lines)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                self._track_body(stmt.body, tainted, findings, filepath, lines)
            elif isinstance(stmt, ast.With):
                self._track_body(stmt.body, tainted, findings, filepath, lines)
            elif isinstance(stmt, ast.Try):
                self._track_body(stmt.body, tainted, findings, filepath, lines)
                for handler in stmt.handlers:
                    self._track_body(handler.body, tainted, findings, filepath, lines)
                if stmt.orelse:
                    self._track_body(stmt.orelse, tainted, findings, filepath, lines)
                if stmt.finalbody:
                    self._track_body(stmt.finalbody, tainted, findings, filepath, lines)

    def _is_tainted(self, value: ast.expr, tainted: dict, depth: int = 0) -> TaintedVar | None:
        """Check if an expression value is tainted."""
        if depth > self.max_hops:
            return None

        if isinstance(value, ast.Name):
            return tainted.get(value.id)
        elif isinstance(value, ast.Subscript):
            # os.environ["VAR"] or dict["key"]
            root = self._get_subscript_root(value)
            if root in ("os.environ", "environ"):
                key = self._get_subscript_key(value)
                if key and _CRED_NAME_RE.search(key):
                    return TaintedVar(root, "env_var", value.lineno)
            # Also check if the subscript itself is tainted
            if isinstance(value.value, ast.Name):
                return tainted.get(value.value.id)
        elif isinstance(value, ast.Call):
            # os.getenv("KEY") or environ.get("KEY")
            call_name = self._get_call_name(value)
            if call_name in ENV_VAR_SOURCES and value.args:
                key = self._extract_string(value.args[0])
                if key and _CRED_NAME_RE.search(key):
                    return TaintedVar(call_name, "env_var", value.lineno)
                # If key not literal, treat all env vars as potentially tainted
                if not key:
                    return TaintedVar(call_name, "env_var", value.lineno)
        elif isinstance(value, ast.BinOp):
            # f-string parts or concatenation — check both sides
            return (self._is_tainted(value.left, tainted, depth + 1)
                    or self._is_tainted(value.right, tainted, depth + 1))
        elif isinstance(value, ast.Dict):
            # Check all values in dict literal (e.g. headers={"Auth": token})
            for v in value.values:
                taint = self._is_tainted(v, tainted, depth + 1)
                if taint:
                    return taint
        elif isinstance(value, ast.List) or isinstance(value, ast.Tuple):
            # Check elements in list/tuple
            for elt in value.elts:
                taint = self._is_tainted(elt, tainted, depth + 1)
                if taint:
                    return taint
        elif isinstance(value, ast.JoinedStr):
            # f-string — check all values
            for v in value.values:
                if isinstance(v, ast.FormattedValue):
                    taint = self._is_tainted(v.value, tainted, depth + 1)
                    if taint:
                        return taint

        return None

    def _check_assignment(self, node: ast.Assign, tainted: dict,
                         findings: list, filepath: str, lines: list[str]) -> None:
        """Check if assignment introduces or propagates taint."""
        value = node.value
        taint = self._is_tainted(value, tainted)

        for target in node.targets:
            if isinstance(target, ast.Tuple):
                # a, b = something — skip complex unpacking
                continue
            if isinstance(target, ast.Name):
                name = target.id
                if taint:
                    tainted[name] = taint
                elif _CRED_NAME_RE.search(name):
                    # Variable named like a credential but no obvious source
                    tainted[name] = TaintedVar(name, "credential_name", node.lineno)
                elif name in tainted:
                    # Reassignment without taint — remove taint
                    del tainted[name]

    def _check_sink_call(self, call: ast.Call, tainted: dict,
                         findings: list, filepath: str, lines: list[str]) -> None:
        """Check if a function call passes tainted data to a dangerous sink."""
        call_name = self._get_call_name(call)
        if not call_name:
            return

        sink_type = None
        if call_name in NETWORK_SINKS:
            sink_type = "network"
        elif call_name in EXEC_SINKS:
            sink_type = "exec"
        elif call_name in FILE_SINKS:
            sink_type = "file"

        if sink_type:
            self._emit_taint_findings(call, tainted, findings, filepath, lines, sink_type)

        # Also check method calls on objects (e.g. open().write(secret))
        if isinstance(call.func, ast.Attribute):
            method_name = call.func.attr
            if method_name in ("write", "send", "post", "execute", "query"):
                for arg in call.args:
                    taint = self._is_tainted(arg, tainted)
                    if taint:
                        line = call.lineno
                        line_content = lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""
                        findings.append(Finding(
                            file=filepath,
                            line=line,
                            column=call.col_offset,
                            severity="high",
                            category="taint_flow",
                            description=f"Tainted data flows to {method_name}() method",
                            matched_text=line_content[:120],
                            line_content=line_content,
                        ))
                        break

    def _emit_taint_findings(self, call: ast.Call, tainted: dict,
                             findings: list, filepath: str, lines: list[str],
                             sink_type: str) -> None:
        """Emit findings for tainted args/kwargs flowing to a sink."""
        descriptions = {
            ("network", "env_var"): "Credential exfiltration chain — environment variable flows to network request",
            ("network", "credential_name"): "Credential exfiltration chain — credential variable flows to network request",
            ("exec", "env_var"): "Credential exfiltration chain — environment variable flows to code execution",
            ("exec", "credential_name"): "Credential exfiltration chain — credential variable flows to code execution",
            ("file", "env_var"): "Credential exfiltration chain — environment variable flows to file write",
            ("file", "credential_name"): "Credential exfiltration chain — credential variable flows to file write",
        }
        severity_map = {"network": "critical", "exec": "critical", "file": "high"}

        # Check positional args
        for arg in call.args:
            taint = self._is_tainted(arg, tainted)
            if taint:
                line = call.lineno
                line_content = lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""
                desc = descriptions.get((sink_type, taint.source_type),
                                        f"Tainted data ({taint.source_type}) flows to {sink_type} sink")
                findings.append(Finding(
                    file=filepath,
                    line=line,
                    column=call.col_offset,
                    severity=severity_map.get(sink_type, "high"),
                    category="taint_flow",
                    description=desc,
                    matched_text=line_content[:120],
                    line_content=line_content,
                ))
                break  # One finding per call

        # Check keyword args
        for kw in call.keywords:
            taint = self._is_tainted(kw.value, tainted)
            if taint:
                line = call.lineno
                line_content = lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""
                severity = "critical" if sink_type in ("network", "exec") else "high"
                findings.append(Finding(
                    file=filepath,
                    line=line,
                    column=call.col_offset,
                    severity=severity,
                    category="taint_flow",
                    description=f"Tainted data ({taint.source_type}) flows to {sink_type} sink via keyword argument",
                    matched_text=line_content[:120],
                    line_content=line_content,
                ))
                break

    # --- Helpers ---

    def _get_call_name(self, node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            return f"{self._get_attr_root(func)}.{func.attr}"
        return None

    def _get_attr_root(self, node: ast.Attribute) -> str:
        if isinstance(node.value, ast.Name):
            return node.value.id
        elif isinstance(node.value, ast.Attribute):
            return self._get_attr_root(node.value)
        return "<expr>"

    def _get_subscript_root(self, node: ast.Subscript) -> str:
        if isinstance(node.value, ast.Name):
            return node.value.id
        elif isinstance(node.value, ast.Attribute):
            return self._get_attr_root(node.value)
        return ""

    def _get_subscript_key(self, node: ast.Subscript) -> str | None:
        if isinstance(node.slice, ast.Constant):
            return str(node.slice.value)
        return None

    def _extract_string(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None
