"""SkillGuard MCP Server — Local AI skill security scanner for MCP clients.

Run: skillguard-mcp
Or:  python -m skillguard.mcp_server

Tools: scan_file, scan_prompt, scan_directory, scan_url, audit_mcp, get_patterns
Transport: stdio (no network, no server)
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Import existing scanners
from skillguard.scanners.static import StaticScanner
from skillguard.scanners.prompt import PromptScanner
from skillguard.scanners.ast_scanner import ASTScanner
from skillguard.scanners.taint_tracker import TaintTracker
from skillguard.scanners.osv_checker import OSVChecker
from skillguard.scanners.url import smart_scan_url

# ─── Init ───

mcp = FastMCP(
    "skillguard",
    instructions=(
        "AI Skill & Prompt Security Scanner — detect malware, prompt injection, "
        "hidden payloads, and credential leaks in AI skills, plugins, MCP servers, and prompts.\n\n"
        "Tools:\n"
        "- scan_file: Scan a local file for threats\n"
        "- scan_prompt: Scan text for injection/manipulation patterns\n"
        "- scan_directory: Recursively scan a folder\n"
        "- scan_url: Scan a GitHub repo or HuggingFace model\n"
        "- audit_mcp: Audit another MCP server's tool definitions for security risks\n"
        "- get_patterns: List available detection patterns and categories\n\n"
        "Always scan before loading/trusting any skill, plugin, or MCP server."
    ),
)

_static = StaticScanner()
_prompt = PromptScanner()
_ast = ASTScanner()
_taint = TaintTracker()
_osv = OSVChecker()

PATTERNS_DIR = Path(__file__).parent / "patterns"


# ─── Helpers ───

def _severity_emoji(severity: str) -> str:
    return {"critical": "🔴", "high": "🟠", "warning": "🟡", "info": "🔵"}.get(severity, "⚪")


def _recommendation(risk_score: int) -> str:
    if risk_score >= 75:
        return "⛔ REJECT — Critical threats detected"
    elif risk_score >= 50:
        return "⚠️ REVIEW — High-risk findings, manual review required"
    elif risk_score >= 25:
        return "🔍 CAUTION — Warnings found, review recommended"
    return "✅ SAFE — No significant threats detected"


def _format_findings(findings: list) -> list[dict]:
    result = []
    for f in findings[:20]:  # Cap at 20 for readability
        entry = {
            "severity": f.severity,
            "emoji": _severity_emoji(f.severity),
            "category": f.category,
            "description": f.description,
            "file": f.file if hasattr(f, "file") else None,
            "line": f.line if hasattr(f, "line") else None,
            "matched_text": f.matched_text if hasattr(f, "matched_text") else None,
        }
        result.append(entry)
    return result


def _risk_level(score: int) -> str:
    return (
        "CRITICAL" if score >= 75
        else "HIGH" if score >= 50
        else "MEDIUM" if score >= 25
        else "LOW"
    )


# ─── Existing Tools ───

@mcp.tool()
def scan_file(path: str) -> str:
    """Scan a file for security threats (malware, injection, credential leaks).

    Use this before loading any AI skill, plugin, or configuration file.
    Supports: .py, .js, .md, .yaml, .json, .sh, .txt files.

    Args:
        path: Absolute path to the file to scan.
    """
    file_path = Path(path).expanduser().resolve()

    if not file_path.exists():
        return json.dumps({"error": f"File not found: {path}"})

    if not file_path.is_file():
        return json.dumps({"error": f"Not a file: {path}"})

    findings = _static.scan_file(file_path)

    # Deep scan: AST + Taint for Python files
    if file_path.suffix == ".py":
        try:
            findings.extend(_ast.scan_file(file_path))
            findings.extend(_taint.scan_file(file_path))
        except Exception:
            pass  # Don't break scan if deep scan fails

    weights = {"critical": 25, "high": 15, "warning": 5, "info": 1}
    risk_score = min(sum(weights.get(f.severity, 1) for f in findings), 100)

    result = {
        "file": file_path.name,
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "recommendation": _recommendation(risk_score),
        "findings_count": len(findings),
        "critical_count": sum(1 for f in findings if f.severity == "critical"),
        "high_count": sum(1 for f in findings if f.severity == "high"),
        "warning_count": sum(1 for f in findings if f.severity == "warning"),
        "findings": _format_findings(findings),
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def scan_prompt(content: str) -> str:
    """Scan a prompt or text for injection attacks and manipulation.

    Use this to analyze user input, skill instructions, or any text
    before passing it to an AI model.

    Args:
        content: The prompt text to scan for injection patterns.
    """
    if not content or not content.strip():
        return json.dumps({"error": "Empty content provided"})

    findings = _prompt.scan(content, source="<user_input>")

    weights = {"critical": 25, "high": 15, "warning": 5, "info": 1}
    risk_score = min(sum(weights.get(f.severity, 1) for f in findings), 100)

    result = {
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "recommendation": _recommendation(risk_score),
        "findings_count": len(findings),
        "critical_count": sum(1 for f in findings if f.severity == "critical"),
        "high_count": sum(1 for f in findings if f.severity == "high"),
        "warning_count": sum(1 for f in findings if f.severity == "warning"),
        "findings": _format_findings(findings),
    }

    return json.dumps(result, indent=2)


@mcp.tool()
def scan_directory(path: str) -> str:
    """Scan a directory recursively for security threats in all files.

    Use this to scan entire skill collections, plugin directories,
    or project folders before deployment.

    Args:
        path: Absolute path to the directory to scan.
    """

    dir_path = Path(path).expanduser().resolve()

    if not dir_path.exists():
        return json.dumps({"error": f"Directory not found: {path}"})

    if not dir_path.is_dir():
        return json.dumps({"error": f"Not a directory: {path}"})

    result = _static.scan_directory(dir_path)

    # Deep scan: AST + Taint on Python files
    skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}
    py_count = 0
    for fp in dir_path.rglob("*.py"):
        if py_count >= 50:
            break
        if any(skip in fp.parts for skip in skip_dirs):
            continue
        try:
            result.findings.extend(_ast.scan_file(fp))
            result.findings.extend(_taint.scan_file(fp))
            py_count += 1
        except Exception:
            pass

    # OSV dependency check
    for dep_name in {"requirements.txt", "pyproject.toml", "package.json"}:
        dep_path = dir_path / dep_name
        if dep_path.exists():
            try:
                result.findings.extend(_osv.scan_file(dep_path))
            except Exception:
                pass

    # Collect per-file breakdown
    file_map = {}
    for f in result.findings:
        fname = f.file if hasattr(f, "file") else "unknown"
        file_map[fname] = file_map.get(fname, 0) + 1
    file_summaries = [{"file": k, "findings": v} for k, v in sorted(file_map.items(), key=lambda x: -x[1])][:10]

    output = {
        "directory": str(dir_path),
        "files_scanned": result.files_scanned,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "recommendation": _recommendation(result.risk_score),
        "total_findings": len(result.findings),
        "critical_count": result.critical_count(),
        "high_count": result.high_count(),
        "warning_count": result.warning_count(),
        "top_categories": list({f.category for f in result.findings[:10]}),
        "file_summaries": file_summaries[:10],
        "findings": _format_findings(result.findings),
    }

    return json.dumps(output, indent=2)


# ─── New Tools ───

@mcp.tool()
def scan_url(url: str) -> str:
    """Scan a GitHub repository or HuggingFace model for security threats.

    Clones the repository content and runs a full security scan.
    Supports github.com and huggingface.co URLs.

    Args:
        url: GitHub repo URL (https://github.com/user/repo) or HuggingFace model URL.
    """
    if not url or not url.strip():
        return json.dumps({"error": "Empty URL provided"})

    url = url.strip()

    if "github.com" not in url and "huggingface.co" not in url:
        return json.dumps({"error": "Only github.com and huggingface.co URLs are supported"})

    try:
        result = smart_scan_url(url, _static, _ast)
    except Exception as e:
        return json.dumps({"error": f"Failed to scan URL: {str(e)}"})

    # Per-file breakdown
    file_map = {}
    for f in result.findings:
        fname = f.file if hasattr(f, "file") else "unknown"
        file_map[fname] = file_map.get(fname, 0) + 1
    file_summaries = [{"file": k, "findings": v} for k, v in sorted(file_map.items(), key=lambda x: -x[1])][:10]

    output = {
        "url": url,
        "files_scanned": result.files_scanned,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "recommendation": _recommendation(result.risk_score),
        "total_findings": len(result.findings),
        "critical_count": result.critical_count(),
        "high_count": result.high_count(),
        "warning_count": result.warning_count(),
        "top_categories": sorted({f.category for f in result.findings}),
        "file_summaries": file_summaries,
        "findings": _format_findings(result.findings),
    }

    return json.dumps(output, indent=2)


@mcp.tool()
def audit_mcp(definition: str) -> str:
    """Audit an MCP server's tool definitions for security risks.

    Analyzes tool names, descriptions, and input schemas to detect:
    - Overly broad filesystem access (no path restrictions)
    - Network call capability without validation
    - Credential/secret exposure via tool descriptions
    - Unsafe input handling (shell injection, path traversal)
    - Destructive operations without safeguards

    Args:
        definition: JSON string of MCP tool definitions. Can be the full MCP server
            manifest, or a tools array with name/description/inputSchema fields.
            Example: '[{"name": "read_file", "description": "Read any file", "inputSchema": {...}}]'
    """
    if not definition or not definition.strip():
        return json.dumps({"error": "Empty definition provided"})

    # Parse input
    try:
        data = json.loads(definition)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON: {str(e)}"})

    # Normalize to tools list
    tools = []
    if isinstance(data, list):
        tools = data
    elif isinstance(data, dict):
        tools = data.get("tools", data.get("resources", [data]))
    else:
        return json.dumps({"error": "Expected JSON object or array"})

    if not tools:
        return json.dumps({"error": "No tools found in definition"})

    findings = []

    # ─── Security patterns for MCP tool auditing ───

    # 1. Overly broad filesystem access
    filesystem_keywords = ["read", "write", "file", "path", "directory", "folder", "filesystem", "ls", "cat"]
    restricted_patterns = ["/etc/", "/tmp/", "~/.ssh", "~/.aws", "~/.env", ".ssh/", ".aws/", "passwords"]

    # 2. Network access
    network_keywords = ["fetch", "http", "request", "api", "curl", "download", "upload", "send", "post", "webhook"]

    # 3. Destructive operations
    destructive_keywords = ["delete", "remove", "drop", "truncate", "clear", "purge", "destroy", "kill", "exec", "run", "eval"]

    # 4. Credential-related
    credential_keywords = ["password", "secret", "token", "key", "credential", "auth", "api_key", "private"]

    # 5. Unsafe shell patterns
    shell_keywords = ["shell", "bash", "cmd", "exec", "system", "subprocess", "command", "terminal"]

    for tool in tools:
        name = tool.get("name", "unknown")
        description = (tool.get("description", "") or "").lower()
        schema = tool.get("inputSchema", tool.get("input_schema", {}))

        # Check if schema has no required fields (too open)
        required = schema.get("required", []) if isinstance(schema, dict) else []
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
        has_no_required = len(required) == 0 and len(properties) > 0

        # Check for path parameter without restriction
        matching_props = [p for p in properties if any(kw in p.lower() for kw in ["path", "file", "dir", "url", "command"])]
        path_param = bool(matching_props)
        path_has_enum = False
        if matching_props:
            for mp in matching_props:
                mp_schema = properties.get(mp, {})
                if isinstance(mp_schema, dict) and "enum" in mp_schema:
                    path_has_enum = True
                    break

        # 1. Overly broad filesystem access
        if any(kw in description for kw in filesystem_keywords):
            if not path_has_enum and not any(rp in description for rp in ["restrict", "sandbox", "allowlist", "whitelist", "safe", "specific"]):
                findings.append({
                    "tool": name,
                    "severity": "high",
                    "category": "broad_filesystem_access",
                    "description": f"Tool '{name}' has filesystem access without path restrictions or sandbox boundaries",
                    "recommendation": "Add allowlist/sandbox constraints or limit accessible paths"
                })

        # 2. Network capability
        if any(kw in description for kw in network_keywords):
            if not any(safe in description for safe in ["validate", "verify", "allowlist", "restrict", "specific", "approved"]):
                findings.append({
                    "tool": name,
                    "severity": "high",
                    "category": "unrestricted_network",
                    "description": f"Tool '{name}' can make network calls without URL/domain restrictions",
                    "recommendation": "Restrict to allowlisted domains or validate URLs before making requests"
                })

        # 3. Destructive operations
        if any(kw in description for kw in destructive_keywords):
            has_confirm = any(kw in description for kw in ["confirm", "verify", "check", "safe", "dry-run", "preview", "warning"])
            if not has_confirm:
                findings.append({
                    "tool": name,
                    "severity": "critical",
                    "category": "destructive_no_safeguard",
                    "description": f"Tool '{name}' performs destructive operations without confirmation or dry-run",
                    "recommendation": "Add confirmation step, dry-run mode, or undo capability"
                })

        # 4. Credential exposure
        if any(kw in description for kw in credential_keywords):
            findings.append({
                "tool": name,
                "severity": "critical",
                "category": "credential_handling",
                "description": f"Tool '{name}' handles credentials/secrets — ensure no logging or exfiltration risk",
                "recommendation": "Use secure secret storage, never log credentials, encrypt at rest"
            })

        # 5. Unsafe shell execution
        if any(kw in description for kw in shell_keywords):
            if not any(safe in description for safe in ["safe", "sandbox", "restrict", "validate", "sanitize"]):
                findings.append({
                    "tool": name,
                    "severity": "critical",
                    "category": "shell_execution",
                    "description": f"Tool '{name}' can execute shell commands without input sanitization",
                    "recommendation": "Implement strict input validation, use allowlisted commands only, sandbox execution"
                })

        # 6. No required parameters (too open)
        if has_no_required and len(properties) == 0:
            findings.append({
                "tool": name,
                "severity": "warning",
                "category": "no_input_validation",
                "description": f"Tool '{name}' has no input schema — cannot validate or restrict usage",
                "recommendation": "Define inputSchema with typed, validated parameters"
            })

        # 7. Direct path parameter without validation
        if path_param and not path_has_enum:
            findings.append({
                "tool": name,
                "severity": "high",
                "category": "path_traversal_risk",
                "description": f"Tool '{name}' accepts path/file parameter without enum constraints — path traversal risk",
                "recommendation": "Add path validation, restrict to specific directories, use path.resolve() checks"
            })

    # Calculate risk
    weights = {"critical": 25, "high": 15, "warning": 5, "info": 1}
    risk_score = min(sum(weights.get(f["severity"], 1) for f in findings), 100)

    # Tool safety summary
    tool_ratings = []
    for tool in tools:
        name = tool.get("name", "unknown")
        tool_findings = [f for f in findings if f["tool"] == name]
        critical = sum(1 for f in tool_findings if f["severity"] == "critical")
        high = sum(1 for f in tool_findings if f["severity"] == "high")

        if critical > 0:
            rating = "⛔ UNSAFE"
        elif high > 0:
            rating = "⚠️ CAUTION"
        elif len(tool_findings) > 0:
            rating = "🔍 REVIEW"
        else:
            rating = "✅ SAFE"

        tool_ratings.append({"tool": name, "rating": rating, "findings": len(tool_findings)})

    output = {
        "tools_audited": len(tools),
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "recommendation": _recommendation(risk_score),
        "findings_count": len(findings),
        "critical_count": sum(1 for f in findings if f["severity"] == "critical"),
        "high_count": sum(1 for f in findings if f["severity"] == "high"),
        "warning_count": sum(1 for f in findings if f["severity"] == "warning"),
        "tool_ratings": tool_ratings,
        "findings": findings,
    }

    return json.dumps(output, indent=2)


@mcp.tool()
def get_patterns(category: str = "") -> str:
    """List available detection patterns and categories.

    Returns all pattern categories with pattern counts, descriptions,
    and severity levels. Filter by category to see specific patterns.

    Args:
        category: Optional category name to filter (e.g. 'context_hijacking',
            'reverse_shell', 'data_exfiltration'). Leave empty to see all categories.
    """
    import json as _json

    categories = {}

    # Load malware patterns
    malware_path = PATTERNS_DIR / "malware.json"
    if malware_path.exists():
        with open(malware_path) as f:
            malware = _json.load(f)
        for cat_name, cat_data in malware.get("categories", {}).items():
            categories[cat_name] = {
                "source": "malware.json",
                "severity": cat_data.get("severity", "unknown"),
                "pattern_count": len(cat_data.get("patterns", [])),
            }

    # Load injection patterns
    injection_path = PATTERNS_DIR / "injection.json"
    if injection_path.exists():
        with open(injection_path) as f:
            injection = _json.load(f)
        for cat_name, cat_data in injection.get("categories", {}).items():
            categories[cat_name] = {
                "source": "injection.json",
                "severity": cat_data.get("severity", "unknown"),
                "pattern_count": len(cat_data.get("patterns", [])),
            }

    # Filter if category specified
    if category:
        cat = category.lower().strip()
        if cat in categories:
            categories = {cat: categories[cat]}
        else:
            # Fuzzy match
            matches = {k: v for k, v in categories.items() if cat in k.lower()}
            if matches:
                categories = matches
            else:
                available = list(categories.keys())
                return json.dumps({
                    "error": f"Category '{category}' not found",
                    "available_categories": available,
                }, indent=2)

    # If single category, include pattern details
    if len(categories) == 1 and category:
        cat_name = list(categories.keys())[0]
        source = categories[cat_name]["source"]
        with open(PATTERNS_DIR / source) as f:
            data = _json.load(f)
        cat_data = data["categories"][cat_name]
        patterns = [
            {
                "regex": p.get("regex", ""),
                "description": p.get("description", ""),
            }
            for p in cat_data.get("patterns", [])
        ]
        output = {
            "category": cat_name,
            "severity": categories[cat_name]["severity"],
            "pattern_count": len(patterns),
            "patterns": patterns,
        }
    else:
        total = sum(c["pattern_count"] for c in categories.values())
        output = {
            "total_patterns": total,
            "total_categories": len(categories),
            "categories": categories,
            "mcp_tools": 6,
            "tools": [
                {"name": "scan_file", "description": "Scan a local file for threats"},
                {"name": "scan_prompt", "description": "Scan text for injection/manipulation patterns"},
                {"name": "scan_directory", "description": "Recursively scan a folder"},
                {"name": "scan_url", "description": "Scan GitHub repos and HuggingFace models"},
                {"name": "audit_mcp", "description": "Audit MCP server tool definitions for security risks"},
                {"name": "get_patterns", "description": "List available detection patterns and categories"},
            ],
        }

    return json.dumps(output, indent=2)


# ─── Entry Point ───

def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
