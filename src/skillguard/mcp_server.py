"""SkillGuard MCP Server — Local AI skill security scanner for MCP clients.

Run: skillguard-mcp
Or:  python -m skillguard.mcp_server

Tools: scan_file, scan_prompt, scan_directory
Transport: stdio (no network, no server)
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# Import existing scanners
from skillguard.scanners.static import StaticScanner
from skillguard.scanners.prompt import PromptScanner

# ─── Init ───

mcp = FastMCP(
    "skillguard",
    instructions="AI Skill & Prompt Security Scanner — detect malware, prompt injection, and credential leaks. Use scan_file before loading any skill, scan_prompt to analyze text, scan_directory for bulk scanning.",
)

_static = StaticScanner()
_prompt = PromptScanner()

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


# ─── Tools ───

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

    weights = {"critical": 25, "high": 15, "warning": 5, "info": 1}
    risk_score = min(sum(weights.get(f.severity, 1) for f in findings), 100)
    risk_level = (
        "CRITICAL" if risk_score >= 75
        else "HIGH" if risk_score >= 50
        else "MEDIUM" if risk_score >= 25
        else "LOW"
    )

    result = {
        "file": file_path.name,
        "risk_score": risk_score,
        "risk_level": risk_level,
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
    risk_level = (
        "CRITICAL" if risk_score >= 75
        else "HIGH" if risk_score >= 50
        else "MEDIUM" if risk_score >= 25
        else "LOW"
    )

    result = {
        "risk_score": risk_score,
        "risk_level": risk_level,
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


# ─── Entry Point ───

def main():
    mcp.run(transport="stdio")

if __name__ == "__main__":
    main()
