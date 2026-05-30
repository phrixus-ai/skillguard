"""SARIF (Static Analysis Results Interchange Format) output generator.

Converts SkillGuard scan findings to SARIF v2.1.0 format for CI/CD integration
(GitHub Code Scanning, Azure DevOps, etc.).

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from skillguard.scanners.static import Finding, ScanResult
from skillguard import __version__


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# SARIF rule severity mapping
SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

# SARIF rule level confidence
CONFIDENCE_MAP = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
}


def findings_to_sarif(findings: list[Finding], target: str, tool_name: str = "SkillGuard") -> dict:
    """Convert a list of SkillGuard findings to SARIF format."""
    # Group by category to create unique rules
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for finding in findings:
        rule_id = _make_rule_id(finding.category, finding.description)
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.category,
                "shortDescription": {"text": finding.category.replace("_", " ").title()},
                "fullDescription": {"text": finding.description},
                "helpUri": "https://github.com/phrixus-ai/skillguard#categories",
                "properties": {
                    "category": finding.category,
                },
            }

        result: dict = {
            "ruleId": rule_id,
            "level": SEVERITY_MAP.get(finding.severity, "warning"),
            "message": {"text": finding.description},
            "locations": [_make_location(finding)],
            "properties": {
                "severity": finding.severity,
                "matchedText": finding.matched_text or "",
            },
        }

        if finding.line > 0:
            result["fingerprints"] = {
                "primaryLocationLineHash": _line_fingerprint(finding),
            }

        results.append(result)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": __version__,
                    "informationUri": "https://github.com/phrixus-ai/skillguard",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
            }],
            "artifacts": [_make_artifact(target)],
        }],
    }

    return sarif


def scan_result_to_sarif(result: ScanResult, tool_name: str = "SkillGuard") -> dict:
    """Convert a full ScanResult to SARIF format."""
    return findings_to_sarif(result.findings, result.target, tool_name)


def write_sarif(findings: list[Finding], target: str, output_path: str | Path) -> Path:
    """Write SARIF output to a file."""
    sarif = findings_to_sarif(findings, target)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False))
    return output_path


def write_scan_result_sarif(result: ScanResult, output_path: str | Path) -> Path:
    """Write ScanResult as SARIF to a file."""
    return write_sarif(result.findings, result.target, output_path)


def sarif_to_json_string(findings: list[Finding], target: str) -> str:
    """Get SARIF as JSON string (for API responses)."""
    sarif = findings_to_sarif(findings, target)
    return json.dumps(sarif, indent=2, ensure_ascii=False)


# --- Helpers ---

def _make_rule_id(category: str, description: str) -> str:
    """Create a unique, stable rule ID from category + description hash."""
    import hashlib
    h = hashlib.md5(f"{category}:{description}".encode()).hexdigest()[:8]
    return f"SG{h.upper()}"


def _make_location(finding: Finding) -> dict:
    """Create a SARIF location from a finding."""
    location: dict = {
        "physicalLocation": {
            "artifactLocation": {
                "uri": finding.file or "<unknown>",
            },
        },
    }

    if finding.line > 0:
        location["physicalLocation"]["region"] = {
            "startLine": finding.line,
            "startColumn": finding.column + 1 if finding.column > 0 else 1,
        }

    return location


def _make_artifact(target: str) -> dict:
    """Create a SARIF artifact entry."""
    artifact: dict = {
        "location": {
            "uri": target,
        },
    }

    # Check if target is a file
    if Path(target).exists() and Path(target).is_file():
        artifact["length"] = Path(target).stat().st_size
        try:
            artifact["hashes"] = {
                "sha-256": _file_hash(Path(target)),
            }
        except Exception:
            pass

    return artifact


def _file_hash(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    import hashlib
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _line_fingerprint(finding: Finding) -> str:
    """Create a stable fingerprint for deduplication."""
    import hashlib
    content = f"{finding.file}:{finding.line}:{finding.category}:{finding.matched_text}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]
