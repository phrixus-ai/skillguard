"""OSV.dev vulnerability checker — scans dependency files for known CVEs.

Checks Python (requirements.txt, pyproject.toml), Node.js (package.json),
and other ecosystem dependency files against the OSV.dev API.

Limitations:
- Max 50 packages per scan (OSV.dev batch limit)
- Network dependency (requires internet)
- Rate limited by OSV.dev (1 req/sec recommended)
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from skillguard.scanners.static import Finding


OSV_API = "https://api.osv.dev/v1/query"

# Dependency file patterns
DEP_FILES = {
    # Python
    "requirements.txt": "PyPI",
    "requirements-dev.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "setup.py": "PyPI",
    "setup.cfg": "PyPI",
    # Node.js
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    # Ruby
    "Gemfile": "RubyGems",
    "Gemfile.lock": "RubyGems",
    "gemspec": "RubyGems",
    # Go
    "go.mod": "Go",
    "go.sum": "Go",
    # Rust
    "Cargo.toml": "crates.io",
    "Cargo.lock": "crates.io",
    # Java
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "build.gradle.kts": "Maven",
}


@dataclass
class Dependency:
    """A parsed dependency with name and optional version."""
    name: str
    version: str | None = None
    ecosystem: str = "unknown"
    file: str = ""


@dataclass
class Vulnerability:
    """A vulnerability found in a dependency."""
    dep_name: str
    dep_version: str | None
    vuln_id: str
    summary: str
    severity: str
    ecosystem: str
    file: str
    aliases: list[str] = field(default_factory=list)


class OSVChecker:
    """Check dependencies against OSV.dev vulnerability database."""

    def __init__(self, max_packages: int = 50) -> None:
        self.max_packages = max_packages

    def scan_directory(self, directory: Path) -> list[Finding]:
        """Scan a directory for dependency files and check for vulnerabilities."""
        directory = Path(directory)
        if not directory.is_dir():
            return []

        findings: list[Finding] = []
        dep_count = 0

        for filepath in directory.rglob("*"):
            if dep_count >= self.max_packages:
                break

            name = filepath.name
            if name in DEP_FILES:
                ecosystem = DEP_FILES[name]
                deps = self._parse_dep_file(filepath, ecosystem)
                vulns = self._check_vulnerabilities(deps, str(filepath))
                findings.extend(vulns)
                dep_count += len(deps)

        return findings

    def scan_file(self, filepath: Path) -> list[Finding]:
        """Scan a single dependency file."""
        filepath = Path(filepath)
        name = filepath.name
        if name not in DEP_FILES:
            return []

        ecosystem = DEP_FILES[name]
        deps = self._parse_dep_file(filepath, ecosystem)
        return self._check_vulnerabilities(deps, str(filepath))

    def _parse_dep_file(self, filepath, ecosystem: str) -> list[Dependency]:
        """Parse a dependency file and extract package names + versions."""
        name = Path(filepath).name
        try:
            content = Path(filepath).read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return []

        parser = {
            "requirements.txt": self._parse_requirements,
            "requirements-dev.txt": self._parse_requirements,
            "pyproject.toml": self._parse_pyproject,
            "setup.py": self._parse_setup_py,
            "setup.cfg": self._parse_setup_cfg,
            "package.json": self._parse_package_json,
            "Gemfile": self._parse_gemfile,
            "go.mod": self._parse_go_mod,
            "Cargo.toml": self._parse_cargo_toml,
            "pom.xml": self._parse_pom_xml,
        }.get(name)

        if parser:
            return parser(content, ecosystem)
        return []

    # --- Parsers ---

    def _parse_requirements(self, content: str, ecosystem: str) -> list[Dependency]:
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle: package==1.0, package>=1.0, package~=1.0, package
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:([><=!~]+)\s*)?([0-9][\w\.\-\*]*)?", line)
            if match:
                deps.append(Dependency(
                    name=match.group(1).lower(),
                    version=match.group(3),
                    ecosystem=ecosystem,
                ))
        return deps

    def _parse_pyproject(self, content: str, ecosystem: str) -> list[Dependency]:
        deps = []
        # Simple regex parse for dependencies array
        for match in re.finditer(r'([a-zA-Z0-9_\-\.]+)\s*(?:[><=!~]+\s*)?([0-9][\w\.\-\*]*)', content):
            dep_name = match.group(1).lower()
            # Skip common non-dependency fields
            if dep_name in ("python", "requires", "build-system", "project"):
                continue
            deps.append(Dependency(
                name=dep_name,
                version=match.group(2) or None,
                ecosystem=ecosystem,
            ))
        return deps

    def _parse_setup_py(self, content: str, ecosystem: str) -> list[Dependency]:
        deps = []
        for match in re.finditer(r'install_requires\s*=\s*\[([^\]]+)\]', content, re.DOTALL):
            block = match.group(1)
            for dep_match in re.finditer(r'["\']([a-zA-Z0-9_\-\.]+)', block):
                name = dep_match.group(1).lower()
                if name not in ("python", "setuptools", "wheel"):
                    deps.append(Dependency(name=name, ecosystem=ecosystem))
        return deps

    def _parse_setup_cfg(self, content: str, ecosystem: str) -> list[Dependency]:
        deps = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("install_requires"):
                in_deps = True
                continue
            if in_deps and stripped.startswith("["):
                in_deps = False
                continue
            if in_deps:
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)", stripped)
                if match:
                    deps.append(Dependency(name=match.group(1).lower(), ecosystem=ecosystem))
        return deps

    def _parse_package_json(self, content: str, ecosystem: str) -> list[Dependency]:
        deps = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return []

        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in data.get(section, {}).items():
                # Strip ^, ~, >, < etc from version
                ver = re.sub(r"^[^0-9]*", "", version)
                deps.append(Dependency(
                    name=name.lower(),
                    version=ver or None,
                    ecosystem=ecosystem,
                ))
        return deps

    def _parse_gemfile(self, content: str, ecosystem: str) -> list[Dependency]:
        deps = []
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("gem "):
                match = re.match(r'gem\s+["\']([^"\']+)', stripped)
                if match:
                    deps.append(Dependency(name=match.group(1).lower(), ecosystem=ecosystem))
        return deps

    def _parse_go_mod(self, content: str, ecosystem: str) -> list[Dependency]:
        deps = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_deps = True
                continue
            if in_deps and stripped == ")":
                in_deps = False
                continue
            if in_deps:
                parts = stripped.split()
                if len(parts) >= 2:
                    deps.append(Dependency(
                        name=parts[0],
                        version=parts[1].lstrip("v"),
                        ecosystem=ecosystem,
                    ))
        return deps

    def _parse_cargo_toml(self, content: str, ecosystem: str) -> list[Dependency]:
        deps = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("[dependencies]") or stripped.startswith("[dev-dependencies]"):
                in_deps = True
                continue
            if in_deps and stripped.startswith("["):
                in_deps = False
                continue
            if in_deps:
                match = re.match(r'([a-zA-Z0-9_\-]+)\s*=\s*["\']?([0-9][\w\.\-\*]*)', stripped)
                if match:
                    deps.append(Dependency(
                        name=match.group(1),
                        version=match.group(2) or None,
                        ecosystem=ecosystem,
                    ))
        return deps

    def _parse_pom_xml(self, content: str, ecosystem: str) -> list[Dependency]:
        deps = []
        in_deps = False
        for line in content.splitlines():
            stripped = line.strip()
            if "<dependency>" in stripped:
                in_deps = True
            if in_deps:
                if "<groupId>" in stripped:
                    group = re.search(r"<groupId>([^<]+)", stripped)
                elif "<artifactId>" in stripped:
                    art = re.search(r"<artifactId>([^<]+)", stripped)
                elif "<version>" in stripped:
                    ver = re.search(r"<version>([^<]+)", stripped)
                elif "</dependency>" in stripped:
                    if art:
                        name = art.group(1) if art else ""
                        v = ver.group(1) if ver else None
                        deps.append(Dependency(name=name, version=v, ecosystem=ecosystem))
                    in_deps = False
        return deps

    # --- OSV.dev API ---

    def _check_vulnerabilities(self, deps: list[Dependency], filepath: str) -> list[Finding]:
        """Query OSV.dev for each dependency and return findings."""
        findings: list[Finding] = []

        # Batch query (up to 10 packages at a time)
        batch_size = 10
        for i in range(0, min(len(deps), self.max_packages), batch_size):
            batch = deps[i:i + batch_size]
            vulns = self._query_osv_batch(batch)
            for vuln in vulns:
                findings.append(Finding(
                    file=filepath,
                    line=0,
                    column=0,
                    severity=self._map_severity(vuln.severity),
                    category="dependency_vulnerability",
                    description=f"[{vuln.vuln_id}] {vuln.summary} — {vuln.dep_name} {vuln.dep_version or '(unknown version)'}",
                    matched_text=vuln.vuln_id,
                    line_content=f"Package: {vuln.dep_name} {vuln.dep_version or '?'}",
                ))

        return findings

    def _query_osv_batch(self, deps: list[Dependency]) -> list[Vulnerability]:
        """Query OSV.dev API for a batch of dependencies."""
        vulns: list[Vulnerability] = []
        for dep in deps:
            try:
                payload = {
                    "package": {
                        "name": dep.name,
                        "ecosystem": dep.ecosystem,
                    },
                    "version": dep.version,
                }
                result = subprocess.run(
                    ["curl", "-sL", "--max-time", "10", OSV_API,
                     "-X", "POST",
                     "-H", "Content-Type: application/json",
                     "-d", json.dumps(payload)],
                    capture_output=True, text=True, timeout=15,
                )
                if result.returncode == 0:
                    data = json.loads(result.stdout)
                    for vuln_data in data.get("vulns", []):
                        severity = self._extract_severity(vuln_data)
                        vulns.append(Vulnerability(
                            dep_name=dep.name,
                            dep_version=dep.version,
                            vuln_id=vuln_data.get("id", "UNKNOWN"),
                            summary=vuln_data.get("summary", "No summary"),
                            severity=severity,
                            ecosystem=dep.ecosystem,
                            file=dep.file,
                            aliases=vuln_data.get("aliases", []),
                        ))
            except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
                continue
        return vulns

    def _extract_severity(self, vuln_data: dict) -> str:
        """Extract severity from OSV.dev vulnerability data."""
        severity = "medium"

        # Check database_specific.severity (GitHub advisories)
        db_specific = vuln_data.get("database_specific", {})
        if isinstance(db_specific, dict):
            sev = db_specific.get("severity", "")
            if sev:
                return sev.lower()

        # Check CVSS scores in severity array
        for s in vuln_data.get("severity", []):
            score = s.get("score", "")
            if isinstance(score, str):
                try:
                    val = float(score)
                    if val >= 9.0:
                        return "critical"
                    elif val >= 7.0:
                        return "high"
                    elif val >= 4.0:
                        return "medium"
                    else:
                        return "low"
                except ValueError:
                    pass

        return severity

    def _map_severity(self, osv_severity: str) -> str:
        """Map OSV severity to SkillGuard severity."""
        mapping = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        return mapping.get(osv_severity, "medium")
