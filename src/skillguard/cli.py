"""SkillGuard CLI — command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from skillguard import __version__
from skillguard.scanners.static import StaticScanner
from skillguard.scanners.prompt import PromptScanner
from skillguard.scanners.ast_scanner import ASTScanner
from skillguard.scanners.taint_tracker import TaintTracker
from skillguard.scanners.osv_checker import OSVChecker
from skillguard.output.sarif import write_scan_result_sarif, sarif_to_json_string

console = Console()

SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "bold yellow",
    "warning": "cyan",
    "info": "dim",
}
SEVERITY_ICONS = {
    "critical": "🔴",
    "high": "🟡",
    "warning": "🔵",
    "info": "⚪",
}


@click.group()
@click.version_option(__version__, prog_name="skillguard")
def main():
    """🛡️ SkillGuard — AI Skill & Prompt Security Scanner"""
    pass


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["rich", "json", "sarif"]), default="rich", help="Output format")
@click.option("--severity", "-s", type=click.Choice(["critical", "high", "medium", "low", "info"]), default=None, help="Minimum severity filter")
@click.option("--deep", "-d", is_flag=True, help="Enable AST + Taint + OSV deep scanning")
@click.option("--sarif-output", type=click.Path(), default=None, help="Write SARIF to file")
def scan(target: str, output_format: str, severity: str | None, deep: bool, sarif_output: str | None):
    """Scan a file or directory for security threats."""
    scanner = StaticScanner()
    result = scanner.scan_directory(target)

    # Deep scanning: AST + Taint + OSV
    if deep:
        ast_scanner = ASTScanner()
        taint_tracker = TaintTracker()
        osv_checker = OSVChecker()

        target_path = Path(target)
        skip_dirs = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}

        if target_path.is_file() and target_path.suffix == ".py":
            result.findings.extend(ast_scanner.scan_file(target_path))
            result.findings.extend(taint_tracker.scan_file(target_path))
        elif target_path.is_dir():
            count = 0
            for fp in target_path.rglob("*.py"):
                if count >= 50:
                    break
                if any(skip in fp.parts for skip in skip_dirs):
                    continue
                result.findings.extend(ast_scanner.scan_file(fp))
                result.findings.extend(taint_tracker.scan_file(fp))
                count += 1

            # OSV dependency check
            for dep_name in {"requirements.txt", "requirements-dev.txt", "pyproject.toml",
                             "package.json", "Gemfile", "go.mod", "Cargo.toml", "pom.xml"}:
                dep_path = target_path / dep_name
                if dep_path.exists():
                    result.findings.extend(osv_checker.scan_file(dep_path))

        # Recalculate risk score with new findings (property-based, auto-recalculated)

    if output_format == "json":
        _print_json(result)
    elif output_format == "sarif":
        click.echo(sarif_to_json_string(result.findings, target))
        if sarif_output:
            write_scan_result_sarif(result, sarif_output)
            console.print(f"[dim]SARIF written to {sarif_output}[/dim]")
    else:
        _print_rich_report(result, severity_filter=severity)


@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
def analyze(file: str, json_output: bool):
    """Analyze a prompt file for injection patterns."""
    content = Path(file).read_text(encoding="utf-8", errors="replace")
    scanner = PromptScanner()
    findings = scanner.scan(content, source=file)

    if json_output:
        click.echo(json.dumps({
            "source": file,
            "findings": [_finding_dict(f) for f in findings],
        }, indent=2))
    else:
        _print_prompt_findings(file, findings)


def _print_json(result):
    click.echo(json.dumps({
        "target": result.target,
        "files_scanned": result.files_scanned,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "findings": [_finding_dict(f) for f in result.findings],
    }, indent=2))


def _print_rich_report(result, severity_filter=None):
    findings = result.findings
    if severity_filter:
        order = {"critical": 0, "high": 1, "warning": 2, "info": 3}
        min_idx = order.get(severity_filter, 3)
        findings = [f for f in findings if order.get(f.severity, 3) <= min_idx]

    # Header
    console.print()
    console.print(Panel(
        f"[bold]🔍 SkillGuard Report[/bold] — {result.target}\n"
        f"Files scanned: {result.files_scanned} | Duration: {result.duration_seconds}s",
        style="bold white on #1a1a2e",
    ))

    if not findings:
        console.print("[bold green]✅ No threats detected![/bold green]")
        return

    # Summary bar
    crit = result.critical_count()
    high = result.high_count()
    warn = result.warning_count()
    score = result.risk_score
    level_style = "bold red" if score >= 75 else "bold yellow" if score >= 50 else "bold cyan" if score >= 25 else "bold green"

    console.print(f"\n  🔴 Critical: {crit}  |  🟡 High: {high}  |  🔵 Warning: {warn}  |  "
                  f"Risk Score: [{level_style}]{score}/100[/]")
    console.print(f"  Risk Level: [{level_style}]{result.risk_level}[/]")
    console.print()

    # Findings table
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Category", width=18)
    table.add_column("File", style="cyan")
    table.add_column("Line", justify="right", width=5)
    table.add_column("Description")

    for i, f in enumerate(findings, 1):
        icon = SEVERITY_ICONS.get(f.severity, "⚪")
        sev_style = SEVERITY_STYLES.get(f.severity, "")
        # Shorten file path
        rel_path = f.file
        if len(rel_path) > 50:
            rel_path = "..." + rel_path[-47:]
        table.add_row(
            str(i),
            f"[{sev_style}]{icon} {f.severity.upper()}[/]",
            f.category,
            rel_path,
            str(f.line),
            f.description,
        )

    console.print(table)
    console.print()


def _print_prompt_findings(source, findings):
    console.print()
    console.print(Panel(
        f"[bold]💉 Prompt Injection Analysis[/bold] — {source}",
        style="bold white on #1a1a2e",
    ))

    if not findings:
        console.print("[bold green]✅ No injection patterns detected![/bold green]")
        return

    console.print(f"  Found [bold red]{len(findings)}[/bold red] suspicious pattern(s)\n")

    for i, f in enumerate(findings, 1):
        icon = SEVERITY_ICONS.get(f.severity, "⚪")
        sev_style = SEVERITY_STYLES.get(f.severity, "")
        console.print(f"  [{sev_style}]{icon} {f.severity.upper()}[/] — {f.description}")
        console.print(f"     [dim]Line {f.line}: {f.line_content}[/dim]")
        console.print()


def _finding_dict(f):
    return {
        "file": f.file,
        "line": f.line,
        "column": f.column,
        "severity": f.severity,
        "category": f.category,
        "description": f.description,
        "matched_text": f.matched_text,
    }


if __name__ == "__main__":
    main()
