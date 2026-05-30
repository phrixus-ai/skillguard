"""Smart URL Scanner — GitHub, Hugging Face, and generic repo scanning with file filtering."""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from skillguard.scanners.static import StaticScanner, ScanResult

# Only scan these extensions — skip model weights, images, binaries
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".ps1",
    ".rb", ".go", ".rs", ".java", ".php", ".pl", ".lua",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
    ".md", ".txt", ".env",
    ".html", ".htm", ".css", ".svg",
    ".dockerfile",
}

# Always skip these
SKIP_PATTERNS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
    ".bin", ".safetensors", ".gguf", ".pt", ".pth", ".onnx",
    ".h5", ".pkl", ".npy", ".npz", ".tar", ".gz", ".zip",
    ".woff", ".woff2", ".ttf", ".eot", ".ico", ".png", ".jpg",
    ".jpeg", ".gif", ".mp4", ".mp3", ".wav", ".avi", ".mov",
}

MAX_REPO_SIZE_MB = 50
MAX_FILE_SIZE_KB = 2048  # 2MB per file


def is_huggingface_url(url: str) -> bool:
    return "huggingface.co" in url


def is_github_url(url: str) -> bool:
    return "github.com" in url


def _should_scan(filepath: Path) -> bool:
    name = filepath.name.lower()
    if any(skip in name for skip in SKIP_PATTERNS):
        return False
    if filepath.suffix.lower() in SCAN_EXTENSIONS:
        return True
    # Check extensionless files like Dockerfile, Makefile
    if name in {"dockerfile", "makefile", "rakefile", "gemfile"}:
        return True
    return False


def scan_huggingface(url: str, scanner: StaticScanner, ast_scanner=None,
                    taint_tracker=None, osv_checker=None) -> ScanResult:
    """Scan a Hugging Face repo using the API — no model weight downloads."""
    import time
    start = time.time()

    # Parse repo from URL: huggingface.co/user/repo or huggingface.co/user/repo/tree/main
    parsed = urlparse(url)
    parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(parts) < 2:
        result = ScanResult(target=url, files_scanned=0)
        result.duration_seconds = round(time.time() - start, 2)
        return result

    repo_id = f"{parts[0]}/{parts[1]}"
    api_url = f"https://huggingface.co/api/models/{repo_id}"

    # Get file tree from API
    try:
        proc = subprocess.run(
            ["curl", "-sL", "--max-time", "15", api_url],
            capture_output=True, text=True, timeout=20,
        )
        data = json.loads(proc.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        # Fallback to git clone with sparse checkout
        return _clone_and_scan(url, scanner, ast_scanner, taint_tracker, osv_checker)

    siblings = data.get("siblings", [])
    scan_files = []
    for s in siblings:
        rfname = s.get("rfilename", "")
        ext = Path(rfname).suffix.lower()
        if ext in SCAN_EXTENSIONS or Path(rfname).name.lower() in SCAN_EXTENSIONS:
            scan_files.append(rfname)

    if not scan_files:
        result = ScanResult(target=url, files_scanned=0)
        result.duration_seconds = round(time.time() - start, 2)
        return result

    # Download and scan each file
    import tempfile
    all_findings = []
    py_files = []  # Collect .py files for AST scan
    with tempfile.TemporaryDirectory() as tmpdir:
        for rfname in scan_files[:100]:  # Max 100 files
            file_url = f"https://huggingface.co/{repo_id}/resolve/main/{rfname}"
            local_path = Path(tmpdir) / rfname
            local_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                subprocess.run(
                    ["curl", "-sL", "--max-time", "10", "--output", str(local_path), file_url],
                    capture_output=True, timeout=15,
                )
                if local_path.exists() and local_path.stat().st_size < MAX_FILE_SIZE_KB * 1024:
                    findings = scanner.scan_file(local_path)
                    for f in findings:
                        f.file = f"huggingface:{repo_id}/{rfname}"
                    all_findings.extend(findings)
                    if local_path.suffix == ".py":
                        py_files.append(local_path)
            except (subprocess.TimeoutExpired, Exception):
                continue

        # AST + Taint scan on Python files
        if ast_scanner and py_files:
            for py_path in py_files[:50]:
                try:
                    ast_findings = ast_scanner.scan_file(py_path)
                    for f in ast_findings:
                        f.file = f"huggingface:{repo_id}/{f.file}"
                    all_findings.extend(ast_findings)
                    if taint_tracker:
                        taint_findings = taint_tracker.scan_file(py_path)
                        for f in taint_findings:
                            f.file = f"huggingface:{repo_id}/{f.file}"
                        all_findings.extend(taint_findings)
                except Exception:
                    continue

    result = ScanResult(target=url, files_scanned=len(scan_files))
    result.findings = all_findings
    result.duration_seconds = round(time.time() - start, 2)
    return result


def scan_github(url: str, scanner: StaticScanner, ast_scanner=None,
                taint_tracker=None, osv_checker=None) -> ScanResult:
    """Scan a GitHub repo using git clone with depth 1."""
    # Convert URL to git clone URL if needed
    clone_url = url
    if clone_url.endswith("/"):
        clone_url = clone_url[:-1]
    if not clone_url.endswith(".git"):
        clone_url += ".git"
    return _clone_and_scan(clone_url, scanner, ast_scanner, taint_tracker, osv_checker)


def _clone_and_scan(url: str, scanner: StaticScanner, ast_scanner=None,
                    taint_tracker=None, osv_checker=None) -> ScanResult:
    """Clone repo with depth 1, filter files, and scan."""
    import time
    start = time.time()

    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir) / "repo"
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(repo_dir)],
                capture_output=True, timeout=60,
            )
        except subprocess.TimeoutExpired:
            result = ScanResult(target=url, files_scanned=0)
            result.duration_seconds = round(time.time() - start, 2)
            return result

        if not repo_dir.exists():
            result = ScanResult(target=url, files_scanned=0)
            result.duration_seconds = round(time.time() - start, 2)
            return result

        # Check total size
        total_size = sum(f.stat().st_size for f in repo_dir.rglob("*") if f.is_file())
        if total_size > MAX_REPO_SIZE_MB * 1024 * 1024:
            result = ScanResult(target=url, files_scanned=0)
            result.duration_seconds = round(time.time() - start, 2)
            return result

        # Filter and scan only relevant files
        all_findings = []
        files_scanned = 0
        for filepath in repo_dir.rglob("*"):
            if not filepath.is_file():
                continue
            if any(skip in filepath.parts for skip in {".git", "node_modules", "__pycache__"}):
                continue
            if filepath.stat().st_size > MAX_FILE_SIZE_KB * 1024:
                continue
            if not _should_scan(filepath):
                continue

            files_scanned += 1
            findings = scanner.scan_file(filepath)
            # Make paths relative to repo root
            for f in findings:
                try:
                    f.file = str(filepath.relative_to(repo_dir))
                except ValueError:
                    pass
            all_findings.extend(findings)

        # AST + Taint scan on Python files
        if ast_scanner:
            py_count = 0
            for py_path in repo_dir.rglob("*.py"):
                if py_count >= 50:
                    break
                if any(skip in py_path.parts for skip in {".git", "node_modules", "__pycache__", ".venv"}):
                    continue
                try:
                    ast_findings = ast_scanner.scan_file(py_path)
                    for f in ast_findings:
                        try:
                            f.file = str(py_path.relative_to(repo_dir))
                        except ValueError:
                            pass
                    all_findings.extend(ast_findings)
                    if taint_tracker:
                        taint_findings = taint_tracker.scan_file(py_path)
                        for f in taint_findings:
                            try:
                                f.file = str(py_path.relative_to(repo_dir))
                            except ValueError:
                                pass
                        all_findings.extend(taint_findings)
                    py_count += 1
                except Exception:
                    continue

        # OSV dependency check
        if osv_checker:
            for dep_name in {"requirements.txt", "pyproject.toml", "package.json"}:
                dep_path = repo_dir / dep_name
                if dep_path.exists():
                    try:
                        osv_findings = osv_checker.scan_file(dep_path)
                        all_findings.extend(osv_findings)
                    except Exception:
                        pass

    result = ScanResult(target=url, files_scanned=files_scanned)
    result.findings = all_findings
    result.duration_seconds = round(time.time() - start, 2)
    return result


def smart_scan_url(url: str, scanner: StaticScanner, ast_scanner=None,
                  taint_tracker=None, osv_checker=None) -> ScanResult:
    """Smart URL scanner — picks the best strategy based on URL type."""
    if is_huggingface_url(url):
        return scan_huggingface(url, scanner, ast_scanner, taint_tracker, osv_checker)
    elif is_github_url(url):
        return scan_github(url, scanner, ast_scanner, taint_tracker, osv_checker)
    else:
        return _clone_and_scan(url, scanner, ast_scanner, taint_tracker, osv_checker)
