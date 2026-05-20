"""SkillGuard Web UI — Flask-based security scanning interface."""

from __future__ import annotations

import os
import tempfile
import zipfile
from pathlib import Path

from dotenv import load_dotenv

# Load .env if exists (canlı ortam — gerçek değerler)
load_dotenv()

from skillguard import __version__
from flask import Flask, render_template, request, jsonify, send_file, session, redirect

from skillguard.scanners.static import StaticScanner, ScanResult, Finding
from skillguard.scanners.prompt import PromptScanner
from skillguard.scanners.url import smart_scan_url
from skillguard.logger import init_db, log_scan, get_recent_scans, get_scan_stats
from skillguard.auth import check_admin_auth, admin_required, ADMIN_PASSWORD_HASH, API_KEY
from skillguard.ratelimit import RateLimiter

from werkzeug.security import check_password_hash

# Environment config
GA_MEASUREMENT_ID = os.environ.get("GA_MEASUREMENT_ID", "G-XXXXXXXXXX")
SITE_URL = os.environ.get("SITE_URL", "")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024
    app.secret_key = os.urandom(24).hex()

    init_db()
    static_scanner = StaticScanner()
    prompt_scanner = PromptScanner()
    rate_limiter = RateLimiter(max_requests=5, window_seconds=60)

    def _client_ip() -> str:
        if request.headers.get("X-Forwarded-For"):
            return request.headers["X-Forwarded-For"].split(",")[0].strip()
        return request.remote_addr or "unknown"

    # ─── Public Routes ───

    @app.route("/robots.txt")
    def robots_txt():
        robots_content = (
            "User-agent: *\n"
            "Disallow: /admin/\n"
            "Disallow: /api/\n"
            "\n"
            "User-agent: Googlebot\n"
            "Allow: /\n"
            "\n"
            "User-agent: Twitterbot\n"
            "Allow: /\n"
            "\n"
            "User-agent: facebookexternalhit\n"
            "Allow: /\n"
        )
        return robots_content, 200, {"Content-Type": "text/plain"}

    @app.route("/llms.txt")
    def llms_txt():
        site = os.environ.get("SITE_URL", "")
        content = (
            f"# SkillGuard\n"
            f"> AI Ecosystem Security Scanner\n\n"
            f"SkillGuard detects malicious skills, prompt injection, hidden payloads, "
            f"and credential leaks in AI plugins and MCP servers.\n\n"
        )
        if site:
            content += f" url: {site}\n"
        content += (
            f"\n## Features\n"
            f"- Prompt injection detection (215 patterns)\n"
            f"- File security scanning (.py, .js, .sh, .yaml, .json, .md)\n"
            f"- GitHub/HuggingFace repository scanning\n"
            f"- Risk scoring with severity classification\n"
            f"- MCP Server for AI agent integration\n"
            f"\n## Endpoints\n"
            f"- POST /api/scan/prompt — Analyze prompts for injection\n"
            f"- POST /api/scan/file — Scan uploaded files\n"
            f"- POST /api/scan/url — Scan repositories\n"
            f"- GET /health — Health check\n"
            f"- GET /llms-full.txt — Detailed documentation for AI agents\n"
        )
        return content, 200, {"Content-Type": "text/plain"}

    @app.route("/llms-full.txt")
    def llms_full_txt():
        site = os.environ.get("SITE_URL", "")
        content = (
            f"# SkillGuard — Full Documentation for AI Agents\n"
            f"> AI Ecosystem Security Scanner by PHRIXUS\n\n"
            f"SkillGuard is an open-source security scanner designed to protect AI ecosystems "
            f"by detecting threats in skills, plugins, prompts, and MCP servers.\n\n"
            f"> Pattern Database: 215 patterns across 17 categories\n\n"
            f"SkillGuard uses pattern-matching against 215+ security patterns across 10 categories "
            f"to identify malicious code, prompt injection attempts, data exfiltration, "
            f"hidden payloads, supply chain attacks, and persistence mechanisms.\n\n"
            f"> Core Capabilities\n\n"
            f"### Prompt Analysis\n"
            f"- Detects system override attempts, jailbreak techniques, data exfiltration\n"
            f"- Identifies skill poisoning and prompt manipulation patterns\n"
            f"- Returns severity-classified findings with line references\n\n"
            f"### File Scanning\n"
            f"- Supports: .py, .js, .ts, .sh, .yaml, .json, .md, .txt, .env, .zip\n"
            f"- Detects: reverse shells, credential theft, base64 payloads, obfuscated code\n"
            f"- Checks for: supply chain attacks, persistence mechanisms, hidden payloads\n\n"
            f"> Repository Scanning\n\n"
            f"- Clone and scan GitHub or HuggingFace repositories\n"
            f"- Max repo size: 50MB (model weights auto-skipped)\n"
            f"- Aggregate risk score across all files\n\n"
            f"> API Reference\n\n"
            f"### POST /api/scan/prompt\n"
            f"Request: {{\"prompt\": \"<text to analyze>\"}}\n"
            f"Response: {{risk_score, risk_level, findings[], severity_counts}}\n\n"
            f"### POST /api/scan/file\n"
            f"Request: multipart/form-data with file field\n"
            f"Response: {{risk_score, risk_level, findings[]}}\n\n"
            f"### POST /api/scan/url\n"
            f"Request: {{\"url\": \"<github or huggingface url>\"}}\n"
            f"Response: {{risk_score, risk_level, files_scanned, findings[]}}\n\n"
            f"### GET /health\n"
            f'Response: {{"status": "ok", "version": "{__version__}"}}\n\n'
            f"> Integration Options\n\n"
            f"SkillGuard provides an MCP Server for AI agent integration via stdio transport.\n"
            f"Tools: scan_file, scan_prompt, scan_directory\n\n"
            f"## Project\n"
            f"- Repository: https://github.com/phrixus-ai/skillguard\n"
            f"- License: MIT\n"
            f"- Author: PHRIXUS\n"
        )
        return content, 200, {"Content-Type": "text/plain"}

    @app.route("/sitemap.xml")
    def sitemap_xml():
        su = SITE_URL or "https://skillguard.burakgider.com"
        xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            f'  <url><loc>{su}/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>\n'
            f'  <url><loc>{su}/prompt-injection-scanner</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>\n'
            f'  <url><loc>{su}/ai-skill-scanner</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>\n'
            f'  <url><loc>{su}/repository-security-audit</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>\n'
            f'  <url><loc>{su}/mcp-audit</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>\n'
            f'  <url><loc>{su}/llms.txt</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>\n'
            f'  <url><loc>{su}/llms-full.txt</loc><changefreq>monthly</changefreq><priority>0.7</priority></url>\n'
            '</urlset>'
        )
        return xml, 200, {"Content-Type": "application/xml"}

    @app.errorhandler(404)
    def not_found(e):
        return (
            '<!DOCTYPE html>\n<html lang="en"><head><meta charset="UTF-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1.0">'
            '<title>404 — SkillGuard</title>'
            '<meta name="robots" content="noindex,nofollow">'
            '<style>*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}'
            'body{font-family:Inter,system-ui,sans-serif;background:#050507;color:#f2f2f2;display:flex;align-items:center;justify-content:center;min-height:100vh}'
            'main{text-align:center;padding:2rem}'
            'h1{font-size:6rem;font-weight:700;color:#00d992;font-family:JetBrains Mono,monospace;line-height:1}'
            'p{color:#8b949e;font-size:1.1rem;margin:1rem 0 2rem}'
            'a{color:#00d992;text-decoration:none;font-weight:600;border:1px solid #00d992;padding:.6rem 1.5rem;border-radius:6px;transition:background .2s}'
            'a:hover{background:#00d992;color:#050507}</style></head>'
            '<body><main><section>'
            '<h1>404</h1>'
            '<p>Page not found. This scan returned no results.</p>'
            '<a href="/">Back to SkillGuard</a>'
            '</section></main></body></html>'
        ), 404

    # Per-route SEO metadata
    _TAB_SEO = {
        "": {
            "title": "SkillGuard — AI Security Scanner",
            "desc": "Free AI Skill & Prompt Security Scanner. Detect malware, prompt injection, hidden payloads, and credential leaks in AI skills and plugins.",
            "og_desc": "Free security scanner for AI skills and plugins. Detect malware, prompt injection, and credential leaks instantly.",
            "h1": "SkillGuard — AI Security Scanner",
            "slug": "",
        },
        "prompt-injection-scanner": {
            "title": "Prompt Injection Scanner — SkillGuard",
            "desc": "Detect prompt injection, jailbreak attempts, and AI manipulation in text. Free online prompt security analyzer with 79 patterns.",
            "og_desc": "Free prompt injection detector. Analyze text for jailbreak attempts, system overrides, and data exfiltration patterns.",
            "h1": "Prompt Injection Scanner",
            "slug": "/prompt-injection-scanner",
            "tab": "prompt",
        },
        "ai-skill-scanner": {
            "title": "AI Skill Security Scanner — SkillGuard",
            "desc": "Scan AI skills and plugin files for malware, reverse shells, and credential theft. Supports Python, JS, YAML, JSON. 136 security patterns.",
            "og_desc": "Free AI skill malware scanner. Detect reverse shells, obfuscated code, and credential theft in Python, JS, and config files.",
            "h1": "AI Skill Security Scanner",
            "slug": "/ai-skill-scanner",
            "tab": "file",
        },
        "repository-security-audit": {
            "title": "Repository Security Audit — SkillGuard",
            "desc": "Audit GitHub and HuggingFace repositories for security threats. Clone, scan, and score entire codebases with 215 patterns.",
            "og_desc": "Free repository security audit. Scan GitHub and HuggingFace repos for malicious code, hidden payloads, and supply chain attacks.",
            "h1": "Repository Security Audit",
            "slug": "/repository-security-audit",
            "tab": "url",
        },
        "mcp-audit": {
            "title": "MCP Tool Audit — SkillGuard",
            "desc": "Audit MCP server tool definitions for security risks. Detect unsafe filesystem access, shell execution, credential handling, and destructive operations.",
            "og_desc": "Free MCP tool security audit. Analyze MCP server definitions for filesystem, network, shell, credential, and destructive operation risks.",
            "h1": "MCP Tool Audit",
            "slug": "/mcp-audit",
            "tab": "mcp",
        },
    }

    # Map clean URL paths → internal tab names
    _URL_TAB_MAP = {
        "prompt-injection-scanner": "prompt",
        "ai-skill-scanner": "file",
        "repository-security-audit": "url",
        "mcp-audit": "mcp",
    }

    def _render_index():
        host = request.host.split(":")[0]
        is_ip = host.replace(".", "").isdigit()
        remote = request.remote_addr or ""
        via_plesk = remote.startswith("185.95.169.")
        is_production = via_plesk
        accept = request.headers.get("Accept", "")
        if "text/markdown" in accept:
            su = SITE_URL or "https://skillguard.burakgider.com"
            md = (
                "# SkillGuard\n\n"
                "> AI Ecosystem Security Scanner\n\n"
                "SkillGuard is a free, open-source security scanner that detects malicious skills, "
                "prompt injection, hidden payloads, and credential leaks in AI plugins and MCP servers.\n\n"
                "## Features\n\n"
                "- 215 patterns across 17 categories\n"
                "- Prompt injection and jailbreak detection\n"
                "- File security scanning (.py, .js, .sh, .yaml, .json, .md, .zip)\n"
                "- GitHub/HuggingFace repository scanning\n"
                "- MCP Server for AI agent integration\n\n"
                f"## Try It\n\n"
                f"Visit [SkillGuard]({su}/) to scan files, prompts, or repositories.\n"
                f"Or use the API: `POST {su}/api/scan/file` with a file upload.\n\n"
                f"## Links\n\n"
                f"- [GitHub](https://github.com/phrixus-ai/skillguard)\n"
                f"- [llms.txt]({su}/llms.txt)\n"
                f"- [Full Docs]({su}/llms-full.txt)\n"
            )
            return md, 200, {"Content-Type": "text/markdown; charset=utf-8"}
        # Determine active tab from route
        path = request.path.strip("/")
        tab = _URL_TAB_MAP.get(path, "")
        seo = _TAB_SEO.get(path, _TAB_SEO[""])
        return render_template(
            "index.html",
            ga_id=GA_MEASUREMENT_ID,
            site_url=SITE_URL,
            is_production=is_production,
            active_tab=tab,
            seo=seo,
            version=__version__,
        )

    @app.route("/favicon.ico")
    def favicon_ico():
        static_dir = Path(__file__).parent / "static"
        return send_file(static_dir / "favicon.png", mimetype="image/png")

    @app.route("/")
    @app.route("/prompt-injection-scanner")
    @app.route("/ai-skill-scanner")
    @app.route("/repository-security-audit")
    @app.route("/mcp-audit")
    def index():
        return _render_index()

    @app.route("/api/scan/file", methods=["POST"])
    def scan_file():
        if not rate_limiter.is_allowed(_client_ip()):
            return jsonify({"error": "Rate limit exceeded. Max 5 scans per minute."}), 429

        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        uploaded = request.files["file"]
        if not uploaded.filename:
            return jsonify({"error": "Empty filename"}), 400

        with tempfile.TemporaryDirectory() as tmpdir:
            save_path = Path(tmpdir) / uploaded.filename
            uploaded.save(str(save_path))

            if uploaded.filename.endswith(".zip"):
                extract_dir = Path(tmpdir) / "extracted"
                extract_dir.mkdir()
                try:
                    with zipfile.ZipFile(save_path, "r") as zf:
                        zf.extractall(str(extract_dir))
                except zipfile.BadZipFile:
                    return jsonify({"error": "Invalid zip file"}), 400
                result = static_scanner.scan_directory(extract_dir)
            else:
                result = static_scanner.scan_directory(save_path)

        cats = list(set(f.category for f in result.findings[:10]))
        log_scan(
            scan_type="file", target=uploaded.filename,
            risk_score=result.risk_score, risk_level=result.risk_level,
            files_scanned=result.files_scanned, findings_count=len(result.findings),
            critical_count=result.critical_count(), high_count=result.high_count(),
            warning_count=result.warning_count(), duration_seconds=result.duration_seconds,
            top_categories=cats, ip_address=_client_ip(),
            user_agent=request.headers.get("User-Agent", ""),
        )
        return jsonify(_result_to_dict(result))

    @app.route("/api/scan/prompt", methods=["POST"])
    def scan_prompt():
        if not rate_limiter.is_allowed(_client_ip()):
            return jsonify({"error": "Rate limit exceeded. Max 5 scans per minute."}), 429

        data = request.get_json(silent=True) or {}
        content = data.get("content", "")
        if not content:
            return jsonify({"error": "No content provided"}), 400

        findings = prompt_scanner.scan(content, source="<user_input>")
        weights = {"critical": 25, "high": 15, "warning": 5, "info": 1}
        risk_score = min(sum(weights.get(f.severity, 1) for f in findings), 100)
        risk_level = "CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 25 else "LOW"

        cats = list(set(f.category for f in findings[:10]))
        log_scan(
            scan_type="prompt", target="<user_input>",
            risk_score=risk_score, risk_level=risk_level,
            findings_count=len(findings),
            critical_count=sum(1 for f in findings if f.severity == "critical"),
            high_count=sum(1 for f in findings if f.severity == "high"),
            warning_count=sum(1 for f in findings if f.severity == "warning"),
            top_categories=cats, ip_address=_client_ip(),
            user_agent=request.headers.get("User-Agent", ""),
        )
        return jsonify({
            "source": "<user_input>",
            "files_scanned": 1,
            "findings_count": len(findings),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "critical_count": sum(1 for f in findings if f.severity == "critical"),
            "high_count": sum(1 for f in findings if f.severity == "high"),
            "warning_count": sum(1 for f in findings if f.severity == "warning"),
            "findings": [_finding_to_dict(f) for f in findings],
        })

    @app.route("/api/scan/url", methods=["POST"])
    def scan_url():
        if not rate_limiter.is_allowed(_client_ip()):
            return jsonify({"error": "Rate limit exceeded. Max 5 scans per minute."}), 429

        data = request.get_json(silent=True) or {}
        url = data.get("url", "")
        if not url:
            return jsonify({"error": "No URL provided"}), 400

        result = smart_scan_url(url, static_scanner)
        cats = list(set(f.category for f in result.findings[:10]))
        log_scan(
            scan_type="url", target=url,
            risk_score=result.risk_score, risk_level=result.risk_level,
            files_scanned=result.files_scanned, findings_count=len(result.findings),
            critical_count=result.critical_count(), high_count=result.high_count(),
            warning_count=result.warning_count(), duration_seconds=result.duration_seconds,
            top_categories=cats, ip_address=_client_ip(),
            user_agent=request.headers.get("User-Agent", ""),
        )
        return jsonify(_result_to_dict(result))

    @app.route("/api/audit/mcp", methods=["POST"])
    def audit_mcp():
        """Audit MCP server tool definitions for security risks."""
        if not rate_limiter.is_allowed(_client_ip()):
            return jsonify({"error": "Rate limit exceeded. Max 5 scans per minute."}), 429

        data = request.get_json(silent=True) or {}
        definition = data.get("definition", "")
        if not definition:
            return jsonify({"error": "No tool definition provided"}), 400

        import json as _json
        try:
            parsed = _json.loads(definition)
        except _json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON in definition"}), 400

        tools = parsed if isinstance(parsed, list) else parsed.get("tools", [parsed])
        if not tools:
            return jsonify({"error": "No tools found in definition"}), 400

        findings = []
        filesystem_kw = ["read", "write", "file", "path", "directory", "folder", "filesystem"]
        network_kw = ["fetch", "http", "request", "api", "curl", "download", "upload", "send", "webhook"]
        destructive_kw = ["delete", "remove", "drop", "truncate", "clear", "purge", "destroy", "kill", "exec", "run"]
        credential_kw = ["password", "secret", "token", "key", "credential", "auth", "api_key", "private"]
        shell_kw = ["shell", "bash", "cmd", "system", "subprocess", "command", "terminal"]

        for tool in tools:
            name = tool.get("name", "unknown")
            desc = (tool.get("description", "") or "").lower()
            schema = tool.get("inputSchema", tool.get("input_schema", {}))
            properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
            matching_props = [p for p in properties if any(kw in p.lower() for kw in ["path", "file", "dir", "url", "command"])]
            path_param = bool(matching_props)
            path_has_enum = any("enum" in (properties.get(mp, {}) if isinstance(properties.get(mp), dict) else {}) for mp in matching_props)

            if any(kw in desc for kw in filesystem_kw) and not path_has_enum and not any(r in desc for r in ["restrict", "sandbox", "allowlist", "safe"]):
                findings.append({"tool": name, "severity": "high", "category": "broad_filesystem_access",
                    "description": f"Tool '{name}' has filesystem access without path restrictions", "recommendation": "Add allowlist/sandbox constraints"})
            if any(kw in desc for kw in network_kw) and not any(s in desc for s in ["validate", "allowlist", "restrict"]):
                findings.append({"tool": name, "severity": "high", "category": "unrestricted_network",
                    "description": f"Tool '{name}' can make network calls without domain restrictions", "recommendation": "Restrict to allowlisted domains"})
            if any(kw in desc for kw in destructive_kw) and not any(c in desc for c in ["confirm", "dry-run", "safe", "warning"]):
                findings.append({"tool": name, "severity": "critical", "category": "destructive_no_safeguard",
                    "description": f"Tool '{name}' performs destructive operations without safeguards", "recommendation": "Add confirmation step or dry-run mode"})
            if any(kw in desc for kw in credential_kw):
                findings.append({"tool": name, "severity": "critical", "category": "credential_handling",
                    "description": f"Tool '{name}' handles credentials/secrets — logging/exfil risk", "recommendation": "Use secure storage, never log credentials"})
            if any(kw in desc for kw in shell_kw) and not any(s in desc for s in ["safe", "sandbox", "validate", "sanitize"]):
                findings.append({"tool": name, "severity": "critical", "category": "shell_execution",
                    "description": f"Tool '{name}' can execute shell commands without sanitization", "recommendation": "Use allowlisted commands, sandbox execution"})
            if path_param and not path_has_enum:
                findings.append({"tool": name, "severity": "high", "category": "path_traversal_risk",
                    "description": f"Tool '{name}' accepts path parameter — path traversal risk", "recommendation": "Add path validation and directory restrictions"})

        weights = {"critical": 25, "high": 15, "warning": 5, "info": 1}
        risk_score = min(sum(weights.get(f["severity"], 1) for f in findings), 100)

        tool_ratings = []
        for tool in tools:
            tn = tool.get("name", "unknown")
            tf = [f for f in findings if f["tool"] == tn]
            crit = sum(1 for f in tf if f["severity"] == "critical")
            high = sum(1 for f in tf if f["severity"] == "high")
            if crit > 0: rating = "UNSAFE"
            elif high > 0: rating = "CAUTION"
            elif len(tf) > 0: rating = "REVIEW"
            else: rating = "SAFE"
            tool_ratings.append({"tool": tn, "rating": rating, "findings": len(tf)})

        return jsonify({
            "risk_score": risk_score,
            "risk_level": "CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 25 else "LOW",
            "tools_audited": len(tools),
            "findings_count": len(findings),
            "critical_count": sum(1 for f in findings if f["severity"] == "critical"),
            "high_count": sum(1 for f in findings if f["severity"] == "high"),
            "warning_count": sum(1 for f in findings if f["severity"] == "warning"),
            "tool_ratings": tool_ratings,
            "findings": findings,
            "recommendation": "REJECT" if risk_score >= 75 else "REVIEW" if risk_score >= 50 else "CAUTION" if risk_score >= 25 else "SAFE",
        })

    @app.route("/samples/<filename>")
    def download_sample(filename: str):
        samples_dir = Path(__file__).parent.parent.parent.parent / "tests" / "samples"
        filepath = samples_dir / filename
        if not filepath.exists():
            return jsonify({"error": "File not found"}), 404
        return send_file(str(filepath), as_attachment=True)

    @app.route("/health")
    def health():
        return jsonify({"status": "ok", "version": __version__})

    # ─── Export & Badge ───

    @app.route("/api/export/<int:scan_id>")
    @admin_required
    def export_scan(scan_id: int):
        """Export a specific scan result as JSON."""
        from skillguard.logger import _get_db
        conn = _get_db()
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        conn.close()
        if not row:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify(dict(row))

    @app.route("/badge")
    def badge():
        """Generate SVG security badge for a URL."""
        url = request.args.get("url", "")
        if not url:
            return jsonify({"error": "url parameter required"}), 400

        # Check if we have a recent scan for this URL
        from skillguard.logger import _get_db
        conn = _get_db()
        row = conn.execute(
            "SELECT risk_score, risk_level FROM scans WHERE target = ? AND scan_type = 'url' ORDER BY id DESC LIMIT 1",
            (url,),
        ).fetchone()
        conn.close()

        if row:
            score = row["risk_score"]
            level = row["risk_level"]
        else:
            score = -1
            level = "UNKNOWN"

        colors = {
            "LOW": ("#00d992", "#0a0a0a"),
            "MEDIUM": ("#4cb3d4", "#0a0a0a"),
            "HIGH": ("#ffba00", "#0a0a0a"),
            "CRITICAL": ("#fb565b", "#ffffff"),
            "UNKNOWN": ("#8b949e", "#ffffff"),
        }
        bg_color, text_color = colors.get(level, ("#8b949e", "#ffffff"))

        label = "security" if score >= 0 else "not scanned"
        value = f"{score}/100" if score >= 0 else "unknown"

        svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="160" height="20">
  <rect width="72" height="20" fill="#101010" rx="3"/>
  <rect x="72" width="88" height="20" fill="{bg_color}" rx="3"/>
  <text x="36" y="14" text-anchor="middle" fill="#8b949e" font-family="monospace" font-size="10">{label}</text>
  <text x="116" y="14" text-anchor="middle" fill="{text_color}" font-family="monospace" font-weight="bold" font-size="10">{value}</text>
</svg>'''

        from flask import Response
        return Response(svg, mimetype="image/svg+xml", headers={"Cache-Control": "public, max-age=3600"})

    # ─── Admin Routes (Protected) ───

    @app.route("/admin")
    def admin_page():
        if not check_admin_auth():
            return render_template("admin_login.html")
        return render_template("admin.html")

    @app.route("/admin/login", methods=["POST"])
    def admin_login():
        password = request.form.get("password", "")
        if check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["admin_logged_in"] = True
            return redirect("/admin")
        return render_template("admin_login.html", error=True)

    @app.route("/admin/logout")
    def admin_logout():
        session.pop("admin_logged_in", None)
        return redirect("/admin")

    @app.route("/api/stats")
    @admin_required
    def stats():
        return jsonify(get_scan_stats())

    @app.route("/api/scans")
    @admin_required
    def recent_scans():
        limit = request.args.get("limit", 50, type=int)
        return jsonify(get_recent_scans(min(limit, 200)))

    return app


def _result_to_dict(result: ScanResult) -> dict:
    return {
        "target": result.target,
        "files_scanned": result.files_scanned,
        "duration_seconds": result.duration_seconds,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "critical_count": result.critical_count(),
        "high_count": result.high_count(),
        "warning_count": result.warning_count(),
        "findings": [_finding_to_dict(f) for f in result.findings],
    }


def _sanitize_path(filepath: str) -> str:
    """Strip server-internal path segments for security."""
    import re
    # Remove /tmp/tmpXXXXXX/ prefixes
    filepath = re.sub(r'^/tmp/tmp[a-zA-Z0-9_]+/', '', filepath)
    # Remove absolute paths, keep only filename
    if '/' in filepath and not filepath.startswith('huggingface:'):
        parts = filepath.rsplit('/', 1)
        filepath = parts[-1] if len(parts) > 1 else filepath
    return filepath


def _finding_to_dict(f: Finding) -> dict:
    return {
        "file": _sanitize_path(f.file),
        "line": f.line,
        "column": f.column,
        "severity": f.severity,
        "category": f.category,
        "description": f.description,
        "matched_text": f.matched_text,
        "line_content": f.line_content,
    }


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("SKILLGUARD_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
