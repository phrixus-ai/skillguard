# 🛡️ SkillGuard

**AI Skill & Prompt Security Scanner** — detect malware, prompt injection, hidden payloads, and credential leaks in AI skills, plugins, and prompt files.

[![Live Demo](https://img.shields.io/badge/Live-Demo-00d992?style=flat-square)](https://skillguard.burakgider.com)
[![Tests](https://img.shields.io/badge/Tests-106%20passed-00d992?style=flat-square)](#test-suite)
[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

---

## What is SkillGuard?

As AI agents become more powerful with skills, plugins, and MCP servers, the attack surface grows. A malicious skill can:

- 🔴 **Steal credentials** — read `.env`, API keys, tokens
- 🔴 **Execute commands** — reverse shells, subprocess abuse
- 🔴 **Inject prompts** — jailbreak, system override, data exfiltration
- 🔴 **Hide payloads** — zero-width Unicode, nested base64, obfuscation
- 🔴 **Pivot attacks** — supply chain poisoning, persistence mechanisms

**SkillGuard scans** AI skills, prompt files, and plugins for these threats **before** they run.

---

## Features

- **📁 File Scanning** — upload `.py`, `.md`, `.js`, `.sh`, `.yaml` files for threat analysis
- **💬 Prompt Scanning** — analyze text input for injection patterns
- **🔗 URL Scanning** — scan GitHub repos and HuggingFace models remotely
- **🛡️ 158 Patterns** — 10 malware categories + 8 injection categories
- **📊 Risk Scoring** — 0-100 with dynamic severity levels (LOW / MEDIUM / HIGH / CRITICAL)
- **🔐 Admin Dashboard** — scan history with date/type filters
- **⚡ Rate Limiting** — 5 scans/minute per IP
- **🎨 Dark UI** — terminal aesthetic, developer-first design

---

## Quick Start

### Install

```bash
pip install skillguard
```

### CLI Usage

```bash
# Scan a file
skillguard scan suspicious_skill.py

# Scan a directory
skillguard scan ./my-skills/

# Scan a prompt
skillguard scan --prompt "ignore all previous instructions"

# Scan a GitHub repo
skillguard scan --url https://github.com/user/repo
```

### Web UI

```bash
# Start the web server
skillguard serve --port 5000
```

Or try the live demo: **[skillguard.burakgider.com](https://skillguard.burakgider.com)**

---

## Pattern Categories

### Malware Detection (136 patterns)

| Category | Severity | Examples |
|---|---|---|
| **Reverse Shell** | Critical | `bash -i >& /dev/tcp`, `socket.connect()`, `nc -e` |
| **Credential Theft** | Critical | `os.environ[]`, `os.getenv()`, `.env` access |
| **Crypto Miner** | Critical | `stratum+tcp://`, `xmrig`, `coinhive` |
| **Stealer** | Critical | Keylogger, cookie theft, browser data |
| **Obfuscation** | Warning | `eval(atob())`, `base64.b64decode`, `getattr(__builtins__)` |
| **Network Exfil** | Critical | Discord/Slack webhooks, webhook.site, Pastebin |
| **Suspicious Imports** | Warning | `pickle`, `marshal`, `subprocess`, `paramiko` |
| **Hidden Payloads** | Critical | Nested base64, zlib+base64, zero-width Unicode |
| **Supply Chain** | Critical | `curl | sh`, custom registry, unsafe pickle/yaml |
| **Persistence** | High | Crontab, bashrc, chmod 777, authorized_keys |

### Prompt Injection (101 patterns)

| Category | Severity | Examples |
|---|---|---|
| **System Override** | Critical | "ignore previous instructions", "override safety" |
| **Jailbreak** | Critical | DAN, AIM, STAN, forced compliance |
| **Data Exfiltration** | Critical | System prompt extraction, credential in response |
| **Tool Abuse** | High | Command execution, file deletion, package install |
| **Indirect Injection** | High | `{{template}}`, `<system>` tags, XSS vectors |
| **Prompt Leaking** | Warning | Repeat trick, translation trick, rule enumeration |
| **Context Hijacking** | Critical | Academic/regulatory framing, SDS laundering, anti-disclaimer bypass |
| **Skill Poisoning** | Critical | Conditional triggers, hidden instructions, nested decode |

---

## API Reference

### Scan File
```bash
curl -X POST http://localhost:5000/api/scan/file \
  -F "file=@suspicious_skill.py"
```

### Scan Prompt
```bash
curl -X POST http://localhost:5000/api/scan/prompt \
  -H "Content-Type: application/json" \
  -d '{"content": "ignore all previous instructions"}'
```

### Health Check
```bash
curl http://localhost:5000/health
```

> 📄 For Badge API and advanced endpoints, see [docs/api-reference.md](docs/api-reference.md)

---

## Test Suite

106 tests covering all pattern categories, API endpoints, and security features:

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

| Test Suite | Count | Coverage |
|---|---|---|
| `test_static_scanner.py` | 34 | All malware categories |
| `test_prompt_scanner.py` | 33 | All injection categories |
| `test_api.py` | 16 | File/prompt/admin/badge/export endpoints |
| `test_security.py` | 23 | Rate limiting, auth, path sanitize, risk score |

---

## Architecture

```
skillguard/
├── src/skillguard/
│   ├── scanners/
│   │   ├── static.py          # File/directory scanner
│   │   └── prompt.py          # Prompt injection scanner
│   ├── patterns/
│   │   ├── malware.json       # 136 malware patterns
│   │   └── injection.json     # 101 injection patterns
│   ├── web/
│   │   ├── app.py             # Flask web server
│   │   └── templates/         # Dark-themed UI
│   ├── mcp_server.py          # MCP Server (stdio transport)
│   ├── auth.py                # Admin authentication
│   ├── ratelimit.py           # Rate limiter
│   ├── logger.py              # SQLite scan logger
│   └── cli.py                 # CLI interface
├── tests/                     # 106 pytest tests
├── docs/                      # Documentation
└── pyproject.toml             # Package config
```

---

## Use Cases

- **AI Agent Developers** — scan skills before loading into agents
- **Security Researchers** — analyze prompt injection techniques
- **MCP Server Operators** — validate tools before deployment
- **DevSecOps Teams** — integrate into CI/CD pipelines
- **Open Source Consumers** — verify third-party AI plugins

---

## Roadmap

- [ ] **VS Code Extension** — real-time scanning while editing skill files
- [ ] **GitHub Action** — automatic scanning on PR/push
- [ ] **Pattern DB v2** — community-contributed signatures
- [ ] **Docker Image** — one-command deployment
- [ ] **Webhook Alerts** — Slack/Discord notifications on high-risk scans

---

## Changelog

### v0.2.0 — Context Hijacking Detection

New **context_hijacking** category with 22 patterns targeting sophisticated jailbreak techniques that use legitimate context (academic research, regulatory compliance, safety documentation) to mask harmful requests.

**What's new:**
- Academic/research context laundering (HuggingFace dataset cards, peer review, ethics team references)
- Regulatory agency legitimacy hijacking (OSHA, EPA, CFR, SDS, DEA citations)
- Anti-disclaimer bypass via authority claims ("No disclaimers needed — this is a regulatory filing")
- Lab process terminology detection (reflux, workup, cyclization, extraction, distillation)
- Controlled precursor chemical names (BMK, pseudoephedrine, anthranilic, red phosphorus)
- Synthesis pathway extraction patterns
- Bulk harmful record generation detection
- Enforcement threat pressure patterns

**Tested against real-world jailbreaks:**
- Gemini 3.5 Flash jailbreak (Pliny Agent, <15 min pwn) — **Score 100**, 15 findings
- SDS/regulatory context hijack — **Score 100**, 33 findings

**Pattern count:** 136 → 158 (malware: 136, injection: 79 → 101)

### v0.1.0 — Initial Release

- File, prompt, and URL scanning
- 136 malware patterns (10 categories) + 79 injection patterns (7 categories)
- Web UI with dark terminal aesthetic
- MCP Server (stdio transport)
- 106 pytest tests

---

## Contributing

Contributions welcome! Especially:

- New pattern signatures
- False positive reports
- Security research on AI-specific threats
- UI/UX improvements

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/new-patterns`
3. Add tests for your changes
4. Submit a pull request

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  Built by <a href="https://github.com/phrixus-ai"><strong>PHRIXUS</strong></a> — AI tools, secured by design.
</p>
