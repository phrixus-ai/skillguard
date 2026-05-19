# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅ Active |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a vulnerability in SkillGuard, please report it responsibly.

### How to Report

**Do NOT open a public GitHub issue.**

Instead, please:

1. Go to the [Security tab](https://github.com/phrixus-ai/skillguard/security) of this repository
2. Click **"Report a vulnerability"**
3. Fill in the details

Or email the maintainer directly via GitHub.

### What to Include

- **Description** of the vulnerability
- **Steps to reproduce** the issue
- **Potential impact** (what could an attacker do?)
- **Suggested fix** (if you have one)

### Response Timeline

- **Acknowledgment** — within 48 hours
- **Initial assessment** — within 7 days
- **Fix & disclosure** — depends on severity, typically within 30 days

### Responsible Disclosure

We kindly ask that you:

- Give us reasonable time to fix the issue before public disclosure
- Do not access or modify other users' data
- Do not degrade the quality of service (e.g., DoS)

## Security Features

SkillGuard itself includes several security measures:

- Rate limiting (5 scans/minute per IP)
- Path sanitization (no directory traversal)
- Admin authentication
- Input validation on all endpoints
- No execution of scanned code

## Scope

This policy covers:

- The SkillGuard web application
- CLI tool
- MCP server
- Pattern detection engine

Out of scope:

- Third-party dependencies (report to their maintainers)
- Social engineering attacks
- Physical attacks

---

Thank you for helping keep SkillGuard and its users safe! 🛡️
