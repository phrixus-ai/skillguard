# Contributing to SkillGuard

Thank you for your interest in contributing to SkillGuard! We welcome contributions from everyone.

## Ways to Contribute

- **Report bugs** — Open an issue with steps to reproduce
- **Suggest features** — Open an issue with the `enhancement` label
- **Submit patterns** — Add new detection signatures (see below)
- **Fix issues** — Pick from [open issues](https://github.com/phrixus-ai/skillguard/issues)
- **Improve docs** — Fix typos, add examples, clarify instructions

## Development Setup

```bash
# Clone the repository
git clone https://github.com/phrixus-ai/skillguard.git
cd skillguard

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

## Adding New Patterns

SkillGuard's detection power comes from its pattern database. Here's how to add new patterns:

### Malware Patterns (`src/skillguard/patterns/malware.json`)

```json
{
  "category": "your_category",
  "name": "Pattern name",
  "severity": "critical|high|warning",
  "description": "What this pattern detects",
  "patterns": ["regex_pattern_here"],
  "false_positives": ["Known false positive strings"]
}
```

### Prompt Injection Patterns (`src/skillguard/patterns/injection.json`)

Same format, different categories:
- `system_override` — Instructions that override AI behavior
- `jailbreak` — Known jailbreak techniques
- `data_exfiltration` — Attempts to extract sensitive data
- `tool_abuse` — Misuse of tool/function calling
- `skill_poisoning` — Hidden instructions in skills/plugins

### Pattern Guidelines

1. **Test your patterns** — Add test cases in `tests/fixtures/` and corresponding tests
2. **Minimize false positives** — Include common safe patterns in `false_positives`
3. **Use descriptive names** — `python_reverse_shell_tcp` not `bad_pattern_1`
4. **Set appropriate severity**:
   - `critical` — Immediate security risk (RCE, credential theft)
   - `high` — Significant risk (persistence, privilege escalation)
   - `warning` — Suspicious but may have legitimate uses

## Pull Request Process

1. **Fork** the repository
2. Create a **feature branch**: `git checkout -b feature/your-feature`
3. Make your changes
4. **Add tests** for new functionality
5. Ensure all tests pass: `pytest tests/ -v`
6. **Update documentation** if needed
7. Submit a **pull request** with a clear description

### PR Checklist

- [ ] Tests pass (`pytest tests/ -v`)
- [ ] New patterns include test cases
- [ ] No false positives introduced (tested against `tests/fixtures/clean_*`)
- [ ] Documentation updated (if applicable)

## Reporting Security Vulnerabilities

Please see [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.

## Questions?

Feel free to open an issue with the `question` label, and we'll help you out.

---

Thank you for helping make AI tools safer! 🛡️
