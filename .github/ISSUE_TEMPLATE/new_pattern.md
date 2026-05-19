---
name: New Pattern Submission
about: Submit a new detection pattern
title: "[PATTERN] "
labels: pattern, enhancement
---

## Pattern Type
- [ ] Malware detection
- [ ] Prompt injection
- [ ] Other: ___

## Category
e.g., reverse_shell, data_exfiltration, system_override

## Pattern Details

```json
{
  "category": "",
  "name": "",
  "severity": "critical|high|warning",
  "description": "",
  "patterns": [""],
  "false_positives": [""]
}
```

## Test Case
Provide an example string that should trigger this pattern:

```
Paste example here
```

## False Positive Check
Provide an example of legitimate code that should NOT trigger this pattern:

```
Paste example here
```

## References
Any relevant references, CVEs, or documentation.
