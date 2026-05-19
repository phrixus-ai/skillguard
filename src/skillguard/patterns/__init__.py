"""Pattern loading utilities."""

import json
from pathlib import Path
from typing import Any

PATTERNS_DIR = Path(__file__).parent


def load_pattern_file(filename: str) -> dict[str, Any]:
    """Load a pattern JSON file from the patterns directory."""
    filepath = PATTERNS_DIR / filename
    if not filepath.exists():
        raise FileNotFoundError(f"Pattern file not found: {filepath}")
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def get_all_patterns(category_file: str) -> list[dict[str, Any]]:
    """Flatten all patterns from a category file into a single list with category info."""
    data = load_pattern_file(category_file)
    results = []
    for cat_name, cat_data in data.get("categories", {}).items():
        severity = cat_data.get("severity", "info")
        for pattern in cat_data.get("patterns", []):
            results.append({
                "category": cat_name,
                "severity": severity,
                "regex": pattern["regex"],
                "description": pattern["description"],
            })
    return results
