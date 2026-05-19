"""SkillGuard Test Suite — Pytest configuration and fixtures."""

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Ensure skillguard is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def static_scanner():
    """Create a StaticScanner instance."""
    from skillguard.scanners.static import StaticScanner
    return StaticScanner()


@pytest.fixture
def prompt_scanner():
    """Create a PromptScanner instance."""
    from skillguard.scanners.prompt import PromptScanner
    return PromptScanner()


@pytest.fixture
def rate_limiter():
    """Create a RateLimiter instance (5 req/min)."""
    from skillguard.ratelimit import RateLimiter
    return RateLimiter(max_requests=5, window_seconds=60)


@pytest.fixture
def app_client():
    """Create a Flask test client."""
    from skillguard.web.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


@pytest.fixture
def admin_client(app_client):
    """Create an authenticated admin client."""
    app_client.post("/admin/login", data={"password": "skillguard2026"})
    return app_client


@pytest.fixture
def sample_dir(tmp_path):
    """Create a temporary directory with sample files."""
    return tmp_path


def create_temp_file(tmp_path, name, content):
    """Helper to create a temp file with content."""
    filepath = tmp_path / name
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(content, encoding="utf-8")
    return filepath
