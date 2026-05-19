"""Tests for RateLimiter, Auth, and PathSanitize."""

import pytest


class TestRateLimiter:
    """Rate limiter tests."""

    def test_allowed_under_limit(self, rate_limiter):
        for _ in range(5):
            assert rate_limiter.is_allowed("192.168.1.1") is True

    def test_blocked_over_limit(self, rate_limiter):
        for _ in range(5):
            rate_limiter.is_allowed("10.0.0.1")
        # 6th request should be blocked
        assert rate_limiter.is_allowed("10.0.0.1") is False

    def test_different_keys_independent(self, rate_limiter):
        # Use up limit for IP A
        for _ in range(5):
            rate_limiter.is_allowed("10.0.0.1")
        # IP B should still be allowed
        assert rate_limiter.is_allowed("10.0.0.2") is True

    def test_remaining_count(self, rate_limiter):
        assert rate_limiter.remaining("10.0.0.1") == 5
        rate_limiter.is_allowed("10.0.0.1")
        assert rate_limiter.remaining("10.0.0.1") == 4

    def test_remaining_zero(self, rate_limiter):
        for _ in range(5):
            rate_limiter.is_allowed("10.0.0.1")
        assert rate_limiter.remaining("10.0.0.1") == 0

    def test_window_expiry(self):
        """Test that rate limiter resets after window."""
        from skillguard.ratelimit import RateLimiter
        rl = RateLimiter(max_requests=2, window_seconds=1)
        rl.is_allowed("test")
        rl.is_allowed("test")
        assert rl.is_allowed("test") is False
        import time
        time.sleep(1.1)
        assert rl.is_allowed("test") is True


class TestAuth:
    """Authentication tests."""

    def test_api_key_valid(self):
        from skillguard.auth import check_admin_auth, API_KEY
        assert API_KEY == "sg_5c8a386a25edac0b13d579bb6016a77c"

    def test_api_key_format(self):
        from skillguard.auth import API_KEY
        assert API_KEY.startswith("sg_")
        assert len(API_KEY) > 10


class TestPathSanitize:
    """Path sanitization tests."""

    def test_tmp_path_removed(self):
        """Test _sanitize_path removes /tmp/tmpXXXX/ prefix."""
        # Import from app
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from skillguard.web.app import _sanitize_path

        result = _sanitize_path("/tmp/tmpABC123/malicious_skill.py")
        assert result == "malicious_skill.py"
        assert "/tmp/" not in result

    def test_normal_path_unchanged(self):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from skillguard.web.app import _sanitize_path

        result = _sanitize_path("malicious_skill.py")
        assert result == "malicious_skill.py"

    def test_nested_tmp_path(self):
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
        from skillguard.web.app import _sanitize_path

        result = _sanitize_path("/tmp/tmpXYZ789/subdir/file.py")
        assert result == "file.py" or result == "subdir/file.py"
        assert "/tmp/" not in result


class TestRiskScore:
    """Risk score calculation tests."""

    def test_zero_findings_zero_score(self, static_scanner, tmp_path):
        from pathlib import Path
        f = tmp_path / "clean.py"
        f.write_text("# Nothing suspicious here\ndef hello():\n    return 'world'\n")
        result = static_scanner.scan_directory(f)
        assert result.risk_score == 0

    def test_score_capped_at_100(self, static_scanner, tmp_path):
        """Risk score should never exceed 100."""
        from pathlib import Path
        f = Path(__file__).parent / "fixtures" / "malicious_multi.py"
        result = static_scanner.scan_directory(f)
        assert result.risk_score <= 100
        assert result.risk_score == 100  # This file should hit max

    def test_risk_level_critical(self, static_scanner):
        from pathlib import Path
        f = Path(__file__).parent / "fixtures" / "malicious_multi.py"
        result = static_scanner.scan_directory(f)
        assert result.risk_level == "CRITICAL"

    def test_risk_level_low(self, static_scanner, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("# Clean file\ndef greet(name):\n    return f'Hello {name}'\n")
        result = static_scanner.scan_directory(f)
        assert result.risk_level == "LOW"
