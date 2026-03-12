"""
test_utils.py - Unit tests for utility functions

What's going on:
    These tests verify that our helper functions work correctly.
    They run automatically via GitHub Actions on every push.

    Run manually: python -m pytest tests/ -v
"""

import pytest
import sys
import os

# Add parent directory to path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqli_tool.core.utils import parse_cookies, calculate_average, size_differs


class TestParseCookies:
    """Tests for the cookie parser."""

    def test_simple_cookies(self):
        """Standard cookie string should be parsed correctly."""
        result = parse_cookies("PHPSESSID=abc123; security=low")
        assert result == {"PHPSESSID": "abc123", "security": "low"}

    def test_single_cookie(self):
        """A single cookie (no semicolons) should work."""
        result = parse_cookies("session=xyz789")
        assert result == {"session": "xyz789"}

    def test_empty_string(self):
        """Empty string should return empty dict."""
        result = parse_cookies("")
        assert result == {}

    def test_none_input(self):
        """None input should return empty dict."""
        result = parse_cookies(None)
        assert result == {}

    def test_extra_whitespace(self):
        """Whitespace around keys and values should be stripped."""
        result = parse_cookies("  key1 = value1 ;  key2 = value2  ")
        assert result == {"key1": "value1", "key2": "value2"}

    def test_value_with_equals(self):
        """Values containing '=' should be handled (split on first only)."""
        result = parse_cookies("token=abc=def=ghi")
        assert result == {"token": "abc=def=ghi"}


class TestCalculateAverage:
    """Tests for the average calculator."""

    def test_normal_list(self):
        """Average of [10, 20, 30] should be 20."""
        assert calculate_average([10, 20, 30]) == 20.0

    def test_single_value(self):
        """Average of a single value should be that value."""
        assert calculate_average([42]) == 42.0

    def test_empty_list(self):
        """Average of empty list should be 0."""
        assert calculate_average([]) == 0

    def test_float_values(self):
        """Should handle float values correctly."""
        result = calculate_average([0.1, 0.2, 0.3])
        assert abs(result - 0.2) < 0.001


class TestSizeDiffers:
    """Tests for the response size comparison."""

    def test_significant_difference(self):
        """20% difference should be flagged (threshold=10%)."""
        assert size_differs(1000, 1200, threshold=0.10) is True

    def test_small_difference(self):
        """5% difference should NOT be flagged (threshold=10%)."""
        assert size_differs(1000, 1050, threshold=0.10) is False

    def test_exact_match(self):
        """Identical sizes should NOT be flagged."""
        assert size_differs(1000, 1000, threshold=0.10) is False

    def test_zero_baseline(self):
        """Zero baseline with non-zero test should be flagged."""
        assert size_differs(0, 100, threshold=0.10) is True

    def test_zero_both(self):
        """Both zero should NOT be flagged."""
        assert size_differs(0, 0, threshold=0.10) is False

    def test_smaller_response(self):
        """Response smaller than baseline should also be detected."""
        assert size_differs(1000, 800, threshold=0.10) is True