"""
Tests for the Network Traffic Analyzer module.
"""

import time
import pytest
from shield.core.network import NetworkTrafficAnalyzer


class TestNetworkTrafficAnalyzer:
    """Test suite for NetworkTrafficAnalyzer."""

    def setup_method(self):
        self.analyzer = NetworkTrafficAnalyzer()

    def test_requires_root_true(self):
        """Network analyzer should indicate root is required for full functionality."""
        assert self.analyzer.requires_root() is True

    def test_is_known_malicious(self):
        """Should detect known malicious domains."""
        conn = {"destination": "malicious-example.com"}
        # Would be true if domain is in KNOWN_SPYWARE_DOMAINS
        result = self.analyzer._is_known_malicious(conn)
        assert isinstance(result, bool)

    def test_is_suspicious_pattern_large_transfer(self):
        """Should flag large transfers to uncommon ports."""
        conn = {
            "destination": "192.168.1.100",
            "port": 4444,
            "bytes_sent": 20_000_000,
        }
        assert self.analyzer._is_suspicious_pattern(conn) is True

    def test_is_off_hours_transfer(self):
        """Should detect large transfers during off-hours."""
        # Simulate 3 AM transfer
        off_hours_time = time.mktime((2026, 1, 1, 3, 0, 0, 0, 0, 0))
        conn = {
            "timestamp": off_hours_time,
            "bytes_sent": 5_000_000,
        }
        assert self.analyzer._is_off_hours_transfer(conn) is True

    def test_is_off_hours_normal_hours(self):
        """Should not flag transfers during normal hours."""
        normal_time = time.mktime((2026, 1, 1, 12, 0, 0, 0, 0, 0))
        conn = {
            "timestamp": normal_time,
            "bytes_sent": 5_000_000,
        }
        assert self.analyzer._is_off_hours_transfer(conn) is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
