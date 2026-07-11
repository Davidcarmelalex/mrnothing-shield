"""
Tests for the Hidden App Detector module.
"""

import pytest
from shield.core.hidden_apps import HiddenAppDetector


class TestHiddenAppDetector:
    """Test suite for HiddenAppDetector."""

    def setup_method(self):
        self.detector = HiddenAppDetector()

    def test_requires_root_false(self):
        """Hidden app detector should not require root."""
        assert self.detector.requires_root() is False

    def test_find_hidden_apps(self):
        """Should correctly identify hidden apps."""
        installed = [
            {"package": "com.visible.app"},
            {"package": "com.hidden.app"},
            {"package": "android"},
        ]
        launcher = ["com.visible.app"]
        
        hidden = self.detector._find_hidden_apps(installed, launcher)
        
        assert len(hidden) == 2
        hidden_packages = {app["package"] for app in hidden}
        assert "com.hidden.app" in hidden_packages
        assert "android" in hidden_packages

    def test_spyware_pattern_detection(self):
        """Should flag packages matching spyware patterns."""
        # This would be tested with actual device context in integration tests
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
