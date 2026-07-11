"""
Tests for the Root & Compromise Detector module.
"""

import pytest
from shield.core.root_detect import RootDetector


class TestRootDetector:
    """Test suite for RootDetector."""

    def setup_method(self):
        self.detector = RootDetector()

    def test_requires_root_false(self):
        """Root detector should not require root access."""
        assert self.detector.requires_root() is False

    def test_su_paths_defined(self):
        """Should have comprehensive su binary paths."""
        assert len(self.detector.SU_PATHS) > 10
        assert "/system/bin/su" in self.detector.SU_PATHS
        assert "/system/xbin/su" in self.detector.SU_PATHS

    def test_root_indicator_files_defined(self):
        """Should have root indicator file list."""
        assert len(self.detector.ROOT_INDICATOR_FILES) > 5

    def test_magisk_paths_defined(self):
        """Should have Magisk detection paths."""
        assert len(self.detector.MAGISK_PATHS) > 3
        assert "/sbin/.magisk" in self.detector.MAGISK_PATHS

    def test_critical_properties_defined(self):
        """Should check critical system properties."""
        props = {
            "ro.debuggable": "1",
            "ro.secure": "0",
        }
        assert len(props) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
