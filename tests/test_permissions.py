"""
Tests for the Permission Auditor module.
"""

import pytest
from shield.core.permissions import PermissionAuditor, PERMISSION_RISK_WEIGHTS, CRITICAL_PERMISSION_COMBOS


class TestPermissionAuditor:
    """Test suite for PermissionAuditor."""

    def setup_method(self):
        self.auditor = PermissionAuditor()

    def test_requires_root_false(self):
        """Permission auditor should not require root."""
        assert self.auditor.requires_root() is False

    def test_calculate_risk_score_empty(self):
        """Empty permissions should yield zero risk."""
        score = self.auditor._calculate_risk_score([])
        assert score == 0.0

    def test_calculate_risk_score_single_low(self):
        """Single low-risk permission should yield low score."""
        score = self.auditor._calculate_risk_score(["android.permission.INTERNET"])
        assert score < 0.5

    def test_calculate_risk_score_surveillance_combo(self):
        """Camera + Mic + Location + Internet should yield critical score."""
        perms = [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET",
        ]
        score = self.auditor._calculate_risk_score(perms)
        assert score > 0.8

    def test_critical_combo_detection(self):
        """Should detect all critical permission combinations."""
        for combo in CRITICAL_PERMISSION_COMBOS:
            app = {
                "package_name": "com.test.app",
                "app_name": "Test App",
                "permissions": combo,
            }
            findings = self.auditor._analyze_app_permissions(app)
            assert len(findings) > 0
            assert findings[0]["severity"] in ["critical", "high"]

    def test_all_permissions_have_weights(self):
        """All permissions in critical combos should have risk weights."""
        for combo in CRITICAL_PERMISSION_COMBOS:
            for perm in combo:
                assert perm in PERMISSION_RISK_WEIGHTS, f"Missing weight for {perm}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
