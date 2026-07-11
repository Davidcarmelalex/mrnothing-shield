"""
Permission Auditor — Detects dangerous permission combinations
that indicate spyware, stalkerware, or surveillance applications.
"""

from datetime import datetime, timezone
from typing import Dict, List


# Critical permission combinations that strongly indicate surveillance software
CRITICAL_PERMISSION_COMBOS = [
    ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"],
    ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.INTERNET"],
    ["android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.INTERNET"],
    ["android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO", "android.permission.INTERNET"],
    ["android.permission.ACCESS_FINE_LOCATION", "android.permission.RECORD_AUDIO", "android.permission.INTERNET"],
    ["android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET", "android.permission.WRITE_EXTERNAL_STORAGE"],
]

# Individual permissions weighted by surveillance risk
PERMISSION_RISK_WEIGHTS = {
    "android.permission.CAMERA": 0.7,
    "android.permission.RECORD_AUDIO": 0.8,
    "android.permission.ACCESS_FINE_LOCATION": 0.7,
    "android.permission.ACCESS_COARSE_LOCATION": 0.4,
    "android.permission.ACCESS_BACKGROUND_LOCATION": 0.9,
    "android.permission.READ_SMS": 0.6,
    "android.permission.SEND_SMS": 0.5,
    "android.permission.READ_CONTACTS": 0.5,
    "android.permission.READ_CALL_LOG": 0.6,
    "android.permission.READ_PHONE_STATE": 0.4,
    "android.permission.PROCESS_OUTGOING_CALLS": 0.7,
    "android.permission.INTERNET": 0.2,
    "android.permission.WRITE_EXTERNAL_STORAGE": 0.3,
    "android.permission.READ_EXTERNAL_STORAGE": 0.2,
    "android.permission.RECEIVE_BOOT_COMPLETED": 0.3,
    "android.permission.FOREGROUND_SERVICE": 0.2,
    "android.permission.SYSTEM_ALERT_WINDOW": 0.5,
    "android.permission.BIND_ACCESSIBILITY_SERVICE": 0.9,
    "android.permission.DEVICE_ADMIN": 0.8,
    "android.permission.PACKAGE_USAGE_STATS": 0.4,
    "android.permission.GET_TASKS": 0.5,
}


class PermissionAuditor:
    """
    Analyzes app permissions to detect surveillance indicators.
    
    Scans all installed applications and flags dangerous permission
    combinations that are characteristic of spyware and stalkerware.
    """

    name = "Permission Auditor"
    version = "1.0.0"

    def requires_root(self) -> bool:
        return False

    def scan(self, device_context: dict) -> List[dict]:
        """
        Execute permission audit.
        
        In production, this would query the device via ADB for
        actual installed app permissions. This implementation
        provides the detection framework.
        """
        findings = []
        
        # Simulate scanning installed apps
        # In production: adb shell pm list packages -f, then dump permissions
        simulated_apps = self._get_installed_apps(device_context)
        
        for app in simulated_apps:
            app_findings = self._analyze_app_permissions(app)
            findings.extend(app_findings)
            
        return findings

    def _get_installed_apps(self, device_context: dict) -> List[dict]:
        """
        Retrieve installed app information from device.
        
        In production, this executes:
        adb shell pm list packages -f -u  (all packages including uninstalled)
        adb shell dumpsys package <package_name>  (detailed permission info)
        """
        # Placeholder: Production implementation uses ADB queries
        return []

    def _analyze_app_permissions(self, app: dict) -> List[dict]:
        """Analyze permissions for a single app and return findings."""
        findings = []
        permissions = app.get("permissions", [])
        package_name = app.get("package_name", "unknown")
        app_name = app.get("app_name", package_name)
        
        # Check for critical permission combinations
        for combo in CRITICAL_PERMISSION_COMBOS:
            if all(perm in permissions for perm in combo):
                risk_score = self._calculate_risk_score(permissions)
                findings.append({
                    "module": "permissions",
                    "severity": "critical" if risk_score > 0.8 else "high",
                    "title": f"Surveillance permission pattern detected: {app_name}",
                    "description": (
                        f"Application '{app_name}' ({package_name}) requests a dangerous "
                        f"combination of permissions: {', '.join(combo)}. "
                        f"This pattern is characteristic of spyware or stalkerware applications. "
                        f"Risk score: {risk_score:.2f}/1.0"
                    ),
                    "evidence": {
                        "package_name": package_name,
                        "app_name": app_name,
                        "permissions": permissions,
                        "triggered_combo": combo,
                        "risk_score": risk_score,
                    },
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "remediation": (
                        f"Immediately uninstall {app_name} or revoke all critical permissions "
                        f"via Settings > Apps > {app_name} > Permissions. "
                        f"If the app cannot be uninstalled normally, boot into Safe Mode."
                    ),
                    "confidence": 0.95,
                    "tags": ["spyware", "surveillance", "permission_abuse"],
                })
        
        # Flag individual high-risk permissions
        high_risk_perms = [p for p in permissions if PERMISSION_RISK_WEIGHTS.get(p, 0) > 0.7]
        if high_risk_perms and not findings:
            risk_score = self._calculate_risk_score(permissions)
            if risk_score > 0.5:
                findings.append({
                    "module": "permissions",
                    "severity": "medium" if risk_score < 0.7 else "high",
                    "title": f"High-risk permissions detected: {app_name}",
                    "description": (
                        f"Application '{app_name}' ({package_name}) has elevated risk "
                        f"due to high-sensitivity permissions: {', '.join(high_risk_perms)}."
                    ),
                    "evidence": {
                        "package_name": package_name,
                        "app_name": app_name,
                        "permissions": permissions,
                        "high_risk_permissions": high_risk_perms,
                        "risk_score": risk_score,
                    },
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "remediation": f"Review and revoke unnecessary permissions for {app_name}.",
                    "confidence": 0.7,
                    "tags": ["permission_abuse"],
                })
        
        return findings

    def _calculate_risk_score(self, permissions: List[str]) -> float:
        """Calculate composite risk score based on permission weights."""
        if not permissions:
            return 0.0
        
        total_weight = sum(PERMISSION_RISK_WEIGHTS.get(p, 0.1) for p in permissions)
        # Normalize: more permissions = higher potential risk
        combo_multiplier = 1.0
        for combo in CRITICAL_PERMISSION_COMBOS:
            if all(perm in permissions for perm in combo):
                combo_multiplier = max(combo_multiplier, 1.5)
        
        score = (total_weight / len(permissions)) * combo_multiplier
        return min(score, 1.0)
