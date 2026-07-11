"""
Hidden App Detector — Identifies applications that are installed
but hidden from the launcher, a common spyware technique.
"""

from datetime import datetime, timezone
from typing import List


class HiddenAppDetector:
    """
    Detects applications installed on the device that do not
    appear in the launcher — a primary indicator of spyware.
    
    Spyware frequently hides itself by not declaring a launcher
    activity or by using alias components to mask its presence.
    """

    name = "Hidden App Detector"
    version = "1.0.0"

    # Known system packages that legitimately have no launcher
    SYSTEM_PACKAGES = [
        "android",
        "com.android.",
        "com.google.android.gms",
        "com.google.android.providers",
    ]

    # Known spyware package patterns
    SPYWARE_PATTERNS = [
        "spy",
        "track",
        "monitor",
        "stealth",
        "hidden",
        "systemupdate",
        "securitypatch",
        "settingservice",
    ]

    def requires_root(self) -> bool:
        return False

    def scan(self, device_context: dict) -> List[dict]:
        """
        Detect hidden applications by cross-referencing installed
        packages with launcher entries.
        """
        findings = []
        
        installed_packages = self._get_installed_packages(device_context)
        launcher_packages = self._get_launcher_packages(device_context)
        
        hidden_apps = self._find_hidden_apps(installed_packages, launcher_packages)
        
        for app in hidden_apps:
            is_system = any(app["package"].startswith(sp) for sp in self.SYSTEM_PACKAGES)
            is_spyware_pattern = any(pattern in app["package"].lower() for pattern in self.SPYWARE_PATTERNS)
            
            severity = "info" if is_system else ("critical" if is_spyware_pattern else "high")
            
            findings.append({
                "module": "hidden_apps",
                "severity": severity,
                "title": f"Hidden application detected: {app['package']}",
                "description": (
                    f"Application '{app['package']}' is installed but does not "
                    f"appear in the device launcher. "
                    f"{'Package name matches known spyware pattern. ' if is_spyware_pattern else ''}"
                    f"This is a common technique used by surveillance software to evade detection."
                ),
                "evidence": {
                    "package_name": app["package"],
                    "app_name": app.get("app_name", "unknown"),
                    "is_system": is_system,
                    "matches_spyware_pattern": is_spyware_pattern,
                    "installation_source": app.get("installer", "unknown"),
                    "install_date": app.get("install_date", "unknown"),
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "remediation": (
                    f"Investigate {app['package']} immediately. "
                    f"Check Settings > Apps > Show system apps. "
                    f"If unrecognized, uninstall or disable. "
                    f"Boot into Safe Mode if uninstall is blocked."
                ),
                "confidence": 0.9 if is_spyware_pattern else 0.75,
                "tags": ["hidden_app", "spyware"] if is_spyware_pattern else ["hidden_app"],
            })
        
        return findings

    def _get_installed_packages(self, device_context: dict) -> List[dict]:
        """
        Get all installed packages from device.
        Production: adb shell pm list packages -f -u
        """
        return []

    def _get_launcher_packages(self, device_context: dict) -> List[str]:
        """
        Get packages visible in launcher.
        Production: adb shell pm query-activities -a android.intent.action.MAIN -c android.intent.category.LAUNCHER
        """
        return []

    def _find_hidden_apps(self, installed: List[dict], launcher: List[str]) -> List[dict]:
        """Cross-reference to find installed apps not in launcher."""
        launcher_set = set(launcher)
        hidden = []
        for app in installed:
            if app["package"] not in launcher_set:
                hidden.append(app)
        return hidden
