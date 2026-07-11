"""
Root & Compromise Detector — Identifies if the device has been
rooted or compromised, which enables deep surveillance capabilities.
"""

import os
from datetime import datetime, timezone
from typing import List


class RootDetector:
    """
    Detects root access and device compromise indicators.
    
    A rooted device is significantly more vulnerable to deep
    surveillance as root access allows installation of kernel-level
    spyware that is nearly impossible to detect from userspace.
    """

    name = "Root & Compromise Detector"
    version = "1.0.0"

    # Common paths where su binary may be found
    SU_PATHS = [
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sbin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/system/usr/we-need-root/su",
        "/magisk/.core/bin/su",
    ]

    # Files that indicate root management apps
    ROOT_INDICATOR_FILES = [
        "/system/app/Superuser.apk",
        "/system/app/Kinguser.apk",
        "/system/xbin/daemonsu",
        "/system/etc/init.d/99SuperSUDaemon",
        "/system/bin/.ext/.su",
        "/system/etc/.has_su_daemon",
        "/system/etc/.installed_su_daemon",
        "/dev/com.koushikdutta.superuser.daemon/",
    ]

    # Magisk-specific indicators
    MAGISK_PATHS = [
        "/sbin/.magisk",
        "/dev/.magisk.unblock",
        "/system/bin/magisk",
        "/system/addon.d/99-magisk.sh",
    ]

    def requires_root(self) -> bool:
        return False  # Can detect root without root access

    def scan(self, device_context: dict) -> List[dict]:
        """Execute root and compromise detection checks."""
        findings = []
        
        # Check for su binary
        su_findings = self._check_su_binary(device_context)
        findings.extend(su_findings)
        
        # Check for root indicator files
        file_findings = self._check_root_files(device_context)
        findings.extend(file_findings)
        
        # Check for Magisk
        magisk_findings = self._check_magisk(device_context)
        findings.extend(magisk_findings)
        
        # Check system properties
        prop_findings = self._check_system_properties(device_context)
        findings.extend(prop_findings)
        
        return findings

    def _check_su_binary(self, device_context: dict) -> List[dict]:
        """Check for su binary in common locations."""
        findings = []
        
        for su_path in self.SU_PATHS:
            # In production: adb shell ls -la {su_path}
            exists = self._file_exists(su_path, device_context)
            
            if exists:
                findings.append({
                    "module": "root_detect",
                    "severity": "critical",
                    "title": f"Root binary detected: {su_path}",
                    "description": (
                        f"The 'su' binary was found at {su_path}. "
                        f"This indicates the device has been rooted, granting "
                        f"unrestricted root access to any application that requests it. "
                        f"Rooted devices are vulnerable to kernel-level spyware that "
                        f"cannot be detected by standard security tools."
                    ),
                    "evidence": {
                        "file_path": su_path,
                        "file_hash": self._get_file_hash(su_path, device_context),
                        "modification_time": self._get_file_mtime(su_path, device_context),
                    },
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "remediation": (
                        "Unroot the device immediately. Remove Magisk or SuperSU. "
                        "Consider factory reset if sensitive data was on device during root period."
                    ),
                    "confidence": 0.99,
                    "tags": ["root", "compromise", "critical"],
                })
        
        return findings

    def _check_root_files(self, device_context: dict) -> List[dict]:
        """Check for root management app indicators."""
        findings = []
        
        for indicator in self.ROOT_INDICATOR_FILES:
            if self._file_exists(indicator, device_context):
                findings.append({
                    "module": "root_detect",
                    "severity": "high",
                    "title": f"Root indicator found: {indicator}",
                    "description": (
                        f"Root management file detected at {indicator}. "
                        f"This file is installed by root tools and indicates "
                        f"the device has been or is currently rooted."
                    ),
                    "evidence": {"file_path": indicator},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "remediation": "Remove root management tools and unroot device.",
                    "confidence": 0.95,
                    "tags": ["root", "compromise"],
                })
        
        return findings

    def _check_magisk(self, device_context: dict) -> List[dict]:
        """Check for Magisk installation."""
        findings = []
        magisk_found = False
        
        for magisk_path in self.MAGISK_PATHS:
            if self._file_exists(magisk_path, device_context):
                magisk_found = True
                break
        
        if magisk_found:
            findings.append({
                "module": "root_detect",
                "severity": "high",
                "title": "Magisk root framework detected",
                "description": (
                    "Magisk — a systemless root framework — was detected on this device. "
                    "Magisk provides root access while hiding modifications from system checks. "
                    "This enables sophisticated spyware to operate at the system level."
                ),
                "evidence": {"detection_method": "path_scan", "magisk_paths_found": self.MAGISK_PATHS},
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "remediation": (
                    "Open Magisk Manager and select 'Uninstall' > 'Complete Uninstall'. "
                    "Reboot device after removal."
                ),
                "confidence": 0.95,
                "tags": ["root", "magisk", "compromise"],
            })
        
        return findings

    def _check_system_properties(self, device_context: dict) -> List[dict]:
        """Check system properties for root indicators."""
        findings = []
        
        # In production: adb shell getprop
        critical_props = {
            "ro.debuggable": "1",  # Debug mode enabled
            "ro.secure": "0",      # ADB has root access
        }
        
        for prop, dangerous_value in critical_props.items():
            actual_value = self._get_prop(prop, device_context)
            if actual_value == dangerous_value:
                findings.append({
                    "module": "root_detect",
                    "severity": "high",
                    "title": f"Dangerous system property: {prop}={actual_value}",
                    "description": (
                        f"System property '{prop}' is set to '{actual_value}', "
                        f"indicating a compromised or development build. "
                        f"This enables ADB root access and debugging capabilities."
                    ),
                    "evidence": {"property": prop, "value": actual_value},
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "remediation": "Flash stock ROM to restore secure system properties.",
                    "confidence": 0.9,
                    "tags": ["root", "compromise", "system_properties"],
                })
        
        return findings

    def _file_exists(self, path: str, device_context: dict) -> bool:
        """Check if file exists on device. Production: uses ADB shell."""
        return False  # Placeholder

    def _get_file_hash(self, path: str, device_context: dict) -> str:
        """Get SHA-256 hash of file."""
        return "N/A"

    def _get_file_mtime(self, path: str, device_context: dict) -> str:
        """Get file modification time."""
        return "N/A"

    def _get_prop(self, prop: str, device_context: dict) -> str:
        """Get system property. Production: adb shell getprop {prop}"""
        return ""
