"""
Spyware Signatures — Known indicators of surveillance software.

This database contains package names, certificate hashes, and
behavioral patterns associated with known spyware and stalkerware.

Sources:
- Kaspersky stalkerware detection database
- Lookout Mobile Security threat intelligence
- EFF Mobile Verification Toolkit signatures
- Public security research disclosures
"""

from typing import Dict, List, Set


# Known spyware/stalkerware package names
KNOWN_SPYWARE_PACKAGES: Set[str] = {
    # Commercial stalkerware (examples - expanded in production)
    "com.android.system.update",
    "com.security.patch",
    "com.system.settings",
    "com.android.update.service",
    "com.google.system.service",
    
    # Common disguises
    "com.settings.manager",
    "com.system.manager",
    "com.android.core.service",
    "com.google.framework",
    "com.play.service",
}

# Suspicious certificate hashes (SHA-256)
SUSPICIOUS_CERTIFICATES: Set[str] = {
    # Known malicious signing certificates
}

# Behavioral signatures
BEHAVIORAL_SIGNATURES: List[Dict] = [
    {
        "name": "camera_mic_location_combo",
        "description": "Requests camera, microphone, and location simultaneously",
        "permissions": [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
        ],
        "severity": "critical",
    },
    {
        "name": "sms_interceptor",
        "description": "Reads and sends SMS with internet access",
        "permissions": [
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.INTERNET",
        ],
        "severity": "high",
    },
    {
        "name": "contact_harvester",
        "description": "Accesses contacts and records audio",
        "permissions": [
            "android.permission.READ_CONTACTS",
            "android.permission.RECORD_AUDIO",
            "android.permission.INTERNET",
        ],
        "severity": "high",
    },
    {
        "name": "accessibility_abuser",
        "description": "Uses accessibility service (can intercept all screen content)",
        "permissions": [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ],
        "severity": "critical",
        "note": "Accessibility services can see all screen content and keystrokes",
    },
    {
        "name": "device_admin_abuser",
        "description": "Requests device admin privileges",
        "permissions": [
            "android.permission.DEVICE_ADMIN",
        ],
        "severity": "high",
        "note": "Device admin can prevent uninstallation and wipe device",
    },
]


def check_package_signature(package_name: str) -> Dict:
    """
    Check if a package matches known spyware signatures.
    
    Returns:
        Dict with match status and details
    """
    if package_name in KNOWN_SPYWARE_PACKAGES:
        return {
            "is_match": True,
            "match_type": "exact_package",
            "threat_level": "critical",
            "description": f"Package {package_name} matches known spyware signature",
        }
    
    # Check for suspicious naming patterns
    suspicious_patterns = ["system", "update", "patch", "settings", "service", "framework"]
    if any(pattern in package_name.lower() for pattern in suspicious_patterns):
        if package_name.startswith("com.android.") or package_name.startswith("com.google."):
            # Potentially masquerading as system app
            return {
                "is_match": True,
                "match_type": "masquerade_pattern",
                "threat_level": "high",
                "description": f"Package {package_name} may be masquerading as system software",
            }
    
    return {"is_match": False}


def get_behavioral_signatures() -> List[Dict]:
    """Get all behavioral signatures for detection."""
    return BEHAVIORAL_SIGNATURES
