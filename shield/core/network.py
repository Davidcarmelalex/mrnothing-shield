"""
Network Traffic Analyzer — Detects suspicious outbound connections
that may indicate data exfiltration by spyware.
"""

from datetime import datetime, timezone
from typing import Dict, List


# Known malicious/suspicious IP ranges (CIDR notation)
SUSPICIOUS_IP_RANGES = [
    # Example ranges - production uses live threat intelligence feeds
]

# Suspicious domain patterns
SUSPICIOUS_DOMAIN_PATTERNS = [
    "*.ddns.net",
    "*.no-ip.com",
    "*.duckdns.org",
    "*.hopto.org",
    "*.zapto.org",
]

# Well-known spyware C2 domains (examples)
KNOWN_SPYWARE_DOMAINS = [
    # Populated from threat intelligence feeds
]


class NetworkTrafficAnalyzer:
    """
    Analyzes network traffic to detect data exfiltration patterns
    characteristic of spyware and stalkerware.
    
    Requires root access for full packet capture. Falls back to
    connection log analysis without root.
    """

    name = "Network Traffic Analyzer"
    version = "1.0.0"

    def requires_root(self) -> bool:
        return True  # Full capture requires root; limited analysis works without

    def scan(self, device_context: dict) -> List[dict]:
        """
        Analyze network traffic for suspicious patterns.
        """
        findings = []
        
        connection_logs = self._get_connection_logs(device_context)
        
        # Check for connections to known malicious endpoints
        for conn in connection_logs:
            if self._is_known_malicious(conn):
                findings.append(self._create_finding(conn, "critical", "known_malicious"))
            elif self._is_suspicious_pattern(conn):
                findings.append(self._create_finding(conn, "high", "suspicious_pattern"))
            elif self._is_off_hours_transfer(conn):
                findings.append(self._create_finding(conn, "medium", "off_hours_transfer"))
        
        return findings

    def _get_connection_logs(self, device_context: dict) -> List[dict]:
        """
        Get network connection logs from device.
        Production: adb shell cat /proc/net/tcp, tcpdump, or ss
        """
        return []

    def _is_known_malicious(self, conn: dict) -> bool:
        """Check if connection endpoint is in known malicious list."""
        dst = conn.get("destination", "")
        return dst in KNOWN_SPYWARE_DOMAINS

    def _is_suspicious_pattern(self, conn: dict) -> bool:
        """Check for suspicious connection patterns."""
        # Large data transfer to uncommon port
        if conn.get("bytes_sent", 0) > 10_000_000:  # > 10MB
            if conn.get("port", 0) not in [80, 443, 8080]:
                return True
        
        # Connection to dynamic DNS domain
        domain = conn.get("domain", "")
        for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
            if domain.endswith(pattern.replace("*.", "")):
                return True
        
        return False

    def _is_off_hours_transfer(self, conn: dict) -> bool:
        """Detect large transfers during typical sleep hours."""
        import time
        hour = time.localtime(conn.get("timestamp", 0)).tm_hour
        if 1 <= hour <= 5:  # 1 AM to 5 AM
            if conn.get("bytes_sent", 0) > 1_000_000:  # > 1MB
                return True
        return False

    def _create_finding(self, conn: dict, severity: str, finding_type: str) -> dict:
        """Create a standardized threat finding."""
        descriptions = {
            "known_malicious": (
                f"Connection to known malicious endpoint: {conn.get('destination', 'unknown')}"
            ),
            "suspicious_pattern": (
                f"Suspicious traffic pattern detected: {conn.get('bytes_sent', 0)} bytes "
                f"to {conn.get('destination', 'unknown')}:{conn.get('port', 0)}"
            ),
            "off_hours_transfer": (
                f"Large data transfer during off-hours: {conn.get('bytes_sent', 0)} bytes "
                f"at {conn.get('timestamp', 'unknown')}"
            ),
        }
        
        return {
            "module": "network",
            "severity": severity,
            "title": f"Network anomaly: {conn.get('app', 'unknown')}",
            "description": descriptions.get(finding_type, "Unknown network anomaly"),
            "evidence": conn,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "remediation": (
                f"Block {conn.get('destination', 'unknown')} in firewall. "
                f"Investigate {conn.get('app', 'unknown')} for spyware."
            ),
            "confidence": 0.9 if finding_type == "known_malicious" else 0.7,
            "tags": ["network", "exfiltration", finding_type],
        }
