"""
Indicators of Compromise (IOCs) for network-based threat detection.

Maintains lists of known malicious IPs, domains, and certificates
used by spyware C2 (command and control) infrastructure.
"""

from typing import Dict, List, Set


# Known malicious IP addresses (updated via threat intelligence feeds)
MALICIOUS_IPS: Set[str] = {
    # Populated from threat intelligence feeds
}

# Known malicious domains
MALICIOUS_DOMAINS: Set[str] = {
    # Populated from threat intelligence feeds
}

# Dynamic DNS providers commonly abused by spyware
DYNAMIC_DNS_PROVIDERS: Set[str] = {
    "ddns.net",
    "no-ip.com",
    "duckdns.org",
    "hopto.org",
    "zapto.org",
    "synology.me",
    "myq-see.com",
    "3utilities.com",
    "bounceme.net",
    "freedynamicdns.net",
    "servebeer.com",
    "serveblog.net",
    "servecounterstrike.com",
    "serveftp.com",
    "servegame.com",
    "servehalflife.com",
    "servehttp.com",
    "serveirc.com",
    "serveminecraft.net",
    "servemp3.com",
    "servepics.com",
    "servequake.com",
}

# Suspicious ports for data exfiltration
SUSPICIOUS_PORTS: Set[int] = {
    4444,   # Common malware C2 port
    5555,   # ADB default (often left open)
    6666,   # Common IRC/botnet
    8080,   # Alternative HTTP (check context)
    8888,   # Alternative HTTP
    9999,   # Common backdoor
}


class IOCChecker:
    """
    Checks network endpoints against known indicators of compromise.
    """

    @staticmethod
    def is_malicious_ip(ip: str) -> bool:
        """Check if IP is in malicious list."""
        return ip in MALICIOUS_IPS

    @staticmethod
    def is_malicious_domain(domain: str) -> bool:
        """Check if domain is in malicious list."""
        return domain in MALICIOUS_DOMAINS

    @staticmethod
    def is_dynamic_dns(domain: str) -> bool:
        """Check if domain uses dynamic DNS (suspicious for C2)."""
        domain_lower = domain.lower()
        return any(domain_lower.endswith(provider) for provider in DYNAMIC_DNS_PROVIDERS)

    @staticmethod
    def is_suspicious_port(port: int) -> bool:
        """Check if port is commonly used for malicious activity."""
        return port in SUSPICIOUS_PORTS

    @classmethod
    def check_endpoint(cls, ip: str = "", domain: str = "", port: int = 0) -> Dict:
        """
        Comprehensive endpoint check.
        
        Returns:
            Dict with threat assessment
        """
        findings = []
        threat_level = "none"

        if ip and cls.is_malicious_ip(ip):
            findings.append(f"IP {ip} is in known malicious list")
            threat_level = "critical"

        if domain:
            if cls.is_malicious_domain(domain):
                findings.append(f"Domain {domain} is in known malicious list")
                threat_level = "critical"
            elif cls.is_dynamic_dns(domain):
                findings.append(f"Domain {domain} uses dynamic DNS — commonly abused for C2")
                threat_level = max(threat_level, "medium")

        if port and cls.is_suspicious_port(port):
            findings.append(f"Port {port} is commonly used for malicious C2")
            threat_level = max(threat_level, "medium")

        return {
            "is_threat": len(findings) > 0,
            "threat_level": threat_level,
            "findings": findings,
        }
