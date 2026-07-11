"""
Input validation utilities for MrNothing Shield.

Ensures all inputs are sanitized before processing to prevent
injection attacks and ensure data integrity.
"""

import re
from typing import Optional


def validate_package_name(package_name: str) -> bool:
    """
    Validate Android package name format.
    
    Package names must follow reverse domain notation:
    com.example.app
    """
    if not package_name:
        return False
    
    # Android package name rules
    pattern = r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'
    return bool(re.match(pattern, package_name.lower()))


def validate_device_id(device_id: str) -> bool:
    """
    Validate ADB device ID format.
    
    Common formats:
    - emulator-5554
    - 192.168.1.100:5555
    - USB serial numbers
    """
    if not device_id:
        return False
    
    # Allow alphanumeric, dots, colons, hyphens
    pattern = r'^[a-zA-Z0-9\.:\-_]+$'
    return bool(re.match(pattern, device_id))


def sanitize_shell_input(input_str: str) -> str:
    """
    Sanitize input for shell command usage.
    
    Prevents command injection by removing dangerous characters.
    """
    if not input_str:
        return ""
    
    # Remove shell metacharacters
    dangerous = [';', '&', '|', '`', '$', '(', ')', '<', '>', '\\', '"', "'", '\n', '\r']
    sanitized = input_str
    for char in dangerous:
        sanitized = sanitized.replace(char, '')
    
    return sanitized.strip()


def validate_ip_address(ip: str) -> bool:
    """Validate IPv4 address format."""
    if not ip:
        return False
    
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    
    octets = ip.split('.')
    return all(0 <= int(o) <= 255 for o in octets)


def validate_port(port: int) -> bool:
    """Validate port number range."""
    return 1 <= port <= 65535
