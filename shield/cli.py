#!/usr/bin/env python3
"""
MrNothing Shield — Command Line Interface

Provides an intuitive CLI for executing security audits,
generating reports, and managing the Shield framework.
"""

import sys
from pathlib import Path

# Add shield to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core.auditor import SecurityAuditor


def print_banner():
    """Display the Shield banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║   ███╗   ███╗██████╗ ███╗   ██╗ ██████╗ ████████╗██╗  ██╗  ║
    ║   ████╗ ████║██╔══██╗████╗  ██║██╔═══██╗╚══██╔══╝██║  ██║  ║
    ║   ██╔████╔██║██████╔╝██╔██╗ ██║██║   ██║   ██║   ███████║  ║
    ║   ██║╚██╔╝██║██╔══██╗██║╚██╗██║██║   ██║   ██║   ██╔══██║  ║
    ║   ██║ ╚═╝ ██║██║  ██║██║ ╚████║╚██████╔╝   ██║   ██║  ██║  ║
    ║   ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝  ║
    ║                                                               ║
    ║        Mobile Security Audit Framework v1.0.0                 ║
    ║        Detect Spyware · Hidden Apps · Malicious Permissions   ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main CLI entry point."""
    print_banner()
    
    print("Usage: python -m shield audit [options]")
    print("\nOptions:")
    print("  --device <id>      Target device ID (default: local)")
    print("  --module <name>    Specific module to run (permissions, hidden_apps, network, root_detect)")
    print("  --output <format>  Output format: json, pdf, html (default: json)")
    print("  --verbose          Enable verbose output")
    print("\nExamples:")
    print("  python -m shield audit --device emulator-5554 --output report.html")
    print("  python -m shield audit --module permissions --verbose")
    
    # For now, run a demo audit
    print("\n" + "=" * 60)
    print("Running demo audit...")
    print("=" * 60 + "\n")
    
    auditor = SecurityAuditor(device_id="demo")
    result = auditor.run_audit()
    
    print(f"\nAudit ID: {result.audit_id}")
    print(f"Duration: {result.duration_seconds:.2f}s")
    print(f"Risk Score: {result.risk_score:.2f}/1.0")
    print(f"Findings: {len(result.findings)}")
    print(f"\nRecommendation: {result.summary.get('recommendation', 'N/A')}")


if __name__ == "__main__":
    main()
