"""
SecurityAuditor — Main orchestration engine for MrNothing Shield.

Coordinates all detection modules, aggregates findings, and
manages the audit lifecycle.
"""

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .permissions import PermissionAuditor
from .hidden_apps import HiddenAppDetector
from .network import NetworkTrafficAnalyzer
from .root_detect import RootDetector
from .report import ReportGenerator


@dataclass
class AuditResult:
    """Container for complete audit results."""

    audit_id: str
    timestamp: str
    device_id: str
    device_fingerprint: str
    findings: List[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    duration_seconds: float = 0.0
    modules_executed: List[str] = field(default_factory=list)

    @property
    def has_critical_findings(self) -> bool:
        return any(f.get("severity") == "critical" for f in self.findings)

    @property
    def has_spyware_indicators(self) -> bool:
        spyware_keywords = ["spyware", "surveillance", "hidden_app", "masquerade"]
        return any(
            any(kw in f.get("tags", []) for kw in spyware_keywords)
            for f in self.findings
        )

    @property
    def risk_score(self) -> float:
        if not self.findings:
            return 0.0
        severity_weights = {"info": 0.1, "low": 0.3, "medium": 0.5, "high": 0.8, "critical": 1.0}
        total = sum(severity_weights.get(f.get("severity", "low"), 0.3) for f in self.findings)
        return min(total / len(self.findings), 1.0)

    def to_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp,
            "device_id": self.device_id,
            "device_fingerprint": self.device_fingerprint,
            "duration_seconds": self.duration_seconds,
            "modules_executed": self.modules_executed,
            "risk_score": self.risk_score,
            "has_critical_findings": self.has_critical_findings,
            "has_spyware_indicators": self.has_spyware_indicators,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "summary": self.summary,
        }


class SecurityAuditor:
    """
    Main orchestrator for security audits.

    Coordinates all detection modules and produces comprehensive
    audit reports with forensic integrity.
    """

    MODULES = {
        "permissions": PermissionAuditor,
        "hidden_apps": HiddenAppDetector,
        "network": NetworkTrafficAnalyzer,
        "root_detect": RootDetector,
    }

    def __init__(self, device_id: str = "local", output_dir: str = "./reports"):
        self.device_id = device_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _generate_audit_id(self) -> str:
        """Generate unique audit ID with timestamp and hash."""
        timestamp = datetime.now(timezone.utc).isoformat()
        hash_input = f"{self.device_id}:{timestamp}:{time.time()}"
        hash_digest = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
        return f"SHIELD-{datetime.now().strftime('%Y%m%d')}-{hash_digest}"

    def _get_device_fingerprint(self) -> str:
        """Generate device fingerprint for audit chain."""
        # In production, this would gather device-specific identifiers
        fingerprint_data = f"{self.device_id}:{datetime.now(timezone.utc).isoformat()}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

    def run_audit(
        self,
        modules: Optional[List[str]] = None,
        verbose: bool = False,
    ) -> AuditResult:
        """
        Run security audit with specified modules.

        Args:
            modules: List of module names to run. If None, runs all.
            verbose: Enable verbose output

        Returns:
            AuditResult containing all findings
        """
        start_time = time.time()
        audit_id = self._generate_audit_id()
        timestamp = datetime.now(timezone.utc).isoformat()

        if modules is None:
            modules = list(self.MODULES.keys())

        all_findings = []
        device_context = {
            "device_id": self.device_id,
            "timestamp": timestamp,
            "verbose": verbose,
        }

        for module_name in modules:
            if module_name not in self.MODULES:
                continue

            try:
                module_class = self.MODULES[module_name]
                detector = module_class()
                findings = detector.scan(device_context)
                all_findings.extend(findings)
            except Exception as e:
                all_findings.append({
                    "module": module_name,
                    "severity": "error",
                    "title": f"Module execution failed: {module_name}",
                    "description": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "tags": ["error"],
                })

        duration = time.time() - start_time

        summary = self._generate_summary(all_findings)

        result = AuditResult(
            audit_id=audit_id,
            timestamp=timestamp,
            device_id=self.device_id,
            device_fingerprint=self._get_device_fingerprint(),
            findings=all_findings,
            summary=summary,
            duration_seconds=duration,
            modules_executed=modules,
        )

        return result

    def _generate_summary(self, findings: List[dict]) -> dict:
        """Generate audit summary statistics."""
        severity_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0, "error": 0}
        for finding in findings:
            severity = finding.get("severity", "low")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        module_counts = {}
        for finding in findings:
            module = finding.get("module", "unknown")
            module_counts[module] = module_counts.get(module, 0) + 1

        return {
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "findings_by_module": module_counts,
            "recommendation": self._generate_recommendation(severity_counts),
        }

    def _generate_recommendation(self, severity_counts: dict) -> str:
        """Generate human-readable recommendation based on findings."""
        critical = severity_counts.get("critical", 0)
        high = severity_counts.get("high", 0)

        if critical > 0:
            return (
                f"CRITICAL: {critical} critical threat(s) detected. "
                "Immediate action required. Review flagged applications and "
                "consider factory reset if spyware is confirmed."
            )
        elif high > 0:
            return (
                f"WARNING: {high} high-risk finding(s) detected. "
                "Review flagged applications and revoke unnecessary permissions."
            )
        elif severity_counts.get("medium", 0) > 0:
            return (
                f"CAUTION: {severity_counts['medium']} medium-risk finding(s). "
                "Monitor flagged applications and review permissions."
            )
        else:
            return "No significant threats detected. Device appears secure."

    def generate_report(self, result: AuditResult, output_format: str = "json") -> str:
        """Generate audit report in specified format."""
        generator = ReportGenerator(result)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"shield_audit_{timestamp}"

        if output_format == "json":
            filepath = self.output_dir / f"{filename}.json"
            generator.to_json(str(filepath))
        elif output_format == "pdf":
            filepath = self.output_dir / f"{filename}.pdf"
            generator.to_pdf(str(filepath))
        elif output_format == "html":
            filepath = self.output_dir / f"{filename}.html"
            generator.to_html(str(filepath))
        else:
            raise ValueError(f"Unsupported format: {output_format}")

        return str(filepath)
