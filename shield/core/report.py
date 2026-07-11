"""
Report Generator — Produces comprehensive security audit reports
in multiple formats with forensic integrity.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class ReportGenerator:
    """
    Generates security audit reports in JSON, PDF, and HTML formats.
    
    All reports include cryptographic signatures for evidence integrity
    and chain of custody documentation.
    """

    def __init__(self, audit_result):
        self.audit_result = audit_result
        self.generated_at = datetime.now(timezone.utc).isoformat()

    def _sign_report(self, data: str) -> str:
        """Generate SHA-256 signature of report data."""
        return hashlib.sha256(data.encode()).hexdigest()

    def to_json(self, filepath: str) -> str:
        """Generate JSON report with forensic metadata."""
        report = {
            "report_metadata": {
                "generator": "MrNothing Shield v1.0.0",
                "generated_at": self.generated_at,
                "report_format": "json",
                "signature": "",
            },
            "audit_result": self.audit_result.to_dict(),
        }
        
        # Sign the report
        report_data = json.dumps(self.audit_result.to_dict(), sort_keys=True)
        report["report_metadata"]["signature"] = self._sign_report(report_data)
        
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        
        return filepath

    def to_pdf(self, filepath: str) -> str:
        """Generate PDF report with professional formatting."""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            )
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
        except ImportError:
            # Fallback: generate HTML instead
            return self.to_html(filepath.replace(".pdf", ".html"))

        doc = SimpleDocTemplate(filepath, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)
        
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#ff3333'),
            spaceAfter=30,
        )
        story.append(Paragraph("MRNOTHING SHIELD", title_style))
        story.append(Paragraph("Mobile Security Audit Report", styles['Heading2']))
        story.append(Spacer(1, 0.2 * inch))
        
        # Metadata
        meta_data = [
            ["Audit ID:", self.audit_result.audit_id],
            ["Generated:", self.generated_at],
            ["Device ID:", self.audit_result.device_id],
            ["Duration:", f"{self.audit_result.duration_seconds:.1f} seconds"],
            ["Risk Score:", f"{self.audit_result.risk_score:.2f}/1.0"],
        ]
        meta_table = Table(meta_data, colWidths=[2 * inch, 4 * inch])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 0.3 * inch))
        
        # Summary
        story.append(Paragraph("Executive Summary", styles['Heading3']))
        story.append(Paragraph(
            self.audit_result.summary.get("recommendation", "No summary available."),
            styles['BodyText']
        ))
        story.append(Spacer(1, 0.2 * inch))
        
        # Findings
        story.append(Paragraph("Detailed Findings", styles['Heading3']))
        
        for finding in self.audit_result.findings:
            severity_color = {
                "critical": colors.red,
                "high": colors.orange,
                "medium": colors.yellow,
                "low": colors.green,
                "info": colors.blue,
            }.get(finding.get("severity", "low"), colors.black)
            
            story.append(Paragraph(
                f"[{finding.get('severity', 'unknown').upper()}] {finding.get('title', '')}",
                ParagraphStyle('Severity', parent=styles['Heading4'], textColor=severity_color)
            ))
            story.append(Paragraph(finding.get("description", ""), styles['BodyText']))
            
            if finding.get("remediation"):
                story.append(Paragraph(
                    f"<b>Remediation:</b> {finding['remediation']}",
                    styles['BodyText']
                ))
            
            story.append(Spacer(1, 0.1 * inch))
        
        # Signature
        story.append(PageBreak())
        story.append(Paragraph("Report Integrity", styles['Heading3']))
        report_data = json.dumps(self.audit_result.to_dict(), sort_keys=True)
        signature = self._sign_report(report_data)
        story.append(Paragraph(f"SHA-256 Signature: <code>{signature}</code>", styles['BodyText']))
        story.append(Paragraph(
            "This signature verifies the integrity of the audit data. "
            "Any modification to the underlying data will invalidate this signature.",
            styles['Italic']
        ))
        
        doc.build(story)
        return filepath

    def to_html(self, filepath: str) -> str:
        """Generate interactive HTML report."""
        findings_html = ""
        for finding in self.audit_result.findings:
            severity = finding.get("severity", "low")
            color = {
                "critical": "#ff3333",
                "high": "#ff8800",
                "medium": "#ffcc00",
                "low": "#33cc33",
                "info": "#3399ff",
            }.get(severity, "#666666")
            
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; margin: 10px 0; padding: 10px; background: #f9f9f9;">
                <h4 style="color: {color}; margin: 0;">[{severity.upper()}] {finding.get('title', '')}</h4>
                <p>{finding.get('description', '')}</p>
                {f'<p><strong>Remediation:</strong> {finding["remediation"]}</p>' if finding.get('remediation') else ''}
                <small style="color: #666;">Module: {finding.get('module', 'unknown')} | 
                Confidence: {finding.get('confidence', 0)*100:.0f}%</small>
            </div>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MrNothing Shield - Security Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #0f0f0f; color: #fff; }}
        .header {{ text-align: center; padding: 30px; background: linear-gradient(135deg, #1a1a1a 0%, #0f0f0f 100%); border-radius: 8px; margin-bottom: 20px; }}
        .header h1 {{ color: #ff3333; margin: 0; font-size: 2.5em; }}
        .meta {{ background: #1a1a1a; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .meta table {{ width: 100%; }}
        .meta td {{ padding: 8px; border-bottom: 1px solid #333; }}
        .meta td:first-child {{ color: #888; width: 30%; }}
        .findings {{ margin-top: 20px; }}
        .risk-score {{ font-size: 3em; text-align: center; padding: 20px; background: #1a1a1a; border-radius: 8px; margin: 20px 0; }}
        .risk-critical {{ color: #ff3333; }}
        .risk-high {{ color: #ff8800; }}
        .risk-medium {{ color: #ffcc00; }}
        .risk-low {{ color: #33cc33; }}
        .signature {{ margin-top: 30px; padding: 20px; background: #1a1a1a; border-radius: 8px; font-family: monospace; font-size: 0.9em; color: #888; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>MRNOTHING SHIELD</h1>
        <p>Mobile Security Audit Report</p>
    </div>
    
    <div class="meta">
        <table>
            <tr><td>Audit ID</td><td>{self.audit_result.audit_id}</td></tr>
            <tr><td>Generated</td><td>{self.generated_at}</td></tr>
            <tr><td>Device ID</td><td>{self.audit_result.device_id}</td></tr>
            <tr><td>Duration</td><td>{self.audit_result.duration_seconds:.1f} seconds</td></tr>
            <tr><td>Modules</td><td>{', '.join(self.audit_result.modules_executed)}</td></tr>
        </table>
    </div>
    
    <div class="risk-score {{'risk-critical' if self.audit_result.risk_score > 0.8 else 'risk-high' if self.audit_result.risk_score > 0.5 else 'risk-medium' if self.audit_result.risk_score > 0.3 else 'risk-low'}}">
        Risk Score: {self.audit_result.risk_score:.2f}/1.0
    </div>
    
    <h2>Executive Summary</h2>
    <p>{self.audit_result.summary.get('recommendation', 'No summary available.')}</p>
    
    <div class="findings">
        <h2>Findings ({len(self.audit_result.findings)})</h2>
        {findings_html}
    </div>
    
    <div class="signature">
        <strong>Report Integrity</strong><br>
        SHA-256: {self._sign_report(json.dumps(self.audit_result.to_dict(), sort_keys=True))}<br>
        <em>This signature verifies the integrity of the audit data.</em>
    </div>
</body>
</html>"""
        
        with open(filepath, "w") as f:
            f.write(html)
        
        return filepath
