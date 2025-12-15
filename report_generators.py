#!/usr/bin/env python3
"""
Firefox Forensics - Report Generators
======================================
Generates forensic reports in multiple formats:
- JSON (machine-readable structured data)
- Summary TXT (executive summary)

Follows DFIR best practices with consistent schema and full evidence integrity.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from forensic_models import (
    ForensicReport,
    ProcessingStatus,
    SECURITY_BANNER,
)


class JSONReportGenerator:
    """Generate machine-readable JSON forensic reports."""
    
    # JSON Schema version for stability tracking
    SCHEMA_VERSION = "2.0.0"
    
    def __init__(self, report: ForensicReport):
        """Initialize generator with report data.
        
        Args:
            report: ForensicReport object to serialize.
        """
        self.report = report
    
    def generate(self) -> str:
        """Generate complete JSON report.
        
        Returns:
            JSON string with formatted report data.
        """
        report_dict = self._build_report_dict()
        return json.dumps(report_dict, indent=2, default=self._json_serializer, ensure_ascii=False)
    
    def save(self, output_path: Path) -> None:
        """Save JSON report to file.
        
        Args:
            output_path: Path to write JSON file.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(self.generate())
    
    def _build_report_dict(self) -> Dict[str, Any]:
        """Build the complete report dictionary.
        
        Returns:
            Dictionary representing the full report.
        """
        return {
            "$schema_version": self.SCHEMA_VERSION,
            "$generated_at": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "security_notice": {
                "read_only_analysis": True,
                "local_execution": True,
                "no_persistence": True,
                "intended_use": "Academic / Personal forensic / Authorized security research"
            },
            "case_metadata": self.report.case_metadata.to_dict(),
            "acquisition_summary": self.report.acquisition_summary.to_dict(),
            "decryption_context": self.report.decryption_context.to_dict(),
            "findings": {k: v.to_dict() for k, v in self.report.findings.items()},
            "errors_and_warnings": [e.to_dict() for e in self.report.errors_and_warnings],
            "appendix": self.report.appendix,
            "report_statistics": self._calculate_statistics()
        }
    
    def _calculate_statistics(self) -> Dict[str, Any]:
        """Calculate report statistics.
        
        Returns:
            Dictionary with report statistics.
        """
        total_items = sum(cat.total_count for cat in self.report.findings.values())
        successful = sum(1 for cat in self.report.findings.values() if cat.status == ProcessingStatus.SUCCESS)
        partial = sum(1 for cat in self.report.findings.values() if cat.status == ProcessingStatus.PARTIAL)
        failed = sum(1 for cat in self.report.findings.values() if cat.status == ProcessingStatus.FAILED)
        
        return {
            "total_categories": len(self.report.findings),
            "total_items_extracted": total_items,
            "categories_successful": successful,
            "categories_partial": partial,
            "categories_failed": failed,
            "files_analyzed": len(self.report.acquisition_summary.files_accessed),
            "errors_count": len([e for e in self.report.errors_and_warnings if e.status == ProcessingStatus.FAILED]),
            "warnings_count": len([e for e in self.report.errors_and_warnings if e.status == ProcessingStatus.PARTIAL])
        }
    
    @staticmethod
    def _json_serializer(obj: Any) -> Any:
        """Custom JSON serializer for non-standard types.
        
        Args:
            obj: Object to serialize.
            
        Returns:
            JSON-serializable representation.
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        if isinstance(obj, bytes):
            return obj.hex()
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        return str(obj)


class SummaryGenerator:
    """Generate executive summary text report."""
    
    def __init__(self, report: ForensicReport):
        """Initialize generator with report data.
        
        Args:
            report: ForensicReport object to summarize.
        """
        self.report = report
    
    def generate(self) -> str:
        """Generate executive summary.
        
        Returns:
            Plain text summary string.
        """
        lines = []
        
        # Header
        lines.append("=" * 78)
        lines.append("FIREFOX FORENSICS EXTRACTION - EXECUTIVE SUMMARY")
        lines.append("=" * 78)
        lines.append("")
        
        # Security Notice (abbreviated)
        lines.append("NOTICE: Read-only analysis | Local execution | Academic/forensic use only")
        lines.append("-" * 78)
        lines.append("")
        
        # Case Information
        meta = self.report.case_metadata
        lines.append("CASE INFORMATION")
        lines.append("-" * 40)
        lines.append(f"  Date (UTC):     {meta.date_utc}")
        lines.append(f"  Analyst:        {meta.analyst_username}")
        lines.append(f"  Host System:    {meta.host_os} ({meta.architecture})")
        lines.append(f"  Tool Version:   {meta.tool_version} (commit: {meta.commit_hash or 'N/A'})")
        lines.append("")
        
        # Acquisition Overview
        acq = self.report.acquisition_summary
        lines.append("ACQUISITION OVERVIEW")
        lines.append("-" * 40)
        lines.append(f"  Firefox Version:   {acq.firefox_version or 'Unknown'}")
        lines.append(f"  Profile Path:      {acq.profile_paths[0] if acq.profile_paths else 'N/A'}")
        lines.append(f"  Files Analyzed:    {len(acq.files_accessed)}")
        lines.append(f"  Access Mode:       {acq.access_mode}")
        
        # Calculate total data size
        total_size = sum(f.file_size for f in acq.files_accessed)
        lines.append(f"  Total Data Size:   {self._format_bytes(total_size)}")
        lines.append("")
        
        # Decryption Status
        ctx = self.report.decryption_context
        lines.append("DECRYPTION STATUS")
        lines.append("-" * 40)
        lines.append(f"  Master Password:   {ctx.master_password_status.replace('_', ' ').title()}")
        lines.append(f"  Decryption:        {ctx.decryption_status.value}")
        if ctx.failure_reason:
            lines.append(f"  Failure Reason:    {ctx.failure_reason}")
        lines.append("")
        
        # Findings Summary
        lines.append("FINDINGS SUMMARY")
        lines.append("-" * 40)
        
        # Create findings table
        findings_data = []
        for name, category in self.report.findings.items():
            findings_data.append((
                category.name,
                category.total_count,
                category.status.value
            ))
        
        # Sort by count descending
        findings_data.sort(key=lambda x: x[1], reverse=True)
        
        # Display as table
        lines.append(f"  {'Category':<30} {'Count':>10} {'Status':>12}")
        lines.append("  " + "-" * 54)
        
        total_items = 0
        for name, count, status in findings_data:
            lines.append(f"  {name:<30} {count:>10} {status:>12}")
            total_items += count
        
        lines.append("  " + "-" * 54)
        lines.append(f"  {'TOTAL':<30} {total_items:>10}")
        lines.append("")
        
        # Key Findings Highlight
        lines.append("KEY FINDINGS HIGHLIGHT")
        lines.append("-" * 40)
        
        # Count credentials/sensitive data
        credentials_count = 0
        passwords_count = 0
        
        for name, category in self.report.findings.items():
            if 'credential' in name.lower() or 'password' in name.lower():
                passwords_count += category.total_count
            elif 'cookie' in name.lower():
                credentials_count += category.total_count
        
        lines.append(f"  Saved Passwords Found:     {passwords_count}")
        lines.append(f"  Cookies Extracted:         {credentials_count}")
        
        # History stats
        history_count = 0
        for name, category in self.report.findings.items():
            if 'history' in name.lower() or 'visit' in name.lower():
                history_count += category.total_count
        
        lines.append(f"  History Entries:           {history_count}")
        lines.append("")
        
        # Errors/Warnings
        errors = [e for e in self.report.errors_and_warnings if e.status == ProcessingStatus.FAILED]
        warnings = [e for e in self.report.errors_and_warnings if e.status == ProcessingStatus.PARTIAL]
        
        if errors or warnings:
            lines.append("ERRORS AND WARNINGS")
            lines.append("-" * 40)
            lines.append(f"  Errors:   {len(errors)}")
            lines.append(f"  Warnings: {len(warnings)}")
            
            # Show first few errors
            if errors:
                lines.append("")
                lines.append("  Top Errors:")
                for err in errors[:3]:
                    lines.append(f"    - [{err.component}] {err.operation}: {err.message or 'No details'}")
            lines.append("")
        
        # Evidence Integrity
        lines.append("EVIDENCE INTEGRITY")
        lines.append("-" * 40)
        lines.append("  File                            SHA256 (first 16 chars)")
        lines.append("  " + "-" * 54)
        
        for evidence in acq.files_accessed[:10]:
            filename = evidence.original_path.split('/')[-1]
            lines.append(f"  {filename:<30} {evidence.sha256_hash[:16]}...")
        
        if len(acq.files_accessed) > 10:
            lines.append(f"  ... and {len(acq.files_accessed) - 10} more files")
        lines.append("")
        
        # Footer
        lines.append("=" * 78)
        lines.append("END OF EXECUTIVE SUMMARY")
        lines.append(f"Full details available in: report.html and report.json")
        lines.append("=" * 78)
        
        return "\n".join(lines)
    
    def save(self, output_path: Path) -> None:
        """Save summary to file.
        
        Args:
            output_path: Path to write summary file.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(self.generate())
    
    @staticmethod
    def _format_bytes(size_bytes: int) -> str:
        """Format bytes as human-readable string.
        
        Args:
            size_bytes: Size in bytes.
            
        Returns:
            Formatted string.
        """
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} TB"


class ReportOutputManager:
    """Manages generation of all report outputs."""
    
    def __init__(self, report: ForensicReport, output_dir: Path):
        """Initialize output manager.
        
        Args:
            report: ForensicReport object.
            output_dir: Directory to write reports to.
        """
        self.report = report
        self.output_dir = Path(output_dir)
    
    def generate_all(self) -> Dict[str, Path]:
        """Generate all report formats.
        
        Returns:
            Dictionary mapping format name to output path.
        """
        from html_renderer import ForensicHTMLRenderer
        
        outputs = {}
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate HTML report
        html_path = self.output_dir / "report.html"
        html_renderer = ForensicHTMLRenderer(self.report)
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_renderer.render())
        outputs['html'] = html_path
        
        # Generate JSON report
        json_path = self.output_dir / "report.json"
        json_generator = JSONReportGenerator(self.report)
        json_generator.save(json_path)
        outputs['json'] = json_path
        
        # Generate summary
        summary_path = self.output_dir / "summary.txt"
        summary_generator = SummaryGenerator(self.report)
        summary_generator.save(summary_path)
        outputs['summary'] = summary_path
        
        return outputs
