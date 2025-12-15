#!/usr/bin/env python3
"""
Firefox Forensics - Data Models for DFIR Reports
=================================================
Structured data models for forensic report generation.
Follows digital forensics best practices with full evidence integrity tracking.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import hashlib
import os
import platform
import subprocess
import sys


class ProcessingStatus(Enum):
    """Status indicators for processing steps."""
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


@dataclass
class FileEvidence:
    """Evidence integrity information for a source file."""
    original_path: str
    sha256_hash: str
    file_size: int
    last_modified: str  # ISO-8601 UTC
    last_modified_raw: float
    copied_path: Optional[str] = None
    access_mode: str = "read-only"
    
    @classmethod
    def from_path(cls, path: str, copied_path: Optional[str] = None) -> "FileEvidence":
        """Create FileEvidence from a file path."""
        import os
        from pathlib import Path
        
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        stat = p.stat()
        mtime = stat.st_mtime
        mtime_utc = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()
        
        # Calculate SHA256 hash
        sha256 = hashlib.sha256()
        with open(p, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
        
        return cls(
            original_path=str(p.absolute()),
            sha256_hash=sha256.hexdigest(),
            file_size=stat.st_size,
            last_modified=mtime_utc,
            last_modified_raw=mtime,
            copied_path=copied_path,
            access_mode="copied" if copied_path else "read-only"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "original_path": self.original_path,
            "sha256_hash": self.sha256_hash,
            "file_size": self.file_size,
            "last_modified": self.last_modified,
            "last_modified_raw": self.last_modified_raw,
            "copied_path": self.copied_path,
            "access_mode": self.access_mode
        }


@dataclass
class NormalizedTimestamp:
    """Normalized timestamp with raw and UTC representation."""
    raw: int
    utc: str
    local: Optional[str] = None
    
    @classmethod
    def from_firefox_timestamp(cls, value: Any, field_name: str = "") -> Optional["NormalizedTimestamp"]:
        """Convert Firefox timestamp to normalized format."""
        if value is None or value == '' or value == 0:
            return None
        
        try:
            ts = float(value)
            
            # Detect timestamp format based on magnitude
            if ts > 1e15:  # Microseconds (Firefox places.sqlite)
                ts_seconds = ts / 1000000
            elif ts > 1e12:  # Milliseconds
                ts_seconds = ts / 1000
            else:
                ts_seconds = ts
            
            # Sanity check: should be between 2000 and 2100
            if not (946684800 < ts_seconds < 4102444800):
                return None
            
            utc_dt = datetime.fromtimestamp(ts_seconds, tz=timezone.utc)
            local_dt = datetime.fromtimestamp(ts_seconds)
            
            return cls(
                raw=int(value),
                utc=utc_dt.strftime('%Y-%m-%dT%H:%M:%SZ'),
                local=local_dt.strftime('%Y-%m-%d %H:%M:%S')
            )
        except (ValueError, OSError, OverflowError):
            return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "raw": self.raw,
            "utc": self.utc,
            "local": self.local
        }


@dataclass
class ProcessingStep:
    """Record of a processing step with status."""
    component: str  # NSS / SQLite / OS / JSON
    operation: str
    status: ProcessingStatus
    message: Optional[str] = None
    cause: Optional[str] = None
    remediation: Optional[str] = None
    exception: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "component": self.component,
            "operation": self.operation,
            "status": self.status.value,
        }
        if self.message:
            result["message"] = self.message
        if self.cause:
            result["cause"] = self.cause
        if self.remediation:
            result["remediation"] = self.remediation
        if self.exception:
            result["exception"] = self.exception
        return result


@dataclass
class CaseMetadata:
    """Case metadata for forensic report header."""
    tool_name: str = "Firefox Forensics Extraction Tool"
    tool_version: str = "2.0.0"
    commit_hash: Optional[str] = None
    analyst_username: str = ""
    host_os: str = ""
    kernel_version: str = ""
    architecture: str = ""
    python_version: str = ""
    date_utc: str = ""
    date_local: str = ""
    nss_version: Optional[str] = None
    execution_args: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Populate system information."""
        if not self.analyst_username:
            self.analyst_username = os.getenv('USER', os.getenv('USERNAME', 'unknown'))
        
        if not self.host_os:
            self.host_os = f"{platform.system()} {platform.release()}"
        
        if not self.kernel_version:
            self.kernel_version = platform.version()
        
        if not self.architecture:
            self.architecture = platform.machine()
        
        if not self.python_version:
            self.python_version = sys.version
        
        if not self.date_utc:
            self.date_utc = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        
        if not self.date_local:
            self.date_local = datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')
        
        if not self.commit_hash:
            self.commit_hash = self._get_git_commit()
    
    @staticmethod
    def _get_git_commit() -> Optional[str]:
        """Get current git commit hash if available."""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', 'HEAD'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()[:8]
        except Exception:
            pass
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "commit_hash": self.commit_hash,
            "analyst_username": self.analyst_username,
            "host_os": self.host_os,
            "kernel_version": self.kernel_version,
            "architecture": self.architecture,
            "python_version": self.python_version,
            "date_utc": self.date_utc,
            "date_local": self.date_local,
            "nss_version": self.nss_version,
            "execution_args": self.execution_args
        }


@dataclass
class AcquisitionSummary:
    """Summary of data acquisition."""
    firefox_version: Optional[str] = None
    profile_paths: List[str] = field(default_factory=list)
    files_accessed: List[FileEvidence] = field(default_factory=list)
    access_mode: str = "read-only"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "firefox_version": self.firefox_version,
            "profile_paths": self.profile_paths,
            "files_accessed": [f.to_dict() for f in self.files_accessed],
            "access_mode": self.access_mode
        }


@dataclass
class DecryptionContext:
    """Context information for decryption operations."""
    nss_version: Optional[str] = None
    master_password_status: str = "unknown"  # set / not_set / unknown
    key_derivation_status: ProcessingStatus = ProcessingStatus.SKIPPED
    decryption_status: ProcessingStatus = ProcessingStatus.SKIPPED
    failure_reason: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "nss_version": self.nss_version,
            "master_password_status": self.master_password_status,
            "key_derivation_status": self.key_derivation_status.value,
            "decryption_status": self.decryption_status.value,
            "failure_reason": self.failure_reason
        }


@dataclass
class CredentialFinding:
    """A credential or sensitive data finding."""
    category: str  # saved_password / cookie / form_data / etc.
    source_file: str
    field_name: str
    value: str
    url: Optional[str] = None
    username: Optional[str] = None
    timestamp: Optional[NormalizedTimestamp] = None
    times_used: Optional[int] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "category": self.category,
            "source_file": self.source_file,
            "field_name": self.field_name,
            "value": self.value,
        }
        if self.url:
            result["url"] = self.url
        if self.username:
            result["username"] = self.username
        if self.timestamp:
            result["timestamp"] = self.timestamp.to_dict()
        if self.times_used is not None:
            result["times_used"] = self.times_used
        if self.additional_data:
            result["additional_data"] = self.additional_data
        return result


@dataclass
class FindingsCategory:
    """A category of forensic findings (credentials, cookies, history, etc.)."""
    name: str
    description: str
    total_count: int
    items: List[Dict[str, Any]]
    raw_sql_query: Optional[str] = None
    status: ProcessingStatus = ProcessingStatus.SUCCESS
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "total_count": self.total_count,
            "status": self.status.value,
            "error_message": self.error_message,
            "items": self.items,
            "raw_sql_query": self.raw_sql_query
        }


@dataclass
class ForensicReport:
    """Complete forensic report data structure."""
    case_metadata: CaseMetadata
    acquisition_summary: AcquisitionSummary
    decryption_context: DecryptionContext
    findings: Dict[str, FindingsCategory]  # {category_name: FindingsCategory}
    errors_and_warnings: List[ProcessingStep]
    appendix: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "case_metadata": self.case_metadata.to_dict(),
            "acquisition_summary": self.acquisition_summary.to_dict(),
            "decryption_context": self.decryption_context.to_dict(),
            "findings": {k: v.to_dict() for k, v in self.findings.items()},
            "errors_and_warnings": [e.to_dict() for e in self.errors_and_warnings],
            "appendix": self.appendix
        }


# Security and Ethics Banner Text
SECURITY_BANNER = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                           SECURITY & ETHICS NOTICE                            ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  • This report was generated using READ-ONLY analysis methods                 ║
║  • All processing was performed LOCALLY on the analysis system                ║
║  • No data was transmitted externally or persisted beyond this report         ║
║  • This tool is intended for ACADEMIC, PERSONAL FORENSIC, and AUTHORIZED      ║
║    SECURITY RESEARCH purposes only                                            ║
║  • Unauthorized access to computer data may violate applicable laws           ║
║  • The analyst is responsible for ensuring proper authorization               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
