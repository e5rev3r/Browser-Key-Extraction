#!/usr/bin/env python3
"""
Firefox Forensics - Evidence Integrity Module
==============================================
Handles file hashing, integrity verification, and read-only artifact copying.
Follows digital forensics evidence handling best practices.
"""

import hashlib
import os
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from forensic_models import FileEvidence, ProcessingStatus, ProcessingStep


class EvidenceIntegrityManager:
    """Manages evidence integrity for forensic analysis."""
    
    # Files that should be collected as evidence
    EVIDENCE_FILES = [
        "places.sqlite",
        "cookies.sqlite",
        "formhistory.sqlite",
        "permissions.sqlite",
        "webappsstore.sqlite",
        "favicons.sqlite",
        "content-prefs.sqlite",
        "storage.sqlite",
        "logins.json",
        "key4.db",
        "key3.db",  # Legacy
        "cert9.db",
        "cert8.db",  # Legacy
        "extensions.json",
        "addons.json",
        "search.json.mozlz4",
        "prefs.js",
        "sessionstore.jsonlz4",
        "handlers.json",
    ]
    
    def __init__(self, profile_path: Path, output_dir: Path):
        """Initialize evidence manager.
        
        Args:
            profile_path: Path to Firefox profile directory.
            output_dir: Path to output directory for artifacts.
        """
        self.profile_path = Path(profile_path)
        self.output_dir = Path(output_dir)
        self.artifacts_dir = self.output_dir / "artifacts"
        self.evidence_log: List[FileEvidence] = []
        self.processing_log: List[ProcessingStep] = []
    
    def calculate_sha256(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file.
        
        Args:
            file_path: Path to file to hash.
            
        Returns:
            Hex digest of SHA256 hash.
        """
        sha256 = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            self.processing_log.append(ProcessingStep(
                component="OS",
                operation=f"hash_file:{file_path.name}",
                status=ProcessingStatus.FAILED,
                message=f"Failed to calculate SHA256 hash",
                exception=str(e)
            ))
            return ""
    
    def get_file_metadata(self, file_path: Path) -> Dict:
        """Get comprehensive file metadata.
        
        Args:
            file_path: Path to file.
            
        Returns:
            Dictionary with file metadata.
        """
        try:
            stat_info = file_path.stat()
            mtime_utc = datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc)
            
            return {
                "path": str(file_path.absolute()),
                "size": stat_info.st_size,
                "mtime_raw": stat_info.st_mtime,
                "mtime_utc": mtime_utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
                "atime_raw": stat_info.st_atime,
                "ctime_raw": stat_info.st_ctime,
                "mode": oct(stat_info.st_mode),
                "uid": stat_info.st_uid,
                "gid": stat_info.st_gid,
            }
        except Exception as e:
            return {"error": str(e)}
    
    def create_file_evidence(self, file_path: Path, copied_path: Optional[Path] = None) -> FileEvidence:
        """Create evidence record for a file.
        
        Args:
            file_path: Original file path.
            copied_path: Path to copied file (if applicable).
            
        Returns:
            FileEvidence object.
        """
        stat_info = file_path.stat()
        mtime_utc = datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc)
        
        evidence = FileEvidence(
            original_path=str(file_path.absolute()),
            sha256_hash=self.calculate_sha256(file_path),
            file_size=stat_info.st_size,
            last_modified=mtime_utc.strftime('%Y-%m-%dT%H:%M:%SZ'),
            last_modified_raw=stat_info.st_mtime,
            copied_path=str(copied_path.absolute()) if copied_path else None,
            access_mode="copied" if copied_path else "read-only"
        )
        
        return evidence
    
    def copy_artifact_readonly(self, src_path: Path) -> Tuple[Optional[Path], Optional[str]]:
        """Copy a file to artifacts directory as read-only.
        
        Args:
            src_path: Source file path.
            
        Returns:
            Tuple of (destination_path, error_message).
        """
        if not src_path.exists():
            return None, f"Source file not found: {src_path}"
        
        try:
            # Create artifacts directory if needed
            self.artifacts_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate destination path with timestamp prefix for uniqueness
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            dest_name = f"{timestamp}_{src_path.name}"
            dest_path = self.artifacts_dir / dest_name
            
            # Copy file
            shutil.copy2(src_path, dest_path)
            
            # Make read-only
            current_mode = dest_path.stat().st_mode
            readonly_mode = current_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
            dest_path.chmod(readonly_mode)
            
            self.processing_log.append(ProcessingStep(
                component="OS",
                operation=f"copy_artifact:{src_path.name}",
                status=ProcessingStatus.SUCCESS,
                message=f"Copied to {dest_path}"
            ))
            
            return dest_path, None
            
        except PermissionError as e:
            error = f"Permission denied copying {src_path.name}"
            self.processing_log.append(ProcessingStep(
                component="OS",
                operation=f"copy_artifact:{src_path.name}",
                status=ProcessingStatus.FAILED,
                message=error,
                cause="Insufficient permissions to read source or write destination",
                remediation="Run with elevated privileges or check file permissions",
                exception=str(e)
            ))
            return None, error
            
        except Exception as e:
            error = f"Failed to copy {src_path.name}: {str(e)}"
            self.processing_log.append(ProcessingStep(
                component="OS",
                operation=f"copy_artifact:{src_path.name}",
                status=ProcessingStatus.FAILED,
                message=error,
                exception=str(e)
            ))
            return None, error
    
    def collect_evidence_files(self, copy_artifacts: bool = False) -> List[FileEvidence]:
        """Collect evidence information for all relevant files.
        
        Args:
            copy_artifacts: Whether to copy files to artifacts directory.
            
        Returns:
            List of FileEvidence objects.
        """
        evidence_list = []
        
        for filename in self.EVIDENCE_FILES:
            file_path = self.profile_path / filename
            
            if not file_path.exists():
                continue
            
            try:
                copied_path = None
                
                if copy_artifacts:
                    copied_path, error = self.copy_artifact_readonly(file_path)
                    if error:
                        # Log but continue - we can still analyze original
                        pass
                
                evidence = self.create_file_evidence(file_path, copied_path)
                evidence_list.append(evidence)
                
                self.processing_log.append(ProcessingStep(
                    component="OS",
                    operation=f"collect_evidence:{filename}",
                    status=ProcessingStatus.SUCCESS,
                    message=f"SHA256: {evidence.sha256_hash[:16]}..."
                ))
                
            except Exception as e:
                self.processing_log.append(ProcessingStep(
                    component="OS",
                    operation=f"collect_evidence:{filename}",
                    status=ProcessingStatus.FAILED,
                    message=f"Failed to collect evidence",
                    exception=str(e)
                ))
        
        self.evidence_log = evidence_list
        return evidence_list
    
    def verify_evidence_integrity(self, evidence: FileEvidence) -> Tuple[bool, str]:
        """Verify that a file hasn't been modified since evidence collection.
        
        Args:
            evidence: FileEvidence object to verify.
            
        Returns:
            Tuple of (is_valid, message).
        """
        try:
            file_path = Path(evidence.original_path)
            if not file_path.exists():
                return False, "Original file no longer exists"
            
            current_hash = self.calculate_sha256(file_path)
            
            if current_hash == evidence.sha256_hash:
                return True, "Hash verified - file unchanged"
            else:
                return False, f"Hash mismatch - file has been modified (original: {evidence.sha256_hash[:16]}..., current: {current_hash[:16]}...)"
                
        except Exception as e:
            return False, f"Verification failed: {str(e)}"
    
    def generate_evidence_manifest(self) -> Dict:
        """Generate a manifest of all collected evidence.
        
        Returns:
            Dictionary containing evidence manifest.
        """
        manifest = {
            "collection_time": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            "profile_path": str(self.profile_path.absolute()),
            "artifacts_directory": str(self.artifacts_dir.absolute()) if self.artifacts_dir.exists() else None,
            "total_files": len(self.evidence_log),
            "total_size_bytes": sum(e.file_size for e in self.evidence_log),
            "files": [e.to_dict() for e in self.evidence_log]
        }
        
        return manifest
    
    def get_sqlite_databases(self) -> List[Path]:
        """Get list of SQLite database files in profile.
        
        Returns:
            List of paths to SQLite files.
        """
        databases = []
        for file_path in self.profile_path.glob("*.sqlite"):
            if file_path.is_file():
                databases.append(file_path)
        return sorted(databases)
    
    def get_json_files(self) -> List[Path]:
        """Get list of JSON files in profile.
        
        Returns:
            List of paths to JSON files.
        """
        json_files = []
        for file_path in self.profile_path.glob("*.json"):
            if file_path.is_file():
                json_files.append(file_path)
        return sorted(json_files)


def format_file_size(size_bytes: int) -> str:
    """Format bytes as human-readable string.
    
    Args:
        size_bytes: Size in bytes.
        
    Returns:
        Formatted string (e.g., "1.5 MB").
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"
