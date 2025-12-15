#!/usr/bin/env python3
"""
Firefox Forensics - Report Builder
===================================
Main orchestration module for building complete forensic reports.
Integrates evidence collection, data extraction, and report generation.
"""

import sqlite3
import json
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import sys

from forensic_models import (
    ForensicReport,
    CaseMetadata,
    AcquisitionSummary,
    DecryptionContext,
    FindingsCategory,
    ProcessingStep,
    ProcessingStatus,
    FileEvidence,
)
from evidence_integrity import EvidenceIntegrityManager
from timestamp_utils import TimestampNormalizer, normalize_row_timestamps
from queries import QUERY_REGISTRY


class ForensicReportBuilder:
    """Builds complete forensic reports from Firefox profiles."""
    
    def __init__(
        self,
        profile_path: Path,
        output_dir: Path,
        copy_artifacts: bool = False,
        execution_args: Optional[List[str]] = None
    ):
        """Initialize report builder.
        
        Args:
            profile_path: Path to Firefox profile directory.
            output_dir: Path to output directory.
            copy_artifacts: Whether to copy source files as read-only artifacts.
            execution_args: Command line arguments used for execution.
        """
        self.profile_path = Path(profile_path)
        self.output_dir = Path(output_dir)
        self.copy_artifacts = copy_artifacts
        self.execution_args = execution_args or []
        
        # Initialize components
        self.evidence_manager = EvidenceIntegrityManager(profile_path, output_dir)
        self.timestamp_normalizer = TimestampNormalizer()
        
        # Processing state
        self.findings: Dict[str, FindingsCategory] = {}
        self.errors_and_warnings: List[ProcessingStep] = []
        self.appendix: Dict[str, Any] = {
            'sql_queries': {},
            'raw_json_objects': {},
            'stack_traces': []
        }
        
        # Decryption state
        self.decryption_context = DecryptionContext()
        self.decrypted_passwords: List[Dict] = []
    
    def build(self) -> ForensicReport:
        """Build complete forensic report.
        
        Returns:
            Complete ForensicReport object.
        """
        # Step 1: Collect evidence integrity information
        evidence_files = self.evidence_manager.collect_evidence_files(self.copy_artifacts)
        
        # Step 2: Detect Firefox version
        firefox_version = self._detect_firefox_version()
        
        # Step 3: Extract database data
        self._extract_all_databases()
        
        # Step 4: Extract JSON artifacts
        self._extract_json_artifacts()
        
        # Step 5: Attempt password decryption
        self._attempt_password_decryption()
        
        # Step 6: Collect processing errors
        self.errors_and_warnings.extend(self.evidence_manager.processing_log)
        
        # Step 7: Build case metadata
        case_metadata = CaseMetadata(
            execution_args=self.execution_args,
            nss_version=self.decryption_context.nss_version
        )
        
        # Step 8: Build acquisition summary
        acquisition_summary = AcquisitionSummary(
            firefox_version=firefox_version,
            profile_paths=[str(self.profile_path)],
            files_accessed=evidence_files,
            access_mode="copied" if self.copy_artifacts else "read-only"
        )
        
        # Step 9: Build and return report
        return ForensicReport(
            case_metadata=case_metadata,
            acquisition_summary=acquisition_summary,
            decryption_context=self.decryption_context,
            findings=self.findings,
            errors_and_warnings=self.errors_and_warnings,
            appendix=self.appendix
        )
    
    def _detect_firefox_version(self) -> Optional[str]:
        """Detect Firefox version from profile.
        
        Returns:
            Firefox version string or None.
        """
        # Try compatibility.ini
        compat_file = self.profile_path / "compatibility.ini"
        if compat_file.exists():
            try:
                with open(compat_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if line.startswith('LastVersion='):
                            version = line.split('=')[1].strip()
                            # Extract just version number (e.g., "133.0_20241119185447" -> "133.0")
                            return version.split('_')[0]
            except Exception:
                pass
        
        # Try prefs.js
        prefs_file = self.profile_path / "prefs.js"
        if prefs_file.exists():
            try:
                with open(prefs_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Look for app.update.lastUpdateTime.background-update-timer
                    if 'extensions.lastAppVersion' in content:
                        for line in content.split('\n'):
                            if 'extensions.lastAppVersion' in line:
                                # Extract version from pref line
                                parts = line.split('"')
                                if len(parts) >= 4:
                                    return parts[3]
            except Exception:
                pass
        
        return None
    
    def _extract_all_databases(self) -> None:
        """Extract data from all SQLite databases."""
        databases = self.evidence_manager.get_sqlite_databases()
        
        for db_path in databases:
            self._extract_database(db_path)
    
    def _extract_database(self, db_path: Path) -> None:
        """Extract data from a single SQLite database.
        
        Args:
            db_path: Path to SQLite database.
        """
        db_name = db_path.name
        
        # Check if we have queries for this database
        if db_name not in QUERY_REGISTRY:
            return
        
        queries = QUERY_REGISTRY[db_name]
        
        for query_name, query_sql in queries.items():
            try:
                rows, error = self._execute_query(db_path, query_sql)
                
                if error:
                    self.errors_and_warnings.append(ProcessingStep(
                        component="SQLite",
                        operation=f"{db_name}:{query_name}",
                        status=ProcessingStatus.FAILED,
                        message=error,
                        cause=self._diagnose_sqlite_error(error),
                        remediation=self._suggest_sqlite_remediation(error)
                    ))
                    
                    self.findings[query_name] = FindingsCategory(
                        name=self._format_query_name(query_name),
                        description=f"Data from {db_name}",
                        total_count=0,
                        items=[],
                        raw_sql_query=query_sql,
                        status=ProcessingStatus.FAILED,
                        error_message=error
                    )
                else:
                    # Normalize timestamps in results
                    normalized_rows = [normalize_row_timestamps(row) for row in rows]
                    
                    self.findings[query_name] = FindingsCategory(
                        name=self._format_query_name(query_name),
                        description=f"Data from {db_name}",
                        total_count=len(normalized_rows),
                        items=normalized_rows,
                        raw_sql_query=query_sql,
                        status=ProcessingStatus.SUCCESS
                    )
                    
                    # Store query in appendix
                    self.appendix['sql_queries'][query_name] = query_sql
                    
            except Exception as e:
                self.errors_and_warnings.append(ProcessingStep(
                    component="SQLite",
                    operation=f"{db_name}:{query_name}",
                    status=ProcessingStatus.FAILED,
                    message=str(e),
                    exception=traceback.format_exc()
                ))
                
                self.appendix['stack_traces'].append({
                    'operation': f"{db_name}:{query_name}",
                    'trace': traceback.format_exc()
                })
    
    def _execute_query(self, db_path: Path, query: str) -> Tuple[List[Dict], Optional[str]]:
        """Execute SQL query against database.
        
        Args:
            db_path: Path to database.
            query: SQL query string.
            
        Returns:
            Tuple of (results, error_message).
        """
        try:
            # Use URI mode for read-only access
            uri = f"file:{db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
            conn.close()
            
            return [dict(row) for row in rows], None
            
        except sqlite3.OperationalError as e:
            error_msg = str(e)
            if "database is locked" in error_msg:
                return [], f"Database is locked: {db_path.name}"
            elif "no such table" in error_msg:
                return [], f"Table not found: {error_msg}"
            else:
                return [], f"SQLite error: {error_msg}"
        except Exception as e:
            return [], f"Error: {str(e)}"
    
    def _diagnose_sqlite_error(self, error: str) -> str:
        """Diagnose the cause of a SQLite error.
        
        Args:
            error: Error message.
            
        Returns:
            Probable cause description.
        """
        if "locked" in error.lower():
            return "Firefox is running and holding a lock on the database"
        elif "no such table" in error.lower():
            return "Database schema differs from expected (possibly different Firefox version)"
        elif "permission" in error.lower():
            return "Insufficient file permissions to read database"
        elif "corrupt" in error.lower():
            return "Database file appears to be corrupted"
        else:
            return "Unknown SQLite error"
    
    def _suggest_sqlite_remediation(self, error: str) -> str:
        """Suggest remediation for a SQLite error.
        
        Args:
            error: Error message.
            
        Returns:
            Suggested action.
        """
        if "locked" in error.lower():
            return "Close Firefox or copy profile directory to a separate location"
        elif "no such table" in error.lower():
            return "Update forensic queries to match current Firefox schema"
        elif "permission" in error.lower():
            return "Run with elevated privileges or adjust file permissions"
        elif "corrupt" in error.lower():
            return "Attempt database recovery using sqlite3 .recover command"
        else:
            return "Check database integrity and permissions"
    
    def _format_query_name(self, query_name: str) -> str:
        """Format query name for display.
        
        Args:
            query_name: Raw query name.
            
        Returns:
            Human-readable name.
        """
        # Convert PLACES_HISTORY_ALL -> "Places History All"
        words = query_name.lower().split('_')
        return ' '.join(word.capitalize() for word in words)
    
    def _extract_json_artifacts(self) -> None:
        """Extract data from JSON configuration files."""
        json_files = self.evidence_manager.get_json_files()
        
        for json_path in json_files:
            self._extract_json_file(json_path)
    
    def _extract_json_file(self, json_path: Path) -> None:
        """Extract data from a single JSON file.
        
        Args:
            json_path: Path to JSON file.
        """
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Store raw JSON in appendix
            self.appendix['raw_json_objects'][json_path.name] = data
            
            # Parse specific known files
            if json_path.name == 'logins.json':
                self._process_logins_json(data)
            elif json_path.name in ['extensions.json', 'addons.json']:
                self._process_extensions_json(data, json_path.name)
            elif json_path.name == 'handlers.json':
                self._process_handlers_json(data)
            
            self.errors_and_warnings.append(ProcessingStep(
                component="JSON",
                operation=f"parse:{json_path.name}",
                status=ProcessingStatus.SUCCESS,
                message=f"Parsed successfully"
            ))
            
        except json.JSONDecodeError as e:
            self.errors_and_warnings.append(ProcessingStep(
                component="JSON",
                operation=f"parse:{json_path.name}",
                status=ProcessingStatus.FAILED,
                message=f"Invalid JSON: {str(e)}",
                cause="File is not valid JSON or is corrupted",
                remediation="Check file integrity"
            ))
        except Exception as e:
            self.errors_and_warnings.append(ProcessingStep(
                component="JSON",
                operation=f"parse:{json_path.name}",
                status=ProcessingStatus.FAILED,
                message=str(e),
                exception=traceback.format_exc()
            ))
    
    def _process_logins_json(self, data: Dict) -> None:
        """Process logins.json for encrypted credentials.
        
        Args:
            data: Parsed JSON data.
        """
        logins = data.get('logins', [])
        
        items = []
        for login in logins:
            item = {
                'id': login.get('id'),
                'hostname': login.get('hostname'),
                'formSubmitURL': login.get('formSubmitURL'),
                'usernameField': login.get('usernameField'),
                'passwordField': login.get('passwordField'),
                'encryptedUsername': login.get('encryptedUsername', '')[:50] + '...' if login.get('encryptedUsername') else None,
                'encryptedPassword': login.get('encryptedPassword', '')[:50] + '...' if login.get('encryptedPassword') else None,
                'timesUsed': login.get('timesUsed'),
                'timeCreated': login.get('timeCreated'),
                'timeLastUsed': login.get('timeLastUsed'),
                'timePasswordChanged': login.get('timePasswordChanged'),
            }
            # Normalize timestamps
            items.append(normalize_row_timestamps(item))
        
        self.findings['logins_encrypted'] = FindingsCategory(
            name="Saved Logins (Encrypted)",
            description="Encrypted login credentials from logins.json",
            total_count=len(items),
            items=items,
            status=ProcessingStatus.SUCCESS
        )
    
    def _process_extensions_json(self, data: Dict, filename: str) -> None:
        """Process extensions/addons JSON.
        
        Args:
            data: Parsed JSON data.
            filename: Source filename.
        """
        addons = data.get('addons', [])
        
        items = []
        for addon in addons:
            item = {
                'id': addon.get('id'),
                'name': addon.get('name'),
                'version': addon.get('version'),
                'type': addon.get('type'),
                'active': addon.get('active'),
                'installDate': addon.get('installDate'),
                'updateDate': addon.get('updateDate'),
                'permissions': ', '.join(addon.get('permissions', [])) if addon.get('permissions') else None,
            }
            items.append(normalize_row_timestamps(item))
        
        self.findings['browser_extensions'] = FindingsCategory(
            name="Browser Extensions",
            description=f"Installed extensions from {filename}",
            total_count=len(items),
            items=items,
            status=ProcessingStatus.SUCCESS
        )
    
    def _process_handlers_json(self, data: Dict) -> None:
        """Process handlers.json for protocol handlers.
        
        Args:
            data: Parsed JSON data.
        """
        handlers = data.get('schemes', {})
        
        items = []
        for scheme, handler_data in handlers.items():
            item = {
                'scheme': scheme,
                'handlers': str(handler_data)[:200]
            }
            items.append(item)
        
        if items:
            self.findings['protocol_handlers'] = FindingsCategory(
                name="Protocol Handlers",
                description="Custom protocol handlers from handlers.json",
                total_count=len(items),
                items=items,
                status=ProcessingStatus.SUCCESS
            )
    
    def _attempt_password_decryption(self) -> None:
        """Attempt to decrypt saved passwords."""
        try:
            from nss_decrypt import (
                decrypt_firefox_passwords,
                validate_environment,
                check_master_password_required,
                check_nss_library_available,
                UnsupportedEnvironment,
                NSSLibraryMissing,
                OSKeyringLocked,
                MasterPasswordRequired,
            )
            
            # Try to get NSS version
            try:
                available, lib_path, _ = check_nss_library_available()
                if available and lib_path:
                    self.decryption_context.nss_version = lib_path
            except Exception:
                pass
            
            # Validate environment first
            try:
                validate_environment(self.profile_path)
            except UnsupportedEnvironment as e:
                self.decryption_context.decryption_status = ProcessingStatus.FAILED
                self.decryption_context.failure_reason = f"Unsupported environment: {str(e)}"
                self.errors_and_warnings.append(ProcessingStep(
                    component="NSS",
                    operation="validate_environment",
                    status=ProcessingStatus.FAILED,
                    message=str(e),
                    cause="Firefox installation type not supported for decryption",
                    remediation="Use native Firefox installation (not Snap/Flatpak)"
                ))
                return
            except NSSLibraryMissing as e:
                self.decryption_context.decryption_status = ProcessingStatus.FAILED
                self.decryption_context.failure_reason = f"NSS library not found: {str(e)}"
                self.errors_and_warnings.append(ProcessingStep(
                    component="NSS",
                    operation="load_library",
                    status=ProcessingStatus.FAILED,
                    message=str(e),
                    cause="NSS library (libnss3) not installed or not found",
                    remediation="Install libnss3 package or ensure Firefox is properly installed"
                ))
                return
            except OSKeyringLocked as e:
                self.decryption_context.decryption_status = ProcessingStatus.FAILED
                self.decryption_context.failure_reason = f"OS keyring locked: {str(e)}"
                return
            
            # Check if master password is required
            try:
                requires_master = check_master_password_required(self.profile_path)
                self.decryption_context.master_password_status = "set" if requires_master else "not_set"
            except Exception:
                self.decryption_context.master_password_status = "unknown"
            
            # Attempt decryption (without master password for now)
            passwords, error = decrypt_firefox_passwords(self.profile_path, "")
            
            if error:
                if "master password" in error.lower():
                    self.decryption_context.decryption_status = ProcessingStatus.PARTIAL
                    self.decryption_context.failure_reason = "Master password required"
                    self.decryption_context.master_password_status = "set"
                else:
                    self.decryption_context.decryption_status = ProcessingStatus.FAILED
                    self.decryption_context.failure_reason = error
            elif passwords:
                self.decryption_context.decryption_status = ProcessingStatus.SUCCESS
                self.decryption_context.key_derivation_status = ProcessingStatus.SUCCESS
                
                # Add decrypted passwords to findings
                items = []
                for pwd in passwords:
                    item = {
                        'hostname': pwd.hostname,
                        'username': pwd.username,
                        'password': pwd.password,
                        'formSubmitURL': pwd.form_submit_url,
                        'timesUsed': pwd.times_used,
                        'timeCreated': pwd.time_created,
                        'timeLastUsed': pwd.time_last_used,
                    }
                    items.append(normalize_row_timestamps(item))
                
                self.findings['saved_credentials_decrypted'] = FindingsCategory(
                    name="Saved Credentials (Decrypted)",
                    description="Decrypted saved passwords from Firefox",
                    total_count=len(items),
                    items=items,
                    status=ProcessingStatus.SUCCESS
                )
                
                self.decrypted_passwords = items
            else:
                self.decryption_context.decryption_status = ProcessingStatus.SUCCESS
                self.decryption_context.key_derivation_status = ProcessingStatus.SUCCESS
                
        except ImportError as e:
            self.decryption_context.decryption_status = ProcessingStatus.SKIPPED
            self.decryption_context.failure_reason = f"Decryption module not available: {str(e)}"
        except Exception as e:
            self.decryption_context.decryption_status = ProcessingStatus.FAILED
            self.decryption_context.failure_reason = str(e)
            self.errors_and_warnings.append(ProcessingStep(
                component="NSS",
                operation="decrypt_passwords",
                status=ProcessingStatus.FAILED,
                message=str(e),
                exception=traceback.format_exc()
            ))
            self.appendix['stack_traces'].append({
                'operation': 'decrypt_passwords',
                'trace': traceback.format_exc()
            })
    
    def set_decrypted_passwords(self, passwords: List, master_password_used: bool = False) -> None:
        """Set decrypted passwords from external source.
        
        Args:
            passwords: List of decrypted password objects.
            master_password_used: Whether master password was provided.
        """
        self.decryption_context.decryption_status = ProcessingStatus.SUCCESS
        self.decryption_context.key_derivation_status = ProcessingStatus.SUCCESS
        
        if master_password_used:
            self.decryption_context.master_password_status = "set"
        
        items = []
        for pwd in passwords:
            item = {
                'hostname': pwd.hostname,
                'username': pwd.username,
                'password': pwd.password,
                'formSubmitURL': pwd.form_submit_url,
                'timesUsed': pwd.times_used,
                'timeCreated': pwd.time_created,
                'timeLastUsed': pwd.time_last_used,
            }
            items.append(normalize_row_timestamps(item))
        
        self.findings['saved_credentials_decrypted'] = FindingsCategory(
            name="Saved Credentials (Decrypted)",
            description="Decrypted saved passwords from Firefox",
            total_count=len(items),
            items=items,
            status=ProcessingStatus.SUCCESS
        )
        
        self.decrypted_passwords = items


def build_forensic_report(
    profile_path: Path,
    output_dir: Path,
    copy_artifacts: bool = False,
    execution_args: Optional[List[str]] = None
) -> ForensicReport:
    """Convenience function to build a forensic report.
    
    Args:
        profile_path: Path to Firefox profile.
        output_dir: Output directory.
        copy_artifacts: Whether to copy source files.
        execution_args: Command line arguments.
        
    Returns:
        Complete ForensicReport object.
    """
    builder = ForensicReportBuilder(
        profile_path=profile_path,
        output_dir=output_dir,
        copy_artifacts=copy_artifacts,
        execution_args=execution_args
    )
    return builder.build()
