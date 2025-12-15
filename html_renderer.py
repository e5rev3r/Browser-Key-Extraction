#!/usr/bin/env python3
"""
Firefox Forensics - HTML Report Renderer
=========================================
Generates forensic-grade HTML reports following DFIR best practices.

Features:
- Professional forensic UI with semantic color grading
- Global and per-table search functionality
- Separate username/password fields with masking and reveal
- Sorting and filtering capabilities
- Expandable raw data views
- Copy-to-clipboard with warnings
- Sticky headers and responsive design
- Evidence integrity display
"""

import html
import json
from typing import Any, Dict, List, Optional, Tuple

from forensic_models import (
    ForensicReport,
    ProcessingStatus,
    FindingsCategory,
    SECURITY_BANNER,
)


# Finding categories ordered by forensic importance
CATEGORY_ORDER = {
    # High-value findings (credentials, auth)
    'saved_credentials_decrypted': 1,
    'logins_encrypted': 2,
    'COOKIES_AUTH_TOKENS': 3,
    'COOKIES_AUTH_HIGH_PRIORITY': 4,
    'COOKIES_PERSISTENT_SESSIONS': 5,
    
    # Supporting auth data
    'FORMHISTORY_SENSITIVE_FIELDS': 10,
    'FORMHISTORY_EMAILS': 11,
    'FORMHISTORY_ALL_EMAILS': 12,
    'FORMHISTORY_USERNAMES': 13,
    'PLACES_LOGIN_URLS': 14,
    
    # Session/storage data
    'WEBAPPSSTORE_LOCALSTORAGE': 20,
    'STORAGE_ORIGINS': 21,
    'STORAGE_ALL': 22,
    
    # Browsing activity
    'PLACES_HISTORY_ALL': 30,
    'PLACES_RECENT_24H': 31,
    'PLACES_BOOKMARKS': 32,
    'PLACES_TOP_SITES': 33,
    'PLACES_DOWNLOADS': 34,
    'PLACES_REFERRER_CHAINS': 35,
    'PLACES_SEARCH_QUERIES': 36,
    
    # Permissions
    'PERMISSIONS_ALL': 40,
    'PERMISSIONS_GRANTED': 41,
    'PERMISSIONS_GEOLOCATION': 42,
    'PERMISSIONS_MEDIA': 43,
    'PERMISSIONS_NOTIFICATIONS': 44,
    'PERMISSIONS_SENSITIVE': 45,
    
    # Cookies (lower priority, high volume)
    'COOKIES_ALL': 50,
    'COOKIES_BY_DOMAIN': 51,
    
    # Form data (general)
    'FORMHISTORY_ALL': 60,
    'FORMHISTORY_PERSONAL_INFO': 61,
    'FORMHISTORY_SEARCH_QUERIES': 62,
    
    # Extensions/misc
    'browser_extensions': 70,
    'protocol_handlers': 71,
    'FAVICONS_MAPPING': 80,
}

# Category importance levels for color grading
IMPORTANCE_LEVELS = {
    'critical': ['saved_credentials_decrypted', 'logins_encrypted'],
    'high': ['COOKIES_AUTH_TOKENS', 'COOKIES_AUTH_HIGH_PRIORITY', 'COOKIES_PERSISTENT_SESSIONS',
             'FORMHISTORY_SENSITIVE_FIELDS', 'PLACES_LOGIN_URLS'],
    'medium': ['WEBAPPSSTORE_LOCALSTORAGE', 'PLACES_HISTORY_ALL', 'PLACES_BOOKMARKS',
               'browser_extensions', 'PERMISSIONS_ALL'],
    'low': ['COOKIES_ALL', 'COOKIES_BY_DOMAIN', 'FAVICONS_MAPPING', 'FORMHISTORY_ALL']
}


class ForensicHTMLRenderer:
    """Render forensic reports as HTML with professional DFIR formatting."""
    
    def __init__(self, report: ForensicReport):
        """Initialize renderer with report data.
        
        Args:
            report: ForensicReport object to render.
        """
        self.report = report
    
    def render(self) -> str:
        """Generate complete HTML report.
        
        Returns:
            Complete HTML document as string.
        """
        # Order findings by importance
        ordered_findings = self._order_findings()
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Firefox Forensics Report - {html.escape(self.report.case_metadata.date_utc)}</title>
    <style>
{self._get_styles()}
    </style>
</head>
<body>
    <div class="report-container">
        {self._render_global_search()}
        {self._render_security_banner()}
        {self._render_toc(ordered_findings)}
        {self._render_case_metadata()}
        {self._render_acquisition_summary()}
        {self._render_decryption_context()}
        {self._render_errors_and_warnings()}
        {self._render_findings(ordered_findings)}
        {self._render_appendix()}
        {self._render_footer()}
    </div>
    <script>
{self._get_scripts()}
    </script>
</body>
</html>"""
    
    def _order_findings(self) -> List[Tuple[str, FindingsCategory]]:
        """Order findings by forensic importance.
        
        Returns:
            List of (name, category) tuples ordered by importance.
        """
        findings_list = list(self.report.findings.items())
        
        def get_order(item):
            name, category = item
            return CATEGORY_ORDER.get(name, 100)
        
        return sorted(findings_list, key=get_order)
    
    def _get_importance_level(self, category_name: str) -> str:
        """Get importance level for a category.
        
        Args:
            category_name: Name of the category.
            
        Returns:
            Importance level string.
        """
        for level, categories in IMPORTANCE_LEVELS.items():
            if category_name in categories:
                return level
        return 'standard'
    
    def _get_styles(self) -> str:
        """Get CSS styles for forensic report."""
        return """
        :root {
            /* Base colors - neutral professional palette */
            --bg-primary: #f8f9fa;
            --bg-secondary: #ffffff;
            --bg-code: #f4f4f4;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --border-color: #dee2e6;
            
            /* Semantic colors - minimal palette */
            --accent-primary: #495057;      /* Dark slate for case-critical */
            --accent-high: #0d6efd;         /* Professional blue for high-value */
            --accent-medium: #6c757d;       /* Neutral for supporting data */
            
            /* Status colors - muted, not alarming */
            --status-success: #198754;
            --status-partial: #fd7e14;
            --status-failed: #dc3545;
            --status-skipped: #6c757d;
            
            /* Functional */
            --highlight-sensitive: #fff3cd;
            --mono-font: 'Consolas', 'Monaco', 'Courier New', monospace;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            font-size: 14px;
            line-height: 1.5;
            color: var(--text-primary);
            background: var(--bg-primary);
        }
        
        .report-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Global Search Bar */
        .global-search {
            position: sticky;
            top: 0;
            z-index: 1000;
            background: var(--bg-secondary);
            padding: 15px 20px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .search-container {
            display: flex;
            gap: 10px;
            align-items: center;
        }
        
        .search-input {
            flex: 1;
            padding: 10px 15px;
            font-size: 14px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-family: var(--mono-font);
        }
        
        .search-input:focus {
            outline: none;
            border-color: var(--accent-high);
            box-shadow: 0 0 0 2px rgba(13, 110, 253, 0.15);
        }
        
        .search-stats {
            font-size: 12px;
            color: var(--text-secondary);
            margin-left: 10px;
        }
        
        .search-clear {
            padding: 8px 15px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        
        .search-clear:hover {
            background: #e9ecef;
        }
        
        /* Table of Contents */
        .toc {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 15px 20px;
            margin-bottom: 20px;
        }
        
        .toc-title {
            font-weight: 600;
            margin-bottom: 10px;
            color: var(--accent-primary);
        }
        
        .toc-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 8px;
        }
        
        .toc-item {
            display: flex;
            justify-content: space-between;
            padding: 4px 8px;
            text-decoration: none;
            color: var(--text-primary);
            border-radius: 3px;
            font-size: 13px;
        }
        
        .toc-item:hover {
            background: var(--bg-primary);
        }
        
        .toc-item.critical { border-left: 3px solid var(--status-failed); }
        .toc-item.high { border-left: 3px solid var(--accent-high); }
        .toc-item.medium { border-left: 3px solid var(--text-secondary); }
        
        /* Security Banner */
        .security-banner {
            background: #e9ecef;
            border: 2px solid var(--accent-primary);
            border-radius: 4px;
            padding: 15px 20px;
            margin-bottom: 20px;
            font-family: var(--mono-font);
            font-size: 12px;
        }
        
        .security-banner h3 {
            text-align: center;
            margin-bottom: 10px;
            font-size: 14px;
            color: var(--accent-primary);
        }
        
        .security-banner ul {
            list-style: none;
            padding: 0;
        }
        
        .security-banner li {
            padding: 2px 0;
        }
        
        .security-banner li::before {
            content: "• ";
            color: var(--accent-primary);
        }
        
        /* Section Cards with Importance Levels */
        .section {
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        
        .section-header {
            padding: 12px 20px;
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
            font-size: 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        /* Header importance levels */
        .section-header.level-critical {
            background: #f8f9fa;
            border-left: 4px solid var(--accent-primary);
        }
        
        .section-header.level-high {
            background: #f8f9fa;
            border-left: 4px solid var(--accent-high);
        }
        
        .section-header.level-medium {
            background: var(--bg-primary);
        }
        
        .section-header.level-low {
            background: var(--bg-primary);
            color: var(--text-secondary);
        }
        
        .section-content {
            padding: 20px;
        }
        
        /* Badges */
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            margin-left: 8px;
        }
        
        .badge-critical { background: var(--accent-primary); color: white; }
        .badge-high { background: var(--accent-high); color: white; }
        .badge-count { background: var(--bg-code); color: var(--text-secondary); }
        .badge-success { background: var(--status-success); color: white; }
        .badge-warning { background: var(--status-partial); color: black; }
        .badge-failed { background: var(--status-failed); color: white; }
        .badge-skipped { background: var(--status-skipped); color: white; }
        
        /* Metadata Grid */
        .metadata-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 15px;
        }
        
        .metadata-item {
            display: flex;
            border-bottom: 1px dotted var(--border-color);
            padding: 5px 0;
        }
        
        .metadata-label {
            font-weight: 600;
            color: var(--text-secondary);
            min-width: 150px;
            flex-shrink: 0;
        }
        
        .metadata-value {
            font-family: var(--mono-font);
            word-break: break-all;
        }
        
        /* Tables with Search and Sort */
        .table-controls {
            display: flex;
            gap: 10px;
            margin-bottom: 10px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .table-search {
            padding: 6px 12px;
            font-size: 12px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            font-family: var(--mono-font);
            min-width: 200px;
        }
        
        .table-filter {
            padding: 6px 12px;
            font-size: 12px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: white;
            cursor: pointer;
        }
        
        .table-filter:hover {
            background: var(--bg-primary);
        }
        
        .table-filter.active {
            background: var(--accent-high);
            color: white;
            border-color: var(--accent-high);
        }
        
        .table-container {
            overflow-x: auto;
            margin: 10px 0;
            max-height: 500px;
            overflow-y: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-family: var(--mono-font);
            font-size: 12px;
        }
        
        th, td {
            padding: 8px 12px;
            text-align: left;
            border: 1px solid var(--border-color);
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        th {
            background: var(--bg-primary);
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
            cursor: pointer;
            user-select: none;
        }
        
        th:hover {
            background: #e9ecef;
        }
        
        th .sort-indicator {
            margin-left: 5px;
            opacity: 0.5;
        }
        
        th.sort-asc .sort-indicator::after { content: "▲"; }
        th.sort-desc .sort-indicator::after { content: "▼"; }
        
        tr:nth-child(even) {
            background: var(--bg-code);
        }
        
        tr:hover {
            background: #e9ecef;
        }
        
        tr.hidden {
            display: none;
        }
        
        tr.highlight {
            background: #fff3cd !important;
        }
        
        /* Credential Display */
        .credential-row {
            background: #fff8e6 !important;
        }
        
        .credential-row:hover {
            background: #fff3cd !important;
        }
        
        .password-cell {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .password-masked {
            font-family: var(--mono-font);
            letter-spacing: 2px;
        }
        
        .password-revealed {
            font-family: var(--mono-font);
            color: var(--status-failed);
            font-weight: bold;
        }
        
        .reveal-btn, .copy-pwd-btn {
            padding: 2px 6px;
            font-size: 10px;
            border: 1px solid var(--border-color);
            border-radius: 3px;
            background: white;
            cursor: pointer;
        }
        
        .reveal-btn:hover, .copy-pwd-btn:hover {
            background: var(--bg-primary);
        }
        
        .copy-pwd-btn {
            color: var(--status-failed);
            border-color: var(--status-failed);
        }
        
        /* Expandable Details */
        details {
            margin: 10px 0;
            border: 1px solid var(--border-color);
            border-radius: 4px;
        }
        
        summary {
            padding: 10px 15px;
            background: var(--bg-code);
            cursor: pointer;
            font-weight: 500;
            user-select: none;
        }
        
        summary:hover {
            background: #e9ecef;
        }
        
        details[open] summary {
            border-bottom: 1px solid var(--border-color);
        }
        
        .details-content {
            padding: 15px;
            background: var(--bg-secondary);
        }
        
        /* Code/JSON Display */
        .code-block {
            background: var(--bg-code);
            border: 1px solid var(--border-color);
            border-radius: 4px;
            padding: 15px;
            font-family: var(--mono-font);
            font-size: 12px;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 400px;
            overflow-y: auto;
        }
        
        /* Copy Button */
        .copy-btn {
            background: var(--accent-primary);
            color: white;
            border: none;
            padding: 4px 10px;
            border-radius: 3px;
            font-size: 11px;
            cursor: pointer;
            margin-left: 10px;
        }
        
        .copy-btn:hover {
            background: #343a40;
        }
        
        .copy-btn.copied {
            background: var(--status-success);
        }
        
        /* Evidence File Table */
        .evidence-table td:nth-child(2) {
            font-family: var(--mono-font);
            font-size: 10px;
        }
        
        /* Sensitive Data Highlight */
        .sensitive {
            background: var(--highlight-sensitive);
        }
        
        /* Error/Warning Items */
        .error-item {
            border-left: 4px solid var(--status-failed);
            padding: 10px 15px;
            margin: 10px 0;
            background: #fff5f5;
        }
        
        .warning-item {
            border-left: 4px solid var(--status-partial);
            padding: 10px 15px;
            margin: 10px 0;
            background: #fffbeb;
        }
        
        .error-component {
            font-weight: 600;
            color: var(--status-failed);
        }
        
        .error-message {
            font-family: var(--mono-font);
            margin: 5px 0;
        }
        
        .error-remediation {
            font-style: italic;
            color: var(--text-secondary);
        }
        
        /* Findings Category */
        .findings-category {
            margin-bottom: 25px;
            scroll-margin-top: 80px;
        }
        
        .category-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 15px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 4px 4px 0 0;
        }
        
        .category-header.importance-critical {
            border-left: 4px solid var(--accent-primary);
            background: #f8f9fa;
        }
        
        .category-header.importance-high {
            border-left: 4px solid var(--accent-high);
        }
        
        .category-title {
            font-weight: 600;
        }
        
        .category-meta {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 20px;
            color: var(--text-secondary);
            font-size: 12px;
            border-top: 1px solid var(--border-color);
            margin-top: 30px;
        }
        
        /* Quick Filters */
        .quick-filters {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-bottom: 15px;
        }
        
        .filter-btn {
            padding: 6px 12px;
            font-size: 12px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: white;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .filter-btn:hover {
            background: var(--bg-primary);
        }
        
        .filter-btn.active {
            background: var(--accent-high);
            color: white;
            border-color: var(--accent-high);
        }
        
        /* Print Styles */
        @media print {
            body {
                background: white;
                font-size: 10pt;
            }
            
            .report-container {
                max-width: none;
            }
            
            .global-search, .copy-btn, .reveal-btn, .copy-pwd-btn,
            .table-controls, .quick-filters, .toc {
                display: none;
            }
            
            .password-revealed {
                display: none;
            }
            
            details {
                display: block;
            }
            
            .section {
                page-break-inside: avoid;
            }
        }
        """
    
    def _get_scripts(self) -> str:
        """Get JavaScript for interactive features."""
        return """
        // Global search state
        let globalSearchTerm = '';
        
        // Initialize on DOM ready
        document.addEventListener('DOMContentLoaded', function() {
            initializeSearch();
            initializeSorting();
            initializePasswordMasking();
            initializeCopyButtons();
            initializeFilters();
        });
        
        // Global search functionality
        function initializeSearch() {
            const globalInput = document.getElementById('global-search');
            if (globalInput) {
                globalInput.addEventListener('input', function(e) {
                    globalSearchTerm = e.target.value.toLowerCase();
                    performGlobalSearch(globalSearchTerm);
                });
            }
            
            // Per-table search
            document.querySelectorAll('.table-search').forEach(function(input) {
                input.addEventListener('input', function(e) {
                    const tableId = input.dataset.table;
                    const table = document.getElementById(tableId);
                    if (table) {
                        filterTable(table, e.target.value.toLowerCase());
                    }
                });
            });
        }
        
        function performGlobalSearch(term) {
            let totalMatches = 0;
            let sectionsWithMatches = 0;
            
            document.querySelectorAll('.findings-category').forEach(function(category) {
                const table = category.querySelector('table');
                if (table) {
                    const matches = filterTable(table, term);
                    totalMatches += matches;
                    if (matches > 0) sectionsWithMatches++;
                }
            });
            
            // Update stats
            const stats = document.getElementById('search-stats');
            if (stats) {
                if (term) {
                    stats.textContent = `${totalMatches} matches in ${sectionsWithMatches} sections`;
                } else {
                    stats.textContent = '';
                }
            }
        }
        
        function filterTable(table, term) {
            const rows = table.querySelectorAll('tbody tr');
            let matches = 0;
            
            rows.forEach(function(row) {
                const text = row.textContent.toLowerCase();
                const match = !term || text.includes(term);
                row.classList.toggle('hidden', !match);
                row.classList.toggle('highlight', match && term);
                if (match) matches++;
            });
            
            return matches;
        }
        
        function clearSearch() {
            const globalInput = document.getElementById('global-search');
            if (globalInput) {
                globalInput.value = '';
                globalSearchTerm = '';
                performGlobalSearch('');
            }
            
            document.querySelectorAll('.table-search').forEach(function(input) {
                input.value = '';
            });
        }
        
        // Table sorting
        function initializeSorting() {
            document.querySelectorAll('th[data-sortable]').forEach(function(header) {
                header.addEventListener('click', function() {
                    const table = header.closest('table');
                    const columnIndex = Array.from(header.parentNode.children).indexOf(header);
                    const isAsc = header.classList.contains('sort-asc');
                    
                    // Reset all headers
                    table.querySelectorAll('th').forEach(th => {
                        th.classList.remove('sort-asc', 'sort-desc');
                    });
                    
                    // Set new sort direction
                    header.classList.add(isAsc ? 'sort-desc' : 'sort-asc');
                    
                    sortTable(table, columnIndex, !isAsc);
                });
            });
        }
        
        function sortTable(table, columnIndex, ascending) {
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            
            rows.sort(function(a, b) {
                const aVal = a.children[columnIndex]?.textContent.trim() || '';
                const bVal = b.children[columnIndex]?.textContent.trim() || '';
                
                // Try numeric sort
                const aNum = parseFloat(aVal);
                const bNum = parseFloat(bVal);
                
                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return ascending ? aNum - bNum : bNum - aNum;
                }
                
                // String sort
                return ascending ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
            });
            
            rows.forEach(row => tbody.appendChild(row));
        }
        
        // Password masking
        function initializePasswordMasking() {
            document.querySelectorAll('.reveal-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    const cell = btn.closest('.password-cell');
                    const masked = cell.querySelector('.password-masked');
                    const revealed = cell.querySelector('.password-revealed');
                    
                    if (masked.style.display !== 'none') {
                        masked.style.display = 'none';
                        revealed.style.display = 'inline';
                        btn.textContent = 'Hide';
                    } else {
                        masked.style.display = 'inline';
                        revealed.style.display = 'none';
                        btn.textContent = 'Reveal';
                    }
                });
            });
        }
        
        // Copy to clipboard
        function initializeCopyButtons() {
            document.querySelectorAll('.copy-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    const target = btn.dataset.copy || btn.previousElementSibling?.textContent;
                    copyToClipboard(target, btn);
                });
            });
            
            document.querySelectorAll('.copy-pwd-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    const cell = btn.closest('.password-cell');
                    const password = cell.querySelector('.password-revealed').textContent;
                    
                    if (confirm('⚠️ WARNING: You are about to copy a password to your clipboard.\\n\\nThis is sensitive data. Ensure your clipboard is secure and clear it after use.\\n\\nContinue?')) {
                        copyToClipboard(password, btn);
                    }
                });
            });
        }
        
        function copyToClipboard(text, button) {
            navigator.clipboard.writeText(text).then(function() {
                const originalText = button.textContent;
                button.textContent = 'Copied!';
                button.classList.add('copied');
                setTimeout(function() {
                    button.textContent = originalText;
                    button.classList.remove('copied');
                }, 2000);
            }).catch(function(err) {
                console.error('Failed to copy:', err);
                button.textContent = 'Failed';
            });
        }
        
        function copyHash(hash, btn) {
            copyToClipboard(hash, btn);
        }
        
        // Quick filters
        function initializeFilters() {
            document.querySelectorAll('.filter-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    const filterType = btn.dataset.filter;
                    btn.classList.toggle('active');
                    applyFilters();
                });
            });
        }
        
        function applyFilters() {
            const activeFilters = Array.from(document.querySelectorAll('.filter-btn.active'))
                .map(btn => btn.dataset.filter);
            
            document.querySelectorAll('.findings-category').forEach(function(category) {
                const categoryType = category.dataset.importance;
                
                if (activeFilters.length === 0) {
                    category.style.display = 'block';
                } else {
                    const show = activeFilters.includes(categoryType) ||
                                 activeFilters.includes('all');
                    category.style.display = show ? 'block' : 'none';
                }
            });
        }
        
        // Smooth scroll to section
        function scrollToSection(id) {
            const element = document.getElementById(id);
            if (element) {
                element.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        }
        """
    
    def _render_global_search(self) -> str:
        """Render global search bar."""
        return """
        <div class="global-search">
            <div class="search-container">
                <input type="text" 
                       id="global-search" 
                       class="search-input" 
                       placeholder="🔍 Search across all findings (domain, username, cookie name, value...)">
                <button class="search-clear" onclick="clearSearch()">Clear</button>
                <span id="search-stats" class="search-stats"></span>
            </div>
        </div>
        """
    
    def _render_toc(self, ordered_findings: List[Tuple[str, FindingsCategory]]) -> str:
        """Render table of contents."""
        items = ""
        for name, category in ordered_findings:
            if category.total_count == 0:
                continue
            
            importance = self._get_importance_level(name)
            importance_class = f"class=\"toc-item {importance}\"" if importance in ['critical', 'high'] else "class=\"toc-item\""
            
            items += f"""
            <a {importance_class} href="javascript:scrollToSection('category-{html.escape(name)}')">
                <span>{html.escape(category.name)}</span>
                <span class="badge badge-count">{category.total_count}</span>
            </a>
            """
        
        return f"""
        <div class="toc">
            <div class="toc-title">📋 Quick Navigation</div>
            <div class="quick-filters">
                <button class="filter-btn" data-filter="critical">🔴 Critical</button>
                <button class="filter-btn" data-filter="high">🔵 High Value</button>
                <button class="filter-btn" data-filter="medium">⚪ Supporting</button>
                <button class="filter-btn" data-filter="low">📊 High Volume</button>
            </div>
            <div class="toc-grid">
                {items}
            </div>
        </div>
        """
    
    def _render_security_banner(self) -> str:
        """Render security and ethics banner."""
        return """
        <div class="security-banner">
            <h3>SECURITY &amp; ETHICS NOTICE</h3>
            <ul>
                <li>This report was generated using <strong>READ-ONLY</strong> analysis methods</li>
                <li>All processing was performed <strong>LOCALLY</strong> on the analysis system</li>
                <li>No data was transmitted externally or persisted beyond this report</li>
                <li>Intended for <strong>ACADEMIC</strong>, <strong>PERSONAL FORENSIC</strong>, and <strong>AUTHORIZED SECURITY RESEARCH</strong> only</li>
                <li>Unauthorized access to computer data may violate applicable laws</li>
                <li>The analyst is responsible for ensuring proper authorization</li>
            </ul>
        </div>
        """
    
    def _render_case_metadata(self) -> str:
        """Render case metadata section (Level 1 - Critical)."""
        meta = self.report.case_metadata
        
        return f"""
        <div class="section" id="section-metadata">
            <div class="section-header level-critical">
                <span>📋 Case Metadata</span>
                <span class="badge badge-critical">PROVENANCE</span>
            </div>
            <div class="section-content">
                <div class="metadata-grid">
                    <div class="metadata-item">
                        <span class="metadata-label">Tool Name:</span>
                        <span class="metadata-value">{html.escape(meta.tool_name)}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Tool Version:</span>
                        <span class="metadata-value">{html.escape(meta.tool_version)}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Git Commit:</span>
                        <span class="metadata-value">{html.escape(meta.commit_hash or 'N/A')}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Analyst:</span>
                        <span class="metadata-value">{html.escape(meta.analyst_username)}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Host OS:</span>
                        <span class="metadata-value">{html.escape(meta.host_os)}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Kernel:</span>
                        <span class="metadata-value">{html.escape(meta.kernel_version[:80] + '...' if len(meta.kernel_version) > 80 else meta.kernel_version)}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Architecture:</span>
                        <span class="metadata-value">{html.escape(meta.architecture)}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Python Version:</span>
                        <span class="metadata-value">{html.escape(meta.python_version.split()[0])}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Date (UTC):</span>
                        <span class="metadata-value">{html.escape(meta.date_utc)}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Date (Local):</span>
                        <span class="metadata-value">{html.escape(meta.date_local)}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">NSS Version:</span>
                        <span class="metadata-value">{html.escape(meta.nss_version or 'Not detected')}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Execution Args:</span>
                        <span class="metadata-value">{html.escape(' '.join(meta.execution_args) if meta.execution_args else 'N/A')}</span>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _render_acquisition_summary(self) -> str:
        """Render acquisition summary section (Level 1 - Critical)."""
        acq = self.report.acquisition_summary
        
        # Build files table
        files_rows = ""
        for evidence in acq.files_accessed:
            filename = evidence.original_path.split('/')[-1]
            files_rows += f"""
            <tr>
                <td>{html.escape(filename)}</td>
                <td>
                    <span style="font-family: var(--mono-font); font-size: 10px;">{html.escape(evidence.sha256_hash)}</span>
                    <button class="copy-btn" onclick="copyHash('{evidence.sha256_hash}', this)" style="margin-left: 5px; padding: 2px 6px; font-size: 9px;">Copy</button>
                </td>
                <td>{evidence.file_size:,}</td>
                <td>{html.escape(evidence.last_modified)}</td>
                <td>{html.escape(evidence.access_mode)}</td>
            </tr>
            """
        
        return f"""
        <div class="section" id="section-acquisition">
            <div class="section-header level-critical">
                <span>📁 Acquisition Summary</span>
                <span class="badge badge-critical">EVIDENCE INTEGRITY</span>
            </div>
            <div class="section-content">
                <div class="metadata-grid">
                    <div class="metadata-item">
                        <span class="metadata-label">Firefox Version:</span>
                        <span class="metadata-value">{html.escape(acq.firefox_version or 'Unknown')}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Access Mode:</span>
                        <span class="metadata-value">{html.escape(acq.access_mode)}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Profile Path(s):</span>
                        <span class="metadata-value">{html.escape(', '.join(acq.profile_paths))}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Files Accessed:</span>
                        <span class="metadata-value">{len(acq.files_accessed)}</span>
                    </div>
                </div>
                
                <details style="margin-top: 15px;">
                    <summary>📄 Evidence File Integrity - SHA256 Hashes ({len(acq.files_accessed)} files)</summary>
                    <div class="details-content">
                        <div class="table-container">
                            <table class="evidence-table">
                                <thead>
                                    <tr>
                                        <th data-sortable>Filename <span class="sort-indicator"></span></th>
                                        <th>SHA256 Hash</th>
                                        <th data-sortable>Size (bytes) <span class="sort-indicator"></span></th>
                                        <th data-sortable>Last Modified (UTC) <span class="sort-indicator"></span></th>
                                        <th>Access Mode</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {files_rows}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </details>
            </div>
        </div>
        """
    
    def _render_decryption_context(self) -> str:
        """Render decryption context section (Level 1 - Critical)."""
        ctx = self.report.decryption_context
        
        def status_badge(status: ProcessingStatus) -> str:
            badge_class = f"badge-{status.value.lower()}"
            if status == ProcessingStatus.SUCCESS:
                badge_class = "badge-success"
            elif status == ProcessingStatus.PARTIAL:
                badge_class = "badge-warning"
            elif status == ProcessingStatus.FAILED:
                badge_class = "badge-failed"
            else:
                badge_class = "badge-skipped"
            return f'<span class="badge {badge_class}">{status.value}</span>'
        
        return f"""
        <div class="section" id="section-decryption">
            <div class="section-header level-critical">
                <span>🔐 Decryption Context</span>
                {status_badge(ctx.decryption_status)}
            </div>
            <div class="section-content">
                <div class="metadata-grid">
                    <div class="metadata-item">
                        <span class="metadata-label">NSS Version:</span>
                        <span class="metadata-value">{html.escape(ctx.nss_version or 'Not available')}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Master Password:</span>
                        <span class="metadata-value">{html.escape(ctx.master_password_status.replace('_', ' ').title())}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Key Derivation:</span>
                        <span class="metadata-value">{status_badge(ctx.key_derivation_status)}</span>
                    </div>
                    <div class="metadata-item">
                        <span class="metadata-label">Decryption Status:</span>
                        <span class="metadata-value">{status_badge(ctx.decryption_status)}</span>
                    </div>
                </div>
                {f'<div class="error-item" style="margin-top: 15px;"><strong>Failure Reason:</strong> {html.escape(ctx.failure_reason)}</div>' if ctx.failure_reason else ''}
            </div>
        </div>
        """
    
    def _render_errors_and_warnings(self) -> str:
        """Render errors and warnings section (before findings, for visibility)."""
        errors = [e for e in self.report.errors_and_warnings if e.status == ProcessingStatus.FAILED]
        warnings = [e for e in self.report.errors_and_warnings if e.status == ProcessingStatus.PARTIAL]
        
        if not errors and not warnings:
            return """
            <div class="section" id="section-errors">
                <div class="section-header level-medium">
                    <span>⚠️ Errors and Warnings</span>
                    <span class="badge badge-success">NONE</span>
                </div>
                <div class="section-content">
                    <p style="color: var(--text-secondary);">No errors or warnings encountered during extraction.</p>
                </div>
            </div>
            """
        
        items = ""
        for step in errors[:10]:  # Show first 10 errors
            items += f"""
            <div class="error-item">
                <div>
                    <span class="error-component">[{html.escape(step.component)}]</span>
                    <strong>{html.escape(step.operation)}</strong>
                    <span class="badge badge-failed">FAILED</span>
                </div>
                {f'<div class="error-message">Reason: {html.escape(step.message)}</div>' if step.message else ''}
                {f'<div class="error-message">Cause: {html.escape(step.cause)}</div>' if step.cause else ''}
                {f'<div class="error-remediation">Action: {html.escape(step.remediation)}</div>' if step.remediation else ''}
            </div>
            """
        
        for step in warnings[:5]:  # Show first 5 warnings
            items += f"""
            <div class="warning-item">
                <div>
                    <span style="color: var(--status-partial); font-weight: 600;">[{html.escape(step.component)}]</span>
                    <strong>{html.escape(step.operation)}</strong>
                    <span class="badge badge-warning">WARNING</span>
                </div>
                {f'<div class="error-message">{html.escape(step.message)}</div>' if step.message else ''}
            </div>
            """
        
        remaining = len(errors) + len(warnings) - 15
        if remaining > 0:
            items += f'<p style="color: var(--text-secondary); font-style: italic;">... and {remaining} more. See JSON report for complete list.</p>'
        
        return f"""
        <div class="section" id="section-errors">
            <div class="section-header level-medium">
                <span>⚠️ Errors and Warnings</span>
                <span>
                    {f'<span class="badge badge-failed">{len(errors)} ERRORS</span>' if errors else ''}
                    {f'<span class="badge badge-warning">{len(warnings)} WARNINGS</span>' if warnings else ''}
                </span>
            </div>
            <div class="section-content">
                {items}
            </div>
        </div>
        """
    
    def _render_findings(self, ordered_findings: List[Tuple[str, FindingsCategory]]) -> str:
        """Render all findings sections in order of importance."""
        if not ordered_findings:
            return """
            <div class="section">
                <div class="section-header">🔍 Findings</div>
                <div class="section-content">
                    <p>No findings extracted.</p>
                </div>
            </div>
            """
        
        sections = ""
        for name, category in ordered_findings:
            sections += self._render_findings_category(name, category)
        
        return f"""
        <div class="section" id="section-findings">
            <div class="section-header level-high">
                <span>🔍 Extracted Findings</span>
                <span class="badge badge-count">{len(ordered_findings)} categories</span>
            </div>
            <div class="section-content">
                {sections}
            </div>
        </div>
        """
    
    def _render_findings_category(self, name: str, category: FindingsCategory) -> str:
        """Render a single findings category with appropriate formatting."""
        importance = self._get_importance_level(name)
        importance_class = f"importance-{importance}" if importance in ['critical', 'high'] else ""
        
        # Status badge
        status_badge = ""
        if category.status == ProcessingStatus.SUCCESS:
            status_badge = '<span class="badge badge-success">SUCCESS</span>'
        elif category.status == ProcessingStatus.PARTIAL:
            status_badge = '<span class="badge badge-warning">PARTIAL</span>'
        elif category.status == ProcessingStatus.FAILED:
            status_badge = f'<span class="badge badge-failed">FAILED</span>'
        
        # Importance badge
        importance_badge = ""
        if importance == 'critical':
            importance_badge = '<span class="badge badge-critical">HIGH VALUE</span>'
        elif importance == 'high':
            importance_badge = '<span class="badge badge-high">AUTH DATA</span>'
        
        # Build table if items exist
        table_html = ""
        if category.items:
            # Check if this is a credentials category (needs special handling)
            is_credentials = name in ['saved_credentials_decrypted', 'logins_encrypted']
            
            table_html = self._render_category_table(name, category, is_credentials)
        
        # Raw JSON view
        raw_json = json.dumps(category.items[:100], indent=2, default=str) if category.items else "[]"
        
        return f"""
        <div class="findings-category" id="category-{html.escape(name)}" data-importance="{importance}">
            <div class="category-header {importance_class}">
                <span class="category-title">{html.escape(category.name)}</span>
                <span class="category-meta">
                    {importance_badge}
                    <span class="badge badge-count">{category.total_count} items</span>
                    {status_badge}
                </span>
            </div>
            
            {f'<div class="error-item">{html.escape(category.error_message)}</div>' if category.error_message else ''}
            
            {table_html}
            
            <details>
                <summary>📄 Raw JSON Data (first 100 items)</summary>
                <div class="details-content">
                    <div class="code-block">{html.escape(raw_json)}</div>
                </div>
            </details>
            
            {f'''
            <details>
                <summary>📝 SQL Query</summary>
                <div class="details-content">
                    <div class="code-block">{html.escape(category.raw_sql_query)}</div>
                </div>
            </details>
            ''' if category.raw_sql_query else ''}
        </div>
        """
    
    def _render_category_table(self, name: str, category: FindingsCategory, is_credentials: bool) -> str:
        """Render table for a category with search, sort, and special credential handling."""
        if not category.items:
            return ""
        
        table_id = f"table-{name.replace(' ', '-').lower()}"
        
        # Get columns
        columns = list(category.items[0].keys())
        
        # Build header cells with sort indicators
        header_cells = ""
        for col in columns:
            header_cells += f'<th data-sortable>{html.escape(str(col))} <span class="sort-indicator"></span></th>'
        
        # Build rows
        rows = ""
        for idx, item in enumerate(category.items[:500]):  # Limit to 500 items
            row_class = "credential-row" if is_credentials else ""
            cells = self._render_row_cells(item, columns, is_credentials)
            rows += f'<tr class="{row_class}">{cells}</tr>'
        
        # Search input for this table
        search_html = f"""
        <div class="table-controls">
            <input type="text" 
                   class="table-search" 
                   data-table="{table_id}"
                   placeholder="🔍 Filter this table...">
        </div>
        """
        
        truncation_note = ""
        if len(category.items) > 500:
            truncation_note = f'<p style="color: var(--text-secondary); font-style: italic; margin-top: 10px;">Showing first 500 of {len(category.items)} items. See JSON report for complete data.</p>'
        
        return f"""
        {search_html}
        <div class="table-container">
            <table id="{table_id}">
                <thead><tr>{header_cells}</tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        {truncation_note}
        """
    
    def _render_row_cells(self, item: Dict, columns: List[str], is_credentials: bool) -> str:
        """Render cells for a table row with special handling for credentials."""
        cells = ""
        
        for col in columns:
            value = item.get(col, '')
            
            # Handle normalized timestamps
            if isinstance(value, dict) and 'utc' in value:
                display_val = f"{value.get('utc', '')} (raw: {value.get('raw', '')})"
            else:
                display_val = str(value) if value is not None else ''
            
            # Special handling for password field
            if is_credentials and col.lower() == 'password':
                cells += self._render_password_cell(display_val)
                continue
            
            # Special handling for username field
            if is_credentials and col.lower() == 'username':
                cells += f'<td class="sensitive" style="font-weight: bold;">{html.escape(display_val)}</td>'
                continue
            
            # Truncate long values
            if len(display_val) > 100:
                display_val = display_val[:100] + '...'
            
            # Check for sensitive fields
            is_sensitive = any(kw in str(col).lower() for kw in ['password', 'token', 'secret', 'key', 'credential', 'encrypted'])
            cell_class = 'sensitive' if is_sensitive else ''
            
            cells += f'<td class="{cell_class}">{html.escape(display_val)}</td>'
        
        return cells
    
    def _render_password_cell(self, password: str) -> str:
        """Render a password cell with masking and reveal functionality."""
        masked = "•" * min(len(password), 12)
        
        return f'''<td class="sensitive">
            <div class="password-cell">
                <span class="password-masked">{masked}</span>
                <span class="password-revealed" style="display: none;">{html.escape(password)}</span>
                <button class="reveal-btn">Reveal</button>
                <button class="copy-pwd-btn">Copy</button>
            </div>
        </td>'''
    
    def _render_appendix(self) -> str:
        """Render appendix section (lowest priority)."""
        appendix = self.report.appendix
        
        if not appendix:
            return ""
        
        sections = ""
        
        # Raw SQL Queries
        if 'sql_queries' in appendix and appendix['sql_queries']:
            queries_html = ""
            for qname, query in appendix['sql_queries'].items():
                queries_html += f"""
                <details>
                    <summary>{html.escape(qname)}</summary>
                    <div class="details-content">
                        <div class="code-block">{html.escape(query)}</div>
                    </div>
                </details>
                """
            
            sections += f"""
            <h3 style="margin: 20px 0 10px; color: var(--text-secondary);">Raw SQL Queries ({len(appendix['sql_queries'])})</h3>
            {queries_html}
            """
        
        # Stack Traces (collapsed)
        if 'stack_traces' in appendix and appendix['stack_traces']:
            traces_html = ""
            for trace in appendix['stack_traces']:
                traces_html += f"""
                <details>
                    <summary style="color: var(--status-failed);">{html.escape(trace.get('operation', 'Unknown'))}</summary>
                    <div class="details-content">
                        <div class="code-block" style="font-size: 10px;">{html.escape(trace.get('trace', ''))}</div>
                    </div>
                </details>
                """
            
            sections += f"""
            <h3 style="margin: 20px 0 10px; color: var(--text-secondary);">Stack Traces (collapsed)</h3>
            {traces_html}
            """
        
        if not sections:
            return ""
        
        return f"""
        <div class="section" id="section-appendix">
            <div class="section-header level-low">
                <span>📎 Appendix</span>
                <span class="badge badge-count">RAW DATA</span>
            </div>
            <div class="section-content">
                {sections}
            </div>
        </div>
        """
    
    def _render_footer(self) -> str:
        """Render report footer with versioning info."""
        meta = self.report.case_metadata
        
        return f"""
        <div class="footer">
            <div><strong>Report Generated By:</strong> {html.escape(meta.tool_name)} v{html.escape(meta.tool_version)}</div>
            <div>
                <strong>Git Commit:</strong> {html.escape(meta.commit_hash or 'N/A')} | 
                <strong>Python:</strong> {html.escape(meta.python_version.split()[0])} | 
                <strong>NSS:</strong> {html.escape(meta.nss_version or 'N/A')}
            </div>
            <div><strong>Execution Arguments:</strong> {html.escape(' '.join(meta.execution_args) if meta.execution_args else 'N/A')}</div>
            <div style="margin-top: 10px; color: var(--text-secondary);">
                Generated: {html.escape(meta.date_utc)} (UTC) | {html.escape(meta.date_local)} (Local)
            </div>
        </div>
        """
