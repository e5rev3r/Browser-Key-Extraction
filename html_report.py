"""
HTML Report Generator for Browser Forensics Tool.

Generates professional forensics reports in HTML format with:
- Executive summary with key statistics
- Searchable and sortable data tables
- Password masking with reveal functionality
- Evidence traceability
- Print-optimized styling
- Accessibility features
"""

import html
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional


def generate_html_report(
    browser_name: str,
    profile_path: Path,
    data: Dict[str, Any],
    output_path: Path,
    errors: List[str] = None,
) -> None:
    """
    Generate a professional HTML forensics report.
    
    Args:
        browser_name: Name of the browser (e.g., "Firefox", "Chrome")
        profile_path: Path to the browser profile
        data: Dictionary containing extracted data by category
        output_path: Path where the HTML report will be saved
        errors: List of errors/warnings encountered during extraction
    """
    errors = errors or []
    timestamp = datetime.now(timezone.utc)
    timestamp_iso = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    timestamp_display = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Calculate statistics
    stats = _calculate_stats(data)
    categories = {k: v for k, v in data.items() if v and isinstance(v, list) and len(v) > 0}
    
    # Determine overall status
    has_passwords = stats['passwords'] > 0
    decryption_status = "SUCCESS" if has_passwords else "NOT ATTEMPTED" if 'passwords' not in data else "NONE FOUND"
    if errors:
        if has_passwords:
            decryption_status = "PARTIAL"
        else:
            decryption_status = "FAILED"
    
    # Build HTML
    html_content = _build_document(
        browser_name=browser_name,
        profile_path=profile_path,
        timestamp_iso=timestamp_iso,
        timestamp_display=timestamp_display,
        stats=stats,
        categories=categories,
        errors=errors,
        decryption_status=decryption_status,
    )
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)


def _calculate_stats(data: Dict) -> Dict[str, int]:
    """Calculate statistics from extracted data."""
    return {
        'passwords': len(data.get('passwords', [])),
        'cookies': len(data.get('cookies', [])),
        'history': len(data.get('history', [])),
        'bookmarks': len(data.get('bookmarks', [])),
        'downloads': len(data.get('downloads', [])),
        'autofill': len(data.get('autofill', [])),
        'extensions': len(data.get('extensions', [])),
        'total': sum(len(v) for v in data.values() if isinstance(v, list)),
        'categories': len([k for k, v in data.items() if v and isinstance(v, list) and len(v) > 0]),
    }


def _build_document(
    browser_name: str,
    profile_path: Path,
    timestamp_iso: str,
    timestamp_display: str,
    stats: Dict[str, int],
    categories: Dict[str, List],
    errors: List[str],
    decryption_status: str,
) -> str:
    """Build the complete HTML document."""
    
    css = _get_css()
    js = _get_javascript()
    
    # Build sections
    exec_summary = _build_executive_summary(browser_name, profile_path, timestamp_display, stats, decryption_status, errors)
    error_section = _build_error_section(errors) if errors else ""
    metadata_section = _build_metadata_section(browser_name, profile_path, timestamp_iso, timestamp_display)
    
    # Build data sections - credentials first (high value)
    data_sections = []
    
    # Credentials first with HIGH VALUE badge
    if 'passwords' in categories:
        data_sections.append(_build_credentials_section(categories['passwords'], profile_path))
    
    # Other sections (collapsible for high-volume)
    section_order = ['history', 'cookies', 'bookmarks', 'downloads', 'autofill', 'extensions']
    collapse_threshold = 50  # Collapse sections with more than this many items
    
    for key in section_order:
        if key in categories and key != 'passwords':
            collapsed = len(categories[key]) > collapse_threshold
            data_sections.append(_build_data_section(key, categories[key], profile_path, collapsed))
    
    # Handle any remaining categories
    for key, records in categories.items():
        if key not in section_order and key != 'passwords':
            collapsed = len(records) > collapse_threshold
            data_sections.append(_build_data_section(key, records, profile_path, collapsed))
    
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Browser Forensics Report - {html.escape(browser_name)} - {timestamp_iso}</title>
    <style>{css}</style>
</head>
<body>
<div class="container">
    <header class="report-header">
        <h1>Browser Forensics Report</h1>
        <p class="subtitle">{html.escape(browser_name)} Profile Analysis</p>
        <p class="timestamp">Generated: {timestamp_display}</p>
    </header>
    
    <div class="controls-bar">
        <div class="search-global">
            <input type="text" id="globalSearch" placeholder="Search all data (domains, usernames, cookies...)" autocomplete="off">
            <span id="searchResults" class="search-results"></span>
        </div>
        <div class="control-buttons">
            <button id="redactToggle" class="btn btn-outline" onclick="toggleRedaction()">Enable Redaction</button>
            <button class="btn btn-outline" onclick="window.print()">Print Report</button>
        </div>
    </div>
    
    {exec_summary}
    {error_section}
    {metadata_section}
    {''.join(data_sections)}
    
    <footer class="report-footer">
        <p>Browser Forensics Extraction Tool</p>
        <p>Report Generated: {timestamp_display}</p>
        <p class="notice">Read-only analysis | Local execution | Forensic/personal use only</p>
    </footer>
</div>
<script>{js}</script>
</body>
</html>'''


def _get_css() -> str:
    """Return the CSS styles."""
    return '''
:root {
    --bg-primary: #f5f5f5;
    --bg-secondary: #ffffff;
    --bg-tertiary: #fafafa;
    --text-primary: #1a1a1a;
    --text-secondary: #555555;
    --text-muted: #777777;
    --border-color: #e0e0e0;
    --border-dark: #cccccc;
    
    /* Semantic colors - used sparingly */
    --color-high-value: #0066cc;
    --color-warning: #b86e00;
    --color-error: #c41e3a;
    --color-success: #1a7f37;
    --color-neutral: #555555;
    
    /* Status backgrounds */
    --bg-high-value: #e8f4fc;
    --bg-warning: #fff8e6;
    --bg-error: #fef2f2;
    --bg-success: #f0fdf4;
    
    --font-mono: 'Consolas', 'Monaco', 'Courier New', monospace;
    --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
    --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
    --shadow-md: 0 2px 4px rgba(0,0,0,0.1);
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: var(--font-sans);
    font-size: 14px;
    line-height: 1.6;
    color: var(--text-primary);
    background: var(--bg-primary);
}

.container { max-width: 1400px; margin: 0 auto; padding: 20px; }

/* Header */
.report-header {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-left: 4px solid var(--text-primary);
    padding: 24px;
    margin-bottom: 20px;
}

.report-header h1 {
    font-size: 22px;
    font-weight: 600;
    margin-bottom: 4px;
    color: var(--text-primary);
}

.report-header .subtitle {
    font-size: 14px;
    color: var(--text-secondary);
}

.report-header .timestamp {
    font-size: 12px;
    color: var(--text-muted);
    font-family: var(--font-mono);
    margin-top: 8px;
}

/* Controls Bar */
.controls-bar {
    position: sticky;
    top: 0;
    z-index: 100;
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    padding: 12px 16px;
    margin-bottom: 20px;
    display: flex;
    gap: 16px;
    align-items: center;
    box-shadow: var(--shadow-sm);
}

.search-global {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 12px;
}

.search-global input {
    flex: 1;
    padding: 8px 12px;
    font-size: 14px;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    font-family: var(--font-mono);
    max-width: 500px;
}

.search-global input:focus {
    outline: none;
    border-color: var(--color-high-value);
}

.search-results {
    font-size: 12px;
    color: var(--text-muted);
}

.control-buttons {
    display: flex;
    gap: 8px;
}

.btn {
    padding: 8px 14px;
    font-size: 13px;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    background: var(--bg-secondary);
    cursor: pointer;
    font-family: var(--font-sans);
}

.btn:hover { background: var(--bg-tertiary); }
.btn-outline { background: transparent; }
.btn-small { padding: 4px 8px; font-size: 11px; }

/* Executive Summary */
.exec-summary {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    margin-bottom: 20px;
}

.exec-summary-header {
    padding: 16px 20px;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.exec-summary-header h2 {
    font-size: 16px;
    font-weight: 600;
}

.status-badge {
    padding: 4px 10px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.status-success { background: var(--bg-success); color: var(--color-success); border: 1px solid var(--color-success); }
.status-partial { background: var(--bg-warning); color: var(--color-warning); border: 1px solid var(--color-warning); }
.status-failed { background: var(--bg-error); color: var(--color-error); border: 1px solid var(--color-error); }
.status-neutral { background: var(--bg-tertiary); color: var(--text-secondary); border: 1px solid var(--border-color); }

.exec-summary-content {
    padding: 20px;
}

.summary-stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 16px;
    margin-bottom: 20px;
}

.stat-card {
    background: var(--bg-tertiary);
    border: 1px solid var(--border-color);
    padding: 16px;
    text-align: center;
}

.stat-card.highlight {
    background: var(--bg-high-value);
    border-color: var(--color-high-value);
}

.stat-value {
    font-size: 28px;
    font-weight: 700;
    color: var(--text-primary);
    line-height: 1;
}

.stat-card.highlight .stat-value { color: var(--color-high-value); }

.stat-label {
    font-size: 11px;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-top: 6px;
}

.summary-details {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    font-size: 13px;
}

.summary-col h4 {
    font-size: 12px;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 8px;
    letter-spacing: 0.5px;
}

.summary-col dl {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 4px 12px;
}

.summary-col dt { color: var(--text-secondary); }
.summary-col dd { font-family: var(--font-mono); font-size: 12px; }

/* Error Section */
.error-section {
    background: var(--bg-error);
    border: 1px solid var(--color-error);
    border-left: 4px solid var(--color-error);
    margin-bottom: 20px;
    padding: 16px 20px;
}

.error-section h3 {
    font-size: 14px;
    color: var(--color-error);
    margin-bottom: 12px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.error-list {
    list-style: none;
    font-size: 13px;
}

.error-list li {
    padding: 4px 0;
    color: var(--text-primary);
}

.error-list li::before {
    content: "\\2022";
    color: var(--color-error);
    margin-right: 8px;
}

/* Data Sections */
.data-section {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    margin-bottom: 16px;
}

.data-section.high-value {
    border-left: 4px solid var(--color-high-value);
}

.section-header {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border-color);
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--bg-tertiary);
    cursor: pointer;
    user-select: none;
}

.section-header:hover { background: #f0f0f0; }

.section-title {
    display: flex;
    align-items: center;
    gap: 10px;
}

.section-title h3 {
    font-size: 15px;
    font-weight: 600;
}

.badge {
    padding: 3px 8px;
    border-radius: 3px;
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
}

.badge-high-value {
    background: var(--bg-high-value);
    color: var(--color-high-value);
    border: 1px solid var(--color-high-value);
}

.badge-count {
    background: var(--bg-tertiary);
    color: var(--text-secondary);
    border: 1px solid var(--border-color);
}

.section-controls {
    display: flex;
    align-items: center;
    gap: 10px;
}

.collapse-icon {
    font-size: 12px;
    color: var(--text-muted);
    transition: transform 0.2s;
}

.section-header.collapsed .collapse-icon { transform: rotate(-90deg); }

.section-content {
    padding: 16px 20px;
}

.section-content.collapsed { display: none; }

/* Table Controls */
.table-controls {
    display: flex;
    gap: 12px;
    margin-bottom: 12px;
    flex-wrap: wrap;
    align-items: center;
}

.table-search {
    padding: 6px 10px;
    font-size: 12px;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    font-family: var(--font-mono);
    min-width: 200px;
}

.filter-group {
    display: flex;
    gap: 6px;
    align-items: center;
}

.filter-group label {
    font-size: 11px;
    color: var(--text-muted);
}

.filter-group select {
    padding: 4px 8px;
    font-size: 12px;
    border: 1px solid var(--border-color);
    border-radius: 3px;
}

/* Tables */
.table-wrapper {
    overflow-x: auto;
    border: 1px solid var(--border-color);
}

.table-wrapper.limited {
    max-height: 400px;
    overflow-y: auto;
}

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
}

th, td {
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border-color);
}

th {
    background: var(--bg-tertiary);
    font-weight: 600;
    color: var(--text-secondary);
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.3px;
    position: sticky;
    top: 0;
    z-index: 10;
    cursor: pointer;
    white-space: nowrap;
}

th:hover { background: #eaeaea; }
th .sort-icon { margin-left: 4px; opacity: 0.4; font-size: 10px; }
th.asc .sort-icon::after { content: "\\25B2"; }
th.desc .sort-icon::after { content: "\\25BC"; }

td {
    font-family: var(--font-mono);
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

td.wrap { white-space: normal; word-break: break-word; }

tr:hover { background: var(--bg-tertiary); }
tr.hidden { display: none; }
tr.highlight { background: #fffde7 !important; }

/* Credential styling */
.credential-row { background: #fafafa; }
.credential-row:hover { background: #f5f5f5 !important; }

.password-cell {
    display: flex;
    align-items: center;
    gap: 6px;
}

.pwd-value {
    font-family: var(--font-mono);
    max-width: 150px;
    overflow: hidden;
    text-overflow: ellipsis;
}

.pwd-masked { color: var(--text-muted); letter-spacing: 1px; }
.pwd-revealed { color: var(--color-error); font-weight: 500; }

.pwd-btn {
    padding: 2px 6px;
    font-size: 10px;
    border: 1px solid var(--border-color);
    border-radius: 2px;
    background: var(--bg-secondary);
    cursor: pointer;
    text-transform: uppercase;
}

.pwd-btn:hover { background: var(--bg-tertiary); }

/* Redaction mode */
body.redacted .pwd-value,
body.redacted .sensitive-data {
    filter: blur(4px);
    user-select: none;
}

body.redacted .pwd-btn { display: none; }

/* Metadata */
.metadata-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 12px;
}

.metadata-item {
    display: flex;
    padding: 6px 0;
    border-bottom: 1px dotted var(--border-color);
}

.metadata-label {
    font-weight: 600;
    color: var(--text-secondary);
    min-width: 120px;
    font-size: 12px;
}

.metadata-value {
    font-family: var(--font-mono);
    font-size: 12px;
    word-break: break-all;
}

/* Source file indicator */
.source-file {
    font-size: 10px;
    color: var(--text-muted);
    font-style: italic;
}

/* Show more button */
.show-more-row td {
    text-align: center;
    padding: 12px;
    background: var(--bg-tertiary);
}

.show-more-btn {
    padding: 6px 16px;
    font-size: 12px;
    border: 1px solid var(--border-color);
    border-radius: 4px;
    background: var(--bg-secondary);
    cursor: pointer;
}

.show-more-btn:hover { background: #f0f0f0; }

/* Footer */
.report-footer {
    text-align: center;
    padding: 24px;
    color: var(--text-muted);
    font-size: 12px;
    border-top: 1px solid var(--border-color);
    margin-top: 24px;
}

.report-footer .notice {
    margin-top: 8px;
    font-size: 11px;
}

/* Print styles */
@media print {
    body { background: white; font-size: 10pt; }
    .controls-bar, .pwd-btn, .show-more-btn, .table-controls { display: none !important; }
    .section-content.collapsed { display: block !important; }
    .pwd-revealed { display: none !important; }
    .pwd-masked { display: inline !important; }
    .data-section { page-break-inside: avoid; }
    .container { max-width: 100%; padding: 0; }
    .table-wrapper { max-height: none !important; overflow: visible !important; }
}

/* Grayscale test - report remains readable */
@media (prefers-color-scheme: dark) {
    /* Maintain readability in all conditions */
}
'''


def _get_javascript() -> str:
    """Return the JavaScript code."""
    return '''
// State
let redactionEnabled = false;
let expandedTables = new Set();

// Global search
document.getElementById('globalSearch').addEventListener('input', function(e) {
    const term = e.target.value.toLowerCase().trim();
    let matches = 0, total = 0;
    
    document.querySelectorAll('table tbody tr:not(.show-more-row)').forEach(function(row) {
        total++;
        const text = row.textContent.toLowerCase();
        const isMatch = !term || text.includes(term);
        row.classList.toggle('hidden', !isMatch);
        row.classList.toggle('highlight', isMatch && term.length > 2);
        if (isMatch) matches++;
    });
    
    const results = document.getElementById('searchResults');
    if (term) {
        results.textContent = matches + ' of ' + total + ' records match';
        results.style.color = matches > 0 ? 'var(--color-success)' : 'var(--color-error)';
    } else {
        results.textContent = '';
    }
});

// Table-specific search
document.querySelectorAll('.table-search').forEach(function(input) {
    input.addEventListener('input', function() {
        const tableId = input.dataset.table;
        const table = document.getElementById(tableId);
        if (!table) return;
        
        const term = input.value.toLowerCase().trim();
        table.querySelectorAll('tbody tr:not(.show-more-row)').forEach(function(row) {
            const text = row.textContent.toLowerCase();
            row.classList.toggle('hidden', term && !text.includes(term));
        });
    });
});

// Column filters
document.querySelectorAll('.column-filter').forEach(function(select) {
    select.addEventListener('change', function() {
        const tableId = select.dataset.table;
        const column = parseInt(select.dataset.column);
        const value = select.value.toLowerCase();
        const table = document.getElementById(tableId);
        if (!table) return;
        
        table.querySelectorAll('tbody tr:not(.show-more-row)').forEach(function(row) {
            if (!value) {
                row.classList.remove('hidden');
                return;
            }
            const cell = row.cells[column];
            if (cell) {
                const cellText = cell.textContent.toLowerCase();
                row.classList.toggle('hidden', !cellText.includes(value));
            }
        });
    });
});

// Column sorting
document.querySelectorAll('th[data-sort]').forEach(function(header) {
    header.addEventListener('click', function() {
        const table = header.closest('table');
        const idx = Array.from(header.parentNode.children).indexOf(header);
        const asc = header.classList.contains('asc');
        
        table.querySelectorAll('th').forEach(th => th.classList.remove('asc', 'desc'));
        header.classList.add(asc ? 'desc' : 'asc');
        
        const tbody = table.querySelector('tbody');
        const rows = Array.from(tbody.querySelectorAll('tr:not(.show-more-row)'));
        
        rows.sort(function(a, b) {
            const aVal = a.cells[idx]?.textContent || '';
            const bVal = b.cells[idx]?.textContent || '';
            return asc ? bVal.localeCompare(aVal) : aVal.localeCompare(bVal);
        });
        
        rows.forEach(row => tbody.appendChild(row));
    });
});

// Section collapse/expand
document.querySelectorAll('.section-header').forEach(function(header) {
    header.addEventListener('click', function(e) {
        if (e.target.closest('.table-search, .column-filter, button')) return;
        
        const content = header.nextElementSibling;
        const isCollapsed = content.classList.toggle('collapsed');
        header.classList.toggle('collapsed', isCollapsed);
    });
});

// Password reveal
function togglePwd(btn) {
    if (redactionEnabled) return;
    
    const cell = btn.closest('.password-cell');
    const masked = cell.querySelector('.pwd-masked');
    const revealed = cell.querySelector('.pwd-revealed');
    
    if (masked.style.display !== 'none') {
        masked.style.display = 'none';
        revealed.style.display = 'inline';
        btn.textContent = 'Hide';
    } else {
        masked.style.display = 'inline';
        revealed.style.display = 'none';
        btn.textContent = 'Show';
    }
}

// Copy password
function copyPwd(btn) {
    if (redactionEnabled) return;
    
    const cell = btn.closest('.password-cell');
    const pwd = cell.querySelector('.pwd-revealed').textContent;
    navigator.clipboard.writeText(pwd).then(function() {
        const orig = btn.textContent;
        btn.textContent = 'Copied';
        setTimeout(function() { btn.textContent = orig; }, 1000);
    });
}

// Redaction toggle
function toggleRedaction() {
    redactionEnabled = !redactionEnabled;
    document.body.classList.toggle('redacted', redactionEnabled);
    document.getElementById('redactToggle').textContent = redactionEnabled ? 'Disable Redaction' : 'Enable Redaction';
    
    // Hide all revealed passwords
    if (redactionEnabled) {
        document.querySelectorAll('.pwd-revealed').forEach(el => el.style.display = 'none');
        document.querySelectorAll('.pwd-masked').forEach(el => el.style.display = 'inline');
        document.querySelectorAll('.pwd-btn').forEach(btn => { if (btn.textContent === 'Hide') btn.textContent = 'Show'; });
    }
}

// Show more rows
function showMoreRows(btn, tableId) {
    const table = document.getElementById(tableId);
    const hiddenRows = table.querySelectorAll('tr.initially-hidden');
    hiddenRows.forEach(row => {
        row.classList.remove('initially-hidden');
        row.style.display = '';
    });
    btn.closest('tr').remove();
    expandedTables.add(tableId);
}
'''


def _build_executive_summary(
    browser_name: str,
    profile_path: Path,
    timestamp: str,
    stats: Dict[str, int],
    decryption_status: str,
    errors: List[str],
) -> str:
    """Build the executive summary section."""
    
    status_class = {
        'SUCCESS': 'status-success',
        'PARTIAL': 'status-partial', 
        'FAILED': 'status-failed',
        'NOT ATTEMPTED': 'status-neutral',
        'NONE FOUND': 'status-neutral',
    }.get(decryption_status, 'status-neutral')
    
    error_count = len(errors)
    
    return f'''
    <section class="exec-summary">
        <div class="exec-summary-header">
            <h2>Executive Summary</h2>
            <span class="status-badge {status_class}">{decryption_status}</span>
        </div>
        <div class="exec-summary-content">
            <div class="summary-stats">
                <div class="stat-card{' highlight' if stats['passwords'] > 0 else ''}">
                    <div class="stat-value">{stats['passwords']}</div>
                    <div class="stat-label">Credentials</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['cookies']}</div>
                    <div class="stat-label">Cookies</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['history']}</div>
                    <div class="stat-label">History</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['bookmarks']}</div>
                    <div class="stat-label">Bookmarks</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats['total']}</div>
                    <div class="stat-label">Total Records</div>
                </div>
                <div class="stat-card{' highlight' if error_count > 0 else ''}">
                    <div class="stat-value">{error_count}</div>
                    <div class="stat-label">{'Warnings' if error_count else 'No Errors'}</div>
                </div>
            </div>
            <div class="summary-details">
                <div class="summary-col">
                    <h4>Profile Information</h4>
                    <dl>
                        <dt>Browser</dt>
                        <dd>{html.escape(browser_name)}</dd>
                        <dt>Profile</dt>
                        <dd>{html.escape(profile_path.name)}</dd>
                        <dt>Categories</dt>
                        <dd>{stats['categories']} extracted</dd>
                    </dl>
                </div>
                <div class="summary-col">
                    <h4>Analysis Details</h4>
                    <dl>
                        <dt>Timestamp</dt>
                        <dd>{timestamp}</dd>
                        <dt>Decryption</dt>
                        <dd>{decryption_status}</dd>
                        <dt>Access Mode</dt>
                        <dd>Read-Only</dd>
                    </dl>
                </div>
            </div>
        </div>
    </section>'''


def _build_error_section(errors: List[str]) -> str:
    """Build the errors and warnings section."""
    if not errors:
        return ""
    
    error_items = '\n'.join(f'<li>{html.escape(err)}</li>' for err in errors)
    
    return f'''
    <section class="error-section">
        <h3>Errors &amp; Warnings ({len(errors)})</h3>
        <ul class="error-list">
            {error_items}
        </ul>
    </section>'''


def _build_metadata_section(
    browser_name: str,
    profile_path: Path,
    timestamp_iso: str,
    timestamp_display: str,
) -> str:
    """Build the extraction metadata section."""
    return f'''
    <section class="data-section">
        <div class="section-header">
            <div class="section-title">
                <h3>Extraction Metadata</h3>
            </div>
            <span class="collapse-icon">▼</span>
        </div>
        <div class="section-content">
            <div class="metadata-grid">
                <div class="metadata-item">
                    <span class="metadata-label">Browser</span>
                    <span class="metadata-value">{html.escape(browser_name)}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Profile Path</span>
                    <span class="metadata-value">{html.escape(str(profile_path))}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Timestamp (UTC)</span>
                    <span class="metadata-value">{timestamp_iso}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Timestamp (Local)</span>
                    <span class="metadata-value">{timestamp_display}</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Access Mode</span>
                    <span class="metadata-value">Read-Only</span>
                </div>
                <div class="metadata-item">
                    <span class="metadata-label">Profile Hash</span>
                    <span class="metadata-value">{hashlib.md5(str(profile_path).encode()).hexdigest()[:16]}...</span>
                </div>
            </div>
        </div>
    </section>'''


def _build_credentials_section(records: List, profile_path: Path) -> str:
    """Build the credentials section with special handling."""
    if not records:
        return ""
    
    table_id = "table-credentials"
    
    # Build table rows
    rows = []
    for i, record in enumerate(records):
        # Handle both dict and object formats
        if hasattr(record, '__dict__'):
            hostname = getattr(record, 'hostname', getattr(record, 'signon_realm', getattr(record, 'url', 'N/A')))
            username = getattr(record, 'username', 'N/A')
            password = getattr(record, 'password', '')
            times_used = getattr(record, 'times_used', '')
        else:
            hostname = record.get('hostname', record.get('signon_realm', record.get('url', 'N/A')))
            username = record.get('username', 'N/A')
            password = record.get('password', '')
            times_used = record.get('times_used', '')
        
        row_html = f'''<tr class="credential-row">
            <td title="{html.escape(str(hostname))}">{html.escape(str(hostname)[:60])}</td>
            <td class="sensitive-data">{html.escape(str(username))}</td>
            <td>
                <div class="password-cell">
                    <span class="pwd-value pwd-masked">••••••••</span>
                    <span class="pwd-value pwd-revealed" style="display:none">{html.escape(str(password))}</span>
                    <button class="pwd-btn" onclick="togglePwd(this)">Show</button>
                    <button class="pwd-btn" onclick="copyPwd(this)">Copy</button>
                </div>
            </td>
            <td>{html.escape(str(times_used)) if times_used else '-'}</td>
            <td class="source-file">logins.json / key4.db</td>
        </tr>'''
        rows.append(row_html)
    
    return f'''
    <section class="data-section high-value" id="section-credentials">
        <div class="section-header">
            <div class="section-title">
                <h3>Saved Credentials</h3>
                <span class="badge badge-high-value">High Value</span>
                <span class="badge badge-count">{len(records)} records</span>
            </div>
            <span class="collapse-icon">▼</span>
        </div>
        <div class="section-content">
            <div class="table-controls">
                <input type="text" class="table-search" data-table="{table_id}" placeholder="Filter credentials...">
            </div>
            <div class="table-wrapper">
                <table id="{table_id}">
                    <thead>
                        <tr>
                            <th data-sort>Host / Domain<span class="sort-icon"></span></th>
                            <th data-sort>Username<span class="sort-icon"></span></th>
                            <th>Password</th>
                            <th data-sort>Times Used<span class="sort-icon"></span></th>
                            <th>Source</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </div>
    </section>'''


def _build_data_section(category: str, records: List[Dict], profile_path: Path, collapsed: bool = False) -> str:
    """Build a generic data section with table."""
    if not records or not isinstance(records[0], dict):
        return ''
    
    labels = {
        'cookies': 'Cookies',
        'history': 'Browsing History',
        'bookmarks': 'Bookmarks',
        'downloads': 'Downloads',
        'autofill': 'Form Autofill',
        'extensions': 'Extensions',
    }
    
    # Source files by category
    source_files = {
        'cookies': 'cookies.sqlite',
        'history': 'places.sqlite',
        'bookmarks': 'places.sqlite',
        'downloads': 'places.sqlite',
        'autofill': 'formhistory.sqlite',
        'extensions': 'extensions.json',
    }
    
    label = labels.get(category, category.replace('_', ' ').title())
    source = source_files.get(category, 'database')
    table_id = f'table-{category}'
    
    # Get columns (limit for readability)
    columns = list(records[0].keys())[:8]
    
    # Determine if cookies - add filters
    is_cookies = category == 'cookies'
    filters_html = ""
    if is_cookies:
        filters_html = '''
            <div class="filter-group">
                <label>Filter:</label>
                <select class="column-filter" data-table="table-cookies" data-column="0">
                    <option value="">All Domains</option>
                </select>
            </div>'''
    
    # Build headers
    headers = []
    for col in columns:
        headers.append(f'<th data-sort>{html.escape(col.replace("_", " ").title())}<span class="sort-icon"></span></th>')
    headers.append('<th>Source</th>')
    
    # Build rows - show limited initially
    initial_limit = 50
    rows = []
    
    for i, record in enumerate(records):
        hidden_class = ' class="initially-hidden" style="display:none"' if i >= initial_limit else ''
        cells = []
        for col in columns:
            value = str(record.get(col, ''))
            # Truncate long values
            display = value[:80] + '...' if len(value) > 80 else value
            cells.append(f'<td title="{html.escape(value)}">{html.escape(display)}</td>')
        cells.append(f'<td class="source-file">{source}</td>')
        rows.append(f'<tr{hidden_class}>\n            {chr(10).join(cells)}\n        </tr>')
    
    # Add "show more" row if needed
    show_more = ""
    if len(records) > initial_limit:
        remaining = len(records) - initial_limit
        show_more = f'''<tr class="show-more-row">
            <td colspan="{len(columns) + 1}">
                <button class="show-more-btn" onclick="showMoreRows(this, '{table_id}')">Show all {len(records)} entries ({remaining} more)</button>
            </td>
        </tr>'''
    
    collapsed_class = ' collapsed' if collapsed else ''
    
    return f'''
    <section class="data-section" id="section-{category}">
        <div class="section-header{collapsed_class}">
            <div class="section-title">
                <h3>{html.escape(label)}</h3>
                <span class="badge badge-count">{len(records):,} records</span>
            </div>
            <span class="collapse-icon">▼</span>
        </div>
        <div class="section-content{collapsed_class}">
            <div class="table-controls">
                <input type="text" class="table-search" data-table="{table_id}" placeholder="Filter {label.lower()}...">
                {filters_html}
            </div>
            <div class="table-wrapper limited">
                <table id="{table_id}">
                    <thead>
                        <tr>
                            {''.join(headers)}
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                        {show_more}
                    </tbody>
                </table>
            </div>
        </div>
    </section>'''
