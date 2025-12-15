# Firefox Forensics Extraction Tool - Setup Guide

## Project Overview

This is a professional-grade forensics extraction tool for Mozilla Firefox profiles. It extracts and analyzes:

- **Browsing History**: All visited URLs with timestamps
- **Bookmarks**: Saved bookmarks with folder structure
- **Cookies**: HTTP cookies with authentication tokens
- **Form History**: Saved form inputs and search queries
- **Permissions**: Site-specific permissions (geolocation, camera, etc.)
- **DOM Storage**: Web application state (localStorage, sessionStorage)
- **Favicons**: Cached website icons
- **Extensions**: Installed addons with metadata
- **Preferences**: Browser configuration
- **Saved Passwords**: Decrypted login credentials (Windows & Linux)

## Project Structure

```
code_base/
├── main.py              # CLI entry point and orchestrator
├── extractor.py         # Core extraction classes
├── formatters.py        # Report generation (HTML, CSV, Markdown)
├── queries.py           # Forensic SQL queries (30+)
├── nss_decrypt.py       # Firefox password decryption via NSS
├── utils.py             # Utility functions
├── README.md            # Full documentation
├── SETUP.md             # This file
├── FIREFOX_FORENSICS.md # Forensic analysis reference
├── INDEX.md             # Documentation index
├── LICENSE              # MIT License
├── requirements.txt     # Dependencies (none - stdlib only)
└── .gitignore           # Git ignore patterns
```

## Quick Start

### 1. View Help

```bash
python main.py --help
```

### 2. List Available Queries

```bash
python main.py --list-queries
```

Output shows all 23 forensic queries across 6 databases:
- places.sqlite: 7 queries
- cookies.sqlite: 4 queries
- formhistory.sqlite: 4 queries
- permissions.sqlite: 5 queries
- storage.sqlite: 2 queries
- favicons.sqlite: 1 query

### 3. Extract Profile

```bash
python main.py ~/.mozilla/firefox/profile.default
```

This creates `firefox_forensics_output/` with:
- `databases/`: Raw SQLite exports (CSV)
- `csv_export/`: Individual CSV files per query (21 files)
- `artifacts/`: Processed JSON files (13 files)
- `forensics_report.html`: Interactive HTML report
- `forensics_report.md`: Markdown report
- `master_report.md`: Comprehensive summary

### 4. Interactive Extraction

Run in interactive mode (recommended for first-time users):

```bash
python main.py ~/.mozilla/firefox/xxxx.default-release
```

The tool will guide you through:
1. Confirmation to proceed with extraction
2. Output format selection (HTML, CSV, Markdown)
3. Save location (default: ~/Downloads/firefox_forensics_output)
4. Directory creation if needed
5. Execute a query
6. Parse JSON files

## CLI Options

```
usage: main.py [-h] [--output OUTPUT] [--format {html,csv,md,all}] [--no-interactive]
               [--verbose] [--quiet] [--list-queries] [--check-env] [profile]

positional arguments:
  profile              Path to Firefox profile (optional - auto-detects if omitted)

options:
  -h, --help           Show help message
  --output, -o OUTPUT  Output directory (default: ~/Downloads/firefox_forensics_output)
  --format, -f FORMAT  Output format: html, csv, md, or all (default: all)
  --no-interactive, -n Disable interactive prompts (use defaults)
  --verbose, -v        Enable DEBUG logging
  --quiet, -q          Suppress INFO logging
  --list-queries       List all available queries and exit
  --check-env          Check environment compatibility for password decryption
```

### Environment Check

```bash
# Check if password decryption is supported on your system
python main.py --check-env

# Check for a specific profile
python main.py --check-env ~/.mozilla/firefox/xxxx.default-release
```

This checks:
- ✅ NSS library availability (nss3.dll on Windows, libnss3.so on Linux)
- ✅ Firefox installation (required on Windows for NSS DLLs)
- ✅ Profile compatibility
- ✅ OS keyring integration status (Linux only)

## Module Guide

### main.py - Entry Point

**Functions:**
- `extract_databases()`: Extract all SQLite databases
- `extract_json_artifacts()`: Parse JSON configuration files
- `extract_profile()`: Main orchestration function
- `print_decrypted_passwords()`: Display decrypted passwords
- `prompt_master_password()`: Securely prompt for master password
- `main()`: CLI interface

**Usage:**
```bash
python main.py /path/to/profile --output analysis --verbose
```

### nss_decrypt.py - Password Decryption

**Classes:**
1. **NSSDecryptor**
   - `initialize(profile_path, master_password)`: Init NSS with profile
   - `decrypt(encrypted_data)`: Decrypt base64-encoded data
   - `decrypt_logins()`: Decrypt all saved passwords
   - `shutdown()`: Cleanup NSS resources

2. **DecryptedLogin** (dataclass)
   - `url`: Login URL
   - `hostname`: Site hostname
   - `username`: Decrypted username
   - `password`: Decrypted password
   - `times_used`: Usage count
   - `form_submit_url`: Form action URL

**Exceptions:**
- `MasterPasswordRequired`: Profile has master password
- `UnsupportedEnvironment`: Snap/Flatpak Firefox
- `NSSLibraryMissing`: libnss3 not found
- `OSKeyringLocked`: GNOME Keyring/KWallet integration

**Environment Functions:**
- `validate_environment(profile_path)`: Check decryption support
- `run_environment_check(profile_path)`: Print diagnostic info
- `detect_firefox_installation_type()`: Native/Snap/Flatpak
- `check_nss_library_available()`: Find libnss3

### extractor.py - Core Extraction

**Classes:**

1. **FirefoxDatabaseExtractor**
   - `find_databases()`: Locate .sqlite files
   - `find_json_files()`: Locate .json files
   - `get_tables(db_path)`: Enumerate database tables
   - `export_table_to_csv()`: Export table to CSV
   - `run_forensic_query()`: Execute SQL query
   - `export_query_results_to_csv()`: Export query results

2. **FirefoxJSONExtractor**
   - `parse_extensions()`: Parse addons.json
   - `parse_search_engines()`: Parse search.json
   - `parse_json_file()`: Generic JSON parser
   - `save_json_report()`: Export JSON data

3. **ForensicReportGenerator**
   - `generate_database_summary()`: Create DB summary
   - `generate_master_report()`: Create full report

4. **ExtractionResult** (dataclass)
   - `success`: Boolean success flag
   - `database`: Database name
   - `rows_extracted`: Total rows extracted
   - `error`: Error message if any
   - `output_path`: Path to output directory

**Usage:**
```python
from extractor import FirefoxDatabaseExtractor
from pathlib import Path

extractor = FirefoxDatabaseExtractor(Path("~/.mozilla/firefox/profile"))
tables = extractor.get_tables(extractor.find_databases()[0])
print(tables)
```

### queries.py - Forensic Queries

**Contents:**
- SQL query definitions for each database
- `QUERY_REGISTRY`: Registry mapping databases to queries
- `get_query(database, query_name)`: Retrieve a query
- `list_queries()`: List all queries

**Database Coverage:**

| Database | Queries | Purpose |
|----------|---------|---------|
| places.sqlite | 7 | History, bookmarks, visits |
| cookies.sqlite | 4 | HTTP cookies, sessions |
| formhistory.sqlite | 4 | Form input, searches, emails |
| permissions.sqlite | 5 | Site permissions |
| storage.sqlite | 2 | DOM storage |
| favicons.sqlite | 1 | Website icons |

**Adding Custom Queries:**

```python
# In queries.py
CUSTOM_QUERY = """
SELECT url, title FROM moz_places
WHERE url LIKE '%suspicious%'
"""

QUERY_REGISTRY["places.sqlite"]["suspicious"] = CUSTOM_QUERY
```

### utils.py - Utilities

**Logging:**
- `setup_logging()`: Configure logging with DEBUG/INFO/WARNING/ERROR

**Filesystem:**
- `create_output_directory()`: Create output structure
- `validate_profile_path()`: Verify Firefox profile
- `expand_firefox_path()`: Expand ~, resolve paths
- `safe_file_copy()`: Safe file copying
- `sanitize_filename()`: Sanitize filenames

**Data:**
- `get_profile_info()`: Extract profile metadata
- `format_bytes()`: Human-readable byte sizes
- `count_table_rows()`: Count SQLite rows
- `generate_summary_text()`: Format summary text

**Progress:**
- `ProgressTracker` class: Track extraction progress

## Forensic Artifacts

### Browsing History (places.sqlite)
- All visited URLs with titles
- Visit timestamps and types (typed, clicked, redirect, etc.)
- Visit counts and frecency scores
- Referrer chains for navigation paths

**Key Query:** `browsing_history`

### Bookmarks (places.sqlite)
- Saved bookmarks with titles and URLs
- Creation and modification timestamps
- Folder hierarchy
- Unique identifiers (GUID)

**Key Query:** `bookmarks`

### Cookies (cookies.sqlite)
- HTTP cookie name/value pairs
- Domain and path restrictions
- Expiry dates
- Secure and HttpOnly flags
- Last accessed timestamps

**Key Query:** `all_cookies` or `auth_tokens`

### Form History (formhistory.sqlite)
- Saved search queries
- Email addresses entered
- Usernames and text fields
- Frequency and timing of use

**Key Query:** `sensitive_fields` or `email_addresses`

### Permissions (permissions.sqlite)
- Geolocation grants/denials
- Camera/microphone access
- Notification permissions
- Grant timestamps

**Key Query:** `granted_permissions` or `geolocation`

### DOM Storage (storage.sqlite)
- localStorage entries by origin
- sessionStorage entries
- Web application state
- Authentication tokens

**Key Query:** `localstorage` or `sessionstorage`

### Extensions (extensions.json / addons.json)
- Installed addon names and versions
- Installation dates
- Enabled/disabled status
- Permissions granted

**Key Query:** Use `FirefoxJSONExtractor.parse_extensions()`

## Output Structure

### /databases/ - Raw SQLite Exports
One CSV file per table in each database:
```
places_moz_places.csv
places_moz_historyvisits.csv
places_moz_bookmarks.csv
cookies_moz_cookies.csv
formhistory_moz_formhistory.csv
permissions_moz_perms.csv
storage_webappsSession.csv
favicons_moz_favicons.csv
```

### /forensics/ - Forensic Query Results
Specialized query results in CSV format:
```
places_browsing_history.csv        # Full visit history
places_bookmarks.csv               # All bookmarks
places_top_sites.csv               # Most visited sites
places_recent_24h.csv              # Last 24 hours
places_downloads.csv               # Download-related
places_search_queries.csv          # Search history
places_referrer_chains.csv         # Navigation chains

cookies_all_cookies.csv            # All cookies
cookies_auth_tokens.csv            # Authentication tokens
cookies_persistent_sessions.csv    # Long-lived sessions
cookies_by_domain.csv              # Cookies grouped by domain

formhistory_all_form_history.csv   # All form inputs
formhistory_sensitive_fields.csv   # Emails, usernames, etc.
formhistory_search_queries.csv     # Search queries
formhistory_email_addresses.csv    # Unique emails

permissions_all_permissions.csv    # All permissions
permissions_granted_permissions.csv # Granted only
permissions_geolocation.csv        # Geolocation grants
permissions_media_devices.csv      # Camera/mic grants
permissions_notifications.csv      # Notification grants

storage_localstorage.csv           # localStorage entries
storage_sessionstorage.csv         # sessionStorage entries

favicons_favicon_mapping.csv       # Favicon URLs
```

### /reports/ - Database Summaries
Markdown summaries for each database:
```
places_summary.md       # History database info
cookies_summary.md      # Cookies database info
formhistory_summary.md  # Form history database info
permissions_summary.md  # Permissions database info
storage_summary.md      # Storage database info
favicons_summary.md     # Favicons database info
```

### /artifacts/ - Processed JSON Files
Processed and formatted JSON files:
```
extensions.json         # Installed extensions
addons.json            # Addon metadata
search.json            # Search engine config
... other JSON files
```

### master_report.md - Comprehensive Report
Summary of entire extraction:
- Profile information
- Extraction statistics
- Database summaries
- Query result counts
- Output file structure

## Typical Workflow

### 1. Locate Firefox Profile
```bash
# Linux
ls -la ~/.mozilla/firefox/

# Windows (PowerShell)
Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles"

# Or just run the tool - it auto-detects profiles!
python main.py
```

### 2. Extract Forensics
```bash
# Interactive mode (recommended)
python main.py

# Or specify profile directly
python main.py ~/.mozilla/firefox/xxxx.default-release --output my_case
```

### 3. Review Master Report
```bash
cat my_case/master_report.md
```

### 4. Analyze Specific Artifacts
```bash
# View browsing history
cat my_case/forensics/places_browsing_history.csv | head -20

# View top sites
cat my_case/forensics/places_top_sites.csv

# View authentication tokens
cat my_case/forensics/cookies_auth_tokens.csv

# View email addresses from forms
cat my_case/forensics/formhistory_email_addresses.csv
```

### 5. Import into Analysis Tools
```bash
# Import into Excel/Numbers
# Import into SQLite for advanced analysis
sqlite3
> .import my_case/forensics/places_browsing_history.csv history
> SELECT * FROM history LIMIT 10;

# Import into Python/Pandas
python3
>>> import pandas as pd
>>> df = pd.read_csv('my_case/forensics/places_browsing_history.csv')
>>> df.head()
```

## Advanced Usage

### Batch Processing Multiple Profiles

```bash
#!/bin/bash
for profile in ~/.mozilla/firefox/*/; do
    name=$(basename "$profile")
    python main.py "$profile" --output "output_${name}"
done
```

### Custom Query Analysis

```python
from extractor import FirefoxDatabaseExtractor
from queries import QUERY_REGISTRY
from pathlib import Path

profile = Path("~/.mozilla/firefox/profile.default").expanduser()
extractor = FirefoxDatabaseExtractor(profile)
places_db = list(extractor.find_databases())[0]

# Execute custom query
query = """
SELECT url, visit_count FROM moz_places 
WHERE url LIKE '%github%'
ORDER BY visit_count DESC
"""

results, count = extractor.run_forensic_query(places_db, query)
for row in results:
    print(f"{row['url']}: {row['visit_count']} visits")
```

### Timeline Generation

```python
import csv
from extractor import FirefoxDatabaseExtractor
from queries import get_query
from pathlib import Path

profile = Path("~/.mozilla/firefox/profile.default").expanduser()
extractor = FirefoxDatabaseExtractor(profile)
places_db = list(extractor.find_databases())[0]

# Get history with timestamps
query = get_query("places.sqlite", "browsing_history")
results, _ = extractor.run_forensic_query(places_db, query)

# Write timeline
with open("timeline.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["timestamp", "url", "type"])
    writer.writeheader()
    for row in sorted(results, key=lambda r: r['visit_time']):
        writer.writerow({
            "timestamp": row['visit_time'],
            "url": row['url'],
            "type": row['visit_type']
        })
```

## Troubleshooting

### Firefox is Running
**Error:** `sqlite3.OperationalError: database is locked`

**Solution:** Close Firefox before extraction
```bash
killall firefox  # Linux/macOS
taskkill /F /IM firefox.exe  # Windows
```

### Profile Not Found
**Error:** `Invalid Firefox profile`

**Solution:** Find correct profile path
```bash
# Linux/macOS
~/.mozilla/firefox/

# macOS alternative
~/Library/Application Support/Firefox/Profiles/

# Windows
%APPDATA%\Mozilla\Firefox\Profiles\
```

### No Databases Found
**Error:** `Found 0 SQLite databases`

**Solution:** Verify profile is valid
```bash
ls -la ~/.mozilla/firefox/xxxx.default-release/*.sqlite
```

### Permission Denied
**Error:** `PermissionError: Permission denied`

**Solution:** Fix permissions
```bash
chmod -R 755 ~/.mozilla/firefox/profile/
```

## Performance Notes

- **Extraction Time**: 30 seconds to 5 minutes depending on profile size
- **Output Size**: 50-500 MB CSV exports (profile-dependent)
- **Memory Usage**: < 500 MB (streaming CSV export)
- **Disk Space**: Ensure 2x profile size available

## Security Notes

- **Sensitive Data**: Output contains cookies, emails, search history
- **Decrypted Passwords**: On supported systems, saved passwords are decrypted
- **Handle Carefully**: Treat output directory as confidential evidence
- **Plaintext Output**: Decrypted passwords appear in terminal and reports
- **Master Password**: If set, required for decryption (prompted interactively)

### Password Decryption Limitations

| Environment | Supported | Notes |
|-------------|-----------|-------|
| Windows | ✅ Yes | Firefox must be installed (uses nss3.dll) |
| Native Linux Firefox | ✅ Yes | Requires libnss3 |
| Snap Firefox | ❌ No | Sandboxed NSS library |
| Flatpak Firefox | ❌ No | Sandboxed NSS library |
| GNOME Keyring | ❌ No | Keys stored in system keyring |
| KWallet | ❌ No | Keys stored in system keyring |
| macOS | ❌ No | Not yet implemented |

**Workaround for unsupported environments:**
- Firefox → Settings → Passwords → ⋮ (menu) → Export Logins

## References

- Firefox Profile Data: https://support.mozilla.org/kb/profiles-where-firefox-stores-user-data
- SQLite Documentation: https://www.sqlite.org/
- Digital Forensics: https://www.sans.org/white-papers/

---

**Created:** December 2025
**Python Version:** 3.9+
**License:** MIT License - For authorized forensic use only
