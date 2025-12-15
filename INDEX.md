# Firefox Forensics Extraction Tool - Documentation Index

## Quick Start
- **[README.md](README.md)** - Full documentation and usage
- **[SETUP.md](SETUP.md)** - Installation and quick start
- **[FIREFOX_FORENSICS.md](FIREFOX_FORENSICS.md)** - Forensic reference guide

## Source Files
- **[main.py](main.py)** - CLI entry point and orchestrator
- **[nss_decrypt.py](nss_decrypt.py)** - Firefox password decryption via NSS
- **[extractor.py](extractor.py)** - Database extraction core
- **[formatters.py](formatters.py)** - Report generation (HTML/CSV/MD)
- **[queries.py](queries.py)** - Forensic SQL queries
- **[utils.py](utils.py)** - Utility functions

## Quick Usage

```bash
# Basic extraction (interactive profile selection)
python main.py

# Extract specific profile
python main.py ~/.mozilla/firefox/profile.default

# Custom output directory
python main.py /path/to/profile --output my_analysis

# List available queries
python main.py --list-queries

# Check password decryption support
python main.py --check-env
```

## Forensic Queries

**places.sqlite**: browsing_history, bookmarks, top_sites, recent_24h, downloads, search_queries, referrer_chains  
**cookies.sqlite**: all_cookies, auth_tokens, persistent_sessions, cookies_by_domain  
**formhistory.sqlite**: all_form_history, sensitive_fields, search_queries, email_addresses  
**permissions.sqlite**: all_permissions, granted_permissions, geolocation, media_devices, notifications  
**storage.sqlite**: localstorage, sessionstorage  
**favicons.sqlite**: favicon_mapping

## Output Structure

```
firefox_forensics_output/
├── forensics_report.html  # Interactive HTML report with decrypted passwords
├── forensics_report.md    # Markdown report
├── master_report.md       # Comprehensive summary
├── csv_export/            # CSV files (history, cookies, credentials, etc.)
│   ├── CREDENTIALS.csv    # Decrypted passwords!
│   ├── browsing_history.csv
│   ├── all_cookies.csv
│   └── ... (19 files)
└── artifacts/             # Processed JSON files (13 files)
```

## Key Features

- ✓ Automatic database detection and table enumeration
- ✓ 30+ forensic SQL queries (history, cookies, forms, permissions)
- ✓ **Password decryption** via NSS (Windows & Linux)
- ✓ HTML, CSV, and Markdown report generation
- ✓ JSON artifact parsing (extensions, sessions)
- ✓ Interactive profile selection
- ✓ Master password support
- ✓ Environment validation for decryption compatibility
- ✓ Zero external dependencies (Python stdlib only)

## Password Decryption

```bash
# Check if your system supports password decryption
python main.py --check-env

# Supported: Windows, Native Linux Firefox with libnss3
# NOT Supported: Snap, Flatpak, GNOME Keyring, KWallet, macOS
```

## Common Tasks

```bash
# View browsing history
cat firefox_forensics_output/csv_export/browsing_history.csv

# View decrypted credentials
cat firefox_forensics_output/csv_export/CREDENTIALS.csv

# View auth tokens
cat firefox_forensics_output/csv_export/auth_tokens.csv

# View form inputs
cat firefox_forensics_output/csv_export/all_form_history.csv
```

## Programmatic Usage

```python
from extractor import FirefoxDatabaseExtractor
from pathlib import Path

profile = Path.home() / ".mozilla/firefox/profile.default"
extractor = FirefoxDatabaseExtractor(profile)

for db in extractor.find_databases():
    tables = extractor.get_tables(db)
    print(f"{db.name}: {', '.join(tables)}")
```

---

**Python 3.9+ | Windows & Linux Password Decryption | HTML/CSV/Markdown Output**
