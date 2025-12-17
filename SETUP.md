# Browser Forensics Extraction Tool - Setup Guide

## Project Overview

This is a professional-grade forensics extraction tool for web browsers. It supports:

### Supported Browsers
- **Firefox** (Gecko engine)
- **Chrome** (Chromium engine)
- **Microsoft Edge** (Chromium engine)
- **Brave** (Chromium engine)
- **Opera** (Chromium engine)
- **Vivaldi** (Chromium engine)

### Extracted Data
- **Browsing History**: All visited URLs with timestamps
- **Bookmarks**: Saved bookmarks with folder structure
- **Cookies**: HTTP cookies with authentication tokens
- **Form History**: Saved form inputs and search queries
- **Autofill Data**: Address and payment card autofill
- **Permissions**: Site-specific permissions (geolocation, camera, etc.)
- **Downloads**: Download history with file paths
- **Extensions**: Installed addons with metadata
- **Search History**: Search engine queries
- **Saved Passwords**: Decrypted login credentials (Windows & Linux)

## Project Structure

```
browser-forensics/
├── main.py              # CLI entry point with multi-browser support
├── browser_profiles.py  # Browser detection and profile discovery
├── chromium_extractor.py # Chromium database/JSON extraction
├── chromium_queries.py  # Chromium forensic SQL queries
├── chromium_decrypt.py  # Chromium password decryption
├── extractor.py         # Firefox extraction classes
├── formatters.py        # Report generation (HTML, CSV, Markdown)
├── queries.py           # Firefox forensic SQL queries
├── nss_decrypt.py       # Firefox password decryption via NSS
├── utils.py             # Utility functions
├── README.md            # Main documentation
├── SETUP.md             # This file
├── FIREFOX_FORENSICS.md # Firefox artifact reference
├── CHROMIUM_FORENSICS.md # Chromium artifact reference
├── INDEX.md             # Documentation index
├── LICENSE              # MIT License
├── requirements.txt     # Dependencies
└── .gitignore           # Git ignore patterns
```

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/browser-forensics.git
cd browser-forensics
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

**Required packages:**
- `pycryptodome>=3.19.0` - For Chromium AES decryption

**Optional packages:**
- `secretstorage` - For Linux GNOME Keyring access (Chromium passwords)

### 3. Verify Installation

```bash
python main.py --check-env
```

## Quick Start

### 1. List Available Browsers

```bash
python main.py --list-browsers
```

Output shows all detected browsers and profiles:
```
Detected Browsers:
══════════════════
[1] Chrome - Default (Chromium)
    Path: /home/user/.config/google-chrome/Default
[2] Firefox - default-release (Gecko)
    Path: /home/user/.mozilla/firefox/xxxx.default-release
[3] Brave - Default (Chromium)
    Path: /home/user/.config/BraveSoftware/Brave-Browser/Default
```

### 2. Interactive Extraction

```bash
python main.py
```

The tool will:
1. Auto-detect installed browsers
2. Let you select a browser/profile
3. Extract all forensic data
4. Generate reports in `~/Downloads/browser_forensics_output/`

### 3. Extract Specific Browser

```bash
# Extract from Chrome
python main.py -b chrome

# Extract from Firefox
python main.py -b firefox

# Extract from Brave
python main.py -b brave
```

### 4. Selective Extraction

```bash
# Extract only history
python main.py -e history

# Extract history and cookies
python main.py -e history cookies

# Extract passwords only
python main.py -e passwords

# Extract everything except passwords
python main.py --no-passwords
```

### 5. Terminal-Only Output

```bash
# Print to terminal without creating files
python main.py -e history --print-only

# Combine with browser selection
python main.py -b chrome -e history cookies --print-only
```

## CLI Options

```
usage: main.py [-h] [-b BROWSER] [-e EXTRACT...] [--list-browsers] [--print-only]
               [--no-passwords] [-o OUTPUT] [-n] [-v] [-q] [--list-queries] 
               [--check-env] [-c] [profile]

positional arguments:
  profile               Path to browser profile (optional - auto-detects)

options:
  -h, --help            Show help message
  -b, --browser BROWSER Browser to extract: firefox, chrome, chromium, edge,
                        brave, opera, vivaldi, auto (default: auto)
  -e, --extract CATEGORIES
                        Categories to extract: history, cookies, passwords,
                        downloads, bookmarks, autofill, extensions, forms,
                        permissions, search, all (default: all)
  --list-browsers       List all detected browsers and exit
  --print-only          Print to terminal only (no file output)
  --no-passwords        Skip password decryption
  -o, --output OUTPUT   Output directory path
  -n, --no-interactive  Disable interactive prompts
  -v, --verbose         Enable DEBUG logging
  -q, --quiet           Suppress INFO logging
  --list-queries        List all available queries and exit
  --check-env           Check environment for password decryption support
  -c, --copy-artifacts  Copy source database files as artifacts
```

### Environment Check

```bash
# Check password decryption support
python main.py --check-env
```

This checks:
- ✅ NSS library availability (Firefox)
- ✅ DPAPI/pycryptodome availability (Chromium on Windows)
- ✅ secretstorage availability (Chromium on Linux)
- ✅ Browser installations
- ✅ Profile compatibility

## Module Guide

### main.py - Entry Point

**Key Functions:**
- `detect_browsers()`: Find installed browsers and profiles
- `extract_chromium_forensics()`: Extract from Chromium browsers
- `extract_firefox_quick()`: Extract from Firefox
- `print_*_terminal()`: Print data categories to terminal
- `main()`: CLI interface

### browser_profiles.py - Browser Detection

**Classes:**
- `BrowserType`: Enum of supported browsers
- `BrowserFamily`: Gecko or Chromium
- `BrowserProfile`: Profile information dataclass

**Functions:**
- `detect_all_browsers()`: Auto-detect all installed browsers
- `get_browser_profiles()`: Get profiles for specific browser
- `get_profile_path()`: Platform-specific profile paths

### chromium_extractor.py - Chromium Extraction

**Classes:**
1. **ChromiumDatabaseExtractor**
   - `find_databases()`: Locate SQLite databases
   - `run_query()`: Execute SQL query
   - `export_to_csv()`: Export results to CSV

2. **ChromiumJSONExtractor**
   - `flatten_bookmarks()`: Parse Bookmarks JSON
   - `get_extensions()`: Parse Extensions data

### chromium_queries.py - Chromium Queries

Contains `CHROMIUM_QUERY_REGISTRY` with queries for:
- History.db: browsing_history, downloads, search_terms
- Cookies.db: all_cookies, persistent_cookies
- Login Data.db: passwords (encrypted)
- Web Data.db: autofill, credit_cards (encrypted)
- Preferences: extensions, permissions

### chromium_decrypt.py - Chromium Password Decryption

**Functions:**
- `decrypt_chromium_passwords()`: Decrypt passwords using platform-specific methods
- `check_decryption_requirements()`: Verify decryption is possible

**Platform Methods:**
- Windows: DPAPI + AES-GCM
- Linux: PBKDF2 + AES-CBC (via secretstorage)
- macOS: Keychain + AES-CBC

### Firefox Modules

- `extractor.py`: Firefox database/JSON extraction
- `queries.py`: Firefox forensic SQL queries (30+)
- `nss_decrypt.py`: Firefox NSS password decryption

## Data Categories

| Category | Flag | Description |
|----------|------|-------------|
| history | `-e history` | Browsing history with timestamps |
| cookies | `-e cookies` | HTTP cookies, auth tokens |
| passwords | `-e passwords` | Decrypted saved passwords |
| downloads | `-e downloads` | Download history |
| bookmarks | `-e bookmarks` | Saved bookmarks |
| autofill | `-e autofill` | Form autofill data |
| forms | `-e forms` | Form history |
| extensions | `-e extensions` | Installed extensions |
| permissions | `-e permissions` | Site permissions |
| search | `-e search` | Search queries |
| all | `-e all` | Everything (default) |

## Output Structure

### Default Location
`~/Downloads/<browser>_forensics_output/`

### Directory Structure
```
browser_forensics_output/
├── report.html              # Interactive HTML report
├── report.json              # Machine-readable data
├── summary.txt              # Executive summary
├── csv/                     # CSV files per category
│   ├── History_browsing_history.csv
│   ├── Cookies_all_cookies.csv
│   ├── Credentials_passwords.csv
│   └── ...
└── artifacts/               # Source database copies (if -c flag)
```

## Password Decryption

### Firefox
- Uses Mozilla NSS library
- Master password supported
- Works on Windows & Linux (native installation)

### Chromium (Chrome, Edge, Brave, etc.)
| Platform | Method | Requirements |
|----------|--------|--------------|
| Windows | DPAPI + AES-GCM | `pycryptodome` |
| Linux | PBKDF2 + AES-CBC | `pycryptodome`, `secretstorage` (optional) |
| macOS | Keychain + AES-CBC | `pycryptodome` |

## Troubleshooting

### No Browsers Detected
```bash
# Check browser paths manually
ls ~/.config/google-chrome/       # Chrome (Linux)
ls ~/.config/chromium/            # Chromium (Linux)
ls ~/.mozilla/firefox/            # Firefox (Linux)
```

### Database Locked
**Error:** `sqlite3.OperationalError: database is locked`

**Solution:** Close the browser before extraction

### Password Decryption Fails
```bash
# Run environment check
python main.py --check-env

# Install required packages
pip install pycryptodome
pip install secretstorage  # Linux with GNOME
```

### Missing pycryptodome
```bash
pip install pycryptodome>=3.19.0
```

## Security Notes

- **Sensitive Data**: Output contains cookies, passwords, browsing history
- **Decrypted Passwords**: Appear in plaintext in terminal and reports
- **Handle Carefully**: Treat all output as confidential evidence
- **Master Password**: Firefox master password required if set

### Decryption Support Matrix

| Environment | Firefox | Chromium |
|-------------|---------|----------|
| Windows | ✅ Full | ✅ Full |
| Linux (Native) | ✅ Full | ✅ Full |
| Linux (Snap) | ❌ Sandboxed | ❌ Sandboxed |
| Linux (Flatpak) | ❌ Sandboxed | ❌ Sandboxed |
| macOS | ❌ Not yet | ⚠️ Keychain |

## References

- Firefox Profile Data: https://support.mozilla.org/kb/profiles-where-firefox-stores-user-data
- Chromium User Data: https://chromium.googlesource.com/chromium/src/+/master/docs/user_data_dir.md
- SQLite Documentation: https://www.sqlite.org/

---

**Created:** December 2025
**Python Version:** 3.9+
**Version:** 2.0 (Multi-Browser Support)
**License:** MIT License - For authorized forensic use only
