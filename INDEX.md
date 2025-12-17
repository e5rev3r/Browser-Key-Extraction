# Browser Forensics Extraction Tool - Documentation Index

## Quick Start
- **[README.md](README.md)** - Full documentation and usage
- **[SETUP.md](SETUP.md)** - Installation and quick start
- **[FIREFOX_FORENSICS.md](FIREFOX_FORENSICS.md)** - Firefox artifact reference
- **[CHROMIUM_FORENSICS.md](CHROMIUM_FORENSICS.md)** - Chromium artifact reference

## Supported Browsers

| Browser | Engine | Windows | Linux | macOS |
|---------|--------|---------|-------|-------|
| Firefox | Gecko | ✅ | ✅ | ✅ |
| Chrome | Chromium | ✅ | ✅ | ✅ |
| Edge | Chromium | ✅ | ✅ | ✅ |
| Brave | Chromium | ✅ | ✅ | ✅ |
| Opera | Chromium | ✅ | ✅ | ✅ |
| Vivaldi | Chromium | ✅ | ✅ | ✅ |

## Source Files

### Core Modules
- **[main.py](main.py)** - CLI entry point with multi-browser support
- **[browser_profiles.py](browser_profiles.py)** - Browser detection and profile discovery
- **[utils.py](utils.py)** - Utility functions
- **[formatters.py](formatters.py)** - Report generation (HTML/CSV/MD)

### Firefox Modules
- **[extractor.py](extractor.py)** - Firefox database extraction
- **[queries.py](queries.py)** - Firefox forensic SQL queries
- **[nss_decrypt.py](nss_decrypt.py)** - Firefox password decryption via NSS

### Chromium Modules
- **[chromium_extractor.py](chromium_extractor.py)** - Chromium database/JSON extraction
- **[chromium_queries.py](chromium_queries.py)** - Chromium forensic SQL queries
- **[chromium_decrypt.py](chromium_decrypt.py)** - Chromium password decryption

## Quick Usage

```bash
# Auto-detect all browsers (interactive)
python main.py

# List detected browsers
python main.py --list-browsers

# Extract from specific browser
python main.py -b chrome
python main.py -b firefox
python main.py -b brave

# Selective extraction
python main.py -e history
python main.py -e history cookies bookmarks
python main.py -e passwords

# Terminal-only output
python main.py -e history --print-only

# Skip password decryption
python main.py --no-passwords

# Check environment
python main.py --check-env
```

## CLI Flags

| Flag | Description |
|------|-------------|
| `-b, --browser` | Browser: firefox, chrome, edge, brave, opera, vivaldi, auto |
| `-e, --extract` | Categories: history, cookies, passwords, downloads, bookmarks, autofill, extensions, forms, permissions, search, all |
| `--list-browsers` | List all detected browsers |
| `--print-only` | Print to terminal only |
| `--no-passwords` | Skip password decryption |
| `-o, --output` | Output directory |
| `-n, --no-interactive` | Non-interactive mode |
| `-v, --verbose` | Debug logging |
| `--check-env` | Check decryption support |

## Data Categories

| Category | Firefox | Chromium | Flag |
|----------|---------|----------|------|
| Browsing History | ✅ | ✅ | `-e history` |
| Cookies | ✅ | ✅ | `-e cookies` |
| Passwords | ✅ | ✅ | `-e passwords` |
| Downloads | ✅ | ✅ | `-e downloads` |
| Bookmarks | ✅ | ✅ | `-e bookmarks` |
| Autofill | ✅ | ✅ | `-e autofill` |
| Form History | ✅ | ✅ | `-e forms` |
| Extensions | ✅ | ✅ | `-e extensions` |
| Permissions | ✅ | ✅ | `-e permissions` |
| Search History | ✅ | ✅ | `-e search` |

## Output Structure

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
└── artifacts/               # Source database copies
```

## Password Decryption Support

| Platform | Firefox | Chromium |
|----------|---------|----------|
| Windows | ✅ NSS | ✅ DPAPI+AES |
| Linux (Native) | ✅ libnss3 | ✅ PBKDF2+AES |
| Linux (Snap) | ❌ | ❌ |
| macOS | ❌ | ⚠️ Keychain |

```bash
# Check decryption support
python main.py --check-env
```

## Dependencies

**Required:**
```
pycryptodome>=3.19.0    # Chromium AES decryption
```

**Optional:**
```
secretstorage           # Linux GNOME keyring (Chromium)
```

**Install:**
```bash
pip install -r requirements.txt
```

## Common Tasks

```bash
# Quick history view
python main.py -e history --print-only

# Export all data from Chrome
python main.py -b chrome -o ./chrome_forensics

# Extract passwords only
python main.py -e passwords

# Export cookies as CSV
python main.py -e cookies -b firefox
```

## Programmatic Usage

```python
# Firefox extraction
from extractor import FirefoxDatabaseExtractor
from pathlib import Path

profile = Path.home() / ".mozilla/firefox/profile.default"
extractor = FirefoxDatabaseExtractor(profile)
for db in extractor.find_databases():
    print(db.name)

# Chromium extraction
from chromium_extractor import ChromiumDatabaseExtractor
from browser_profiles import detect_all_browsers

browsers = detect_all_browsers()
chrome_profile = [b for b in browsers if b.browser_type.value == 'chrome'][0]
extractor = ChromiumDatabaseExtractor(Path(chrome_profile.profile_path))
```

---

**Version 2.0** | Python 3.9+ | Multi-Browser Support | HTML/CSV/Markdown Output
