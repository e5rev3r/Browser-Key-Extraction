# 🔍 Browser Forensics Extraction Tool

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Extract and analyze forensic artifacts from web browsers - Firefox, Chrome, Edge, Brave, Opera, and Vivaldi.

## 🚀 Quick Start

```bash
# Just run it! Dependencies auto-install on first run
python main.py
```

That's it! The tool automatically checks and installs required dependencies.

## ✨ Features

- 🌐 **Multi-Browser Support** - Firefox, Chrome, Edge, Brave, Opera, Vivaldi
- � **Cross-Platform** - Windows and Linux support
- 🔎 **Forensic Queries** - History, cookies, forms, permissions, bookmarks
- 🔓 **Password Decryption** - NSS for Firefox, DPAPI/AES for Chromium
- 🍪 **Cookie Decryption** - Full v10/v11/v20 cookie decryption
- 📊 **JSON Reports** - Export data to JSON format with HTML report
- 🎯 **Selective Extraction** - Extract only what you need
- 🖥️ **Terminal Output** - Print data directly with `--print-only`
- 💬 **Interactive Mode** - Friendly prompts guide you through extraction
- 🔍 **Auto-Detection** - Automatically finds browsers and profiles

## 📖 Usage

### Basic Usage

```bash
# Auto-detect all browsers (interactive)
python main.py

# List all detected browsers
python main.py --list-browsers

# Extract from specific browser
python main.py -b firefox
python main.py -b chrome
python main.py -b brave
```

### Selective Extraction

```bash
# Extract only history
python main.py -e history

# Extract multiple categories
python main.py -e history cookies bookmarks

# Print to terminal only (no files)
python main.py -e history --print-only

# Extract passwords only
python main.py -e passwords

# Skip password decryption
python main.py --no-passwords
```

### Advanced Options

```bash
# Non-interactive extraction
python main.py -b firefox -e all -n -o ./output

# Custom output directory
python main.py --output ~/forensics_output

# Check environment compatibility
python main.py --check-env
```

## 🔧 CLI Reference

| Flag | Description |
|------|-------------|
| `-b, --browser` | Browser: `firefox`, `chrome`, `chromium`, `edge`, `brave`, `opera`, `vivaldi`, `auto` |
| `-e, --extract` | Categories: `history`, `cookies`, `passwords`, `downloads`, `bookmarks`, `autofill`, `extensions`, `all` |
| `--list-browsers` | List detected browsers and profiles |
| `--print-only` | Print to terminal only (no files) |
| `--no-passwords` | Skip password decryption |
| `-o, --output` | Output directory path |
| `-n, --no-interactive` | Disable interactive prompts |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Quiet output |
| `--check-env` | Check environment compatibility |

## 📁 Project Structure

```
Browser-Key-Extraction/
├── main.py              # Main entry point (auto-installs deps)
├── browser_profiles.py  # Browser detection & profiles
├── extractors.py        # Database extraction classes
├── sql_queries.py       # Firefox & Chromium SQL queries
├── nss_decrypt.py       # Firefox password decryption (NSS)
├── chromium_decrypt.py  # Chromium password decryption (DPAPI/AES)
├── html_report.py       # HTML report generation
└── README.md            # This file
```

## 📤 Output Format

The tool generates output in the following structure:
```
output_folder/
├── report.html          # Interactive HTML report
├── summary.txt          # Quick text summary
└── artifacts/           # JSON data files
    ├── history.json
    ├── cookie.json
    ├── password.json
    ├── autofill.json
    ├── bookmark.json
    └── download.json
```

## 🔒 Password Decryption

### Automatic Setup
Dependencies (`pycryptodome`) are **automatically installed** when you run `main.py`.

### Firefox Requirements
- **Linux**: `libnss3` system library (install: `sudo apt install libnss3` or `sudo pacman -S nss`)
- **Windows**: Firefox must be installed (uses bundled NSS DLLs)

### Chromium Requirements (Windows)
- **v10 encryption** (Chrome < 127): Automatic DPAPI decryption
- **v20 encryption** (Chrome 127+): Requires **Administrator privileges**
  - Install `PythonForWindows` for full support: `pip install PythonForWindows`
  - Run as Admin to decrypt v20 passwords and cookies

### Chromium Requirements (Linux)
- **v11 encryption**: Automatic AES-128-CBC decryption
- Uses GNOME Keyring/libsecret if available, or hardcoded "peanuts" password
- Optional: `pip install secretstorage` for keyring support

### ⚠️ Chrome 127+ App-Bound Encryption (v20) - Windows Only

Starting with Chrome 127 (July 2024), Chrome, Edge, Brave, and other Chromium browsers use **App-Bound Encryption** for saved passwords. This security feature binds password decryption to the browser's code-signing certificate.

**Affected browsers**: Chrome 127+, Edge, Brave, Opera, Vivaldi (recent versions)

**What this means**: 
- Passwords encrypted with v20 cannot be decrypted by external tools
- The tool will show: `[v20 PROTECTED - Use browser export]`

**Workaround**: Export passwords directly from the browser:
1. Open browser Settings
2. Go to **Passwords** (or **Autofill > Password Manager**)
3. Click **Export Passwords** (⋮ menu)
4. Save the CSV file

Older passwords using v10 encryption can still be decrypted normally.

## 📊 Extracted Data

| Category | Firefox | Chromium |
|----------|---------|----------|
| Browsing History | ✅ | ✅ |
| Cookies | ✅ | ✅ |
| Bookmarks | ✅ | ✅ |
| Downloads | ✅ | ✅ |
| Saved Passwords | ✅ | ✅ |
| Form Autofill | ✅ | ✅ |
| Extensions | ✅ | ✅ |
| Site Permissions | ✅ | - |

## ⚠️ Legal Disclaimer

This tool is intended for:
- Forensic investigations with proper authorization
- Security audits of your own systems
- Educational purposes

**Do not use this tool on systems you do not own or have explicit permission to analyze.**

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.
