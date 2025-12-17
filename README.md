# 🔍 Browser Forensics Extraction Tool

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Extract and analyze forensic artifacts from web browsers - Firefox, Chrome, Edge, Brave, Opera, and Vivaldi.

## 🚀 Quick Start

```bash
# Clone and run
git clone https://github.com/yourusername/browser-forensics.git
cd browser-forensics
pip install -r requirements.txt
python main.py
```

## ✨ Features

- 🌐 **Multi-Browser Support** - Firefox, Chrome, Edge, Brave, Opera, Vivaldi
- 🔎 **50+ Forensic Queries** - History, cookies, forms, permissions across databases
- 🔓 **Password Decryption** - Decrypt saved passwords (NSS for Firefox, AES for Chromium)
- 📊 **Multi-Format Reports** - HTML, Markdown, and CSV exports
- 🎯 **Selective Extraction** - Extract only what you need (history, cookies, passwords, etc.)
- 🖥️ **Terminal Output** - Print data directly to terminal with `--print-only`
- 🔐 **Credential Detection** - Auto-highlights passwords and auth tokens
- 💬 **Interactive Mode** - Friendly prompts guide you through extraction
- 🔍 **Auto-Detection** - Automatically finds installed browsers and profiles
- ⏱️ **Human Timestamps** - Converts browser timestamps to readable dates

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

# Extract and print to terminal only (no files)
python main.py -e history --print-only

# Extract passwords only
python main.py -e passwords

# Extract everything except passwords
python main.py --no-passwords
```

### Advanced Options

```bash
# Filter by browser and extract specific data
python main.py -b chrome -e history cookies --print-only

# Non-interactive extraction
python main.py -b firefox -e all -n -o ./output

# Custom output directory
python main.py --output ~/forensics_output

# Copy source database files
python main.py --copy-artifacts

# Show all available queries
python main.py --list-queries

# Check environment compatibility
python main.py --check-env
```

## 🔧 CLI Reference

| Flag | Description |
|------|-------------|
| `-b, --browser` | Browser to extract from: `firefox`, `chrome`, `chromium`, `edge`, `brave`, `opera`, `vivaldi`, `auto` |
| `-e, --extract` | Categories to extract: `history`, `cookies`, `passwords`, `downloads`, `bookmarks`, `autofill`, `extensions`, `forms`, `permissions`, `search`, `all` |
| `--list-browsers` | List all detected browsers and profiles |
| `--print-only` | Print data to terminal only (no file output) |
| `--no-passwords` | Skip password decryption |
| `-o, --output` | Output directory path |
| `-n, --no-interactive` | Disable interactive prompts |
| `-c, --copy-artifacts` | Copy source database files as read-only artifacts |
| `--list-queries` | Show all available forensic queries |
| `--check-env` | Check environment for password decryption support |
| `-v, --verbose` | Enable debug logging |
| `-q, --quiet` | Suppress non-critical output |

## 📁 Output Structure

Default location: `~/Downloads/<browser>_forensics_output/`

```
browser_forensics_output/
├── report.html              # Interactive HTML report
├── report.json              # Machine-readable JSON data
├── summary.txt              # Executive summary
├── csv/                     # CSV files per category
│   ├── History_browsing_history.csv
│   ├── Cookies_all_cookies.csv
│   ├── Credentials_passwords.csv
│   └── ...
└── artifacts/               # Source database copies (if --copy-artifacts)
```

## 🔍 Supported Data Categories

| Category | Firefox | Chromium | Description |
|----------|---------|----------|-------------|
| `history` | ✅ | ✅ | Browsing history with timestamps |
| `cookies` | ✅ | ✅ | HTTP cookies, auth tokens |
| `passwords` | ✅ | ✅ | Decrypted saved passwords |
| `downloads` | ✅ | ✅ | Download history |
| `bookmarks` | ✅ | ✅ | Saved bookmarks |
| `autofill` | ✅ | ✅ | Form autofill data |
| `forms` | ✅ | ✅ | Form history |
| `extensions` | ✅ | ✅ | Installed browser extensions |
| `permissions` | ✅ | ✅ | Site permissions (camera, location, etc.) |
| `search` | ✅ | ✅ | Search engine queries |

## 🔓 Password Decryption

### Firefox
- Uses Mozilla NSS library
- Supports master password
- Works on Windows & Linux (native installation)

### Chromium-based (Chrome, Edge, Brave, etc.)
- **Windows**: DPAPI + AES-GCM decryption
- **Linux**: PBKDF2 + AES-CBC (requires `secretstorage` for GNOME Keyring)
- **macOS**: Keychain access (requires `secretstorage`)

```bash
# Check decryption support
python main.py --check-env
```

## 🏗️ Architecture

| Module | Purpose |
|--------|---------|
| `main.py` | CLI entry point, multi-browser orchestration |
| `browser_profiles.py` | Browser detection and profile discovery |
| `chromium_extractor.py` | Chromium database/JSON extraction |
| `chromium_queries.py` | Chromium forensic SQL queries |
| `chromium_decrypt.py` | Chromium password decryption |
| `extractor.py` | Firefox database extraction |
| `queries.py` | Firefox forensic SQL queries |
| `nss_decrypt.py` | Firefox NSS password decryption |
| `formatters.py` | Report generation (HTML/CSV/MD) |
| `utils.py` | Utility functions |

## 💡 Use Cases

- **Digital Forensics** - Extract evidence from suspect profiles
- **Incident Response** - Timeline reconstruction and threat analysis
- **Privacy Audits** - Review site permissions and stored data
- **Security Research** - Analyze browser behavior and data storage
- **Penetration Testing** - Credential extraction from compromised systems
- **Data Recovery** - Retrieve browsing data and saved passwords

## ⚠️ Important Notes

### Password Decryption Support

| Platform | Firefox | Chromium |
|----------|---------|----------|
| Windows | ✅ Full | ✅ Full (DPAPI) |
| Linux (Native) | ✅ Full | ✅ Full (PBKDF2) |
| Linux (Snap/Flatpak) | ❌ Sandboxed | ❌ Sandboxed |
| macOS | ❌ Not yet | ⚠️ Keychain required |

### General Limitations
- Close browsers before extraction to avoid database locks
- Only recoverable data is extracted (no deleted entry recovery)

### Security Warning
- Output may contain **plaintext passwords**, cookies, and sensitive data
- Treat all extracted data as confidential evidence
- Store securely and follow data protection policies

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| No browsers detected | Check browser installation paths |
| Database locked | Close the browser before running |
| Password decryption fails | Run `python main.py --check-env` |
| Missing `pycryptodome` | Run `pip install pycryptodome` |
| Missing `secretstorage` | Run `pip install secretstorage` (Linux GNOME) |
| libnss3 missing (Firefox) | Install: `sudo apt install libnss3` |

## 📚 Documentation

- **[SETUP.md](SETUP.md)** - Installation and setup guide
- **[FIREFOX_FORENSICS.md](FIREFOX_FORENSICS.md)** - Firefox artifact reference
- **[CHROMIUM_FORENSICS.md](CHROMIUM_FORENSICS.md)** - Chromium artifact reference
- **[INDEX.md](INDEX.md)** - Documentation index

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

**Version 2.0** | Python 3.9+ | Firefox & Chromium Support 🔬
