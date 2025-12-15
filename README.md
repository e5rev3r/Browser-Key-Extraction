# 🔍 Firefox Forensics Tool

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![No Dependencies](https://img.shields.io/badge/dependencies-none-green.svg)]()

Extract and analyze forensic artifacts from Firefox profiles - browsing history, cookies, credentials, bookmarks, and more.

## 🚀 Quick Start

```bash
# Clone and run
git clone https://github.com/yourusername/firefox-forensics.git
cd firefox-forensics
python main.py ~/.mozilla/firefox/xxxx.default-release
```

No dependencies needed - uses Python stdlib only!

## ✨ Features

- 🔎 **30+ Forensic Queries** - History, cookies, forms, permissions across 6 databases
- 🔓 **Password Decryption** - Decrypt saved passwords using NSS library (Windows & Linux)
- 📊 **Multi-Format Reports** - HTML, Markdown, and CSV exports
- 🔐 **Credential Detection** - Auto-highlights passwords and auth tokens
- 💬 **Interactive Mode** - Friendly prompts guide you through extraction
- ⏱️ **Human Timestamps** - Converts Unix time to readable dates
- 🛡️ **Environment Validation** - Detects Snap/Flatpak/keyring limitations
- 🎯 **Zero Dependencies** - Pure Python stdlib (uses Firefox's bundled NSS)

## 📖 Usage

**Interactive (recommended):**
```bash
python main.py ~/.mozilla/firefox/xxxx.default-release
```

**Non-interactive:**
```bash
python main.py ~/.mozilla/firefox/profile --output my_results --format all --no-interactive
```

**Other options:**
```bash
python main.py --list-queries   # Show all available queries
python main.py --check-env      # Check password decryption compatibility
python main.py profile --format html --verbose  # HTML only with debug logs
```

💡 **Tip:** Enter `0` to exit when prompted for directory

## 📁 Output

Default location: `~/Downloads/firefox_forensics_output/` (Linux) or `Downloads\firefox_forensics_output` (Windows)

```
output/
├── forensics_report.html    # Styled web report with decrypted passwords
├── forensics_report.md      # Markdown tables
├── master_report.md         # Comprehensive summary
├── csv_export/              # 19 CSV files
│   ├── CREDENTIALS.csv      # Decrypted passwords!
│   ├── browsing_history.csv
│   ├── all_cookies.csv
│   └── ...
└── artifacts/               # 13 JSON files (extensions, logins, etc.)
```

All timestamps converted to `YYYY-MM-DD HH:MM:SS` format. Credentials and decrypted passwords automatically highlighted.

## 🔍 What Gets Extracted

**30+ forensic queries across:**
- 🌐 **Browsing History** - URLs, titles, timestamps, visit types
- 🔖 **Bookmarks** - All saved bookmarks with dates
- 🍪 **Cookies** - Including auth tokens and sessions
- 📝 **Form History** - Searches, emails, sensitive fields
- 🔐 **Permissions** - Geolocation, camera, microphone grants
- 💾 **DOM Storage** - localStorage and sessionStorage
- 🖼️ **Favicons** - Site icons and mappings
- 🧩 **Extensions** - Installed addons metadata
- 🔑 **Saved Passwords** - Decrypted logins via NSS (Windows & Linux)

### 🔓 Password Decryption

The tool can decrypt saved Firefox passwords on supported systems:

```bash
# Check if your environment supports decryption
python main.py --check-env

# Extract with password decryption
python main.py  # Interactive profile selection
```

**Windows Requirements:**
- Firefox must be installed (uses bundled nss3.dll)
- Profile at `%APPDATA%\Mozilla\Firefox\Profiles\`

**Linux Requirements:**
- Native Firefox installation (not Snap/Flatpak)
- `libnss3` system library installed
- No OS keyring integration (GNOME Keyring/KWallet)

**Master Password:** If set, the tool will prompt for it interactively.

## 🏗️ Architecture

| Module | Lines | Purpose |
|--------|-------|---------|
| `main.py` | 861 | CLI and interactive prompts |
| `nss_decrypt.py` | 1076 | NSS password decryption |
| `formatters.py` | 951 | HTML/MD/CSV report generation |
| `queries.py` | 663 | 30+ forensic SQL queries |
| `extractor.py` | 388 | Database/JSON extraction |
| `utils.py` | 312 | Helper functions |

**Total:** ~4,200 lines of clean, modular Python code

## 💡 Use Cases

- **Digital Forensics** - Extract evidence from suspect profiles
- **Incident Response** - Timeline reconstruction and threat analysis
- **Privacy Audits** - Review site permissions and stored data
- **Security Research** - Analyze browser behavior and data storage
- **Data Recovery** - Retrieve deleted or lost browsing data

## ⚠️ Important Notes

**Password Decryption Support:**
- ✅ **Windows** - Fully supported (Firefox must be installed)
- ✅ **Native Linux Firefox** - Fully supported with libnss3
- ❌ **Snap Firefox** - Sandboxed, uses bundled NSS library
- ❌ **Flatpak Firefox** - Sandboxed, uses bundled NSS library  
- ❌ **OS Keyring** - GNOME Keyring/KWallet integration not supported
- ❌ **macOS** - Not yet supported

**General Limitations:**
- Close Firefox before extraction to avoid database locks
- Only recoverable data is extracted (no deleted entry recovery)

**Security:**
- Output may contain **plaintext passwords**, cookies, and sensitive data
- Treat all extracted data as confidential evidence
- Store securely and follow data protection policies

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| Profile not found | Check path: Linux `~/.mozilla/firefox/`, macOS `~/Library/Application Support/Firefox/Profiles/`, Windows `%APPDATA%\Mozilla\Firefox\Profiles\` |
| Database locked | Close Firefox before running |
| Permission denied | Run `chmod -R u+r ~/.mozilla/firefox/profile/` |
| No query results | Database may be empty or corrupted |
| Password decryption fails | Run `python main.py --check-env` to diagnose |
| Snap/Flatpak detected | Use Firefox's built-in export: Settings → Passwords → Export |
| Master password prompt | Enter your Firefox master password when prompted |
| libnss3 missing | Install: `sudo apt install libnss3` or `sudo pacman -S nss` |

## 🤝 Contributing

PRs welcome! Add new queries to `queries.py` or improve formatters in `formatters.py`.

## 📊 Stats

- **Code:** ~4,200 lines across 6 modules
- **Queries:** 30+ forensic SQL queries
- **Formats:** HTML, Markdown, CSV
- **Features:** Password decryption, environment validation
- **Dependencies:** 0 (stdlib only, libnss3 for decryption)

## 📄 License

MIT License - see [LICENSE](LICENSE)

## 📚 Documentation

- **[SETUP.md](SETUP.md)** - Installation and quick start
- **[FIREFOX_FORENSICS.md](FIREFOX_FORENSICS.md)** - Deep dive into Firefox artifacts
- **[INDEX.md](INDEX.md)** - Complete documentation index

---

**Version 1.0** | Python 3.9+ | Made for forensics professionals 🔬
