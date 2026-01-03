# 🔍 Browser Forensics Extraction Tool

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](https://github.com)

A forensic tool for extracting browser artifacts (passwords, cookies, history, bookmarks) from Firefox, Chrome, Edge, Brave, Opera, and Vivaldi. Works on Windows and Linux with automatic dependency management.

---

## 🚀 Quick Start

```bash
python main.py
```
That's it. Dependencies auto-install on first run.

---

## 📋 What It Does

Extracts and decrypts browser data including:

| Data Type | Description |
|-----------|-------------|
| 🔑 **Passwords** | Saved login credentials (fully decrypted) |
| 🍪 **Cookies** | Session cookies with decrypted values |
| 🌐 **History** | Browsing history with timestamps |
| 📁 **Bookmarks** | Saved bookmarks hierarchy |
| 📥 **Downloads** | Download history |
| 📝 **Autofill** | Form autofill data |
| 🧩 **Extensions** | Installed browser extensions |

**Supported Browsers:** Firefox, Chrome, Edge, Brave, Opera, Vivaldi

---

## 🎯 Use Cases

### ✅ Authorized Uses

| Use Case | Description |
|----------|-------------|
| **Digital Forensics** | Law enforcement investigations with proper warrants |
| **Incident Response** | Security teams analyzing compromised systems |
| **Personal Recovery** | Recovering your own forgotten passwords |
| **Security Audits** | Penetration testing with written authorization |
| **IT Support** | Helping users migrate data with their consent |
| **Compliance Checks** | Auditing what sensitive data browsers store |

### ❌ Prohibited Uses

- Accessing other users' data without authorization
- Corporate espionage or competitive intelligence
- Stalking, harassment, or privacy violations
- Any illegal surveillance activities

---

## 📖 How to Use

### Interactive Mode (Recommended)
```bash
python main.py
```
Follow the prompts to select browser and profile.

### Command Line Options
```bash
# Extract passwords only
python main.py -e passwords

# Target specific browser
python main.py -b firefox -e passwords

# Extract multiple categories
python main.py -e history cookies bookmarks

# Non-interactive with custom output
python main.py -b chrome -e all -n -o ./output

# List detected browsers
python main.py --list-browsers
```

### Common Flags
| Flag | Description |
|------|-------------|
| `-b` | Browser: `firefox`, `chrome`, `edge`, `brave`, `opera`, `vivaldi` |
| `-e` | Extract: `passwords`, `cookies`, `history`, `bookmarks`, `all` |
| `-o` | Output directory |
| `-n` | Non-interactive mode |
| `--print-only` | Display only, no files |

---

## 📸 Demo

<details>
<summary><b>🖥️ Browser Selection</b></summary>

```
╔══════════════════════════════════════════════════════════════════════╗
║  BROWSER FORENSICS EXTRACTION TOOL                                   ║
║  Firefox │ Chrome │ Edge │ Brave │ Opera │ Vivaldi                   ║
╚══════════════════════════════════════════════════════════════════════╝

[*] System: Windows 11 (AMD64)
[*] Scanning for browsers...
[+] Found 4 browser(s) with 6 profile(s)

Available Profiles:
────────────────────────────────────────────────────────

  CHROME (Chromium)
    [1] Default (default)
    [2] Work Profile

  BRAVE (Chromium)
    [3] Personal (default)

  FIREFOX (Gecko)
    [4] default-release (default)

  [0] Exit

? Select profile [1]: 
```
</details>

<details>
<summary><b>🔑 Password Extraction</b></summary>

```
══════════════════════════════════════════════════════════════════════
[!] DECRYPTED PASSWORDS
══════════════════════════════════════════════════════════════════════

[1] https://github.com
    Username: testuser
    Password: ●●●●●●●●●●●● [O]
    Times Used: 15

[2] https://discord.com
    Username: testuser@gmail.com
    Password: ●●●●●●●●●●●● [O]
    Times Used: 42

══════════════════════════════════════════════════════════════════════
Total: 2 password(s) decrypted successfully
══════════════════════════════════════════════════════════════════════

[*] Saving reports...
  ✓ artifacts/password.json
  ✓ summary.txt
  ✓ report.html

Extraction Complete!
Output: ~/Downloads/firefox_2026-01-04_default-release/
```
</details>

<details>
<summary><b>📊 HTML Report</b></summary>

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Browser Forensics Report                              [Print Report]   │
│  Firefox Profile Analysis                                               │
│  Generated: 2026-01-04 19:10:36 UTC                                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐       │
│   │     2      │  │    499     │  │     47     │  │     13     │       │
│   │ CREDENTIALS│  │  COOKIES   │  │  HISTORY   │  │ BOOKMARKS  │       │
│   └────────────┘  └────────────┘  └────────────┘  └────────────┘       │
│                                                                         │
│   Decryption: SUCCESS          Access Mode: Read-Only                   │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│  ▸ Saved Credentials         [HIGH VALUE]           2 records          │
│  ▸ Browsing History                                47 records          │
│  ▸ Cookies                                        499 records          │
│  ▸ Bookmarks                                       13 records          │
│  ▸ Form Autofill                                    6 records          │
└─────────────────────────────────────────────────────────────────────────┘
```
</details>

---

## 🔧 Installation

### Automatic (Recommended)
```bash
git clone https://github.com/yourusername/Browser-Key-Extraction.git
cd Browser-Key-Extraction
python main.py  # Auto-installs dependencies
```

### Linux System Dependencies
```bash
# Debian/Ubuntu
sudo apt install libnss3 libsecret-1-0

# Arch
sudo pacman -S nss libsecret

# Fedora
sudo dnf install nss libsecret
```

### Windows Requirements
- Python 3.9+
- Firefox installed (for Firefox decryption)
- Run as Administrator (for Chrome 127+ v20 passwords)

---

## 📤 Output

```
output_folder/
├── report.html       # Interactive searchable report
├── summary.txt       # Executive summary with SHA256 hashes
└── artifacts/        # Raw JSON data
    ├── password.json
    ├── cookie.json
    ├── history.json
    └── ...
```

---

## ⚠️ Disclaimer

> **For personal and authorized use only.** Don't use this on someone else's system without their permission. The authors are not responsible for misuse.

---

## 📚 Technical Documentation

For in-depth technical details, see [`docs/`](docs/):
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — Data flow, module responsibilities
- [DECRYPTION.md](docs/DECRYPTION.md) — Firefox & Chromium encryption model
- [CLI.md](docs/CLI.md) — CLI flags, examples, scripting

---

## 🤝 Contributing

Contributions welcome:
- macOS Keychain support
- Additional browsers (Safari, etc.)
- Bug fixes and optimizations

---

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

<p align="center">
  <b>⚡ Quick Start:</b> <code>python main.py</code><br>
  <b>📚 Docs:</b> <a href="docs/CLI.md">CLI Reference</a> · <a href="docs/DECRYPTION.md">Decryption</a> · <a href="docs/ARCHITECTURE.md">Architecture</a><br>
  <b>⭐ Star this repo if useful!</b>
</p>
