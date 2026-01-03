# CLI Reference

## Basic Usage

```bash
python main.py [OPTIONS] [PROFILE_PATH]
```

---

## Arguments

| Argument | Description |
|----------|-------------|
| `PROFILE_PATH` | Direct path to browser profile (optional) |

---

## Options

### Browser Selection

| Flag | Description |
|------|-------------|
| `-b, --browser` | Target specific browser |

**Values:** `firefox`, `chrome`, `edge`, `brave`, `opera`, `vivaldi`, `all`

```bash
python main.py -b chrome
python main.py -b firefox
python main.py -b all
```

### Data Extraction

| Flag | Description |
|------|-------------|
| `-e, --extract` | Data types to extract |

**Values:** `passwords`, `history`, `cookies`, `bookmarks`, `downloads`, `all`

```bash
python main.py -e passwords
python main.py -e history cookies bookmarks
python main.py -e all
```

### Output Control

| Flag | Description |
|------|-------------|
| `-o, --output` | Output directory |
| `-f, --format` | Output format |
| `--no-console` | Suppress console output |

**Format values:** `json`, `html`, `text`, `all`

```bash
python main.py -o ./results -f json
python main.py -f html
python main.py -f all --no-console
```

### Profile Selection

| Flag | Description |
|------|-------------|
| `-p, --profile` | Select specific profile |
| `-l, --list` | List available profiles |

```bash
python main.py -l
python main.py -p "Profile 1"
python main.py -p Default
```

### Other Options

| Flag | Description |
|------|-------------|
| `-v, --verbose` | Enable verbose output |
| `--check-env` | Check environment setup |
| `-h, --help` | Show help message |

---

## Examples

### Extract All Data from All Browsers

```bash
python main.py -b all -e all
```

### Chrome Passwords Only

```bash
python main.py -b chrome -e passwords
```

### Firefox History to JSON

```bash
python main.py -b firefox -e history -f json -o ./output
```

### Specific Profile Path

```bash
# Windows
python main.py "C:\Users\John\AppData\Local\Google\Chrome\User Data\Default" -e all

# Linux
python main.py ~/.config/google-chrome/Default -e all
```

### List All Detected Profiles

```bash
python main.py -l
```

### Generate HTML Report

```bash
python main.py -b all -e all -f html -o ./report
```

### Silent JSON Export

```bash
python main.py -b chrome -e passwords -f json --no-console -o ./export
```

### Debug Mode

```bash
python main.py -v -b chrome -e passwords
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | No browsers detected |
| 2 | Extraction error |
| 3 | Permission denied |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PYTHONIOENCODING` | Set to `utf-8` for Unicode support |

```bash
# Windows
set PYTHONIOENCODING=utf-8
python main.py

# Linux
PYTHONIOENCODING=utf-8 python main.py
```

---

## Scripting

### PowerShell

```powershell
# Extract and process
$result = python main.py -b chrome -e passwords -f json --no-console -o ./temp
$data = Get-Content ./temp/chrome_passwords.json | ConvertFrom-Json
$data.passwords | Where-Object { $_.url -like "*github*" }
```

### Bash

```bash
# Extract and filter
python main.py -b chrome -e passwords -f json --no-console -o ./temp
jq '.passwords[] | select(.url | contains("github"))' ./temp/chrome_passwords.json
```

### Python

```python
import subprocess
import json

subprocess.run(["python", "main.py", "-b", "chrome", "-e", "passwords", 
                "-f", "json", "--no-console", "-o", "./temp"])

with open("./temp/chrome_passwords.json") as f:
    data = json.load(f)
    for entry in data["passwords"]:
        print(f"{entry['url']}: {entry['username']}")
```

---

## Combining Options

```bash
# Full extraction with all outputs
python main.py -b all -e all -f all -o ./full_report -v

# Multiple browsers, specific data
python main.py -b chrome -b firefox -e passwords history

# Quick password check
python main.py -b chrome -e passwords -v
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No browsers detected | Specify path: `python main.py /path/to/profile` |
| libnss3 not found | `sudo apt install libnss3` |
| Database locked | Close the browser |
| Decryption failed | Install `secretstorage`, check keyring |
| v20 PROTECTED | Run as Admin + `pip install PythonForWindows` |

**Debug:**
```bash
python main.py -v              # Verbose output
python main.py --check-env     # Check dependencies
```

---

## Dependencies

| Package | Purpose | Platform |
|---------|---------|----------|
| pycryptodome | AES decryption | All |
| secretstorage | GNOME Keyring | Linux |
| PythonForWindows | v20 decryption | Windows (optional) |

**System:**
- `libnss3` - Firefox (Linux)
- `libsecret` - Keyring (Linux)
