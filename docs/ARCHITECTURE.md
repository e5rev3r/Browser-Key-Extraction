# Architecture

## Project Structure

```
Browser-Key-Extraction/
├── main.py              # Entry point, CLI, orchestration
├── browser_profiles.py  # Browser detection, profile paths
├── extractors.py        # Data extraction (history, cookies, bookmarks, downloads)
├── sql_queries.py       # SQL queries for Firefox/Chromium databases
├── chromium_decrypt.py  # Chromium password decryption (v10/v11/v20)
├── nss_decrypt.py       # Firefox password decryption (NSS/PK11)
├── html_report.py       # HTML report generation
└── docs/
    ├── ARCHITECTURE.md  # This file
    ├── DECRYPTION.md    # Encryption details
    └── CLI.md           # Command reference
```

## Module Responsibilities

| Module | Purpose |
|--------|---------|
| `main.py` | CLI parsing, browser selection, output coordination |
| `browser_profiles.py` | Detect installed browsers, locate profile directories |
| `extractors.py` | Query databases for history, cookies, bookmarks, downloads |
| `sql_queries.py` | SQL query definitions for both browser engines |
| `chromium_decrypt.py` | Handle v10 (DPAPI), v11 (Keyring), v20 (App-Bound) |
| `nss_decrypt.py` | Load NSS library, decrypt Firefox passwords |
| `html_report.py` | Generate styled HTML reports |

## Data Flow

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   main.py   │────▶│ browser_profiles │────▶│ Profile paths   │
│   (CLI)     │     │    .py           │     │ detected        │
└─────────────┘     └──────────────────┘     └────────┬────────┘
                                                      │
                    ┌─────────────────────────────────┘
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                      extractors.py                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐│
│  │ History  │  │ Cookies  │  │Bookmarks │  │    Downloads     ││
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Password Extraction                          │
│  ┌─────────────────────────┐  ┌───────────────────────────────┐│
│  │   nss_decrypt.py        │  │   chromium_decrypt.py         ││
│  │   (Firefox)             │  │   (Chrome/Edge/Brave/etc)     ││
│  └─────────────────────────┘  └───────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Output                                   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐│
│  │ Console  │  │   JSON   │  │   HTML   │  │      Text        ││
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Browser Support

### Supported Browsers

| Browser | Engine | Windows | Linux |
|---------|--------|---------|-------|
| Firefox | Gecko | ✅ | ✅ |
| Chrome | Chromium | ✅ | ✅ |
| Edge | Chromium | ✅ | ✅ |
| Brave | Chromium | ✅ | ✅ |
| Opera | Chromium | ✅ | ✅ |
| Vivaldi | Chromium | ✅ | ✅ |

### Profile Paths

**Windows:**
```
Firefox:  %APPDATA%\Mozilla\Firefox\Profiles\
Chrome:   %LOCALAPPDATA%\Google\Chrome\User Data\
Edge:     %LOCALAPPDATA%\Microsoft\Edge\User Data\
Brave:    %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\
Opera:    %APPDATA%\Opera Software\Opera Stable\
Vivaldi:  %LOCALAPPDATA%\Vivaldi\User Data\
```

**Linux:**
```
Firefox:  ~/.mozilla/firefox/
Chrome:   ~/.config/google-chrome/
Edge:     ~/.config/microsoft-edge/
Brave:    ~/.config/BraveSoftware/Brave-Browser/
Opera:    ~/.config/opera/
Vivaldi:  ~/.config/vivaldi/
```

## Database Files

### Firefox (SQLite)

| File | Content |
|------|---------|
| `places.sqlite` | History, bookmarks |
| `cookies.sqlite` | Cookies |
| `logins.json` | Encrypted passwords |
| `key4.db` | Encryption keys |

### Chromium (SQLite)

| File | Content |
|------|---------|
| `History` | Browsing history |
| `Cookies` | Cookies |
| `Bookmarks` | Bookmarks (JSON) |
| `Login Data` | Encrypted passwords |
| `Local State` | Encryption keys |

## Output Formats

### JSON Schema (Passwords)

```json
{
  "browser": "chrome",
  "profile": "Default",
  "extracted_at": "2025-01-04T12:00:00",
  "passwords": [
    {
      "url": "https://example.com",
      "username": "user@example.com",
      "password": "decrypted_password",
      "created": "2024-06-15T10:30:00",
      "modified": "2024-12-01T14:20:00"
    }
  ]
}
```

### HTML Report

- Tabbed interface per data type
- Searchable/sortable tables
- Dark mode support
- Expandable password fields

## Database Queries

### Firefox
```sql
-- History (places.sqlite)
SELECT url, title, visit_count, last_visit_date FROM moz_places;

-- Cookies (cookies.sqlite)
SELECT host, name, value, path, expiry FROM moz_cookies;

-- Passwords: logins.json (decrypted via NSS)
```

### Chromium
```sql
-- History
SELECT url, title, visit_count, last_visit_time FROM urls;

-- Cookies (encrypted)
SELECT host_key, name, encrypted_value, path, expires_utc FROM cookies;

-- Passwords (encrypted)
SELECT origin_url, username_value, password_value, times_used FROM logins;
```

### Timestamps
- **Chromium:** `(webkit_time / 1000000) - 11644473600` → Unix
- **Firefox:** `firefox_time / 1000000` → Unix
