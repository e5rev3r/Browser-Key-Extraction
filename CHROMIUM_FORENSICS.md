# Chromium Browser Forensics Reference

## Overview

This document covers forensic artifacts in Chromium-based browsers:
- **Google Chrome**
- **Microsoft Edge**
- **Brave Browser**
- **Opera**
- **Vivaldi**

All Chromium browsers use similar database structures and file formats, making cross-browser forensic analysis consistent.

## Profile Locations

### Linux
```
Chrome:    ~/.config/google-chrome/Default/
Chromium:  ~/.config/chromium/Default/
Edge:      ~/.config/microsoft-edge/Default/
Brave:     ~/.config/BraveSoftware/Brave-Browser/Default/
Opera:     ~/.config/opera/
Vivaldi:   ~/.config/vivaldi/Default/
```

### Windows
```
Chrome:    %LOCALAPPDATA%\Google\Chrome\User Data\Default\
Edge:      %LOCALAPPDATA%\Microsoft\Edge\User Data\Default\
Brave:     %LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\
Opera:     %APPDATA%\Opera Software\Opera Stable\
Vivaldi:   %LOCALAPPDATA%\Vivaldi\User Data\Default\
```

### macOS
```
Chrome:    ~/Library/Application Support/Google/Chrome/Default/
Edge:      ~/Library/Application Support/Microsoft Edge/Default/
Brave:     ~/Library/Application Support/BraveSoftware/Brave-Browser/Default/
Opera:     ~/Library/Application Support/com.operasoftware.Opera/
Vivaldi:   ~/Library/Application Support/Vivaldi/Default/
```

## Database Files

| Database | Contents | Forensic Value |
|----------|----------|----------------|
| `History` | Browsing history, downloads, search terms | High |
| `Cookies` | HTTP cookies | High |
| `Login Data` | Saved passwords (encrypted) | Critical |
| `Web Data` | Autofill, credit cards, addresses | High |
| `Favicons` | Site icons | Low |
| `Top Sites` | Frequently visited sites | Medium |
| `Shortcuts` | Omnibox shortcuts | Medium |
| `Network Action Predictor` | URL predictions | Low |

## Browsing History (History)

### Tables
- `urls` - All visited URLs
- `visits` - Individual visits with timestamps
- `downloads` - Download history
- `keyword_search_terms` - Search queries

### Key Queries

**All Browsing History:**
```sql
SELECT 
    urls.url,
    urls.title,
    urls.visit_count,
    datetime(visits.visit_time/1000000-11644473600, 'unixepoch', 'localtime') as visit_time,
    visits.transition
FROM urls
JOIN visits ON urls.id = visits.url
ORDER BY visits.visit_time DESC;
```

**Download History:**
```sql
SELECT 
    target_path,
    tab_url as source_url,
    total_bytes,
    datetime(start_time/1000000-11644473600, 'unixepoch', 'localtime') as start_time,
    datetime(end_time/1000000-11644473600, 'unixepoch', 'localtime') as end_time,
    state,
    danger_type,
    mime_type
FROM downloads;
```

**Search Terms:**
```sql
SELECT 
    keyword_search_terms.term,
    urls.url as search_url,
    datetime(visits.visit_time/1000000-11644473600, 'unixepoch', 'localtime') as search_time
FROM keyword_search_terms
JOIN urls ON keyword_search_terms.url_id = urls.id
JOIN visits ON urls.id = visits.url
ORDER BY visits.visit_time DESC;
```

### Timestamps

Chromium uses **WebKit timestamps** (microseconds since January 1, 1601):

```python
# Convert WebKit timestamp to Unix timestamp
def webkit_to_unix(webkit_timestamp):
    return webkit_timestamp / 1000000 - 11644473600

# Convert to datetime
from datetime import datetime
dt = datetime.utcfromtimestamp(webkit_to_unix(timestamp))
```

## Cookies (Cookies)

### Tables
- `cookies` - All HTTP cookies

### Key Fields
| Field | Description |
|-------|-------------|
| `host_key` | Domain (leading dot = includes subdomains) |
| `name` | Cookie name |
| `encrypted_value` | Encrypted cookie value |
| `path` | URL path |
| `expires_utc` | Expiration timestamp |
| `is_secure` | HTTPS only flag |
| `is_httponly` | HttpOnly flag |
| `samesite` | SameSite policy |
| `last_access_utc` | Last access timestamp |

### Key Queries

**All Cookies:**
```sql
SELECT 
    host_key,
    name,
    path,
    datetime(expires_utc/1000000-11644473600, 'unixepoch', 'localtime') as expires,
    datetime(last_access_utc/1000000-11644473600, 'unixepoch', 'localtime') as last_access,
    is_secure,
    is_httponly,
    samesite
FROM cookies
ORDER BY host_key, name;
```

**Session Cookies (Authentication):**
```sql
SELECT host_key, name, path, is_secure
FROM cookies
WHERE name LIKE '%session%' 
   OR name LIKE '%token%' 
   OR name LIKE '%auth%'
   OR name LIKE '%login%';
```

### Cookie Encryption

Chrome encrypts cookie values using AES-256-GCM (Windows) or AES-128-CBC (Linux/macOS):

- **Windows**: Key protected by DPAPI, stored in `Local State`
- **Linux**: Key derived from PBKDF2 with "peanuts" salt
- **macOS**: Key stored in Keychain

## Saved Passwords (Login Data)

### Tables
- `logins` - Saved credentials
- `stats` - Password usage statistics

### Key Fields
| Field | Description |
|-------|-------------|
| `origin_url` | Site URL |
| `action_url` | Form submission URL |
| `username_element` | Username field name |
| `username_value` | Saved username |
| `password_element` | Password field name |
| `password_value` | Encrypted password |
| `date_created` | Creation timestamp |
| `times_used` | Usage count |

### Key Query

```sql
SELECT 
    origin_url,
    action_url,
    username_value,
    password_value,  -- Encrypted!
    datetime(date_created/1000000-11644473600, 'unixepoch', 'localtime') as created,
    times_used
FROM logins;
```

### Password Decryption

#### Windows (DPAPI + AES-GCM)
```python
import win32crypt
from Cryptodome.Cipher import AES

# Get key from Local State
with open(local_state_path, 'r') as f:
    local_state = json.load(f)
    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
    # Remove 'DPAPI' prefix
    encrypted_key = encrypted_key[5:]
    key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

# Decrypt password
def decrypt_password(encrypted_password, key):
    iv = encrypted_password[3:15]  # Skip 'v10' or 'v11' prefix
    ciphertext = encrypted_password[15:-16]
    tag = encrypted_password[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
```

#### Linux (PBKDF2 + AES-CBC)
```python
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2

# Derive key
key = PBKDF2(b'peanuts', b'saltysalt', dkLen=16, count=1)

# Decrypt
def decrypt_password(encrypted_password, key):
    iv = b' ' * 16
    encrypted_password = encrypted_password[3:]  # Remove 'v10' prefix
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_password)
    # Remove PKCS7 padding
    return decrypted[:-decrypted[-1]].decode('utf-8')
```

## Autofill Data (Web Data)

### Tables
- `autofill` - Form autofill entries
- `autofill_profiles` - Saved addresses
- `credit_cards` - Saved payment cards (encrypted)

### Key Queries

**Autofill Entries:**
```sql
SELECT 
    name,
    value,
    count,
    datetime(date_created, 'unixepoch', 'localtime') as first_used,
    datetime(date_last_used, 'unixepoch', 'localtime') as last_used
FROM autofill
ORDER BY count DESC;
```

**Saved Addresses:**
```sql
SELECT 
    company_name,
    street_address,
    city,
    state,
    zipcode,
    country_code,
    datetime(date_modified, 'unixepoch', 'localtime') as modified
FROM autofill_profiles;
```

## Bookmarks (Bookmarks)

Bookmarks are stored in JSON format in the `Bookmarks` file.

### Structure
```json
{
  "roots": {
    "bookmark_bar": { "children": [...] },
    "other": { "children": [...] },
    "synced": { "children": [...] }
  }
}
```

### Bookmark Object
```json
{
  "date_added": "13345678901234567",  // WebKit timestamp
  "date_last_used": "0",
  "guid": "unique-guid-here",
  "id": "1",
  "name": "Bookmark Title",
  "type": "url",
  "url": "https://example.com"
}
```

## Extensions (Preferences / Secure Preferences)

### Location
```
{profile}/Extensions/           # Extension files
{profile}/Preferences           # Extension settings
{profile}/Secure Preferences    # Signed extension data
```

### Preferences Structure
```json
{
  "extensions": {
    "settings": {
      "extension_id": {
        "manifest": {...},
        "path": "...",
        "state": 1,
        "install_time": "..."
      }
    }
  }
}
```

## Site Permissions

### Location
- `Preferences` file under `profile.content_settings.exceptions`

### Permission Types
| Permission | Key |
|------------|-----|
| Geolocation | `geolocation` |
| Notifications | `notifications` |
| Camera | `media_stream_camera` |
| Microphone | `media_stream_mic` |
| Clipboard | `clipboard` |
| USB | `usb_chooser_data` |

### Values
- `1` = Allow
- `2` = Block
- `0` = Ask (default)

## Cache Analysis

### Location
```
{profile}/Cache/
{profile}/Code Cache/
{profile}/GPUCache/
```

### Cache Entry Structure
Chromium uses a custom cache format. Each entry contains:
- URL
- Request headers
- Response headers
- Cached content

Tools like `ChromeCacheView` (NirSoft) can parse cache files.

## Session Data

### Current Session
```
{profile}/Current Session    # Currently open tabs
{profile}/Current Tabs       # Tab state
```

### Last Session
```
{profile}/Last Session       # Tabs from last session
{profile}/Last Tabs          # Previous tab state
```

### Format
SNSS (Session Saver) binary format. Contains:
- Tab URLs
- Tab titles
- Navigation history per tab
- Form data
- Scroll positions

## Local State File

Located at `{User Data}/Local State`:

```json
{
  "os_crypt": {
    "encrypted_key": "base64_encoded_key"  // Master encryption key
  },
  "profile": {
    "info_cache": {...}  // Profile metadata
  }
}
```

## Forensic Extraction

### Using This Tool

```bash
# Extract Chrome data
python main.py -b chrome

# Extract only history and cookies
python main.py -b chrome -e history cookies

# Print to terminal
python main.py -b chrome -e history --print-only

# Extract passwords (requires pycryptodome)
python main.py -b chrome -e passwords
```

### Manual Database Access

```bash
# Copy database (browser must be closed)
cp ~/.config/google-chrome/Default/History ./History_copy

# Query with sqlite3
sqlite3 History_copy "SELECT url, title FROM urls LIMIT 10;"
```

## Security Considerations

1. **Encryption Keys**: Master key is stored locally, accessible to any process running as the user
2. **Cookie Encryption**: Provides protection at rest, not against local attacks
3. **Password Manager**: Passwords accessible to any local process with user privileges
4. **Sync Data**: If Chrome Sync is enabled, data may exist on Google servers

## Timestamps Reference

| Source | Format | Conversion |
|--------|--------|------------|
| WebKit | Microseconds since 1601-01-01 | `/1000000 - 11644473600` |
| Unix | Seconds since 1970-01-01 | Direct |
| Chrome Date | Same as WebKit | `/1000000 - 11644473600` |

## Common Forensic Queries

### User Activity Timeline
```sql
SELECT 
    'Visit' as type,
    urls.url,
    datetime(visits.visit_time/1000000-11644473600, 'unixepoch') as timestamp
FROM urls JOIN visits ON urls.id = visits.url
UNION ALL
SELECT 
    'Download' as type,
    target_path,
    datetime(start_time/1000000-11644473600, 'unixepoch') as timestamp
FROM downloads
ORDER BY timestamp DESC;
```

### Credential Audit
```sql
SELECT 
    origin_url,
    username_value,
    times_used,
    datetime(date_created/1000000-11644473600, 'unixepoch') as created
FROM logins
WHERE password_value IS NOT NULL AND length(password_value) > 0;
```

### Authentication Cookies
```sql
SELECT host_key, name, is_secure, is_httponly
FROM cookies
WHERE name IN ('sessionid', 'session', 'auth', 'token', 'sid', 
               'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId');
```

---

**Related Documentation:**
- [Firefox Forensics Reference](FIREFOX_FORENSICS.md)
- [Setup Guide](SETUP.md)
- [README](README.md)
