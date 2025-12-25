# Browser Key Extraction - Technical Process Documentation

This document explains the technical process for extracting and decrypting data from various browsers.

---

## Table of Contents

1. [Supported Browsers](#supported-browsers)
2. [Password Decryption](#password-decryption)
3. [Cookie Extraction](#cookie-extraction)
4. [History Extraction](#history-extraction)
5. [Bookmark Extraction](#bookmark-extraction)
6. [Download History](#download-history)
7. [Autofill Data](#autofill-data)
8. [Extensions](#extensions)

---

## Supported Browsers

### Chromium-Based Browsers
| Browser | Windows | Linux |
|---------|---------|-------|
| Chrome | ✅ | ✅ |
| Edge | ✅ | ✅ |
| Brave | ✅ | ✅ |
| Opera | ✅ | ✅ |
| Vivaldi | ✅ | ✅ |
| Chromium | ✅ | ✅ |

### Gecko-Based Browsers
| Browser | Windows | Linux |
|---------|---------|-------|
| Firefox | ✅ | ✅ |

---

## Password Decryption

### Firefox (NSS Decryption)

**Storage Location:**
- Windows: `%APPDATA%\Mozilla\Firefox\Profiles\<profile>\logins.json`
- Linux: `~/.mozilla/firefox/<profile>/logins.json`

**Key Database:**
- `key4.db` (SQLite - modern)
- `key3.db` (Berkeley DB - legacy)

**Process:**
1. Load NSS library (`nss3.dll` on Windows, `libnss3.so` on Linux)
2. On Windows, load `mozglue.dll` first (required dependency)
3. Initialize NSS with profile path using `NSS_Init()`
4. Get internal key slot via `PK11_GetInternalKeySlot()`
5. Authenticate with master password if set via `PK11_CheckUserPassword()`
6. Read `logins.json` for encrypted credentials
7. Base64 decode `encryptedUsername` and `encryptedPassword`
8. Decrypt using `PK11SDR_Decrypt()`
9. Cleanup with `NSS_Shutdown()`

**Encryption:** Mozilla's Security Services (NSS) using 3DES-CBC with PKCS#5 padding

**Limitations:**
- Snap/Flatpak Firefox on Linux: Cannot access due to sandboxing
- OS Keyring integration (GNOME Keyring/KWallet): Requires unlocked keyring

---

### Chromium (Multi-Version Decryption)

**Storage Location:**
- Windows: `%LOCALAPPDATA%\<Browser>\User Data\<Profile>\Login Data`
- Linux: `~/.config/<browser>/<profile>/Login Data`

**Key Storage:**
- Windows: `%LOCALAPPDATA%\<Browser>\User Data\Local State` (JSON)
- Linux: GNOME Keyring / KWallet or hardcoded key

**Encryption Versions:**

#### v10 (Windows DPAPI)
```
Format: v10 + AES-GCM encrypted data
Key: DPAPI-protected in Local State (base64 "encrypted_key")
```

**Process:**
1. Read `Local State` JSON file
2. Extract `os_crypt.encrypted_key` (base64)
3. Strip "DPAPI" prefix (5 bytes)
4. Decrypt with Windows DPAPI (`CryptUnprotectData`)
5. Use decrypted key for AES-256-GCM decryption
6. Extract: nonce (12 bytes) + ciphertext + tag (16 bytes)

#### v11 (Linux)
```
Format: v11 + AES-128-CBC encrypted data
Key: From GNOME Keyring or hardcoded "peanuts"
```

**Process:**
1. Query GNOME Keyring for browser-specific password
2. Fallback to hardcoded key `peanuts` if unavailable
3. Derive key using PBKDF2-SHA1 (1003 iterations, 16-byte salt `saltysalt`)
4. AES-128-CBC decryption with IV = 16 bytes of space (0x20)

#### v20 (Windows App-Bound Encryption)
```
Format: v20 + encrypted payload
Requires: Administrator privileges + IElevator COM interface
```

**Process:**
1. Detect v20 prefix in encrypted data
2. Requires elevation to Administrator
3. Use Chrome's IElevator COM interface
4. Call `DecryptData()` method with encrypted blob
5. Returns AES-GCM key for decryption
6. Browser-specific CLSID required (Chrome, Edge, Brave differ)

**Browser CLSIDs for v20:**
- Chrome: `{708860E0-F641-4611-8895-7D867DD3675B}`
- Edge: `{B2E6D3A2-4221-4B14-A397-4D4AE51D8C77}` (format differs)
- Brave: `{576B31AF-6369-4B6B-8560-E4B203A97A8B}` (format differs)

---

## Cookie Extraction

### Firefox

**Storage:** `cookies.sqlite` (SQLite database)

**Table:** `moz_cookies`

**Fields:**
| Field | Description |
|-------|-------------|
| host | Domain |
| name | Cookie name |
| value | Cookie value (plaintext) |
| path | URL path |
| expiry | Unix timestamp |
| isSecure | HTTPS only flag |
| isHttpOnly | HTTP only flag |
| sameSite | SameSite policy |

**Process:**
1. Open `cookies.sqlite` in read-only mode
2. Query `moz_cookies` table
3. No decryption needed - values stored in plaintext

---

### Chromium

**Storage:** `Cookies` (SQLite database)

**Table:** `cookies`

**Fields:**
| Field | Description |
|-------|-------------|
| host_key | Domain |
| name | Cookie name |
| encrypted_value | Encrypted cookie value |
| path | URL path |
| expires_utc | WebKit timestamp |
| is_secure | HTTPS only flag |
| is_httponly | HTTP only flag |
| samesite | SameSite policy |

**Process:**
1. Open `Cookies` database in read-only mode
2. Query `cookies` table
3. For each cookie, decrypt `encrypted_value`:
   - Check version prefix (v10/v11/v20)
   - Apply appropriate decryption method
4. Convert WebKit timestamp to Unix timestamp

**Timestamp Conversion:**
```python
# WebKit epoch: January 1, 1601
# Unix epoch: January 1, 1970
# Difference: 11644473600 seconds
unix_time = (webkit_time / 1_000_000) - 11644473600
```

---

## History Extraction

### Firefox

**Storage:** `places.sqlite`

**Tables:** `moz_places`, `moz_historyvisits`

**Process:**
1. Join `moz_places` with `moz_historyvisits`
2. Extract URL, title, visit count, last visit time
3. Convert PRTime (microseconds since Unix epoch) to datetime

**Query:**
```sql
SELECT p.url, p.title, p.visit_count, 
       h.visit_date, h.visit_type
FROM moz_places p
JOIN moz_historyvisits h ON p.id = h.place_id
ORDER BY h.visit_date DESC
```

---

### Chromium

**Storage:** `History` (SQLite database)

**Tables:** `urls`, `visits`

**Process:**
1. Join `urls` with `visits` table
2. Extract URL, title, visit count, last visit time
3. Convert WebKit timestamp to datetime

**Query:**
```sql
SELECT u.url, u.title, u.visit_count,
       u.last_visit_time, v.visit_time
FROM urls u
LEFT JOIN visits v ON u.id = v.url
ORDER BY u.last_visit_time DESC
```

---

## Bookmark Extraction

### Firefox

**Storage:** `places.sqlite`

**Tables:** `moz_bookmarks`, `moz_places`

**Process:**
1. Query `moz_bookmarks` joined with `moz_places`
2. Filter by bookmark type (type=1 for URLs)
3. Extract title, URL, date added, parent folder

---

### Chromium

**Storage:** `Bookmarks` (JSON file)

**Structure:**
```json
{
  "roots": {
    "bookmark_bar": { "children": [...] },
    "other": { "children": [...] },
    "synced": { "children": [...] }
  }
}
```

**Process:**
1. Parse JSON file
2. Recursively traverse bookmark tree
3. Extract name, URL, date added for each entry

---

## Download History

### Firefox

**Storage:** `places.sqlite`

**Table:** `moz_annos` (annotations on places)

**Process:**
1. Query annotations related to downloads
2. Extract file path, URL, download time

---

### Chromium

**Storage:** `History` (SQLite database)

**Table:** `downloads`, `downloads_url_chains`

**Process:**
1. Query `downloads` table
2. Join with `downloads_url_chains` for source URLs
3. Extract target path, total bytes, start/end time, state

---

## Autofill Data

### Firefox

**Storage:** `formhistory.sqlite`

**Table:** `moz_formhistory`

**Fields:** fieldname, value, timesUsed, firstUsed, lastUsed

---

### Chromium

**Storage:** `Web Data` (SQLite database)

**Table:** `autofill`

**Fields:** name, value, count, date_created, date_last_used

---

## Extensions

### Firefox

**Storage:** `extensions.json`

**Process:**
1. Parse JSON file
2. Extract addon ID, name, version, enabled status
3. Filter by type (extensions vs themes)

---

### Chromium

**Storage:** `%LOCALAPPDATA%\<Browser>\User Data\<Profile>\Extensions\`

**Process:**
1. Read `Preferences` or `Secure Preferences` JSON
2. Parse `extensions.settings` object
3. Or enumerate extension directories and read `manifest.json`

---

## Security Considerations

### Read-Only Access
- All database files are opened in read-only mode (`?mode=ro`)
- WAL (Write-Ahead Logging) files are handled appropriately
- No modifications made to browser data

### Temporary Copies
- NSS requires write access, so profile files are copied to temp directory
- Temp files are cleaned up after use

### Privilege Requirements
| Operation | Windows | Linux |
|-----------|---------|-------|
| v10 Decryption | User | N/A |
| v11 Decryption | N/A | User (+ keyring) |
| v20 Decryption | Administrator | N/A |
| Firefox Decryption | User | User |

---

## Error Handling

| Error | Cause | Solution |
|-------|-------|----------|
| `NSSLibraryMissing` | Firefox not installed | Install Firefox |
| `MasterPasswordRequired` | Firefox master password set | Provide password |
| `UnsupportedEnvironment` | Snap/Flatpak Firefox | Use native Firefox |
| `OSKeyringLocked` | GNOME Keyring locked | Unlock keyring |
| `v20 requires elevation` | App-Bound Encryption | Run as Administrator |
| `Database locked` | Browser running | Close browser |

---

## References

- [Chromium OS Crypt](https://source.chromium.org/chromium/chromium/src/+/main:components/os_crypt/)
- [Mozilla NSS](https://firefox-source-docs.mozilla.org/security/nss/)
- [SQLite URI Parameters](https://www.sqlite.org/uri.html)
- [Windows DPAPI](https://docs.microsoft.com/en-us/windows/win32/api/dpapi/)
- [Chrome App-Bound Encryption](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
